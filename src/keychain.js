"use strict";

const { execFileSync } = require("child_process");

/**
 * OS-native secure credential storage for `scan --seal --keychain` and
 * `unseal --keychain`. Instead of a user-typed passphrase run through
 * scrypt, residoo generates a truly random, high-entropy secret and hands
 * it to the OS's own secure store: nothing needs to be typed or
 * remembered, and the vault's strength no longer depends on a human's
 * passphrase choice (the weak spot a security audit flagged in passphrase
 * mode, where the only floor was an 8-character length check).
 *
 * The secret itself is still passed straight through to sealcrypto.js's
 * existing deriveKey(passphrase, salt) exactly as a typed passphrase would
 * be: scrypt on a full 256-bit-entropy input is harmless extra defense in
 * depth, and reusing the same, already-tested code path here means no
 * change to sealcrypto.js or sealvault.js at all — only how the secret is
 * obtained changes.
 *
 * Scoped honestly rather than half-built everywhere: macOS via the
 * `security` CLI (built into the OS, no new dependency) is the primary,
 * fully-supported path. Linux via `secret-tool` (libsecret) works when it's
 * installed and is treated as best-effort, gated by isSupported() the same
 * way every source in this codebase declares availability rather than
 * assuming it. Windows has no equivalent built-in CLI story and is refused
 * outright with a clear message rather than half-implemented against a
 * module residoo would have to newly depend on.
 *
 * IMPORTANT TRADEOFF, stated plainly: a keychain-backed vault key lives in
 * THIS machine's (or account's) secure store. It is not portable the way a
 * passphrase is — unseal it on a different machine and there is nothing to
 * retrieve. Use a passphrase instead when a vault needs to travel.
 */
const SERVICE = "residoo-vault";

/**
 * Test-only escape hatch, macOS only: when RESIDOO_TEST_KEYCHAIN_FILE is
 * set, every operation below scopes to that keychain FILE instead of the
 * real default login keychain. Exists so this project's own tests can run
 * a genuine store/retrieve/remove round trip against a throwaway keychain
 * created and destroyed within the test (see tests/smoke.js), crossing a
 * spawned child process boundary via env var rather than a function
 * parameter, without ever touching, prompting about, or depending on
 * whatever machine happens to run them. Not a documented flag: no real
 * user has a reason to set this, and even if one did, the only effect is
 * redirecting to a named file instead of the default keychain, never an
 * unexpected access to anything.
 */
function testKeychainFile() {
  return process.env.RESIDOO_TEST_KEYCHAIN_FILE || null;
}

function isSupported() {
  if (process.platform === "darwin") return true;
  if (process.platform === "linux") {
    try {
      execFileSync("which", ["secret-tool"], { stdio: "ignore" });
      return true;
    } catch {
      return false;
    }
  }
  return false;
}

function unsupportedReason() {
  if (process.platform === "darwin") return null;
  if (process.platform === "linux") {
    return "secret-tool (libsecret) is not installed. Install it (e.g. \"apt install libsecret-tools\" or \"dnf install libsecret\") or omit --keychain to use a passphrase instead.";
  }
  return `--keychain is not supported on ${process.platform} yet. Omit --keychain to use a passphrase instead.`;
}

/**
 * Store `secret` (a string) under `account` in the OS keychain, for later
 * retrieve(account). `keychainFile`, macOS only, is an escape hatch used
 * ONLY by this project's own tests: passing a path scopes the operation to
 * that specific keychain FILE instead of the real default login keychain,
 * so a test round-trip never touches, prompts about, or depends on the
 * developer's actual keychain. The real feature (seal/unseal) never passes
 * this — it always targets the default keychain, which is the whole point.
 */
function store(account, secret, keychainFile) {
  if (process.platform === "darwin") {
    // -U updates the entry in place if `account` already exists, rather
    // than erroring on a name collision.
    const kf = keychainFile || testKeychainFile();
    const args = ["add-generic-password", "-a", account, "-s", SERVICE, "-w", secret, "-U"];
    if (kf) args.push(kf);
    execFileSync("security", args, { stdio: "ignore" });
    return;
  }
  if (process.platform === "linux") {
    // secret-tool reads the secret from stdin, never a CLI argument, so it
    // never appears in a process listing or shell history.
    execFileSync("secret-tool", [
      "store", "--label", "residoo sealed vault key", "service", SERVICE, "account", account,
    ], { input: secret, stdio: ["pipe", "ignore", "ignore"] });
    return;
  }
  throw new Error(unsupportedReason());
}

/** Retrieve a secret previously stored under `account`. Throws if not found or unsupported. See store() re: keychainFile. */
function retrieve(account, keychainFile) {
  if (process.platform === "darwin") {
    const kf = keychainFile || testKeychainFile();
    const args = ["find-generic-password", "-a", account, "-s", SERVICE, "-w"];
    if (kf) args.push(kf);
    return execFileSync("security", args, { encoding: "utf8" }).trim();
  }
  if (process.platform === "linux") {
    return execFileSync("secret-tool", [
      "lookup", "service", SERVICE, "account", account,
    ], { encoding: "utf8" }).trim();
  }
  throw new Error(unsupportedReason());
}

/**
 * Remove a previously stored secret. Not used by seal/unseal (a vault's
 * keychain entry is meant to outlive the command that created it); exists
 * for callers that manage a keychain entry's lifecycle themselves, and for
 * this project's own tests to clean up after a real round-trip check
 * without leaving entries behind. See store() re: keychainFile.
 */
function remove(account, keychainFile) {
  if (process.platform === "darwin") {
    const kf = keychainFile || testKeychainFile();
    const args = ["delete-generic-password", "-a", account, "-s", SERVICE];
    if (kf) args.push(kf);
    execFileSync("security", args, { stdio: "ignore" });
    return;
  }
  if (process.platform === "linux") {
    execFileSync("secret-tool", ["clear", "service", SERVICE, "account", account], { stdio: "ignore" });
    return;
  }
  throw new Error(unsupportedReason());
}

module.exports = { isSupported, unsupportedReason, store, retrieve, remove };
