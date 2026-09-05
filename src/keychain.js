"use strict";

// Not destructured: kept as `cp.execFileSync(...)` at every call site so a
// test can monkey-patch `require("child_process").execFileSync` (the same
// shared module object) the way tests/smoke.js's Windows-path tests do for
// both this file and integrity.js -- a destructured `const { execFileSync
// } = ...` would copy the reference at import time and never see a patch.
const cp = require("child_process");

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
 *
 * `service` (4th param on store/retrieve/remove, added for `residoo cred`,
 * see src/credRun.js) is an ADDITIVE, trailing-optional parameter that
 * defaults to SERVICE below -- every pre-existing call site (cli.js's
 * seal/unseal, this project's own tests) is byte-for-byte unaffected by its
 * addition. `residoo cred` passes CRED_SERVICE explicitly so credential
 * entries are visually distinct from sealed-vault keys in the OS keychain
 * UI, and so the two account-name spaces can never collide.
 */
const SERVICE = "residoo-vault";
const CRED_SERVICE = "residoo-cred";

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
      cp.execFileSync("which", ["secret-tool"], { stdio: "ignore" });
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
  if (process.platform === "win32") {
    // Specifically about THIS by-name store/retrieve/remove API (residoo
    // cred's only use of it) -- `--seal --keychain` works on Windows via a
    // different, vault-relative mechanism (wrapVaultKeyWindows/
    // unwrapVaultKeyWindows below), so this message must not read as "no
    // --keychain support at all on Windows," which would be wrong.
    return "residoo cred needs a named credential store, and Windows has none reachable without an extra dependency " +
      "(cmdkey.exe can store a credential but never reads its password back -- confirmed against Microsoft's own docs). " +
      "--seal --keychain works on Windows through a different mechanism; this specific store is what's unavailable.";
  }
  return `--keychain is not supported on ${process.platform} yet. Omit --keychain to use a passphrase instead.`;
}

/**
 * True when wrapVaultKeyWindows/unwrapVaultKeyWindows (below) can run --
 * Windows only, since DPAPI is a Windows-specific API. Deliberately
 * SEPARATE from isSupported() above: that function is about the by-name
 * store()/retrieve()/remove() API (false on Windows -- no OS-level named
 * credential store is reachable there without an extra dependency, since
 * cmdkey.exe is confirmed write/list-only, never returning a stored
 * password). This one is about the vault-relative wrap/unwrap pair, which
 * exists only because `--seal --keychain` has a legitimate place (the
 * vault directory itself) to put a DPAPI-wrapped blob -- `residoo cred`
 * has no such place and does not use this.
 */
function isVaultKeySupported() {
  return process.platform === "win32";
}

/**
 * Windows-only DPAPI (Data Protection API) wrap/unwrap for `--seal
 * --keychain`'s vault key, via a PowerShell shell-out -- the same
 * "invoke the OS's own tool" pattern as macOS's `security` and Linux's
 * `secret-tool` above, but a materially different SHAPE, and why these
 * two functions exist separately from store()/retrieve() rather than as a
 * Windows branch inside them.
 *
 * Windows has no OS-level "store this under a name, fetch it back by that
 * name later" service the way macOS Keychain/secret-tool do. Verified
 * directly, not assumed: `cmdkey.exe` (Windows Credential Manager's own
 * CLI) can WRITE a generic credential but Microsoft's own documentation
 * states plainly "Passwords are not displayed after they're stored," and
 * `/list` only ever surfaces target names and usernames -- cmdkey is
 * write/list-only, and cannot serve a store-then-retrieve flow at all.
 * DPAPI (`System.Security.Cryptography.ProtectedData`, confirmed reachable
 * from stock PowerShell 5.1 via `Add-Type -AssemblyName System.Security`
 * with zero extra installs -- learn.microsoft.com/dotnet/standard/security/
 * how-to-use-data-protection) is the real built-in alternative, but it is
 * a stateless encrypt/decrypt PRIMITIVE, not a named registry: something
 * still has to decide where the encrypted bytes are persisted.
 *
 * That is why wrapVaultKeyWindows only WRAPS a secret and hands the
 * encrypted blob straight back to its caller -- this module never decides
 * where it lives. `--seal --keychain` (cli.js's resolveSealSecret/
 * resolveUnsealSecret) is the one caller with a rule-compliant place to
 * put it: the vault directory itself, already within `--seal`'s own
 * carve-out under CONTRIBUTING.md's hard rule (residoo writes nothing
 * outside `~/.residoo/rotations.json` and an explicit `--seal`). `residoo
 * cred` stores a long-lived credential with no vault of its own, so there
 * is no rule-compliant place to write a DPAPI blob for it -- it remains
 * genuinely unsupported on Windows (isSupported() above, unchanged), not
 * worked around by squeezing it through this pair too.
 *
 * Disclosed security-property difference, not glossed over: on macOS/
 * Linux, the key lives in a genuinely separate OS-managed store, entirely
 * absent from the vault directory -- copying just the vault gets an
 * attacker nothing at all. On Windows, the wrapped blob travels WITH the
 * vault directory (inside it), so copying the whole vault also copies the
 * blob. DPAPI's CurrentUser-scope encryption still means that blob is
 * only decryptable by the same Windows user account on the same Windows
 * installation -- not portable, the same end-user guarantee --keychain
 * already documents -- but a threat model where an attacker can read the
 * vault directory's files without being able to run code as that same
 * user gets less protection here than macOS/Linux's physically-separate
 * store provides. Verified against Microsoft's own DPAPI documentation;
 * not live-tested against a real Windows install.
 */
function wrapVaultKeyWindows(secret) {
  if (process.platform !== "win32") throw new Error("wrapVaultKeyWindows is Windows-only.");
  const escaped = String(secret).replace(/'/g, "''");
  const script =
    "$ErrorActionPreference='Stop'; " +
    "Add-Type -AssemblyName System.Security; " +
    `$bytes = [System.Text.Encoding]::UTF8.GetBytes('${escaped}'); ` +
    "$enc = [Security.Cryptography.ProtectedData]::Protect($bytes, $null, [Security.Cryptography.DataProtectionScope]::CurrentUser); " +
    "[Convert]::ToBase64String($enc)";
  return cp.execFileSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", script], { encoding: "utf-8" }).trim();
}

/** The other half of wrapVaultKeyWindows -- see its docstring for the full design. */
function unwrapVaultKeyWindows(blob) {
  if (process.platform !== "win32") throw new Error("unwrapVaultKeyWindows is Windows-only.");
  const escaped = String(blob).replace(/'/g, "''");
  const script =
    "$ErrorActionPreference='Stop'; " +
    "Add-Type -AssemblyName System.Security; " +
    `$enc = [Convert]::FromBase64String('${escaped}'); ` +
    "$dec = [Security.Cryptography.ProtectedData]::Unprotect($enc, $null, [Security.Cryptography.DataProtectionScope]::CurrentUser); " +
    "[System.Text.Encoding]::UTF8.GetString($dec)";
  return cp.execFileSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", script], { encoding: "utf-8" }).trim();
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
function store(account, secret, keychainFile, service = SERVICE) {
  if (process.platform === "darwin") {
    // -U updates the entry in place if `account` already exists, rather
    // than erroring on a name collision.
    const kf = keychainFile || testKeychainFile();
    const args = ["add-generic-password", "-a", account, "-s", service, "-w", secret, "-U"];
    if (kf) args.push(kf);
    cp.execFileSync("security", args, { stdio: "ignore" });
    return;
  }
  if (process.platform === "linux") {
    // secret-tool reads the secret from stdin, never a CLI argument, so it
    // never appears in a process listing or shell history.
    cp.execFileSync("secret-tool", [
      "store", "--label", "residoo sealed vault key", "service", service, "account", account,
    ], { input: secret, stdio: ["pipe", "ignore", "ignore"] });
    return;
  }
  throw new Error(unsupportedReason());
}

/**
 * Retrieve a secret previously stored under `account`. Throws if not found
 * or unsupported. See store() re: keychainFile/service.
 */
function retrieve(account, keychainFile, service = SERVICE) {
  if (process.platform === "darwin") {
    const kf = keychainFile || testKeychainFile();
    const args = ["find-generic-password", "-a", account, "-s", service, "-w"];
    if (kf) args.push(kf);
    return cp.execFileSync("security", args, { encoding: "utf8" }).trim();
  }
  if (process.platform === "linux") {
    return cp.execFileSync("secret-tool", [
      "lookup", "service", service, "account", account,
    ], { encoding: "utf8" }).trim();
  }
  throw new Error(unsupportedReason());
}

/**
 * Remove a previously stored secret. Not used by seal/unseal (a vault's
 * keychain entry is meant to outlive the command that created it); exists
 * for callers that manage a keychain entry's lifecycle themselves, and for
 * this project's own tests to clean up after a real round-trip check
 * without leaving entries behind. See store() re: keychainFile/service.
 */
function remove(account, keychainFile, service = SERVICE) {
  if (process.platform === "darwin") {
    const kf = keychainFile || testKeychainFile();
    const args = ["delete-generic-password", "-a", account, "-s", service];
    if (kf) args.push(kf);
    cp.execFileSync("security", args, { stdio: "ignore" });
    return;
  }
  if (process.platform === "linux") {
    cp.execFileSync("secret-tool", ["clear", "service", service, "account", account], { stdio: "ignore" });
    return;
  }
  throw new Error(unsupportedReason());
}

module.exports = {
  isSupported, unsupportedReason, store, retrieve, remove, CRED_SERVICE,
  isVaultKeySupported, wrapVaultKeyWindows, unwrapVaultKeyWindows,
};
