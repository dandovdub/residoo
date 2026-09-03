"use strict";

const { spawnSync } = require("child_process");
const path = require("path");
const keychain = require("./keychain");

/**
 * `residoo cred`: run one allow-listed command with one stored credential
 * injected as environment variables, without the caller ever seeing the
 * raw value. This is the first residoo feature that is NOT purely
 * detection/read-only -- it stores a live credential and executes a
 * subprocess. Built after an adversarial red-team pass against a first
 * draft found its central safety claim false as written (see the shipped
 * plan for the full writeup): matching a caller-supplied command string
 * against an allow-list by basename alone verifies the NAME the caller
 * claims, not the binary that actually runs. Two concrete bypasses
 * followed directly from that gap (a path-separator-smuggled command, and
 * PATH-order poisoning via a writable directory earlier in this process's
 * own inherited PATH) -- both closed here by making `command` a pure
 * lookup key into an operator-pinned absolute-path map, never a value
 * that participates in path resolution at all.
 *
 * Modeled on src/verify.js's verifyAwsCredential: env built from scratch
 * (never inheriting process.env), spawnSync (not shell:true, args always a
 * structured array), an explicit timeout. The one deliberate departure:
 * this never returns the executed command's own stdout/stderr content --
 * only exit status and line counts -- because that output is a channel the
 * injected secret could leak through in ways no redaction pass can
 * guarantee to catch (an echoed env var, a stack trace).
 */

const FIXED_TIMEOUT_MS = 30000;

function sanitizeDetail(s) {
  return String(s || "").replace(/[\x00-\x1f\x7f]/g, "").slice(0, 200);
}

/**
 * Parse RESIDOO_CRED_ALLOWED_COMMANDS ("name=/absolute/path,name2=/path2")
 * into a `Map<name, absolutePath>`. Fails closed on the WHOLE list if any
 * single entry is malformed (not "name=path", or a non-absolute path),
 * rather than silently dropping just the bad entry and running with a
 * partial list the operator might not realize is incomplete -- a
 * misconfiguration should be loud, not quietly permissive.
 */
function parseAllowedCommands(raw) {
  const map = new Map();
  const text = String(raw || "").trim();
  if (text === "") return { map, error: null };
  for (const entry of text.split(",")) {
    const eq = entry.indexOf("=");
    if (eq <= 0) {
      return { map: new Map(), error: `entry "${entry}" is not in the form name=/absolute/path` };
    }
    const name = entry.slice(0, eq).trim();
    const p = entry.slice(eq + 1).trim();
    if (!name) return { map: new Map(), error: `entry "${entry}" has an empty name` };
    if (!path.isAbsolute(p)) return { map: new Map(), error: `entry for "${name}" ("${p}") is not an absolute path` };
    map.set(name, p);
  }
  return { map, error: null };
}

/**
 * Run one allow-listed command with one stored credential injected as
 * environment variables.
 *
 * `command` is a LOOKUP KEY into the allow-list, never a path: it can
 * never cause any file other than the operator-pinned absolute path to
 * execute, regardless of what the caller supplies -- that is the entire
 * point of this design, not an incidental property of it.
 *
 * Returns `{ ok: true, exitCode, succeeded, timedOut, stdoutLineCount,
 * stderrLineCount }` for a completed run (even a nonzero exit --
 * `ok: true` means "we ran something and can report on it," not "it
 * succeeded"; check `succeeded`), or `{ ok: false, reason }` for every
 * fail-closed case (unconfigured allow-list, unknown command, credential
 * not found, corrupt credential, spawn failure). Never returns the
 * command's own stdout/stderr content, and never the injected credential
 * value, in either shape.
 */
function runWithCredential({
  credentialName,
  command,
  args = [],
  allowedCommandsRaw = process.env.RESIDOO_CRED_ALLOWED_COMMANDS,
  spawnFn = spawnSync,
  log = (line) => process.stderr.write(line),
  // Test-only override (this project's own tests, e.g. proving the
  // timeout+SIGKILL escalation actually bounds a hung command, without a
  // real 30s wait). NEVER passed by cli.js's runCredRun or mcpTools.js's
  // handleRunWithCred -- both call this function without this option, so
  // production always uses the fixed, safe default. Not exposed via
  // either the CLI argument parser or the MCP inputSchema.
  timeoutMs = FIXED_TIMEOUT_MS,
}) {
  if (typeof credentialName !== "string" || !credentialName) return { ok: false, reason: "credentialName is required" };
  if (typeof command !== "string" || !command) return { ok: false, reason: "command is required" };
  if (!Array.isArray(args) || !args.every((a) => typeof a === "string")) {
    return { ok: false, reason: "args must be an array of strings" };
  }

  const { map: allowed, error: parseError } = parseAllowedCommands(allowedCommandsRaw);
  if (parseError) return { ok: false, reason: `RESIDOO_CRED_ALLOWED_COMMANDS is misconfigured: ${parseError}` };
  if (allowed.size === 0) {
    return { ok: false, reason: "RESIDOO_CRED_ALLOWED_COMMANDS is not set: nothing is allowed to run. Set it to \"name=/absolute/path,...\" to allow specific commands." };
  }

  // Defense in depth, not the only thing preventing this: `command`
  // containing a path separator can never match a bare allow-list name
  // anyway, since allowed.get() below only ever returns an operator-pinned
  // absolute path, never the caller's own string.
  if (command.includes("/") || command.includes("\\")) {
    return { ok: false, reason: `command must be a name from RESIDOO_CRED_ALLOWED_COMMANDS, not a path: "${command}"` };
  }
  const pinnedPath = allowed.get(command);
  if (!pinnedPath) return { ok: false, reason: `"${command}" is not in RESIDOO_CRED_ALLOWED_COMMANDS` };

  let blobText;
  try {
    blobText = keychain.retrieve(credentialName, null, keychain.CRED_SERVICE);
  } catch (e) {
    return { ok: false, reason: `credential "${credentialName}" not found: ${sanitizeDetail(e && e.message)}` };
  }
  let blob;
  try {
    blob = JSON.parse(blobText);
  } catch {
    return { ok: false, reason: `credential "${credentialName}" is corrupt (not valid JSON)` };
  }
  if (!blob || !Array.isArray(blob.envVars) || blob.envVars.length === 0) {
    return { ok: false, reason: `credential "${credentialName}" is corrupt (missing envVars)` };
  }

  // Built from scratch -- never process.env spread/inherited -- exactly
  // verify.js's verifyAwsCredential's existing, already-audited pattern.
  const env = { PATH: process.env.PATH || "" };
  for (const v of blob.envVars) {
    if (v && typeof v.name === "string" && typeof v.value === "string") env[v.name] = v.value;
  }
  // Ported from verify.js: forces the aws CLI to never silently fall back
  // to the operator's real default profile if the stored credential is
  // malformed in some way that would otherwise trigger a fallback. No
  // other vendor gets bespoke hardening in v1 -- a stated, accepted gap,
  // not a hidden one.
  if (command === "aws") {
    env.AWS_CONFIG_FILE = "/dev/null";
    env.AWS_SHARED_CREDENTIALS_FILE = "/dev/null";
  }

  let r;
  try {
    r = spawnFn(pinnedPath, args, {
      env,
      timeout: timeoutMs,
      // SIGKILL, not the default SIGTERM: residoo's MCP dispatcher is
      // fully sequential while waiting on this call, so the timeout bound
      // must actually be reliable, not dependent on the child honoring a
      // termination request. Known, accepted secondary limitation: this
      // kills the direct child only, not any detached grandchildren it may
      // have already spawned -- the allow-list fix above is what actually
      // closes the credential-exfiltration path, not perfect process-tree
      // cleanup.
      killSignal: "SIGKILL",
      encoding: "utf-8",
      shell: false,
      stdio: ["ignore", "pipe", "pipe"],
    });
  } catch (e) {
    log(`residoo cred: "${command}" (credential "${credentialName}") failed to start: ${sanitizeDetail(e && e.message)}\n`);
    return { ok: false, reason: `failed to start "${command}": ${sanitizeDetail(e && e.message)}` };
  }

  const timedOut = !!(r.error && r.error.code === "ETIMEDOUT");
  if (r.error && !timedOut) {
    const detail = r.error.code === "ENOENT" ? "the pinned path does not exist or is not executable" : sanitizeDetail(r.error.message);
    log(`residoo cred: "${command}" (credential "${credentialName}") failed to start: ${detail}\n`);
    return { ok: false, reason: `failed to start "${command}": ${detail}` };
  }

  const countLines = (s) => (s ? String(s).split("\n").filter((l) => l !== "").length : 0);
  const exitCode = timedOut ? null : r.status;
  const succeeded = !timedOut && r.status === 0;

  log(`residoo cred: ran "${command}" with credential "${credentialName}", exit ${timedOut ? "TIMEOUT" : exitCode}\n`);

  return { ok: true, exitCode, succeeded, timedOut, stdoutLineCount: countLines(r.stdout), stderrLineCount: countLines(r.stderr) };
}

module.exports = { runWithCredential, parseAllowedCommands, FIXED_TIMEOUT_MS };
