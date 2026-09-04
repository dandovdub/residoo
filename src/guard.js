"use strict";

/**
 * `residoo guard`: a Claude Code PreToolUse hook that blocks an obviously-
 * sensitive file read before it happens, instead of finding the leak in the
 * transcript afterward.
 *
 * Scope, stated plainly because it is much narrower than "prevent secrets
 * from leaking": Claude Code's hooks API gives a PreToolUse hook the
 * PROPOSED tool input (a Bash command string, a Read file_path) before the
 * tool runs, and lets it deny the call outright -- but it never sees the
 * tool's OUTPUT, and by the time a PostToolUse hook fires, that output is
 * already committed to the transcript and can no longer be redacted. There
 * is no documented hook mechanism for "let the read happen, but strip the
 * secret out of what the model sees." So this can only block INPUT that
 * matches a known-sensitive file path pattern (.env, id_rsa, .aws/credentials,
 * and similar) -- it cannot catch a secret typed directly into a prompt, a
 * secret arriving in the output of an otherwise-unremarkable command
 * (curl, a build log), or any file path this pattern list does not name.
 * `residoo scan`/`watch`/`mcp` remain the actual safety net; this is a
 * narrower, best-effort tripwire on top, not a replacement for them.
 *
 * Fails safe in the direction of NOT blocking on any uncertainty: a
 * malformed hook payload, an unrecognized tool name, or a parse error all
 * fall through to "allow" (no stdout, exit 0) rather than denying a call
 * this module does not understand. The one thing this module must never do
 * is silently hang or crash the agent's turn over a tool call that was
 * always going to be fine.
 */

// A matched path fragment must be preceded by a path separator or the start
// of the string, and followed by either the end of the string (the common
// case for Read's file_path) or a shell metacharacter/whitespace (the case
// for a Bash command string, where the path is one argument among several,
// e.g. "cat .env && echo done"). Applying this uniformly, rather than a
// bespoke `$`-anchor per pattern, is what makes every entry below work
// identically for both tool_input shapes.
const BOUNDARY = "(?:$|[\\s'\"`;|&)<>])";
// Left boundary: start of string, a path separator (mid-path, e.g.
// "/foo/.env"), OR whitespace/a shell metacharacter (the path is one
// argument in a longer command, e.g. "cat .env && echo done" -- ".env" is
// preceded by a space, not a separator).
const SEP = "(?:^|[\\s'\"`;|&(<>\\\\/])";
const pat = (body) => new RegExp(SEP + body + BOUNDARY, "i");

const SENSITIVE_PATH_PATTERNS = [
  // dotenv files, including staged/numbered variants (.env.local, .env.1)
  { re: pat("\\.env(?:\\.[\\w.-]+)?"), label: "a .env file" },
  // SSH private keys: the conventional default names, and any *.pem/*.key
  { re: pat("id_(?:rsa|dsa|ecdsa|ed25519)(?:\\.pub)?"), label: "an SSH private key" },
  { re: new RegExp(SEP + "\\.ssh[\\\\/]", "i"), label: "the SSH directory" },
  { re: pat("[\\w.-]+\\.pem"), label: "a .pem key file" },
  { re: pat("[\\w.-]+\\.key"), label: "a .key file" },
  // cloud / vendor credential files with a fixed, well-known name
  { re: pat("\\.aws[\\\\/](?:credentials|config)"), label: "the AWS credentials file" },
  { re: pat("\\.netrc"), label: "the .netrc file" },
  { re: pat("\\.npmrc"), label: "the .npmrc file (may hold a publish token)" },
  { re: pat("\\.git-credentials"), label: "the git-credentials file" },
  { re: pat("\\.docker[\\\\/]config\\.json"), label: "the Docker config (may hold registry auth)" },
  { re: pat("\\.kube[\\\\/]config"), label: "the kubeconfig file" },
  { re: pat("application_default_credentials\\.json"), label: "gcloud application-default credentials" },
  { re: pat("credentials\\.json"), label: "a credentials.json file" },
  { re: pat("service[_-]?account[\\w.-]*\\.json"), label: "a GCP service-account key file" },
  { re: pat("secrets?\\.(?:json|ya?ml)"), label: "a secrets file" },
];

/** True if `text` (a file path, or a whole shell command string) contains a recognizable sensitive-path match. Returns the matched label or null. */
function matchSensitivePath(text) {
  if (typeof text !== "string" || !text) return null;
  for (const { re, label } of SENSITIVE_PATH_PATTERNS) {
    if (re.test(text)) return label;
  }
  return null;
}

const GUARDED_TOOL_NAMES = new Set(["Bash", "Read"]);

/**
 * Pure decision function: given a PreToolUse hook payload's tool_name and
 * tool_input, decide whether to block. No I/O, fully unit-testable.
 */
function evaluateToolInput(toolName, toolInput) {
  if (!GUARDED_TOOL_NAMES.has(toolName) || !toolInput || typeof toolInput !== "object") {
    return { block: false, reason: null };
  }
  const candidate = toolName === "Bash" ? toolInput.command : toolInput.file_path;
  const label = matchSensitivePath(candidate);
  if (!label) return { block: false, reason: null };
  return {
    block: true,
    reason: `residoo guard: this looks like a read of ${label}. Blocked before it could be written to the session transcript. ` +
      `If this is intentional and safe, ask the human to read it themselves, or disable this hook in .claude/settings.json.`,
  };
}

/**
 * Reads one PreToolUse hook payload from `input` (default stdin), decides,
 * and writes the hook's own JSON response protocol to `output` (default
 * stdout) -- exit code is the caller's job (bin/residoo.js), this returns
 * the intended process exit code instead of calling process.exit itself,
 * matching every other run* function in cli.js.
 */
async function runGuard({ input = process.stdin, output = process.stdout } = {}) {
  const chunks = [];
  for await (const chunk of input) chunks.push(chunk);
  const raw = Buffer.concat(chunks.map((c) => (Buffer.isBuffer(c) ? c : Buffer.from(c)))).toString("utf-8");

  let payload;
  try {
    payload = JSON.parse(raw);
  } catch {
    return 0; // malformed payload: fail open, never block on something we can't parse
  }

  const decision = evaluateToolInput(payload.tool_name, payload.tool_input);
  if (!decision.block) return 0;

  output.write(JSON.stringify({
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision: "deny",
      permissionDecisionReason: decision.reason,
    },
  }) + "\n");
  return 0;
}

module.exports = { evaluateToolInput, matchSensitivePath, runGuard, SENSITIVE_PATH_PATTERNS };
