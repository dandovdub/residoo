"use strict";

/**
 * Detection rules for residoo.
 *
 * Every rule is high-confidence by design: a security tool that cries wolf gets
 * uninstalled. Broad, noisy patterns (bare "password=" style matches) are
 * deliberately left out of the default set rather than included and caveated —
 * see NOISY_PATTERNS below if you want them anyway via --include-noisy.
 *
 * `confidence: "high"` = the shape is specific enough that a match is almost
 * certainly real (a vendor-prefixed token format). `confidence: "medium"` =
 * shape-based, occasionally a placeholder or test fixture.
 */

const PATTERNS = [
  { id: "aws_access_key_id", label: "AWS Access Key ID", confidence: "high",
    re: /\bAKIA[0-9A-Z]{16}\b/g },
  { id: "aws_session_token", label: "AWS Temporary Access Key ID", confidence: "high",
    re: /\bASIA[0-9A-Z]{16}\b/g },
  { id: "private_key_block", label: "Private key block", confidence: "high",
    re: /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/g },
  { id: "github_pat", label: "GitHub personal access token", confidence: "high",
    re: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/g },
  { id: "gitlab_pat", label: "GitLab personal access token", confidence: "high",
    re: /\bglpat-[A-Za-z0-9_-]{20,}\b/g },
  { id: "slack_token", label: "Slack token", confidence: "high",
    re: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/g },
  { id: "stripe_key", label: "Stripe API key", confidence: "high",
    re: /\b(sk|rk)_live_[A-Za-z0-9]{20,}\b/g },
  // The negative lookahead keeps this rule and anthropic_key mutually exclusive —
  // without it, "sk-ant-..." matches BOTH patterns and gets reported twice under
  // two different (one wrong) provider labels. Verified: both regexes independently
  // matched a synthetic sk-ant- key before this fix.
  { id: "openai_key", label: "OpenAI API key", confidence: "high",
    re: /\bsk-(?!ant-)(proj-)?[A-Za-z0-9_-]{20,}\b/g },
  { id: "anthropic_key", label: "Anthropic API key", confidence: "high",
    re: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g },
  { id: "google_api_key", label: "Google / Firebase API key", confidence: "high",
    re: /\bAIza[0-9A-Za-z_-]{35}\b/g },
  { id: "npm_token", label: "npm access token", confidence: "high",
    re: /\bnpm_[A-Za-z0-9]{36}\b/g },
  { id: "sendgrid_key", label: "SendGrid API key", confidence: "high",
    re: /\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b/g },
  { id: "twilio_key", label: "Twilio API key", confidence: "high",
    re: /\bSK[a-f0-9]{32}\b/g },
  { id: "jwt", label: "JWT-shaped token", confidence: "medium",
    re: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g },
  { id: "connection_string_with_password", label: "Database connection string with embedded password", confidence: "high",
    re: /\b(postgres(?:ql)?|mysql|mongodb(?:\+srv)?):\/\/[^\s:@\/]+:[^\s@\/]{3,}@[^\s\/]+/g },
  { id: "bearer_header", label: "Authorization: Bearer header with a real-looking token", confidence: "medium",
    re: /\bauthorization["']?\s*[:=]\s*["']?bearer\s+[A-Za-z0-9._-]{16,}/gi },
  { id: "refresh_token_field", label: "refresh_token field", confidence: "medium",
    re: /"refresh_token"\s*:\s*"[^"\s]{20,}"/gi },
  { id: "access_token_field", label: "access_token field", confidence: "medium",
    re: /"access_token"\s*:\s*"[^"\s]{20,}"/gi },
];

/**
 * Broader, shape-based patterns that catch more but false-positive more often —
 * a bare `password = "..."` line is frequently a placeholder, a variable name,
 * or documentation. Opt-in only, never part of the headline count.
 */
const NOISY_PATTERNS = [
  { id: "generic_password_assignment", label: "password / pwd assignment", confidence: "low",
    re: /\b(password|passwd|pwd)\s*[:=]\s*["']?[^\s"']{6,}["']?/gi },
  { id: "generic_secret_assignment", label: "generic secret / apikey assignment", confidence: "low",
    re: /\b(api[_-]?key|secret)\s*[:=]\s*["']?[A-Za-z0-9_\-\/+=]{12,}["']?/gi },
];

/**
 * Strip C0 control characters (0x00-0x1F) and DEL (0x7F) — this is where ANSI
 * escape sequences live. Two of the rules above (connection strings, the
 * *_token_field rules) match against a negated character class that excludes
 * whitespace and quotes but NOT control bytes, so a crafted or malformed
 * transcript line could otherwise put a raw terminal-control sequence into
 * this tool's own report output. Verified: an unsanitized preview containing
 * "\x1b[2J" actually clears the screen when printed. Applied here, at the
 * one place raw matched text turns into displayable text, rather than left
 * to every call site to remember.
 */
function stripControlChars(s) {
  let out = "";
  for (const ch of s) {
    const code = ch.codePointAt(0);
    if (code >= 0x20 && code !== 0x7f) out += ch;
  }
  return out;
}

/** Mask a matched value for display: never print secret material to a terminal. */
function redact(value) {
  const v = stripControlChars(String(value));
  // Split by code point (spread, not .slice/.length) — several rules match via
  // negated character classes that don't exclude non-ASCII, so a matched value
  // CAN contain an astral character (surrogate pair) straddling a UTF-16 cut
  // point. .slice(0,4) on the raw string can then return one half of a pair,
  // rendering as a broken glyph. Array.from(v) counts code points, not units.
  const cps = Array.from(v);
  if (cps.length <= 10) return "*".repeat(cps.length || 1);
  return cps.slice(0, 4).join("") + "…" + cps.slice(-4).join("") + `  (${String(value).length} chars)`;
}

module.exports = { PATTERNS, NOISY_PATTERNS, redact };
