"use strict";

const { scanZeroWidth } = require("./integrity");

/**
 * Prompt-injection signature detection, applied to the SAME transcript
 * content every other pass already reads (tool_result blocks, fetched-page
 * text, file contents an agent read, ordinary message text) -- no new
 * source, no new file walk, just a second/third rule set matched against
 * lines scan.js already has in memory. Opt-in via `--include-injection`,
 * the same "different risk category, not a lower-confidence secret"
 * reasoning pii.js's own header states for `--include-pii`.
 *
 * WHAT THIS IS NOT, stated up front because it is the single most important
 * scope distinction here: this is NOT a static-analysis scanner for an LLM
 * APPLICATION'S OWN SOURCE CODE (an f-string concatenating user input into a
 * prompt, unsanitized external content reaching a prompt template). That is
 * a real, different product -- it's what Medusa's own PI-SCAN does (checked
 * directly against Medusa's own docs/AI_SECURITY.md, fetched 2026-09-05:
 * "Direct Injection: f-string interpolation with user_input... Indirect
 * Injection: External content fetched and embedded in prompts without
 * sanitization" -- both examples are about auditing an application's PROMPT
 * -CONSTRUCTION code for a latent vulnerability class). residoo has no
 * access to that code and isn't built to read it; what residoo already has,
 * uniquely, is the agent's own TRANSCRIPT -- a record of what actually got
 * fed to a live agent. So this module detects INJECTION PAYLOADS THAT
 * ALREADY REACHED AN AGENT, sitting in the same at-rest data every other
 * residoo pass scans -- a genuinely different, arguably more valuable
 * signal (a realized attempt, not a hypothetical vulnerable code path), not
 * an attempt to clone Medusa's SAST feature with a worse implementation.
 *
 * SIGNAL SOURCES, verified 2026-09-05:
 *
 *   - **Special/role-token injection**: `<|im_start|>`, `<|im_end|>`,
 *     `<|system|>`, `<|user|>`, `<|assistant|>`, `<|endoftext|>`,
 *     `<|endofprompt|>`, `[INST]`/`[/INST]`, `<<SYS>>`/`<</SYS>>` -- the
 *     control tokens chat-templated models use to delineate a message's
 *     ROLE. An attacker who gets one of these into content an agent reads
 *     (a fetched webpage, a file, a tool's output) can, on a vulnerable
 *     serving pipeline, make the model treat injected text as a new
 *     system/assistant turn rather than untrusted data. This is a named,
 *     real technique -- "Special Token Injection" (Sentry's own STI attack
 *     guide, blog.sentry.security/special-token-injection-sti-attack-guide,
 *     fetched directly: "the model expects certain token patterns to
 *     signify roles... if the... pipeline does not properly filter or
 *     escape these sequences, an attacker's input will reach the model...
 *     analogous to injecting a SQL query via an input field"), corroborated
 *     by OWASP's LLM01 Prompt Injection entry (genai.owasp.org) and a 2026
 *     arXiv paper specifically on chat-template abuse for indirect
 *     injection ("ChatInject: Abusing Chat Templates for Prompt Injection
 *     in LLM Agents," arxiv.org/abs/2509.22830) -- not one vendor's
 *     unverified claim. Medusa's own docs name this same technique family
 *     ("Code-Level Prompt Injection... ChatML tokens, role manipulation"),
 *     confirming it's a real, converged-upon signal, not something invented
 *     here. HIGH confidence: these exact token strings essentially never
 *     appear in ordinary prose or code by accident -- the honest, disclosed
 *     exception is a message that *discusses* these tokens by name (a
 *     tokenizer bug report, this very file's own docstring) rather than
 *     attempting to use them, the same "a real key a user pasted to ask
 *     about it" false-positive class patterns.js's private_key_block rule
 *     already carries.
 *   - **Hidden/invisible Unicode**: reuses `scanZeroWidth` from
 *     `integrity.js` verbatim (see that function's own docstring for the
 *     TrapDoor campaign citation and the always-suspicious/context-
 *     dependent tiering) -- extended here to every line of every
 *     transcript this project reads, not only the fixed CLAUDE.md/memory-
 *     file locations `checkIntegrity` already covers. This closes a real
 *     gap in the existing coverage: a hidden instruction delivered via a
 *     fetched web page or a tool's own output lands in ordinary transcript
 *     content, not in one of `checkIntegrity`'s known config paths, so the
 *     existing check cannot see it.
 *
 * NOISY_INJECTION_PATTERNS (opt-in ADDITIONALLY via `--include-noisy`,
 * exactly mirroring patterns.js's own NOISY_PATTERNS contract -- "broader,
 * shape-based patterns that catch more but false-positive more often"):
 * a small set of the most-cited canonical instruction-override phrases
 * ("ignore previous instructions" and its close variants). Disclosed
 * plainly, not glossed over: phrase-based matching is genuinely prone to
 * matching a security-research conversation, a GitHub issue about prompt
 * injection, or this very codebase's own documentation discussing the
 * technique -- OWASP's own LLM01 page and multiple practitioner write-ups
 * (Simon Willison's "prompt injection" writing among them) describe
 * reliable phrase-based detection as an open, unsolved problem, not
 * something this rule set claims to have solved. LOW confidence, never
 * part of the default report, for exactly that reason.
 *
 * WHAT THIS DOES NOT COVER, stated rather than silently gapped: tool-
 * DESCRIPTION poisoning (a malicious MCP server changing a tool's
 * description after approval, "rug-pull") is a real, named technique
 * (Medusa's own "Tool Poisoning (MCP101)") that this module cannot check,
 * because a tool's description is part of the MCP protocol payload sent to
 * the model at request time, not something Claude Code's own transcript
 * JSONL logs — verified directly against a real transcript on this
 * project's own build machine: a `tool_use` record for an
 * `mcp__`-namespaced tool carries only `{name, input}`, never the tool's
 * description or input schema. Checking that would require a live MCP
 * client connection to query `tools/list`, a fundamentally different
 * architecture (an active protocol client, not a file scanner) that this
 * project has not built and is not attempting to fake here.
 */

const CHATML_TOKEN_RE = /<\|(?:im_start|im_end|system|user|assistant|endoftext|endofprompt)\|>|\[\/?INST\]|<<\/?SYS>>/g;

const INJECTION_PATTERNS = [
  { id: "chatml_special_token", label: "Special/role-token injection (ChatML or similar)", confidence: "high" },
  { id: "zero_width_hidden_instruction", label: "Hidden instruction carried by invisible Unicode", confidence: "high" },
];

const NOISY_INJECTION_PATTERNS = [
  {
    id: "injection_override_phrase", label: "Instruction-override phrase (heuristic)", confidence: "low",
    // Deliberately narrow: the small set of phrasings cited across OWASP's
    // LLM01 page and independent practitioner write-ups as the canonical
    // "ignore what came before" injection framing, not an attempt at
    // exhaustive jailbreak-phrase coverage (see module docstring on why
    // phrase-based detection stays opt-in and low-confidence).
    re: /\b(?:ignore|disregard)\s+(?:all\s+|any\s+)?(?:the\s+|your\s+)?(?:previous|prior|above|earlier)\s+instructions\b|\bforget\s+(?:everything|all)\s+(?:above|before\s+this)\b/gi,
  },
];

/**
 * Minimal per-line invisible-character summary: codepoint name + count,
 * no line-number list (unlike integrity.js's summarizeZeroWidth, which is
 * built for a whole-file, many-line summary) -- the caller already has the
 * real line number for this one call, so repeating it here would just be
 * confusing "(line 1)" noise from scanZeroWidth's own internal, line-blind
 * counting of a single line with no embedded newline.
 */
function summarizeInvisibles(hits) {
  const byCp = new Map();
  for (const h of hits) byCp.set(h.cp, (byCp.get(h.cp) || 0) + 1);
  const parts = [];
  for (const [cp, count] of byCp) {
    parts.push("U+" + cp.toString(16).toUpperCase().padStart(4, "0") + " ×" + count);
  }
  return parts.join(", ");
}

module.exports = { INJECTION_PATTERNS, NOISY_INJECTION_PATTERNS, CHATML_TOKEN_RE, summarizeInvisibles };
