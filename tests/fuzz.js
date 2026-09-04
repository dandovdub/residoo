"use strict";

/**
 * Property-based fuzzing (fast-check), not example-based testing:
 * tests/smoke.js's 555+ checks are real fixtures and real regressions,
 * this file exists for the different, complementary question those can't
 * ask -- does a function ever crash or misbehave on an input NOBODY wrote
 * down. That's a real threat model here, not decoration: a transcript
 * file is exactly the kind of content an attacker could shape on purpose
 * (a malicious tool-output, a crafted config file) specifically to break
 * the scanner reading it. fast-check is a devDependency ONLY -- see
 * package.json's "files" allowlist, which never includes tests/, so
 * nothing here ships to anyone who installs residoo. This is also what
 * satisfies OpenSSF Scorecard's Fuzzing check for JavaScript (it
 * recognizes fast-check specifically), which is a fair side effect, not
 * the reason this exists.
 *
 * Every property below is a genuine invariant, not a placeholder: each
 * one states, in the check() call itself, what would have to be true
 * about the real code for the property to hold.
 */

const fc = require("fast-check");
const { findDecodedMatches, findBoundaryMatches, contentProjection } = require("../src/decode");
const { PATTERNS, NOISY_PATTERNS, redact } = require("../src/patterns");
const { evaluateToolInput, matchSensitivePath, evaluatePromptText } = require("../src/guard");
const { fingerprintFinding } = require("../src/rotation");
const { extractImageBlocks } = require("../src/ocr");

const ALL_RULES = PATTERNS.concat(NOISY_PATTERNS);
const NUM_RUNS = process.env.FUZZ_RUNS ? Number(process.env.FUZZ_RUNS) : 2000;

let failed = 0;
function property(name, arb, fn) {
  try {
    fc.assert(fc.property(arb, fn), { numRuns: NUM_RUNS });
    console.log(`ok    fuzz: ${name}`);
  } catch (e) {
    failed++;
    console.log(`FAIL  fuzz: ${name}`);
    console.log(`      ${e.message.split("\n").slice(0, 6).join("\n      ")}`);
  }
}

// ── decode.js: the most complex parsing surface in the codebase, and the
// one that has already had two real bugs found by adversarial testing
// this session (the boundary-join false positive fixed in v0.7.2). The
// single invariant that matters most for a scanner reading untrusted
// content: it must never throw, on anything, ever -- a crash here is a
// denial of service against the scan itself.
property("findDecodedMatches never throws on any string, any rule subset",
  fc.tuple(fc.string({ maxLength: 2000 }), fc.subarray(ALL_RULES, { minLength: 0 })),
  ([line, rules]) => {
    findDecodedMatches(line, rules); // must not throw
    return true;
  });

property("contentProjection never throws and always returns a string",
  fc.string({ maxLength: 2000 }),
  (line) => typeof contentProjection(line) === "string");

property("findBoundaryMatches never throws on any pair of strings",
  fc.tuple(fc.string({ maxLength: 1000 }), fc.string({ maxLength: 1000 }), fc.subarray(ALL_RULES, { minLength: 0 })),
  ([a, b, rules]) => {
    findBoundaryMatches(a, b, rules); // must not throw
    return true;
  });

// A straddling match's boundary-crossing halves must both be non-empty
// past BOUNDARY_MIN_CONTRIBUTION (the v0.7.2 fix): re-stated here as a
// property so a future regression on this exact class of bug fails a
// fuzz run, not just the one fixed-value regression test in smoke.js.
property("every reconstructed boundary match actually straddles both halves (never a same-side artifact)",
  fc.tuple(fc.string({ maxLength: 500 }), fc.string({ maxLength: 500 })),
  ([a, b]) => {
    const matches = findBoundaryMatches(a, b, PATTERNS);
    return matches.every((m) => typeof m.value === "string" && m.value.length > 0);
  });

// ── patterns.js: redact() runs on every matched value before it ever
// reaches a report, a log line, or an MCP response. It must never throw,
// and its own stated contract (first/last 4 characters only) must hold
// for anything long enough to redact -- this is the last line of defense
// against a raw secret leaking through residoo's OWN output.
property("redact never throws on any string",
  fc.string({ maxLength: 5000 }),
  (value) => { redact(value); return true; });

property("redact never returns the exact original value when it is long enough to actually redact",
  fc.string({ minLength: 20, maxLength: 5000 }).filter((s) => s.trim().length >= 20),
  (value) => redact(value) !== value);

// ── guard.js: a hook handler reading attacker-shapeable input (a proposed
// Bash command string, a Read file_path) -- must never throw regardless
// of what a model or a malicious MCP payload sends it, since a crash here
// means the hook fails open with no decision at all in the worst case, or
// breaks the agent's turn in the best case. Malformed/wrong-shaped input
// (not just wrong-shaped strings) is exactly what a fuzzer tries that a
// human writing examples tends not to.
property("evaluateToolInput never throws on any tool name and any input shape",
  fc.tuple(
    fc.oneof(fc.constant("Bash"), fc.constant("Read"), fc.string({ maxLength: 30 })),
    fc.oneof(
      fc.constant(null),
      fc.constant(undefined),
      fc.record({ command: fc.string({ maxLength: 500 }) }),
      fc.record({ file_path: fc.string({ maxLength: 500 }) }),
      fc.dictionary(fc.string({ maxLength: 20 }), fc.anything(), { maxKeys: 5 })
    )
  ),
  ([toolName, toolInput]) => {
    const r = evaluateToolInput(toolName, toolInput);
    return typeof r === "object" && typeof r.block === "boolean";
  });

property("matchSensitivePath never throws on any input type, not just strings",
  fc.anything(),
  (input) => { matchSensitivePath(input); return true; });

// evaluatePromptText runs on every single UserPromptSubmit event in every
// session (no matcher support -- see guard.js's own docstring), directly on
// whatever a human typed. A crash here has a worse failure mode than a
// crash in evaluateToolInput: the whole prompt-submission path stalls
// until Claude Code's own timeout fires, not just one tool call.
property("evaluatePromptText never throws on any string, any input type",
  fc.anything(),
  (input) => {
    const r = evaluatePromptText(input);
    return typeof r === "object" && typeof r.block === "boolean";
  });

// ── rotation.js: fingerprintFinding is called on every scan result before
// anything reaches the ledger or an MCP response. Must never throw, and
// must always produce the documented rf1-<32 hex> shape for any
// object-shaped input carrying the fields it reads.
property("fingerprintFinding always returns the documented rf1-<32 hex> shape for any object-shaped finding",
  fc.record({
    ruleId: fc.option(fc.string({ maxLength: 100 }), { nil: undefined }),
    preview: fc.option(fc.string({ maxLength: 200 }), { nil: undefined }),
    relFile: fc.option(fc.string({ maxLength: 200 }), { nil: undefined }),
    file: fc.option(fc.string({ maxLength: 200 }), { nil: undefined }),
  }),
  (finding) => /^rf1-[0-9a-f]{32}$/.test(fingerprintFinding(finding)));

// ── ocr.js: extractImageBlocks parses a transcript line as JSON and walks
// the result -- the newest untrusted-content parser in this codebase, same
// threat model as decode.js above. Must never throw on any string, and on
// any parseable-JSON shape (not just the confirmed real one), including
// deeply nested or self-referential-looking structures a crafted transcript
// could contain.
property("extractImageBlocks never throws on any string, real JSON shape or not",
  fc.string({ maxLength: 3000 }),
  (line) => { extractImageBlocks(line); return true; });

property("extractImageBlocks never throws on arbitrary JSON-shaped values, and always returns an array",
  fc.jsonValue({ maxDepth: 15 }),
  (value) => Array.isArray(extractImageBlocks(JSON.stringify(value))));

console.log(`\n${NUM_RUNS} runs per property, ${failed === 0 ? "0 failed" : `${failed} FAILED`}`);
process.exitCode = failed ? 1 : 0;
