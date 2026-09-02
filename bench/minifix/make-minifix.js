#!/usr/bin/env node
"use strict";

/**
 * Mini-fixture generator for harness development and smoke tests.
 *
 * This is NOT the benchmark corpus. It exists so every adapter's parser is
 * built and tested against the tool's REAL output on a tiny, fully synthetic
 * input before the full corpus lands. Same rules as the corpus, though:
 *
 *   - 100% synthetic and deterministic from SEED. No real content, ever.
 *   - Every planted value is a pattern-true FAKE in the CredData style:
 *     correct prefix, charset, and length, but generated, never a real
 *     credential (AWS's own documented example key AKIAIOSFODNN7EXAMPLE is
 *     the canonical model and appears here as the suppress-class instance).
 *   - manifest.json follows the exact schema bench/harness/score.js scores
 *     against, so the scorer is exercised end to end.
 *
 * Regenerate with: node bench/minifix/make-minifix.js
 */

const fs = require("fs");
const path = require("path");

const SEED = 20260902;
const OUT = path.join(__dirname, "data");

// Deterministic PRNG (mulberry32). Math.random is banned here: two runs of
// this script must produce byte-identical fixtures or "reproducible" is a lie.
function mulberry32(a) {
  return function () {
    a |= 0; a = (a + 0x6D2B79F5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
const rand = mulberry32(SEED);

function pick(chars, n) {
  let s = "";
  for (let i = 0; i < n; i++) s += chars[Math.floor(rand() * chars.length)];
  return s;
}

const UPPER_NUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

// Pattern-true fakes, deterministic from SEED.
const FAKE_AWS_KEY = "AKIA" + pick(UPPER_NUM, 16);            // AKIA + 16 chars
const FAKE_GH_PAT = "ghp_" + pick(ALNUM, 36);                  // ghp_ + 36 chars
const SUPPRESS_AWS = "AKIAIOSFODNN7EXAMPLE";                   // AWS's documented example key
const CHAFF_NEAR_MISS = "AKIA" + pick(UPPER_NUM, 9);           // AKIA + 9 chars: too short to be a key

function jline(obj) { return JSON.stringify(obj); }

const projDir = path.join(OUT, "home", ".claude", "projects", "-Users-bench-webapp");
fs.rmSync(OUT, { recursive: true, force: true });
fs.mkdirSync(projDir, { recursive: true });

// File 1: first exposures. Line numbers below are load-bearing for the manifest.
const fileA = [
  jline({ type: "user", uuid: "mini-a-1", timestamp: "2026-09-01T09:00:00.000Z", message: { role: "user", content: "wire up the deploy script, creds below" } }),
  jline({ type: "user", uuid: "mini-a-2", timestamp: "2026-09-01T09:00:10.000Z", message: { role: "user", content: "export AWS_ACCESS_KEY_ID=" + FAKE_AWS_KEY + " and use eu-west-1" } }),
  jline({ type: "assistant", uuid: "mini-a-3", timestamp: "2026-09-01T09:00:20.000Z", message: { role: "assistant", content: [{ type: "text", text: "Done. Deploy script written." }] } }),
  jline({ type: "assistant", uuid: "mini-a-4", timestamp: "2026-09-01T09:00:30.000Z", message: { role: "assistant", content: [{ type: "text", text: "I also set GITHUB_TOKEN=" + FAKE_GH_PAT + " in the workflow env as you asked." }] } }),
].join("\n") + "\n";

// File 2: a re-exposure of the same AWS key, one suppress-class instance, one chaff instance.
const fileB = [
  jline({ type: "user", uuid: "mini-b-1", timestamp: "2026-09-01T11:00:00.000Z", message: { role: "user", content: "same bucket as this morning" } }),
  jline({ type: "assistant", uuid: "mini-b-2", timestamp: "2026-09-01T11:00:10.000Z", message: { role: "assistant", content: [{ type: "text", text: "Reusing AWS_ACCESS_KEY_ID=" + FAKE_AWS_KEY + " from the earlier session." }] } }),
  jline({ type: "user", uuid: "mini-b-3", timestamp: "2026-09-01T11:00:20.000Z", message: { role: "user", content: "the docs show AKIAIOSFODNN7EXAMPLE as the placeholder, keep that in the README" } }),
  jline({ type: "user", uuid: "mini-b-4", timestamp: "2026-09-01T11:00:30.000Z", message: { role: "user", content: "ticket ref " + CHAFF_NEAR_MISS + " is the shipment batch id, not a credential" } }),
].join("\n") + "\n";

fs.writeFileSync(path.join(projDir, "mini-chat-alpha.jsonl"), fileA);
fs.writeFileSync(path.join(projDir, "mini-chat-bravo.jsonl"), fileB);

const rel = (name) => path.join("home", ".claude", "projects", "-Users-bench-webapp", name);

const manifest = {
  schemaVersion: 1,
  seed: SEED,
  generator: "bench/minifix/make-minifix.js",
  note: "Mini-fixture for harness development. All values are pattern-true fakes, deterministic from seed. Not the benchmark corpus.",
  classes: {
    "transcript-user-paste": { kind: "secret", description: "credential pasted by the user into a transcript message" },
    "transcript-assistant-echo": { kind: "secret", description: "credential echoed back in an assistant message" },
    "chaff-near-miss": { kind: "chaff", description: "credential-shaped string that is not a credential (wrong length/charset); flagging it is a false positive" },
    "suppress-doc-example": { kind: "suppress", description: "vendor-documented example value; flagging it is a false positive" },
  },
  planted: [
    { id: "m01", class: "transcript-user-paste", kind: "secret", ruleFamily: "aws", value: FAKE_AWS_KEY, file: rel("mini-chat-alpha.jsonl"), line: 2, distinctGroup: "g-aws-1", exposure: "first" },
    { id: "m02", class: "transcript-assistant-echo", kind: "secret", ruleFamily: "github", value: FAKE_GH_PAT, file: rel("mini-chat-alpha.jsonl"), line: 4, distinctGroup: "g-gh-1", exposure: "first" },
    { id: "m03", class: "transcript-assistant-echo", kind: "secret", ruleFamily: "aws", value: FAKE_AWS_KEY, file: rel("mini-chat-bravo.jsonl"), line: 2, distinctGroup: "g-aws-1", exposure: "re-exposed" },
    // surfaceClass: the surface these non-secrets are embedded in, used for
    // claimed-scope decisions (a tool that claims transcripts is exposed to
    // transcript-resident chaff even though chaff is its own class).
    { id: "m04", class: "suppress-doc-example", kind: "suppress", ruleFamily: "aws", value: SUPPRESS_AWS, file: rel("mini-chat-bravo.jsonl"), line: 3, distinctGroup: "g-sup-1", exposure: "first", surfaceClass: "transcript-user-paste" },
    { id: "m05", class: "chaff-near-miss", kind: "chaff", ruleFamily: "aws", value: CHAFF_NEAR_MISS, file: rel("mini-chat-bravo.jsonl"), line: 4, distinctGroup: "g-chaff-1", exposure: "first", surfaceClass: "transcript-user-paste" },
  ],
};

fs.writeFileSync(path.join(OUT, "manifest.json"), JSON.stringify(manifest, null, 2) + "\n");
console.log("mini-fixture written to " + OUT);
console.log("planted:", manifest.planted.map((p) => p.id + ":" + p.class).join(", "));
