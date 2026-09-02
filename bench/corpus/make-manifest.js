#!/usr/bin/env node
"use strict";

/**
 * Bridge: bench/corpus/truth.json -> bench/corpus/data/manifest.json
 * (the schemaVersion 1 contract in bench/harness/README.md).
 *
 * Deterministic: pure function of truth.json, no clock, no randomness.
 * Rerun after regenerating the corpus. The manifest lives in the fixture
 * ROOT (bench/corpus/data), next to home/, never inside home/, so it can
 * never contaminate a scan of the fixture home.
 *
 * Mapping decisions, stated so a hostile reader finds them answered:
 *
 * - Class ids are surface-first (transcript-* / agent-config-*) because
 *   claimed-scope scoring keys on what SURFACE a tool claims to scan.
 *   A tool that claims agent transcripts but not agent config files is
 *   scored "out of claimed scope" on agent-config-*, never zero.
 * - truth.json classes map 1:1 onto manifest classes, except PLANT-PLAIN,
 *   which splits by surface: transcript plants -> transcript-plain, the
 *   three config-file plants -> agent-config-plain.
 * - One planted entry per exposure LINE. A multi-line plant (echo
 *   re-exposures, split halves) is one distinct credential (distinctGroup =
 *   truth plant id) with several sites. Echo lines after the first are
 *   exposure "re-exposed". Split continuation lines are exposure
 *   "part-continuation", deliberately NOT "re-exposed": finding half a
 *   split credential is not the same phenomenon as finding a repeat, and
 *   the re-exposure metric must not be inflated by split halves.
 * - ruleFamily uses the same normalizer applied to every tool's rule ids
 *   (lib.familyFromRule), so family-tier matching compares like with like.
 * - Chaff gets ruleFamily "generic": when a scanner flags a git SHA or a
 *   sha256 hex string it does so under a generic/entropy rule, and the
 *   family-tier matcher should attribute that flag to the chaff instance
 *   (an honest false positive) rather than leave it dangling.
 */

const fs = require("fs");
const path = require("path");
const { familyFromRule } = require("../harness/lib");

const HERE = __dirname;
const truth = JSON.parse(fs.readFileSync(path.join(HERE, "truth.json"), "utf8"));

const CLASSES = {
  "transcript-plain": {
    kind: "secret",
    description: "credential in plain sight in a session transcript line (user paste, tool stdout, or file-read echo)",
  },
  "agent-config-plain": {
    kind: "secret",
    description: "credential in an agent config file (settings.local.json, .mcp.json)",
  },
  "transcript-json-nested": {
    kind: "secret",
    description: "credential nested inside JSON-in-JSON (tool input/result structures) in a transcript line",
  },
  "transcript-echo": {
    kind: "secret",
    description: "one credential re-exposed on several tool_result transcript lines of the same session",
  },
  "transcript-b64": {
    kind: "secret",
    hard: true,
    description: "credential present only base64-encoded in tool stdout (hard class: commonly missed by line-oriented scanners, defeated by decoding; scored separately)",
  },
  "transcript-split": {
    kind: "secret",
    hard: true,
    description: "credential split across two adjacent transcript lines, never contiguous (hard class: commonly missed by line-oriented scanners; scored separately)",
  },
  "suppress-placeholder": {
    kind: "suppress",
    description: "vendor-style placeholder or documented example value; flagging it as a real secret is a false positive",
  },
  "chaff-shaped": {
    kind: "chaff",
    description: "credential-shaped non-secret (git SHA, uuid, sha256 hex, base64 image fragment); flagging it is a false positive",
  },
};

function isConfig(file) {
  return !file.endsWith(".jsonl");
}

function classOf(plant) {
  switch (plant.class) {
    case "PLANT-PLAIN":
      return isConfig(plant.file) ? "agent-config-plain" : "transcript-plain";
    case "PLANT-JSON-NESTED": return "transcript-json-nested";
    case "PLANT-ECHO": return "transcript-echo";
    case "PLANT-B64": return "transcript-b64";
    case "PLANT-SPLIT": return "transcript-split";
    case "SUPPRESS-EXPECTED": return "suppress-placeholder";
    default: throw new Error("unknown truth class: " + plant.class);
  }
}

const planted = [];

for (const p of truth.plants) {
  const cls = classOf(p);
  const kind = CLASSES[cls].kind;
  const fam = familyFromRule(p.family);
  p.lines.forEach((line, i) => {
    const entry = {
      id: p.id + (p.lines.length > 1 ? String.fromCharCode(97 + i) : ""),
      truthId: p.id,
      class: cls,
      kind,
      ruleFamily: fam,
      value: p.value,
      file: p.file,
      line,
      distinctGroup: p.id,
      exposure:
        i === 0 ? "first" : p.class === "PLANT-SPLIT" ? "part-continuation" : "re-exposed",
    };
    if (kind !== "secret") entry.surfaceClass = isConfig(p.file) ? "agent-config-plain" : "transcript-plain";
    planted.push(entry);
  });
}

for (const c of truth.chaff) {
  c.lines.forEach((line, i) => {
    planted.push({
      id: c.id + (c.lines.length > 1 ? String.fromCharCode(97 + i) : ""),
      truthId: c.id,
      class: "chaff-shaped",
      kind: "chaff",
      ruleFamily: "generic",
      chaffKind: c.kind,
      value: c.value,
      file: c.file,
      line,
      distinctGroup: c.id,
      exposure: i === 0 ? "first" : "re-exposed",
      surfaceClass: isConfig(c.file) ? "agent-config-plain" : "transcript-plain",
    });
  });
}

// Ambiguity guards for the location-based matching tiers (see score.js):
// basename-only emitters disambiguate by line (tier 2); family-tier matching
// (tier 3) always sees full paths from the tools that use it. So the fatal
// collisions are same basename + same line, and same full file + same line.
const seen = new Map();
for (const e of planted) {
  const k = path.basename(e.file) + ":" + e.line;
  if (seen.has(k)) {
    throw new Error(`ambiguous plant sites: ${seen.get(k)} and ${e.id} share basename+line ${k}`);
  }
  seen.set(k, e.id);
}

const manifest = {
  schemaVersion: 1,
  seed: truth.seed,
  generator: "bench/corpus/generate.js + bench/corpus/make-manifest.js",
  note:
    "Derived deterministically from bench/corpus/truth.json. All values are synthetic pattern-true fakes; " +
    "none was ever issued by a provider. Lives in the fixture root, outside home/, so it never contaminates a scan.",
  classes: CLASSES,
  planted,
};

const out = path.join(HERE, "data", "manifest.json");
fs.writeFileSync(out, JSON.stringify(manifest, null, 2) + "\n");
console.log(`${out}: ${planted.length} planted site entries (${truth.plants.length} plants + ${truth.chaff.length} chaff from truth.json)`);
