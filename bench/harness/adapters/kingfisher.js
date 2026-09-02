"use strict";

const fs = require("fs");
const path = require("path");
const { makeFinding } = require("../lib");

/**
 * Kingfisher (mongodb/kingfisher), filesystem scan, OFFLINE:
 *
 *   kingfisher scan <fixture home> --no-validate --format jsonl
 *       --no-dedup --no-rule-cache --no-update-check
 *
 * DUAL-MODE RULE (see also adapters/kingfisher-default-verification.js):
 * Kingfisher validates findings against provider APIs by default (its
 * README: "Validate discovered credentials against provider APIs to reduce
 * false positives"; its own top-level help calls it a tool to "Detect and
 * validate secrets"). Scoring recall in that default mode would conflate
 * the recall axis with the egress axis, so recall is scored in the tool's
 * OWN documented offline mode: `--no-validate` ("Disable secret
 * validation", its --help; the README shows `kingfisher scan ~/src/myrepo
 * --no-validate` under "Scan without validation"). The default mode's
 * scan-time egress is observed separately by the
 * kingfisher-default-verification adapter and reported factually.
 *
 * Flag rationale, each from its own --help:
 * - --format jsonl: machine-readable "JSON Lines (one JSON object per
 *   line)". The last line is a scan summary object (no `rule` key), which
 *   the parser skips.
 * - --no-dedup: "Display every occurrence of a finding". Kingfisher dedupes
 *   findings by default; this benchmark scores exposure SITES, and the tool
 *   documents this flag for exactly that reporting mode, so it gets its
 *   best shot at site recall. Detection is unchanged either way.
 * - --no-rule-cache: "Disable the compiled Vectorscan rule database cache".
 *   Verified on this machine: without it Kingfisher writes
 *   Library/Caches/kingfisher/rule-cache/*.vscdb under HOME, which the
 *   harness pins INSIDE the scanned fixture, and a scanner write into the
 *   scanned tree breaks the corpus's byte-identical guarantee (macOS cache
 *   resolution ignores the XDG_CACHE_HOME scratch pin). Cost is honest:
 *   wall time includes rule compilation on every run.
 * - --no-update-check: "Disable automatic update checks". Verified on this
 *   machine: even a --no-validate scan performs a version self-check by
 *   default (summary line: update_check_status "ok"). The scored offline
 *   scan must be network-free by the tool's own flags; the default-on
 *   update check is observed and reported on the egress axis by the
 *   default-verification run (same treatment as agentsweep's TTY update
 *   check in v1).
 *
 * Exit codes, from its README and observed: 0 no findings, 200 findings.
 * (205 = validated findings, unreachable with --no-validate.)
 *
 * Output (observed on the mini-fixture, bench/tools/samples/): one JSON
 * object per finding with rule.{id,name,title} (rule ids namespaced, e.g.
 * betterleaks.github-pat, veles.secrets/npmjsaccesstoken) and
 * finding.{snippet,line,path,confidence,entropy,fingerprint,validation}.
 * snippet carries the matched secret text unredacted by default (no
 * --redact is passed: scan-only, and the value enables exact-value
 * matching); line is 1-based and matched planted lines exactly in sample
 * runs (59/59 on the corpus probe).
 */

function binaryPath(ctx) {
  const pinned = path.join(ctx.toolsDir, "bin", "kingfisher");
  if (fs.existsSync(pinned)) return pinned;
  return "kingfisher"; // PATH fallback
}

function parseJsonlFindings(results, notes) {
  const findings = [];
  for (const r of results) {
    for (const line of (r.stdout || "").split("\n")) {
      if (!line.trim()) continue;
      let f;
      try {
        f = JSON.parse(line);
      } catch (e) {
        notes.push(`stdout line was not valid JSON (skipped): ${line.slice(0, 120)}`);
        continue;
      }
      if (!f.rule || !f.finding) {
        // Trailing scan-summary object; keep its update/validation counters
        // as evidence in the notes rather than dropping it silently.
        if (f.findings !== undefined) {
          notes.push(
            `scan summary: findings=${f.findings} rules_applied=${f.rules_applied} ` +
            `update_check=${f.kingfisher ? f.kingfisher.update_check_status : "n/a"} ` +
            `validations ok/fail/skip=${f.successful_validations}/${f.failed_validations}/${f.skipped_validations}`
          );
        }
        continue;
      }
      findings.push(
        makeFinding({
          file: f.finding.path || null,
          line: f.finding.line,
          rawRule: f.rule.id,
          value: f.finding.snippet || null,
          meta: {
            ruleName: f.rule.name,
            confidence: f.finding.confidence,
            entropy: f.finding.entropy,
            fingerprint: f.finding.fingerprint,
            validation: f.finding.validation ? f.finding.validation.outcome : null,
          },
        })
      );
    }
  }
  return findings;
}

module.exports = {
  id: "kingfisher",
  displayName: "Kingfisher",
  homepage: "https://github.com/mongodb/kingfisher",
  kind: "binary",

  claimedClasses: ["*"],
  claimsNote:
    "Kingfisher README: 'Kingfisher is an open source secret scanner and live secret validation tool built in Rust.' Its " +
    "scan command takes any 'file, directory, or local Git repository' (--help) and the README's quickstart scans a plain " +
    "directory, so every corpus class is in its claimed scope.",

  available(ctx) {
    const pinned = path.join(ctx.toolsDir, "bin", "kingfisher");
    if (fs.existsSync(pinned)) return { ok: true };
    return {
      ok: false,
      reason: "no pinned kingfisher at bench/tools/bin/kingfisher and none guaranteed on PATH",
      installHint:
        "download kingfisher-darwin-arm64.tgz from github.com/mongodb/kingfisher releases, verify its sha256 against the " +
        "digest in the release's multiple.intoto.jsonl sigstore attestation (and the tarball's own CHECKSUM-darwin-arm64.txt " +
        "for the inner binary), and extract the binary to bench/tools/bin/kingfisher (exact commands in " +
        "bench/tools/VERSIONS.md; install-time network fetch, not part of any scored scan)",
    };
  },

  version(ctx) {
    return { cmd: binaryPath(ctx), args: ["--version"] };
  },

  command(ctx) {
    return {
      cmd: binaryPath(ctx),
      args: [
        "scan", ctx.fixtureHome,
        "--no-validate",
        "--format", "jsonl",
        "--no-dedup",
        "--no-rule-cache",
        "--no-update-check",
      ],
      cwd: ctx.benchRoot,
      expectedExitCodes: [0, 200], // 0 = no findings, 200 = findings, by its own contract; 205 unreachable with --no-validate
      note:
        "SCORED OFFLINE MODE per the dual-mode rule: --no-validate is Kingfisher's own documented offline flag; " +
        "--no-update-check its documented update-check off-switch; --no-rule-cache keeps its compiled-rule cache write " +
        "out of the scanned fixture (verified: the default location is under HOME). Default-mode egress is observed by " +
        "the kingfisher-default-verification adapter.",
    };
  },

  parse(results) {
    const notes = [];
    const findings = parseJsonlFindings(results, notes);
    notes.push(
      "JSONL stdout parsed (rule.id, finding.path/line/snippet); the trailing summary object is recorded in these notes, " +
      "not emitted as a finding"
    );
    return { findings, notes };
  },

  // Shared with the default-verification variant so the two modes can never
  // drift apart in parsing.
  parseJsonlFindings,

  staticGrepRoots() {
    return { binary: true }; // compiled Rust binary; static source grep not applicable
  },
};
