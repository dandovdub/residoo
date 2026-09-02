"use strict";

const fs = require("fs");
const path = require("path");
const { makeFinding } = require("../lib");

/**
 * detect-secrets (Yelp, PyPI), installed once into bench/tools/uv
 * (install-time fetch, not scored) and executed from there with HOME pinned
 * into the fixture.
 *
 * SCORED IN ITS DOCUMENTED OFFLINE MODE (the dual-mode rule): detect-secrets
 * verifies some candidate secrets over the network by default. Its own CLI
 * help documents the off-switch: "-n, --no-verify  Disables additional
 * verification of secrets via network call." Recall is scored with -n so the
 * recall axis is never conflated with the egress axis; the default mode's
 * observed egress is recorded by the companion adapter
 * detect-secrets-default-verification.js and reported as its own labeled line.
 *
 * Invocation (its README's documented non-git form: "Scanning non-git
 * tracked files: detect-secrets scan test_data/ --all-files"):
 *
 *   detect-secrets scan --all-files -n <fixture home>
 *
 * It emits a baseline JSON document to stdout: {version, plugins_used,
 * filters_used, results, generated_at}. results is a dict keyed by file path
 * (relative to the invocation cwd) whose entries are
 * {type, filename, hashed_secret, is_verified, line_number}.
 *
 * Parser notes, from real observed output on the mini-fixture (v1.5.0):
 * - One entry per (file, hashed secret, plugin type). The baseline dedupes
 *   re-occurrences of the same secret within one file (line_number is the
 *   first occurrence), so a re-exposure at another line of the SAME file is
 *   aggregated; re-exposures in other files appear per file. The scorer's
 *   distinct-value metric guards this honestly, like whatileaked's dedup.
 * - No double-counting: each baseline entry becomes exactly one normalized
 *   finding. The same site reported by several plugins (e.g. AWSKeyDetector
 *   plus KeywordDetector plus Base64HighEntropyString) yields several
 *   entries; the scorer counts planted INSTANCES, so re-reports of a matched
 *   site are neither extra recall nor false positives. Entropy-plugin floods
 *   on chaff or unplanted text remain fully charged, as they should be:
 *   that is a legitimate result of running its default plugin set.
 * - Output is redacted by design: hashed_secret is a SHA-1 of the value, the
 *   raw secret is never printed. Findings carry value: null and are matched
 *   by the file+line tier (line_number is the physical 1-based line, verified
 *   against the mini-fixture manifest), never penalized for redaction.
 * - Exit code is 0 with or without findings (observed; the baseline workflow
 *   reserves nonzero for its pre-commit hook, not scan).
 *
 * SCAN-ONLY: never `detect-secrets audit`, never the hook, never a baseline
 * update. Plain `scan` with the default plugin set and default filters.
 */

function binPath(ctx) {
  return path.join(ctx.toolsDir, "uv", "bin", "detect-secrets");
}

module.exports = {
  id: "detect-secrets",
  displayName: "detect-secrets (Yelp)",
  homepage: "https://github.com/Yelp/detect-secrets",
  kind: "python",

  claimedClasses: ["*"],
  claimsNote:
    "detect-secrets README: 'detect-secrets is an aptly named module for (surprise, surprise) detecting secrets within a code base.' " +
    "Its documented non-git form scans any directory tree ('Scanning non-git tracked files: detect-secrets scan test_data/ --all-files'), " +
    "so like gitleaks it is a generic file scanner scored on every corpus class. It makes no AI-agent or transcript claims; scanning a " +
    "transcript tree requires aiming it at the directory explicitly, which is exactly what this benchmark does.",

  available(ctx) {
    const bin = binPath(ctx);
    return fs.existsSync(bin)
      ? { ok: true }
      : {
          ok: false,
          reason: `detect-secrets not installed at ${bin}`,
          installHint:
            "UV_TOOL_DIR=bench/tools/uv/tools UV_TOOL_BIN_DIR=bench/tools/uv/bin uv tool install detect-secrets==1.5.0 " +
            "(pinned to the benchmarked version; install-time network fetch, not part of any scored scan)",
        };
  },

  version(ctx) {
    return { cmd: binPath(ctx), args: ["--version"] };
  },

  command(ctx) {
    return {
      cmd: binPath(ctx),
      args: ["scan", "--all-files", "-n", ctx.fixtureHome],
      cwd: ctx.benchRoot,
      expectedExitCodes: [0], // 0 with or without findings (observed on the mini-fixture)
      note:
        "documented offline mode: -n / --no-verify is its own flag ('Disables additional verification of secrets via network call'); " +
        "default-mode egress is observed separately by the detect-secrets-default-verification adapter",
    };
  },

  parse(results, ctx) {
    const r = results[0];
    const notes = [];
    let doc;
    try {
      doc = JSON.parse(r.stdout);
    } catch (e) {
      return { findings: [], notes: [`stdout was not a valid baseline JSON document: ${e.message}`] };
    }
    const findings = [];
    const cwd = r.cwd || ctx.benchRoot;
    for (const entries of Object.values(doc.results || {})) {
      for (const e of entries) {
        findings.push(
          makeFinding({
            file: path.resolve(cwd, e.filename),
            line: e.line_number,
            rawRule: e.type, // its plugin's secret_type string, e.g. "AWS Access Key"
            value: null, // hashed_secret only (SHA-1); redacted by design, matched by file+line
            meta: { hashedSecret: e.hashed_secret, isVerified: e.is_verified === true },
          })
        );
      }
    }
    notes.push(
      `baseline: ${(doc.plugins_used || []).length} plugins enabled (default set), ${findings.length} result entries across ${Object.keys(doc.results || {}).length} files`
    );
    notes.push(
      "one finding per baseline entry (file + hashed secret + plugin type); same-file re-occurrences are deduped by the tool at the first line"
    );
    notes.push("redacted output (SHA-1 hashes only): matched via the file+line tier, never penalized for redaction");
    return { findings, notes };
  },

  staticGrepRoots(ctx) {
    // Its verification plugins import requests; that is capability, and the
    // scored -n run's dynamic layers measure conduct.
    return [path.join(ctx.toolsDir, "uv", "tools", "detect-secrets")];
  },
};
