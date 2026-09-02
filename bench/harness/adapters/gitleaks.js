"use strict";

const fs = require("fs");
const path = require("path");
const { makeFinding } = require("../lib");

/**
 * gitleaks in filesystem mode: gitleaks dir <fixture home>
 *
 * `dir` is gitleaks' modern subcommand for scanning plain directories (the
 * invocation tools/VERSIONS.md documents); the legacy spelling
 * `detect --no-git --source <dir>` was verified to produce an identical
 * finding set (same rule/file/line/secret) on this corpus before the
 * adapter was aligned to `dir`.
 *
 * Uses the pinned binary in bench/tools/bin when present (version recorded),
 * falling back to a gitleaks on PATH. Parser reads the JSON report file
 * (RuleID / File / StartLine / Secret), which is gitleaks' stable machine
 * format. Exit code 1 means "leaks found" and is expected, not a failure.
 *
 * gitleaks is a general-purpose file scanner: its docs claim directory/file
 * scanning of anything on disk, so it is scored on every corpus class.
 */

function binaryPath(ctx) {
  const pinned = path.join(ctx.toolsDir, "bin", "gitleaks");
  if (fs.existsSync(pinned)) return pinned;
  return "gitleaks"; // PATH fallback
}

function reportPath(ctx) {
  return path.join(ctx.rawDir, "gitleaks.report.json");
}

module.exports = {
  id: "gitleaks",
  displayName: "gitleaks",
  homepage: "https://github.com/gitleaks/gitleaks",
  kind: "binary",

  claimedClasses: ["*"],
  claimsNote:
    "gitleaks README: detects secrets in files and directories (detect --no-git scans a directory tree, format-agnostic), " +
    "so every corpus class is in its claimed scope.",

  available(ctx) {
    const pinned = path.join(ctx.toolsDir, "bin", "gitleaks");
    if (fs.existsSync(pinned)) return { ok: true };
    return {
      ok: false,
      reason: "no pinned gitleaks at bench/tools/bin/gitleaks and none guaranteed on PATH",
      installHint: "place the official release binary at bench/tools/bin/gitleaks (see bench/tools/bin/README.md), or brew install gitleaks",
    };
  },

  version(ctx) {
    return { cmd: binaryPath(ctx), args: ["version"] };
  },

  command(ctx) {
    return {
      cmd: binaryPath(ctx),
      args: [
        "dir", ctx.fixtureHome,
        "--report-format", "json",
        "--report-path", reportPath(ctx),
        "--no-banner",
      ],
      cwd: ctx.benchRoot,
      expectedExitCodes: [0, 1], // 1 = leaks found, by gitleaks' own contract
      note: "filesystem (dir) mode over the fixture home; JSON report parsed from the report file",
    };
  },

  parse(results, ctx) {
    const notes = [];
    const rp = reportPath(ctx);
    if (!fs.existsSync(rp)) {
      return { findings: [], notes: [`no report file at ${rp}; stderr: ${results[0].stderr.slice(0, 300)}`] };
    }
    let doc;
    try {
      doc = JSON.parse(fs.readFileSync(rp, "utf8"));
    } catch (e) {
      return { findings: [], notes: [`report file was not valid JSON: ${e.message}`] };
    }
    const findings = (doc || []).map((f) =>
      makeFinding({
        file: path.isAbsolute(f.File) ? f.File : path.resolve(ctx.benchRoot, f.File),
        line: f.StartLine,
        rawRule: f.RuleID,
        value: f.Secret || null,
        meta: { entropy: f.Entropy, fingerprint: f.Fingerprint },
      })
    );
    return { findings, notes };
  },

  staticGrepRoots() {
    return { binary: true }; // compiled Go binary; static source grep not applicable
  },
};
