"use strict";

const fs = require("fs");
const path = require("path");
const { makeFinding, stripAnsi } = require("../lib");

/**
 * whatileaked (npm), installed once into bench/tools/node (install-time
 * fetch, not scored) and executed directly via node from that cached copy,
 * so the monitored scan window contains no npx registry resolution.
 *
 * Its CLI has exactly two commands and no flags: scan and wipe. SCAN-ONLY
 * here, never wipe. Exit 0 = clean, 1 = findings (observed).
 *
 * Output is human text, parsed from the real format observed on the
 * mini-fixture (v0.3.0):
 *
 *   * aws-access-token  2 secrets
 *       f0b93847  project-name           sent 25 times
 *                 <masked context line>
 *                 ~/.claude/projects/.../file.jsonl
 *
 * It reports DISTINCT credentials (fingerprint-deduped), one representative
 * file per credential and no line numbers, so matching uses the
 * file+ruleFamily tier. Re-exposures of the same credential in other files
 * are aggregated into "sent N times"; the scorer's site-level metric
 * reflects that honestly (distinct-value recall can be full while
 * exposure-site recall is partial). Rule names are gitleaks rule ids by its
 * own documentation.
 */

function cliPath(ctx) {
  return path.join(ctx.toolsDir, "node", "node_modules", "whatileaked", "dist", "cli.js");
}

module.exports = {
  id: "whatileaked",
  displayName: "whatileaked",
  homepage: "https://www.npmjs.com/package/whatileaked",
  kind: "node",

  claimedClasses: ["transcript-*", "agent-memory-*"],
  claimsNote:
    "whatileaked README: scans local Claude Code, Codex and Cursor transcripts (plus memory files, per its own scan banner). " +
    "It claims agent transcripts, not agent config files or repo-resident files; those are out of claimed scope for it, not zeroes.",

  available(ctx) {
    const cli = cliPath(ctx);
    return fs.existsSync(cli)
      ? { ok: true }
      : {
          ok: false,
          reason: `whatileaked not installed at ${cli}`,
          installHint:
            "cd bench/tools/node && npm install whatileaked@0.3.0 " +
            "(install-time network fetch; not part of any scored scan)",
        };
  },

  version(ctx) {
    // No --version flag; report the installed package version from its manifest.
    const pkg = path.join(ctx.toolsDir, "node", "node_modules", "whatileaked", "package.json");
    return { literal: fs.existsSync(pkg) ? "whatileaked " + JSON.parse(fs.readFileSync(pkg, "utf8")).version : "unknown" };
  },

  command(ctx) {
    return {
      cmd: process.execPath,
      args: [cliPath(ctx), "scan"],
      cwd: ctx.benchRoot,
      expectedExitCodes: [0, 1], // 1 = findings (observed on the mini-fixture)
      note: "scan command only; the tool has no other scan options",
    };
  },

  parse(results, ctx) {
    const { stdout } = results[0];
    const notes = [];
    const findings = [];
    const lines = stripAnsi(stdout).split("\n");

    let currentRule = null;
    let pending = null; // {fingerprint, project, sentCount} awaiting its path line

    const flush = (file) => {
      if (!pending) return;
      if (file === null) {
        // An entry whose path line the parser could not pair is a HARNESS
        // parse gap, not tool conduct. Emitting it as a file:null finding
        // would score as an unplanted false positive against the tool, so
        // it is surfaced as a loud note instead and never charged.
        notes.push(
          `PARSE GAP (not charged to the tool): entry ${pending.fingerprint} under rule ${currentRule} had no ` +
          "recognizable path line; inspect results/raw/whatileaked.txt and fix the parser before trusting precision"
        );
        pending = null;
        return;
      }
      findings.push(
        makeFinding({
          file,
          line: null, // not reported by the tool
          rawRule: currentRule,
          value: null, // masked output only
          meta: { fingerprint: pending.fingerprint, project: pending.project, sentCount: pending.sentCount },
        })
      );
      pending = null;
    };

    for (const raw of lines) {
      const ruleM = raw.match(/^\* (\S+)\s+\d+ secrets?\s*$/);
      if (ruleM) { currentRule = ruleM[1]; continue; }

      const entryM = raw.match(/^\s{2,}([0-9a-f]{8})\s{2,}(\S+)\s+sent (once|\d+ times?)\s*$/);
      if (entryM && currentRule) {
        flush(null); // previous entry never got a path line: parse gap, noted above
        pending = {
          fingerprint: entryM[1],
          project: entryM[2],
          sentCount: entryM[3] === "once" ? 1 : parseInt(entryM[3], 10),
        };
        continue;
      }

      const pathM = raw.match(/^\s+(~\/\S+|\/\S+)\s*$/);
      if (pathM && pending) {
        let p = pathM[1];
        if (p.startsWith("~/")) p = path.join(ctx.fixtureHome, p.slice(2));
        flush(p);
        continue;
      }
    }
    flush(null);

    const header = lines.find((l) => l.includes("scanned") && l.includes("transcript"));
    if (header) notes.push(header.trim());
    notes.push("distinct-credential output: one representative file per fingerprint, no line numbers; matched via file+ruleFamily tier");
    return { findings, notes };
  },

  staticGrepRoots(ctx) {
    return [path.join(ctx.toolsDir, "node", "node_modules", "whatileaked")];
  },
};
