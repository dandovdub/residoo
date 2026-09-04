"use strict";

const fs = require("fs");
const path = require("path");
const { makeFinding } = require("../lib");

/**
 * residoo, run from this repository checkout: node bin/residoo.js scan --json
 *
 * Machine-scan mode with HOME pinned into the fixture, exactly how a user
 * runs it. Findings are redacted by design (basename + line + rule only),
 * so recall matching for residoo uses the file+line tier, never exact value.
 * That redaction also means residoo is scored on the same evidence any
 * hostile re-runner can verify from its raw output.
 */
module.exports = {
  id: "residoo",
  displayName: "residoo",
  homepage: "https://github.com/dandovdub/residoo",
  kind: "node",

  // Claim source: residoo's own help text and README: transcripts of coding
  // agents plus agent config locations. Machine mode deliberately does NOT
  // scan arbitrary project files (.env inside a repo checkout is --project
  // mode), so repo-file classes are out of claimed scope here, not zeroes.
  claimedClasses: ["transcript-*", "agent-config-*", "agent-memory-*"],
  claimsNote:
    "residoo --help: scans coding-agent session transcripts and agent config locations on the machine. " +
    "Repo-resident files (e.g. .env inside a project checkout) are claimed only by --project mode, which is not what this benchmark runs.",

  available(ctx) {
    const bin = path.join(ctx.repoRoot, "bin", "residoo.js");
    return fs.existsSync(bin)
      ? { ok: true }
      : { ok: false, reason: `residoo entrypoint not found at ${bin}` };
  },

  version(ctx) {
    // No --version flag; the checkout's package.json is the authoritative version.
    const pkg = path.join(ctx.repoRoot, "package.json");
    return { literal: "residoo " + JSON.parse(fs.readFileSync(pkg, "utf8")).version };
  },

  command(ctx) {
    return {
      cmd: process.execPath,
      args: [path.join(ctx.repoRoot, "bin", "residoo.js"), "scan", "--json"],
      cwd: ctx.repoRoot,
      expectedExitCodes: [0],
      note: "machine scan with HOME pinned into the fixture; --json output is redacted by design",
    };
  },

  parse(results) {
    const { stdout } = results[0];
    const notes = [];
    let doc;
    try {
      doc = JSON.parse(stdout);
    } catch (e) {
      return { findings: [], notes: [`stdout was not valid JSON: ${e.message}`] };
    }
    const findings = (doc.findings || []).map((f) =>
      makeFinding({
        file: f.file, // basename by design; matcher uses basename+line
        line: f.line,
        rawRule: f.rule,
        value: null, // redacted by design
        meta: { source: f.source, confidence: f.confidence, fingerprint: f.fingerprint, preview: f.preview },
      })
    );
    if (doc.summary) {
      notes.push(`filesScanned=${doc.summary.filesScanned} suppressedCount=${doc.summary.suppressedCount}`);
    }
    return { findings, notes };
  },

  staticGrepRoots(ctx) {
    return [path.join(ctx.repoRoot, "src"), path.join(ctx.repoRoot, "bin")];
  },
};
