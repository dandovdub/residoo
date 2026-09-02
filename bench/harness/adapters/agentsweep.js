"use strict";

const fs = require("fs");
const path = require("path");
const { makeFinding } = require("../lib");

/**
 * agentsweep (PyPI), installed once into bench/tools/uv (install-time fetch,
 * not scored) and executed from there with HOME pinned into the fixture.
 *
 * agentsweep scans ONE agent's history per invocation (--source, default
 * claude-code; there is no --source all in 0.1.9). To give it its documented
 * best shot rather than only its default, the adapter probes the fixture for
 * each agent root agentsweep's own --source list covers and runs one scan
 * per source that actually exists in the fixture. All invocations run inside
 * the same monitored window; findings are aggregated. Which sources ran is
 * recorded in the parse notes so a re-runner can verify the exact commands.
 *
 * SCAN-ONLY: never `agentsweep fix` (its redact mode). Exit codes per its
 * docs: 0 clean, 1 findings, 2 error.
 */

// agentsweep --source value -> fixture-relative directory that signals the
// agent is present. Derived from agentsweep's own documented roots.
const SOURCE_PROBES = [
  ["claude-code", [".claude", "projects"]],
  ["codex", [".codex", "sessions"]],
  ["aider", [".aider"]],
  ["gemini-cli", [".gemini", "tmp"]],
  ["openclaw", [".openclaw"]],
  ["goose", [".local", "share", "goose"]],
  ["opencode", [".local", "share", "opencode"]],
  ["cline", [".cline"]],
];

function binPath(ctx) {
  return path.join(ctx.toolsDir, "uv", "bin", "agentsweep");
}

function presentSources(ctx) {
  const out = [];
  for (const [source, rel] of SOURCE_PROBES) {
    if (fs.existsSync(path.join(ctx.fixtureHome, ...rel))) out.push(source);
  }
  return out.length ? out : ["claude-code"]; // its own default when nothing probes
}

module.exports = {
  id: "agentsweep",
  displayName: "AgentSweep",
  homepage: "https://github.com/Ishannaik/agent-sweep",
  kind: "python",

  claimedClasses: ["transcript-*"],
  claimsNote:
    "agentsweep README: 'Find and redact secrets in your AI coding agent's local history' with an explicit --source list of agent " +
    "history roots. It claims agent transcripts/history, not agent config files or repo-resident files; those classes are out of " +
    "claimed scope for it, not zeroes.",

  available(ctx) {
    const bin = binPath(ctx);
    return fs.existsSync(bin)
      ? { ok: true }
      : {
          ok: false,
          reason: `agentsweep not installed at ${bin}`,
          installHint:
            "UV_TOOL_DIR=bench/tools/uv/tools UV_TOOL_BIN_DIR=bench/tools/uv/bin uv tool install agentsweep==0.1.9 " +
            "(pinned to the benchmarked version; install-time network fetch, not part of any scored scan)",
        };
  },

  version(ctx) {
    return { cmd: binPath(ctx), args: ["--version"] };
  },

  command(ctx) {
    const sources = presentSources(ctx);
    return sources.map((source) => ({
      cmd: binPath(ctx),
      args: ["scan", "--source", source, "--json"],
      cwd: ctx.benchRoot,
      expectedExitCodes: [0, 1], // 1 = findings, by its own contract
      note: `--source ${source} (fixture contains this agent's root)`,
    }));
  },

  parse(results) {
    const notes = [];
    const findings = [];
    for (const r of results) {
      notes.push(`invocation [${r.args.join(" ")}] exit=${r.exitCode}`);
      if (!r.stdout.trim()) continue;
      let doc;
      try {
        doc = JSON.parse(r.stdout);
      } catch (e) {
        notes.push(`stdout was not valid JSON for [${r.args.join(" ")}]: ${e.message}`);
        continue;
      }
      for (const f of doc || []) {
        findings.push(
          makeFinding({
            file: f.file,
            line: f.line,
            rawRule: f.rule,
            value: null, // masked output only (head/tail), kept in meta
            meta: { masked: f.masked, fingerprint: f.fingerprint, keypath: f.keypath, display: f.display },
          })
        );
      }
    }
    return { findings, notes };
  },

  staticGrepRoots(ctx) {
    return [path.join(ctx.toolsDir, "uv", "tools", "agentsweep")];
  },
};
