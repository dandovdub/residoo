"use strict";

const { availableSources, ALL_SOURCES } = require("./sources");
const { scan } = require("./scan");
const { render, renderJson } = require("./report");

const HELP = `residoo — find secrets leaking through your AI agent's session history

  Coding agents (Claude Code, Cursor, Copilot, ...) write everything you do
  to a local transcript, including file contents your prompts touch — which
  means real credentials sitting in plaintext on disk, indefinitely, in a
  place nobody thinks to check. residoo scans those transcripts for them.

  It makes NO network calls, reads nothing but session transcripts, and
  changes nothing on disk. Findings are redacted in every output format.

Usage:
  residoo scan [options]

Options:
  --json                 machine-readable output (full detail, still redacted)
  --include-noisy        also run broad, false-positive-prone rules
  --include-suppressed    also show matches that looked like placeholder/example text
  --fail-on-find          exit code 1 if anything is found (for CI)
  --no-color            disable ANSI colour
  -h, --help            show this help

Sources checked on this machine: ${ALL_SOURCES.map((s) => s.label()).join(", ")}
`;

function main(argv) {
  const args = argv.slice(2);
  if (args.includes("-h") || args.includes("--help") || args.length === 0) {
    process.stdout.write(HELP);
    return 0;
  }

  const cmd = args[0];
  if (cmd !== "scan") {
    process.stderr.write(`Unknown command "${cmd}". Try "residoo --help".\n`);
    return 2;
  }

  const wantsJson = args.includes("--json");
  const includeNoisy = args.includes("--include-noisy");
  const includeSuppressed = args.includes("--include-suppressed");
  const failOnFind = args.includes("--fail-on-find");

  const sources = availableSources();
  if (sources.length === 0) {
    process.stderr.write(
      "No known transcript sources found on this machine.\n" +
      `Checked: ${ALL_SOURCES.map((s) => s.label()).join(", ")}.\n`
    );
    return 0;
  }

  const result = scan({ sources, includeNoisy, includeSuppressed });
  process.stdout.write((wantsJson ? renderJson(result) : render(result)) + "\n");

  return failOnFind && result.findings.length > 0 ? 1 : 0;
}

module.exports = { main };
