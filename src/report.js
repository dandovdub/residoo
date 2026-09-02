"use strict";

const path = require("path");

// Minimal raw ANSI — no chalk, no deps. A security tool asking you to trust
// a pile of third-party packages before it's even scanned anything is a bad
// first impression; residoo ships with zero runtime dependencies.
const c = {
  reset: "\x1b[0m", bold: "\x1b[1m", dim: "\x1b[2m",
  red: "\x1b[31m", yellow: "\x1b[33m", green: "\x1b[32m", cyan: "\x1b[36m",
};
// Read fresh on every call, not once at require() time. cli.js sets NO_COLOR
// in response to --no-color AFTER this module is already required — a module-
// level const here would freeze the pre-flag value and silently ignore the
// flag. Verified: with the const version, forcing NO_COLOR post-require still
// rendered ANSI codes.
function supportsColor() { return process.stdout.isTTY && process.env.NO_COLOR === undefined; }
const paint = (code, s) => (supportsColor() ? `${code}${s}${c.reset}` : s);

function ageDays(mtimeMs) {
  return Math.max(0, Math.floor((Date.now() - mtimeMs) / 86400000));
}

function render({ findings, filesScanned, sourcesScanned, bytesScanned, suppressedCount = 0, distinctCounts = {}, unreadableFiles = [] }) {
  const lines = [];
  const push = (s = "") => lines.push(s);

  const suppressedNote = suppressedCount > 0
    ? paint(c.dim, ` (${suppressedCount} more matched but looked like placeholder/example text — see --include-suppressed)`)
    : "";
  // Surfaced, not silent: a file that couldn't be read was NOT scanned, and a
  // clean report must not read as "checked and found nothing" for it.
  const unreadableNote = unreadableFiles.length > 0
    ? paint(c.yellow, `⚠  ${unreadableFiles.length} file(s) could not be read and were NOT scanned — see --json for paths.`)
    : null;

  if (findings.length === 0) {
    push(paint(c.green + c.bold, "✓ No exposed secrets found") +
      ` — ${filesScanned} file${filesScanned === 1 ? "" : "s"} scanned across ${sourcesScanned.join(", ") || "no sources"}.` +
      suppressedNote);
    if (unreadableNote) push(unreadableNote);
    return lines.join("\n");
  }

  // Group by rule for the headline counts.
  const byRule = new Map();
  for (const f of findings) {
    if (!byRule.has(f.ruleId)) byRule.set(f.ruleId, { label: f.label, confidence: f.confidence, items: [] });
    byRule.get(f.ruleId).items.push(f);
  }
  const byFile = new Map();
  for (const f of findings) byFile.set(f.file, (byFile.get(f.file) || 0) + 1);
  const oldest = findings.reduce((a, b) => (b.fileMTimeMs < a ? b.fileMTimeMs : a), Date.now());
  const newest = findings.reduce((a, b) => (b.fileMTimeMs > a ? b.fileMTimeMs : a), 0);

  push();
  push(paint(c.red + c.bold, `⚠  ${findings.length} potential secret${findings.length === 1 ? "" : "s"} found`) +
    ` across ${byFile.size} file${byFile.size === 1 ? "" : "s"}`);
  push(paint(c.dim, `   ${filesScanned} files scanned (${(bytesScanned / 1024 / 1024).toFixed(1)} MB) · sources: ${sourcesScanned.join(", ")}`));
  push(paint(c.dim, `   oldest match ~${ageDays(oldest)}d old · most recent ~${ageDays(newest)}d old`) + suppressedNote);
  if (unreadableNote) push(unreadableNote);
  push();

  const sorted = [...byRule.entries()].sort((a, b) => b[1].items.length - a[1].items.length);
  for (const [ruleId, { label, confidence, items }] of sorted) {
    const tag = confidence === "high" ? paint(c.red, "high") : confidence === "medium" ? paint(c.yellow, "med ") : paint(c.dim, "low ");
    const distinct = distinctCounts[ruleId];
    const distinctNote = distinct && distinct !== items.length
      ? paint(c.dim, `  (${distinct} distinct value${distinct === 1 ? "" : "s"}, re-exposed ${items.length - distinct}× across tool output)`)
      : "";
    push(`  ${paint(c.bold, String(items.length).padStart(4))}  [${tag}]  ${label}${distinctNote}`);
  }

  push();
  push(paint(c.bold, "By file:"));
  const fileRows = [...byFile.entries()].sort((a, b) => b[1] - a[1]).slice(0, 15);
  for (const [file, count] of fileRows) {
    push(`  ${String(count).padStart(4)}  ${paint(c.cyan, path.basename(file))}`);
  }
  if (byFile.size > fileRows.length) push(paint(c.dim, `  … and ${byFile.size - fileRows.length} more file(s)`));

  push();
  push(paint(c.dim, "Values are redacted in this report — first/last 4 characters only. Nothing scanned"));
  push(paint(c.dim, "here left your machine; residoo makes no network calls. Run with --json for full detail."));

  return lines.join("\n");
}

function renderJson(result) {
  return JSON.stringify(
    {
      summary: {
        findingCount: result.findings.length,
        filesScanned: result.filesScanned,
        filesWithFindings: new Set(result.findings.map((f) => f.file)).size,
        sourcesScanned: result.sourcesScanned,
        bytesScanned: result.bytesScanned,
        suppressedCount: result.suppressedCount || 0,
        unreadableFiles: result.unreadableFiles || [],
      },
      findings: result.findings.map((f) => ({
        rule: f.ruleId, label: f.label, confidence: f.confidence,
        source: f.source, file: f.relFile, line: f.line, preview: f.preview,
      })),
    },
    null,
    2
  );
}

module.exports = { render, renderJson };
