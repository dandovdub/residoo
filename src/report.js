"use strict";

const path = require("path");

// Minimal raw ANSI — no chalk, no deps. A security tool asking you to trust
// a pile of third-party packages before it's even scanned anything is a bad
// first impression; residoo ships with zero runtime dependencies.
const c = {
  reset: "\x1b[0m", bold: "\x1b[1m", dim: "\x1b[2m",
  red: "\x1b[31m", yellow: "\x1b[33m", green: "\x1b[32m", cyan: "\x1b[36m",
};
// Read fresh on every call, not once at require() time — a module-level
// const would freeze whatever the environment was at require() time, before
// cli.js has even parsed argv. `forceNoColor` is how cli.js's --no-color
// flag actually reaches this function: as an explicit per-call argument, not
// by mutating process.env.NO_COLOR. `main()` is an exported function, not
// only a one-shot CLI entrypoint — a mutated env var would leak into any
// later call in the same process (a test runner, a wrapper CLI reusing it)
// and silently disable color for calls that never asked for that.
function supportsColor(forceNoColor) {
  return !forceNoColor && process.stdout.isTTY && process.env.NO_COLOR === undefined;
}
function makePaint(forceNoColor) {
  return (code, s) => (supportsColor(forceNoColor) ? `${code}${s}${c.reset}` : s);
}

function ageDays(mtimeMs) {
  return Math.max(0, Math.floor((Date.now() - mtimeMs) / 86400000));
}

/**
 * The integrity section — findings from src/integrity.js, rendered in the
 * same visual language as the scan report. Severity drives everything:
 * "warn" (a verified campaign signature, or a location that exists but
 * couldn't be verified) paints red and counts toward --fail-on-find; "info"
 * (a hook/rules file that runs automatically and merely deserves the user's
 * confirmation) stays dim. Every finding is printed — integrity findings are
 * few by construction (checkIntegrity caps its own noise), so unlike scan
 * findings they are never truncated to a top-N.
 *
 * Exported separately because cli.js's "no transcript sources on this
 * machine" path still runs the integrity checks — a planted repo-level hook
 * is exactly as dangerous on a machine with no transcripts to scan.
 */
function renderIntegrity(integrity, { noColor = false } = {}) {
  const paint = makePaint(noColor);
  const lines = [];
  const push = (s = "") => lines.push(s);

  const warns = integrity.findings.filter((f) => f.severity === "warn");
  const infos = integrity.findings.filter((f) => f.severity === "info");
  const checked = integrity.filesChecked.filter((f) => f.status === "checked").length;
  const absent = integrity.filesChecked.filter((f) => f.status === "absent").length;

  if (integrity.findings.length === 0) {
    push(paint(c.green + c.bold, "✓ Integrity: no planted hooks, droppers, or hidden instructions detected") +
      `: ${checked} location${checked === 1 ? "" : "s"} checked, ${absent} absent.`);
  } else if (warns.length > 0) {
    push(paint(c.red + c.bold, `⚠  Integrity: ${warns.length} warning${warns.length === 1 ? "" : "s"}`) +
      (infos.length > 0 ? ` + ${infos.length} item${infos.length === 1 ? "" : "s"} to review` : "") +
      paint(c.dim, ` · ${checked} location${checked === 1 ? "" : "s"} checked`));
  } else {
    push(paint(c.bold, `Integrity: ${infos.length} item${infos.length === 1 ? "" : "s"} to review`) +
      paint(c.dim, ` (nothing matching a known campaign signature) · ${checked} location${checked === 1 ? "" : "s"} checked`));
  }
  for (const f of warns) {
    push(`  ${paint(c.red, "warn")}  ${paint(c.cyan, f.file)}`);
    push(`        ${f.detail}`);
  }
  for (const f of infos) {
    push(`  ${paint(c.dim, "info")}  ${paint(c.cyan, f.file)}`);
    push(paint(c.dim, `        ${f.detail}`));
  }
  push(paint(c.dim, `   ${integrity.scopeNote}`));
  return lines.join("\n");
}

function render({ findings, filesScanned, sourcesScanned, bytesScanned, suppressedCount = 0, distinctCounts = {}, unreadableFiles = [] }, { noColor = false, integrity = null } = {}) {
  const paint = makePaint(noColor);
  const lines = [];
  const push = (s = "") => lines.push(s);

  const suppressedNote = suppressedCount > 0
    ? paint(c.dim, ` (${suppressedCount} more matched but looked like placeholder/example text; see --include-suppressed)`)
    : "";
  // Surfaced, not silent: a file that couldn't be (fully) read was not fully
  // scanned, and a report must not read as "checked and found nothing" for
  // it. `unreadableFiles` holds { file: <basename>, reason } — basenames
  // only, deliberately: the full path can itself carry a username or a
  // project-name-derived directory slug, which is exactly the kind of thing
  // every other line in this report is careful to redact down from.
  const unreadableNote = unreadableFiles.length > 0
    ? paint(c.yellow, `⚠  ${unreadableFiles.length} file(s) not fully scanned. See --json for which and why.`)
    : null;

  if (findings.length === 0) {
    push(paint(c.green + c.bold, "✓ No exposed secrets found") +
      `: ${filesScanned} file${filesScanned === 1 ? "" : "s"} scanned across ${sourcesScanned.join(", ") || "no sources"}.` +
      suppressedNote);
    if (unreadableNote) push(unreadableNote);
    if (integrity) {
      push();
      push(renderIntegrity(integrity, { noColor }));
    }
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

  if (integrity) {
    push();
    push(renderIntegrity(integrity, { noColor }));
  }

  push();
  push(paint(c.dim, "Values are redacted in this report (first/last 4 characters only). Nothing scanned"));
  push(paint(c.dim, "here left your machine; residoo makes no network calls. Run with --json for full detail."));

  return lines.join("\n");
}

// `integrity` is the checkIntegrity() result, or null when --no-integrity
// skipped it — the key is always present so a --json consumer can tell
// "checked, clean" apart from "never checked" without guessing from absence.
function renderJson(result, integrity = null) {
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
      integrity: integrity
        ? {
            warningCount: integrity.findings.filter((f) => f.severity === "warn").length,
            findings: integrity.findings,
            filesChecked: integrity.filesChecked,
            scopeNote: integrity.scopeNote,
          }
        : null,
    },
    null,
    2
  );
}

module.exports = { render, renderIntegrity, renderJson };
