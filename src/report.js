"use strict";

const path = require("path");
const { fingerprintFinding, ROTATION_ORDER_ADVISORY } = require("./rotation");

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

const SPINNER_FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

/**
 * Printed once, before scanning starts: what this is, what version, where
 * it lives. Answers exactly the question a first-time (or every-time)
 * reader has before results ever appear, without waiting for the report.
 * Same TTY gate and same stream as the progress spinner below and for the
 * same reason: stderr only, so a --json/--sarif consumer's stdout is
 * untouched, and a complete no-op under redirection, piping, or CI.
 */
function printIntro(noColor) {
  if (!process.stderr.isTTY) return;
  const paint = makePaint(noColor);
  const { version } = require("../package.json");
  process.stderr.write(
    paint(c.bold + c.cyan, `residoo v${version}`) +
    paint(c.dim, " · find secrets your AI coding agent left on disk\n") +
    paint(c.dim, "https://github.com/dandovdub/residoo\n\n")
  );
}

/**
 * A progress indicator for the scan phase, wired to scan()'s own
 * onProgress callback. Writes to STDERR only, never stdout: --json/--sarif
 * consumers pipe stdout into a parser, and a spinner corrupting that would
 * be a much worse bug than not having one. Gated on stderr actually being a
 * TTY, so it is a complete no-op under redirection, piping, or CI, exactly
 * the contexts where carriage-return spam in a captured log would be
 * useless or actively annoying, not merely invisible. Shows the actual
 * current file (basename only, through the same safeBasename() every other
 * displayed path in this report goes through — control bytes stripped,
 * invisible code points made visible), not just a running count: real
 * signal, not just motion, and genuinely useful if a scan stalls on one
 * huge file. `stop()` clears the line so whatever prints next starts
 * clean.
 */
function makeProgressReporter(noColor) {
  if (!process.stderr.isTTY) return { onProgress: null, stop() {} };
  const paint = makePaint(noColor);
  let count = 0;
  let lastWriteMs = 0;
  let lastLineLen = 0;
  let frame = 0;
  const write = (s, visibleLen) => {
    process.stderr.write("\r" + " ".repeat(lastLineLen) + "\r" + s);
    lastLineLen = visibleLen;
  };
  const onProgress = ({ source, file }) => {
    count++;
    const now = Date.now();
    if (now - lastWriteMs < 80) return; // throttled: avoid flicker on a fast scan
    lastWriteMs = now;
    frame = (frame + 1) % SPINNER_FRAMES.length;
    const label = `scanning ${source}… ${count} file${count === 1 ? "" : "s"}  ${safeBasename(file)}`;
    write(paint(c.bold + c.cyan, SPINNER_FRAMES[frame]) + " " + paint(c.dim, label), 2 + label.length);
  };
  const stop = () => { if (lastLineLen > 0) process.stderr.write("\r" + " ".repeat(lastLineLen) + "\r"); };
  return { onProgress, stop };
}

// File NAMES are attacker-controllable text headed for a terminal: in
// --project mode a hostile checkout chooses its own filenames, and a name
// carrying raw ESC bytes could clear the screen or overwrite the findings
// block with a spoofed all-clear. Same discipline integrity.js applies to
// its displayed paths (its stripControlChars/escapeInvisibles pair, mirrored
// here rather than exported: patterns.js and integrity.js each keep their own
// copy for the same shared-file reason): control bytes stripped, invisible
// code points made visible so a zero-width name cannot render as nothing.
const INVISIBLES_RE = /[\u200b\u200c\u200d\u2060\ufeff\u{e0000}-\u{e007f}]/gu;
function safeBasename(file) {
  return path.basename(String(file))
    .replace(/[\x00-\x1f\x7f]/g, "")
    .replace(INVISIBLES_RE, (ch) => "\\u{" + ch.codePointAt(0).toString(16).toUpperCase() + "}");
}

// Plain greedy word wrap for the one long-paragraph string this report prints
// (the rotation ordering advisory). Continuation lines get the indent.
function wrapText(s, width, indent) {
  const words = String(s).split(/\s+/);
  const lines = [];
  let cur = "";
  for (const w of words) {
    if (cur && cur.length + 1 + w.length > width) { lines.push(cur); cur = w; }
    else cur = cur ? cur + " " + w : w;
  }
  if (cur) lines.push(cur);
  return lines.map((l, i) => (i === 0 ? l : indent + l));
}

/**
 * The rotation section: what to DO about each distinct finding, fed by
 * src/rotation.js's renderRotation() (pure data) and printed in the same
 * visual language as the rest of the report. Compact on purpose: one status
 * line plus one guidance pointer per distinct value; the full runbook lives
 * behind "residoo explain <rule-id>" so the report stays scannable. The
 * fingerprint is printed in full because it is the exact argument
 * "residoo ack" takes; a truncated one would be prettier and useless.
 *
 * `showAdvisory` is set by render() only when integrity WARNINGS and secret
 * findings coexist in one run: that is the ChainDrop scenario where rotating
 * first can itself trigger the planted payload, so remediation order becomes
 * safety-critical and the report says so before listing anything to rotate.
 */
function renderRotationSection(rotation, { noColor = false, showAdvisory = false } = {}) {
  const paint = makePaint(noColor);
  const lines = [];
  const push = (s = "") => lines.push(s);
  const { counts, entries } = rotation;
  if (counts.distinct === 0) return "";

  // "rotations", not "distinct values": the headline's distinct count dedupes
  // raw values, while these entries dedupe fingerprints (which include the
  // basename, so one value in two differently-named files is two rotations to
  // track). Two counts under one word would read as a contradiction.
  const resolvedNote = [
    counts.acked > 0 ? `${counts.acked} acknowledged` : null,
    counts.dismissed > 0 ? `${counts.dismissed} dismissed` : null,
  ].filter(Boolean).join(", ");
  push(paint(c.bold, "Rotation:") +
    ` ${counts.pending} of ${counts.distinct} rotation${counts.distinct === 1 ? "" : "s"} pending` +
    (resolvedNote ? ` (${resolvedNote})` : ""));
  if (showAdvisory) {
    const wrapped = wrapText(ROTATION_ORDER_ADVISORY, 72, "     ");
    push(`  ${paint(c.red + c.bold, "⚠  " + wrapped[0])}`);
    for (const l of wrapped.slice(1)) push(`  ${paint(c.red, l)}`);
  }
  // Grouped by rule, not one row per finding: with several distinct values
  // of the same credential type pending, the old flat list repeated the
  // exact same rotation URL once per finding, all noise, no signal.
  // Guidance now prints once per credential TYPE; what actually differs
  // between two findings of the same type is which value and where, so
  // that's what each row shows: the redacted preview (the one piece of
  // information that lets a reader tell "this looks like my prod key" from
  // "this looks like the placeholder ending in HERE" without cross-checking
  // anything else) and how many files it's in, with the fingerprint kept
  // but de-emphasized, still there for `ack`/`dismiss` but no longer the
  // only thing on the line.
  const groups = new Map(); // ruleId -> { label, entries: [] }
  for (const e of entries) {
    if (!groups.has(e.ruleId)) groups.set(e.ruleId, { label: e.label, entries: [] });
    groups.get(e.ruleId).entries.push(e);
  }
  // Group order: any group with at least one pending entry first (matches
  // the report's own "what needs attention" priority throughout), fully
  // resolved groups after, alphabetical by label within each tier.
  const groupList = [...groups.values()].sort((a, b) => {
    const aPending = a.entries.some((e) => e.status === "pending");
    const bPending = b.entries.some((e) => e.status === "pending");
    if (aPending !== bPending) return aPending ? -1 : 1;
    return a.label < b.label ? -1 : 1;
  });

  const STATUS_TAG = {
    pending: paint(c.yellow, "pending  "),
    acked: paint(c.green, "acked    "),
    dismissed: paint(c.dim, "dismissed"),
  };
  // Same anti-flood policy as the by-file table: a report is a summary, not
  // a dump. Everything elided here is in --json in full. Counted in
  // individual findings, not groups, so the cap means the same thing here
  // as it always has.
  const MAX_SHOWN = 12;
  let shownCount = 0;
  let elided = 0;
  for (const g of groupList) {
    if (shownCount >= MAX_SHOWN) { elided += g.entries.length; continue; }
    push();
    const g0 = g.entries[0];
    const where = g0.guidance.rotateUrl ? `rotate: ${g0.guidance.rotateUrl}` : `where: ${g0.guidance.consolePath}`;
    push(`  ${paint(c.bold, g.label)}`);
    push(paint(c.dim, `    ${where}`));
    for (const e of g.entries) {
      if (shownCount >= MAX_SHOWN) { elided++; continue; }
      shownCount++;
      // e.files always has exactly one entry: the fingerprint is derived
      // from this same basename (see fingerprintFinding in rotation.js), so
      // two findings only ever merge into one entry when they share it. Same
      // discipline as the "By file:" table: a filename is attacker-
      // controllable text (a hostile --project checkout picks its own
      // names), so it goes through safeBasename before it ever reaches the
      // terminal, control bytes stripped, invisible code points made visible.
      const fileNote = safeBasename(e.files[0]);
      // Last SEEN, not last used or last rotated: the most recent transcript
      // occurrence residoo found, nothing more. There is no reliable way to
      // tell from a local scan whether an older value of the same rule type
      // was superseded by a newer one, both because most credential formats
      // (AWS access keys, vendor API tokens) carry no shared identifier
      // linking a rotated key to its predecessor, and because residoo makes
      // no network calls to ask the provider. Two distinct pending values of
      // the same type are shown as two separate lines on purpose, not
      // collapsed on a guess.
      const lastSeenNote = typeof e.lastSeenMs === "number" ? `last seen ~${ageDays(e.lastSeenMs)}d ago` : null;
      push(`    ${STATUS_TAG[e.status]}  ${e.preview}  ${paint(c.dim, fileNote)}` +
        (lastSeenNote ? `  ${paint(c.dim, lastSeenNote)}` : ""));
      if (e.status === "acked") {
        push(paint(c.dim, `               acknowledged ${e.ackedAt || "(no timestamp)"}${e.ackNote ? `: ${e.ackNote}` : ""} · ${e.fingerprint}`));
      } else if (e.status === "dismissed") {
        push(paint(c.dim, `               dismissed ${e.ackedAt || "(no timestamp)"}${e.ackNote ? `: ${e.ackNote}` : ""} (not a real secret) · ${e.fingerprint}`));
      } else {
        push(paint(c.dim, `               ${e.fingerprint}`));
      }
    }
  }
  if (elided > 0) {
    push();
    push(paint(c.dim, `  … and ${elided} more; see --json for the full list`));
  }
  push();
  push(paint(c.dim, `  Full runbook: residoo explain <rule-id> · rotated: residoo ack <fp> · not a secret: residoo dismiss <fp>`));
  return lines.join("\n");
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

/** "YYYY-MM-DD HH:MM" in local time — matches the user's own system clock, not UTC. */
function localTimestamp(d) {
  const p2 = (n) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p2(d.getMonth() + 1)}-${p2(d.getDate())} ${p2(d.getHours())}:${p2(d.getMinutes())}`;
}

function render({ findings, filesScanned, sourcesScanned, bytesScanned, suppressedCount = 0, distinctCounts = {}, unreadableFiles = [] }, { noColor = false, integrity = null, rotation = null } = {}) {
  const paint = makePaint(noColor);
  const lines = [];
  const push = (s = "") => lines.push(s);

  // Which build ran and when, up front: a report pasted or screenshotted
  // hours later (or a "why don't I see feature X" question) should never
  // require asking "what version were you even running."
  const { version } = require("../package.json");
  push(paint(c.dim, `residoo v${version} · scanned ${localTimestamp(new Date())}`));

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
  for (const f of findings) {
    const entry = byFile.get(f.file) || { count: 0, mtimeMs: f.fileMTimeMs };
    entry.count++;
    // Newest mtime wins if a file's own findings ever carried different
    // values (they should not, mtimeMs is a per-file stat, but a defensive
    // max here costs nothing and avoids depending on finding order).
    if (f.fileMTimeMs > entry.mtimeMs) entry.mtimeMs = f.fileMTimeMs;
    byFile.set(f.file, entry);
  }
  const oldest = findings.reduce((a, b) => (b.fileMTimeMs < a ? b.fileMTimeMs : a), Date.now());
  const newest = findings.reduce((a, b) => (b.fileMTimeMs > a ? b.fileMTimeMs : a), 0);

  push();
  push(paint(c.red + c.bold, `⚠  ${findings.length} potential secret${findings.length === 1 ? "" : "s"} found`) +
    ` across ${byFile.size} file${byFile.size === 1 ? "" : "s"}`);
  push(paint(c.dim, `   ${filesScanned} files scanned (${(bytesScanned / 1024 / 1024).toFixed(1)} MB) · sources: ${sourcesScanned.join(", ")}`));
  push(paint(c.dim, `   oldest match ~${ageDays(oldest)}d old · most recent ~${ageDays(newest)}d old`) + suppressedNote);
  if (unreadableNote) push(unreadableNote);

  // The practical, act-on-this-now summary, first, before the full
  // rule-by-rule and file-by-file detail below: a raw count of findings
  // (which can run into the hundreds on a machine with a lot of history) is
  // not by itself a to-do list. What actually needs a person's attention is
  // the count of DISTINCT values not yet triaged (rotated or dismissed) —
  // everything else is either already handled or a re-exposure of a value
  // already accounted for.
  if (rotation && rotation.counts.distinct > 0) {
    const { pending, distinct, acked, dismissed } = rotation.counts;
    push();
    push(paint(c.bold, "Recommended actions:"));
    if (pending > 0) {
      push(`  ${paint(c.yellow, "→")} ${pending} of ${distinct} distinct value${distinct === 1 ? "" : "s"} ${pending === 1 ? "needs" : "need"} review: rotate the real ones (residoo ack), dismiss the rest (residoo dismiss)`);
    } else {
      push(`  ${paint(c.green, "✓")} Nothing new to review; every distinct value here has already been triaged`);
    }
    const resolvedParts = [
      acked > 0 ? `${acked} acknowledged` : null,
      dismissed > 0 ? `${dismissed} dismissed` : null,
    ].filter(Boolean);
    if (resolvedParts.length > 0) {
      push(paint(c.dim, `    ${resolvedParts.join(", ")} already, no action needed (see Rotation below for which)`));
    }
  }
  push();

  const sorted = [...byRule.entries()].sort((a, b) => b[1].items.length - a[1].items.length);
  for (const [ruleId, { label, confidence, items }] of sorted) {
    const tag = confidence === "high" ? paint(c.red, "high") : confidence === "medium" ? paint(c.yellow, "med ") : paint(c.dim, "low ");
    const distinct = distinctCounts[ruleId];
    const distinctNote = distinct && distinct !== items.length
      ? paint(c.dim, `  (${distinct} distinct value${distinct === 1 ? "" : "s"}, re-exposed ${items.length - distinct}× across tool output)`)
      : "";
    // Flag when a rule's matches came from a decode/reconstruct pass rather
    // than plain text: those would be invisible to a line-oriented scanner,
    // so the reader should know the value was hidden.
    const encoded = items.filter((f) => f.encoding).length;
    const split = items.filter((f) => f.spanLines).length;
    const marks = [];
    if (encoded) marks.push(`${encoded} base64-wrapped`);
    if (split) marks.push(`${split} split across lines`);
    const markNote = marks.length ? paint(c.yellow, `  [${marks.join(", ")}]`) : "";
    push(`  ${paint(c.bold, String(items.length).padStart(4))}  [${tag}]  ${label}${distinctNote}${markNote}`);
  }

  push();
  push(paint(c.bold, "By file:"));
  const fileRows = [...byFile.entries()].sort((a, b) => b[1].count - a[1].count).slice(0, 15);
  for (const [file, { count, mtimeMs }] of fileRows) {
    push(`  ${String(count).padStart(4)}  ${paint(c.dim, `~${String(ageDays(mtimeMs)).padStart(2)}d old`)}  ${paint(c.cyan, safeBasename(file))}`);
  }
  if (byFile.size > fileRows.length) push(paint(c.dim, `  … and ${byFile.size - fileRows.length} more file(s)`));

  if (rotation && rotation.counts.distinct > 0) {
    const integrityWarns = integrity ? integrity.findings.filter((f) => f.severity === "warn").length : 0;
    push();
    push(renderRotationSection(rotation, { noColor, showAdvisory: integrityWarns > 0 }));
  }

  if (integrity) {
    push();
    push(renderIntegrity(integrity, { noColor }));
  }

  push();
  push(paint(c.bold, "Next steps:"));
  push(`  residoo scan --json          ${paint(c.dim, "machine-readable output, full detail")}`);
  push(`  residoo scan --seal          ${paint(c.dim, "encrypt the affected files into a local vault (originals untouched)")}`);
  push();
  push(paint(c.dim, "Values are redacted in this report (first/last 4 characters only). Nothing scanned"));
  push(paint(c.dim, "here left your machine; residoo makes no network calls."));

  return lines.join("\n");
}

// `integrity` is the checkIntegrity() result, or null when --no-integrity
// skipped it — the key is always present so a --json consumer can tell
// "checked, clean" apart from "never checked" without guessing from absence.
// `rotation` is src/rotation.js's renderRotation() result (counts + per-
// distinct-fingerprint entries with guidance attached), or null for a caller
// that never computed it; the per-finding `fingerprint` is emitted either
// way, since it is derived from already-redacted material and is what
// "residoo ack" takes.
function renderJson(result, integrity = null, rotation = null) {
  const { version } = require("../package.json");
  return JSON.stringify(
    {
      residooVersion: version,
      scannedAt: new Date().toISOString(),
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
        fileMTimeMs: f.fileMTimeMs,
        // Markers for the two decode/reconstruct passes (absent on ordinary
        // findings). `encoding` names how the value was wrapped ("base64" /
        // "base64url"); `spanLines` names the adjacent line pair a split value
        // was reconstructed across.
        ...(f.encoding ? { encoding: f.encoding } : {}),
        ...(f.spanLines ? { spanLines: f.spanLines } : {}),
        fingerprint: fingerprintFinding(f),
        // Only present on an --include-suppressed run: says WHY this finding
        // is low-confidence, so a JSON consumer doesn't have to guess.
        ...(f.suppressedReason ? { suppressedReason: f.suppressedReason } : {}),
      })),
      // orderAdvisory mirrors the human report's ChainDrop ordering warning:
      // remediation order is safety-critical when planted persistence and
      // leaked credentials coexist, and a --json consumer (a CI summarizer)
      // must not have to re-derive that condition. The advisory text when the
      // condition holds, null otherwise.
      rotation: rotation
        ? {
            counts: rotation.counts,
            entries: rotation.entries,
            orderAdvisory:
              result.findings.length > 0 &&
              integrity && integrity.findings.some((f) => f.severity === "warn")
                ? ROTATION_ORDER_ADVISORY
                : null,
          }
        : null,
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

// confidence -> SARIF level. "high"/"medium" map to the two levels GitHub's
// code-scanning UI treats as real alerts ("error" surfaces most
// prominently); "low" only ever appears with --include-suppressed (a
// placeholder/example match) and maps to "note", SARIF's own tier for
// exactly that: worth showing, not worth alarming over.
const SARIF_LEVEL = { high: "error", medium: "warning", low: "note" };

/**
 * SARIF 2.1.0 output (--sarif): the format GitHub's code-scanning Security
 * tab, and inline pull-request annotations, both consume. residoo already
 * ships a GitHub Action and a pre-commit hook, so not emitting the one
 * format that plugs a scan straight into GitHub's native UI was a real gap
 * for exactly the CI audience those two things target.
 *
 * Scoped to secret findings only (result.findings), not the separate
 * integrity checks (planted hooks, droppers): those don't share the same
 * per-line, per-file location shape, and forcing them into one schema badly
 * would be worse than a stated, honest scope limit. --json remains the
 * format that carries everything (findings, integrity, rotation) together.
 *
 * partialFingerprints carries residoo's own stable fingerprint
 * (fingerprintFinding, already proven stable across line-number and
 * directory changes, see tests/smoke.js) under a versioned key, so GitHub's
 * own alert-dedup logic can track one finding across reruns without
 * depending on line numbers moving, exactly the property SARIF's
 * fingerprinting is designed around.
 */
function renderSarif(result) {
  const { version } = require("../package.json");
  const rules = new Map();
  const results = result.findings.map((f) => {
    if (!rules.has(f.ruleId)) {
      rules.set(f.ruleId, {
        id: f.ruleId,
        name: f.label,
        shortDescription: { text: f.label },
        properties: { "security-severity": f.confidence === "high" ? "9.0" : f.confidence === "medium" ? "6.0" : "3.0" },
      });
    }
    return {
      ruleId: f.ruleId,
      level: SARIF_LEVEL[f.confidence] || "warning",
      message: { text: `${f.label} (redacted: ${f.preview})` },
      locations: [{
        physicalLocation: {
          artifactLocation: { uri: f.relFile },
          ...(Number.isInteger(f.line) ? { region: { startLine: f.line } } : {}),
        },
      }],
      partialFingerprints: { "residooFingerprint/v1": fingerprintFinding(f) },
      properties: { source: f.source, confidence: f.confidence },
    };
  });

  return JSON.stringify({
    $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [{
      tool: {
        driver: {
          name: "residoo",
          version,
          informationUri: "https://github.com/dandovdub/residoo",
          rules: [...rules.values()],
        },
      },
      results,
    }],
  }, null, 2);
}

module.exports = { render, renderIntegrity, renderRotationSection, renderJson, renderSarif, makeProgressReporter, printIntro };
