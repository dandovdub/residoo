"use strict";

const path = require("path");
const { PATTERNS, NOISY_PATTERNS, redact } = require("./patterns");
const { findDecodedMatches, findBoundaryMatches, contentProjection } = require("./decode");

/**
 * Text immediately before a match that strongly suggests "this is an example
 * or a UI hint," not a real credential — verified against residoo's own
 * first real run, which flagged HTML `placeholder="AKIA..."` attributes in
 * an unrelated codebase's connector form (a UI hint showing the expected
 * key SHAPE) as if they were leaked keys. Suppressed by default, reported
 * separately rather than silently dropped, and re-includable with
 * --include-suppressed — a scanner that hides its own uncertainty is worse
 * than one that shows it.
 */
const SUPPRESS_CONTEXT_RE = /(placeholder|example|sample|dummy|<REDACTED>|xxxxxxxx|your[_-]?(api[_-]?)?key|EXAMPLE)/i;
const CONTEXT_WINDOW = 40;

/** Matches every finding's own `relFile` convention — never the full path. See SECURITY.md. */
function safeName(file) { return path.basename(file); }

/**
 * Scan every transcript from every available source.
 *
 * Matches raw text lines directly rather than parsing each line as JSON and
 * walking specific fields — transcript schemas vary by tool and change over
 * time, but a leaked key looks the same either way. This is also exactly the
 * method verified against a real, populated transcript directory while this
 * tool was built, so it's a known-working default rather than a redesign.
 *
 * Returns { findings, filesScanned, sourcesScanned, bytesScanned,
 * suppressedCount, distinctCounts, unreadableFiles }. `findings` never
 * contains the raw matched secret — only a redacted preview — because a
 * security tool's own report output is itself a place secrets could leak
 * from (a screenshot, a copied terminal log, a CI artifact). Same reasoning
 * is why `unreadableFiles` holds basenames only, not full paths — an
 * absolute path can itself carry a username or a project name the rest of
 * this report is careful never to print.
 */
async function scan({ sources, includeNoisy = false, includeSuppressed = false, onProgress = null } = {}) {
  const rules = includeNoisy ? PATTERNS.concat(NOISY_PATTERNS) : PATTERNS;
  // The decode pass (see decode.js) only applies high-confidence, vendor-
  // prefixed rules to decoded bytes: random binary that decodes to printable
  // text can shape-match a generic rule, but not a vendor prefix. NOISY rules
  // are low confidence and never qualify.
  const highRules = rules.filter((r) => r.confidence === "high");
  const findings = [];
  let suppressedCount = 0;
  let filesScanned = 0;
  let bytesScanned = 0;
  const sourcesScanned = [];
  const unreadableFiles = [];
  // Raw values live ONLY in this in-process Set, for counting how many
  // DISTINCT secrets exist vs. how many times one got echoed back across
  // tool calls (a token re-surfacing in every screenshot/read_page during a
  // browser-testing run is one leak, not ten) — never written to a report,
  // never leaves this function.
  const distinctByRule = new Map();

  // One place raw matched text turns into a recorded finding: counts the
  // distinct value and pushes the redacted record. `extra` carries the
  // encoding / split markers for the decode and boundary passes; the raw pass
  // passes none.
  const record = (rule, value, relFile, file, lineNo, mtimeMs, confidence, suppressedReason, extra) => {
    if (!distinctByRule.has(rule.id)) distinctByRule.set(rule.id, new Set());
    distinctByRule.get(rule.id).add(value);
    findings.push({
      ruleId: rule.id,
      label: rule.label,
      confidence,
      suppressedReason: suppressedReason || null,
      source: relFile.source,
      file, relFile: relFile.name,
      line: lineNo,
      preview: redact(value),
      fileMTimeMs: mtimeMs,
      ...(extra || {}),
    });
  };

  const matchLine = (line, file, relFile, lineNo, mtimeMs) => {
    for (const rule of rules) {
      rule.re.lastIndex = 0; // rules are reused across files; reset global regex state
      let m;
      while ((m = rule.re.exec(line)) !== null) {
        const before = line.slice(Math.max(0, m.index - CONTEXT_WINDOW), m.index);
        const looksLikePlaceholder = SUPPRESS_CONTEXT_RE.test(before);
        if (looksLikePlaceholder && !includeSuppressed) {
          suppressedCount++;
        } else {
          record(rule, m[0], relFile, file, lineNo,
            mtimeMs,
            looksLikePlaceholder ? "low" : rule.confidence,
            looksLikePlaceholder ? "placeholder-like context" : null);
        }
        if (m.index === rule.re.lastIndex) rule.re.lastIndex++; // guard zero-width matches
      }
    }
  };

  // Feature 1: base64 decode-then-rescan. A finding here means a credential
  // was present only encoded on this line. It redacts from the DECODED value
  // (the encoded run is treated as secret material and never appears in the
  // preview), and carries an `encoding` marker the report renders as
  // "base64-wrapped".
  const decodeLine = (line, file, relFile, lineNo, mtimeMs) => {
    for (const d of findDecodedMatches(line, highRules)) {
      record({ id: d.ruleId, label: d.label }, d.value, relFile, file, lineNo,
        mtimeMs, "high", null, { encoding: d.encoding });
    }
  };

  // Feature 2: split-line boundary join. A finding here means one credential
  // was split across this line and the next and is contiguous on neither. It
  // is recorded against BOTH contributing lines (each holds a fragment of the
  // exposed secret) and carries a `spanLines` marker. `contentA`/`contentB`
  // are the two lines' content projections, computed once per line by the
  // caller and reused across both of a line's pairs.
  const boundaryPair = (contentA, contentB, file, relFile, lineNoA, mtimeMs) => {
    for (const b of findBoundaryMatches(contentA, contentB, rules)) {
      const span = [lineNoA, lineNoA + 1];
      record({ id: b.ruleId, label: b.label }, b.value, relFile, file, lineNoA, mtimeMs, b.confidence, null, { spanLines: span });
      record({ id: b.ruleId, label: b.label }, b.value, relFile, file, lineNoA + 1, mtimeMs, b.confidence, null, { spanLines: span });
    }
  };

  for (const source of sources) {
    let sourceScannedAnything = false;

    for (const entry of source.files()) {
      if (onProgress) onProgress({ source: source.id(), file: entry.file });

      // files() itself can now report an entry it couldn't resolve at all —
      // chiefly a dangling symlink. Surfaced the same way an unreadable file
      // is: visibly, never silently dropped inside the walk.
      if (entry.broken) {
        unreadableFiles.push({ file: safeName(entry.file), reason: "could not be resolved" });
        continue;
      }
      const { file, mtimeMs, sizeBytes } = entry;

      // Any unexpected throw here (a source's readLines behaving outside its
      // documented contract, a future bug) must not take down the rest of
      // the scan and discard every finding already collected from other
      // files — one bad file degrading to "unreadable" is the correct
      // failure mode; the whole run crashing is not.
      let result;
      try {
        result = await source.readLines(file);
      } catch (err) {
        unreadableFiles.push({ file: safeName(file), reason: "unexpected error" });
        continue;
      }

      const { lines, status, bytesRead } = result;
      if (status === "failed") {
        unreadableFiles.push({ file: safeName(file), reason: "could not be read" });
        continue;
      }
      if (status === "too-large") {
        unreadableFiles.push({ file: safeName(file), reason: "too large to scan" });
        continue;
      }
      // "partial" means the read failed partway through, but real lines WERE
      // captured before that — those lines get scanned normally below (a
      // secret in the part that succeeded is still a real finding), and the
      // file is ALSO flagged so the user knows it wasn't fully checked.
      if (status === "partial") {
        unreadableFiles.push({ file: safeName(file), reason: "only partially read" });
      }

      sourceScannedAnything = true;
      filesScanned++;
      // Actual bytes streamed, not the pre-read stat() snapshot — matters
      // for a file Claude Code is actively appending to mid-scan, where the
      // two can genuinely differ.
      bytesScanned += bytesRead || sizeBytes || 0;

      const relFile = { name: safeName(file), source: source.id() };
      // Content projection of the PREVIOUS line, kept so each line is
      // projected once and reused for both pairs it belongs to.
      let prevContent = null;
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (line) {
          matchLine(line, file, relFile, i + 1, mtimeMs);
          decodeLine(line, file, relFile, i + 1, mtimeMs);
          const content = contentProjection(line);
          // Boundary join with the previous line (2-way splits only; see
          // decode.js). Both lines must be non-empty so a blank separator
          // never forms a spurious pair.
          if (prevContent !== null) {
            boundaryPair(prevContent, content, file, relFile, i, mtimeMs);
          }
          prevContent = content;
        } else {
          prevContent = null;
        }
      }
    }

    if (sourceScannedAnything) sourcesScanned.push(source.id());
  }

  const distinctCounts = {};
  for (const [ruleId, set] of distinctByRule) distinctCounts[ruleId] = set.size;
  return { findings, filesScanned, sourcesScanned, bytesScanned, suppressedCount, distinctCounts, unreadableFiles };
}

/**
 * The shape of a scan() result with nothing in it — exported so callers with
 * a "nothing to scan" path (no sources on this machine) can reuse the exact
 * result shape instead of hand-typing a duplicate literal that has to be
 * remembered and kept in sync every time a new field is added here.
 */
function emptyResult() {
  return {
    findings: [], filesScanned: 0, sourcesScanned: [], bytesScanned: 0,
    suppressedCount: 0, distinctCounts: {}, unreadableFiles: [],
  };
}

module.exports = { scan, emptyResult };
