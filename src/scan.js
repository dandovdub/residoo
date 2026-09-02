"use strict";

const path = require("path");
const { PATTERNS, NOISY_PATTERNS, redact } = require("./patterns");

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

/**
 * Exact literals that vendors publish in their own documentation as example
 * credentials. These pass every shape check by construction (they ARE the
 * documented shape), and the context heuristic above can't be relied on to
 * catch them: it only looks at the 40 characters BEFORE a match, so "the
 * docs show AKIAIOSFODNN7EXAMPLE as the placeholder" sails straight through.
 * The value itself is the signal here. Same policy as the context heuristic:
 * suppressed by default, counted, re-includable with --include-suppressed.
 * gitleaks and other production scanners filter the AWS pair the same way.
 *
 * Every literal below was verified against the vendor's own published docs
 * (2026-09), not copied from another scanner's allowlist:
 *   - AWS's two documented example access key ids, used across the IAM and
 *     STS docs (e.g. the GetAccessKeyInfo API reference).
 *   - GitHub's documented example tokens from docs.github.com: the REST API
 *     getting-started guide's PAT, and the OAuth-apps guide's access +
 *     refresh token pair (the same body appears under ghp_ and gho_).
 *   - jwt.io's default demo token (header {"alg":"HS256","typ":"JWT"},
 *     payload sub 1234567890 / John Doe), the canonical example JWT quoted
 *     in tutorials everywhere.
 */
const VENDOR_EXAMPLE_VALUES = new Set([
  "AKIAIOSFODNN7EXAMPLE",
  "AKIAI44QH8DHBEXAMPLE",
  "ghp_16C7e42F292c6912E7710c838347Ae178B4a",
  "gho_16C7e42F292c6912E7710c838347Ae178B4a",
  "ghr_1B4a2e77838347a7E420ce178F2E7c6912E169246c34E1ccbF66C46812d16D5B1A9Dc86A1498",
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
]);

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

  const matchLine = (line, file, relFile, lineNo, mtimeMs) => {
    for (const rule of rules) {
      rule.re.lastIndex = 0; // rules are reused across files; reset global regex state
      let m;
      while ((m = rule.re.exec(line)) !== null) {
        const before = line.slice(Math.max(0, m.index - CONTEXT_WINDOW), m.index);
        // The literal check runs first: it's exact, while the context window
        // is a heuristic — a vendor-doc example is suppressed no matter what
        // text happens to sit before it.
        const suppressedReason = VENDOR_EXAMPLE_VALUES.has(m[0])
          ? "vendor-documented example value"
          : SUPPRESS_CONTEXT_RE.test(before)
            ? "placeholder-like context"
            : null;
        if (suppressedReason && !includeSuppressed) {
          suppressedCount++;
        } else {
          if (!distinctByRule.has(rule.id)) distinctByRule.set(rule.id, new Set());
          distinctByRule.get(rule.id).add(m[0]);
          findings.push({
            ruleId: rule.id,
            label: rule.label,
            confidence: suppressedReason ? "low" : rule.confidence,
            suppressedReason,
            source: relFile.source,
            file, relFile: relFile.name,
            line: lineNo,
            preview: redact(m[0]),
            fileMTimeMs: mtimeMs,
          });
        }
        if (m.index === rule.re.lastIndex) rule.re.lastIndex++; // guard zero-width matches
      }
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
      for (let i = 0; i < lines.length; i++) {
        if (lines[i]) matchLine(lines[i], file, relFile, i + 1, mtimeMs);
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

// VENDOR_EXAMPLE_VALUES is exported for the smoke tests, which assert every
// literal in it is still matched IN FULL by some detection rule — a literal
// no rule can produce as a whole match is dead weight that suppresses nothing.
module.exports = { scan, emptyResult, VENDOR_EXAMPLE_VALUES };
