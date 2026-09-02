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
 * Scan every transcript from every available source.
 *
 * Matches raw text lines directly rather than parsing each line as JSON and
 * walking specific fields — transcript schemas vary by tool and change over
 * time, but a leaked key looks the same either way. This is also exactly the
 * method verified against a real, populated transcript directory while this
 * tool was built, so it's a known-working default rather than a redesign.
 *
 * Returns { findings, filesScanned, sourcesScanned, bytesScanned }.
 * `findings` never contains the raw matched secret — only a redacted
 * preview — because a security tool's own report output is itself a place
 * secrets could leak from (a screenshot, a copied terminal log, a CI artifact).
 */
function scan({ sources, includeNoisy = false, includeSuppressed = false, onProgress = null } = {}) {
  const rules = includeNoisy ? PATTERNS.concat(NOISY_PATTERNS) : PATTERNS;
  const findings = [];
  let suppressedCount = 0;
  let filesScanned = 0;
  let bytesScanned = 0;
  const sourcesScanned = [];
  // Raw values live ONLY in this in-process Set, for counting how many
  // DISTINCT secrets exist vs. how many times one got echoed back across
  // tool calls (a token re-surfacing in every screenshot/read_page during a
  // browser-testing run is one leak, not ten) — never written to a report,
  // never leaves this function.
  const distinctByRule = new Map();

  for (const source of sources) {
    let touchedThisSource = false;
    for (const { file, mtimeMs, sizeBytes } of source.files()) {
      touchedThisSource = true;
      filesScanned++;
      bytesScanned += sizeBytes || 0;
      if (onProgress) onProgress({ source: source.id(), file });

      const lines = source.readLines(file);
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (!line) continue;
        for (const rule of rules) {
          rule.re.lastIndex = 0; // rules are reused across files; reset global regex state
          let m;
          while ((m = rule.re.exec(line)) !== null) {
            const before = line.slice(Math.max(0, m.index - CONTEXT_WINDOW), m.index);
            const looksLikePlaceholder = SUPPRESS_CONTEXT_RE.test(before);
            if (looksLikePlaceholder && !includeSuppressed) {
              suppressedCount++;
            } else {
              if (!distinctByRule.has(rule.id)) distinctByRule.set(rule.id, new Set());
              distinctByRule.get(rule.id).add(m[0]);
              findings.push({
                ruleId: rule.id,
                label: rule.label,
                confidence: looksLikePlaceholder ? "low" : rule.confidence,
                suppressedReason: looksLikePlaceholder ? "placeholder-like context" : null,
                source: source.id(),
                file,
                relFile: path.basename(file),
                line: i + 1,
                preview: redact(m[0]),
                fileMTimeMs: mtimeMs,
              });
            }
            if (m.index === rule.re.lastIndex) rule.re.lastIndex++; // guard zero-width matches
          }
        }
      }
    }
    if (touchedThisSource) sourcesScanned.push(source.id());
  }

  const distinctCounts = {};
  for (const [ruleId, set] of distinctByRule) distinctCounts[ruleId] = set.size;
  return { findings, filesScanned, sourcesScanned, bytesScanned, suppressedCount, distinctCounts };
}

module.exports = { scan };
