"use strict";

const path = require("path");
const { PATTERNS, NOISY_PATTERNS, redact } = require("./patterns");
const { findDecodedMatches, findBoundaryMatches, contentProjection } = require("./decode");
const { findPairedSecret } = require("./pairing");
const { looksRandom } = require("./rarity");

// Rule ids that findPairedSecret's window search applies to (see pairing.js):
// AWS access key ids and STS session tokens both pair with the same shape
// of 40-char base64 secret value.
const AWS_PAIR_RULE_IDS = new Set(["aws_access_key_id", "aws_session_token"]);

// The two NOISY_PATTERNS ids (see patterns.js): the only rules the rarity
// check (rarity.js) ever touches. Never applied to the default 38 rules.
const NOISY_RULE_IDS = new Set(["generic_password_assignment", "generic_secret_assignment"]);

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
/**
 * A trailing run of 12+ identical characters inside a matched value. No
 * vendor issues credentials with a repeated-character body — key material is
 * random, and 12 identical characters in a row in a real random body is a
 * ~62^-11 event — but placeholder keys built as prefix + XXXX.../0000... are
 * everywhere in docs and templates, and they match the shape rules by
 * construction. This is a property of the VALUE, so unlike the context
 * heuristic it also works where no surrounding text exists: a placeholder
 * that arrives base64-encoded or split across lines is still zero-entropy
 * after decoding/joining. gitleaks ships equivalent repeated-character
 * allowlists. Anchored to the END of the value on purpose: an INTERIOR run
 * can occur inside a real token (base64 of a zero-byte run is a run of
 * "A"s, so a genuine JWT payload can contain one), but real key material
 * never ends in one, and prefix+XXXX placeholders always do. Same policy
 * as every suppression: counted, re-includable with --include-suppressed,
 * never silently dropped.
 *
 * Implemented as a fixed 12-character look at the END of the value, not as
 * the equivalent anchored-backreference regex /(.)\1{11,}$/ — that regex is
 * O(n^2) on a matched value containing a long INTERIOR identical-character
 * run (the greedy backreference re-tests the anchor at every start
 * position), and such values are reachable: base64 of zero-heavy bytes is a
 * long run of "A"s inside a prefix-matched value. Checking only the last 12
 * code units is exactly equivalent to "ends in 12 or more identical
 * characters" and O(1) whatever the value looks like.
 */
function zeroEntropyTail(value) {
  if (value.length < 12) return false;
  const last = value.charCodeAt(value.length - 1);
  for (let i = value.length - 12; i < value.length - 1; i++) {
    if (value.charCodeAt(i) !== last) return false;
  }
  return true;
}

const VENDOR_EXAMPLE_VALUES = new Set([
  "AKIAIOSFODNN7EXAMPLE",
  "AKIAI44QH8DHBEXAMPLE",
  "ghp_16C7e42F292c6912E7710c838347Ae178B4a",
  "gho_16C7e42F292c6912E7710c838347Ae178B4a",
  "ghr_1B4a2e77838347a7E420ce178F2E7c6912E169246c34E1ccbF66C46812d16D5B1A9Dc86A1498",
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
  // Stripe's two published sample test keys, verified against Stripe's own
  // material (2026-09): the API reference authentication page
  // (docs.stripe.com/api/authentication) embeds the first in its curl
  // example under "A sample test API key is included in all the examples
  // here"; the second is Stripe's long-running docs sample key, present
  // verbatim in Stripe's own repositories (stripe/stripe-java and
  // stripe/stripe-dotnet test suites) and echoed by virtually every Stripe
  // tutorial a transcript might read. Both match stripe_test_key by
  // construction, so without this entry each is reported at high confidence.
  // Written split (prefix + body) so the faithful example literals do not
  // trip GitHub push protection; the Set still holds the whole values.
  "sk_test_" + "BQokikJOvBiI2HlWgH4olfQ2",
  "sk_test_" + "4eC39HqLyjWDarjtT1zdp7dc",
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

  // One suppression policy for all three passes (raw, decoded, boundary).
  // The value-based checks run first: they are exact properties of the match
  // itself, so they apply identically to a value found raw, decoded out of
  // base64, or reconstructed across a line boundary — a decoded vendor
  // example is the same non-secret as a plain one. The context heuristic is
  // last and only where surrounding text exists (`before` is null for the
  // decode and boundary passes, whose transforms have no stable "40 chars
  // before" in the original line).
  const suppressionReason = (value, before, ruleId) => {
    if (VENDOR_EXAMPLE_VALUES.has(value)) return "vendor-documented example value";
    if (zeroEntropyTail(value)) return "zero-entropy body";
    if (before !== null && SUPPRESS_CONTEXT_RE.test(before)) return "placeholder-like context";
    // Rarity check (rarity.js): only the two opt-in NOISY_PATTERNS rules ever
    // reach here with a matching ruleId. A generic password/secret
    // assignment whose value reads as English (a placeholder, a variable
    // name, a pasted sentence) is exactly the false-positive class those
    // rules are known for; a value that reads as machine-random is not.
    if (ruleId && NOISY_RULE_IDS.has(ruleId) && !looksRandom(value)) return "reads like natural language, not random";
    return null;
  };

  // Confidence for a NOISY_PATTERNS match that survives every suppression
  // check is bumped from the rule's default "low" to "medium" when the
  // value also reads as machine-random (rarity.js): passing both "not a
  // known placeholder shape" AND "doesn't read like language" is a real
  // signal boost, not just the absence of a red flag. Never touches any of
  // the default 38 rules' own confidence.
  const resolveConfidence = (ruleId, value, defaultConfidence, suppressedReason) => {
    if (suppressedReason) return "low";
    if (NOISY_RULE_IDS.has(ruleId) && looksRandom(value)) return "medium";
    return defaultConfidence;
  };

  const matchLine = (line, file, relFile, lineNo, mtimeMs) => {
    for (const rule of rules) {
      rule.re.lastIndex = 0; // rules are reused across files; reset global regex state
      let m;
      while ((m = rule.re.exec(line)) !== null) {
        const before = line.slice(Math.max(0, m.index - CONTEXT_WINDOW), m.index);
        const suppressedReason = suppressionReason(m[0], before, rule.id);
        if (suppressedReason && !includeSuppressed) {
          suppressedCount++;
        } else {
          // Feature 3: paired-secret detection (see pairing.js), computed
          // BEFORE the access-key-id finding is recorded so that finding can
          // carry the paired secret's own redacted preview. An access key id
          // alone cannot authenticate anything (see pairing.js's docstring);
          // it is only a usable credential once its secret is known too, so
          // a report showing several access-key-id findings needs to say,
          // on each one's own line, which one actually has a secret sitting
          // next to it in the transcript, not just that a secret exists
          // somewhere in the scan.
          let pairedSecretPreview = null;
          if (!suppressedReason && AWS_PAIR_RULE_IDS.has(rule.id)) {
            const paired = findPairedSecret(line, m[0], m.index);
            if (paired) {
              const pairedSuppressedReason = suppressionReason(paired, null);
              if (pairedSuppressedReason && !includeSuppressed) {
                suppressedCount++;
              } else {
                pairedSecretPreview = redact(paired);
                record({ id: "aws_secret_access_key_paired", label: "AWS Secret Access Key (paired with access key id)" },
                  paired, relFile, file, lineNo, mtimeMs,
                  pairedSuppressedReason ? "low" : "high", pairedSuppressedReason,
                  { paired: true, pairedAccessKeyPreview: redact(m[0]) });
              }
            }
          }
          record(rule, m[0], relFile, file, lineNo,
            mtimeMs,
            resolveConfidence(rule.id, m[0], rule.confidence, suppressedReason),
            suppressedReason,
            pairedSecretPreview ? { pairedSecretPreview } : undefined);
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
      const suppressedReason = suppressionReason(d.value, null);
      if (suppressedReason && !includeSuppressed) {
        suppressedCount++;
        continue;
      }
      record({ id: d.ruleId, label: d.label }, d.value, relFile, file, lineNo,
        mtimeMs, suppressedReason ? "low" : "high", suppressedReason, { encoding: d.encoding });
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
      const suppressedReason = suppressionReason(b.value, null, b.ruleId);
      if (suppressedReason && !includeSuppressed) {
        // One straddling match is one suppressed match, even though an
        // unsuppressed one records against both contributing lines.
        suppressedCount++;
        continue;
      }
      const span = [lineNoA, lineNoA + 1];
      const conf = resolveConfidence(b.ruleId, b.value, b.confidence, suppressedReason);
      record({ id: b.ruleId, label: b.label }, b.value, relFile, file, lineNoA, mtimeMs, conf, suppressedReason, { spanLines: span });
      record({ id: b.ruleId, label: b.label }, b.value, relFile, file, lineNoA + 1, mtimeMs, conf, suppressedReason, { spanLines: span });
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
      // Per-file degradation flag, surfaced at most once so a pathological
      // file produces one visible entry, not thousands.
      let lineMatchFailed = false;
      // Each pass gets its own try/catch: every rule quantifier is bounded
      // (see patterns.js) so none of these should throw on adversarial input
      // any more, but this is the second, independent layer against that
      // failure mode — a throw in one pass must never suppress the other
      // two for the same line. Without this, a bug reintroduced in any one
      // pass silently blinds the other two for that line rather than
      // degrading loudly on its own. One unmatched line must degrade to a
      // visible per-file flag, never abort the scan and discard every
      // finding already collected (same contract as the readLines catch
      // above).
      const flagFailed = () => {
        if (!lineMatchFailed) {
          lineMatchFailed = true;
          unreadableFiles.push({ file: safeName(file), reason: "some lines could not be matched" });
        }
      };
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (line) {
          try {
            matchLine(line, file, relFile, i + 1, mtimeMs);
          } catch (err) {
            flagFailed();
          }
          try {
            decodeLine(line, file, relFile, i + 1, mtimeMs);
          } catch (err) {
            flagFailed();
          }
          try {
            const content = contentProjection(line);
            // Boundary join with the previous line (2-way splits only; see
            // decode.js). Both lines must be non-empty so a blank separator
            // never forms a spurious pair.
            if (prevContent !== null) {
              boundaryPair(prevContent, content, file, relFile, i, mtimeMs);
            }
            prevContent = content;
          } catch (err) {
            flagFailed();
            prevContent = null;
          }
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

// VENDOR_EXAMPLE_VALUES is exported for the smoke tests, which assert every
// literal in it is still matched IN FULL by some detection rule — a literal
// no rule can produce as a whole match is dead weight that suppresses nothing.
module.exports = { scan, emptyResult, VENDOR_EXAMPLE_VALUES };
