"use strict";

/**
 * Two general engine mechanisms that recover credentials a line-oriented
 * regex pass alone cannot see. Both are content transforms feeding the SAME
 * detection PATTERNS; neither adds a new rule. They are deliberately schema
 * agnostic (they never look at transcript field names), because residoo scans
 * many tools' formats and must not key on any one of them.
 *
 *   1. base64 decode-then-rescan (findDecodedMatches)
 *   2. split-line boundary join   (findBoundaryMatches)
 *
 * Both return the DECODED / RECONSTRUCTED plaintext secret to the caller,
 * which is responsible for redaction: like the raw matcher in scan.js, the
 * secret value lives only in-process and never reaches a report unredacted.
 * A decoded or reconstructed secret is still a secret.
 */

// ── Feature 1: base64 decode-then-rescan ────────────────────────────────────
//
// Agents routinely print credentials only in encoded form (a `base64 config`
// dump, an env file pasted as one blob), so the raw pattern never sees the
// key. We locate base64 runs in a line, decode them, and re-run the
// high-confidence patterns over the decoded text.
//
// WRAP TOLERANCE: `base64` output is line-wrapped (RFC 2045 MIME wraps at 76
// columns; the base64 CLI does too). When that wrapped output is embedded in
// a JSON string (a JSONL transcript's tool_result), each wrap newline is
// serialized as the two characters backslash+n. So a single logical base64
// blob shows up on one physical line as several runs separated by real
// whitespace or by the escape sequences \n \r \t. We treat those separators
// as part of one candidate and strip them before decoding, exactly as any
// base64 decoder ignores whitespace. This is the transcript-relevant wrap
// case and stays within one physical line.
//
// LIMITS (general, honestly stated):
//  - Only high-confidence, vendor-prefixed patterns are applied to decoded
//    text. Random binary that happens to decode to printable bytes can shape
//    match a generic/entropy rule; a vendor prefix (AKIA, ghp_, ...) cannot
//    be forged by accident, so restricting to those keeps decode-path false
//    positives near zero.
//  - base64 wrapped across REAL physical newlines (a PEM/MIME block spanning
//    several lines of a plain-text file) is out of this per-line pass's
//    scope. So is hex encoding. Both are future work, left out here rather
//    than half-done.
//  - One decode level only: we do not recursively decode base64-in-base64.
//  - A neighbor token glued onto a wrapped blob across the wrap newline (a
//    command word or filename directly above or below the encoded output)
//    is recovered by retrying the decode with ONE edge chunk dropped — but
//    only one, and only at an edge: junk on both edges, or prose merged into
//    the middle of a blob, still loses the whole candidate.
//  - At most B64_MAX_CANDIDATES candidates are decoded per line; a line with
//    more encoded runs than that is reported by the caller as only partially
//    checked rather than silently truncated.

// A run is made of characters that can appear in base64 or base64url:
// A-Z a-z 0-9 + / = _ - (see isB64Code). Wrap separators between chunks of
// one logical blob are line breaks (CR, LF) only — the whitespace that base64
// line-wrapping actually emits. TAB and space are NOT separators: base64
// wrapping never uses either, and merging across them splices adjacent cells
// of tabbed or spaced output into one dead candidate. When wrapped base64 is
// embedded in a JSON string the line breaks arrive as the escape sequences
// \n \r \t (two chars, backslash+letter); normalizeEscapes() turns those
// into the real characters first, so the escape's letter can never leak into
// a run (a real TAB then dirties the gap like any non-wrap character).
// Candidate runs are located by a hand-rolled single-pass character scan,
// NOT a regex. The obvious regex forms both fail on real data: a repeated
// group (chunk (sep chunk)*) recurses per repetition, and even a plain
// character-class quantifier pushes a backtrack frame per matched character
// in V8 — either one overflows the call stack on the multi-megabyte single
// lines that real transcripts contain (observed on a 7MB tool_result line).
// A char-code loop is O(n) with O(1) stack, whatever the line looks like.
const B64_MIN_CHUNK = 4;

const B64_MIN_CHARS = 24;          // fewer chars cannot hide a real credential
const B64_MAX_ENCODED = 90000;     // ~64KB decoded ceiling; skip bigger runs
const B64_MAX_CANDIDATES = 256;    // per line, so a pathological line stays bounded
const PRINTABLE_MIN = 0.85;        // decoded bytes must be mostly text to rescan

/** JSON whitespace escapes -> the real line breaks they stand for. */
function normalizeEscapes(line) {
  return line.replace(/\\n/g, "\n").replace(/\\r/g, "\r").replace(/\\t/g, "\t");
}

/**
 * Chunk runs merged into logical candidates: consecutive chunks whose gap
 * consists solely of wrap line breaks are one wrapped blob (its separators
 * dropped, exactly as any base64 decoder ignores whitespace); any other gap
 * (a space, TAB, prose, punctuation) ends the candidate. Iterative on
 * purpose — see the character-scan note above isB64Code.
 *
 * Each candidate is returned as its ARRAY of chunks, not pre-joined: the
 * decode step needs the chunk boundaries to retry with an edge chunk dropped
 * (see findDecodedMatches). `truncated` is true when the per-line candidate
 * cap cut the list short, so the caller can surface the partial coverage
 * instead of silently dropping the rest.
 */
function isB64Code(c) {
  return (c >= 48 && c <= 57) || (c >= 65 && c <= 90) || (c >= 97 && c <= 122) ||
    c === 43 || c === 47 || c === 61 || c === 95 || c === 45; // + / = _ -
}

/**
 * "=" can only be terminal padding in valid base64, so an "=" group with more
 * base64 characters after it inside one run separates two independent values
 * glued together — the common shapes being an env assignment (`NAME=<blob>`,
 * where the variable name and "=" would otherwise poison the blob) and a
 * padding-terminated blob directly followed by more encoded content. Split
 * there, keeping the padding attached to the value it terminates.
 */
function splitAtPadding(chunk) {
  const parts = [];
  let start = 0;
  for (let k = 0; k < chunk.length - 1; k++) {
    if (chunk.charCodeAt(k) === 61 && chunk.charCodeAt(k + 1) !== 61) { // "=" then non-"="
      parts.push(chunk.slice(start, k + 1));
      start = k + 1;
    }
  }
  parts.push(chunk.slice(start));
  return parts;
}

function b64Candidates(norm) {
  const candidates = []; // array of chunk arrays
  let truncated = false;
  let current = null;   // chunk array of the candidate in progress
  let runStart = -1;    // start of the b64 run in progress, -1 when not in one
  let gapClean = true;  // gap since the last chunk held only \r \n
  const push = (cand) => {
    if (candidates.length >= B64_MAX_CANDIDATES) { truncated = true; return false; }
    candidates.push(cand);
    return true;
  };
  const n = norm.length;
  for (let i = 0; i <= n; i++) {
    const c = i < n ? norm.charCodeAt(i) : -1; // one virtual terminator flushes the last run
    if (c !== -1 && isB64Code(c)) {
      if (runStart < 0) runStart = i;
      continue;
    }
    if (runStart >= 0) {
      const raw = norm.slice(runStart, i);
      runStart = -1;
      if (raw.length >= B64_MIN_CHUNK) {
        const parts = splitAtPadding(raw);
        for (let p = 0; p < parts.length; p++) {
          if (p === 0 && current !== null && gapClean) current.push(parts[p]);
          else {
            if (current !== null && !push(current)) return { candidates, truncated };
            current = [parts[p]];
          }
          // A part ending in padding is a complete value: nothing after it —
          // not even across a clean wrap gap — can belong to the same blob.
          if (parts[p].charCodeAt(parts[p].length - 1) === 61) {
            if (!push(current)) return { candidates, truncated };
            current = null;
          }
        }
        gapClean = true;
      } else {
        // A sub-minimum run is gap content, not a chunk: it breaks the wrap.
        gapClean = false;
      }
    }
    // Line breaks (CR, LF) keep a wrap gap clean; anything else — TAB and
    // space included, base64 wrapping uses neither — dirties it.
    if (c !== -1 && c !== 10 && c !== 13) gapClean = false;
  }
  if (current !== null) push(current);
  return { candidates, truncated };
}

/**
 * Decode a cleaned base64 run to text, or null if it is not decodable, is too
 * large, or decodes to mostly non-printable bytes (i.e. is not text worth
 * rescanning). Returns { text, encoding } where encoding is "base64url" when
 * the run used the URL-safe alphabet, else "base64".
 */
function decodeToText(cleaned) {
  if (cleaned.length < B64_MIN_CHARS || cleaned.length > B64_MAX_ENCODED) return null;
  // A wrapped blob decodes as one unit; a run that is not wholly base64 after
  // cleaning is not a base64 blob.
  if (!/^[A-Za-z0-9+/=_-]+$/.test(cleaned)) return null;
  const urlSafe = /[-_]/.test(cleaned);
  const std = urlSafe ? cleaned.replace(/-/g, "+").replace(/_/g, "/") : cleaned;
  let buf;
  try {
    buf = Buffer.from(std, "base64");
  } catch (e) {
    return null;
  }
  if (!buf.length || buf.length > 65536) return null;
  // Printable gate first (a cheap byte loop): most non-base64 alnum runs
  // (uuids, hashes, request ids) decode to non-text and are rejected here
  // before the costlier round-trip re-encode runs.
  let printable = 0;
  for (const b of buf) {
    if (b === 9 || b === 10 || b === 13 || (b >= 32 && b <= 126)) printable++;
  }
  if (printable / buf.length < PRINTABLE_MIN) return null;
  // Round-trip guard: Buffer.from is lenient and will "decode" strings that
  // are not really base64 by dropping stray bytes. If re-encoding does not
  // reproduce the input (modulo padding), this was not a base64 blob and its
  // "decoded" bytes are noise we should not rescan.
  const reenc = buf.toString("base64").replace(/=+$/, "");
  if (reenc !== std.replace(/=+$/, "")) return null;
  return { text: buf.toString("utf8"), encoding: urlSafe ? "base64url" : "base64" };
}

/**
 * Find credentials that appear only base64-encoded on one line. `rules` MUST
 * be the high-confidence subset (see LIMITS above). Returns
 * { matches, truncated } where matches is
 * [{ ruleId, label, confidence, value, encoding }] with `value` the DECODED
 * secret (caller redacts), deduped by rule+value so a blob echoed twice on
 * one line (content plus tool-result mirror) is one entry, and `truncated`
 * is true when the per-line candidate cap left runs unchecked (the caller
 * surfaces that as partial coverage, never silently).
 */
function findDecodedMatches(line, rules) {
  const out = [];
  const seen = new Set();
  const norm = normalizeEscapes(line);
  const { candidates, truncated } = b64Candidates(norm);
  for (const chunks of candidates) {
    // A wrap-merged candidate can carry one glued-on neighbor token: a word
    // or filename sitting directly above or below the blob across the wrap
    // newline merges into the candidate and breaks the decode (alignment
    // shift or round-trip failure). When the full join fails, retry once
    // with the first chunk dropped and once with the last chunk dropped —
    // the two positions a foreign neighbor can occupy. LIMIT: one edge
    // chunk only; junk on both edges or prose merged mid-blob still loses
    // the candidate. The round-trip guard in decodeToText applies to every
    // retry, so a retry can not "decode" junk into findings.
    const attempts = [chunks.join("")];
    if (chunks.length > 1) {
      attempts.push(chunks.slice(1).join(""));
      attempts.push(chunks.slice(0, -1).join(""));
    }
    let decoded = null;
    for (const a of attempts) { decoded = decodeToText(a); if (decoded) break; }
    if (!decoded) continue;
    for (const rule of rules) {
      rule.re.lastIndex = 0;
      let m;
      while ((m = rule.re.exec(decoded.text)) !== null) {
        const key = rule.id + "\u0000" + m[0];
        if (!seen.has(key)) {
          seen.add(key);
          out.push({ ruleId: rule.id, label: rule.label, confidence: rule.confidence, value: m[0], encoding: decoded.encoding });
        }
        if (m.index === rule.re.lastIndex) rule.re.lastIndex++;
      }
    }
  }
  return { matches: out, truncated };
}

// ── Feature 2: split-line boundary join ─────────────────────────────────────
//
// Streaming agents write a single assistant/user turn as several adjacent
// records, so a value can be split across two lines and never appear
// contiguously on either. We reconstruct the boundary and rescan it.
//
// The two fragments are the TAIL of the content on line A and the HEAD of the
// content on line B. In a JSONL transcript the conversational content is one
// string VALUE buried inside a per-record JSON envelope (ids, usage, cwd,
// timestamps), often hundreds of characters from the physical line edge. The
// "JSONL structural seam" separating the two fragments is therefore that
// whole envelope, not a couple of punctuation chars. We strip it in a general
// way: project each line to its free-text payload before taking the window.
//
// CONTENT PROJECTION: on a JSON line the free-text payload is the longest
// string VALUE. Conversational text (a sentence, a pasted blob) is long;
// structural metadata (uuids, model names, enums, paths, timestamps) is
// short. This is a property of records that wrap a message, true across agent
// transcript formats, and it never references a field name. Non-JSON lines
// (plain-text chat logs, shell history) are used as-is.
//
// LIMITS (general, honestly stated):
//  - Two-way splits only. A value broken across three or more records, or
//    with unrelated records interleaved between the halves, is out of scope.
//  - The projection assumes the split value lives in the line's LONGEST
//    string. A record whose longest string is not the conversational content
//    (e.g. a huge embedded blob or a very long path) defeats it.
//  - Only BOUNDARY_WINDOW chars from each side of the seam are joined, so a
//    fragment longer than that window (possible only for unbounded-length
//    token shapes) is not reconstructed; the raw pass still fires on any
//    prefix-bearing fragment, so the window never causes a silent all-clear.
//  - A reconstructed match must straddle the seam; a match lying wholly
//    within either original line is already reported by the single-line pass
//    and is dropped here, so nothing is double-counted.
//  - GREEDY-EXTENSION GUARD: a rule with an open-ended quantifier that
//    matches a value ending flush at line A's content end would "straddle"
//    by swallowing whatever alphanumeric characters happen to start line B's
//    content — fabricating a longer, never-existing value out of a complete
//    match plus its neighbor. So a straddling match is dropped when the same
//    rule already produces a complete match ending exactly at the seam (or
//    starting exactly at it) that the straddling match merely extends. The
//    cost, accepted knowingly: a token split so that its first fragment is
//    BY ITSELF a complete valid match of the same rule is reported as that
//    fragment (by the raw pass) rather than reconstructed — for fixed-length
//    token shapes, the common case, no such ambiguity exists.

const BOUNDARY_WINDOW = 300;   // chars taken from each side of the seam
const BOUNDARY_MIN_CONTENT = 24; // shorter "longest string" is treated as non-content

/**
 * Escape-aware list of JSON string-literal CONTENTS on a line. Field names
 * are included (this walker does not distinguish keys from values); the
 * longest-value projection below makes short structural strings lose, which
 * is what keeps keys out of the projection in practice.
 */
function jsonStringValues(line) {
  const out = [];
  const n = line.length;
  let i = 0;
  while (i < n) {
    if (line[i] === '"') {
      let j = i + 1;
      let buf = "";
      while (j < n) {
        const ch = line[j];
        if (ch === "\\") { buf += ch + (line[j + 1] || ""); j += 2; continue; }
        if (ch === '"') break;
        buf += ch;
        j++;
      }
      out.push(buf);
      i = j + 1;
    } else i++;
  }
  return out;
}

/** Project a line to its free-text payload (see CONTENT PROJECTION above). */
function contentProjection(line) {
  const t = line.trim();
  if (t[0] === "{" || t[0] === "[") {
    let longest = "";
    for (const s of jsonStringValues(line)) if (s.length > longest.length) longest = s;
    if (longest.length >= BOUNDARY_MIN_CONTENT) return longest;
  }
  return line;
}

/**
 * Find credentials split across the boundary of two adjacent lines. Takes the
 * CONTENT PROJECTIONS of the two lines (from contentProjection), which the
 * caller computes once per line and reuses across both of that line's pairs.
 * Returns [{ ruleId, label, confidence, value }] for matches that straddle
 * the seam; `value` is the reconstructed secret (caller redacts). Deduped by
 * rule+value.
 */
function findBoundaryMatches(contentA, contentB, rules) {
  const tail = contentA.slice(-BOUNDARY_WINDOW);
  const head = contentB.slice(0, BOUNDARY_WINDOW);
  if (!tail || !head) return [];
  const joined = tail + head;
  const seam = tail.length;
  const out = [];
  const seen = new Set();

  // GREEDY-EXTENSION GUARD (see LIMITS above): the start positions of this
  // rule's complete matches in the tail ALONE that end flush at the seam,
  // and the end positions (in joined coordinates) of its complete matches
  // in the head ALONE that start flush at the seam. A straddling match that
  // shares a start with the former or an end with the latter is a complete
  // single-line match greedily extended across the seam, not a
  // reconstruction, and reporting it would fabricate a value that exists
  // nowhere. Computed lazily: most pairs produce no straddling match.
  const seamFlush = (rule) => {
    const startsAtSeamEnd = new Set();
    const endsFromSeamStart = new Set();
    let t;
    rule.re.lastIndex = 0;
    while ((t = rule.re.exec(tail)) !== null) {
      if (t.index + t[0].length === seam) startsAtSeamEnd.add(t.index);
      if (t.index === rule.re.lastIndex) rule.re.lastIndex++;
    }
    rule.re.lastIndex = 0;
    while ((t = rule.re.exec(head)) !== null) {
      if (t.index === 0) endsFromSeamStart.add(seam + t[0].length);
      if (t.index === rule.re.lastIndex) rule.re.lastIndex++;
    }
    return { startsAtSeamEnd, endsFromSeamStart };
  };

  for (const rule of rules) {
    const straddles = [];
    rule.re.lastIndex = 0;
    let m;
    while ((m = rule.re.exec(joined)) !== null) {
      const start = m.index;
      const end = m.index + m[0].length;
      // Straddle-only: the match must cross the seam, else it lay wholly in
      // one line and the single-line pass already reported it.
      if (start < seam && end > seam) straddles.push({ start, end, value: m[0] });
      if (m.index === rule.re.lastIndex) rule.re.lastIndex++;
    }
    let flush = null;
    for (const p of straddles) {
      if (flush === null) flush = seamFlush(rule);
      if (flush.startsAtSeamEnd.has(p.start) || flush.endsFromSeamStart.has(p.end)) continue;
      const key = rule.id + "\u0000" + p.value;
      if (!seen.has(key)) {
        seen.add(key);
        out.push({ ruleId: rule.id, label: rule.label, confidence: rule.confidence, value: p.value });
      }
    }
  }
  return out;
}

module.exports = { findDecodedMatches, findBoundaryMatches, contentProjection };
