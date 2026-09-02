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

// Characters that can appear in a base64 or base64url run.
const B64_CHARS = "A-Za-z0-9+/=_\\-";
// Wrap separators between chunks of one logical blob are line breaks (CR, LF,
// TAB) — the wrap whitespace that base64 line-wrapping uses. Spaces are NOT a
// separator: base64 wrapping never uses them, and merging on spaces would
// splice ordinary prose words together. When wrapped base64 is embedded in a
// JSON string the line breaks arrive as the escape sequences \n \r \t (two
// chars, backslash+letter); normalizeEscapes() turns those into real line
// breaks first, so the escape's letter can never leak into a run.
const B64_CHUNK = "[" + B64_CHARS + "]{4,}";
const B64_CANDIDATE = new RegExp(B64_CHUNK + "(?:[\\r\\n\\t]+" + B64_CHUNK + ")*", "g");

const B64_MIN_CHARS = 24;          // fewer chars cannot hide a real credential
const B64_MAX_ENCODED = 90000;     // ~64KB decoded ceiling; skip bigger runs
const B64_MAX_CANDIDATES = 256;    // per line, so a pathological line stays bounded
const PRINTABLE_MIN = 0.85;        // decoded bytes must be mostly text to rescan

/** JSON whitespace escapes -> the real line breaks they stand for. */
function normalizeEscapes(line) {
  return line.replace(/\\n/g, "\n").replace(/\\r/g, "\r").replace(/\\t/g, "\t");
}

/** Strip the line-break separators from a wrapped candidate. */
function cleanCandidate(raw) {
  return raw.replace(/[\r\n\t]+/g, "");
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
 * [{ ruleId, label, confidence, value, encoding }] with `value` the DECODED
 * secret (caller redacts). Deduped by rule+value so a blob echoed twice on
 * one line (content plus tool-result mirror) is one entry.
 */
function findDecodedMatches(line, rules) {
  const out = [];
  const seen = new Set();
  const norm = normalizeEscapes(line);
  let cand;
  let count = 0;
  B64_CANDIDATE.lastIndex = 0;
  while ((cand = B64_CANDIDATE.exec(norm)) !== null) {
    if (cand.index === B64_CANDIDATE.lastIndex) B64_CANDIDATE.lastIndex++;
    if (++count > B64_MAX_CANDIDATES) break;
    const decoded = decodeToText(cleanCandidate(cand[0]));
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
  return out;
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
//  - A reconstructed match must straddle the seam; a match lying wholly
//    within either original line is already reported by the single-line pass
//    and is dropped here, so nothing is double-counted.

const BOUNDARY_WINDOW = 300;   // chars taken from each side of the seam
const BOUNDARY_MIN_CONTENT = 24; // shorter "longest string" is treated as non-content

/** Escape-aware list of JSON string-literal CONTENTS on a line (no field names). */
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
  for (const rule of rules) {
    rule.re.lastIndex = 0;
    let m;
    while ((m = rule.re.exec(joined)) !== null) {
      const start = m.index;
      const end = m.index + m[0].length;
      // Straddle-only: the match must cross the seam, else it lay wholly in
      // one line and the single-line pass already reported it.
      if (start < seam && end > seam) {
        const key = rule.id + "\u0000" + m[0];
        if (!seen.has(key)) {
          seen.add(key);
          out.push({ ruleId: rule.id, label: rule.label, confidence: rule.confidence, value: m[0] });
        }
      }
      if (m.index === rule.re.lastIndex) rule.re.lastIndex++;
    }
  }
  return out;
}

module.exports = { findDecodedMatches, findBoundaryMatches, contentProjection };
