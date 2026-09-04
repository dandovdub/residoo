"use strict";

/**
 * Opt-in OCR of pasted-screenshot images inside a transcript (--ocr).
 *
 * Everything else in residoo detects secrets in TEXT already sitting in a
 * transcript line. This module covers a real, verified-unclaimed gap: a
 * user pastes a screenshot of a .env file, a cloud console page, or a
 * terminal into their AI agent, and the credential in that image is
 * invisible to every text-based rule in patterns.js. Real, ground-truth
 * inspection of this machine's own Claude Code session files confirms the
 * exact shape a pasted or tool-returned image takes in the JSONL transcript
 * (both as a direct message content block and nested inside a tool_result):
 *   {"type":"image","source":{"type":"base64","media_type":"image/png","data":"<base64>"}}
 * This module's job stops at extracting that data and turning it into text;
 * the text then flows through the exact same PATTERNS rules and redact()
 * every other line in a transcript does — no new detection logic, no new
 * false-positive surface, just a new place text can come from.
 *
 * Same shell-out posture as verify.js's AWS check, for the same reason:
 * residoo ships zero runtime dependencies, and a correct from-scratch OCR
 * engine is not something this project could build or verify. tesseract is
 * the mature, widely-packaged, offline OCR engine every major distro and
 * Homebrew ships; shelling out to an already-installed copy costs nothing
 * at install time and adds no dependency residoo itself carries. Off by
 * default: it requires tesseract to be installed, and it is real CPU work
 * per image, unlike every other rule in this file which is a regex over
 * text already in memory.
 *
 * Image bytes go to tesseract over stdin and its output is read back over
 * stdout -- never written to a file, matching every other credential-
 * bearing value in this codebase never touching disk unless --seal is
 * explicitly asked for. Nothing here makes a network call; tesseract's own
 * OCR is 100% local.
 *
 * HONEST LIMITATION, found by testing this module against a real rendered
 * image before shipping it (not assumed): OCR is lossy. A real test against
 * a clean, large, monospace "AKIASM0KETESTFAKEKEY"-shaped string produced
 * "AKIASM@KETESTFAKEKE*" at low resolution and "AKIASMOKETESTFAKEKE*" (0
 * misread as O, trailing Y misread as *) even at 2x resolution -- visually
 * similar characters (0/O, Y/*) are a real, inherent tesseract failure
 * mode, not a bug in how this module invokes it. A single misread character
 * breaks an exact-format regex match. This means --ocr is best-effort
 * additive coverage on a previously-zero-coverage surface, not a guarantee
 * every credential in every screenshot will be caught -- documented here so
 * that claim is never overstated in the CLI help text or README either.
 */

const { spawnSync } = require("child_process");

// Test-only escape hatch, same pattern as verify.js's RESIDOO_TEST_AWS_CLI:
// when set, every spawnSync call below runs that path instead of
// "tesseract" on PATH, so tests exercise the real spawnSync + stdin/stdout
// plumbing against a small fixture script rather than requiring the real
// tesseract binary (or the network) on every machine that runs `npm test`.
function tesseractBinary() {
  return process.env.RESIDOO_TEST_TESSERACT || "tesseract";
}

function isTesseractAvailable(spawnFn = spawnSync) {
  try {
    const r = spawnFn(tesseractBinary(), ["--version"], {
      timeout: 5000,
      env: { PATH: process.env.PATH || "" },
      stdio: ["ignore", "ignore", "ignore"],
    });
    return !r.error && r.status === 0;
  } catch {
    return false;
  }
}

// A real screenshot is rarely more than a few MB; this is a generous
// ceiling against a maliciously or accidentally huge "image" field in an
// attacker-plantable transcript, not a real-world limit. Base64 is ~4/3
// the decoded size, hence the larger character-count bound.
const MAX_BASE64_CHARS = 30_000_000; // ~22 MB decoded
// A single line with hundreds of embedded images (crafted or corrupted)
// must not turn --ocr into a hang; cap how many this module will even
// attempt per line. Real transcripts have at most a handful of images per
// message.
const MAX_BLOCKS_PER_LINE = 8;
const MAX_WALK_DEPTH = 12; // defensive bound against pathological nesting

const KNOWN_IMAGE_MEDIA_TYPES = new Set(["image/png", "image/jpeg", "image/webp", "image/gif"]);

/**
 * Find every {type:"image", source:{type:"base64", data, media_type}}
 * block in a transcript line, at any nesting depth (a direct message
 * content block and a tool_result's nested content block are both real,
 * confirmed shapes -- see this file's own docstring). Returns
 * [{ data, mediaType }], capped at MAX_BLOCKS_PER_LINE.
 *
 * Not every source's lines are JSON (or valid JSON) -- a malformed or
 * partial line fails JSON.parse and this returns [] rather than throwing,
 * the same fail-quiet-on-this-one-line posture decode.js's contentProjection
 * already has for the exact same reason.
 */
function extractImageBlocks(line) {
  const t = typeof line === "string" ? line.trim() : "";
  if (t[0] !== "{" && t[0] !== "[") return [];
  let parsed;
  try { parsed = JSON.parse(t); } catch { return []; }

  const out = [];
  const walk = (node, depth) => {
    if (out.length >= MAX_BLOCKS_PER_LINE || depth > MAX_WALK_DEPTH || node == null || typeof node !== "object") return;
    if (Array.isArray(node)) {
      for (const item of node) { if (out.length >= MAX_BLOCKS_PER_LINE) return; walk(item, depth + 1); }
      return;
    }
    const source = node.source;
    if (
      node.type === "image" && source && typeof source === "object" &&
      source.type === "base64" && typeof source.data === "string" && source.data.length > 0 &&
      source.data.length <= MAX_BASE64_CHARS &&
      KNOWN_IMAGE_MEDIA_TYPES.has(source.media_type)
    ) {
      out.push({ data: source.data, mediaType: source.media_type });
      return; // an image block's own fields are never themselves nested image blocks
    }
    for (const key of Object.keys(node)) { if (out.length >= MAX_BLOCKS_PER_LINE) return; walk(node[key], depth + 1); }
  };
  walk(parsed, 0);
  return out;
}

const DEFAULT_TIMEOUT_MS = 20_000;

/** Strip control bytes: OCR output flows into the exact same matching/redaction path as any other text, but must never carry a raw control byte into a terminal. */
function stripControlChars(s) { return String(s || "").replace(/[\x00-\x1f\x7f]/g, ""); }

/**
 * OCR one image's base64 data via tesseract over stdin/stdout. Returns
 * { text, error }: text is "" (never null) on any failure, so a caller
 * never needs a null check before feeding it through the pattern-matching
 * loop; error names why when text is empty, for --ocr's own diagnostics,
 * never surfaced as a scan failure (an unreadable or corrupt image is not
 * a reason to fail the whole scan).
 */
function ocrImageBase64(base64Data, { spawnFn = spawnSync, timeoutMs = DEFAULT_TIMEOUT_MS } = {}) {
  let buf;
  try {
    buf = Buffer.from(base64Data, "base64");
  } catch (e) {
    return { text: "", error: `could not decode base64 image data (${e && e.message})` };
  }
  if (buf.length === 0) return { text: "", error: "decoded image was empty" };

  let r;
  try {
    r = spawnFn(tesseractBinary(), ["stdin", "stdout"], {
      input: buf,
      timeout: timeoutMs,
      maxBuffer: 10 * 1024 * 1024,
      env: { PATH: process.env.PATH || "" },
    });
  } catch (e) {
    return { text: "", error: `tesseract failed to run (${e && e.message})` };
  }
  if (r.error) {
    if (r.error.code === "ENOENT") return { text: "", error: "tesseract not found on PATH" };
    if (r.error.code === "ETIMEDOUT") return { text: "", error: `tesseract timed out after ${timeoutMs}ms` };
    return { text: "", error: `tesseract failed to run (${r.error.code || r.error.message})` };
  }
  if (r.status !== 0) {
    return { text: "", error: `tesseract exited ${r.status}` };
  }
  return { text: stripControlChars((r.stdout || "").toString("utf-8")), error: null };
}

module.exports = { isTesseractAvailable, extractImageBlocks, ocrImageBase64, tesseractBinary };
