"use strict";

const fs = require("fs");
const { createInterface } = require("readline/promises");
const path = require("path");
const os = require("os");

/**
 * PearAI's local chat session history.
 *
 * VERIFICATION STATUS (read this before trusting anything below): PearAI is
 * an open-source VS Code fork (github.com/trypear/pearai-app) whose AI chat
 * is powered by "pearai-submodule" — itself an open-source fork of
 * Continue (github.com/continuedev/continue), bundled into the app rather
 * than installed as a marketplace extension. This matters because it means
 * PearAI does NOT use Cursor/VS Code's per-profile `state.vscdb` SQLite
 * approach for chat content — it inherited Continue's own file-based session
 * store instead. This was confirmed directly from two independent sources:
 *
 *   1. PearAI's own shipped source, `pearai-submodule/core/util/paths.ts`
 *      (fetched from trypear/pearai-submodule@main), which defines:
 *        const CONTINUE_GLOBAL_DIR =
 *          process.env.CONTINUE_GLOBAL_DIR ?? path.join(os.homedir(), ".pearai");
 *      and derives the sessions folder as `<CONTINUE_GLOBAL_DIR>/sessions`,
 *      individual session files as `<sessionId>.json`, and an index file at
 *      `sessions.json`. Note this path has NO per-OS branching — it is
 *      `os.homedir()/.pearai` on every platform, unlike VS Code-derived
 *      products (Cursor, Trae, Void) whose Application Support-style path
 *      differs per OS. (PearAI still ships a VS Code-derived Application
 *      Support/state.vscdb tree too, for ordinary editor/window state, but
 *      that is generic VS Code chrome, not where chat content lives — kept
 *      out of scope here the same way claude-code.js and cursor.js each stay
 *      scoped to where the actual transcript content lives, not every file
 *      the host editor happens to write.)
 *   2. `claude-code-history-viewer` (github.com/jhlee0409/claude-code-history-viewer),
 *      an actively maintained, independently authored desktop app that reads
 *      this exact same layout — its `src-tauri/src/providers/pearai.rs`
 *      module doc reads (fetched verbatim): "PearAI is a fork of Continue
 *      that rebrands the global directory from ~/.continue to ~/.pearai. The
 *      session store format is identical (<sessionId>.json + sessions.json
 *      index)."
 *
 * Both sources agree exactly on the directory, the per-file naming, and the
 * index file. What this source has NOT been checked against is a real
 * PearAI install — PearAI is not installed on the machine this was built on
 * (checked: not in /Applications, not in ~/Library/Application Support, no
 * mdfind hits). If you have PearAI installed and have used its chat at
 * least once, the most useful thing you can do is run `residoo scan` and
 * confirm `sourcesScanned`/`filesScanned` for "pearai" look right against
 * what you can see under ~/.pearai/sessions, then report back either way.
 *
 * Session files are plain JSON text on disk (not SQLite), so — like
 * claude-code.js's JSONL files — they can be streamed and pattern-matched
 * line by line with no parsing required: a pretty-printed session file
 * naturally splits into one scannable line per field, and even a minified
 * one degrades gracefully into a single long line, still fully scanned.
 * `sessions.json` (the index) is included too, on the same "never
 * cherry-pick which files might matter" principle the other sources follow.
 */
const PEARAI_DIR = path.join(os.homedir(), ".pearai");
const SESSIONS_DIR = path.join(PEARAI_DIR, "sessions");

// Same bounds and same rationale as claude-code.js — no PearAI-specific
// large-file data point exists (no real install to measure against), so
// these are carried over unchanged as a generous, conservative backstop.
const MAX_BYTES = 2 * 1024 * 1024 * 1024; // 2GB
const READ_TIMEOUT_MS = 60_000;

function id() { return "pearai"; }
function label() { return "PearAI"; }

function available() {
  try { return fs.statSync(SESSIONS_DIR).isDirectory(); } catch { return false; }
}

/**
 * Same defensive symlink-following helper as claude-code.js — see that
 * file's docstring for the full reasoning. Duplicated rather than shared,
 * matching this project's "each source is a small, self-contained file"
 * convention (stated explicitly in cursor.js).
 */
function isFileFollowingSymlink(fullPath, dirent) {
  if (dirent.isFile()) return true;
  if (!dirent.isSymbolicLink()) return false;
  try { return fs.statSync(fullPath).isFile(); } catch { return false; }
}

/**
 * Yield { file, mtimeMs, sizeBytes, broken } for every session file found.
 *
 * Unlike claude-code.js's two-level walk (project dir -> transcripts), the
 * confirmed layout here is flat: every `*.json` file directly inside
 * `~/.pearai/sessions` — individual `<sessionId>.json` files plus the
 * `sessions.json` index — so this is a single readdir, not a nested one.
 */
function* files() {
  let entries;
  try { entries = fs.readdirSync(SESSIONS_DIR, { withFileTypes: true }); }
  catch { return; }

  for (const e of entries) {
    if (!e.name.endsWith(".json")) continue;
    const file = path.join(SESSIONS_DIR, e.name);
    if (!e.isFile()) {
      const resolved = isFileFollowingSymlink(file, e);
      if (!resolved) {
        if (e.isSymbolicLink()) yield { file, broken: true };
        continue;
      }
    }
    let stat;
    try { stat = fs.statSync(file); } catch { yield { file, broken: true }; continue; }
    yield { file, mtimeMs: stat.mtimeMs, sizeBytes: stat.size, broken: false };
  }
}

/**
 * Read one session file as an array of raw text lines. Same streamed,
 * bounded, honest-partial-status approach as claude-code.js's readLines() —
 * see that file's docstring for the full reasoning, which applies unchanged
 * here since this is likewise a plain text file on disk.
 */
async function readLines(file) {
  let stat;
  try { stat = fs.statSync(file); }
  catch { return { lines: [], status: "failed", bytesRead: 0 }; }
  if (stat.size > MAX_BYTES) return { lines: [], status: "too-large", bytesRead: 0 };

  const lines = [];
  let bytesRead = 0;
  const stream = fs.createReadStream(file, { encoding: "utf-8" });
  const rl = createInterface({ input: stream, crlfDelay: Infinity });

  const timer = setTimeout(() => stream.destroy(new Error("read timed out")), READ_TIMEOUT_MS);

  try {
    for await (const line of rl) {
      lines.push(line);
      bytesRead += Buffer.byteLength(line, "utf-8") + 1;
    }
    return { lines, status: "complete", bytesRead };
  } catch {
    return { lines, status: lines.length > 0 ? "partial" : "failed", bytesRead };
  } finally {
    clearTimeout(timer);
    rl.close();
    stream.destroy();
  }
}

module.exports = { id, label, available, files, readLines };
