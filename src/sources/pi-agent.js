"use strict";

const fs = require("fs");
const { createInterface } = require("readline/promises");
const path = require("path");
const os = require("os");

/**
 * "Pi" (earendil-works/pi on GitHub; installed as `@mariozechner/pi-coding-agent`
 * from npm, run as the `pi` CLI) local session transcripts.
 *
 * VERIFICATION STATUS: corroborated directly from the project's own shipped
 * documentation (fetched from the live repo during this source's research),
 * but NOT checked against a real install on the machine this source was
 * built on (no `~/.pi` directory exists there; see CONTRIBUTING.md).
 *
 * `packages/coding-agent/docs/sessions.md` in the `earendil-works/pi` repo —
 * the project's own docs, not a third party's description of it — states
 * plainly: "Sessions auto-save to `~/.pi/agent/sessions/`, organized by
 * working directory. Each session is a JSONL file with a tree structure,"
 * further describing entries with `id`/`parentId` fields (branching), model
 * changes, thinking-level changes, labels, compactions, and branch summaries
 * all living in the same JSONL stream. "Organized by working directory"
 * means sessions live under per-project subdirectories rather than flat in
 * `sessions/` itself — the exact subdirectory naming isn't spelled out in
 * that doc, so this source walks recursively for `*.jsonl` rather than
 * assuming a fixed depth, the same tolerance claude-code.js applies to
 * project-slug directory names it doesn't try to decode either.
 *
 * Independently, jazzyalex/agent-sessions (github.com/jazzyalex/agent-sessions,
 * 800+ stars, a real macOS app built specifically to parse local
 * AI-coding-agent session history) lists Pi among the CLI agents whose local
 * history it reads, corroborating that this is real, currently-scanned-by-
 * someone-else session data rather than a doc describing an unshipped plan.
 */
const HOME = os.homedir();
const ROOT = path.join(HOME, ".pi", "agent", "sessions");

const MAX_BYTES = 2 * 1024 * 1024 * 1024; // 2GB — same backstop as claude-code.js.
const READ_TIMEOUT_MS = 60_000;
const MAX_WALK_DEPTH = 8;

function id() { return "pi-agent"; }
function label() { return "Pi"; }

function available() {
  try { return fs.statSync(ROOT).isDirectory(); } catch { return false; }
}

/**
 * Same defensive symlink-following helpers as claude-code.js — see that
 * file's docstring. Duplicated rather than imported, per this project's
 * self-contained-source-file convention (see cursor.js's docstring).
 */
function isKindFollowingSymlink(fullPath, dirent, checkFn) {
  if (checkFn(dirent)) return true;
  if (!dirent.isSymbolicLink()) return false;
  try { return checkFn(fs.statSync(fullPath)); } catch { return false; }
}
const isDirFollowingSymlink = (p, d) => isKindFollowingSymlink(p, d, (x) => x.isDirectory());
const isFileFollowingSymlink = (p, d) => isKindFollowingSymlink(p, d, (x) => x.isFile());

/**
 * Recursively yield { file, mtimeMs, sizeBytes, broken } for every plain file
 * under `dir` whose name passes `matchFn`, following symlinks and reporting
 * one that resolves to neither a file nor a directory as `broken: true` — see
 * factory-droid.js's walk() for the identical reasoning (this project
 * duplicates this small helper per source file rather than sharing it; see
 * cursor.js's docstring on why).
 */
function* walk(dir, depth, matchFn) {
  if (depth > MAX_WALK_DEPTH) return;
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); }
  catch { return; }

  for (const e of entries) {
    const full = path.join(dir, e.name);
    if (isDirFollowingSymlink(full, e)) {
      yield* walk(full, depth + 1, matchFn);
      continue;
    }
    const isFile = isFileFollowingSymlink(full, e);
    if (!isFile) {
      if (e.isSymbolicLink()) yield { file: full, broken: true };
      continue;
    }
    if (!matchFn(e.name)) continue;
    let stat;
    try { stat = fs.statSync(full); } catch { yield { file: full, broken: true }; continue; }
    yield { file: full, mtimeMs: stat.mtimeMs, sizeBytes: stat.size, broken: false };
  }
}

function* files() {
  yield* walk(ROOT, 0, (name) => name.endsWith(".jsonl"));
}

/**
 * Read one JSONL session as raw text lines. Identical streaming/timeout/
 * partial-read discipline to claude-code.js's readLines().
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
