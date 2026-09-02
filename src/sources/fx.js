"use strict";

const fs = require("fs");
const { createInterface } = require("readline/promises");
const path = require("path");
const os = require("os");

/**
 * Vercel Labs' "fx" coding agent (github.com/vercel-labs/fx, Apache-2.0,
 * released 2026-08-17) local session transcripts.
 *
 * VERIFICATION STATUS: read directly from the actual, current shipped source
 * (Zig) of vercel-labs/fx@main (fetched from GitHub during this source's
 * research) — but NOT checked against a real install on the machine this
 * source was built on (no `~/.fx` directory exists there; see
 * CONTRIBUTING.md). fx is a genuinely new project (released roughly two
 * weeks before this source was written), so its real-world adoption is still
 * emerging relative to the other sources in this project — flagged here so
 * that's visible alongside the (otherwise strong) path verification.
 *
 * The chain of evidence, from vercel-labs/fx@main:
 *   - `src/core/shared/profile_paths.zig` defines
 *     `root_dir_name = ".fx"` and `sessions_dir_name = "sessions"`, with
 *     `sessionsDir()` joining `<home>/.fx/sessions` — confirmed further by
 *     that same file's own unit test asserting
 *     `rootDir(alloc, "/tmp/fake-home")` equals `"/tmp/fake-home/.fx"`.
 *   - `src/core/session/session_log.zig` defines the per-session file names
 *     used underneath that directory:
 *     `events_file = "events.jsonl"` (the append-only record log — every
 *     event, per that file's own field naming alongside `authority_file`,
 *     `commit_lock_file`, etc.), plus `manifest_file = "session.json"` and
 *     `checkpoint_file = "checkpoint.json"` (a periodic snapshot, not the
 *     primary record). This source targets only `events.jsonl` — the one
 *     file documented as holding every record, matching the "one canonical
 *     transcript stream" shape this project's other JSONL sources scan,
 *     rather than also reading the redundant checkpoint snapshots.
 *
 * `sessionsDir()`'s own constants give the root and the two directory names
 * confirmed above; the exact per-session subdirectory naming underneath
 * `sessions/` (session_layout.zig, not fetched during this research) isn't
 * relied on — this source walks recursively for `events.jsonl` instead of
 * assuming a fixed depth, the same tolerance claude-code.js applies to
 * Claude Code's own project-slug directory names.
 */
const HOME = os.homedir();
const SESSIONS_ROOT = path.join(HOME, ".fx", "sessions");

const MAX_BYTES = 2 * 1024 * 1024 * 1024; // 2GB — same backstop as claude-code.js.
const READ_TIMEOUT_MS = 60_000;
const MAX_WALK_DEPTH = 8;

function id() { return "fx"; }
function label() { return "fx"; }

function available() {
  try { return fs.statSync(SESSIONS_ROOT).isDirectory(); } catch { return false; }
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
 * under `dir` whose name passes `matchFn` — see factory-droid.js's walk()
 * for the identical reasoning.
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
  yield* walk(SESSIONS_ROOT, 0, (name) => name === "events.jsonl");
}

/**
 * Read one events.jsonl transcript as raw text lines. Identical streaming/
 * timeout/partial-read discipline to claude-code.js's readLines().
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
