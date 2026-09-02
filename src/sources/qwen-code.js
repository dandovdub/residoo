"use strict";

const fs = require("fs");
const { createInterface } = require("readline/promises");
const path = require("path");
const os = require("os");

/**
 * Qwen Code (QwenLM/qwen-code) session/chat transcripts.
 *
 * VERIFICATION STATUS (read this before trusting anything below): this
 * source is corroborated by the actual current source code of the official
 * QwenLM/qwen-code repository on GitHub (fetched and read directly) plus
 * that project's own published docs and GitHub issues from real users
 * describing real installs. It has NOT been checked against a real Qwen
 * Code install or real transcript content — Qwen Code is not installed on
 * the machine this adapter was built on (checked: no `qwen` on PATH, no
 * `~/.qwen` directory, no `@qwen-code/qwen-code` in global npm packages).
 * If you have Qwen Code installed, the most useful thing you can do is run
 * `residoo scan` and confirm `sourcesScanned`/`filesScanned` look right for
 * what you know is actually on disk under `~/.qwen`, then report back
 * either way.
 *
 * Qwen Code began as a fork of google-gemini/gemini-cli (same author's
 * `ChatRecordingService` naming, same general architecture) retargeted at
 * Alibaba's Qwen models, but its storage layout has since diverged from
 * gemini-cli's rather than staying a copy with the dotfolder renamed — this
 * source was built by reading QwenLM/qwen-code's OWN code, not by assuming
 * it still matches gemini-cli.js's layout.
 *
 * Storage location, confirmed directly from source
 * (packages/core/src/config/storage.ts and
 * packages/core/src/services/chatRecordingService.ts on QwenLM/qwen-code's
 * `main` branch):
 *
 *   - Base directory: `$QWEN_HOME/.qwen` if that env var is set (confirmed
 *     directly in `getGlobalQwenDir()`'s source: `process.env['QWEN_HOME']`,
 *     resolved and used as-is), otherwise `~/.qwen` (`QWEN_DIR = '.qwen'`
 *     joined onto `os.homedir()`, with a documented fallback to
 *     `os.tmpdir()/.qwen` if `os.homedir()` itself comes back empty — no
 *     other per-OS branching, same as gemini-cli).
 *   - Current (as of this research) chat storage:
 *     `~/.qwen/projects/<sanitizedCwd>/chats/<sessionId>.jsonl` —
 *     `PROJECT_DIR_NAME = 'projects'`, `getProjectDir()` joins it with
 *     `sanitizeCwd(projectRoot)`, and `ChatRecordingService` writes
 *     `path.join(storage.getProjectDir(), 'chats', sessionId + '.jsonl')`,
 *     one JSON record appended per line (metadata line first, then one
 *     record per turn) — confirmed directly in chatRecordingService.ts.
 *     Inactive sessions get moved into a `chats/archive/` subdirectory
 *     (per Qwen Code's own daemon/session-lifecycle docs) rather than
 *     deleted, so archived transcripts are still real, still-scannable
 *     content sitting one level deeper.
 *   - A SEPARATE, older-style temp dir also still exists in the current
 *     source: `~/.qwen/tmp/<hash>/` (`TMP_DIR_NAME = 'tmp'`,
 *     `getProjectTempDir()` using a SHA-256 `getProjectHash()`, the same
 *     shape gemini-cli.js's tmp dir uses) — but on the current codebase
 *     this is used for `checkpoints/`, not `chats/`. Because this project
 *     is a fork whose own history plausibly went through the same
 *     "everything under tmp/" phase gemini-cli.js's docstring describes
 *     before settling on `projects/`, this source defensively ALSO walks
 *     `tmp/<id>/chats/` if present — cheap when absent (a single failed
 *     readdir), and catches transcripts left behind by an older Qwen Code
 *     version without having to know exactly which version drew the line.
 *
 * Deliberately OUT OF SCOPE: an experimental PROJECT-LOCAL history mode
 * referenced in qwen-code's own issue tracker — `getHistoryDir()` falling
 * back to `<projectRoot>/.qwen/chat-history/` instead of a home-directory
 * location when enabled. Every other source in residoo (including this
 * one's primary path) scans one well-known location under the user's home
 * directory; walking every project directory anywhere on disk looking for
 * a stray `.qwen/chat-history` folder is a fundamentally different, far
 * broader operation this source does not attempt. Also out of scope, for
 * the same reasoning as gemini-cli.js: `<projectTempDir>/checkpoints/`.
 *
 * Sources consulted: QwenLM/qwen-code source on GitHub (storage.ts,
 * chatRecordingService.ts, fetched from the `main` branch); Qwen Code's own
 * published docs at qwenlm.github.io/qwen-code-docs (session-lifecycle and
 * daemon-mode pages, confirming the `chats/` + `chats/archive/` structure
 * and JSONL format at a description level); GitHub issues #2373, #1100 and
 * #3606 on QwenLM/qwen-code (real users describing session resume/export
 * behavior against their own installs).
 */
function qwenHomeDir() {
  const base = process.env.QWEN_HOME || os.homedir() || os.tmpdir();
  return path.join(base, ".qwen");
}

const ROOT = qwenHomeDir();
const PROJECTS_DIR = path.join(ROOT, "projects");
const TMP_DIR = path.join(ROOT, "tmp"); // legacy/defensive, see module docstring
const CHAT_FILE_EXT = /\.(jsonl|json)$/i;

// See gemini-cli.js's identical constant for the reasoning — bounded rather
// than hard-coded at exactly the one nesting level (chats/archive/)
// confirmed from source, so a further nesting change gets scanned rather
// than silently missed, and bounded at all so a symlink cycle can't turn
// this into an infinite walk.
const MAX_CHATS_DEPTH = 4;

// Same caveat as gemini-cli.js's identical constant: a generous, untested
// backstop, not evidence from a real large Qwen Code transcript — no
// install was available to produce one.
const MAX_BYTES = 2 * 1024 * 1024 * 1024; // 2GB
const READ_TIMEOUT_MS = 60_000;

function id() { return "qwen-code"; }
function label() { return "Qwen Code"; }

function available() {
  try { return fs.statSync(ROOT).isDirectory(); } catch { return false; }
}

/**
 * Same defensive symlink-following pattern as claude-code.js — see that
 * file's docstring for the full reasoning. Duplicated rather than imported:
 * each source here is meant to be a small, self-contained file a reviewer
 * can audit on its own (see CONTRIBUTING.md).
 */
function isKindFollowingSymlink(fullPath, dirent, checkFn) {
  if (checkFn(dirent)) return true;
  if (!dirent.isSymbolicLink()) return false;
  try { return checkFn(fs.statSync(fullPath)); } catch { return false; }
}
const isDirFollowingSymlink = (p, d) => isKindFollowingSymlink(p, d, (x) => x.isDirectory());
const isFileFollowingSymlink = (p, d) => isKindFollowingSymlink(p, d, (x) => x.isFile());

/**
 * Walk a `chats/` directory (or one of its subdirectories, e.g. `archive/`)
 * for candidate session files, up to MAX_CHATS_DEPTH levels deep. A missing
 * directory yields nothing and is NOT reported broken — a project that has
 * never recorded a chat, or a Qwen Code version that never wrote `tmp/`
 * chats at all, is normal absence, same convention cursor.js's
 * statIfPresent() uses. A directory that exists but can't be read, or a
 * symlink that can't be resolved, IS reported broken.
 */
function* walkChatFiles(dir, depth) {
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); }
  catch { return; }

  for (const e of entries) {
    const full = path.join(dir, e.name);

    if (isDirFollowingSymlink(full, e)) {
      if (depth < MAX_CHATS_DEPTH) yield* walkChatFiles(full, depth + 1);
      continue;
    }
    if (isFileFollowingSymlink(full, e)) {
      if (!CHAT_FILE_EXT.test(e.name)) continue;
      let stat;
      try { stat = fs.statSync(full); } catch { yield { file: full, broken: true }; continue; }
      yield { file: full, mtimeMs: stat.mtimeMs, sizeBytes: stat.size, broken: false };
      continue;
    }
    // Neither resolves as a directory nor a file: a dangling symlink is the
    // one case worth reporting.
    if (e.isSymbolicLink()) yield { file: full, broken: true };
  }
}

/**
 * Enumerate every immediate child of `parentDir` as a candidate project
 * directory and walk its `chats/` subdirectory. Shared between the current
 * `projects/<sanitizedCwd>/` layout and the legacy/defensive `tmp/<hash>/`
 * one — both are "one directory per project, chats live in a `chats/`
 * subdirectory of it," differing only in how the per-project name was
 * derived, which this source does not try to recompute (see module
 * docstring on `sanitizeCwd`/`getProjectHash`).
 */
function* walkProjectDirs(parentDir) {
  let projectDirs;
  try { projectDirs = fs.readdirSync(parentDir, { withFileTypes: true }); }
  catch { return; }

  for (const projEnt of projectDirs) {
    const projDir = path.join(parentDir, projEnt.name);
    if (!isDirFollowingSymlink(projDir, projEnt)) {
      if (projEnt.isSymbolicLink()) yield { file: projDir, broken: true };
      continue;
    }
    yield* walkChatFiles(path.join(projDir, "chats"), 0);
  }
}

/**
 * Yield { file, mtimeMs, sizeBytes, broken } for every Qwen Code chat
 * transcript found under `~/.qwen/projects/<id>/chats/` (current layout)
 * and, defensively, `~/.qwen/tmp/<id>/chats/` (legacy layout — see module
 * docstring). A project directory present in both would be enumerated
 * independently under each root; in practice a given project's chats live
 * under one or the other depending on which Qwen Code version wrote them,
 * so this is not expected to double-count real files, only to widen which
 * Qwen Code versions' transcripts get found.
 */
function* files() {
  yield* walkProjectDirs(PROJECTS_DIR);
  yield* walkProjectDirs(TMP_DIR);
}

/**
 * Read one transcript as an array of raw text lines. Identical approach to
 * claude-code.js's readLines() — see that file's docstring for the full
 * reasoning (streamed via readline/promises, a generous size cap, a hard
 * read timeout since Node's stream/readline stack has none built in); not
 * re-derived here since nothing about it is Qwen-Code-specific.
 *
 * Works the same whether `file` is JSONL (the current, and documented,
 * format) or a legacy whole-session `.json` document — per the adapter
 * contract, lines don't need to be valid JSON individually, they just need
 * pattern-matching against.
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
      bytesRead += Buffer.byteLength(line, "utf-8") + 1; // +1 for the stripped newline
    }
    return { lines, status: "complete", bytesRead };
  } catch {
    // Whatever WAS read before the failure is real content and may contain
    // a real secret — discarding it because the file didn't finish cleanly
    // would be a silent false negative, which is worse than an honest
    // "partial" label.
    return { lines, status: lines.length > 0 ? "partial" : "failed", bytesRead };
  } finally {
    clearTimeout(timer);
    rl.close();
    stream.destroy();
  }
}

module.exports = { id, label, available, files, readLines };
