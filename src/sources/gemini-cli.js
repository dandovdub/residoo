"use strict";

const fs = require("fs");
const { createInterface } = require("readline/promises");
const path = require("path");
const os = require("os");

/**
 * Gemini CLI (google-gemini/gemini-cli) session/chat transcripts.
 *
 * VERIFICATION STATUS (read this before trusting anything below): this
 * source is corroborated by the actual current source code of the official
 * google-gemini/gemini-cli repository on GitHub (fetched and read directly,
 * not inferred from a description of it) plus that project's own published
 * docs and multiple independent GitHub discussions/issues from real users
 * describing real installs. It has NOT been checked against a real Gemini
 * CLI install or real transcript content — Gemini CLI is not installed on
 * the machine this adapter was built on (checked: no `gemini` on PATH, no
 * `~/.gemini` directory, no `@google/gemini-cli` in global npm packages).
 * If you have Gemini CLI installed, the most useful thing you can do is run
 * `residoo scan` and confirm `sourcesScanned`/`filesScanned` look right for
 * what you know is actually on disk under `~/.gemini/tmp`, then report back
 * either way.
 *
 * Storage location, confirmed directly from source
 * (packages/core/src/config/storage.ts, packages/core/src/utils/paths.ts,
 * packages/core/src/services/chatRecordingService.ts on the `main` branch):
 *
 *   - Base directory: `$GEMINI_CLI_HOME/.gemini` if that env var is set
 *     (documented in docs/reference/configuration.md — "Specifies the root
 *     directory for Gemini CLI's user-level configuration and storage...
 *     The CLI will create a `.gemini` folder inside this directory"),
 *     otherwise `~/.gemini` (`GEMINI_DIR = '.gemini'`, joined onto
 *     `os.homedir()` with no other per-OS branching — unlike Cursor, there
 *     is no XDG special-casing to replicate here, confirmed directly from
 *     `getGlobalGeminiDir()`'s source).
 *   - Per-project temp dir: `~/.gemini/tmp/<projectIdentifier>/`
 *     (`TMP_DIR_NAME = 'tmp'`, `getProjectTempDir()` joins the global temp
 *     dir with one path segment). The identifier scheme has itself changed
 *     across versions — an older SHA-256 hex hash of the project root
 *     (`getProjectHash()`, still present in the source) versus a newer
 *     "ProjectRegistry"-assigned short slug — so this source does not try
 *     to recompute either one; see files() below for why it just walks
 *     `tmp/` and treats every entry as a candidate project directory,
 *     independent of which identifier scheme produced its name.
 *   - Chat history: `<projectTempDir>/chats/`, written by
 *     `ChatRecordingService`. As of a PR merged into `main` on 2026-04-09
 *     ("feat(core): migrate chat recording to JSONL streaming", #23749),
 *     sessions are JSON Lines: `session-<ISO-timestamp>-<sessionId8>.jsonl`,
 *     one JSON record per line — a metadata record first (sessionId,
 *     projectHash, startTime, ...), then one record per user/model turn
 *     (type, content, toolCalls, thoughts, tokens, ...). Before that PR,
 *     the same directory held whole-session files named
 *     `session-*.json` instead (one pretty-printed JSON document per
 *     session, rewritten in full on every turn) — the loader introduced by
 *     that PR explicitly still reads both extensions, meaning transcripts
 *     from before an upgrade can still be sitting there. This source reads
 *     both, and does not otherwise care which shape a given file is: like
 *     claude-code.js, it pattern-matches raw text lines and a `.json` file
 *     with embedded secrets still gets scanned line-by-line even though it
 *     isn't itself line-delimited JSON — see readLines()'s docstring.
 *   - Subagent sessions nest one level deeper:
 *     `<projectTempDir>/chats/<sanitizedParentSessionId>/<sessionId>.jsonl`
 *     (confirmed in chatRecordingService.ts). files() below bounds its
 *     descent into `chats/` rather than hard-coding "exactly one extra
 *     level," so a further nesting change wouldn't silently stop being
 *     scanned.
 *
 * Deliberately OUT OF SCOPE: `<projectTempDir>/checkpoints/` (per-tool-call
 * git-snapshot checkpoints created by the `/restore` workflow — a different
 * subsystem from chat recording, and not confirmed to hold prompt/response
 * text the way `chats/` is) and `<projectTempDir>/logs/` (this source's
 * research turned up `getProjectTempLogsDir()` but no confirmation of what,
 * if anything, currently writes there — plausibly OpenTelemetry/debug
 * output, not conversation content). Neither is included here; scanning
 * conversation transcripts is the well-corroborated claim this source
 * makes, and CONTRIBUTING.md's rule against guessing applies per-location,
 * not just per-tool.
 *
 * Sources consulted: google-gemini/gemini-cli source on GitHub
 * (storage.ts, paths.ts, chatRecordingService.ts, docs/reference/
 * configuration.md, all fetched from the `main` branch); geminicli.com's
 * published session-management docs; GitHub discussions #3965, #4974 and
 * issue #5101 (real users describing their own `~/.gemini/tmp` contents);
 * issue #15292 (the JSONL-migration proposal, later implemented via #23749,
 * which is what pins down the pre/post-migration file shapes above).
 */
function geminiHomeDir() {
  const base = process.env.GEMINI_CLI_HOME || os.homedir();
  return path.join(base, ".gemini");
}

const ROOT = geminiHomeDir();
const TMP_DIR = path.join(ROOT, "tmp");
const CHAT_FILE_EXT = /\.(jsonl|json)$/i;

// How many levels deep files() will descend into a project's chats/
// directory looking for session files. The only nesting confirmed from
// source is one extra level (subagent sessions), but this is kept bounded
// rather than hard-coded at exactly 1 so a future extra level of nesting
// gets scanned rather than silently missed — and bounded at all so a
// symlink cycle under chats/ can't turn this into an infinite walk.
const MAX_CHATS_DEPTH = 4;

// Bounds for readLines() — same shape as claude-code.js's, but the actual
// number is NOT backed by a real large Gemini CLI transcript this tool was
// tested against (unlike claude-code.js's, which cites a real 818MB file);
// no Gemini CLI install was available to produce one. Treat this as a
// generous, untested backstop against a pathological file, not evidence of
// what real transcripts look like.
const MAX_BYTES = 2 * 1024 * 1024 * 1024; // 2GB
const READ_TIMEOUT_MS = 60_000;

function id() { return "gemini-cli"; }
function label() { return "Gemini CLI"; }

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
 * Walk a `chats/` directory (or one of its subdirectories) for candidate
 * session files, up to MAX_CHATS_DEPTH levels deep. A missing directory
 * (e.g. a project that has never recorded a chat) yields nothing and is NOT
 * reported broken — same convention cursor.js's statIfPresent() uses for
 * "this path just doesn't exist yet." A directory that exists but can't be
 * read, or a symlink that can't be resolved, IS reported broken — nothing
 * this function declines to descend into or open is done so silently.
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
    // one case worth reporting (a stray FIFO/socket etc. sitting in here
    // was never a scannable transcript in the first place).
    if (e.isSymbolicLink()) yield { file: full, broken: true };
  }
}

/**
 * Yield { file, mtimeMs, sizeBytes, broken } for every Gemini CLI chat
 * transcript found under `~/.gemini/tmp/<projectIdentifier>/chats/`.
 *
 * Every entry under tmp/ is treated as a candidate project directory rather
 * than trying to recompute the identifier scheme (SHA-256 hash vs. registry
 * slug — see the module docstring) — this mirrors cursor.js's choice to
 * walk `workspaceStorage/<hash>` generically rather than recompute VS
 * Code's hash function.
 */
function* files() {
  let idDirs;
  try { idDirs = fs.readdirSync(TMP_DIR, { withFileTypes: true }); }
  catch { return; }

  for (const idEnt of idDirs) {
    const idDir = path.join(TMP_DIR, idEnt.name);
    if (!isDirFollowingSymlink(idDir, idEnt)) {
      if (idEnt.isSymbolicLink()) yield { file: idDir, broken: true };
      continue;
    }
    yield* walkChatFiles(path.join(idDir, "chats"), 0);
  }
}

/**
 * Read one transcript as an array of raw text lines. Identical approach to
 * claude-code.js's readLines() — streamed via readline/promises (not
 * readFileSync+split, for the same V8 string-length-ceiling reason), a
 * generous size cap, and a hard read timeout since Node's stream/readline
 * stack has no built-in one. See claude-code.js's own docstring for the
 * full reasoning; not re-derived here since nothing about it is
 * Gemini-CLI-specific.
 *
 * Works the same whether `file` is JSONL (one record per line, the current
 * format) or a legacy whole-session `.json` document (pretty-printed across
 * many lines) — per the adapter contract, lines don't need to be valid JSON
 * individually, they just need pattern-matching against; a secret inside a
 * multi-line JSON document still lands on whatever physical line it's on.
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
