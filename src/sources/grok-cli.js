"use strict";

const fs = require("fs");
const { createInterface } = require("readline/promises");
const path = require("path");
const os = require("os");

/**
 * Grok Build (xAI's official coding-agent CLI/TUI, binary name `grok` — the
 * product commonly referred to as "Grok CLI") session transcripts.
 *
 * VERIFICATION STATUS (read this before trusting anything below): this
 * source is corroborated by the actual current Rust source code AND
 * first-party documentation of the official xai-org/grok-build repository on
 * GitHub — fetched and read directly from the `main` branch (path-resolution
 * code with its own unit tests, the JSONL storage adapter, and the shipped
 * user-guide doc page), not inferred from a description of it. It has NOT
 * been checked against a real Grok Build install — it is not installed on
 * the machine this adapter was built on (checked: no `grok` on PATH, no
 * `~/.grok` directory). If you have Grok Build installed, the most useful
 * thing you can do is run `residoo scan` and confirm
 * `sourcesScanned`/`filesScanned` look right for what you know is actually
 * under `~/.grok/sessions`, then report back either way.
 *
 * Note on naming: this project's own repo (public, confirmed via `gh api
 * repos/xai-org/grok-build`) and README call the product "Grok Build"; the
 * command is `grok`. Various unofficial third-party npm packages are also
 * named "grok-cli" (e.g. `superagent-ai/grok-cli`) — those are NOT xAI's own
 * tool and are out of scope here; this source is specifically xAI's
 * first-party agent, whatever it's branded as this month.
 *
 * HOME DIRECTORY. `crates/codegen/xai-dirs/src/lib.rs` (`grok_home()`,
 * `home_dir()`, with its own unit tests) resolves, in this exact order:
 *   1. `$GROK_HOME`, used verbatim (not canonicalized), when set and
 *      non-empty.
 *   2. Otherwise `<home>/.grok`, where `<home>` comes from
 *      `std::env::home_dir()` — `$HOME` on Unix (with a passwd-database
 *      fallback), `%USERPROFILE%` on Windows — canonicalized via `dunce`
 *      (resolves symlinks without producing Windows `\\?\` verbatim paths).
 * No OS-specific base directory (no XDG, no `Library/Application Support`):
 * always `<home>/.grok`, on every platform, confirmed directly from source —
 * unlike several other sources in this project (Cursor, Gemini CLI), there
 * is no per-OS branch to replicate here. This source does not replicate the
 * `dunce` canonicalization step (Node has no direct equivalent, and the one
 * documented case it matters for — macOS's `/var` vs `/private/var` — does
 * not apply to a user's own home directory in practice); a noted, minor,
 * intentional gap.
 *
 * STORAGE LAYOUT. `crates/codegen/xai-grok-config/src/paths.rs`
 * (`encode_cwd_dirname`, `sessions_cwd_dir_in`, both with extensive unit
 * tests covering short/long/non-ASCII working directories) and
 * `crates/codegen/xai-grok-shell/src/session/storage/jsonl/mod.rs` (doc
 * comment: "JSONL storage under `{root}/sessions/{url_encoded_cwd}/
 * {session_id}/`") confirm the on-disk shape:
 *
 *   ~/.grok/sessions/<encoded-cwd>/<session-id>/
 *
 * `<encoded-cwd>` is the session's working directory, percent-encoded
 * (`urlencoding::encode`) when that fits in 255 bytes, else a
 * `{slug}-{blake3_hex16}` fallback with the real path recorded in a `.cwd`
 * file inside — see `encode_cwd_dirname()`'s doc comment for the exact
 * rule. This source does not attempt to reproduce that encoding or recover
 * the original working directory: it walks whatever directories exist under
 * `sessions/` generically (same judgment call gemini-cli.js makes for
 * `~/.gemini/tmp/<projectIdentifier>/` rather than recomputing that tool's
 * own hash/slug scheme), because doing so is unnecessary — files() only
 * needs to find candidate files, not decode what project they belong to.
 *
 * Per session, xAI's own shipped user-guide doc
 * (`crates/codegen/xai-grok-pager/docs/user-guide/17-sessions.md`, mirrored
 * near-verbatim in `crates/codegen/xai-grok-shell/README.md`) documents the
 * files inside each session directory:
 *
 *   summary.json            # metadata: summary/title, timestamps, model ID, message counts
 *   updates.jsonl           # ACP session update stream (conversation + tool calls) — SOURCE OF TRUTH
 *   chat_history.jsonl      # raw chat messages sent to the model
 *   plan.json               # TODO/task list state
 *   rewind_points.jsonl     # rewind points for /rewind undo
 *   signals.json            # session signals (token usage, tool/turn counters)
 *   feedback.jsonl          # user feedback and ratings
 *   compaction_checkpoints/ # saved state from compaction (manual or auto)
 *   subagents/               # per-subagent metadata (meta.json) only — the
 *                             # child sessions themselves are ordinary
 *                             # top-level session dirs elsewhere in the tree
 *                             # (confirmed in jsonl/mod.rs:
 *                             # `with_explicit_session_dir` doc comment,
 *                             # "Subagent child sessions use this (top-level
 *                             # dirs; only their metadata nests under the
 *                             # parent's session dir)").
 *
 * The doc page states outright which files matter for content: "JSONL is
 * the source of truth for session content" (`updates.jsonl` and
 * `chat_history.jsonl` specifically — both are grep-confirmed by name
 * dozens of times across the actual production code, its own tests, and its
 * prompt templates, not just the doc prose). A separate local SQLite FTS5
 * index (`grok sessions search`) exists purely as a derived keyword index
 * over titles/prompts, explicitly secondary to the JSONL per the same doc —
 * not scanned here, on the same reasoning cursor.js gives for preferring a
 * primary store over a derived cache: scanning the source of truth is both
 * sufficient and simpler than also opening a SQLite index that can only
 * echo a subset of what the JSONL already holds.
 *
 * This source deliberately does NOT hardcode that filename list. It walks
 * every file under each session directory (bounded depth, so
 * `compaction_checkpoints/` and `subagents/` are covered too) and scans any
 * `.json`/`.jsonl` file found there, for the same reason cursor.js declines
 * to hardcode a key-name allowlist and warp.js declines to hardcode a table
 * list: this project is under fast, active development (its own docs were
 * last updated within the research window for this source) and a stale
 * hardcoded filename list is exactly the kind of silent, permanent gap
 * CONTRIBUTING.md rule 5 exists to prevent. A file this source doesn't
 * specifically recognize costs nothing extra to scan.
 */
function grokHome() {
  const grokHomeEnv = process.env.GROK_HOME;
  if (grokHomeEnv && grokHomeEnv !== "") return grokHomeEnv;
  return path.join(os.homedir(), ".grok");
}

const ROOT = grokHome();
const SESSIONS_DIR = path.join(ROOT, "sessions");
const SESSION_FILE_EXT = /\.(jsonl|json)$/i;

// How many levels deep files() will descend from a session-id directory
// looking for content files. The only nesting actually documented is one
// extra level (compaction_checkpoints/*, subagents/*), but this is kept
// bounded rather than hard-coded at exactly 1 so a future extra level of
// nesting gets scanned rather than silently missed — and bounded at all so
// a symlink cycle can't turn this into an infinite walk. Same convention
// and same reasoning as gemini-cli.js's MAX_CHATS_DEPTH.
const MAX_SESSION_DEPTH = 4;

// Bounds for readLines() — same shape as claude-code.js's, but the actual
// number is NOT backed by a real large Grok Build transcript this tool was
// tested against (unlike claude-code.js's, which cites a real 818MB file);
// no install was available to produce one. `grok du`'s own sample output
// (quoted in the sessions doc) shows a `sessions` directory reaching low
// gigabytes in ordinary heavy use, well under this cap.
const MAX_BYTES = 2 * 1024 * 1024 * 1024; // 2GB
const READ_TIMEOUT_MS = 60_000;

function id() { return "grok-cli"; }
function label() { return "Grok Build"; }

function available() {
  try { return fs.statSync(SESSIONS_DIR).isDirectory(); } catch { return false; }
}

/**
 * Same defensive symlink-following pattern as claude-code.js — see that
 * file's docstring for the full reasoning. Duplicated rather than imported:
 * each source here is meant to be a small, self-contained file a reviewer
 * can audit on its own (CONTRIBUTING.md).
 */
function isKindFollowingSymlink(fullPath, dirent, checkFn) {
  if (checkFn(dirent)) return true;
  if (!dirent.isSymbolicLink()) return false;
  try { return checkFn(fs.statSync(fullPath)); } catch { return false; }
}
const isDirFollowingSymlink = (p, d) => isKindFollowingSymlink(p, d, (x) => x.isDirectory());
const isFileFollowingSymlink = (p, d) => isKindFollowingSymlink(p, d, (x) => x.isFile());

/**
 * Walk one session-id directory (or one of its subdirectories) for
 * candidate content files, up to MAX_SESSION_DEPTH levels deep. See the
 * module docstring for why every `.json`/`.jsonl` file is read rather than
 * an exact filename allowlist.
 */
function* walkSessionFiles(dir, depth) {
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); }
  catch { return; }

  for (const e of entries) {
    const full = path.join(dir, e.name);

    if (isDirFollowingSymlink(full, e)) {
      if (depth < MAX_SESSION_DEPTH) yield* walkSessionFiles(full, depth + 1);
      continue;
    }
    if (isFileFollowingSymlink(full, e)) {
      if (!SESSION_FILE_EXT.test(e.name)) continue;
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
 * Yield { file, mtimeMs, sizeBytes, broken } for every Grok Build session
 * content file found under `~/.grok/sessions/<encoded-cwd>/<session-id>/`.
 *
 * Every entry directly under `sessions/` is treated as a candidate
 * encoded-cwd directory rather than trying to decode or validate the
 * encoding scheme (percent-encoding vs. the long-path slug+hash fallback —
 * see the module docstring) — this mirrors gemini-cli.js's and cursor.js's
 * own choice to walk a similarly-shaped directory generically rather than
 * recompute the source tool's own hashing/encoding.
 */
function* files() {
  let cwdDirs;
  try { cwdDirs = fs.readdirSync(SESSIONS_DIR, { withFileTypes: true }); }
  catch { return; }

  for (const cwdEnt of cwdDirs) {
    const cwdDir = path.join(SESSIONS_DIR, cwdEnt.name);
    if (!isDirFollowingSymlink(cwdDir, cwdEnt)) {
      if (cwdEnt.isSymbolicLink()) yield { file: cwdDir, broken: true };
      continue;
    }
    yield* walkSessionFiles(cwdDir, 0);
  }
}

/**
 * Read one transcript file as an array of raw text lines. Identical approach
 * to claude-code.js's readLines() — streamed via readline/promises (not
 * readFileSync+split, for the same V8 string-length-ceiling reason), a
 * generous size cap, and a hard read timeout since Node's stream/readline
 * stack has no built-in one. See claude-code.js's own docstring for the
 * full reasoning; not re-derived here since nothing about it is
 * Grok-Build-specific.
 *
 * Works the same whether `file` is JSONL (updates.jsonl, chat_history.jsonl,
 * rewind_points.jsonl, feedback.jsonl — one record per line) or a plain
 * multi-line JSON document (summary.json, plan.json, signals.json,
 * subagents/*.json) — per the adapter contract, lines don't need to be
 * valid JSON individually, they just need pattern-matching against.
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
