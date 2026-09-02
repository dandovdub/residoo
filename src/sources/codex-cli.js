"use strict";

const fs = require("fs");
const path = require("path");
const os = require("os");
const { createInterface } = require("readline/promises");

/**
 * OpenAI's Codex CLI (the `codex` coding-agent binary — see
 * https://github.com/openai/codex — NOT the retired "Codex" language model
 * from 2021). Also referred to below as "Codex CLI" throughout to keep that
 * distinction unambiguous.
 *
 * VERIFICATION STATUS: this source was NOT checked against a real Codex CLI
 * install — `codex` is not installed on the machine this adapter was built
 * on (checked: no `codex` on PATH, no `~/.codex`, no Homebrew/npm-global
 * install, mdfind turned up nothing for a local CLI install — the only
 * "codex" hits on this machine were the ChatGPT desktop app's own unrelated
 * `com.openai.chat` local cache for its cloud-hosted "Codex" task feature,
 * which is a different product with no local session transcripts of its
 * own to scan; it runs in a remote container, not on this machine). Per
 * CONTRIBUTING.md this ships anyway because it clears that bar a different
 * way: multiple independent, credible, and largely recent sources agree
 * with each other on the exact path and schema below, including official
 * OpenAI documentation, the tool's own GitHub issue tracker describing this
 * exact file layout as a live bug surface, and more than one third-party
 * tool that reads these same files for a living. Specifically:
 *
 *  - Official docs (developers.openai.com/codex/environment-variables,
 *    redirects to learn.chatgpt.com/docs/config-file/environment-variables):
 *    CODEX_HOME "sets the root directory for Codex state, including config,
 *    auth, logs, sessions, skills, and standalone package metadata,"
 *    defaulting to `~/.codex`.
 *  - openai/codex GitHub issue #21660 ("rollout: session JSONL files are
 *    created world-readable (mode 0644) on Unix") and issue #20864
 *    ("Codex Desktop App becomes laggy because it scans all
 *    `~/.codex/sessions` rollout files...") — both filed against the real
 *    tool, both independently naming this exact directory.
 *  - openai/codex GitHub Discussion #24042, a real, working, open-source
 *    native macOS viewer built specifically to read `~/.codex/sessions/
 *    *.jsonl`, and community tools codex-trace (PixelPaw-Labs) and
 *    codex-history-list (shinshin86) doing the same — the kind of "a
 *    maintained tool reads the same files" corroboration CONTRIBUTING.md
 *    calls out explicitly.
 *  - openai/codex GitHub issue #17000 ("Auto-archive and zstd-compress
 *    inactive local rollout files...") independently confirms the
 *    `rollout-*.jsonl` naming and the date-partitioned directory shape by
 *    proposing changes to it. NOTE: this issue also shows the zstd
 *    compression feature it proposes is NOT yet shipped as of this
 *    research — a compression detail that appeared in one AI-generated
 *    summary was traced back to this still-open proposal, not a shipped
 *    behavior, so no zstd decompression is assumed live here. It's still
 *    handled defensively below (see ZSTD_RE) in case that changes.
 *  - Independent write-ups (a dev.to reverse-engineering post showing real
 *    rollout JSONL line shapes, prismmd.app and betelgeuse.work blog posts,
 *    and a Codex-Knowledge-Base article on session archiving) all agree on
 *    the same `~/.codex/sessions/YYYY/MM/DD/rollout-<ts>-<uuid>.jsonl`
 *    shape and on a parallel `~/.codex/archived_sessions/` tree used when a
 *    session is archived (the rollout JSONL is moved, not transformed).
 *  - Multiple of the above also describe a flat `~/.codex/history.jsonl` —
 *    one line per user turn, holding just the raw text the user typed for
 *    that turn (not the full conversation) — which is real, secret-scanning
 *    -relevant content (a pasted key or token lands here) distinct from the
 *    per-session rollout files, so it's read too.
 *
 * Deliberately NOT read: `~/.codex/session_index.jsonl`. Independent
 * sources agree it is a lightweight metadata cache only (id, timestamp,
 * cwd, model, status) that explicitly does NOT duplicate rollout content —
 * scanning it would add file-walk cost with no realistic chance of a
 * secret-bearing line. Also not read: anything under `~/.codex` that isn't
 * one of the three content locations above — chiefly `config.toml`,
 * `auth.json`, and `log/`, which are Codex's own config/credential/log
 * files, not session transcript content, mirroring how claude-code.js and
 * cursor.js each stay scoped to actual conversation data rather than a
 * tool's entire state directory.
 *
 * If you have Codex CLI installed, the most useful thing you can do is run
 * `residoo scan` and confirm `sourcesScanned`/`filesScanned` look right for
 * what you know is actually on disk under `~/.codex`, then report back
 * either way — see CONTRIBUTING.md.
 */
function codexHome() {
  // Honoring CODEX_HOME (rather than hardcoding ~/.codex) mirrors how
  // cursor.js honors XDG_CONFIG_HOME — the tool's own documented override,
  // not a guess, and the official docs above are explicit that sessions,
  // not just config, live under this root.
  if (process.env.CODEX_HOME) return process.env.CODEX_HOME;
  return path.join(os.homedir(), ".codex");
}

const ROOT = codexHome();
const SESSIONS_DIR = path.join(ROOT, "sessions");
const ARCHIVED_SESSIONS_DIR = path.join(ROOT, "archived_sessions");
const HISTORY_FILE = path.join(ROOT, "history.jsonl");

// A rollout file this large has not been reported anywhere in this source's
// research; kept identical to claude-code.js's bound (same underlying
// concern — V8's whole-string ceiling doesn't apply here since this source
// also streams line-by-line, but a shared, already-reasoned-about number
// beats inventing a new one with no evidence behind it).
const MAX_BYTES = 2 * 1024 * 1024 * 1024; // 2GB
const READ_TIMEOUT_MS = 60_000;

// Symlink-loop safety for the recursive sessions/archived_sessions walk.
// claude-code.js never needed a depth bound — its walk is exactly two
// levels (project dir, then files in it). Walking an arbitrary
// YYYY/MM/DD(/...)? tree that may itself contain a symlink is a genuinely
// new risk this source introduces, so it gets a guard claude-code.js didn't
// need. 12 gives generous headroom over the documented 3-level date
// partitioning while still bounding a pathological symlink cycle.
const MAX_WALK_DEPTH = 12;

// See the ZSTD note in the module docstring: not confirmed shipped, but
// handled honestly rather than assumed absent forever. A zero-dependency
// project has no built-in Zstandard decoder available across the supported
// Node range (>=18), so a matching file is surfaced as a normal, resolvable
// file entry (not "broken" — it's not unresolvable, just undecodable by
// this tool) and readLines() reports it "failed" rather than silently
// omitting it from the walk.
const ZSTD_RE = /\.zst$/i;
const JSONL_RE = /\.jsonl$/i;

function id() { return "codex-cli"; }
function label() { return "Codex CLI"; }

function available() {
  try { return fs.statSync(ROOT).isDirectory(); } catch { return false; }
}

/**
 * Same lstat-vs-stat symlink-following pattern as claude-code.js's
 * isKindFollowingSymlink — duplicated rather than imported, matching this
 * project's convention (cursor.js's docstring on the same duplication:
 * "each source in this project is meant to be a small, self-contained file
 * a reviewer can audit on its own").
 */
function isKindFollowingSymlink(fullPath, dirent, checkFn) {
  if (checkFn(dirent)) return true;
  if (!dirent.isSymbolicLink()) return false;
  try { return checkFn(fs.statSync(fullPath)); } catch { return false; }
}
const isDirFollowingSymlink = (p, d) => isKindFollowingSymlink(p, d, (x) => x.isDirectory());
const isFileFollowingSymlink = (p, d) => isKindFollowingSymlink(p, d, (x) => x.isFile());

/**
 * Recursively walk one directory (sessions/ or archived_sessions/) yielding
 * { file, mtimeMs, sizeBytes, broken } for every `*.jsonl` (scanned) and
 * `*.zst` (surfaced, see ZSTD_RE above) file found at any depth, following
 * symlinks the same way claude-code.js's files() does for project dirs and
 * jsonl files, and reporting a dangling symlink as broken rather than
 * skipping it silently. Any other file extension under this tree is out of
 * scope, same as claude-code.js ignoring non-`.jsonl` entries.
 */
function* walkSessionDir(dir, depth) {
  if (depth > MAX_WALK_DEPTH) return;
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); }
  catch { return; } // dir vanished or unreadable mid-walk — not reportable, nothing was ever yielded for it

  for (const e of entries) {
    const full = path.join(dir, e.name);

    if (!e.isFile() && !e.isDirectory()) {
      // Symlink (or other special entry) — resolve to find out which kind.
      if (isDirFollowingSymlink(full, e)) { yield* walkSessionDir(full, depth + 1); continue; }
      if (isFileFollowingSymlink(full, e)) {
        if (!JSONL_RE.test(e.name) && !ZSTD_RE.test(e.name)) continue;
        let stat;
        try { stat = fs.statSync(full); } catch { yield { file: full, broken: true }; continue; }
        yield { file: full, mtimeMs: stat.mtimeMs, sizeBytes: stat.size, broken: false };
        continue;
      }
      // Didn't resolve to either — a dangling symlink is the plausible
      // real-world case (see claude-code.js's identical reasoning).
      if (e.isSymbolicLink()) yield { file: full, broken: true };
      continue;
    }

    if (e.isDirectory()) { yield* walkSessionDir(full, depth + 1); continue; }

    if (!JSONL_RE.test(e.name) && !ZSTD_RE.test(e.name)) continue;
    let stat;
    try { stat = fs.statSync(full); } catch { yield { file: full, broken: true }; continue; }
    yield { file: full, mtimeMs: stat.mtimeMs, sizeBytes: stat.size, broken: false };
  }
}

/**
 * Yield { file, mtimeMs, sizeBytes, broken } for every rollout file under
 * sessions/ and archived_sessions/, plus the single flat history.jsonl —
 * see the module docstring for why each of these three (and only these
 * three) locations is read.
 */
function* files() {
  yield* walkSessionDir(SESSIONS_DIR, 0);
  yield* walkSessionDir(ARCHIVED_SESSIONS_DIR, 0);

  // history.jsonl is a single fixed-name file, not a directory to walk —
  // same lstat-first, follow-if-symlink handling as cursor.js's
  // statIfPresent, and a path that simply doesn't exist (most installs,
  // depending on version/config) is normal, not broken.
  let lst;
  try { lst = fs.lstatSync(HISTORY_FILE); }
  catch { return; }

  if (lst.isSymbolicLink()) {
    try {
      const st = fs.statSync(HISTORY_FILE);
      if (!st.isFile()) { yield { file: HISTORY_FILE, broken: true }; return; }
      yield { file: HISTORY_FILE, mtimeMs: st.mtimeMs, sizeBytes: st.size, broken: false };
    } catch {
      yield { file: HISTORY_FILE, broken: true };
    }
    return;
  }
  if (!lst.isFile()) return;
  yield { file: HISTORY_FILE, mtimeMs: lst.mtimeMs, sizeBytes: lst.size, broken: false };
}

/**
 * Read one file as an array of raw text lines. Identical streaming strategy
 * to claude-code.js's readLines (see that file's docstring for the full
 * reasoning on why streaming + a read timeout + honest partial-read
 * handling all matter) — duplicated rather than shared, per this project's
 * one-file-per-source convention. The one addition is the zstd short-circuit
 * at the top; see ZSTD_RE above.
 */
async function readLines(file) {
  if (ZSTD_RE.test(file)) return { lines: [], status: "failed", bytesRead: 0 };

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
