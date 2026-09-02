"use strict";

const fs = require("fs");
const path = require("path");
const os = require("os");

/**
 * Crush (charmbracelet/crush) session/chat history.
 *
 * VERIFICATION STATUS (read this before trusting anything below): this
 * source is corroborated by the actual current Go source code of the
 * official charmbracelet/crush repository on GitHub — fetched and read
 * directly from the `main` branch (goose migration SQL, the config/data-dir
 * resolution code, and the project-registry code), not inferred from a
 * description of it. It has NOT been checked against a real Crush install —
 * Crush is not installed on the machine this adapter was built on (checked:
 * no `crush` on PATH, no `~/.local/share/crush` directory, not in `brew
 * list`, no `crush`-named entry anywhere findable via `mdfind`). If you have
 * Crush installed, the most useful thing you can do is run `residoo scan`
 * and confirm `sourcesScanned`/`filesScanned` look right for what you know
 * is actually on disk (`crush dirs` prints Crush's own view of its config
 * and data locations), then report back either way.
 *
 * STORAGE MODEL — genuinely different from most sources in this project, so
 * spelled out in full:
 *
 * Crush keeps its SQLite database PER PROJECT, the same way git keeps a
 * `.git` directory per repo, not in one global well-known folder. Confirmed
 * directly in source (`internal/config/config.go`, the `Options.DataDirectory`
 * field doc comment): "DataDirectory is where Crush keeps per-project state
 * such as the SQLite database and workspace overrides. Relative paths are
 * resolved against the working directory; absolute paths are used as-is,"
 * default `.crush`. `internal/db/connect.go` confirms the filename:
 * `dbPath := filepath.Join(dataDir, "crush.db")`.
 *
 * So there is no single directory to list. What Crush DOES keep centrally is
 * a small JSON registry of every project it has ever been run against —
 * confirmed directly in `internal/projects/projects.go`:
 *   - `projectsFilePath()` returns
 *     `filepath.Join(filepath.Dir(config.GlobalConfigData()), "projects.json")`.
 *   - Schema: `{"projects":[{"path":"...","data_dir":"...","last_accessed":"..."}]}`
 *     (the `Project`/`ProjectList` structs, same file).
 *   - `internal/cmd/root.go` calls `projects.Register(cwd, cfg.Options.DataDirectory)`
 *     unconditionally on every normal `crush` invocation, immediately before
 *     `db.Connect(ctx, cfg.Options.DataDirectory)` — so any project that has
 *     ever actually written a `crush.db` is, in the overwhelmingly common
 *     case, also listed here (failure to register is logged and non-fatal,
 *     so a very unlucky write failure could in principle desync the two —
 *     acknowledged, not fixable from outside the tool).
 *   - Crush's own `stats --all` command reads this exact file to aggregate
 *     across projects (`internal/cmd/stats.go`,
 *     `gatherStatsFromProjects()` → `projects.Load()` →
 *     `filepath.Join(p.DataDir, "crush.db")`) — this source's files() does
 *     the same walk. Crush also ships a `stats --crawl-dir` mode that does a
 *     full recursive filesystem walk for orphaned `.crush/crush.db`
 *     directories instead; this source deliberately does NOT replicate that
 *     — an unbounded home-directory crawl is a different cost/risk profile
 *     than every other source in this project, and Crush's own default
 *     behavior (registry-based, not crawl-based) is the one this mirrors.
 *     A `crush.db` from a project Crush was never actually run `cd`-first
 *     into (registration skipped some other way) would be missed; that is a
 *     real, named gap, not a silent one.
 *
 * `GlobalConfigData()`'s directory (`internal/config/load.go`) — resolved in
 * this exact order, replicated in `crushGlobalDataDir()` below:
 *   1. `$CRUSH_GLOBAL_DATA` if set, used as-is (no `crush` suffix appended).
 *   2. `$XDG_DATA_HOME/crush` if `XDG_DATA_HOME` is set.
 *   3. Windows: `%LOCALAPPDATA%\crush` (`LOCALAPPDATA` env, falling back to
 *      `%USERPROFILE%\AppData\Local`).
 *   4. Otherwise (macOS AND Linux — confirmed no Darwin special-case in
 *      source, unlike Cursor): `$HOME/.local/share/crush`.
 *
 * DB schema, confirmed directly from the goose migration files under
 * `internal/db/migrations/`: `20250424200609_initial.sql` creates `sessions`
 * (id, title, message_count, prompt/completion tokens, cost, timestamps) and
 * `messages` (id, session_id, role, `parts` TEXT — a JSON array of message
 * content parts — model, timestamps) and `files` (id, session_id, path,
 * `content` TEXT, version, timestamps — full-content snapshots of files the
 * agent read or wrote during a session, kept for diffing/undo). Later
 * migrations only ADD columns to `messages`/`sessions`
 * (`20250627000000_add_provider_to_messages.sql`,
 * `20250810000000_add_is_summary_message.sql`,
 * `20250812000000_add_todos_to_sessions.sql`) or add an unrelated
 * path-only `read_files` table (`20260127000000_add_read_files_table.sql` —
 * session_id/path/read_at, no content, not scanned). `internal/message/
 * content.go` confirms `parts` holds real plaintext — `TextContent{Text
 * string}`, `ReasoningContent{Thinking string}` — not an opaque or encrypted
 * blob. `internal/db/connect.go`'s pragmas (`journal_mode=WAL`,
 * `secure_delete=ON`, ordinary `busy_timeout`) show nothing about
 * encryption; nothing in source opens this database with a key.
 *
 * This source reads BOTH `messages` and `files` — both hold real content a
 * secret could be sitting in (a pasted token in a chat turn; a `.env` file
 * the agent happened to read, whose full text `files` snapshots verbatim).
 * `sessions` (title/todos only) and `read_files` (paths/timestamps only) are
 * left out as low-value scope creep, same judgment call gemini-cli.js
 * documents for its own out-of-scope directories. Each table is read via
 * `SELECT * FROM <table>` with no column allowlist — deliberately, same
 * reasoning as cursor.js: column additions (already observed twice above)
 * should not require an adapter update to keep being scanned.
 *
 * `internal/home/home.go` confirms `home.Dir()` is exactly
 * `os.UserHomeDir()` — no XDG override on the home directory itself, matching
 * Node's `os.homedir()`.
 *
 * One secondary source was also checked — Vercel's AI Gateway docs page on
 * Crush — and is worth naming the gap in: it describes the database as
 * simply living in `~/.local/share/crush/`. Direct source inspection shows
 * that is imprecise: that directory holds `crush.json` (config) and
 * `projects.json` (the registry this source actually reads); each project's
 * real `crush.db` lives at the `data_dir` THAT FILE points to, by default
 * `<project>/.crush/crush.db`. This is exactly the kind of guessed-path
 * error CONTRIBUTING.md warns about, caught only by going to source instead
 * of trusting the paraphrase.
 */
function crushGlobalDataDir() {
  const crushGlobalData = process.env.CRUSH_GLOBAL_DATA;
  if (crushGlobalData) return crushGlobalData; // used as-is, per GlobalConfigData()
  const xdgDataHome = process.env.XDG_DATA_HOME;
  if (xdgDataHome) return path.join(xdgDataHome, "crush");
  if (process.platform === "win32") {
    const localAppData = process.env.LOCALAPPDATA || path.join(os.homedir(), "AppData", "Local");
    return path.join(localAppData, "crush");
  }
  return path.join(os.homedir(), ".local", "share", "crush");
}

const GLOBAL_DATA_DIR = crushGlobalDataDir();
const PROJECTS_REGISTRY = path.join(GLOBAL_DATA_DIR, "projects.json");

/**
 * Same lazy-require, feature-detected node:sqlite pattern as cursor.js — see
 * that file's docstring for the full reasoning (an eager top-level require
 * would print Node's ExperimentalWarning on every `residoo scan` for every
 * user, even the majority who have never touched Crush). Duplicated rather
 * than shared: each source here is meant to be a small, self-contained file
 * a reviewer can audit on its own (CONTRIBUTING.md).
 */
const NODE_SQLITE_REQUIREMENT = "needs Node.js 22.5+ (node:sqlite not present in this runtime)";
let sqliteRequireAttempted = false;
let DatabaseSync = null;

function getDatabaseSync() {
  if (!sqliteRequireAttempted) {
    sqliteRequireAttempted = true;
    try { ({ DatabaseSync } = require("node:sqlite")); }
    catch { DatabaseSync = null; }
  }
  return DatabaseSync;
}

function id() { return "crush"; }
function label() { return "Crush"; }

function globalDataDirExists() {
  try { return fs.statSync(GLOBAL_DATA_DIR).isDirectory(); } catch { return false; }
}

function available() {
  // Cheap fs check first, same short-circuit reasoning as cursor.js's
  // available(): the common case is Crush simply isn't installed, and that
  // must not cost requiring node:sqlite.
  return globalDataDirExists() && Boolean(getDatabaseSync());
}

/**
 * Same additive, optional export as cursor.js's unavailableReason() — see
 * that file's docstring. Distinguishes "Crush isn't here" (say nothing) from
 * "Crush is here but this Node runtime can't read its database" (say so).
 */
function unavailableReason() {
  if (!globalDataDirExists()) return null;
  if (getDatabaseSync()) return null;
  return `Crush detected but not scanned — ${NODE_SQLITE_REQUIREMENT}`;
}

/**
 * Resolve one candidate `crush.db` path into zero or one files() entries.
 * Identical in shape and reasoning to cursor.js's statIfPresent(): these
 * paths are constructed from the projects.json registry, not discovered by
 * listing a directory, so lstat is used directly rather than readdirSync's
 * Dirent. A path that simply does not exist (a project registered, then
 * later deleted, or a data_dir that was never actually written to) yields
 * nothing and is NOT broken; a dangling symlink IS.
 */
function* statIfPresent(dbPath) {
  let lst;
  try { lst = fs.lstatSync(dbPath); }
  catch { return; }

  if (lst.isSymbolicLink()) {
    try {
      const st = fs.statSync(dbPath); // follow the link
      if (!st.isFile()) { yield { file: dbPath, broken: true }; return; }
      yield { file: dbPath, mtimeMs: st.mtimeMs, sizeBytes: st.size, broken: false };
    } catch {
      yield { file: dbPath, broken: true }; // dangling symlink
    }
    return;
  }

  if (!lst.isFile()) return; // something unexpected sits at this path — out of scope, not broken
  yield { file: dbPath, mtimeMs: lst.mtimeMs, sizeBytes: lst.size, broken: false };
}

/**
 * Yield { file, mtimeMs, sizeBytes, broken } for every project's crush.db
 * listed in the projects.json registry (see module docstring for exactly
 * what that registry is and isn't guaranteed to contain).
 *
 * A missing registry (Crush never run, or a version old enough not to write
 * one) yields nothing — the ordinary "nothing to scan yet" case, not broken.
 * A registry that exists but fails to parse as JSON IS reported broken: were
 * this silently skipped, a corrupt registry would make a real, populated
 * install scan as cleanly empty, exactly the false "all clear" CONTRIBUTING.md
 * rule 5 exists to prevent.
 */
function* files() {
  let raw;
  try { raw = fs.readFileSync(PROJECTS_REGISTRY, "utf-8"); }
  catch { return; }

  let parsed;
  try { parsed = JSON.parse(raw); }
  catch { yield { file: PROJECTS_REGISTRY, broken: true }; return; }

  const projects = Array.isArray(parsed && parsed.projects) ? parsed.projects : [];
  const seen = new Set();

  for (const p of projects) {
    if (!p || typeof p.data_dir !== "string" || p.data_dir === "") continue;
    // Registered data_dir is documented to always be stored absolute
    // (config.go: "After defaulting the stored value is always absolute").
    // Resolved against the project's own path as a defensive fallback only,
    // in case an older/foreign registry entry ever violates that invariant.
    const dataDir = path.isAbsolute(p.data_dir)
      ? p.data_dir
      : path.resolve(typeof p.path === "string" ? p.path : GLOBAL_DATA_DIR, p.data_dir);
    const dbPath = path.join(dataDir, "crush.db");
    if (seen.has(dbPath)) continue;
    seen.add(dbPath);
    yield* statIfPresent(dbPath);
  }
}

// A crush.db this large has not been observed anywhere in this source's
// research — no real install was available to produce or measure one. Same
// honest caveat as gemini-cli.js's MAX_BYTES: a generous, untested backstop
// against a pathological file, not evidence of what real databases look like.
const MAX_DB_BYTES = 512 * 1024 * 1024;
const READ_TIMEOUT_MS = 60_000;
const BUSY_TIMEOUT_MS = 5_000;
const YIELD_EVERY_N_ROWS = 500;

// See module docstring for why these two tables and not sessions/read_files.
const TABLES = ["messages", "files"];

/**
 * Turn one row (a plain object keyed by column name, as node:sqlite's
 * StatementSync#iterate() returns it) into one scanned text line. No column
 * allowlist — see module docstring. Two JS value shapes need converting
 * before JSON.stringify can touch them without throwing or losing data:
 * a BLOB-affinity column can come back as a Uint8Array (none are declared in
 * this schema today, handled anyway for the same forward-compatibility
 * reason cursor.js's valueToText() exists); and node:sqlite returns an
 * INTEGER that doesn't fit a safe JS number as a BigInt, which
 * JSON.stringify throws a TypeError on unless converted first — verified
 * against node:sqlite's own documented behavior, not observed against a
 * real oversized column in this schema (every INTEGER column here is a
 * timestamp or a small count, in practice always safe-integer-range).
 */
function rowToLine(row) {
  const clean = {};
  for (const [k, v] of Object.entries(row)) {
    if (v instanceof Uint8Array) clean[k] = Buffer.from(v).toString("utf-8");
    else if (typeof v === "bigint") clean[k] = v.toString();
    else clean[k] = v;
  }
  return JSON.stringify(clean);
}

/**
 * Read one crush.db as an array of raw text "lines" — one per row (across
 * `messages` and `files`), each turned into a single JSON-stringified line
 * by rowToLine(). Same status vocabulary and same iterate()-with-periodic-
 * yield-and-deadline-check approach as cursor.js's readLines() for the same
 * reason: node:sqlite is fully synchronous, so a wall-clock deadline can
 * only be enforced between rows, not preemptively mid-row. See cursor.js's
 * own docstring for the full reasoning; not re-derived here since nothing
 * about it is Crush-specific.
 */
async function readLines(file) {
  const DB = getDatabaseSync();
  if (!DB) return { lines: [], status: "failed", bytesRead: 0 };

  let stat;
  try { stat = fs.statSync(file); }
  catch { return { lines: [], status: "failed", bytesRead: 0 }; }
  if (stat.size > MAX_DB_BYTES) return { lines: [], status: "too-large", bytesRead: 0 };

  let db;
  try {
    db = new DB(file, { readOnly: true });
    db.exec(`PRAGMA busy_timeout = ${BUSY_TIMEOUT_MS}`);
  } catch {
    // Deleted between files() and this call, a corrupt/non-SQLite file, or
    // Crush itself holding a lock this readonly open can't get past within
    // BUSY_TIMEOUT_MS — all genuinely "could not read this," not "read it,
    // found nothing." Status "failed" keeps that distinction honest.
    return { lines: [], status: "failed", bytesRead: 0 };
  }

  const lines = [];
  let bytesRead = 0;
  const deadline = Date.now() + READ_TIMEOUT_MS;
  let timedOut = false;
  let sawError = false;
  let foundAnyTable = false;

  for (const table of TABLES) {
    let rows;
    try {
      rows = db.prepare(`SELECT * FROM ${table}`).iterate();
    } catch {
      // This particular table genuinely doesn't exist in this file's schema
      // (a Crush version old enough to predate it, in principle) — not a
      // read failure for the OTHER table, so just move on.
      continue;
    }
    foundAnyTable = true;

    let n = 0;
    try {
      for (const row of rows) {
        const text = rowToLine(row);
        lines.push(text);
        bytesRead += Buffer.byteLength(text, "utf-8");
        n++;
        if (n % YIELD_EVERY_N_ROWS === 0) {
          await new Promise((resolve) => setImmediate(resolve));
          if (Date.now() > deadline) { timedOut = true; break; }
        }
      }
    } catch {
      // A row iterator can itself throw partway (e.g. a corrupted page hit
      // mid-scan) — whatever WAS read before that is real content, kept the
      // same way claude-code.js keeps a partial read rather than discarding it.
      sawError = true;
    }
    if (timedOut) break;
  }

  try { db.close(); } catch { /* best-effort close; nothing left to do if this fails */ }

  // Neither known table existed at all — opened fine as SQLite but didn't
  // match the schema this source understands, a real "could not extract
  // anything," not the same as "extracted zero real rows."
  if (!foundAnyTable) return { lines: [], status: "failed", bytesRead: 0 };
  if (sawError && lines.length === 0) return { lines: [], status: "failed", bytesRead };
  if (timedOut || sawError) return { lines, status: lines.length > 0 ? "partial" : "failed", bytesRead };
  return { lines, status: "complete", bytesRead };
}

module.exports = { id, label, available, unavailableReason, files, readLines };
