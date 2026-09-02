"use strict";

const fs = require("fs");
const path = require("path");
const os = require("os");

/**
 * Simon Willison's `llm` CLI (llm.datasette.io) — logs every prompt/response
 * to a local SQLite database.
 *
 * VERIFICATION STATUS (read this before trusting anything below): this
 * source is corroborated by multiple independent, official/primary sources,
 * but was NOT checked against a real `llm` install — this machine doesn't
 * have one (checked: no `llm` on PATH, no `io.datasette.llm` directory under
 * `~/Library/Application Support`, `pip show llm` empty). Treat it the same
 * way cursor.js's header asks you to treat that source: solid on paper,
 * unconfirmed against real data. What was actually checked, on 2026-09-02:
 *
 *   1. Official docs — https://llm.datasette.io/en/stable/logging.html —
 *      states the default macOS path in a worked example
 *      (`/Users/simon/Library/Application Support/io.datasette.llm/logs.db`),
 *      documents `llm logs path` / `llm logs status`, and describes both the
 *      legacy schema (`conversations`, `responses`, ...) and the newer
 *      content-addressed schema (`threads`, `turns`, `messages`, `parts`,
 *      ...), explicitly noting the legacy tables stay read-only and `llm
 *      logs` merges both generations.
 *   2. Primary source — the `llm` package's own code on GitHub, fetched
 *      directly (raw.githubusercontent.com/simonw/llm/main/...), not a
 *      summary of it:
 *        - `llm/__init__.py`, `user_dir()`:
 *            llm_user_path = os.environ.get("LLM_USER_PATH")
 *            if llm_user_path: path = pathlib.Path(llm_user_path)
 *            else: path = pathlib.Path(click.get_app_dir("io.datasette.llm"))
 *        - `llm/cli.py`, `logs_db_path()`: `return user_dir() / "logs.db"`
 *      i.e. the path is genuinely `<user_dir>/logs.db`, `LLM_USER_PATH`
 *      genuinely overrides it, and the app-id string genuinely is
 *      `io.datasette.llm` — not inferred, read verbatim from source.
 *   3. Click's own source (pallets/click, `src/click/utils.py`,
 *      `get_app_dir()`) for what `click.get_app_dir("io.datasette.llm")`
 *      resolves to per OS — llm's own docs only ever show the macOS case, so
 *      the Linux/Windows branches below are derived from click's documented
 *      and implemented behavior, not from an llm-specific source. See
 *      llmDefaultUserDir() below for the exact per-OS logic mirrored from it.
 *   4. A real user's own report — github.com/simonw/llm/issues/193 —
 *      independently corroborating the `.../Application Support/
 *      io.datasette.llm` directory from the install side (a bug about that
 *      directory not existing yet at first run), not just the docs page.
 *   5. The project's own changelog, release 0.32rc1 (2026-07-30): the
 *      content-addressed schema is the NEW generation, added recently, with
 *      old `responses`/`conversations` data explicitly left in place and
 *      still readable — i.e. this schema has already changed shape once,
 *      which is exactly why readLines() below does not hardcode either
 *      generation's table names (see its docstring).
 *
 * That's genuine primary-source verification of the PATH (docs + the actual
 * source lines that compute it + an independent bug report), which is a
 * stronger basis than cursor.js had for its paths. What's still unverified
 * is what a REAL logs.db, written by a real running `llm`, actually looks
 * like on disk — table-by-table, row-by-row. readLines()'s dynamic
 * table-introspection strategy (below) is the direct mitigation for that gap.
 */
function llmDefaultUserDir() {
  const home = os.homedir();
  if (process.platform === "win32") {
    // click.get_app_dir(): WIN branch — os.environ.get("APPDATA"), falling
    // back to the home directory if APPDATA is unset (roaming=True is
    // click's default, which is what llm calls it with).
    const appData = process.env.APPDATA || home;
    return path.join(appData, "io.datasette.llm");
  }
  if (process.platform === "darwin") {
    // click.get_app_dir(): darwin branch. Matches llm's own doc example.
    return path.join(home, "Library", "Application Support", "io.datasette.llm");
  }
  // click.get_app_dir(): remaining POSIX branch (Linux and friends).
  // _posixify("io.datasette.llm") is a no-op here — it only lowercases and
  // joins on whitespace, and the app id has neither.
  const xdgConfigHome = process.env.XDG_CONFIG_HOME || path.join(home, ".config");
  return path.join(xdgConfigHome, "io.datasette.llm");
}

// user_dir(), verbatim per llm/__init__.py: LLM_USER_PATH wins outright when
// set, otherwise the per-OS default above. Read once at module load — same
// convention cursor.js uses for its own env-derived paths.
const USER_DIR = process.env.LLM_USER_PATH || llmDefaultUserDir();
const LOGS_DB = path.join(USER_DIR, "logs.db");

const NODE_SQLITE_REQUIREMENT = "needs Node.js 22.5+ (node:sqlite not present in this runtime)";
let sqliteRequireAttempted = false;
let DatabaseSync = null;

/**
 * Same lazy-require discipline as cursor.js, and for the identical reason:
 * index.js requires every source unconditionally and cli.js calls
 * available() on all of them every run, so requiring node:sqlite eagerly
 * would print Node's ExperimentalWarning on every invocation for every user,
 * including the (large) majority who have never touched `llm`. Deferred
 * until USER_DIR is confirmed to actually exist — see available() below.
 */
function getDatabaseSync() {
  if (!sqliteRequireAttempted) {
    sqliteRequireAttempted = true;
    try { ({ DatabaseSync } = require("node:sqlite")); }
    catch { DatabaseSync = null; }
  }
  return DatabaseSync;
}

function id() { return "llm"; }
function label() { return "LLM (Datasette)"; }

function userDirExists() {
  try { return fs.statSync(USER_DIR).isDirectory(); } catch { return false; }
}

function available() {
  // Cheap fs check first, short-circuiting getDatabaseSync() (and its
  // possible warning) for the common case where `llm` was never installed —
  // identical shape to cursor.js's available().
  return userDirExists() && Boolean(getDatabaseSync());
}

/**
 * Optional, additive export — see cursor.js's own unavailableReason() for
 * the full rationale. Only distinguishes the one case worth calling out:
 * `llm`'s directory is really there but this Node runtime can't open SQLite.
 */
function unavailableReason() {
  if (!userDirExists()) return null;
  if (getDatabaseSync()) return null;
  return `LLM (Datasette) detected but not scanned — ${NODE_SQLITE_REQUIREMENT}`;
}

/**
 * Resolve the single logs.db candidate path into zero or one files() entries.
 * Same convention as cursor.js's statIfPresent: lstat first so a symlink is
 * detected and followed rather than silently treated as a plain file, a
 * dangling symlink is reported broken rather than skipped, and a path that
 * simply doesn't exist yet (llm installed but never run) yields nothing —
 * that's normal, not broken.
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
 * Yield { file, mtimeMs, sizeBytes, broken } for logs.db, if present.
 *
 * Unlike cursor.js there is exactly one candidate path — `llm` keeps one
 * user-wide database, not one per workspace — so this is a single
 * statIfPresent() call. Pure filesystem work, no SQLite touched, so it works
 * even on a Node runtime without node:sqlite (only readLines() needs that).
 */
function* files() {
  yield* statIfPresent(LOGS_DB);
}

// Not backed by an observed real logs.db (no install to measure — see the
// header). Set generously above cursor.js's 512MB precedent because llm logs
// can embed attachments (e.g. base64 image/PDF bytes passed to multimodal
// prompts) directly in BLOB columns, which plausibly grows a heavy user's
// database well past pure-text chat history the way Cursor's UI-state DB
// never would. An honest guess, not a measurement.
const MAX_DB_BYTES = 1 * 1024 * 1024 * 1024; // 1GB
const READ_TIMEOUT_MS = 60_000;
const BUSY_TIMEOUT_MS = 5_000; // bound how long a read waits on a lock `llm` itself may be holding
const YIELD_EVERY_N_ROWS = 500;

// FTS5 virtual tables (llm's docs mention at least one, for full-text search
// over turns) create shadow tables alongside the virtual table itself, named
// `<table>_data`, `<table>_idx`, `<table>_docsize`, `<table>_config`, and
// sometimes `<table>_content`. These hold compressed/internal index segments,
// not distinct content — the same text is reachable through the virtual
// table itself (a plain `SELECT * FROM <fts-table>` works and returns the
// indexed text). Skipping the shadow tables avoids scanning opaque segment
// blobs for no benefit; if this pattern-match misses a shadow table under
// some future naming, it just gets queried like any other table — caught by
// the per-table try/catch below if that errors, or scanned as harmless extra
// noise if it doesn't. Nothing is ever silently dropped because of this list.
const FTS_SHADOW_SUFFIX_RE = /_(data|idx|docsize|config|content|content_rowid)$/;

/**
 * A column value comes back from node:sqlite as a JS string (TEXT), number
 * or bigint (INTEGER), null, or Uint8Array (BLOB) — same storage-class
 * behavior cursor.js's valueToText() documents and relies on. Uint8Array is
 * decoded as UTF-8 text (attachments are commonly base64-encoded JSON/text
 * already, and even a genuinely binary blob just decodes to a harmless,
 * unmatchable string rather than breaking JSON.stringify, which cannot
 * serialize a Uint8Array or a bigint on its own).
 */
function rowToText(row) {
  try {
    return JSON.stringify(row, (_key, value) => {
      if (value instanceof Uint8Array) return Buffer.from(value).toString("utf-8");
      if (typeof value === "bigint") return value.toString();
      return value;
    });
  } catch {
    return null;
  }
}

/**
 * Read logs.db as an array of raw text "lines" — one per database row,
 * across every user table the file actually contains. Returns { lines,
 * status, bytesRead } with the same status vocabulary claude-code.js and
 * cursor.js use: "complete", "partial", "too-large", "failed".
 *
 * Table names are discovered at read time via `sqlite_master` rather than
 * hardcoded, deliberately — llm's own changelog documents that its schema
 * has already changed shape once (the 0.32rc1 rewrite from
 * `conversations`/`responses` to `threads`/`turns`/`messages`/`parts`, old
 * tables left in place but no longer written to). Hardcoding either
 * generation's table list risks the exact failure this project refuses to
 * ship: a schema that quietly drifts out from under a hardcoded assumption,
 * with the mismatch swallowed instead of surfaced. Introspecting
 * `sqlite_master` and reading whatever tables are actually there is correct
 * against the legacy schema, the current schema, and whatever comes next,
 * without needing to know which one a given logs.db is on.
 *
 * Same synchronous-native-call constraint as cursor.js's readLines() (no
 * 'error'/'close' event, no AbortSignal to hang a preemptive timeout off of)
 * — the same mitigation applies: iterate row-by-row, yield to the event loop
 * and check a wall-clock deadline every YIELD_EVERY_N_ROWS rows, now across
 * however many tables sqlite_master reports rather than a fixed two.
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
    // File deleted between files() and this call, a corrupt/non-SQLite file
    // at this path, or `llm` holding a lock this readonly open can't get
    // past within BUSY_TIMEOUT_MS — all genuinely "could not read this."
    return { lines: [], status: "failed", bytesRead: 0 };
  }

  let tableNames = [];
  try {
    const rows = db
      .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'")
      .all();
    tableNames = rows
      .map((r) => r.name)
      .filter((n) => typeof n === "string" && !FTS_SHADOW_SUFFIX_RE.test(n));
  } catch {
    try { db.close(); } catch { /* best-effort */ }
    // Opened as SQLite but couldn't even list its own tables — treat like
    // cursor.js treats "neither known table existed": a real failure to
    // extract anything, not "extracted zero real rows."
    return { lines: [], status: "failed", bytesRead: 0 };
  }

  const lines = [];
  let bytesRead = 0;
  const deadline = Date.now() + READ_TIMEOUT_MS;
  let timedOut = false;
  let sawError = false;

  for (const table of tableNames) {
    let rows;
    try {
      // Quoted identifier: table names come from sqlite_master itself, not
      // user input, but quoting costs nothing and avoids any accidental
      // reserved-word collision.
      rows = db.prepare(`SELECT * FROM "${table}"`).iterate();
    } catch {
      // A shadow table this source's suffix filter didn't catch, or any
      // other table this build of node:sqlite can't directly SELECT from —
      // move on to the next table rather than aborting the whole file.
      continue;
    }

    let n = 0;
    try {
      for (const row of rows) {
        const text = rowToText(row);
        if (text) { lines.push(text); bytesRead += Buffer.byteLength(text, "utf-8"); }
        n++;
        if (n % YIELD_EVERY_N_ROWS === 0) {
          await new Promise((resolve) => setImmediate(resolve));
          if (Date.now() > deadline) { timedOut = true; break; }
        }
      }
    } catch {
      // A row iterator can itself throw partway (e.g. a corrupted page hit
      // mid-scan) — whatever WAS read before that is real content, kept the
      // same way claude-code.js and cursor.js keep a partial read rather
      // than discarding it.
      sawError = true;
    }
    if (timedOut) break;
  }

  try { db.close(); } catch { /* best-effort close; nothing left to do if this fails */ }

  if (tableNames.length === 0) return { lines: [], status: "failed", bytesRead: 0 };
  if (sawError && lines.length === 0) return { lines: [], status: "failed", bytesRead };
  if (timedOut || sawError) return { lines, status: lines.length > 0 ? "partial" : "failed", bytesRead };
  return { lines, status: "complete", bytesRead };
}

module.exports = { id, label, available, unavailableReason, files, readLines };
