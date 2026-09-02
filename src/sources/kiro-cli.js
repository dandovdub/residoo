"use strict";

const fs = require("fs");
const { createInterface } = require("readline/promises");
const path = require("path");
const os = require("os");

/**
 * Kiro CLI (AWS/Kiro's terminal coding agent, binary `kiro-cli` / `kiro`)
 * session history. Distinct from Kiro IDE (see kiro-ide.js) — same product
 * family, different application, different storage.
 *
 * VERIFICATION STATUS (read this before trusting anything below): the
 * general shape ("SQLite database in ~/.kiro/", per-directory scoping) is
 * confirmed directly from Kiro's own official docs
 * (https://kiro.dev/docs/cli/chat/session-management/, "Technical details"
 * section — fetched as raw HTML and grepped for the literal text). That
 * page turns out to be imprecise about the exact path, though (see below) —
 * caught only by going one step further to a real, actively-maintained,
 * read-only community tool built specifically to read this data:
 * github.com/prabhugr/kiro-cli-history. Its own README states plainly "This
 * tool never writes to or modifies your Kiro CLI session data" and opens
 * the database "in read-only mode" — and this source fetched and read its
 * actual Python source (`kiro_history.py`), not just its README prose, the
 * same standard cursor.js's own research applied to its community source.
 * This has NOT been checked against a real Kiro CLI install — it is not
 * installed on the machine this adapter was built on (checked: no `kiro` or
 * `kiro-cli` on PATH, no `~/.kiro` directory). If you have Kiro CLI
 * installed, the most useful thing you can do is run `residoo scan` and
 * confirm `sourcesScanned`/`filesScanned` look right for what you know is
 * actually on disk, then report back either way.
 *
 * THREE STORAGE FORMATS. `kiro_history.py`'s own module docstring names
 * three, and its actual path constants and SQL confirm each one, quoted
 * near-verbatim:
 *
 *   1. v3 (JSONL, used by `kiro-cli --classic`):
 *      `~/.kiro/sessions/cli/<session-id>.json` (metadata: session_id,
 *      title, cwd, created_at, updated_at) plus a companion
 *      `~/.kiro/sessions/cli/<session-id>.jsonl` (the actual conversation —
 *      one JSON record per line, each with a `kind` field — `"Prompt"` or
 *      `"AssistantMessage"` observed — and the message text nested at
 *      `data.content[].data` where `data.content[].kind === "text"`).
 *      Both files sit FLAT directly in `sessions/cli/`, not nested per
 *      project — confirmed directly from source (`SESSIONS_DIR.glob("*.json")`,
 *      a non-recursive glob).
 *   2. v2 (SQLite, used by the current default TUI mode):
 *      `~/Library/Application Support/kiro-cli/data.sqlite3` (macOS path —
 *      this specific tool is macOS-only per its own README), table
 *      `conversations_v2` — confirmed from its actual query:
 *      `SELECT key, conversation_id, value, created_at, updated_at FROM
 *      conversations_v2 ORDER BY updated_at DESC`, where `value` is a JSON
 *      blob holding the conversation.
 *   3. v1 (SQLite, legacy): same database file, table `conversations` —
 *      confirmed from source: `SELECT key, value FROM conversations`, where
 *      `value` is again a JSON blob (`conversation_id` is read back out of
 *      the parsed JSON itself here, not a separate column — the schema
 *      visibly grew a dedicated column between v1 and v2).
 *
 * That a real, working tool had to reverse-engineer THREE evolving formats
 * to stay useful is itself the reason this source discovers tables from
 * `sqlite_master` at scan time (see readSqliteLines() below) rather than
 * hardcoding only `conversations`/`conversations_v2` — the same schema-drift
 * reasoning warp.js documents at length for a comparable situation. A v3-era
 * SQLite table this source doesn't yet know the name of would still get
 * scanned.
 *
 * WHERE KIRO'S OWN DOCS ARE IMPRECISE: they say simply "SQLite database in
 * ~/.kiro/" — true of the JSONL sessions (which really do live under
 * `~/.kiro/`) but not of the SQLite database itself, which in fact lives in
 * the OS-native local-data directory, a level of precision only the
 * community tool's actual, working source code provided. This is exactly
 * the class of error CONTRIBUTING.md's guessed-path warning describes,
 * caught the same way this project caught an analogous imprecision in a
 * secondary source for Crush (see crush.js's docstring) — by going to a
 * source that had to actually work against the real file, not just describe
 * it.
 *
 * PER-OS SQLITE PATH: only the macOS path above is independently confirmed
 * (kiro-cli-history is explicitly macOS-only). Linux and Windows below are
 * filled in by structural analogy to the OS-native "local data directory"
 * convention (Rust's `dirs::data_local_dir()`) — the exact convention this
 * source separately confirmed, from actual source
 * (`crates/chat-cli/src/util/paths.rs`), that the sibling AWS product Q
 * Developer CLI uses for its own `<data-dir>/amazon-q/data.sqlite3` (Kiro
 * CLI is documented — see kiro.dev's own CLI intro — as building on Q
 * Developer CLI's agent engine, with `amazon-q` swapped for `kiro-cli` in
 * exactly the position confirmed on macOS). Flagged as analogy, not
 * independently quoted, same honesty standard as this project's other
 * per-OS gaps (e.g. warp.js's Preview-channel filename).
 */
function homeDir() { return os.homedir(); }

const KIRO_HOME = path.join(homeDir(), ".kiro");
const JSONL_SESSIONS_DIR = path.join(KIRO_HOME, "sessions", "cli");

function sqliteDbPath() {
  if (process.platform === "darwin") {
    return path.join(homeDir(), "Library", "Application Support", "kiro-cli", "data.sqlite3");
  }
  if (process.platform === "win32") {
    const localAppData = process.env.LOCALAPPDATA || path.join(homeDir(), "AppData", "Local");
    return path.join(localAppData, "kiro-cli", "data.sqlite3");
  }
  // Linux and other XDG-following unix platforms — not independently
  // confirmed for Kiro CLI specifically; see module docstring.
  const xdgDataHome = process.env.XDG_DATA_HOME || path.join(homeDir(), ".local", "share");
  return path.join(xdgDataHome, "kiro-cli", "data.sqlite3");
}

const SQLITE_DB = sqliteDbPath();

/**
 * Same lazy-require, feature-detected node:sqlite pattern as cursor.js,
 * crush.js, and warp.js — see cursor.js's docstring for the full reasoning.
 * Duplicated rather than shared: each source here is meant to be a small,
 * self-contained file a reviewer can audit on its own (CONTRIBUTING.md).
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

function id() { return "kiro-cli"; }
function label() { return "Kiro CLI"; }

function jsonlDirExists() {
  try { return fs.statSync(JSONL_SESSIONS_DIR).isDirectory(); } catch { return false; }
}

function sqliteDbExists() {
  try { return fs.statSync(SQLITE_DB).isFile(); } catch { return false; }
}

/**
 * True when either store is present. The JSONL store needs no node:sqlite
 * at all, so this must not require it merely because the SQLite store also
 * happens not to exist — same short-circuit-order reasoning as cursor.js's
 * available(), applied across two independent stores instead of one.
 */
function available() {
  if (jsonlDirExists()) return true;
  return sqliteDbExists() && Boolean(getDatabaseSync());
}

/**
 * Same additive, optional export as cursor.js's/crush.js's/warp.js's
 * unavailableReason(). Only fires the one case worth calling out
 * specifically: the SQLite store is the only thing present, and this Node
 * runtime can't read it. If the JSONL store is present, available() is
 * already true and there's nothing to explain.
 */
function unavailableReason() {
  if (jsonlDirExists()) return null;
  if (!sqliteDbExists()) return null;
  if (getDatabaseSync()) return null;
  return `Kiro CLI detected but not scanned — ${NODE_SQLITE_REQUIREMENT}`;
}

// Bounds for readLines() on the JSONL store — same shape as claude-code.js's.
const MAX_BYTES = 2 * 1024 * 1024 * 1024; // 2GB
const READ_TIMEOUT_MS = 60_000;

/**
 * Yield { file, mtimeMs, sizeBytes, broken } for every `.json`/`.jsonl` file
 * directly under `~/.kiro/sessions/cli/` — flat, non-recursive, matching
 * kiro-cli-history's own confirmed `SESSIONS_DIR.glob("*.json")` walk (the
 * companion `.jsonl` files sit alongside, same directory, so a plain
 * extension filter over one readdir catches both).
 */
function* jsonlFiles() {
  let entries;
  try { entries = fs.readdirSync(JSONL_SESSIONS_DIR, { withFileTypes: true }); }
  catch { return; }

  for (const e of entries) {
    if (!/\.(jsonl|json)$/i.test(e.name)) continue;
    const full = path.join(JSONL_SESSIONS_DIR, e.name);

    if (e.isFile()) {
      let stat;
      try { stat = fs.statSync(full); } catch { yield { file: full, broken: true }; continue; }
      yield { file: full, mtimeMs: stat.mtimeMs, sizeBytes: stat.size, broken: false };
      continue;
    }
    if (e.isSymbolicLink()) {
      try {
        const stat = fs.statSync(full); // follow the link
        if (!stat.isFile()) { yield { file: full, broken: true }; continue; }
        yield { file: full, mtimeMs: stat.mtimeMs, sizeBytes: stat.size, broken: false };
      } catch {
        yield { file: full, broken: true }; // dangling symlink
      }
    }
    // Anything else (a directory named *.json, a FIFO, ...) was never a
    // scannable transcript in the first place — out of scope, not broken.
  }
}

/**
 * Yield zero or one files() entries for the SQLite database. Identical
 * shape and reasoning to cursor.js's/warp.js's statIfPresent(): a
 * constructed, not discovered, path, so lstat is used directly. Missing
 * entirely (this mode of Kiro CLI never used, or an older/newer version
 * with a different filename) yields nothing and is NOT broken; a dangling
 * symlink IS.
 */
function* sqliteFileEntry() {
  let lst;
  try { lst = fs.lstatSync(SQLITE_DB); }
  catch { return; }

  if (lst.isSymbolicLink()) {
    try {
      const st = fs.statSync(SQLITE_DB);
      if (!st.isFile()) { yield { file: SQLITE_DB, broken: true }; return; }
      yield { file: SQLITE_DB, mtimeMs: st.mtimeMs, sizeBytes: st.size, broken: false };
    } catch {
      yield { file: SQLITE_DB, broken: true };
    }
    return;
  }

  if (!lst.isFile()) return;
  yield { file: SQLITE_DB, mtimeMs: lst.mtimeMs, sizeBytes: lst.size, broken: false };
}

function* files() {
  yield* jsonlFiles();
  yield* sqliteFileEntry();
}

/**
 * Read one JSONL/JSON transcript file as raw text lines. Identical approach
 * to claude-code.js's readLines() — see that file's docstring for the full
 * reasoning; not re-derived here since nothing about it is Kiro-specific.
 */
async function readJsonlLines(file) {
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

// Bounds for the SQLite store's readLines() — same shape as cursor.js's/
// warp.js's. Not backed by a real large data.sqlite3 this tool was tested
// against; a generous, honestly-labeled backstop.
const MAX_DB_BYTES = 512 * 1024 * 1024;
const READ_TIMEOUT_MS_DB = 60_000;
const BUSY_TIMEOUT_MS = 5_000;
const YIELD_EVERY_N_ROWS = 500;

function quoteIdent(name) {
  return '"' + name.replace(/"/g, '""') + '"';
}

/**
 * List every real, user-created table in the database, discovered from
 * `sqlite_master` rather than hardcoded to `conversations`/`conversations_v2`
 * — see the module docstring for why (a real community tool already had to
 * chase this schema through three revisions).
 */
function discoverTableNames(db) {
  try {
    const rows = db.prepare(
      "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite\\_%' ESCAPE '\\'"
    ).all();
    return rows.map((r) => r.name).filter((n) => typeof n === "string" && n.length > 0);
  } catch {
    return [];
  }
}

/**
 * Turn one row into one scanned text line. Same Uint8Array/BigInt handling
 * as crush.js's rowToLine() and warp.js's rowToLine() — see either for the
 * full reasoning; not re-derived here.
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
 * Read the SQLite store as raw text lines — one per row, across every
 * discovered table. Same status vocabulary and periodic-yield-plus-deadline
 * approach as cursor.js's/crush.js's/warp.js's readLines(), for the same
 * reason: node:sqlite is fully synchronous. See cursor.js's own docstring
 * for the full reasoning.
 */
async function readSqliteLines(file) {
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
    return { lines: [], status: "failed", bytesRead: 0 };
  }

  const tables = discoverTableNames(db);

  const lines = [];
  let bytesRead = 0;
  const deadline = Date.now() + READ_TIMEOUT_MS_DB;
  let timedOut = false;
  let sawError = false;

  for (const table of tables) {
    let rows;
    try {
      rows = db.prepare(`SELECT * FROM ${quoteIdent(table)}`).iterate();
    } catch {
      continue;
    }

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
      sawError = true;
    }
    if (timedOut) break;
  }

  try { db.close(); } catch { /* best-effort close */ }

  if (tables.length === 0) return { lines: [], status: "failed", bytesRead: 0 };
  if (sawError && lines.length === 0) return { lines: [], status: "failed", bytesRead };
  if (timedOut || sawError) return { lines, status: lines.length > 0 ? "partial" : "failed", bytesRead };
  return { lines, status: "complete", bytesRead };
}

/**
 * Dispatch to the JSONL or SQLite reader by matching `file` against the one
 * known SQLite path — everything else (every entry jsonlFiles() can ever
 * yield) goes through the plain text reader.
 */
async function readLines(file) {
  if (file === SQLITE_DB) return readSqliteLines(file);
  return readJsonlLines(file);
}

module.exports = { id, label, available, unavailableReason, files, readLines };
