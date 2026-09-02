"use strict";

const fs = require("fs");
const path = require("path");
const os = require("os");

/**
 * Cognition's Devin CLI ("Devin for Terminal," docs.devin.ai/work-with-devin/
 * devin-cli) local session database.
 *
 * VERIFICATION STATUS: corroborated by two independent sources — one of them
 * real, working, tested code that reads the exact file this source targets —
 * but NOT checked against a real install on the machine this source was
 * built on (no `~/.local/share/devin` directory exists there, and Devin CLI
 * was not installed to create one; see CONTRIBUTING.md). Cognition's own docs
 * (docs.devin.ai/cli/reference/commands) confirm Devin CLI is a real local
 * terminal agent — full local file access, no cloud workspace copy — with a
 * `man devin` page and a `--config <PATH>` flag, but do not themselves state
 * the storage path or schema, which is why this source leans on the two
 * sources below instead of Cognition's own docs for those specifics.
 *
 *   1. github.com/fabzter/devin-session-search — a real, working MCP server
 *      (25 passing tests) built specifically to full-text-search "Devin
 *      CLI's SQLite-based session store." Its README states plainly: "Devin
 *      CLI stores every conversation in `~/.local/share/devin/cli/
 *      sessions.db`," and its architecture diagram documents the schema this
 *      source relies on: a `sessions` table (id, title, model, created_at)
 *      and a `message_nodes` table ("4,323+ rows of conversation content")
 *      whose `chat_message` column holds a JSON blob of
 *      `{role, content, tool_calls}`. `indexer.py`'s own source (fetched
 *      during this source's research) opens `sessions.db` with
 *      `sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)` — i.e. this
 *      tool's author built and tested a read-only reader against the real
 *      file, not a description of one.
 *   2. jazzyalex/agent-sessions (github.com/jazzyalex/agent-sessions, 800+
 *      stars, a real macOS app built to parse local AI-coding-agent session
 *      history) independently lists Devin CLI as its "fourteenth agent
 *      source," describing it as reading "from the shared SQLite
 *      `sessions.db` under the CLI data directory," consistent with source 1
 *      above, and separately notes "Resume verified 2026-08-27 on 3000.5.20"
 *      — i.e. its maintainer ran this against a real, current Devin CLI
 *      install.
 *
 * Neither source states a macOS-specific path (both use the Linux/XDG-style
 * `~/.local/share/...` unconditionally, with no OS branching visible in
 * source 1's own code) — this source follows that exactly rather than
 * guessing at a `~/Library/Application Support/devin` variant no source
 * describes; if Devin CLI does branch by OS on a real Mac, this source will
 * correctly report "not available" there rather than silently checking the
 * wrong path (see available() below).
 *
 * Column names beyond the two table names above are not hard-relied upon:
 * like cursor.js's ItemTable/cursorDiskKV handling, this source selects every
 * column of every row (`SELECT *`) and turns each row into one JSON-
 * stringified scanned "line," rather than hard-coding e.g. `chat_message` as
 * the only column worth reading — a schema field this source's research
 * didn't happen to name (an API key column, say) is not silently skipped.
 */
const HOME = os.homedir();
const SESSIONS_DB = path.join(HOME, ".local", "share", "devin", "cli", "sessions.db");

/**
 * node:sqlite is a Node CORE module, not a package — see cursor.js's
 * docstring for the full reasoning on why this is lazy-required (avoiding an
 * ExperimentalWarning on every `residoo scan` for users who don't have Devin
 * CLI installed) and why that reasoning matters project-wide, not just for
 * Cursor.
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

function id() { return "devin-cli"; }
function label() { return "Devin CLI"; }

function dbFileExists() {
  try { return fs.statSync(SESSIONS_DB).isFile(); } catch { return false; }
}

function available() {
  // Cheap fs check first — see cursor.js's available() for why this ordering
  // matters (skip requiring node:sqlite, and its warning, for the common
  // case of Devin CLI simply not being installed).
  return dbFileExists() && Boolean(getDatabaseSync());
}

/**
 * Same "why this exists" as cursor.js's unavailableReason(): distinguishes
 * "Devin CLI is installed here but this Node runtime is too old for
 * node:sqlite" from the ordinary, unremarkable "Devin CLI just isn't here."
 * Optional per the source contract — only cli.js's own diagnostics call this.
 */
function unavailableReason() {
  if (!dbFileExists()) return null;
  if (getDatabaseSync()) return null;
  return `Devin CLI detected but not scanned — ${NODE_SQLITE_REQUIREMENT}`;
}

/**
 * A single fixed file, not a directory walk — mirrors cursor.js's
 * statIfPresent() for GLOBAL_STORAGE_DB. Not `broken: true` when the path
 * simply doesn't exist (the ordinary "Devin CLI isn't installed, or hasn't
 * created a session yet" case); that's reserved for a path that looked like
 * it should resolve to a real file and didn't (a dangling symlink).
 */
function* files() {
  let lst;
  try { lst = fs.lstatSync(SESSIONS_DB); }
  catch { return; }

  if (lst.isSymbolicLink()) {
    try {
      const st = fs.statSync(SESSIONS_DB);
      if (!st.isFile()) { yield { file: SESSIONS_DB, broken: true }; return; }
      yield { file: SESSIONS_DB, mtimeMs: st.mtimeMs, sizeBytes: st.size, broken: false };
    } catch {
      yield { file: SESSIONS_DB, broken: true };
    }
    return;
  }

  if (!lst.isFile()) return; // something unexpected sits at this path — out of scope, not broken
  yield { file: SESSIONS_DB, mtimeMs: lst.mtimeMs, sizeBytes: lst.size, broken: false };
}

const MAX_DB_BYTES = 512 * 1024 * 1024; // generous backstop; no real Devin sessions.db size was
                                          // observed during this source's research (see cursor.js's
                                          // identical caveat about its own MAX_DB_BYTES).
const READ_TIMEOUT_MS = 60_000;
const BUSY_TIMEOUT_MS = 5_000;
const YIELD_EVERY_N_ROWS = 500;

/**
 * Turn one row (a plain object from node:sqlite's StatementSync#iterate())
 * into one scanned text "line." node:sqlite returns a BLOB column as a
 * Uint8Array (decoded to UTF-8 text here, same as cursor.js's valueToText)
 * and an INTEGER too large for a safe JS number as a BigInt (which
 * JSON.stringify throws on unless handled) — both are normalized before
 * stringifying so a row is never silently dropped for containing either.
 */
function rowToLine(row) {
  const normalized = {};
  for (const [key, value] of Object.entries(row)) {
    if (typeof value === "bigint") normalized[key] = value.toString();
    else if (value instanceof Uint8Array) normalized[key] = Buffer.from(value).toString("utf-8");
    else normalized[key] = value;
  }
  try { return JSON.stringify(normalized); }
  catch { return null; } // e.g. a cyclic or otherwise unstringifiable value — skip this row, not the file
}

/**
 * Read sessions.db as an array of raw text "lines" — one per row, across
 * both known tables. Same status vocabulary, same row-by-row-with-a-
 * wall-clock-deadline approach, and same reasoning for all of it as
 * cursor.js's readLines() — see that file's docstring; not repeated in full
 * here since the mechanics are identical, only the table/column names
 * differ.
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
    // readBigInts: true matters here in a way it happens not to for cursor.js's
    // reference implementation — that source only ever SELECTs a fixed `key
    // TEXT, value BLOB` pair, so no column can hold an INTEGER SQLite would
    // need to widen. This source does `SELECT *` against an externally-owned,
    // only-partially-documented schema (see the module docstring) where an
    // INTEGER column — a nanosecond-epoch `created_at`, say, which routinely
    // exceeds 2^53 — is a real possibility. Without this flag, node:sqlite
    // THROWS RangeError the moment it meets such a value mid-iteration
    // (verified directly against this project's own node:sqlite while
    // building this source), which without care would silently drop that row
    // and everything after it in the same table — exactly the "schema
    // surprise swallowed by a bare catch" failure this project exists to
    // avoid (see CONTRIBUTING.md rule 5). With it, the same value comes back
    // as a BigInt, which rowToLine() below already converts to a string.
    db = new DB(file, { readOnly: true, readBigInts: true });
    db.exec(`PRAGMA busy_timeout = ${BUSY_TIMEOUT_MS}`);
  } catch {
    return { lines: [], status: "failed", bytesRead: 0 };
  }

  const lines = [];
  let bytesRead = 0;
  const deadline = Date.now() + READ_TIMEOUT_MS;
  let timedOut = false;
  let sawError = false;
  let foundAnyTable = false;

  for (const table of ["sessions", "message_nodes"]) {
    let rows;
    try {
      rows = db.prepare(`SELECT * FROM ${table}`).iterate();
    } catch {
      continue; // this table doesn't exist in this file's schema — try the other one
    }
    foundAnyTable = true;

    let n = 0;
    try {
      for (const row of rows) {
        const text = rowToLine(row);
        if (text) { lines.push(text); bytesRead += Buffer.byteLength(text, "utf-8"); }
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

  if (!foundAnyTable) return { lines: [], status: "failed", bytesRead: 0 };
  if (sawError && lines.length === 0) return { lines: [], status: "failed", bytesRead };
  if (timedOut || sawError) return { lines, status: lines.length > 0 ? "partial" : "failed", bytesRead };
  return { lines, status: "complete", bytesRead };
}

module.exports = { id, label, available, unavailableReason, files, readLines };
