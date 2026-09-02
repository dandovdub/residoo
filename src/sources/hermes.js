"use strict";

const fs = require("fs");
const path = require("path");
const os = require("os");

/**
 * Hermes Agent (NousResearch/hermes-agent, "the agent that grows with you")
 * local state database.
 *
 * VERIFICATION STATUS: NOT checked against a real install — `hermes` is not
 * on PATH and no `~/.hermes` directory exists on the machine this adapter
 * was built on. Ships per CONTRIBUTING.md rule 3 on two independent
 * corroborating sources, WITH an integrity caveat below that is unusually
 * important to read before trusting this file:
 *
 *   1. Hermes' own docs (fetched from its docs site): primary directory is
 *      `~/.hermes` on Linux/macOS/WSL2, `%LOCALAPPDATA%\hermes` on native
 *      Windows, and explicitly reference `$HERMES_HOME` as the env var that
 *      relocates it (e.g. "Session checkout: $HERMES_HOME/hermes-agent").
 *   2. ccusage (github.com/ccusage/ccusage — a real, independent, actively
 *      developed usage-tracking CLI; its own GitHub star count was sanity-
 *      checked against known repos before being trusted at all, see below)
 *      ships a tested Rust adapter for Hermes
 *      (rust/adapters/hermes/src/{paths,parser,loader}.rs), fetched and read
 *      directly. It confirms: `${HERMES_HOME:-~/.hermes}/state.db`, a real
 *      SQLite database, opened read-only, containing (at minimum) a table
 *      literally named `sessions` — its own unit test creates that table
 *      with `CREATE TABLE sessions (id TEXT PRIMARY KEY, source TEXT NOT
 *      NULL, model TEXT, started_at REAL NOT NULL, message_count INTEGER
 *      ..., input_tokens INTEGER ..., ... billing_provider TEXT,
 *      estimated_cost_usd REAL, actual_cost_usd REAL)` and queries it with
 *      `SELECT id, model, billing_provider, started_at, message_count,
 *      input_tokens, output_tokens, cache_read_tokens, cache_write_tokens,
 *      reasoning_tokens, estimated_cost_usd, actual_cost_usd FROM sessions`.
 *
 * THE INTEGRITY CAVEAT: while researching this source, `gh api` search
 * turned up openclaw/openclaw and NousResearch/hermes-agent GitHub star
 * counts (388,546 and 239,598 respectively, for repos 9-13 months old) that
 * are implausible for organic growth — comparable to or exceeding
 * decade-plus flagship repos like facebook/react and torvalds/linux, which
 * were fetched in the same session as a sanity check and came back in the
 * same 240-250k range. Independent search corroborates a real integrity
 * problem, not just a suspicious number: an arXiv paper on large-scale
 * GitHub fake-star campaigns turned up in the same research pass, alongside
 * a Hacker News thread titled "Nous Research edits GitHub issue to remove
 * plagiarism claims about Hermes Agent," and a GitHub topic description
 * referencing "Two zero-human AI companies battle for GitHub stars using
 * Hermes Agent + Paperclip." None of this proves the file format below is
 * wrong — ccusage's corroborating source is independent of Hermes/OpenClaw
 * and its parsing code is real and tested — but it does mean the two "docs"
 * sources for Hermes and OpenClaw may not be independent of EACH OTHER (one
 * plausibly forked/copied the other; Hermes' own docs describe importing
 * OpenClaw's config directory directly), which weakens this source's
 * corroboration below CONTRIBUTING.md's "2+ independent sources" bar in
 * spirit even where it's technically met. Flagged here and in this
 * adapter's PR description/report; a human should weigh this before
 * treating either this file or openclaw.js as more than
 * multi-source-corroborated-but-unverified.
 *
 * WHAT THIS SOURCE ACTUALLY READS: ccusage's own adapter only ever SELECTs
 * the `sessions` table's usage/cost columns — it has no reason to touch
 * anything else, and its code is silent on whether state.db holds the
 * user's actual conversation text anywhere, and if so, in which table.
 * Hermes' own marketing copy ("searches its own past conversations") implies
 * real message content is persisted somewhere in this database, but no
 * source here names the table. Rather than guess a table/column name likely
 * to be wrong, this source applies the same tolerance cursor.js already
 * established for exactly this situation: it enumerates EVERY table via
 * `sqlite_master` at read time and turns every row of every table into one
 * scanned line, keyed by column name, so it works regardless of which table
 * (if any) turns out to hold conversation content, and keeps working if
 * Hermes' schema drifts. See cursor.js's own docstring for the full
 * reasoning against a hardcoded key/table allowlist.
 */
const HERMES_HOME_ENV = "HERMES_HOME";

function hermesHomeDirs() {
  const envVal = process.env[HERMES_HOME_ENV];
  if (envVal && envVal.trim() !== "") {
    return envVal.split(",").map((s) => s.trim()).filter((s) => s !== "").map((p) => path.resolve(p));
  }
  const home = os.homedir();
  if (process.platform === "win32") {
    const localAppData = process.env.LOCALAPPDATA || path.join(home, "AppData", "Local");
    return [path.join(localAppData, "hermes")];
  }
  return [path.join(home, ".hermes")];
}

function stateDbPaths() {
  return hermesHomeDirs().map((dir) => path.join(dir, "state.db"));
}

/**
 * Lazily require node:sqlite — see cursor.js's getDatabaseSync() docstring
 * for the full reasoning (avoid Node's one-time ExperimentalWarning on every
 * `residoo scan` for users who have never touched a SQLite-backed source).
 * Duplicated rather than shared per this project's one-small-self-contained-
 * file convention.
 */
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

function id() { return "hermes"; }
function label() { return "Hermes"; }

function homeDirExists() {
  return hermesHomeDirs().some((dir) => {
    try { return fs.statSync(dir).isDirectory(); } catch { return false; }
  });
}

function available() {
  // Cheap fs check first — see cursor.js's available() for why short-
  // circuiting matters: the common case is Hermes simply isn't installed,
  // and that answer must not cost requiring node:sqlite.
  return homeDirExists() && Boolean(getDatabaseSync());
}

function unavailableReason() {
  if (!homeDirExists()) return null;
  if (getDatabaseSync()) return null;
  return "Hermes detected but not scanned — needs Node.js 22.5+ (node:sqlite not present in this runtime)";
}

/**
 * Same lstat-first, follow-if-symlink shape as cursor.js's statIfPresent —
 * duplicated for the same reason (no Dirent available for a constructed
 * path). A HERMES_HOME that doesn't have a state.db yet (Hermes installed
 * but never run) is normal and not broken.
 */
function* statIfPresent(dbPath) {
  let lst;
  try { lst = fs.lstatSync(dbPath); }
  catch { return; }

  if (lst.isSymbolicLink()) {
    try {
      const st = fs.statSync(dbPath);
      if (!st.isFile()) { yield { file: dbPath, broken: true }; return; }
      yield { file: dbPath, mtimeMs: st.mtimeMs, sizeBytes: st.size, broken: false };
    } catch {
      yield { file: dbPath, broken: true };
    }
    return;
  }

  if (!lst.isFile()) return;
  yield { file: dbPath, mtimeMs: lst.mtimeMs, sizeBytes: lst.size, broken: false };
}

function* files() {
  for (const dbPath of stateDbPaths()) yield* statIfPresent(dbPath);
}

// No real state.db has been inspected to size this against — unlike
// claude-code.js's MAX_BYTES, this is a generous, untested backstop only,
// same honesty as cursor.js's own MAX_DB_BYTES about the same gap.
const MAX_DB_BYTES = 512 * 1024 * 1024;
const READ_TIMEOUT_MS = 60_000;
const BUSY_TIMEOUT_MS = 5_000;
const YIELD_EVERY_N_ROWS = 500;

/**
 * A BLOB-affinity column comes back as a Uint8Array from node:sqlite, not a
 * Buffer — see cursor.js's valueToText() docstring, verified there directly
 * against this project's own node:sqlite, not assumed from Node's docs.
 */
function valueToText(value) {
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  if (value instanceof Uint8Array) return Buffer.from(value).toString("utf-8");
  return null;
}

/**
 * Read one state.db as an array of raw text "lines" — one per row, across
 * EVERY table found in sqlite_master (see the module docstring for why this
 * is deliberately schema-agnostic rather than hardcoding just `sessions`).
 * Each row becomes one JSON-stringified object of {column: text}, skipping
 * columns whose value isn't text/number/blob (NULL, mainly).
 *
 * Same synchronous-native-call constraint cursor.js's readLines() docstring
 * explains: node:sqlite's DatabaseSync/StatementSync have no event/AbortSignal
 * to hook a real preemptive timeout onto, so this yields to the event loop
 * and checks a wall-clock deadline every YIELD_EVERY_N_ROWS rows across all
 * tables combined — bounding "too many total rows across too many tables
 * taking too long", not a single pathological row's own decode time.
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
    return { lines: [], status: "failed", bytesRead: 0 };
  }

  let tableNames;
  try {
    tableNames = db
      .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'")
      .all()
      .map((row) => row.name)
      .filter((name) => typeof name === "string");
  } catch {
    try { db.close(); } catch { /* best-effort */ }
    return { lines: [], status: "failed", bytesRead: 0 };
  }

  const lines = [];
  let bytesRead = 0;
  const deadline = Date.now() + READ_TIMEOUT_MS;
  let timedOut = false;
  let sawError = false;
  let foundAnyTable = false;

  for (const table of tableNames) {
    let rows;
    try {
      // Table names come from sqlite_master itself, not user input, but are
      // still interpolated into SQL text — quote as a SQLite identifier
      // (doubled internal quotes) rather than trusting they're bare words.
      const quoted = `"${table.replace(/"/g, '""')}"`;
      rows = db.prepare(`SELECT * FROM ${quoted}`).iterate();
    } catch {
      continue; // this table genuinely can't be queried — move on, not fatal to the others
    }
    foundAnyTable = true;

    let n = 0;
    try {
      for (const row of rows) {
        const record = {};
        let hasText = false;
        for (const [column, value] of Object.entries(row)) {
          const text = valueToText(value);
          if (text !== null && text !== "") { record[column] = text; hasText = true; }
        }
        if (hasText) {
          const line = JSON.stringify(record);
          lines.push(line);
          bytesRead += Buffer.byteLength(line, "utf-8");
        }
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
