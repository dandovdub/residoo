"use strict";

const fs = require("fs");
const path = require("path");
const os = require("os");
const { createInterface } = require("readline/promises");

/**
 * OpenCode (https://opencode.ai — repo moved from github.com/sst/opencode to
 * github.com/anomalyco/opencode after the SST team rebranded to Anomaly in
 * 2026; same project, same maintainers, old sst/opencode Docker-image-style
 * references now point at a stale location). Not to be confused with the
 * unrelated, much smaller opencode-ai/opencode project or with GitHub
 * Copilot's own internal "OpenCode" naming, if any — this adapter targets
 * the 75+-provider terminal coding agent at opencode.ai specifically.
 *
 * VERIFICATION STATUS: NOT checked against a real OpenCode install — neither
 * `opencode` nor any `~/.local/share/opencode` / `~/.config/opencode`
 * directory exists on the machine this adapter was built on (checked:
 * PATH, mdfind, common install locations). Ships anyway per CONTRIBUTING.md
 * rule 3 on the strength of multiple independent, corroborating sources
 * that agree with each other and, in two cases, are the project's own real
 * source code and its own maintainers describing a real, live bug in it:
 *
 *  - Official docs (opencode.ai/docs/troubleshooting/): data lives under
 *    `~/.local/share/opencode/` on macOS/Linux (this is the same on macOS
 *    as on Linux — OpenCode does NOT use `~/Library/Application Support`
 *    there, confirmed independently by several GitHub issues filed
 *    specifically complaining that it doesn't follow platform convention
 *    on macOS/Windows, e.g. #18633, #8235 — a real, if debated, choice, not
 *    an assumption made here) and an equivalent path under
 *    `%USERPROFILE%` on Windows.
 *  - The project's own real source, read directly: `session.sql.ts` at
 *    github.com/anomalyco/opencode confirms a Drizzle-ORM SQLite schema
 *    (`sqliteTable(...)`) for the `session` table, and multiple real
 *    GitHub issues on the same repo (#13202 "SQLite storage layer",
 *    #13654, #12889, #34445, #21941) all independently reference the same
 *    two-format reality this adapter is built around — see below.
 *  - GitHub issue #13654, describing a real, live bug: incremental
 *    upgraders can end up with the pre-SQLite storage format never
 *    migrated, leaving JSON session files "permanently orphaned" on disk;
 *    the issue explicitly quotes their real location as
 *    `~/.local/share/opencode/storage/session/*.json`. Issue #12889
 *    ("NotFoundError on startup: session JSON files not found in
 *    storage") independently corroborates the same `storage/` JSON layout
 *    from the other direction (a user hitting the gap this adapter reads
 *    around). A different official-docs excerpt additionally describes a
 *    project-scoped variant of the same idea — `<project-slug>/storage/`
 *    for a git repo, `global/storage/` otherwise — i.e. the exact nesting
 *    under `storage/` has moved across versions. Both shapes share one
 *    trait this adapter relies on instead of picking one to hardcode: the
 *    content-bearing files always sit under a directory literally named
 *    `storage`, at some depth under the OpenCode data root.
 *
 * Given that version drift (confirmed by the project's own migration code
 * existing at all, and by the incremental-upgrade bug above meaning both
 * formats really can coexist on one real machine), this source reads BOTH,
 * the same call cursor.js makes for its own two-copy, moved-across-versions
 * ambiguity:
 *   - `<DATA_DIR>/opencode.db` — current format, read via node:sqlite.
 *   - every `*.json` file under any directory literally named `storage`,
 *     anywhere under `<DATA_DIR>` — legacy/orphaned format.
 *
 * Deliberately NOT read: `<DATA_DIR>/auth.json` (OpenCode's own provider
 * API key vault — the user's intentionally configured credentials, not a
 * leaked one; scanning it would just re-report keys the user put there on
 * purpose) or `<DATA_DIR>/opencode.json` / `log/` (config and application
 * logs, not conversation content) — mirroring how claude-code.js and
 * cursor.js each stay scoped to actual transcript data rather than a
 * tool's entire state directory. Since none of these live under a
 * `storage`-named directory, the walk below already excludes them
 * structurally, not just by convention.
 *
 * The SQLite schema itself is read generically (see readDbFile() below)
 * rather than hardcoding table/column names beyond `session` (the one
 * table this research could confirm directly from source): the exact
 * `message`/`part` table names and columns could not be confirmed against
 * either a real install or the actual message.sql.ts/part.sql.ts source
 * (GitHub's raw/blob endpoints were unreachable during this research), and
 * cursor.js's own docstring already makes the case for why guessing at a
 * key/column allowlist is the wrong tradeoff when the schema is confirmed
 * to have moved before and code review can't check it against a real file.
 * A generic per-table, per-column text scan can't go stale the way a
 * specific column list can.
 *
 * If you have OpenCode installed, the most useful thing you can do is run
 * `residoo scan` and confirm `sourcesScanned`/`filesScanned` look right for
 * what you know is actually on disk under your OpenCode data directory,
 * then report back either way — see CONTRIBUTING.md.
 */
function opencodeDataDir() {
  // XDG_DATA_HOME is honored for OpenCode's config dir per its own docs
  // (opencode.ai/docs — XDG_CONFIG_HOME is explicitly documented there) and
  // the project's data dir follows the same XDG-first convention (per the
  // GitHub issues above discussing XDG_DATA_HOME for this exact directory).
  // Same reasoning as cursor.js honoring XDG_CONFIG_HOME: the tool's own
  // documented override, not a guess.
  const home = os.homedir();
  const dataHome = process.env.XDG_DATA_HOME || path.join(home, ".local", "share");
  return path.join(dataHome, "opencode");
}

const DATA_DIR = opencodeDataDir();
const DB_FILE = path.join(DATA_DIR, "opencode.db");

const MAX_BYTES = 2 * 1024 * 1024 * 1024; // 2GB — same reasoning as claude-code.js/codex-cli.js
const READ_TIMEOUT_MS = 60_000;
const MAX_WALK_DEPTH = 12; // see codex-cli.js's identical constant for why this exists

// Same backstop-not-evidence caveat as cursor.js's MAX_DB_BYTES: no real
// opencode.db has been observed during this research to size this against.
const MAX_DB_BYTES = 512 * 1024 * 1024;
const BUSY_TIMEOUT_MS = 5_000;
const YIELD_EVERY_N_ROWS = 500;

function id() { return "opencode"; }
function label() { return "OpenCode"; }

function dataDirExists() {
  try { return fs.statSync(DATA_DIR).isDirectory(); } catch { return false; }
}

/**
 * Unlike cursor.js, availability here does NOT depend on node:sqlite being
 * present: the legacy JSON-under-storage/ format (see module docstring) is
 * plain text, readable with zero special modules, on any Node version this
 * project supports. Gating the whole source on sqlite would silently drop
 * real, scannable content for exactly the incremental-upgrade users GitHub
 * issue #13654 describes — orphaned JSON sessions with no opencode.db ever
 * written, or a Node runtime too old for node:sqlite. sqlite is required
 * only for the opencode.db file specifically; see readDbFile()'s own
 * "failed" return when it's unavailable, surfaced per-file rather than by
 * hiding the whole source.
 */
function available() {
  return dataDirExists();
}

/**
 * Lazily loaded exactly like cursor.js's getDatabaseSync() — see that
 * file's docstring for the full reasoning (avoid the one-time
 * ExperimentalWarning node:sqlite prints from being paid by every user on
 * every invocation, since index.js requires every source unconditionally).
 * Duplicated rather than shared, per this project's one-file-per-source
 * convention.
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

/** Same lstat-vs-stat symlink-following pattern duplicated across every source in this project. */
function isKindFollowingSymlink(fullPath, dirent, checkFn) {
  if (checkFn(dirent)) return true;
  if (!dirent.isSymbolicLink()) return false;
  try { return checkFn(fs.statSync(fullPath)); } catch { return false; }
}
const isDirFollowingSymlink = (p, d) => isKindFollowingSymlink(p, d, (x) => x.isDirectory());
const isFileFollowingSymlink = (p, d) => isKindFollowingSymlink(p, d, (x) => x.isFile());

/**
 * Recursively walk `dir` looking for directories literally named `storage`;
 * within each one found, recursively yield every `*.json` file underneath
 * it (any depth) as a { file, mtimeMs, sizeBytes, broken } entry. A
 * directory named anything else is only ever a waypoint down to a possible
 * `storage` dir, never scanned itself — this is what keeps auth.json,
 * opencode.json, and log/ out of scope structurally (see module docstring).
 */
function* walkForStorageJson(dir, depth, insideStorage) {
  if (depth > MAX_WALK_DEPTH) return;
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); }
  catch { return; }

  for (const e of entries) {
    const full = path.join(dir, e.name);

    if (e.isDirectory()) {
      yield* walkForStorageJson(full, depth + 1, insideStorage || e.name === "storage");
      continue;
    }
    if (e.isFile()) {
      if (insideStorage && e.name.endsWith(".json")) {
        let stat;
        try { stat = fs.statSync(full); } catch { yield { file: full, broken: true }; continue; }
        yield { file: full, mtimeMs: stat.mtimeMs, sizeBytes: stat.size, broken: false };
      }
      continue; // a real file outside storage/, or not .json — out of scope, not broken
    }
    if (e.isSymbolicLink()) {
      // Resolve once and treat as whichever kind it turns out to be — checked
      // BEFORE any insideStorage gating, deliberately: a dangling symlink here
      // might have been the very `storage` directory (or a path down to one)
      // this walk exists to find, so it must be reported regardless of
      // whether we've already stepped inside a `storage` dir by this point.
      // An earlier version of this function checked `insideStorage` first,
      // which let exactly this case (a dangling symlink encountered before
      // entering storage/) fall through and vanish silently — the same class
      // of bug claude-code.js's own docstring calls out and fixes.
      if (isDirFollowingSymlink(full, e)) {
        yield* walkForStorageJson(full, depth + 1, insideStorage || e.name === "storage");
        continue;
      }
      if (isFileFollowingSymlink(full, e)) {
        if (insideStorage && e.name.endsWith(".json")) {
          try {
            const stat = fs.statSync(full);
            yield { file: full, mtimeMs: stat.mtimeMs, sizeBytes: stat.size, broken: false };
          } catch { yield { file: full, broken: true }; }
        }
        continue;
      }
      yield { file: full, broken: true }; // dangling — resolves to neither a directory nor a file
      continue;
    }
    // Neither directory, file, nor symlink (a device, socket, etc.) — genuinely out of scope.
  }
}

/**
 * Yield { file, mtimeMs, sizeBytes, broken } for opencode.db (if present)
 * and every legacy JSON session/message/part file under any `storage`
 * directory anywhere below DATA_DIR. Purely a filesystem walk + stat, same
 * division of labour as cursor.js's files() — never opens the database, so
 * this works even without node:sqlite; only readLines() needs it.
 */
function* files() {
  let lst;
  try { lst = fs.lstatSync(DB_FILE); }
  catch { lst = null; }

  if (lst) {
    if (lst.isSymbolicLink()) {
      try {
        const st = fs.statSync(DB_FILE);
        if (st.isFile()) yield { file: DB_FILE, mtimeMs: st.mtimeMs, sizeBytes: st.size, broken: false };
        else yield { file: DB_FILE, broken: true };
      } catch {
        yield { file: DB_FILE, broken: true };
      }
    } else if (lst.isFile()) {
      yield { file: DB_FILE, mtimeMs: lst.mtimeMs, sizeBytes: lst.size, broken: false };
    }
  }

  yield* walkForStorageJson(DATA_DIR, 0, false);
}

/** Same string/Uint8Array decode as cursor.js's valueToText — see that file's docstring for why. */
function valueToText(value) {
  if (typeof value === "string") return value;
  if (value instanceof Uint8Array) return Buffer.from(value).toString("utf-8");
  return null;
}

/**
 * Read opencode.db generically: every user table in sqlite_master, every
 * column of every row, each non-null string/blob value becoming one scanned
 * line (see module docstring for why table/column names aren't hardcoded
 * beyond knowing `session` exists). Row-by-row with a periodic yield-and-
 * deadline-check exactly like cursor.js's readLines, for the same reason:
 * node:sqlite's DatabaseSync is fully synchronous, so this is the only
 * preemption point available without adding a dependency.
 */
async function readDbFile(file) {
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

  let tables;
  try {
    tables = db.prepare(
      "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' AND name NOT LIKE '\\_\\_drizzle%' ESCAPE '\\'"
    ).all().map((r) => r.name);
  } catch {
    try { db.close(); } catch { /* best-effort */ }
    return { lines: [], status: "failed", bytesRead: 0 };
  }

  const lines = [];
  let bytesRead = 0;
  const deadline = Date.now() + READ_TIMEOUT_MS;
  let timedOut = false;
  let sawError = false;

  for (const table of tables) {
    let rows;
    try {
      // Table names come from sqlite_master itself, not external input, but
      // they're still quoted defensively rather than trusted to be
      // bare-word-safe.
      rows = db.prepare(`SELECT * FROM "${table.replace(/"/g, '""')}"`).iterate();
    } catch {
      continue; // this table vanished or is a view/virtual table that doesn't support this — move on
    }

    let n = 0;
    try {
      for (const row of rows) {
        for (const key in row) {
          const text = valueToText(row[key]);
          if (text) { lines.push(text); bytesRead += Buffer.byteLength(text, "utf-8"); }
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

  try { db.close(); } catch { /* best-effort */ }

  if (sawError && lines.length === 0) return { lines: [], status: "failed", bytesRead };
  if (timedOut || sawError) return { lines, status: lines.length > 0 ? "partial" : "failed", bytesRead };
  return { lines, status: "complete", bytesRead };
}

/**
 * Read one legacy JSON session/message/part file as raw text lines —
 * identical streaming strategy to claude-code.js's readLines (a JSON file
 * on disk is still line-delimited text; the pattern-matcher works on raw
 * text regardless of what it parses as). Duplicated rather than shared,
 * per this project's convention.
 */
async function readJsonFile(file) {
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

async function readLines(file) {
  return file === DB_FILE ? readDbFile(file) : readJsonFile(file);
}

module.exports = { id, label, available, files, readLines };
