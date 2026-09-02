"use strict";

const fs = require("fs");
const { createInterface } = require("readline/promises");
const path = require("path");
const os = require("os");

/**
 * Goose (github.com/aaif-goose/goose — Block/Square's open-source AI agent,
 * transferred to the Linux Foundation's Agentic AI Foundation in April 2026;
 * same project, same code, `github.com/block/goose` now redirects there).
 *
 * VERIFICATION STATUS: NOT installed on the machine this adapter was built on
 * (checked: no `goose` on PATH, no `~/.local/share/goose`, no
 * `~/Library/Application Support/Block/goose`, no `~/.config/goose`, no
 * Homebrew cask/formula installed — only the unrelated `mongoose` library and
 * the Go database-migration tool of the same name turned up). Ships anyway
 * per CONTRIBUTING.md rule 3, on unusually strong grounds for an "unverified"
 * source: every claim below was confirmed against goose's OWN real source
 * code on GitHub — read directly, not inferred from a description of it —
 * cross-checked against goose's own published docs and, for one genuinely
 * surprising point, the actual source of the third-party crate it delegates
 * the decision to.
 *
 * Storage location — confirmed directly from source
 * (`crates/goose/src/config/paths.rs`, `crates/goose/src/session/session_manager.rs`,
 * both fetched from the `main` branch at commit-current state, schema_version 16):
 *
 *   - `Paths::data_dir()`: if the `GOOSE_PATH_ROOT` env var is set to an
 *     ABSOLUTE path (validated — a relative value is ignored), the base is
 *     `$GOOSE_PATH_ROOT/data`. Otherwise it calls
 *     `etcetera::choose_app_strategy(AppStrategyArgs { top_level_domain:
 *     "Block", author: "Block", app_name: "goose" })` and returns that
 *     strategy's `data_dir()`.
 *   - The surprising point, resolved by reading the `etcetera` crate's own
 *     source (pinned to exactly 0.11.0 in goose's real `Cargo.lock`, fetched
 *     and read directly — `src/app_strategy.rs`'s `cfg_if!` block and
 *     `xdg.rs`): `choose_app_strategy` (unlike `choose_native_strategy`,
 *     which goose does NOT call) resolves to the **Xdg** strategy on macOS
 *     — not the Apple/`~/Library/Application Support` convention most macOS
 *     apps use, matching a documented, deliberate choice ("This is the
 *     convention used by most CLI applications") — and the Xdg strategy's
 *     `data_dir()` ignores `author`/`top_level_domain` entirely, using only
 *     `app_name`. So on BOTH macOS and Linux this resolves to
 *     `$XDG_DATA_HOME/goose` or `~/.local/share/goose` if that's unset — the
 *     `top_level_domain`/`author: "Block"` fields passed above are, per this
 *     reading, dead for the current default path (a maintainer comment right
 *     next to that call, kept for backwards compatibility with older
 *     installs, cites `~/Library/Application Support/Block/goose/` — that is
 *     the OLDER, pre-etcetera-migration path, not what today's code
 *     resolves to; the comment is about not orphaning those old installs,
 *     not about where new ones land). This macOS-follows-Linux choice is
 *     independently confirmed by goose's own published docs (goose-docs.ai's
 *     logging guide states the session DB path as `~/.local/share/goose/sessions/sessions.db`
 *     for "macOS and Linux" as one line, and separately
 *     `%APPDATA%\Block\goose\data\sessions\sessions.db` for Windows) — which
 *     also matches the `etcetera` Windows strategy's own documented formula
 *     (`AppData/Roaming/<author>/<app_name>/data`, author defaulting to
 *     nothing special here since it's passed explicitly as `"Block"`) read
 *     directly from `windows.rs`.
 *   - `SessionStorage::new()` joins `data_dir` with the literal constants
 *     `SESSIONS_FOLDER = "sessions"` then, for the DB, `DB_NAME = "sessions.db"`.
 *
 * Two formats live in that SAME `sessions/` directory, confirmed directly
 * from source, and this adapter reads both:
 *
 *   1. `sessions.db` — the current format (schema_version 16 as of this
 *      research), a plain SQLite file opened via `sqlx`/`SqliteConnectOptions`
 *      (WAL mode, no encryption). Tables confirmed directly from the actual
 *      `CREATE TABLE` statements in `session_manager.rs`: `sessions`
 *      (metadata — name, working_dir, recipe_json, model_config_json, ...),
 *      `messages` (session_id, role, `content_json` — the actual message
 *      content, one row per message), `usage_ledger` (token/cost accounting,
 *      no message content), and, added by a later migration, `threads` /
 *      `thread_messages` (a second, parallel message-content table pair with
 *      its own `content_json` column — confirmed from the migration-9 SQL
 *      block). Given the schema has ALREADY gone through 16 versions of
 *      `ALTER TABLE`/new-table migrations in this one file, and per-table
 *      column sets keep changing, this source does not hardcode a
 *      table/column allowlist — same reasoning opencode.js's own docstring
 *      gives for its generic scan, and the exact same tradeoff: reads every
 *      user table generically (see readDbFile() below), so a future
 *      migration adding yet another `..._json` content column can't silently
 *      stop being scanned the way a hardcoded list would.
 *   2. `*.jsonl` — the legacy pre-1.10.0 format, confirmed directly from
 *      `crates/goose/src/session/legacy.rs`: `list_sessions()` does a flat,
 *      non-recursive `fs::read_dir` over the SAME `sessions/` directory for
 *      `.jsonl` entries, and `load_session()` confirms the shape — the FIRST
 *      line is one JSON object (session metadata), every subsequent line is
 *      one JSON message object — genuine JSONL, no re-serialization needed
 *      to turn it into scannable lines. Per goose's own docs (see above,
 *      also independently corroborated by ccusage.com's own goose-integration
 *      guide), upgrading to v1.10.0+ auto-imports these into `sessions.db`
 *      but leaves the original `.jsonl` files sitting on disk, unmanaged —
 *      real, orphaned, still-scannable content on any machine that has ever
 *      upgraded across that boundary, the same "two formats really do
 *      coexist on one real machine" situation opencode.js's own docstring
 *      describes for its own legacy JSON files.
 *
 * The Goose Desktop app (`ui/desktop/`, Electron/TS) was not traced all the
 * way through its IPC/HTTP layer, but `ui/desktop/src/sessions.ts`'s own
 * `Session` type uses the exact same field names as the Rust `Session` struct
 * above (`user_set_name`, `recipe`, `name`, ...) — strong circumstantial
 * evidence, not a full trace, that it talks to the same local `goosed`
 * server backed by the same `SessionManager`/`sessions.db`, not a separate
 * storage format of its own.
 *
 * Sources consulted: aaif-goose/goose source on GitHub (`crates/goose/src/
 * config/paths.rs`, `crates/goose/src/session/session_manager.rs`,
 * `crates/goose/src/session/legacy.rs`, `Cargo.lock`, all fetched from
 * `main`); the `etcetera` crate's own source at the exact pinned version
 * (lunacookies/etcetera tag v0.11.0 — `src/app_strategy.rs`, `src/app_strategy/
 * xdg.rs`, `src/app_strategy/windows.rs`); goose's own published docs
 * (goose-docs.ai/docs/guides/logs/); ccusage.com's goose integration guide
 * (an independent tool that reads this same sessions.db in production,
 * corroborating table/column names from the consumer side); DeepWiki's
 * goose session-management summary (schema_version terminology cross-check).
 */
function goosePathRoot() {
  const v = process.env.GOOSE_PATH_ROOT;
  return v && path.isAbsolute(v) ? v : null;
}

function xdgDataDir(appName) {
  const home = os.homedir();
  const dataHome = process.env.XDG_DATA_HOME || path.join(home, ".local", "share");
  return path.join(dataHome, appName);
}

function windowsDataDir(author, appName) {
  const home = os.homedir();
  const base = process.env.APPDATA || path.join(home, "AppData", "Roaming");
  return path.join(base, author, appName, "data");
}

function gooseDataDir() {
  const root = goosePathRoot();
  if (root) return path.join(root, "data");
  if (process.platform === "win32") return windowsDataDir("Block", "goose");
  // macOS AND Linux both resolve through etcetera's Xdg strategy here — see
  // the module docstring for why macOS does NOT get the `~/Library/
  // Application Support` treatment most native macOS apps get.
  return xdgDataDir("goose");
}

const SESSIONS_DIR = path.join(gooseDataDir(), "sessions");
const DB_FILE = path.join(SESSIONS_DIR, "sessions.db");

const MAX_BYTES = 2 * 1024 * 1024 * 1024; // 2GB — same reasoning as claude-code.js
const READ_TIMEOUT_MS = 60_000;

// Same backstop-not-evidence caveat as cursor.js's MAX_DB_BYTES: no real
// sessions.db has been observed during this research to size this against.
const MAX_DB_BYTES = 512 * 1024 * 1024;
const BUSY_TIMEOUT_MS = 5_000;
const YIELD_EVERY_N_ROWS = 500;

function id() { return "goose"; }
function label() { return "Goose"; }

function sessionsDirExists() {
  try { return fs.statSync(SESSIONS_DIR).isDirectory(); } catch { return false; }
}

/**
 * Unlike cursor.js, availability does NOT depend on node:sqlite being
 * present: the legacy `*.jsonl` format (see module docstring) is plain text,
 * readable with zero special modules. Gating the whole source on sqlite
 * would silently drop real, scannable content for exactly the
 * upgraded-past-1.10.0-with-orphaned-jsonl case goose's own docs describe, or
 * for a Node runtime too old for node:sqlite. sqlite is required only for
 * sessions.db specifically — see readDbFile()'s own "failed" return when
 * it's unavailable, surfaced per-file rather than by hiding the whole
 * source. Mirrors opencode.js's identical reasoning for its own two-format
 * (sqlite + legacy plain-text) source.
 */
function available() {
  return sessionsDirExists();
}

/**
 * Lazily loaded exactly like cursor.js's/opencode.js's getDatabaseSync() —
 * see cursor.js's docstring for the full reasoning (avoid the one-time
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
function isFileFollowingSymlink(fullPath, dirent) {
  if (dirent.isFile()) return true;
  if (!dirent.isSymbolicLink()) return false;
  try { return fs.statSync(fullPath).isFile(); } catch { return false; }
}

/**
 * Yield { file, mtimeMs, sizeBytes, broken } for sessions.db (if present) and
 * every legacy `*.jsonl` session file — both live directly inside
 * SESSIONS_DIR, flat and non-recursive, matching `legacy.rs`'s own
 * `fs::read_dir` (no subfolder nesting in this format). Purely a filesystem
 * walk + stat, same division of labour as cursor.js's/opencode.js's files():
 * never opens the database, so this works even without node:sqlite; only
 * readLines() needs it.
 */
function* files() {
  let entries;
  try { entries = fs.readdirSync(SESSIONS_DIR, { withFileTypes: true }); }
  catch { return; } // no sessions dir at all — available() already said so, but stay defensive

  for (const e of entries) {
    const isDb = e.name === "sessions.db";
    const isLegacy = e.name.endsWith(".jsonl");
    if (!isDb && !isLegacy) continue;

    const file = path.join(SESSIONS_DIR, e.name);
    if (!isFileFollowingSymlink(file, e)) {
      if (e.isSymbolicLink()) yield { file, broken: true };
      continue;
    }
    let stat;
    try { stat = fs.statSync(file); } catch { yield { file, broken: true }; continue; }
    yield { file, mtimeMs: stat.mtimeMs, sizeBytes: stat.size, broken: false };
  }
}

/** Same string/Uint8Array decode as cursor.js's/opencode.js's valueToText — see cursor.js's docstring for why. */
function valueToText(value) {
  if (typeof value === "string") return value;
  if (value instanceof Uint8Array) return Buffer.from(value).toString("utf-8");
  return null;
}

/**
 * Read sessions.db generically: every user table in sqlite_master, every
 * column of every row, each non-null string/blob value becoming one scanned
 * line (see module docstring for why table/column names beyond knowing
 * `sessions`/`messages`/`usage_ledger`/`threads`/`thread_messages` exist
 * aren't hardcoded further). Row-by-row with a periodic yield-and-deadline
 * check, identical strategy to cursor.js's/opencode.js's readLines/readDbFile
 * for the same reason: node:sqlite's DatabaseSync is fully synchronous, so
 * this is the only preemption point available without adding a dependency.
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
    // Covers: deleted between files() and this call, a corrupt/non-SQLite
    // file, or goose holding a lock this readonly open can't get past within
    // BUSY_TIMEOUT_MS. All three are "could not read this," not "read it,
    // found nothing" — status "failed" keeps the report honest either way.
    return { lines: [], status: "failed", bytesRead: 0 };
  }

  let tables;
  try {
    tables = db.prepare(
      "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
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
      // still quoted defensively rather than trusted to be bare-word-safe.
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
      // A row iterator can itself throw partway (e.g. a corrupted page hit
      // mid-scan) — whatever WAS read before that is real content, kept the
      // same way claude-code.js keeps a partial read rather than discarding it.
      sawError = true;
    }
    if (timedOut) break;
  }

  try { db.close(); } catch { /* best-effort close; nothing left to do if this fails */ }

  if (sawError && lines.length === 0) return { lines: [], status: "failed", bytesRead };
  if (timedOut || sawError) return { lines, status: lines.length > 0 ? "partial" : "failed", bytesRead };
  return { lines, status: "complete", bytesRead };
}

/**
 * Read one legacy `*.jsonl` session file as raw text lines — genuinely
 * line-delimited already (see module docstring), so this is the same plain
 * streamed read as claude-code.js's readLines(), no reformatting needed.
 */
async function readJsonlFile(file) {
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
  return file === DB_FILE ? readDbFile(file) : readJsonlFile(file);
}

module.exports = { id, label, available, files, readLines };
