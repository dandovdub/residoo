"use strict";

const fs = require("fs");
const { createInterface } = require("readline/promises");
const path = require("path");
const os = require("os");

/**
 * Kilo Code (VS Code extension, originally a Roo Code fork) session history.
 *
 * VERIFICATION STATUS AND WHY THIS FILE IS UNUSUAL: the brief for this
 * cluster assumed Kilo Code's local storage would be "very likely
 * near-identical" to Cline/Roo Code's, since it started as a Roo Code fork.
 * That assumption turned out to be WRONG for the currently-shipped
 * extension — Kilo Code has since been rebuilt on top of an embedded fork of
 * OpenCode (sst/opencode; the vendored copy lives at packages/opencode in
 * Kilo Code's own monorepo) and now persists sessions in a SQLite database
 * outside VS Code's storage model entirely, not as per-task JSON files
 * inside globalStorage. The OLD per-task-JSON-file layout still exists, but
 * only as a migration SOURCE the current extension reads from and imports
 * out of — not where new data is written. Both are handled below, because
 * both are real: an install that hasn't been migrated yet (or was migrated
 * without deleting the originals — nothing in the migration code path found
 * during this source's research deletes the old files) can have real
 * content in either place, or both.
 *
 * Sourced directly from Kilo Code's own current source and docs on GitHub
 * (Kilo-Org/kilocode) during this source's research:
 *   - packages/kilo-vscode/package.json — `"name": "kilo-code"`,
 *     `"publisher": "kilocode"`, confirming the legacy on-disk globalStorage
 *     folder id `kilocode.kilo-code` is still current, unchanged by the
 *     OpenCode rewrite.
 *   - packages/kilo-docs/pages/code-with-ai/agents/session-history.md — this
 *     is Kilo Code's own *published, official* documentation, and states the
 *     new database's default path per OS verbatim in a table: macOS/Linux
 *     `~/.local/share/kilo/kilo.db`, Windows
 *     `%USERPROFILE%\.local\share\kilo\kilo.db` (yes, also a dotfile path on
 *     Windows — this is confirmed as real, current, and NOT a typo by an
 *     open upstream OpenCode issue, sst/opencode#8235, describing the exact
 *     same behavior: "Config and Data directories follow the Linux XDG
 *     standard even on windows"). The same doc gives the `session`,
 *     `message`, `part` table/column names used below (e.g. its own example
 *     query joins them and reads `json_extract(p.data, '$.text')`).
 *   - packages/core/src/global.ts — the actual construction of that path:
 *     `app = "kilo"`; `data = path.join(xdgData, app)`, where `xdgData` comes
 *     from the `xdg-basedir` npm package. That package (confirmed by reading
 *     ITS source directly) does NOT special-case macOS or Windows the way
 *     most XDG-inspired Node tools do — every platform falls back to
 *     `path.join(os.homedir(), ".local", "share")` when `$XDG_DATA_HOME`
 *     isn't set. This is exactly what the official doc above independently
 *     confirms, and exactly the kind of easy-to-get-wrong-by-assumption
 *     detail this project's verification rule exists for.
 *   - packages/opencode/src/storage/db.ts — `getChannelPath()`: the database
 *     filename is `kilo.db` for the "latest"/"beta"/"prod" install channels
 *     (what a normal Marketplace install uses), or `kilo-<channel>.db` for
 *     any other channel (nightly/dev builds), with a fallback check for a
 *     same-named `opencode-<channel>.db` left over from before the
 *     product's own rename. `db.node.ts` confirms the VS Code extension
 *     itself opens this via `node:sqlite`'s `DatabaseSync` — the same
 *     built-in module cursor.js already relies on, not a new dependency.
 *   - packages/core/src/session/sql.ts — the Drizzle table definitions used
 *     to build the table list below.
 *   - Kilo-Org/kilocode-legacy (an archived, but real, sibling repo Kilo-Org
 *     split the pre-rewrite extension into) — its own
 *     docs/legacy-ides/getting-started/file-locations.md documents the
 *     legacy globalStorage path per OS, and its
 *     src/shared/globalFileNames.ts (real source, not a guess) gives the
 *     legacy per-task filenames, which match Roo Code's naming exactly (Kilo
 *     Code's legacy extension was, at the source level, a Roo Code fork).
 *
 * What this could NOT be checked against: a real Kilo Code install on the
 * machine this source was built on — VS Code itself isn't installed there.
 * Despite the unusually deep source/docs corroboration above, treat findings
 * from this source accordingly until someone with Kilo Code actually
 * installed confirms it against real data (in particular: confirm which of
 * the two formats below actually has content for a given real install, and
 * whether `kilo db path` on that machine agrees with the default path this
 * source assumes).
 *
 * ---- Format 1: the new SQLite database (current, primary) ----
 *   <XDG data dir>/kilo/kilo.db   (or kilo-<channel>.db / opencode-<channel>.db)
 * Tables scanned: session, message, part, session_message, session_input,
 * todo — the ones that can hold actual conversation/task text. Deliberately
 * NOT scanned: account / account_state / control_account (Kilo's own stored
 * provider credentials — a different concern than a transcript source, and
 * out of scope the same way claude-code.js never reads Claude Code's own
 * settings/credentials files outside ~/.claude/projects), project,
 * session_share, workspace (control-plane/identity records, not transcript
 * content). This mirrors how claude-code.js scopes itself to the transcripts
 * directory rather than all of ~/.claude.
 *
 * ---- Format 2: legacy per-task JSON files (migration source only) ----
 *   <VS Code User dir>/globalStorage/kilocode.kilo-code/tasks/<taskId>/
 *     api_conversation_history.json / ui_messages.json / task_metadata.json
 * Same VS Code User dir scope (standard + Insiders only, see cline.js/
 * roo-code.js for the same named limitation) and the same "glob every *.json
 * in the task dir rather than allow-list filenames" reasoning as those two
 * sibling sources.
 */
const LEGACY_EXT_ID = "kilocode.kilo-code";
const DB_NAME_RE = /^(kilo|opencode)(-[A-Za-z0-9._-]+)?\.db$/;

function vscodeUserDirs() {
  const home = os.homedir();
  const variants = ["Code", "Code - Insiders"];
  if (process.platform === "darwin") {
    return variants.map((v) => path.join(home, "Library", "Application Support", v, "User"));
  }
  if (process.platform === "win32") {
    const appData = process.env.APPDATA || path.join(home, "AppData", "Roaming");
    return variants.map((v) => path.join(appData, v, "User"));
  }
  const configHome = process.env.XDG_CONFIG_HOME || path.join(home, ".config");
  return variants.map((v) => path.join(configHome, v, "User"));
}

function legacyTasksDirs() {
  return vscodeUserDirs().map((userDir) => path.join(userDir, "globalStorage", LEGACY_EXT_ID, "tasks"));
}

/**
 * `xdg-basedir`'s own behavior (verified by reading its source): every
 * platform, not just Linux, falls back to `~/.local/share` when
 * `$XDG_DATA_HOME` isn't set — there is no macOS/Windows special case. See
 * the docstring above for the corroborating official Kilo Code doc and
 * upstream OpenCode issue.
 */
function kiloDataDir() {
  const home = os.homedir();
  const xdgDataHome = process.env.XDG_DATA_HOME || path.join(home, ".local", "share");
  return path.join(xdgDataHome, "kilo");
}

// Bounds for the legacy JSON files — same rationale/values as claude-code.js.
const MAX_BYTES = 2 * 1024 * 1024 * 1024; // 2GB
const READ_TIMEOUT_MS = 60_000;

// Bounds for the SQLite database — same rationale/values as cursor.js: not
// backed by a real kilo.db this tool was tested against, only a generous
// backstop.
const MAX_DB_BYTES = 512 * 1024 * 1024;
const DB_READ_TIMEOUT_MS = 60_000;
const BUSY_TIMEOUT_MS = 5_000;
const YIELD_EVERY_N_ROWS = 500;
const SESSION_TABLES = ["session", "message", "part", "session_message", "session_input", "todo"];

/**
 * node:sqlite, loaded lazily — same reasoning as cursor.js: it's a Node core
 * module (no package.json/lockfile footprint, satisfies CONTRIBUTING.md rule
 * 1), but require()-ing it eagerly would print Node's ExperimentalWarning to
 * stderr on every `residoo scan` for every user, even the large majority who
 * have never touched Kilo Code. Deferred until there is already a concrete
 * reason to make the require (Kilo's own data directory actually exists).
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

function id() { return "kilo-code"; }
function label() { return "Kilo Code"; }

function legacyDirExists() {
  return legacyTasksDirs().some((dir) => {
    try { return fs.statSync(dir).isDirectory(); } catch { return false; }
  });
}

function dbCandidates() {
  const dataDir = kiloDataDir();
  let entries;
  try { entries = fs.readdirSync(dataDir, { withFileTypes: true }); }
  catch { return []; }
  return entries
    .filter((e) => (e.isFile() || e.isSymbolicLink()) && DB_NAME_RE.test(e.name))
    .map((e) => path.join(dataDir, e.name));
}

/**
 * Available whenever there is at least one thing this source could attempt
 * to scan. The legacy JSON path needs nothing beyond plain fs access; the
 * new SQLite path additionally needs node:sqlite to be loadable. This is
 * deliberately looser than cursor.js's available() (which is all-or-nothing
 * because Cursor's ENTIRE content is SQLite-only) — here the legacy format
 * alone is real, scannable content even when node:sqlite is unavailable.
 */
function available() {
  if (legacyDirExists()) return true;
  const candidates = dbCandidates();
  return candidates.length > 0 && Boolean(getDatabaseSync());
}

/**
 * Same purpose as cursor.js's unavailableReason(): the one case worth
 * calling out by name is "a kilo.db was found but this Node runtime can't
 * open it and there's no legacy data either" — otherwise this source would
 * silently vanish from "Sources checked," reading as "Kilo Code isn't
 * installed," which would be false.
 */
function unavailableReason() {
  if (legacyDirExists()) return null; // available() already covers this source correctly
  const candidates = dbCandidates();
  if (candidates.length === 0) return null; // ordinary "Kilo Code just isn't here" case
  if (getDatabaseSync()) return null;
  return `Kilo Code detected but not scanned — ${NODE_SQLITE_REQUIREMENT}`;
}

/**
 * Same defensive symlink-following pattern as claude-code.js's
 * isDirFollowingSymlink/isFileFollowingSymlink — see that file's docstring
 * for the full reasoning. Duplicated rather than imported: each source in
 * this project is meant to be a small, self-contained file a reviewer can
 * audit on its own (see CONTRIBUTING.md and cursor.js's own note on this).
 */
function isKindFollowingSymlink(fullPath, dirent, checkFn) {
  if (checkFn(dirent)) return true;
  if (!dirent.isSymbolicLink()) return false;
  try { return checkFn(fs.statSync(fullPath)); } catch { return false; }
}
const isDirFollowingSymlink = (p, d) => isKindFollowingSymlink(p, d, (x) => x.isDirectory());
const isFileFollowingSymlink = (p, d) => isKindFollowingSymlink(p, d, (x) => x.isFile());

function* legacyFiles() {
  for (const tasksDir of legacyTasksDirs()) {
    let taskEntries;
    try { taskEntries = fs.readdirSync(tasksDir, { withFileTypes: true }); }
    catch { continue; } // this VS Code variant/profile has no legacy Kilo Code tasks dir — normal, not broken

    for (const taskEntry of taskEntries) {
      const taskDir = path.join(tasksDir, taskEntry.name);
      if (!isDirFollowingSymlink(taskDir, taskEntry)) {
        if (taskEntry.isSymbolicLink()) yield { file: taskDir, broken: true };
        continue;
      }

      let fileEntries;
      try { fileEntries = fs.readdirSync(taskDir, { withFileTypes: true }); }
      catch { yield { file: taskDir, broken: true }; continue; }

      for (const e of fileEntries) {
        if (!e.name.endsWith(".json")) continue;
        const file = path.join(taskDir, e.name);
        if (!isFileFollowingSymlink(file, e)) {
          if (e.isSymbolicLink()) yield { file, broken: true };
          continue;
        }
        let stat;
        try { stat = fs.statSync(file); } catch { yield { file, broken: true }; continue; }
        yield { file, mtimeMs: stat.mtimeMs, sizeBytes: stat.size, broken: false };
      }
    }
  }
}

/**
 * Yield the kilo.db candidate(s) directly inside the Kilo data directory.
 * Uses lstat directly (not a Dirent) because dbCandidates() already resolved
 * the directory listing; this just re-stats each already-known path right
 * before scan-time, same TOCTOU-narrowing rationale cursor.js's
 * statIfPresent gives for globalStorage/state.vscdb.
 */
function* dbFiles() {
  for (const dbPath of dbCandidates()) {
    let lst;
    try { lst = fs.lstatSync(dbPath); }
    catch { continue; } // vanished between the directory listing above and now

    if (lst.isSymbolicLink()) {
      try {
        const st = fs.statSync(dbPath);
        if (!st.isFile()) { yield { file: dbPath, broken: true }; continue; }
        yield { file: dbPath, mtimeMs: st.mtimeMs, sizeBytes: st.size, broken: false };
      } catch {
        yield { file: dbPath, broken: true }; // dangling symlink
      }
      continue;
    }

    if (!lst.isFile()) continue;
    yield { file: dbPath, mtimeMs: lst.mtimeMs, sizeBytes: lst.size, broken: false };
  }
}

/**
 * Yield { file, mtimeMs, sizeBytes, broken } for every legacy per-task *.json
 * file AND every kilo*.db candidate. readLines() below tells the two apart
 * by file extension. broken:true marks an entry that looked like it should
 * resolve (chiefly a dangling symlink) but didn't — never silently skipped,
 * same convention as every other source in this project.
 */
function* files() {
  yield* legacyFiles();
  yield* dbFiles();
}

/**
 * Read one legacy per-task JSON file as an array of raw text lines. Kilo
 * Code's legacy extension (a Roo Code fork at the source level) writes these
 * with real indentation/newlines, same as roo-code.js's readLines() — see
 * that file's docstring for the full rationale; this is the same
 * implementation.
 */
async function readJsonLines(file) {
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

/**
 * Read one kilo.db as an array of raw text "lines" — one per row, across
 * SESSION_TABLES. Same synchronous-SQLite/no-preemptive-timeout situation
 * cursor.js documents at length for state.vscdb: node:sqlite's
 * DatabaseSync/StatementSync are fully synchronous, so this iterates
 * row-by-row via StatementSync#iterate() and yields to the event loop (plus
 * checks a wall-clock deadline) every YIELD_EVERY_N_ROWS rows.
 *
 * Each row becomes `JSON.stringify(row)` — the whole row, every column, not
 * just the JSON-encoded `data` column most of these tables have — because
 * unlike cursor.js's single opaque `value` column, several columns here
 * (session.title, session.directory, todo.content, ...) can independently
 * hold real text with no single column to special-case. This is the same
 * "turn each row into one line via JSON.stringify" approach this project's
 * own adapter contract describes for non-line-delimited sources. The one
 * named cost: JSON.stringify re-escapes the already-JSON-encoded `data`
 * column's own quotes/backslashes as it nests that string inside the outer
 * object — harmless for the vendor-prefixed literal token shapes this
 * project's PATTERNS match (e.g. `sk-ant-…`, `AKIA…`), since none of them
 * depend on quote-adjacency, but worth naming rather than leaving implicit.
 */
async function readDbLines(file) {
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
    // Deleted between files() and this call, a corrupt/non-SQLite file at
    // this path, or Kilo Code holding a lock this readonly open can't get
    // past within BUSY_TIMEOUT_MS — genuinely "could not read this."
    return { lines: [], status: "failed", bytesRead: 0 };
  }

  const lines = [];
  let bytesRead = 0;
  const deadline = Date.now() + DB_READ_TIMEOUT_MS;
  let timedOut = false;
  let sawError = false;
  let foundAnyTable = false;

  for (const table of SESSION_TABLES) {
    let rows;
    try {
      rows = db.prepare(`SELECT * FROM ${table}`).iterate();
    } catch {
      // This particular table genuinely doesn't exist in this file's schema
      // (older/newer Kilo Code version) — not a read failure for the other
      // tables, so just move on rather than aborting the whole file.
      continue;
    }
    foundAnyTable = true;

    let n = 0;
    try {
      for (const row of rows) {
        let text;
        try { text = JSON.stringify(row); } catch { text = null; }
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
      // same way claude-code.js/cursor.js keep a partial read.
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

async function readLines(file) {
  return DB_NAME_RE.test(path.basename(file)) ? readDbLines(file) : readJsonLines(file);
}

module.exports = { id, label, available, unavailableReason, files, readLines };
