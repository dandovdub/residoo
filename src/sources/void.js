"use strict";

const fs = require("fs");
const path = require("path");
const os = require("os");

/**
 * Void's local chat thread history.
 *
 * Void (voideditor/void, Apache-2.0) is an open-source fork of VS Code, and
 * it inherited VS Code's own storage service wholesale — it does NOT add a
 * Cursor-style second custom table. Its AI chat is stored as ordinary VS
 * Code application state: one row in the standard `ItemTable` of the
 * standard per-profile `state.vscdb`, under a Void-specific key.
 *
 * VERIFICATION STATUS (read this before trusting anything below): unlike
 * pearai.js and trae.js, which lean on independent third-party tools, this
 * was confirmed by reading Void's own shipped TypeScript source directly
 * (voideditor/void@main, fetched verbatim from GitHub):
 *
 *   - `src/vs/workbench/contrib/void/browser/chatThreadService.ts` persists
 *     every chat thread in one call:
 *       this._storageService.store(THREAD_STORAGE_KEY, JSON.stringify(threads),
 *         StorageScope.APPLICATION, StorageTarget.USER);
 *     i.e. the *entire* set of chat threads, serialized as one JSON blob, at
 *     APPLICATION scope (VS Code's storage service backs APPLICATION-scope
 *     keys with the per-profile globalStorage `state.vscdb`'s `ItemTable` —
 *     the same mechanism, and the same physical file, Cursor's own
 *     non-custom-table state uses; see cursor.js's header for that
 *     mechanism generally).
 *   - `src/vs/workbench/contrib/void/common/storageKeys.ts` defines the
 *     literal key: `THREAD_STORAGE_KEY = 'void.chatThreadStorageII'` (plus
 *     `VOID_SETTINGS_STORAGE_KEY = 'void.settingsServiceStorageII'` and
 *     `OPT_OUT_KEY = 'void.app.optOutAll'`, both also APPLICATION-scoped by
 *     the same mechanism).
 *
 * This is direct confirmation of the actual mechanism, not a third party's
 * inference — but it does NOT by itself confirm the per-OS Application
 * Support-style folder NAME Void's Electron shell actually writes to on a
 * real machine: no independent blog post, forum thread, or community tool
 * naming that exact path (e.g. `~/Library/Application Support/Void`
 * specifically) was found in this source's research. That folder name is
 * derived instead from `product.json`'s `nameShort`/`nameLong`, both
 * `"Void"` (fetched directly from voideditor/void's own product.json), via
 * the same VS Code-family convention already relied on for Cursor in this
 * project (`~/Library/Application Support/Cursor`, nameShort `"Cursor"`)
 * and independently cross-checked against VSCodium, whose product.json sets
 * nameShort to `"VSCodium"` and which is independently documented as
 * writing to `~/Library/Application Support/VSCodium` — i.e. this is a
 * consistent, multi-example VS Code-fork naming rule, not a Void-specific
 * guess, applied to a Void-specific value read from Void's own source.
 *
 * Net effect: HIGH confidence in the storage mechanism and key (read
 * straight from shipped source), MODERATE-plus confidence in the exact
 * folder name (derived from a well-established, cross-checked convention
 * rather than independently witnessed for Void by a third party). Neither
 * substitutes for a real install: Void is not installed on the machine this
 * was built on (checked: not in /Applications, not in ~/Library/Application
 * Support, no mdfind hits), so this has NOT been checked against a real
 * Void install. If you have Void installed, running `residoo scan` and
 * confirming `sourcesScanned`/`filesScanned` for "void" look right against
 * what you know is on disk is the single most useful way to firm this up.
 *
 * As with Trae (see trae.js), no key-name filtering is done here even
 * though the exact chat-thread key IS known (`void.chatThreadStorageII`) —
 * every row in `ItemTable` is turned into one scanned line regardless of
 * key, matching cursor.js's own stated reasoning: key names are exactly the
 * kind of detail known to drift across versions, and scan.js already
 * tolerates raw, unfiltered text. `workspaceStorage/<hash>/state.vscdb` is
 * included alongside `globalStorage` on the same general-VS-Code-architecture
 * basis cursor.js and trae.js both use, even though the specific thread
 * storage read above is APPLICATION-scoped (i.e. global, not per-workspace)
 * — other state (Void's or any installed extension's) may still legitimately
 * live at workspace scope, and this project's existing sources don't
 * cherry-pick which storage tier might matter.
 */
function voidUserDir() {
  const home = os.homedir();
  if (process.platform === "darwin") {
    return path.join(home, "Library", "Application Support", "Void", "User");
  }
  if (process.platform === "win32") {
    const appData = process.env.APPDATA || path.join(home, "AppData", "Roaming");
    return path.join(appData, "Void", "User");
  }
  const configHome = process.env.XDG_CONFIG_HOME || path.join(home, ".config");
  return path.join(configHome, "Void", "User");
}

const USER_DIR = voidUserDir();
const GLOBAL_STORAGE_DB = path.join(USER_DIR, "globalStorage", "state.vscdb");
const WORKSPACE_STORAGE_DIR = path.join(USER_DIR, "workspaceStorage");

// Same lazy-require pattern as cursor.js and trae.js, for the same reason —
// see cursor.js's docstring for the full explanation.
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

function id() { return "void"; }
function label() { return "Void"; }

function userDirExists() {
  try { return fs.statSync(USER_DIR).isDirectory(); } catch { return false; }
}

function available() {
  return userDirExists() && Boolean(getDatabaseSync());
}

/**
 * Same optional, additive export as cursor.js's unavailableReason().
 */
function unavailableReason() {
  if (!userDirExists()) return null;
  if (getDatabaseSync()) return null;
  return `Void detected but not scanned — ${NODE_SQLITE_REQUIREMENT}`;
}

/**
 * Same defensive symlink-following pattern as cursor.js's
 * isDirFollowingSymlink — duplicated rather than imported, matching this
 * project's "small, self-contained file" convention.
 */
function isDirFollowingSymlink(fullPath, dirent) {
  if (dirent.isDirectory()) return true;
  if (!dirent.isSymbolicLink()) return false;
  try { return fs.statSync(fullPath).isDirectory(); } catch { return false; }
}

/**
 * Resolve one candidate `state.vscdb` path into zero or one files() entries.
 * Identical logic and identical broken-vs-absent convention to cursor.js's
 * statIfPresent().
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

/**
 * Yield { file, mtimeMs, sizeBytes, broken } for every state.vscdb found —
 * one for globalStorage, one per workspaceStorage/<hash> directory.
 */
function* files() {
  yield* statIfPresent(GLOBAL_STORAGE_DB);

  let workspaceDirs;
  try { workspaceDirs = fs.readdirSync(WORKSPACE_STORAGE_DIR, { withFileTypes: true }); }
  catch { return; }

  for (const ws of workspaceDirs) {
    const wsDir = path.join(WORKSPACE_STORAGE_DIR, ws.name);
    if (!isDirFollowingSymlink(wsDir, ws)) {
      if (ws.isSymbolicLink()) yield { file: wsDir, broken: true };
      continue;
    }
    yield* statIfPresent(path.join(wsDir, "state.vscdb"));
  }
}

// No Void-specific large-file data point exists (no real install to measure
// against) — carried over unchanged from cursor.js as a generous,
// conservative backstop, not a figure backed by an observed real file here.
const MAX_DB_BYTES = 512 * 1024 * 1024;
const READ_TIMEOUT_MS = 60_000;
const BUSY_TIMEOUT_MS = 5_000;
const YIELD_EVERY_N_ROWS = 500;

/**
 * Same value-decoding rule as cursor.js's valueToText().
 */
function valueToText(value) {
  if (typeof value === "string") return value;
  if (value instanceof Uint8Array) return Buffer.from(value).toString("utf-8");
  return null;
}

/**
 * Read one state.vscdb as an array of raw text "lines" — one per row's
 * decoded value from `ItemTable`. Same synchronous-native-call constraint,
 * same cooperative-yield-plus-deadline timeout approach, and same status
 * vocabulary as cursor.js's readLines() — see that file's docstring for the
 * full reasoning, which applies unchanged here.
 *
 * Only `ItemTable` is queried — no second, Void-specific table exists per
 * this source's research (see module docstring: Void's chat persistence
 * goes through the plain IStorageService, not a custom SQLite table the way
 * Cursor's `cursorDiskKV` is).
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

  const lines = [];
  let bytesRead = 0;
  const deadline = Date.now() + READ_TIMEOUT_MS;
  let timedOut = false;
  let sawError = false;
  let foundAnyTable = false;

  for (const table of ["ItemTable"]) {
    let rows;
    try {
      rows = db.prepare(`SELECT key, value FROM ${table}`).iterate();
    } catch {
      continue;
    }
    foundAnyTable = true;

    let n = 0;
    try {
      for (const row of rows) {
        const text = valueToText(row.value);
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
