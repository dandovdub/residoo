"use strict";

const fs = require("fs");
const path = require("path");
const os = require("os");

/**
 * Trae's local chat/composer history.
 *
 * Trae (ByteDance) is a fork of Code OSS (VS Code's open-source base), and
 * it inherited VS Code's per-profile SQLite storage approach wholesale: a
 * `state.vscdb` file containing a table called `ItemTable`, both under
 * `globalStorage` (one per profile) and per-project under
 * `workspaceStorage/<hash>` — same physical shape as Cursor's, see
 * cursor.js's own header for the general mechanism. Unlike Cursor, nothing
 * found in this source's research indicates Trae adds a second, custom
 * table alongside `ItemTable` — its AI chat/agent content instead appears to
 * live inside `ItemTable` itself, under specially-prefixed keys (see below).
 *
 * VERIFICATION STATUS (read this before trusting anything below): this is
 * corroborated by two independent, real, currently-maintained community
 * tools that read these exact files, not a single guess:
 *
 *   1. `ai-data-extraction` (github.com/0xSero/ai-data-extraction) — a real
 *      extraction tool covering Cursor, Codex, Claude Code, Windsurf, and
 *      Trae — documents Trae's search paths as `~/.trae` and
 *      `~/Library/Application Support/Trae`, formats "JSONL and SQLite
 *      databases".
 *   2. `claude-code-history-viewer` (github.com/jhlee0409/claude-code-history-viewer)
 *      — a separate, independently authored, actively maintained desktop
 *      app — has a dedicated Trae provider module
 *      (`src-tauri/src/providers/trae.rs`) whose contents were fetched and
 *      read directly. It resolves the platform config directory then
 *      appends `Trae/User/workspaceStorage` — i.e. macOS
 *      `~/Library/Application Support/Trae/User/workspaceStorage`, Linux
 *      `~/.config/Trae/User/workspaceStorage`, Windows
 *      `%APPDATA%/Trae/User/workspaceStorage` — each `<hash>/state.vscdb`
 *      holding a single table `ItemTable (key TEXT UNIQUE ON CONFLICT
 *      REPLACE, value TEXT)`, with **no decompression applied to values —
 *      parsed directly as JSON strings**.
 *
 * These two sources agree with each other on the directory layout, the
 * table name, and the column shape, and that layout matches the
 * already-established vanilla-VS-Code / Cursor pattern this project already
 * trusts (see cursor.js) — which is why `globalStorage/state.vscdb` is also
 * included below even though source #2's own description only walked
 * `workspaceStorage` explicitly: every VS Code-family storage service
 * maintains both a per-profile globalStorage and a per-project
 * workspaceStorage side by side, and stated plainly, that specific half
 * (globalStorage existing for Trae too) rests on the general VS Code
 * architecture fact rather than a source naming Trae's globalStorage by name.
 *
 * What is explicitly NOT trusted here: source #2's own documentation flags
 * the specific KEY NAMES it looks for for chat/agent content — things like
 * `memento/icube-ai-agent-storage`, `ChatStore`,
 * `memento/icube-ai-chat-storage-*` (Trae's internal AI subsystem appears to
 * be code-named "icube") — with its own explicit warning: "Unlike the other
 * providers, this schema is NOT from official source — it is
 * reverse-engineered" and "has not been verified against a real Trae
 * install." Rather than bake in a specific key allowlist that even its own
 * author calls provisional, this source follows cursor.js's own precedent
 * exactly: no key-name filtering at all. Every row's value in `ItemTable` is
 * turned into one scanned line, regardless of which key it's stored under.
 * That sidesteps needing the exact icube key names to be right, at the cost
 * of also picking up ordinary editor/window state alongside chat content —
 * the same tradeoff cursor.js already makes and explains in its own header.
 *
 * This source has NOT been checked against a real Trae install — Trae is
 * not installed on the machine this was built on (checked: not in
 * /Applications, not in ~/Library/Application Support, no mdfind hits). If
 * you have Trae installed, running `residoo scan` and confirming
 * `sourcesScanned`/`filesScanned` for "trae" look right against what you
 * know is on disk is the single most useful way to firm this up.
 *
 * Deliberately NOT covered here: `~/.trae` (JSONL files) mentioned by source
 * #1 above. That path is ambiguous — ByteDance also ships a separate,
 * genuinely open-source CLI tool, `trae-agent` (github.com/bytedance/trae-agent,
 * a different product from the Trae IDE this source targets), whose own
 * README documents trajectory files saved to a `trajectories/` directory
 * *relative to wherever the CLI was run*, not a fixed home-directory path —
 * meaning `~/.trae` may not exist at all, or may hold something unrelated to
 * what source #1's short description implied. Rather than guess which it
 * is, this source only covers the `state.vscdb` layout that two independent
 * tools corroborate in matching, specific detail.
 */
function traeUserDir() {
  const home = os.homedir();
  if (process.platform === "darwin") {
    return path.join(home, "Library", "Application Support", "Trae", "User");
  }
  if (process.platform === "win32") {
    const appData = process.env.APPDATA || path.join(home, "AppData", "Roaming");
    return path.join(appData, "Trae", "User");
  }
  const configHome = process.env.XDG_CONFIG_HOME || path.join(home, ".config");
  return path.join(configHome, "Trae", "User");
}

const USER_DIR = traeUserDir();
const GLOBAL_STORAGE_DB = path.join(USER_DIR, "globalStorage", "state.vscdb");
const WORKSPACE_STORAGE_DIR = path.join(USER_DIR, "workspaceStorage");

// Same lazy-require pattern as cursor.js, for the same reason — see that
// file's docstring for the full explanation of why this is deferred until
// Trae's own directory is confirmed to exist, and why that matters for the
// zero-runtime-dependency rule and the ExperimentalWarning node:sqlite prints.
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

function id() { return "trae"; }
function label() { return "Trae"; }

function userDirExists() {
  try { return fs.statSync(USER_DIR).isDirectory(); } catch { return false; }
}

function available() {
  return userDirExists() && Boolean(getDatabaseSync());
}

/**
 * Same optional, additive export as cursor.js's unavailableReason() — see
 * that file's docstring for why this exists and when callers should use it.
 */
function unavailableReason() {
  if (!userDirExists()) return null;
  if (getDatabaseSync()) return null;
  return `Trae detected but not scanned — ${NODE_SQLITE_REQUIREMENT}`;
}

/**
 * Same defensive symlink-following pattern as cursor.js's own
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
 * statIfPresent() — see that file's docstring for the reasoning.
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
 * one for globalStorage, one per workspaceStorage/<hash> directory. Purely
 * a filesystem walk + stat, same division of labour as cursor.js's files().
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

// No Trae-specific large-file data point exists (no real install to measure
// against) — carried over unchanged from cursor.js as a generous,
// conservative backstop, not a figure backed by an observed real file here.
const MAX_DB_BYTES = 512 * 1024 * 1024;
const READ_TIMEOUT_MS = 60_000;
const BUSY_TIMEOUT_MS = 5_000;
const YIELD_EVERY_N_ROWS = 500;

/**
 * Same value-decoding rule as cursor.js's valueToText() — a TEXT-stored
 * value comes back as a JS string, a BLOB-stored one as a Uint8Array. The
 * schema found for Trae's `ItemTable` declares `value TEXT` (rather than
 * Cursor's BLOB-affinity column), so the string branch is expected to cover
 * the normal case here — the Uint8Array branch is kept anyway, defensively,
 * exactly the way cursor.js keeps it for whatever storage class an
 * individual row actually used, regardless of the column's declared type.
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
 * Only one table is queried (`ItemTable`) — unlike cursor.js's two
 * (`ItemTable` and Cursor's own `cursorDiskKV`), because no second,
 * Trae-specific table name is corroborated by more than one source (see the
 * module docstring above on why the "icube" key names found in a single
 * source are deliberately not hard-coded anywhere in this file, including
 * here as a table name).
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
