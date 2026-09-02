"use strict";

const fs = require("fs");
const path = require("path");
const os = require("os");

/**
 * Cursor's local chat/composer history.
 *
 * VERIFICATION STATUS (read this before trusting anything below): the paths
 * and schema here are corroborated by multiple independent community
 * write-ups — including one built from a real `sqlite3 .tables` / row-count
 * inspection of an actual, live Cursor install on Linux, and a real, working
 * desktop tool (not just a blog post) that reads/writes these same
 * tables/keys — cross-checked against several more descriptions that agree
 * with each other on table names, key patterns, and per-OS paths. What this
 * source has NOT been checked against is a real Cursor install on the
 * machine it was built on — Cursor isn't installed there. See CONTRIBUTING.md
 * and this source's PR description for exactly what was and wasn't verified.
 * If you have Cursor installed, the most useful thing you can do is run
 * `residoo scan` and confirm `sourcesScanned`/`filesScanned` look right for
 * what you know is actually on disk, then report back either way.
 *
 * Cursor is a VS Code fork and reuses VS Code's per-profile SQLite storage
 * file for editor/workbench state: `state.vscdb`, containing a table called
 * `ItemTable`. Cursor adds its own table, `cursorDiskKV`, in the same file
 * for chat/composer data. Both tables share the same two-column shape:
 * `key TEXT UNIQUE, value BLOB` — one row per key, value a UTF-8 JSON blob
 * (confirmed directly against this project's own Node/node:sqlite: see
 * valueToText() below for the two storage-class shapes actually observed).
 *
 * Two copies of this file exist per install, and which one holds the actual
 * message text has reportedly moved across Cursor versions (per the sources
 * above — composer/chat data has lived in globalStorage in some versions,
 * with workspaceStorage holding only UI/pointer state, and the reverse has
 * also been reported for older versions). Rather than guess which is current
 * for whatever version is installed, this source reads BOTH, everywhere
 * found:
 *   - globalStorage/state.vscdb — one per Cursor profile.
 *   - workspaceStorage/<hash>/state.vscdb — one per opened project/folder.
 *
 * Key-name filtering (only reading rows named `bubbleId:...`,
 * `composerData:...`, etc.) was deliberately NOT done, for the same reason:
 * the exact universe of "which keys hold real content" has already changed
 * across Cursor versions in the research for this source (composer.composerData
 * vs composer.composerHeaders vs workbench.panel.aichat.view.aichat.chatdata
 * vs agentKv:blob:* were all reported as real, in different versions or
 * subsystems). scan.js already matches raw text regardless of the structure
 * it came from (see its own docstring) — this source reuses that same
 * tolerance by turning every row's value into one scanned line, rather than
 * hard-coding a key allowlist likely to go stale the same way the sources
 * above show it already has.
 */
function cursorUserDir() {
  const home = os.homedir();
  if (process.platform === "darwin") {
    return path.join(home, "Library", "Application Support", "Cursor", "User");
  }
  if (process.platform === "win32") {
    const appData = process.env.APPDATA || path.join(home, "AppData", "Roaming");
    return path.join(appData, "Cursor", "User");
  }
  // Linux and other XDG-following unix platforms.
  const configHome = process.env.XDG_CONFIG_HOME || path.join(home, ".config");
  return path.join(configHome, "Cursor", "User");
}

const USER_DIR = cursorUserDir();
const GLOBAL_STORAGE_DB = path.join(USER_DIR, "globalStorage", "state.vscdb");
const WORKSPACE_STORAGE_DIR = path.join(USER_DIR, "workspaceStorage");

/**
 * node:sqlite is a Node CORE module (built into the `node` binary itself),
 * not a package resolved from node_modules — using it adds no entry to
 * package.json, no lockfile line, nothing `npm audit`/a supply-chain scan
 * would ever see. That is the actual distinction CONTRIBUTING.md's rule 1
 * ("zero runtime dependencies") cares about; Node itself still labels the
 * module "experimental" (it prints an ExperimentalWarning on first use,
 * visible if you run residoo with `--trace-warnings`), which is a stability
 * promise, not a supply-chain one, and irrelevant to that rule.
 *
 * It has been available, unflagged, since Node 22.5.
 *
 * Loaded LAZILY (see getDatabaseSync() below), not at module require() time.
 * require("node:sqlite") makes Node print an ExperimentalWarning to stderr
 * on its first successful load per process (verified directly: calling
 * require() again afterwards, even many times, does not repeat it — the
 * module cache absorbs the rest). index.js requires every registered source
 * unconditionally so ALL_SOURCES can exist, and cli.js calls available() on
 * every one of them on every single `residoo scan` — an eager top-level
 * require here would print that warning on every invocation, forever, for
 * every user on Node 22.5+, even the large majority who have never touched
 * Cursor. Deferring the require until there is already a concrete reason to
 * make it (Cursor's own directory actually exists on this machine) confines
 * that warning to the case where it's actually informative.
 */
const NODE_SQLITE_REQUIREMENT = "needs Node.js 22.5+ (node:sqlite not present in this runtime)";
let sqliteRequireAttempted = false;
let DatabaseSync = null;

/**
 * Resolve node:sqlite's DatabaseSync, requiring it at most once per process
 * (subsequent calls reuse the cached result, success or failure alike).
 *
 * Deliberately does NOT gate on userDirExists() itself — readLines(file), by
 * contract, must still work for whatever file path is handed to it (this
 * mirrors claude-code.js's readLines(), which likewise never checks its own
 * available() before trying to read a file). It is available()'s and
 * unavailableReason()'s job to skip calling this at all when there's
 * plainly nothing to read yet — see their bodies below.
 */
function getDatabaseSync() {
  if (!sqliteRequireAttempted) {
    sqliteRequireAttempted = true;
    try { ({ DatabaseSync } = require("node:sqlite")); }
    catch { DatabaseSync = null; }
  }
  return DatabaseSync;
}

function id() { return "cursor"; }
function label() { return "Cursor"; }

function userDirExists() {
  try { return fs.statSync(USER_DIR).isDirectory(); } catch { return false; }
}

function available() {
  // Cheap fs check first, on purpose: the common case is Cursor simply
  // isn't installed, and answering "not available" for that reason alone
  // must not cost requiring node:sqlite — see getDatabaseSync()'s docstring
  // for exactly why that matters here. Short-circuit evaluation means
  // getDatabaseSync() (and its possible warning) is never reached when
  // userDirExists() is already false.
  return userDirExists() && Boolean(getDatabaseSync());
}

/**
 * Optional, additive beyond the { id, label, available, files, readLines }
 * contract every source implements — scan.js and index.js never call this;
 * only cli.js's own "why is a source missing" messaging does, and only when
 * present (`typeof source.unavailableReason === "function"`). Every other
 * source can safely ignore this export entirely.
 *
 * Returns a human-readable reason string in the one case worth calling out
 * specifically — Cursor IS installed (its User profile directory is really
 * there) but this Node runtime is too old for node:sqlite, so the source
 * silently vanishing from "Sources checked" would read as "Cursor isn't
 * installed," which is false and unhelpful. Returns null otherwise,
 * including the ordinary "Cursor just isn't here" case, where saying nothing
 * more is the correct, unremarkable answer.
 */
function unavailableReason() {
  // Same short-circuit-first shape as available(), and for the same reason:
  // don't pay for (or warn about) a node:sqlite require when Cursor isn't
  // even on this machine, where the answer is "nothing to say" regardless.
  if (!userDirExists()) return null;
  if (getDatabaseSync()) return null; // sqlite is fine; available() already covers this source correctly
  return `Cursor detected but not scanned — ${NODE_SQLITE_REQUIREMENT}`;
}

/**
 * Same defensive symlink-following pattern as claude-code.js's
 * isDirFollowingSymlink — see that file's docstring for the full reasoning
 * (a relocated/symlinked directory should still be scanned, not silently
 * excluded because Dirent reflects lstat semantics for symlinks). Duplicated
 * here rather than imported: each source in this project is meant to be a
 * small, self-contained file a reviewer can audit on its own — see
 * CONTRIBUTING.md.
 */
function isDirFollowingSymlink(fullPath, dirent) {
  if (dirent.isDirectory()) return true;
  if (!dirent.isSymbolicLink()) return false;
  try { return fs.statSync(fullPath).isDirectory(); } catch { return false; }
}

/**
 * Resolve one candidate `state.vscdb` path into zero or one files() entries.
 *
 * Uses lstat directly rather than readdirSync+Dirent, because these paths
 * are constructed (globalStorage/state.vscdb is a fixed, known filename; a
 * workspaceStorage entry's state.vscdb is joined onto an already-resolved
 * directory) rather than discovered by listing a directory — there is no
 * Dirent available to reuse the isDirFollowingSymlink-style check against.
 *
 * A path that simply does not exist yields nothing: for globalStorage that
 * would be unusual, but for a workspaceStorage/<hash> directory that never
 * happened to write a state.vscdb, or wrote one and later had it removed, it
 * is normal and NOT a "broken" entry — broken is reserved for a path that
 * looked like it should resolve to a real file and didn't (a dangling
 * symlink, chiefly), exactly the same convention claude-code.js's files()
 * uses.
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

  if (!lst.isFile()) return; // e.g. something unexpected sits at this path — out of scope, not broken
  yield { file: dbPath, mtimeMs: lst.mtimeMs, sizeBytes: lst.size, broken: false };
}

/**
 * Yield { file, mtimeMs, sizeBytes, broken } for every state.vscdb found —
 * one for globalStorage, one per workspaceStorage/<hash> directory.
 *
 * Purely a filesystem walk + stat, same division of labour as
 * claude-code.js's files(): this function never opens the database, so it
 * works (and can be exercised in tests) even in a Node runtime where
 * node:sqlite isn't available — only readLines() actually needs it.
 */
function* files() {
  yield* statIfPresent(GLOBAL_STORAGE_DB);

  let workspaceDirs;
  try { workspaceDirs = fs.readdirSync(WORKSPACE_STORAGE_DIR, { withFileTypes: true }); }
  catch { return; } // no workspaceStorage directory at all — nothing more to walk

  for (const ws of workspaceDirs) {
    const wsDir = path.join(WORKSPACE_STORAGE_DIR, ws.name);
    if (!isDirFollowingSymlink(wsDir, ws)) {
      if (ws.isSymbolicLink()) yield { file: wsDir, broken: true };
      continue;
    }
    yield* statIfPresent(path.join(wsDir, "state.vscdb"));
  }
}

// A state.vscdb this large has not been observed anywhere in this source's
// research (a real, live install inspected during that research had ~50,000
// rows total across both tables, nowhere near this many bytes) — unlike
// claude-code.js's MAX_BYTES, this is not backed by a real large file this
// tool was tested against, only a generous backstop against a corrupted or
// pathological file.
const MAX_DB_BYTES = 512 * 1024 * 1024;
const READ_TIMEOUT_MS = 60_000;
const BUSY_TIMEOUT_MS = 5_000; // bound how long a read waits on a lock Cursor itself may be holding
const YIELD_EVERY_N_ROWS = 500; // see the docstring inside readLines() for why this exists

/**
 * A row's `value` column comes back as a JS string when Cursor stored it as
 * TEXT — the common case per this source's research: VS Code's storage
 * service writes JSON via a plain JS string, and a BLOB-DECLARED column in
 * SQLite uses "no conversion" (NONE/BLOB) affinity, meaning whatever storage
 * class was written comes back unchanged, string in, string out. When a
 * value WAS stored as raw bytes it comes back as a Uint8Array — verified
 * directly against this project's own node:sqlite (NOT a Buffer, despite
 * Node's own `sqlite` docs describing BLOB columns loosely — Buffer.isBuffer()
 * on a real returned value here is false; checked, not assumed).
 */
function valueToText(value) {
  if (typeof value === "string") return value;
  if (value instanceof Uint8Array) return Buffer.from(value).toString("utf-8");
  return null; // NULL, an integer, or some other SQLite storage class — not text content
}

/**
 * Read one state.vscdb as an array of raw text "lines" — one per row's
 * decoded value, across both known tables. Returns { lines, status,
 * bytesRead } with the same status vocabulary as claude-code.js's
 * readLines(): "complete", "partial", "too-large", "failed".
 *
 * node:sqlite's DatabaseSync/StatementSync are fully SYNCHRONOUS — unlike
 * claude-code.js's stream-based read, there is no 'error'/'close' event and
 * no AbortSignal to hook a real preemptive timeout onto; once a native call
 * has started, a JS-level setTimeout cannot interrupt it. What CAN be done
 * without adding a dependency: iterate row-by-row via
 * StatementSync#iterate() (confirmed to exist and work on this project's
 * node:sqlite floor — Node 22.5+, per the module docstring above) and
 * explicitly yield to the event loop every YIELD_EVERY_N_ROWS rows, checking
 * a wall-clock deadline at each yield point. This bounds the failure mode
 * that is actually plausible for this source — a cursorDiskKV table with
 * tens of thousands of rows (a real install inspected during this source's
 * research had roughly 50,000) taking too long — at the cost of NOT bounding
 * a single pathologically large row's own decode time. That is the same
 * asymmetry claude-code.js's own docstring admits for peak memory: a real,
 * named limitation, not a silent gap.
 */
async function readLines(file) {
  // Unconditional — not gated on userDirExists() the way available() is.
  // readLines() must work for whatever file path is actually handed to it
  // (including, e.g., a test fixture living outside Cursor's real directory
  // entirely), matching claude-code.js's readLines() never checking its own
  // available() either. In the real scan path this call reuses the already-
  // cached result from the available() check that gated this source in.
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
    // Covers: the file was deleted between files() and this call, a
    // corrupt/non-SQLite file sitting at this path, or Cursor holding a lock
    // this readonly open can't get past even within BUSY_TIMEOUT_MS. All
    // three are genuinely "could not read this," not "read it, found
    // nothing" — status "failed" is what keeps scan.js's report honest about
    // the difference (see CONTRIBUTING.md rule 5).
    return { lines: [], status: "failed", bytesRead: 0 };
  }

  const lines = [];
  let bytesRead = 0;
  const deadline = Date.now() + READ_TIMEOUT_MS;
  let timedOut = false;
  let sawError = false;
  let foundAnyTable = false;

  for (const table of ["ItemTable", "cursorDiskKV"]) {
    let rows;
    try {
      rows = db.prepare(`SELECT key, value FROM ${table}`).iterate();
    } catch {
      // This particular table genuinely doesn't exist in this file's schema
      // (older/newer Cursor version) — not a read failure for the OTHER
      // table, so just move on rather than aborting the whole file.
      continue;
    }
    foundAnyTable = true;

    let n = 0;
    try {
      for (const row of rows) {
        const text = valueToText(row.value);
        // One database row becomes one scanned "line," using the value
        // exactly as stored — not re-serialized through JSON.parse/stringify
        // — for the same reason scan.js matches raw text rather than parsed
        // fields: that keeps every byte the regexes depend on (quoting,
        // escaping, control characters) exactly as Cursor wrote it.
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
      // same way claude-code.js keeps a partial read rather than discarding it.
      sawError = true;
    }
    if (timedOut) break;
  }

  try { db.close(); } catch { /* best-effort close; nothing left to do if this fails */ }

  // Neither known table existed at all — this file opened fine as SQLite but
  // didn't match the schema this source understands, which is a real "could
  // not extract anything," not the same as "extracted zero real rows."
  if (!foundAnyTable) return { lines: [], status: "failed", bytesRead: 0 };
  if (sawError && lines.length === 0) return { lines: [], status: "failed", bytesRead };
  if (timedOut || sawError) return { lines, status: lines.length > 0 ? "partial" : "failed", bytesRead };
  return { lines, status: "complete", bytesRead };
}

module.exports = { id, label, available, unavailableReason, files, readLines };
