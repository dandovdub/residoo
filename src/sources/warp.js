"use strict";

const fs = require("fs");
const path = require("path");
const os = require("os");

/**
 * Warp terminal's local session/block/agent database.
 *
 * VERIFICATION STATUS (read this before trusting anything below): the per-OS
 * paths below are quoted VERBATIM out of Warp's own official documentation —
 * fetched as raw HTML directly (not through an AI-summarized fetch, after an
 * earlier summarized pass turned out to blur two different sections of the
 * same page together) and grepped for the literal strings, so what follows
 * is transcription, not paraphrase. This has NOT been checked against a real
 * Warp install — Warp is not installed on the machine this adapter was built
 * on (checked: no Warp.app under /Applications, no matching directory under
 * `~/Library/Application Support` or `~/Library/Group Containers`, not
 * findable via `mdfind`). If you have Warp installed, the most useful thing
 * you can do is run `residoo scan` and confirm `sourcesScanned`/`filesScanned`
 * look right for what you know is actually on disk, then report back either
 * way.
 *
 * THE FILE AND WHERE IT LIVES. Warp's own docs, "Session Restoration"
 * (https://docs.warp.dev/terminal/sessions/session-restoration/,
 * "#session-restoration-database" — fetched Sept 2026), give the exact path
 * per OS as a copy-pasteable `sqlite3 "<path>"` command a user can run to
 * inspect the file directly:
 *
 *   macOS:   $HOME/Library/Group Containers/2BBY89MBSN.dev.warp/Library/
 *            Application Support/dev.warp.Warp-Stable/warp.sqlite
 *   Windows: $env:LOCALAPPDATA\warp\Warp\data\warp.sqlite
 *   Linux:   ${XDG_STATE_HOME:-$HOME/.local/state}/warp-terminal/warp.sqlite
 *
 * The same page states plainly what this file is for and why it belongs in
 * a secret scanner: "Warp saves the data from your previous session's
 * windows, tabs, and panes to a SQLite database on your computer" — AND, in
 * its own section on clearing it: "you may want to prevent a sensitive
 * Block from being saved on your computer, or you may want to clear blocks
 * from a machine entirely" (deleting it is described as destructive because
 * it "will delete any sessions AND BLOCK HISTORY"). That is Warp's own
 * documentation confirming this file holds real block (command + output)
 * content, not just window geometry — exactly the "AI-block history" this
 * source was scoped to cover.
 *
 * Warp's docs separately confirm a Preview release channel uses parallel,
 * differently-named directories specifically so it never collides with
 * Stable's data — "Logging out & uninstalling"
 * (.../logging-out-and-uninstalling/) gives, verbatim:
 *   macOS Preview:   .../dev.warp.Warp-Preview  (same Group Containers root)
 *   Windows Preview: %LOCALAPPDATA%\warp\WarpPreview\  (logs confirmed at
 *                    ...\WarpPreview\data\logs\warp_preview.log*, i.e. the
 *                    same `...\data\` layout as Stable, one level up)
 *   Linux Preview:   "Append `-preview` to each `warp-terminal` directory"
 *                    (file-locations page, verbatim) → warp-terminal-preview
 * None of those three quotes spells out "warp.sqlite" specifically for
 * Preview (only Preview's log filename is spelled out that precisely) — the
 * Preview `warp.sqlite` path below is filled in by direct structural analogy
 * to Stable's confirmed layout, not independently quoted. Flagged here
 * rather than silently assumed.
 *
 * SCHEMA. Warp's docs do not publish a schema. Table names are corroborated
 * by two independent sources that had to actually query a real file to know
 * them:
 *   - github.com/8agana/warp-sqlite-mcp — a maintained MCP server built
 *     specifically to query this database (confirmed against its source,
 *     not just its README: it takes a `table` name as a runtime parameter
 *     for generic `sqlite_select`/`sqlite_insert`/etc., so it doesn't hardcode
 *     a schema in code either — but its README, written by someone with a
 *     real install, names `ai_queries`, `agent_conversations`, `notebooks`,
 *     `active_mcp_servers`, and `commands` as tables it has seen, and gives
 *     a macOS path matching the official docs above character-for-character).
 *   - github.com/warpdotdev/Warp issue #7760 ("Agent Chat Sessions Not
 *     Restored on Restart") — a real user's own direct query against their
 *     own live Linux install (`~/.local/state/warp-terminal/warp.sqlite`,
 *     matching the official path above), showing an `agent_conversations`
 *     table with columns `id`, `conversation_id`, `last_modified_at`, and
 *     `conversation_data` (a blob holding the actual conversation content).
 *
 * That is a real, named, partial table list, not a complete one — and this
 * source deliberately does NOT hardcode it. Instead, readLines() below
 * queries `sqlite_master` at scan time to discover whatever tables actually
 * exist in the specific file being read, and reads all of them (skipping
 * only SQLite's own internal `sqlite_%` tables). Three reasons, stated
 * plainly:
 *   1. No source consulted claims to be a complete table list, and Warp's
 *      own schema is independently known to have changed shape over time —
 *      issue #7760 is itself a report of a schema/behavior regression.
 *      A hardcoded allowlist here would silently miss whatever the true
 *      block/command-history table is called if it doesn't match one of the
 *      five names above, which is precisely the "schema drifted, scan
 *      quietly covered less than it claimed" failure this project exists to
 *      avoid (see CONTRIBUTING.md rule 5, and the agentsweep incident
 *      described in this source's task brief).
 *   2. A table this source doesn't recognize by name (window position
 *      integers, MCP server registrations, etc.) costs nothing extra to
 *      scan and cannot itself produce a false secret match — it just adds a
 *      few harmless, pattern-unmatched lines. There is no accuracy trade to
 *      make by including it.
 *   3. This is the same principle cursor.js already applies one level down
 *      (reading every row's value without a column-name allowlist, for the
 *      same "the exact set of content-bearing keys has already changed
 *      across versions" reason) — applied here one level up, to table names
 *      instead of column names, because Warp's schema is a whole database of
 *      tables rather than Cursor's fixed two.
 *
 * Nothing in Warp's documented pragmas or in either community source
 * suggests this file is encrypted (session-restoration docs literally tell
 * users to open it with a bare `sqlite3 "<path>"`, no key or password) — a
 * password-protected file would make that instruction meaningless.
 */
function warpStateDirs() {
  const home = os.homedir();

  if (process.platform === "darwin") {
    const base = path.join(
      home, "Library", "Group Containers", "2BBY89MBSN.dev.warp",
      "Library", "Application Support"
    );
    return [
      { channel: "stable", dir: path.join(base, "dev.warp.Warp-Stable") },
      { channel: "preview", dir: path.join(base, "dev.warp.Warp-Preview") },
    ];
  }

  if (process.platform === "win32") {
    const localAppData = process.env.LOCALAPPDATA || path.join(home, "AppData", "Local");
    return [
      { channel: "stable", dir: path.join(localAppData, "warp", "Warp", "data") },
      { channel: "preview", dir: path.join(localAppData, "warp", "WarpPreview", "data") },
    ];
  }

  // Linux and other XDG-following unix platforms.
  const xdgStateHome = process.env.XDG_STATE_HOME || path.join(home, ".local", "state");
  return [
    { channel: "stable", dir: path.join(xdgStateHome, "warp-terminal") },
    { channel: "preview", dir: path.join(xdgStateHome, "warp-terminal-preview") },
  ];
}

function candidateDbPaths() {
  return warpStateDirs().map(({ dir }) => path.join(dir, "warp.sqlite"));
}

/**
 * Same lazy-require, feature-detected node:sqlite pattern as cursor.js and
 * crush.js — see cursor.js's docstring for the full reasoning (an eager
 * top-level require would print Node's ExperimentalWarning on every
 * `residoo scan` for every user, even the majority who have never touched
 * Warp). Duplicated rather than shared: each source here is meant to be a
 * small, self-contained file a reviewer can audit on its own
 * (CONTRIBUTING.md).
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

function id() { return "warp"; }
function label() { return "Warp"; }

/**
 * Deliberately checks the CONTAINING DIRECTORY, not the warp.sqlite file
 * itself, and deliberately does not follow into "does the file resolve" —
 * same reasoning as claude-code.js's/cursor.js's available(), which gate on
 * a root directory rather than a specific leaf file. This matters concretely
 * here: statSync on a *file* path follows symlinks and throws for a
 * dangling one, which would make available() report false for exactly the
 * broken-symlink case files() exists to surface — silently un-gating the
 * whole source (per cursor.js's own docstring, available() is what decides
 * whether files()/readLines() get called at all) right when there's a
 * broken entry most worth reporting. Checking the directory instead avoids
 * that trap: a directory being present is a stable signal that Warp (this
 * channel) is installed, independent of whatever state the db file itself
 * is in.
 */
function anyWarpDirExists() {
  for (const { dir } of warpStateDirs()) {
    try { if (fs.statSync(dir).isDirectory()) return true; } catch { /* not this one */ }
  }
  return false;
}

function available() {
  // Cheap fs checks first, same short-circuit reasoning as cursor.js's and
  // crush.js's available(): the common case is Warp simply isn't installed,
  // and that must not cost requiring node:sqlite.
  return anyWarpDirExists() && Boolean(getDatabaseSync());
}

/**
 * Same additive, optional export as cursor.js's/crush.js's
 * unavailableReason() — see cursor.js's docstring. Distinguishes "Warp
 * isn't here" (say nothing) from "Warp is here but this Node runtime can't
 * read its database" (say so).
 */
function unavailableReason() {
  if (!anyWarpDirExists()) return null;
  if (getDatabaseSync()) return null;
  return `Warp detected but not scanned — ${NODE_SQLITE_REQUIREMENT}`;
}

/**
 * Resolve one candidate `warp.sqlite` path into zero or one files() entries.
 * Identical in shape and reasoning to cursor.js's and crush.js's
 * statIfPresent(): these paths are constructed (fixed per-OS/per-channel
 * layout), not discovered by listing a directory, so lstat is used directly.
 * A channel that was simply never installed (Preview, most commonly) yields
 * nothing and is NOT broken; a dangling symlink IS.
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
 * Yield { file, mtimeMs, sizeBytes, broken } for warp.sqlite under every
 * release channel (Stable, Preview) this platform's layout defines. Purely
 * a filesystem walk + stat — never opens the database, so it works (and can
 * be exercised in tests) even in a Node runtime where node:sqlite isn't
 * available.
 */
function* files() {
  for (const dbPath of candidateDbPaths()) {
    yield* statIfPresent(dbPath);
  }
}

// A warp.sqlite this large has not been observed anywhere in this source's
// research — no real install was available to produce or measure one.
// Picked deliberately larger than cursor.js's 512MB backstop: unlike
// Cursor's editor-state file, this one accumulates terminal BLOCK content
// (commands + their full output) continuously for as long as Session
// Restoration stays enabled, which is a plausibly much larger growth curve
// over months/years of daily use — but this is reasoning from the file's
// documented purpose, not a measurement. Same honest caveat as this
// project's other unverified sources' size backstops.
const MAX_DB_BYTES = 1024 * 1024 * 1024; // 1GB
const READ_TIMEOUT_MS = 60_000;
const BUSY_TIMEOUT_MS = 5_000; // bound how long a read waits on a lock Warp itself may be holding
const YIELD_EVERY_N_ROWS = 500;

function quoteIdent(name) {
  return '"' + name.replace(/"/g, '""') + '"';
}

/**
 * List every real, user-facing table in this database file, discovered from
 * `sqlite_master` rather than assumed — see the module docstring for why
 * this source deliberately does not hardcode a table allowlist. SQLite's
 * own internal bookkeeping tables (`sqlite_sequence` and similar, always
 * prefixed `sqlite_`) are excluded; everything else Warp itself created is
 * read.
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
 * Turn one row (a plain object keyed by column name, as node:sqlite's
 * StatementSync#iterate() returns it) into one scanned text line. No column
 * allowlist, same reasoning as cursor.js's valueToText() and crush.js's
 * rowToLine(): a BLOB-affinity column can come back as a Uint8Array
 * (confirmed against this project's own node:sqlite by cursor.js's
 * research — not a Buffer, despite Node's docs describing BLOB columns
 * loosely); an INTEGER too large for a safe JS number comes back as a
 * BigInt, which JSON.stringify throws on unless converted first. Both are
 * converted to plain strings before stringifying so this can never throw on
 * a row shape it didn't anticipate.
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
 * Read one warp.sqlite as an array of raw text "lines" — one per row, across
 * every table discovered in the file (see discoverTableNames()). Same
 * status vocabulary and same iterate()-with-periodic-yield-and-deadline-
 * check approach as cursor.js's and crush.js's readLines(), for the same
 * reason: node:sqlite is fully synchronous, so a wall-clock deadline can
 * only be enforced between rows, not preemptively mid-row. See cursor.js's
 * own docstring for the full reasoning; not re-derived here since nothing
 * about it is Warp-specific.
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
    // Deleted between files() and this call, a corrupt/non-SQLite file, or
    // Warp itself holding a lock this readonly open can't get past within
    // BUSY_TIMEOUT_MS (plausible: Warp may be running and actively writing
    // block/session data) — all genuinely "could not read this," not "read
    // it, found nothing." Status "failed" keeps that distinction honest.
    return { lines: [], status: "failed", bytesRead: 0 };
  }

  const tables = discoverTableNames(db);

  const lines = [];
  let bytesRead = 0;
  const deadline = Date.now() + READ_TIMEOUT_MS;
  let timedOut = false;
  let sawError = false;

  for (const table of tables) {
    let rows;
    try {
      rows = db.prepare(`SELECT * FROM ${quoteIdent(table)}`).iterate();
    } catch {
      // A table sqlite_master listed but that fails to actually SELECT from
      // (a view masquerading as a table entry, a table dropped mid-scan) —
      // not a read failure for the OTHER tables, so just move on.
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
      // A row iterator can itself throw partway (e.g. a corrupted page hit
      // mid-scan) — whatever WAS read before that is real content, kept the
      // same way claude-code.js keeps a partial read rather than discarding it.
      sawError = true;
    }
    if (timedOut) break;
  }

  try { db.close(); } catch { /* best-effort close; nothing left to do if this fails */ }

  // sqlite_master itself failed, or listed no tables at all — opened fine as
  // SQLite but nothing in it could be enumerated, a real "could not extract
  // anything," not the same as "extracted zero real rows."
  if (tables.length === 0) return { lines: [], status: "failed", bytesRead: 0 };
  if (sawError && lines.length === 0) return { lines: [], status: "failed", bytesRead };
  if (timedOut || sawError) return { lines, status: lines.length > 0 ? "partial" : "failed", bytesRead };
  return { lines, status: "complete", bytesRead };
}

module.exports = { id, label, available, unavailableReason, files, readLines };
