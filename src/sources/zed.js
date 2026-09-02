"use strict";

const fs = require("fs");
const path = require("path");
const os = require("os");
const zlib = require("zlib");

/**
 * Zed's local AI agent (chat/thread) history.
 *
 * VERIFICATION STATUS: multi-source-corroborated-but-unverified. Zed is not
 * installed on the machine this source was built on — checked directly:
 * no /Applications/*.app matching Zed, no `dev.zed.Zed` bundle id via
 * `mdfind`, no ~/Library/Application Support/Zed, no ~/.config/zed, no
 * ~/.local/share/zed, no Homebrew cask. So none of this could be checked
 * against a real, on-disk session — only against research. What that
 * research consists of:
 *
 *   1. Zed's own current (`main` branch, fetched live off GitHub while
 *      building this source) open-source implementation:
 *        - crates/agent/src/db.rs — ThreadsDatabase::new() builds the exact
 *          path, the `CREATE TABLE`/`ALTER TABLE` statements below, and
 *          deserialize_thread()'s data_type dispatch (see SCHEMA below).
 *        - crates/paths/src/paths.rs — data_dir()'s per-OS logic (see
 *          PATHS below).
 *      This is a primary source, not a description of one — the literal
 *      code that will still be writing these files after this source
 *      ships, current as of the "main" branch fetched 2026-09-02.
 *   2. A real user's own inspection, reported in a Zed GitHub discussion
 *      ("Where does Zed store Agent Conversation History?",
 *      github.com/zed-industries/zed/discussions/32335): confirms a real
 *      Linux install's conversation history sits under
 *      ~/.local/share/zed/threads/ as "a database... in binary format",
 *      and separately reports a Flatpak install's data root as
 *      ~/.var/app/dev.zed.Zed/data/zed/ instead of ~/.local/share/zed/.
 *   3. zed-chat-export (lib.rs / crates.io), a maintained third-party Rust
 *      CLI that reads this same data for a living — its own docs describe,
 *      in one sentence, reading "Zed's internal SQLite schema" where
 *      conversations are stored "with Zstd-compressed message bodies,"
 *      matching source 1 exactly (SQLite, Zstd), and separately warn that
 *      schema is undocumented and can change between Zed releases — the
 *      same caution this file gives.
 *
 * One discrepancy worth stating plainly: source 2 described the Flatpak
 * path with a "threads-db.1.mdb" (LMDB-shaped) name rather than a flat
 * "threads.db" SQLite file. That is very likely a stale observation from an
 * earlier Zed release — source 1, read directly off the current main
 * branch, is unambiguous that thread persistence today is `sqlez` (a SQLite
 * wrapper) writing one `threads.db` file, and nothing in Zed's current
 * source constructs an ".mdb" path anywhere. Source 1 wins; the Flatpak
 * candidate below still uses today's SQLite filename, not the older name.
 *
 * If you have Zed installed, the most useful thing you can do is run
 * `residoo scan` and confirm `sourcesScanned`/`filesScanned` look right for
 * what you know is actually on disk (a threads.db under one of the PATHS
 * below), then report back either way — see CONTRIBUTING.md.
 *
 * SCHEMA (from source 1, crates/agent/src/db.rs — ThreadsDatabase::new() and
 * deserialize_thread()):
 *   Single table `threads`, one row per conversation thread:
 *     id TEXT PRIMARY KEY, summary TEXT NOT NULL, updated_at TEXT NOT NULL,
 *     data_type TEXT NOT NULL, data BLOB NOT NULL
 *   (+ later ALTER-added columns — parent_id, folder_paths,
 *   folder_paths_order, created_at — irrelevant to scanning, not read here.)
 *   `summary` is the thread's title, plain text. `data` is the actual
 *   conversation payload (title + full message history, as JSON), encoded
 *   per `data_type`:
 *     - "zstd" (current default, per save_thread_sync()): Zstd-compressed
 *       UTF-8 JSON.
 *     - "json" (older/legacy rows, still readable by current Zed): raw
 *       UTF-8 JSON, uncompressed.
 *   deserialize_thread() treats any other data_type value as a hard error —
 *   Zed itself has never written a third kind, so this source doesn't guess
 *   at one either (see decodeThreadData() below).
 *
 * PATHS (from source 1's paths::data_dir(), joined with "threads/threads.db"
 * by db.rs — APP_NAME is "Zed", APP_NAME_LOWERCASE is "zed"):
 *   macOS:         ~/Library/Application Support/Zed/threads/threads.db
 *   Linux/FreeBSD: $XDG_DATA_HOME/zed/threads/threads.db
 *                  (default ~/.local/share/zed/threads/threads.db)
 *   Windows:       %LOCALAPPDATA%\Zed\threads\threads.db
 *   Flatpak (Linux only, checked in addition to the path above):
 *                  ~/.var/app/dev.zed.Zed/data/zed/threads/threads.db
 *
 * Zstd decompression uses node:zlib's built-in zstd support
 * (zlib.zstdDecompressSync) — a Node core API since v22.15.0 (still marked
 * "Experimental" by Node's own docs as of this writing), not a new runtime
 * dependency. Verified directly against this project's own Node: a
 * synthetic threads.db was built (real node:sqlite writes, real
 * zlib.zstdCompressSync-compressed rows, both "zstd" and "json" data_type
 * rows) and read back through the exact logic below during development;
 * that confirms the mechanics of this file, not a real Zed install — see
 * VERIFICATION STATUS above for what remains unverified. Both node:sqlite
 * and zlib's zstd support are feature-detected lazily/cheaply, same
 * reasoning as cursor.js: don't require() node:sqlite (and risk its
 * ExperimentalWarning) until Zed's own data directory is confirmed to exist
 * on this machine.
 */
function zedDataDirs() {
  const home = os.homedir();
  if (process.platform === "darwin") {
    return [path.join(home, "Library", "Application Support", "Zed")];
  }
  if (process.platform === "win32") {
    const localAppData = process.env.LOCALAPPDATA || path.join(home, "AppData", "Local");
    return [path.join(localAppData, "Zed")];
  }
  // Linux, FreeBSD, and other XDG-following unix platforms.
  const xdgDataHome = process.env.XDG_DATA_HOME || path.join(home, ".local", "share");
  return [
    path.join(xdgDataHome, "zed"),
    // Flatpak installs use a separate per-app data root instead of
    // $XDG_DATA_HOME — see the module docstring for why this still targets
    // today's SQLite filename rather than the older ".mdb" name some
    // reports mention.
    path.join(home, ".var", "app", "dev.zed.Zed", "data", "zed"),
  ];
}

const ZED_DATA_DIRS = zedDataDirs();
const THREADS_DB_PATHS = ZED_DATA_DIRS.map((dir) => path.join(dir, "threads", "threads.db"));

// Bounds for readLines(), mirroring claude-code.js/cursor.js.
const MAX_DB_BYTES = 512 * 1024 * 1024; // generous backstop against a
                                          // corrupted/pathological file — no
                                          // real threads.db has been observed
                                          // to size this against, same
                                          // caveat cursor.js's MAX_DB_BYTES
                                          // states for itself (no real
                                          // install here to test against).
const READ_TIMEOUT_MS = 60_000;
const BUSY_TIMEOUT_MS = 5_000; // bound how long a read waits on a lock Zed itself may be holding
const YIELD_EVERY_N_ROWS = 500; // see readLines()'s docstring for why this exists

function id() { return "zed"; }
function label() { return "Zed"; }

function zedDataDirExists() {
  return ZED_DATA_DIRS.some((dir) => {
    try { return fs.statSync(dir).isDirectory(); } catch { return false; }
  });
}

/**
 * node:sqlite is a Node CORE module — see cursor.js's own getDatabaseSync()
 * docstring for the full reasoning this mirrors exactly, including why the
 * require() is deferred rather than done at module load time (an eager
 * top-level require would print Node's ExperimentalWarning on every
 * `residoo scan`, for every user, even the large majority who have never
 * touched Zed).
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

/**
 * zlib.zstdDecompressSync — unlike node:sqlite, requiring the `zlib` module
 * itself is not experimental and prints no warning (it's been a stable Node
 * core module for years); only these specific zstd methods on it are new
 * enough to be version-gated, so a plain feature-detect is all this needs
 * (no lazy-require ceremony to avoid a warning, since there isn't one).
 */
function getZstdDecompressSync() {
  return typeof zlib.zstdDecompressSync === "function" ? zlib.zstdDecompressSync : null;
}

const NODE_SQLITE_REQUIREMENT = "needs Node.js 22.5+ (node:sqlite not present in this runtime)";
const NODE_ZSTD_REQUIREMENT = "needs Node.js 22.15+ (zlib.zstdDecompressSync not present in this runtime)";

function available() {
  // Cheap fs check first, on purpose — same short-circuit reasoning as
  // cursor.js's available(): the common case is Zed simply isn't installed,
  // and answering "not available" for that reason alone must not cost
  // requiring node:sqlite or evaluating zstd support.
  return zedDataDirExists() && Boolean(getDatabaseSync()) && Boolean(getZstdDecompressSync());
}

/**
 * Same optional, additive export cursor.js defines — see its own
 * unavailableReason() docstring for the full contract (only cli.js's "why is
 * a source missing" messaging calls this; scan.js/index.js never do).
 *
 * Returns a reason string only in the cases worth calling out specifically —
 * Zed IS installed (its data directory is really there) but this Node
 * runtime is missing node:sqlite and/or zlib's zstd support, so the source
 * silently vanishing from "Sources checked" would read as "Zed isn't
 * installed," which is false. Returns null for the ordinary "Zed just isn't
 * here" case, and once available() is already true.
 */
function unavailableReason() {
  if (!zedDataDirExists()) return null;
  const missing = [];
  if (!getDatabaseSync()) missing.push(NODE_SQLITE_REQUIREMENT);
  if (!getZstdDecompressSync()) missing.push(NODE_ZSTD_REQUIREMENT);
  if (missing.length === 0) return null;
  return `Zed detected but not scanned — ${missing.join("; ")}`;
}

/**
 * Same defensive symlink-following pattern as cursor.js's statIfPresent —
 * see that file's docstring for the full reasoning. Duplicated rather than
 * imported: each source in this project is meant to be a small,
 * self-contained file a reviewer can audit on its own — see CONTRIBUTING.md.
 *
 * A candidate path that simply does not exist yields nothing — normal for
 * every candidate but whichever one matches this machine's actual OS/install
 * (and normal even for that one, if Zed is installed but its agent panel has
 * never been used). "broken" is reserved for a path that looked like it
 * should resolve to a real file and didn't — chiefly a dangling symlink.
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
 * Yield { file, mtimeMs, sizeBytes, broken } for every threads.db candidate
 * path (see PATHS in the module docstring). Purely a filesystem walk + stat,
 * same division of labour as cursor.js's files(): never opens the database,
 * so it works even in a Node runtime where node:sqlite/zstd aren't available
 * — only readLines() actually needs those.
 */
function* files() {
  for (const dbPath of THREADS_DB_PATHS) yield* statIfPresent(dbPath);
}

/**
 * Decode one `threads` row's `data` BLOB into UTF-8 text, per its
 * `data_type` column — mirrors deserialize_thread() in Zed's own db.rs
 * exactly (see SCHEMA in the module docstring). Returns null when the value
 * can't be turned into text — a corrupt/truncated blob, or a "zstd" row
 * encountered without zstd support available (checked by available() before
 * this source is ever scanned in the real path, but readLines() itself
 * doesn't re-check its own available(), matching claude-code.js/cursor.js).
 * A null here means nothing was ever successfully decoded, not that real
 * content got discarded after being read — the distinction CONTRIBUTING.md's
 * rule 5 (honest partial-read handling) cares about.
 */
function decodeThreadData(dataType, data, zstdDecompressSync) {
  if (!(data instanceof Uint8Array) || data.length === 0) return null;
  const buf = Buffer.from(data.buffer, data.byteOffset, data.byteLength);
  try {
    if (dataType === "zstd") {
      if (!zstdDecompressSync) return null;
      return zstdDecompressSync(buf).toString("utf-8");
    }
    // "json" (legacy, uncompressed) and any future/unrecognized data_type:
    // best-effort treat the bytes as UTF-8 text directly — the same
    // tolerant fallback cursor.js's valueToText() uses for a storage class
    // it doesn't specifically recognize, and the only sane thing to do
    // given Zed's own code has, to date, never written a third data_type.
    return buf.toString("utf-8");
  } catch {
    return null; // corrupt/truncated blob — nothing decodable here
  }
}

/**
 * Read one threads.db as an array of raw text "lines" — one per thread's
 * `summary` (its title) plus one per thread's decoded `data` payload (the
 * full message history as JSON). Returns { lines, status, bytesRead } with
 * the same status vocabulary as claude-code.js/cursor.js: "complete",
 * "partial", "too-large", "failed".
 *
 * Row-by-row iteration + periodic event-loop yield/deadline-check, for
 * exactly the reason cursor.js's readLines() gives: node:sqlite is fully
 * synchronous, so there is no event/AbortSignal to hook a real preemptive
 * timeout onto once a native call has started — this bounds "too many rows
 * taking too long," not a single pathological row's own decode time (same
 * named, not silent, asymmetry cursor.js and claude-code.js each admit for
 * their own analogous gaps).
 */
async function readLines(file) {
  // Unconditional — not gated on zedDataDirExists()/available() here,
  // matching claude-code.js's and cursor.js's readLines(), which likewise
  // never re-check their own available() before trying to read a file.
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
    // corrupt/non-SQLite file sitting at this path, or Zed holding a lock
    // this readonly open can't get past even within BUSY_TIMEOUT_MS — all
    // genuinely "could not read this," not "read it, found nothing."
    return { lines: [], status: "failed", bytesRead: 0 };
  }

  let rows;
  try {
    rows = db.prepare("SELECT summary, data_type, data FROM threads").iterate();
  } catch {
    // Opened fine as SQLite but has no `threads` table matching the schema
    // this source understands — wrong file, or a schema that has since
    // moved on (Zed's own maintainers call this schema undocumented and
    // subject to change — see the module docstring). A real "could not
    // extract anything," not "extracted zero real rows."
    try { db.close(); } catch { /* best-effort close */ }
    return { lines: [], status: "failed", bytesRead: 0 };
  }

  const zstdDecompressSync = getZstdDecompressSync();
  const lines = [];
  let bytesRead = 0;
  const deadline = Date.now() + READ_TIMEOUT_MS;
  let timedOut = false;
  let sawError = false;

  try {
    let n = 0;
    for (const row of rows) {
      if (typeof row.summary === "string" && row.summary.length > 0) {
        lines.push(row.summary);
        bytesRead += Buffer.byteLength(row.summary, "utf-8");
      }

      const text = decodeThreadData(row.data_type, row.data, zstdDecompressSync);
      if (text) {
        lines.push(text);
        bytesRead += Buffer.byteLength(text, "utf-8");
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
    // same way claude-code.js/cursor.js keep a partial read rather than
    // discarding it.
    sawError = true;
  }

  try { db.close(); } catch { /* best-effort close; nothing left to do if this fails */ }

  if (sawError && lines.length === 0) return { lines: [], status: "failed", bytesRead };
  if (timedOut || sawError) return { lines, status: lines.length > 0 ? "partial" : "failed", bytesRead };
  return { lines, status: "complete", bytesRead };
}

module.exports = { id, label, available, unavailableReason, files, readLines };
