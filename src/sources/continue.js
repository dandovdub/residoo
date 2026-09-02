"use strict";

const fs = require("fs");
const path = require("path");
const os = require("os");
const { createInterface } = require("readline/promises");

/**
 * Continue (continue.dev) — the open-source AI coding extension for VS Code
 * and JetBrains. Both IDE front-ends embed the same IDE-agnostic "core"
 * (github.com/continuedev/continue, package `core/`), and it is that core —
 * not either IDE integration — which owns local storage, so the path below
 * applies the same way regardless of which IDE the user runs Continue in.
 *
 * VERIFICATION STATUS (read this before trusting anything below): this is
 * NOT checked against a real Continue install — no `~/.continue` directory,
 * no VS Code install, and no Continue JetBrains plugin trace exist on the
 * machine this adapter was built on (checked: direct path stat, `mdfind`,
 * `~/.vscode/extensions`, `~/Library/Application Support/JetBrains/*`).
 * Ships anyway per CONTRIBUTING.md rule 3, on the strength of reading the
 * project's own real, current source directly — about as strong as
 * corroboration gets short of a live install — cross-checked against two
 * more independent descriptions that agree with it:
 *
 *   1. THE PROJECT'S OWN SOURCE CODE, read directly from
 *      github.com/continuedev/continue (`main` branch):
 *        - `core/util/paths.ts` — `getContinueGlobalPath()` resolves to
 *          `path.join(os.homedir(), ".continue")` (or the `CONTINUE_GLOBAL_DIR`
 *          env var, not honored by this adapter — see below), with NO
 *          per-OS branching, so this is the path on macOS, Linux, AND
 *          Windows alike (unlike Cursor/Trae's VS Code-inherited per-OS
 *          `Application Support` / `%APPDATA%` split — Continue's core is a
 *          separate Node process the IDE spawns, not a VS Code storage
 *          consumer). `getSessionsFolderPath()` /
 *          `getSessionFilePath(sessionId)` / `getSessionsListPath()` give
 *          `sessions/`, `sessions/<sessionId>.json`, and
 *          `sessions/sessions.json` off that root.
 *        - `core/util/history.ts` (`HistoryManager`) — `save()` writes one
 *          full `Session` object per `sessions/<uuid>.json` (pretty-printed
 *          `JSON.stringify(orderedSession, undefined, 2)`) and appends/
 *          updates a lightweight `BaseSessionMetadata` entry in the
 *          `sessions/sessions.json` array.
 *        - `core/index.d.ts` — `Session.history` is a `ChatHistoryItem[]`;
 *          each item's `message` carries `role` ("user" | "assistant" |
 *          "thinking" | "system" | "tool") and `content` (plain string OR
 *          an array of `{type:"text",text}` / `{type:"imageUrl",imageUrl}`
 *          parts), plus optional `toolCalls`, `contextItems` (full file
 *          contents pulled into context, `{content, name, uri, ...}`), and
 *          `promptLogs` (raw `{prompt, completion}` sent to/from the model)
 *          — i.e. real transcript content, not just metadata.
 *        - `core/data/log.ts` (`DataLogger.logLocalData`) — confirms local
 *          "dev data" logging to `dev_data/<schemaVersion>/<eventName>.jsonl`
 *          (via `getDevDataFilePath()` in paths.ts) runs UNCONDITIONALLY
 *          ("Local logs (always on for all levels)", literal comment in the
 *          source) at `DEFAULT_DEV_DATA_LEVEL = "all"` — i.e. on by
 *          default, not an opt-in telemetry path.
 *        - `packages/config-yaml/src/schemas/data/chatInteraction/v0.2.0.ts`
 *          — confirms the "all"-level `chatInteraction` event schema (the
 *          one written locally by default) includes `prompt` and
 *          `completion` as full fields, only omitted at the opt-in stricter
 *          "noCode" level used for some *remote* destinations.
 *   2. Official docs (docs.continue.dev/development-data, via search
 *      excerpt — the live page itself is a JS-rendered redirect stub
 *      WebFetch could not follow, so this is the search engine's cached
 *      text of it, not a fetch of the rendered page): "By default, this
 *      development data is saved to .continue/dev_data on your local
 *      machine," independently confirming point 1's "always on" reading of
 *      the source.
 *   3. DeepWiki's auto-generated `continuedev/continue` wiki page
 *      "8.7 History and Session Persistence" (deepwiki.com) — independently
 *      describes the same `sessions/sessions.json` +
 *      `sessions/<uuid>.json` split, matching the source exactly.
 *
 * NOT covered by this adapter, named so a future PR knows they were seen
 * and deliberately left out rather than missed: `logs/core.log` and
 * `logs/prompt.log` (`getLogsDirPath()`/`getPromptLogsPath()` in paths.ts)
 * — free-text debug logs, not confirmed to hold full prompt/completion
 * content the way `dev_data` is; `dev_data/**\/*.sqlite`
 * (`getDevDataSqlitePath()`) — a separate SQLite mirror of the same dev-data
 * events, redundant with the JSONL files this adapter already reads; and
 * the `CONTINUE_GLOBAL_DIR` environment-variable override — honoring it
 * would mean trusting an env var to redirect what gets scanned, which
 * didn't seem like the right default to add silently; a relocated
 * `~/.continue` installed via that var will simply read as "not installed"
 * to `available()` below.
 */
const ROOT = path.join(os.homedir(), ".continue");
const SESSIONS_DIR = path.join(ROOT, "sessions");
const SESSIONS_INDEX_FILE = path.join(SESSIONS_DIR, "sessions.json");
const DEV_DATA_DIR = path.join(ROOT, "dev_data");

function id() { return "continue"; }
function label() { return "Continue"; }

function available() {
  // Mirrors cursor.js's choice, not claude-code.js's: like Cursor, this
  // source reads from multiple sibling locations under one root
  // (sessions/, dev_data/) rather than one specific content directory, so
  // the umbrella root is what "installed" means here. It is not proof any
  // session/event content actually exists yet — same caveat cursor.js's
  // available() carries for the same reason.
  try { return fs.statSync(ROOT).isDirectory(); } catch { return false; }
}

/**
 * Same defensive symlink-following pattern as claude-code.js's
 * isDirFollowingSymlink/isFileFollowingSymlink — see that file's docstring
 * for the full reasoning. Duplicated here rather than imported, matching
 * cursor.js's stated rationale: each source is meant to be a small,
 * self-contained file a reviewer can audit on its own.
 */
function isKindFollowingSymlink(fullPath, dirent, checkFn) {
  if (checkFn(dirent)) return true;
  if (!dirent.isSymbolicLink()) return false;
  try { return checkFn(fs.statSync(fullPath)); } catch { return false; }
}
const isDirFollowingSymlink = (p, d) => isKindFollowingSymlink(p, d, (x) => x.isDirectory());
const isFileFollowingSymlink = (p, d) => isKindFollowingSymlink(p, d, (x) => x.isFile());

/**
 * Resolve one FIXED, known directory path (not discovered via a parent
 * readdir, so there is no Dirent to reuse isDirFollowingSymlink against —
 * same situation cursor.js's statIfPresent is in for GLOBAL_STORAGE_DB)
 * into "ok" | "absent" | "broken". "absent" (path simply doesn't exist, or
 * something unexpected — not a directory, not a symlink — sits there) is
 * deliberately NOT reported broken, same convention as everywhere else in
 * this project: broken is reserved for a path that looked like it should
 * resolve to a real directory and didn't (chiefly a dangling symlink).
 */
function resolveDirState(dirPath) {
  let lst;
  try { lst = fs.lstatSync(dirPath); } catch { return "absent"; }
  if (lst.isDirectory()) return "ok";
  if (lst.isSymbolicLink()) {
    try { return fs.statSync(dirPath).isDirectory() ? "ok" : "broken"; }
    catch { return "broken"; }
  }
  return "absent";
}

function* walkJsonSessionFiles() {
  const state = resolveDirState(SESSIONS_DIR);
  if (state === "broken") { yield { file: SESSIONS_DIR, broken: true }; return; }
  if (state !== "ok") return; // no sessions/ yet — normal, not broken

  let entries;
  try { entries = fs.readdirSync(SESSIONS_DIR, { withFileTypes: true }); }
  catch { yield { file: SESSIONS_DIR, broken: true }; return; }

  for (const e of entries) {
    // Covers both sessions.json (the index) and <uuid>.json (per-session
    // history) — readLines() tells them apart by filename, see below.
    if (!e.name.endsWith(".json")) continue;
    const file = path.join(SESSIONS_DIR, e.name);
    if (!e.isFile()) {
      const resolved = isFileFollowingSymlink(file, e);
      if (!resolved) {
        if (e.isSymbolicLink()) yield { file, broken: true };
        continue;
      }
    }
    let stat;
    try { stat = fs.statSync(file); } catch { yield { file, broken: true }; continue; }
    yield { file, mtimeMs: stat.mtimeMs, sizeBytes: stat.size, broken: false };
  }
}

/**
 * Yield one files()-shaped entry for a single `.jsonl` candidate, handling
 * the symlink-following/broken-reporting the same way every other file
 * entry in this project does. `dirent` is the Dirent from whichever
 * readdirSync produced this entry.
 */
function* yieldJsonlEntry(file, dirent) {
  if (!dirent.isFile()) {
    const resolved = isFileFollowingSymlink(file, dirent);
    if (!resolved) {
      if (dirent.isSymbolicLink()) yield { file, broken: true };
      return;
    }
  }
  let stat;
  try { stat = fs.statSync(file); } catch { yield { file, broken: true }; return; }
  yield { file, mtimeMs: stat.mtimeMs, sizeBytes: stat.size, broken: false };
}

/**
 * dev_data/ holds Continue's local interaction-event log — one `.jsonl`
 * file per event type, written on by default (see the header docstring,
 * point 1's `core/data/log.ts` note). The real, documented layout nests
 * these one level down by schema version — `dev_data/<version>/<event>.jsonl`
 * (`getDevDataFilePath()` in paths.ts) — but that version string
 * ("0.2.0" today) is exactly the kind of value likely to drift across
 * Continue releases the way cursor.js's own docstring describes already
 * happening to Cursor's key names; deliberately NOT hard-coded here.
 * Instead this walks two levels: any `.jsonl` sitting directly in dev_data/
 * (in case a future/older layout is flatter), and one directory down inside
 * whatever subdirectories dev_data/ actually contains right now, whatever
 * they're named.
 */
function* walkDevDataFiles() {
  const state = resolveDirState(DEV_DATA_DIR);
  if (state === "broken") { yield { file: DEV_DATA_DIR, broken: true }; return; }
  if (state !== "ok") return; // no dev_data/ yet — normal, not broken

  let topEntries;
  try { topEntries = fs.readdirSync(DEV_DATA_DIR, { withFileTypes: true }); }
  catch { yield { file: DEV_DATA_DIR, broken: true }; return; }

  for (const e of topEntries) {
    const p = path.join(DEV_DATA_DIR, e.name);

    if (e.name.endsWith(".jsonl")) {
      yield* yieldJsonlEntry(p, e);
      continue;
    }

    if (!isDirFollowingSymlink(p, e)) {
      if (e.isSymbolicLink()) yield { file: p, broken: true };
      continue; // some other stray entry — out of scope, not broken
    }

    let innerEntries;
    try { innerEntries = fs.readdirSync(p, { withFileTypes: true }); }
    catch { yield { file: p, broken: true }; continue; }

    for (const ie of innerEntries) {
      if (!ie.name.endsWith(".jsonl")) continue;
      yield* yieldJsonlEntry(path.join(p, ie.name), ie);
    }
  }
}

/**
 * Yield { file, mtimeMs, sizeBytes, broken } for every candidate file this
 * source knows about: session history JSON (sessions/) and default-on
 * interaction-event JSONL (dev_data/). See CONTRIBUTING.md and the header
 * docstring above for what's deliberately excluded.
 */
function* files() {
  yield* walkJsonSessionFiles();
  yield* walkDevDataFiles();
}

// dev_data/*.jsonl is a genuinely line-delimited, append-only log (grows
// with every autocomplete/chat/tool-use event Continue records), so it gets
// the same bounds claude-code.js uses for its own append-only transcripts —
// by analogy, not because a real multi-GB dev_data file was observed; no
// install existed to observe one against (see header docstring).
const MAX_JSONL_BYTES = 2 * 1024 * 1024 * 1024; // 2GB
// sessions/*.json is one whole JSON document per file (a single session's
// history, or the sessions.json index) — not append-only in the same way,
// and has no real large example to size this against either. Generous
// backstop against a corrupted/pathological file, same admitted status as
// cursor.js's own MAX_DB_BYTES.
const MAX_JSON_DOC_BYTES = 512 * 1024 * 1024;
const READ_TIMEOUT_MS = 60_000;

/**
 * Read a genuinely line-delimited `.jsonl` file (dev_data/) exactly the way
 * claude-code.js reads its JSONL transcripts — see that file's docstring
 * for the full reasoning (streaming over readFileSync+split because a real
 * 818MB transcript overflowed V8's single-string limit; the destroy-on-timeout
 * timer because nothing in Node's stream/readline stack times out on its
 * own). Reused verbatim here rather than imported, per this project's
 * one-small-self-contained-file-per-source convention.
 */
async function readJsonlFile(file) {
  let stat;
  try { stat = fs.statSync(file); }
  catch { return { lines: [], status: "failed", bytesRead: 0 }; }
  if (stat.size > MAX_JSONL_BYTES) return { lines: [], status: "too-large", bytesRead: 0 };

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
 * Turn a parsed sessions.json index (expected: BaseSessionMetadata[]) into
 * one scanned "line" per entry. Falls back to a single line for the whole
 * parsed value if it isn't the expected array shape (e.g. an older/newer
 * index format) — still scanned, just not decomposed per-entry.
 */
function linesFromSessionsIndex(parsed) {
  if (Array.isArray(parsed)) return parsed.map((entry) => JSON.stringify(entry));
  return [JSON.stringify(parsed)];
}

/**
 * Turn a parsed individual session document (expected: Session, per
 * core/index.d.ts — sessionId/title/workspaceDirectory/history[]/...) into
 * one line per ChatHistoryItem in `history`, plus one line for everything
 * else in the document (title, workspaceDirectory, mode, chatModelTitle,
 * usage) so a secret sitting somewhere outside `history` — implausible, but
 * this project's whole point is not assuming — still gets scanned. Falls
 * back to a single line for the whole parsed value if `history` isn't an
 * array (older/corrupted format).
 */
function linesFromSessionDocument(parsed) {
  if (!parsed || typeof parsed !== "object" || !Array.isArray(parsed.history)) {
    return [JSON.stringify(parsed)];
  }
  const { history, ...rest } = parsed;
  const lines = [JSON.stringify(rest)];
  for (const item of history) lines.push(JSON.stringify(item));
  return lines;
}

/**
 * Read one whole JSON document file (sessions/sessions.json or
 * sessions/<uuid>.json) and flatten it into scanned "lines" — see
 * linesFromSessionsIndex/linesFromSessionDocument above for how, chosen by
 * filename the same way files() constructs these two kinds of paths.
 *
 * Unlike readJsonlFile above, this can't match patterns against the file as
 * it streams in — the file is one JSON document, not one record per line,
 * so it must be fully assembled before JSON.parse can run at all. It still
 * streams the raw bytes in (rather than fs.readFileSync) so the same
 * destroy-on-timeout protection applies to a file whose read might hang
 * (e.g. a symlink retargeted onto a FIFO with no writer, same scenario
 * claude-code.js's docstring describes) — the read is bounded even though
 * the eventual JSON.parse of the fully-assembled text is not.
 *
 * If the assembled text fails to parse as JSON (corrupted file, or a
 * genuinely different/older format than core/index.d.ts describes), the
 * raw text is scanned as a single line rather than discarded — every byte
 * that was actually read off disk is still scanned, just not decomposed
 * into per-message lines. Status is "complete" in that case: reading the
 * file did succeed start to finish, it just isn't the JSON shape assumed.
 */
async function readJsonDocumentFile(file) {
  let stat;
  try { stat = fs.statSync(file); }
  catch { return { lines: [], status: "failed", bytesRead: 0 }; }
  if (stat.size > MAX_JSON_DOC_BYTES) return { lines: [], status: "too-large", bytesRead: 0 };

  let text = "";
  let tooLarge = false;
  const stream = fs.createReadStream(file, { encoding: "utf-8" });
  const timer = setTimeout(() => stream.destroy(new Error("read timed out")), READ_TIMEOUT_MS);

  // Resolves exactly once, from whichever of 'end'/'error' fires first —
  // 'error' also covers the timeout/size-cap destroy() calls above, since
  // destroying a stream mid-read emits 'error', not a silent 'close'.
  const readCleanly = await new Promise((resolve) => {
    stream.on("data", (chunk) => {
      text += chunk;
      if (!tooLarge && Buffer.byteLength(text, "utf-8") > MAX_JSON_DOC_BYTES) {
        tooLarge = true;
        stream.destroy();
      }
    });
    stream.once("end", () => resolve(true));
    stream.once("error", () => resolve(false));
  });
  clearTimeout(timer);

  if (tooLarge) return { lines: [], status: "too-large", bytesRead: 0 };

  const bytesRead = Buffer.byteLength(text, "utf-8");
  if (!readCleanly && bytesRead === 0) return { lines: [], status: "failed", bytesRead: 0 };

  const isIndex = path.basename(file) === "sessions.json" && path.dirname(file) === SESSIONS_DIR;
  // A read that didn't finish cleanly (timed out, or errored partway) still
  // handed us real bytes off disk — scan them rather than discard them,
  // same principle as claude-code.js's own partial-read handling, just
  // applied to a whole-document read instead of a line-by-line one.
  const status = readCleanly ? "complete" : "partial";

  if (text.length === 0) return { lines: [], status, bytesRead };

  try {
    const parsed = JSON.parse(text);
    const lines = isIndex ? linesFromSessionsIndex(parsed) : linesFromSessionDocument(parsed);
    return { lines, status, bytesRead };
  } catch {
    // Not valid JSON — corrupted, truncated by a timeout/error partway
    // through, or a genuinely different format than core/index.d.ts
    // describes. Whatever text WAS read is real content and may contain a
    // real secret; scan it as one raw line rather than discarding it just
    // because it didn't parse.
    return { lines: [text], status, bytesRead };
  }
}

async function readLines(file) {
  if (file.endsWith(".jsonl")) return readJsonlFile(file);
  return readJsonDocumentFile(file);
}

module.exports = { id, label, available, files, readLines };
