"use strict";

const fs = require("fs");
const path = require("path");
const os = require("os");

/**
 * Sourcegraph Cody — the VS Code extension (publisher.name `sourcegraph.cody-ai`).
 *
 * VERIFICATION STATUS (read this before trusting anything below):
 * multi-source-corroborated-but-UNVERIFIED against a real install. Neither VS
 * Code nor the Cody extension is installed on the machine this adapter was
 * built on (checked: no /Applications/*Code*.app, no `code`/`code-insiders`
 * on PATH, no ~/Library/Application Support/Code, no
 * ~/.vscode/extensions/sourcegraph.cody-ai-*, no
 * ~/Library/Application Support/JetBrains/<product>/options/cody_history.xml).
 * What
 * IS unusually strong here, short of a real install: the storage mechanism
 * was read directly out of two projects' own current shipped source — not
 * inferred from a blog post — cross-checked against Sourcegraph's own docs:
 *
 *   1. CODY'S OWN SOURCE, read directly from
 *      github.com/sourcegraph/cody-public-snapshot (`main`,
 *      vscode/src/services/LocalStorageProvider.ts, fetched verbatim via
 *      `gh api repos/sourcegraph/cody-public-snapshot/contents/...` on
 *      2026-09-02): the class keeps
 *        `protected readonly KEY_LOCAL_HISTORY = 'cody-local-chatHistory-v2'`
 *      and every read/write of chat history
 *      (getChatHistory/setChatHistory/deleteChatHistory) goes through
 *      `this.storage.get/update(this.KEY_LOCAL_HISTORY, ...)`, where
 *      `this.storage` is set, once, at extension activation via
 *      `localStorage.setStorage(context.globalState)` (see the same file,
 *      `activate()`/`initVSCodeStorage()` in `LocalStorageProvider.ts` and
 *      `extension.node.ts`) — i.e. the standard VS Code extension `Memento`
 *      API (`context.globalState`), not a bespoke file Cody writes itself.
 *      `vscode/package.json` (same repo, same fetch) confirms the extension's
 *      identity: `"name": "cody-ai"`, `"publisher": "sourcegraph"` — VS
 *      Code's own `getExtensionId(publisher, name)` (see next point) makes
 *      that `sourcegraph.cody-ai`, matching the `globalStorage/
 *      sourcegraph.cody-ai/` path fragment independently named in
 *      Sourcegraph's own troubleshooting docs
 *      (sourcegraph.com/docs/cody/troubleshooting, a real user's globalStorage
 *      resource path is quoted there verbatim).
 *
 *   2. VS CODE'S OWN SOURCE for what `context.globalState` actually resolves
 *      to on disk, read directly from github.com/microsoft/vscode (`main`,
 *      fetched the same way, 2026-09-02):
 *        - `src/vs/workbench/api/browser/mainThreadStorage.ts` —
 *          `$setValue(shared, key, value)` calls
 *          `extensionStorageService.setExtensionState(key, value, shared)`,
 *          where `key` here is the calling extension's id, not a
 *          caller-chosen storage key.
 *        - `src/vs/platform/extensionManagement/common/extensionStorage.ts`
 *          — `setExtensionState(extension, state, global)` resolves
 *          `extensionId = getExtensionId(extension)` and then does
 *          `storageService.store(extensionId, JSON.stringify(state),
 *          global ? StorageScope.PROFILE : StorageScope.WORKSPACE, ...)`.
 *          `getExtensionId(publisher, name)` (`extensionManagementUtil.ts`)
 *          is exactly `` `${publisher}.${name}` ``.
 *        - Net effect: EVERY globalState key an extension sets (Cody's
 *          `cody-local-chatHistory-v2` included) is merged into ONE JSON
 *          object, and that whole object is stored as a SINGLE row, keyed by
 *          the extension id itself, in the PROFILE-scope storage — which is
 *          the same shared, per-profile `state.vscdb` / `ItemTable` that
 *          cursor.js already reads for Cursor's own tables in this project
 *          (Cursor is a VS Code fork; this is the un-forked, upstream version
 *          of that exact mechanism). This is CORE VS Code behavior, not
 *          Cody-specific or version-fragile the way Cursor's own bespoke
 *          `cursorDiskKV` table naming has reportedly been (see cursor.js).
 *
 * Net path: `<VS Code User dir>/globalStorage/state.vscdb`, table
 * `ItemTable`, one row with `key = 'sourcegraph.cody-ai'` whose `value` is a
 * JSON object containing (among any other keys the extension has ever set)
 * `cody-local-chatHistory-v2` — every chat transcript title, message, and any
 * pasted code/output the user has had Cody see.
 *
 * Deliberately scoped to VS Code only. Cody also ships a JetBrains plugin,
 * but its chat history lives in a fundamentally different place: read
 * directly from the same cody-public-snapshot repo,
 * `jetbrains/src/main/kotlin/com/sourcegraph/cody/history/HistoryService.kt`
 * declares `@State(name = "ChatHistory", storages =
 * [Storage("cody_history.xml")])` at `@Service(Service.Level.PROJECT)` —
 * PROJECT level, meaning one `cody_history.xml` per JetBrains project
 * (typically under that project's own `.idea/` directory), not one file
 * under a single, enumerable user-profile directory the way every other
 * source in this project works. Finding those would mean either scanning the
 * whole filesystem for `.idea/cody_history.xml` or trusting a JetBrains
 * "recent projects" list — neither verified here and both a meaningfully
 * different shape of problem — so it is left out rather than guessed at. See
 * CONTRIBUTING.md.
 *
 * Only the DEFAULT VS Code profile is covered, for the same reason
 * copilot-chat.js in this project already gives for itself: a non-default
 * profile's globalStorage lives under `User/profiles/<profileId>/...`
 * instead of `User/globalStorage` directly, per
 * `IUserDataProfilesService.defaultProfile` in the same VS Code source read
 * above.
 */
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
  // Linux and other XDG-following unix platforms.
  const configHome = process.env.XDG_CONFIG_HOME || path.join(home, ".config");
  return variants.map((v) => path.join(configHome, v, "User"));
}

function id() { return "cody"; }
function label() { return "Sourcegraph Cody"; }

/**
 * Same lazy-require pattern as cursor.js, for the same reason: index.js
 * requires every source unconditionally, so an eager top-level
 * `require("node:sqlite")` would print Node's one-per-process
 * ExperimentalWarning for every user on Node 22.5+, even the large majority
 * who have never installed VS Code at all. See cursor.js's own docstring on
 * getDatabaseSync() for the full reasoning — duplicated here rather than
 * imported, matching this project's "small, self-contained file" convention.
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

function anyVscodeUserDirExists() {
  return vscodeUserDirs().some((dir) => {
    try { return fs.statSync(dir).isDirectory(); } catch { return false; }
  });
}

function available() {
  // Cheap fs check first, on purpose — see cursor.js's available() for why
  // short-circuiting here matters (skip requiring node:sqlite, and its
  // possible warning, when there is plainly nothing to read).
  return anyVscodeUserDirExists() && Boolean(getDatabaseSync());
}

/**
 * Same optional, additive contract as cursor.js's unavailableReason() — see
 * that file's docstring. Only fires for the one case worth calling out: a VS
 * Code User dir genuinely exists but this Node runtime is too old for
 * node:sqlite, so silently vanishing from "Sources checked" would misread as
 * "VS Code isn't installed," which would be false.
 */
function unavailableReason() {
  if (!anyVscodeUserDirExists()) return null;
  if (getDatabaseSync()) return null;
  return `Sourcegraph Cody detected but not scanned — ${NODE_SQLITE_REQUIREMENT}`;
}

/**
 * Same defensive symlink-following stat, duplicated from cursor.js's
 * statIfPresent — see that file's docstring for the full reasoning. A path
 * that doesn't exist yields nothing (normal: e.g. no "Code - Insiders" User
 * dir because Insiders was never installed); a dangling symlink is reported
 * `broken: true` rather than silently skipped.
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
 * Yield { file, mtimeMs, sizeBytes, broken } for the default profile's
 * state.vscdb under every VS Code variant this adapter checks (standard +
 * Insiders). Purely a filesystem walk + stat — never opens the database, so
 * it works even in a Node runtime where node:sqlite isn't available (only
 * readLines() actually needs it, same division of labour as cursor.js).
 */
function* files() {
  for (const userDir of vscodeUserDirs()) {
    yield* statIfPresent(path.join(userDir, "globalStorage", "state.vscdb"));
  }
}

// Not backed by a real Cody state.vscdb row this tool was tested against (no
// VS Code install to test with) — see the verification-status note above.
// Generous backstop against a corrupted/pathological file, same rationale as
// cursor.js's own MAX_DB_BYTES.
const MAX_DB_BYTES = 512 * 1024 * 1024;
const READ_TIMEOUT_MS = 60_000;
const BUSY_TIMEOUT_MS = 5_000;

/**
 * Cody's extension id is `sourcegraph.cody-ai` (verified directly against
 * vscode/package.json — see the module docstring). The LIKE clause is a
 * deliberately narrow safety margin, not a guess-widening: it catches a
 * differently-suffixed Sourcegraph Cody extension id (e.g. a possible future
 * `sourcegraph.cody-ai-nightly`-style variant) without sweeping in any other
 * publisher's or extension's state the way reading the whole ItemTable
 * (cursor.js's approach, appropriate there because Cursor owns that entire
 * file) would for a shared, multi-extension file like this one.
 */
const CODY_KEY_PATTERN = "sourcegraph.cody%";

/**
 * Same storage-class handling as cursor.js's valueToText — see that file's
 * docstring. A PROFILE-scope row here is written via
 * `JSON.stringify(state)` (see module docstring), i.e. always a JS string
 * (TEXT storage class) in every real case this adapter's research found, but
 * the BLOB fallback is kept for parity with cursor.js and cheap insurance
 * against a SQLite storage-class surprise.
 */
function valueToText(value) {
  if (typeof value === "string") return value;
  if (value instanceof Uint8Array) return Buffer.from(value).toString("utf-8");
  return null;
}

/**
 * Read one state.vscdb's Cody-owned row(s) as an array of raw text "lines" —
 * one per matching ItemTable row's decoded value (in practice, at most one:
 * a single row keyed `sourcegraph.cody-ai` holding a JSON object with every
 * globalState key the extension has ever set, `cody-local-chatHistory-v2`
 * included). Returns { lines, status, bytesRead } with the same status
 * vocabulary as every other source in this project.
 *
 * Synchronous node:sqlite, same "no real preemptive timeout possible, so
 * check a wall-clock deadline between statements" approach as cursor.js —
 * see that file's docstring. With at most a handful of matching rows here
 * (unlike cursor.js's tens-of-thousands-of-rows cursorDiskKV table), the
 * per-row yield-to-event-loop machinery is far less likely to matter in
 * practice, but the deadline check is kept for consistency and as insurance
 * against a single pathologically large row's own decode time — the same
 * named, un-bounded asymmetry cursor.js's own docstring admits.
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
    // Deleted between files() and this call, a corrupt/non-SQLite file at
    // this path, or VS Code holding a lock this readonly open can't get past
    // within BUSY_TIMEOUT_MS — genuinely "could not read this," not "read it,
    // found nothing." Status "failed" keeps the scan report honest about
    // that difference (CONTRIBUTING.md rule 5).
    return { lines: [], status: "failed", bytesRead: 0 };
  }

  let rows;
  try {
    rows = db.prepare("SELECT value FROM ItemTable WHERE key LIKE ?").iterate(CODY_KEY_PATTERN);
  } catch {
    // ItemTable itself doesn't exist — this file opened fine as SQLite but
    // didn't match the schema this adapter understands, a real "could not
    // extract anything," not "extracted zero real rows."
    try { db.close(); } catch { /* best-effort */ }
    return { lines: [], status: "failed", bytesRead: 0 };
  }

  const lines = [];
  let bytesRead = 0;
  const deadline = Date.now() + READ_TIMEOUT_MS;
  let timedOut = false;
  let sawError = false;
  let n = 0;

  try {
    for (const row of rows) {
      const text = valueToText(row.value);
      // One matching row becomes one scanned "line," using the value exactly
      // as VS Code wrote it — not re-parsed/re-stringified — same reasoning
      // as cursor.js: keeps every byte the regexes depend on intact, and
      // sidesteps needing to track Cody's own nested key name
      // (`cody-local-chatHistory-v2`) as it evolves across versions.
      if (text) { lines.push(text); bytesRead += Buffer.byteLength(text, "utf-8"); }
      n++;
      if (n % 500 === 0) {
        await new Promise((resolve) => setImmediate(resolve));
        if (Date.now() > deadline) { timedOut = true; break; }
      }
    }
  } catch {
    // Whatever WAS read before a mid-iteration failure (e.g. a corrupted
    // page) is real content and may contain a real secret — kept, not
    // discarded, same as claude-code.js/cursor.js.
    sawError = true;
  }

  try { db.close(); } catch { /* best-effort close */ }

  if (sawError && lines.length === 0) return { lines: [], status: "failed", bytesRead };
  if (timedOut || sawError) return { lines, status: lines.length > 0 ? "partial" : "failed", bytesRead };
  return { lines, status: "complete", bytesRead };
}

module.exports = { id, label, available, unavailableReason, files, readLines };
