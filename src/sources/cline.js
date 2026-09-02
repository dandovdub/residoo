"use strict";

const fs = require("fs");
const { createInterface } = require("readline/promises");
const path = require("path");
const os = require("os");

/**
 * Cline (VS Code extension, historically shipped as "Claude Dev") session
 * history.
 *
 * VERIFICATION STATUS: the path and file layout below were read directly out
 * of Cline's own current source on GitHub (cline/cline) during this source's
 * research — not inferred from a blog post and not guessed from Roo Code's
 * near-identical fork, even though the two are in fact near-identical.
 * Specifically:
 *   - apps/vscode/src/core/storage/disk.ts — GlobalFileNames constants and
 *     ensureTaskDirectoryExists()/getGlobalStorageDir(), which resolve
 *     through the VS Code extension's own `globalStorageUri` (NOT
 *     workspaceStorage) into `tasks/<taskId>/`.
 *   - apps/vscode/package.json — `"name": "claude-dev"`, `"publisher":
 *     "saoudrizwan"`, confirming the on-disk globalStorage folder is really
 *     still `saoudrizwan.claude-dev` (Cline shipped as "Claude Dev" and kept
 *     its original package.json identity across the product's later rename
 *     to Cline — this is NOT the same as the current "Cline" display name,
 *     and guessing `cline.cline` or similar would have been wrong).
 * What this could NOT be checked against: a real Cline install on the
 * machine this source was built on — VS Code itself isn't installed there.
 * See CONTRIBUTING.md for what "verified" is supposed to mean and treat
 * findings from this source accordingly until someone with Cline actually
 * installed confirms it against real data.
 *
 * Cline writes one JSON file per concern into a per-task directory under its
 * extension's VS Code globalStorage folder:
 *
 *   <VS Code User dir>/globalStorage/saoudrizwan.claude-dev/tasks/<taskId>/
 *     api_conversation_history.json   - full message history sent to the model
 *     ui_messages.json                - the rendered chat transcript
 *     context_history.json            - context-window bookkeeping
 *     task_metadata.json              - files touched, model/token usage
 *     settings.json                   - a per-task settings snapshot
 *
 * Filenames are deliberately NOT allow-listed beyond "every *.json file
 * directly inside tasks/<taskId>/": GlobalFileNames in Cline's own source has
 * gained entries over time (context_history.json is a relatively recent
 * addition) and hard-coding today's list is exactly the kind of thing likely
 * to go stale the same way cursor.js's docstring describes for Cursor's own
 * key names. A task's `checkpoints/` subdirectory (shadow-git snapshots used
 * for file revert) is deliberately NOT walked — those are git object stores,
 * not text transcripts.
 *
 * Base directory: VS Code has a portable/remote/Insiders/fork multiverse of
 * possible per-profile "User" directories. This source checks the two by far
 * most common ones on each OS — standard VS Code ("Code") and VS Code
 * Insiders ("Code - Insiders") — and deliberately does NOT attempt every
 * fork (VSCodium, etc.) or the separate ~/.vscode-server tree used by
 * remote-SSH sessions: a named, narrower scope rather than a guess at an
 * exhaustive list.
 *
 * Also out of scope, named rather than silently skipped: Cline's task-title
 * history INDEX (the array a "History" panel is built from) is not a plain
 * file — it is read via VS Code's own `context.globalState` API, which
 * persists into a *different*, central per-profile database
 * (globalStorage/state.vscdb, shared by every installed extension, keyed by
 * extension id) rather than anywhere under this extension's own
 * globalStorage folder. Parsing that shared, VS-Code-owned database is out of
 * scope for this source; the per-task JSON files above are where actual
 * conversation content — and anything pasted into it — lives.
 */
const EXT_ID = "saoudrizwan.claude-dev";

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

function tasksDirs() {
  return vscodeUserDirs().map((userDir) => path.join(userDir, "globalStorage", EXT_ID, "tasks"));
}

// Bounds for readLines() — same rationale and same values as claude-code.js:
// generous headroom over any real transcript, plus a hard stop against a
// hung read. Not backed by a real Cline transcript this tool was tested
// against (no install to test with) — see the verification-status note above.
const MAX_BYTES = 2 * 1024 * 1024 * 1024; // 2GB
const READ_TIMEOUT_MS = 60_000;

function id() { return "cline"; }
function label() { return "Cline"; }

function available() {
  return tasksDirs().some((dir) => {
    try { return fs.statSync(dir).isDirectory(); } catch { return false; }
  });
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

/**
 * Yield { file, mtimeMs, sizeBytes, broken } for every *.json file directly
 * inside every task directory, across every candidate VS Code User dir.
 *
 * broken:true marks a tasks/ entry or a *.json entry that looked like it
 * should resolve (chiefly a dangling symlink) but didn't — never silently
 * skipped, same convention as claude-code.js and cursor.js.
 */
function* files() {
  for (const tasksDir of tasksDirs()) {
    let taskEntries;
    try { taskEntries = fs.readdirSync(tasksDir, { withFileTypes: true }); }
    catch { continue; } // this VS Code variant/profile simply has no Cline tasks dir — normal, not broken

    for (const taskEntry of taskEntries) {
      const taskDir = path.join(tasksDir, taskEntry.name);
      if (!isDirFollowingSymlink(taskDir, taskEntry)) {
        if (taskEntry.isSymbolicLink()) yield { file: taskDir, broken: true };
        continue; // a stray non-directory entry under tasks/ is out of scope, not broken
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
 * Read one JSON file as an array of raw text lines.
 *
 * Cline writes these via `JSON.stringify(value, null, 2)` (confirmed from
 * disk.ts) — real multi-line, indented text, not a single giant line — so
 * the same streamed readline/promises approach claude-code.js uses for JSONL
 * applies here essentially unchanged, and gets the same benefits: no
 * whole-file-as-one-string V8 string-length ceiling, and a partial read (the
 * file started streaming but the read failed partway) still returns
 * whatever lines WERE read rather than discarding real content.
 *
 * Status vocabulary matches every other source in this project: "complete",
 * "partial", "too-large", "failed".
 */
async function readLines(file) {
  let stat;
  try { stat = fs.statSync(file); }
  catch { return { lines: [], status: "failed", bytesRead: 0 }; }
  if (stat.size > MAX_BYTES) return { lines: [], status: "too-large", bytesRead: 0 };

  const lines = [];
  let bytesRead = 0;
  const stream = fs.createReadStream(file, { encoding: "utf-8" });
  const rl = createInterface({ input: stream, crlfDelay: Infinity });

  // Same rationale as claude-code.js: no natural timeout exists anywhere in
  // Node's stream/readline stack, and a retargeted symlink can make the
  // underlying open() block forever with no event ever firing. Destroying
  // the stream is what actually unblocks that.
  const timer = setTimeout(() => stream.destroy(new Error("read timed out")), READ_TIMEOUT_MS);

  try {
    for await (const line of rl) {
      lines.push(line);
      bytesRead += Buffer.byteLength(line, "utf-8") + 1; // +1 for the stripped newline
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

module.exports = { id, label, available, files, readLines };
