"use strict";

const fs = require("fs");
const { createInterface } = require("readline/promises");
const path = require("path");
const os = require("os");

/**
 * Roo Code (VS Code extension, a community fork of Cline) session history.
 *
 * VERIFICATION STATUS: read directly out of Roo Code's own current source on
 * GitHub (RooCodeInc/Roo-Code) during this source's research, not guessed
 * from Cline's near-identical layout even though the two are in fact close:
 *   - src/package.json — `"name": "roo-cline"`, `"publisher":
 *     "RooVeterinaryInc"`. VS Code lowercases publisher.name when it names
 *     the on-disk globalStorage folder, so the real folder is
 *     `rooveterinaryinc.roo-cline`, not the mixed-case form the manifest
 *     declares — corroborated independently by a real user's own reported
 *     path in a GitHub issue about disk usage
 *     (`~/.vscode-server/data/User/globalStorage/rooveterinaryinc.roo-cline/tasks`,
 *     RooCodeInc/Roo-Code#4174), i.e. an actual observed path from an actual
 *     install, not just the manifest's declared casing.
 *   - src/shared/globalFileNames.ts — the per-task filenames below.
 *   - src/core/task-persistence/TaskHistoryStore.ts — its own doc comment
 *     states the exact layout verbatim: "Each task's HistoryItem is stored
 *     as an individual JSON file in its existing task directory
 *     (`globalStorage/tasks/<taskId>/history_item.json`). A single index
 *     file (`globalStorage/tasks/_index.json`) is maintained as a cache for
 *     fast list reads at startup."
 * What this could NOT be checked against: a real Roo Code install on the
 * machine this source was built on — VS Code itself isn't installed there.
 * See CONTRIBUTING.md for what "verified" is supposed to mean and treat
 * findings from this source accordingly until someone with Roo Code actually
 * installed confirms it against real data.
 *
 * Roo Code writes one JSON file per concern into a per-task directory under
 * its extension's VS Code globalStorage folder, plus one root-level index:
 *
 *   <VS Code User dir>/globalStorage/rooveterinaryinc.roo-cline/tasks/
 *     _index.json                     - cache of every task's HistoryItem
 *     <taskId>/
 *       api_conversation_history.json - full message history sent to the model
 *       ui_messages.json              - the rendered chat transcript
 *       history_item.json             - this task's own HistoryItem record
 *       task_metadata.json            - files touched, model/token usage
 *
 * Filenames inside a task directory are deliberately NOT allow-listed beyond
 * "every *.json file directly inside tasks/<taskId>/": this fork has already
 * added fields over time (history_item.json is a comparatively recent
 * addition per its own source comment above) and hard-coding today's list is
 * exactly the kind of thing likely to go stale the same way cursor.js's
 * docstring describes for Cursor's own key names. `_index.json` is one level
 * up, directly inside tasks/, so it is checked separately rather than by the
 * per-task glob. A task's `checkpoints/` subdirectory (shadow-git snapshots
 * used for file revert) is deliberately NOT walked — those are git object
 * stores, not text transcripts.
 *
 * Base directory: VS Code has a portable/remote/Insiders/fork multiverse of
 * possible per-profile "User" directories. This source checks the two by far
 * most common ones on each OS — standard VS Code ("Code") and VS Code
 * Insiders ("Code - Insiders") — and deliberately does NOT attempt every
 * fork (VSCodium, etc.) or the separate ~/.vscode-server tree used by
 * remote-SSH sessions (even though the corroborating GitHub issue above
 * happens to be exactly that case) — a named, narrower scope rather than a
 * guess at an exhaustive list.
 *
 * Also named rather than silently assumed: Roo Code supports a configurable
 * custom storage base path (per open GitHub issues discussing it) that would
 * move all of the above somewhere this source does not check. That is a
 * real, acknowledged gap, not a silent one.
 */
const EXT_ID = "rooveterinaryinc.roo-cline";

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

// Bounds for readLines() — same rationale and same values as claude-code.js.
// Not backed by a real Roo Code transcript this tool was tested against (no
// install to test with) — see the verification-status note above.
const MAX_BYTES = 2 * 1024 * 1024 * 1024; // 2GB
const READ_TIMEOUT_MS = 60_000;

function id() { return "roo-code"; }
function label() { return "Roo Code"; }

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
 * Resolve one constructed file path (not a directory-listing Dirent) into
 * zero or one files() entries — used for tasks/_index.json, which is a fixed
 * filename rather than something discovered by listing a directory. Same
 * convention as cursor.js's statIfPresent: a path that simply doesn't exist
 * yields nothing (normal — e.g. an install old enough to predate this file),
 * `broken: true` is reserved for a path that looked like it should resolve
 * and didn't (a dangling symlink).
 */
function* statIfPresent(filePath) {
  let lst;
  try { lst = fs.lstatSync(filePath); }
  catch { return; }

  if (lst.isSymbolicLink()) {
    try {
      const st = fs.statSync(filePath);
      if (!st.isFile()) { yield { file: filePath, broken: true }; return; }
      yield { file: filePath, mtimeMs: st.mtimeMs, sizeBytes: st.size, broken: false };
    } catch {
      yield { file: filePath, broken: true };
    }
    return;
  }

  if (!lst.isFile()) return;
  yield { file: filePath, mtimeMs: lst.mtimeMs, sizeBytes: lst.size, broken: false };
}

/**
 * Yield { file, mtimeMs, sizeBytes, broken } for tasks/_index.json and every
 * *.json file directly inside every task directory, across every candidate
 * VS Code User dir.
 *
 * broken:true marks a tasks/ entry or a *.json entry that looked like it
 * should resolve (chiefly a dangling symlink) but didn't — never silently
 * skipped, same convention as claude-code.js and cursor.js.
 */
function* files() {
  for (const tasksDir of tasksDirs()) {
    yield* statIfPresent(path.join(tasksDir, "_index.json"));

    let taskEntries;
    try { taskEntries = fs.readdirSync(tasksDir, { withFileTypes: true }); }
    catch { continue; } // this VS Code variant/profile simply has no Roo Code tasks dir — normal, not broken

    for (const taskEntry of taskEntries) {
      if (taskEntry.name === "_index.json") continue; // already handled above
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
 * Roo Code writes these via a JSON-with-indentation writer (safeWriteJson,
 * confirmed used by TaskHistoryStore.ts) — real multi-line, indented text,
 * not a single giant line — so the same streamed readline/promises approach
 * claude-code.js uses for JSONL applies here essentially unchanged, and gets
 * the same benefits: no whole-file-as-one-string V8 string-length ceiling,
 * and a partial read (the file started streaming but the read failed
 * partway) still returns whatever lines WERE read rather than discarding
 * real content.
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
