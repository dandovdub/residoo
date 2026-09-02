"use strict";

const fs = require("fs");
const { createInterface } = require("readline/promises");
const path = require("path");
const os = require("os");

/**
 * Open Interpreter (the classic Python "natural language interface for
 * computers" CLI, `pip install open-interpreter`, entry point `interpreter`).
 *
 * VERIFICATION STATUS: NOT installed on the machine this adapter was built on
 * (checked: no `interpreter`/`open-interpreter` on PATH, no `open-interpreter`
 * in `pip3 list`, no conversations directory under any of the paths below).
 * Ships anyway per CONTRIBUTING.md rule 3, on unusually strong grounds for an
 * "unverified" source: not a description of the tool, but the tool's own
 * source code, read directly, plus a real, on-this-machine execution of the
 * exact path-resolution call the tool itself makes at import time (only the
 * `interpreter.chat()` LLM round-trip itself was not exercised, since that
 * needs a model API key this research had no reason to acquire):
 *
 *  - `interpreter/core/core.py` (fetched from the real GitHub history, tag
 *    v0.4.2 — see the naming note below) confirms conversation logging is ON
 *    by default (`conversation_history=True` in `OpenInterpreter.__init__`)
 *    and shows the exact write path: after every `chat()` turn, the full
 *    `self.messages` list is re-serialized whole with `json.dump(self.messages, f)`
 *    to `<conversation_history_path>/<conversation_filename>`, where the
 *    filename is `<first-25-chars-of-first-message-slug>__<Month_DD_YYYY_HH-MM-SS>.json`
 *    and `conversation_history_path` defaults to `get_storage_path("conversations")`.
 *  - `interpreter/terminal_interface/utils/local_storage_path.py` confirms
 *    `get_storage_path(sub)` is `os.path.join(platformdirs.user_config_dir("open-interpreter"), sub)`
 *    — i.e. a single call into the third-party `platformdirs` library, not a
 *    hand-rolled per-OS branch.
 *  - `interpreter/terminal_interface/conversation_navigator.py` and
 *    `.../utils/get_conversations.py` both independently confirm the
 *    directory is listed non-recursively for `*.json` files — no subfolders,
 *    no other extension.
 *  - `platformdirs`' OWN source (tox-dev/platformdirs, macos.py/windows.py/
 *    unix.py + api.py, fetched and read directly) confirms, for a call with
 *    only an appname (no appauthor) exactly like this one:
 *      * macOS: `user_config_dir` == `user_data_dir` == `~/Library/Application
 *        Support/<appname>` (macOS doesn't split these the way XDG does).
 *      * Linux/XDG: `$XDG_CONFIG_HOME/<appname>` or `~/.config/<appname>`.
 *      * Windows: `user_config_dir` == `user_data_dir`; `appauthor` defaults
 *        to `appname` when omitted (confirmed from platformdirs' own
 *        `api.py` docstring), giving `%LOCALAPPDATA%\<appname>\<appname>`.
 *  - REAL execution, on this machine, of the literal call `core.py` makes:
 *    a throwaway venv with only `platformdirs` installed (a zero-dependency,
 *    pure-path-math package — not the multi-hundred-MB `open-interpreter`
 *    package itself, which was not worth installing just to import one
 *    function) ran `platformdirs.user_config_dir("open-interpreter")` and
 *    printed `/Users/Dan/Library/Application Support/open-interpreter` —
 *    exactly matching the macOS formula derived from source above. The venv
 *    was deleted after use; nothing from it is installed anymore.
 *  - PyPI's `open-interpreter` project page confirms the latest release is
 *    0.4.3 (2024-10-26) — i.e. this scheme, introduced in v0.3.0 (see below),
 *    is still what today's `pip install open-interpreter` ships.
 *
 * NAMING TRAP, resolved during this research: the GitHub org this project
 * lived under (`openinterpreter`) was reused in 2026 for an unrelated, brand
 * new Rust rewrite ("a coding agent for open models like Kimi K3", built on
 * OpenAI's open-sourced Codex CLI — its repo tree is full of `codex-rs/*`
 * paths). That is NOT this tool. This adapter targets the classic Python
 * package the task actually asked for ("Python-based local-execution agent"),
 * reached via the org's still-intact git tag history (tag `v0.4.2`, the last
 * one cut before the rewrite) rather than the `main` branch, which now holds
 * the unrelated project.
 *
 * VERSION DRIFT, checked and deliberately scoped around: fetching
 * `local_storage_path.py` at old tags shows v0.1.x/v0.2.x used a DIFFERENT
 * library and app name — `appdirs.user_config_dir("Open Interpreter")`
 * (capitalized, space, no hyphen) — before v0.3.0 switched to the
 * `platformdirs` + `"open-interpreter"` scheme this adapter targets as
 * current. That legacy scheme was itself verified the same way: real
 * execution on this machine (`appdirs.user_config_dir("Open Interpreter")`
 * printed `/Users/Dan/Library/Application Support/Open Interpreter` — note
 * the differing capitalization from the current path) plus reading appdirs'
 * own source for its Windows/Linux formulas. Both schemes read `conversations/`
 * for `*.json` files the same way in both eras (confirmed directly from
 * source at old and new tags alike), so this source scans both directories
 * rather than picking one — the same "format moved, so read every location
 * it has lived" choice cursor.js and gemini-cli.js make for their own
 * cross-version drift.
 */
function platformdirsConfigDir(appname) {
  const home = os.homedir();
  if (process.platform === "darwin") {
    return path.join(home, "Library", "Application Support", appname);
  }
  if (process.platform === "win32") {
    // appauthor is never passed by Open Interpreter's own call, so
    // platformdirs falls back to using appname as the author too (confirmed
    // from platformdirs' api.py docstring) — hence the doubled segment.
    const base = process.env.LOCALAPPDATA || path.join(home, "AppData", "Local");
    return path.join(base, appname, appname);
  }
  // Linux and other XDG-following unix platforms.
  const configHome = process.env.XDG_CONFIG_HOME || path.join(home, ".config");
  return path.join(configHome, appname);
}

const CURRENT_CONVERSATIONS_DIR = path.join(platformdirsConfigDir("open-interpreter"), "conversations");
const LEGACY_CONVERSATIONS_DIR = path.join(platformdirsConfigDir("Open Interpreter"), "conversations");

// Bounds for readLines() — same shape as claude-code.js's, but the number is
// NOT backed by a real large Open Interpreter conversation file this tool
// was tested against (no install available). A single conversation file here
// is a whole-session JSON re-dump, not an append-only log, so it is expected
// to be far smaller than a multi-session JSONL transcript in practice — this
// is a generous, untested backstop against a pathological file, not evidence
// of what real files look like.
const MAX_BYTES = 2 * 1024 * 1024 * 1024; // 2GB
const READ_TIMEOUT_MS = 60_000;

function id() { return "open-interpreter"; }
function label() { return "Open Interpreter"; }

function available() {
  return dirExists(CURRENT_CONVERSATIONS_DIR) || dirExists(LEGACY_CONVERSATIONS_DIR);
}

function dirExists(p) {
  try { return fs.statSync(p).isDirectory(); } catch { return false; }
}

/**
 * Same defensive symlink-following pattern as claude-code.js — see that
 * file's docstring for the full reasoning. Duplicated rather than imported:
 * each source here is meant to be a small, self-contained file a reviewer
 * can audit on its own (see CONTRIBUTING.md).
 */
function isFileFollowingSymlink(fullPath, dirent) {
  if (dirent.isFile()) return true;
  if (!dirent.isSymbolicLink()) return false;
  try { return fs.statSync(fullPath).isFile(); } catch { return false; }
}

/**
 * Yield { file, mtimeMs, sizeBytes, broken } for every `*.json` file directly
 * inside one conversations directory — flat, non-recursive, matching
 * `get_conversations.py`'s own `os.listdir(...)` + `.endswith(".json")`
 * exactly (no subfolder nesting exists in this format at either the current
 * or legacy path).
 */
function* walkConversationsDir(dir) {
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); }
  catch { return; } // directory doesn't exist — not broken, just nothing here yet

  for (const e of entries) {
    if (!e.name.endsWith(".json")) continue;
    const file = path.join(dir, e.name);
    if (!isFileFollowingSymlink(file, e)) {
      if (e.isSymbolicLink()) yield { file, broken: true };
      continue;
    }
    let stat;
    try { stat = fs.statSync(file); } catch { yield { file, broken: true }; continue; }
    yield { file, mtimeMs: stat.mtimeMs, sizeBytes: stat.size, broken: false };
  }
}

/**
 * Yields every `*.json` conversation file under both the current
 * (platformdirs) and legacy (appdirs) conversations directories — see the
 * module docstring for why both are read. When both directories happen to
 * resolve to the exact same path (impossible here since the app names differ
 * in case/hyphenation on every supported OS, but guarded anyway in case a
 * future platformdirs/appdirs release ever changes that), the second walk is
 * skipped rather than double-yielding every file in it.
 */
function* files() {
  yield* walkConversationsDir(CURRENT_CONVERSATIONS_DIR);
  if (LEGACY_CONVERSATIONS_DIR !== CURRENT_CONVERSATIONS_DIR) {
    yield* walkConversationsDir(LEGACY_CONVERSATIONS_DIR);
  }
}

/**
 * Read one conversation file as an array of raw text lines. Identical
 * streaming strategy to claude-code.js's readLines (a JSON file on disk is
 * still line-delimited text as far as a byte stream is concerned) — see that
 * file's docstring for the full reasoning behind streaming + a hard timeout.
 *
 * In practice, `json.dump(self.messages, f)` is called with no `indent=`, so
 * the whole file is one single physical line (Python's json module escapes
 * embedded newlines inside string values as `\n`, it doesn't emit them raw)
 * — that's fine: the pattern-matcher works on raw text regardless of how
 * many physical lines it's split across, exactly per the adapter contract
 * cursor.js's docstring already spells out for a whole-document-per-row case.
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
    // Whatever WAS read before the failure is real content and may contain a
    // real secret — discarding it because the file didn't finish cleanly
    // would be a silent false negative, which is worse than an honest
    // "partial" label.
    return { lines, status: lines.length > 0 ? "partial" : "failed", bytesRead };
  } finally {
    clearTimeout(timer);
    rl.close();
    stream.destroy();
  }
}

module.exports = { id, label, available, files, readLines };
