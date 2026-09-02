"use strict";

const fs = require("fs");
const path = require("path");
const os = require("os");

/**
 * Codebuff (codebuff.com, formerly named "Manicode" — the on-disk config
 * directory still uses the old name) local chat history.
 *
 * VERIFICATION STATUS: NOT checked against a real Codebuff install — neither
 * `codebuff` nor `manicode` is on PATH, and no `~/.config/manicode*`
 * directory exists on the machine this adapter was built on (checked PATH,
 * npm -g, mdfind, the paths below directly). Ships anyway per
 * CONTRIBUTING.md rule 3, on the strength of three independent, current,
 * mutually-corroborating sources:
 *
 *  1. Codebuff's own official docs (codebuff.com/docs/advanced), which
 *     document the `CODEBUFF_DATA_DIR` override and the fact that history is
 *     scoped per "channel" (production/dev/staging).
 *  2. A real, independent, third-party tool's own written documentation of
 *     the format: CodexBar (github.com/steipete/CodexBar,
 *     docs/codebuff.md), which states conversation history "is stored
 *     locally at ~/.config/manicode/projects/<project-name>/chats" and that
 *     `~/.config/manicode/credentials.json` is written after `codebuff
 *     login` — the "formerly manicode" naming and directory layout agree
 *     exactly with source 3 below.
 *  3. The strongest source: ccusage (github.com/ccusage/ccusage, a real,
 *     independently maintained, actively developed CLI usage tracker with
 *     18k+ real GitHub stars — sanity-checked directly, not assumed) ships
 *     its OWN tested Rust adapter for Codebuff
 *     (rust/adapters/codebuff/src/{paths,parser,loader}.rs), fetched and
 *     read directly, not summarized secondhand. Its unit tests embed a real
 *     fixture file at
 *     `projects/project-a/chats/2026-01-02T03-04-05.000Z/chat-messages.json`
 *     containing actual message-object shapes
 *     (`{"role":"user","text":"hello"}`,
 *     `{"id":"...","role":"assistant","timestamp":"...","metadata":{"model":"...","usage":{...}},"credits":1.25}`)
 *     — this is a real, working, unrelated tool's reverse-engineered
 *     understanding of the exact same file this source reads, the same
 *     evidentiary bar cursor.js's own docstring cites approvingly for its
 *     own two corroborating community tools.
 *
 * Directory layout (agreed by all three sources): one root per "channel" —
 * `~/.config/manicode` (production), `~/.config/manicode-dev`,
 * `~/.config/manicode-staging` — each containing
 * `projects/<project>/chats/<chatId>/chat-messages.json`, overridable via
 * the `CODEBUFF_DATA_DIR` env var (a comma-separated list of channel roots;
 * source 1 and source 3 agree on both the env var name and its comma-list
 * shape). `chat-messages.json` is a JSON ARRAY of message objects — not
 * line-delimited — so, per the adapter-contract note about non-line-
 * delimited storage, each message object becomes one scanned "line" (see
 * extractTopLevelJsonObjects() below).
 *
 * Deliberately NOT scanned: `credentials.json` (Codebuff's own CLI auth
 * token for the logged-in account) — it is not a session transcript, and
 * every other source in this project scans transcripts only, not each
 * tool's own credential store (cursor.js, for instance, does not read
 * Cursor's OS keychain entries either).
 */
const CODEBUFF_DATA_DIR_ENV = "CODEBUFF_DATA_DIR";
const CHANNELS = ["manicode", "manicode-dev", "manicode-staging"];

function id() { return "codebuff"; }
function label() { return "Codebuff"; }

/**
 * Resolve the "projects" root for every configured channel, deduped.
 *
 * Mirrors ccusage's own `codebuff_project_roots()` exactly: when
 * CODEBUFF_DATA_DIR is set, each comma-separated entry is used as-is if its
 * basename is already "projects", otherwise "projects" is appended — this
 * lets a user point the env var either at a channel root or directly at its
 * projects subdirectory, matching Codebuff's own documented flexibility.
 */
function codebuffProjectRoots() {
  const envVal = process.env[CODEBUFF_DATA_DIR_ENV];
  let roots;
  if (envVal && envVal.trim() !== "") {
    roots = envVal
      .split(",")
      .map((s) => s.trim())
      .filter((s) => s !== "")
      .map((p) => path.resolve(p));
  } else {
    const home = os.homedir();
    roots = CHANNELS.map((channel) => path.join(home, ".config", channel));
  }

  const seen = new Set();
  const projectRoots = [];
  for (const root of roots) {
    const projectRoot = path.basename(root) === "projects" ? root : path.join(root, "projects");
    let isDir = false;
    try { isDir = fs.statSync(projectRoot).isDirectory(); } catch { isDir = false; }
    if (isDir && !seen.has(projectRoot)) {
      seen.add(projectRoot);
      projectRoots.push(projectRoot);
    }
  }
  return projectRoots;
}

function available() {
  return codebuffProjectRoots().length > 0;
}

/**
 * Same defensive symlink-following pattern as claude-code.js's
 * isDirFollowingSymlink/isFileFollowingSymlink — duplicated rather than
 * imported per this project's one-small-self-contained-file-per-source
 * convention (see cursor.js's own docstring for why).
 */
function isKindFollowingSymlink(fullPath, dirent, checkFn) {
  if (checkFn(dirent)) return true;
  if (!dirent.isSymbolicLink()) return false;
  try { return checkFn(fs.statSync(fullPath)); } catch { return false; }
}
const isDirFollowingSymlink = (p, d) => isKindFollowingSymlink(p, d, (x) => x.isDirectory());

/**
 * Resolve one candidate `chat-messages.json` path into zero or one files()
 * entries — same lstat-first, follow-if-symlink shape as cursor.js's
 * statIfPresent, and for the same reason: this path is constructed (joined
 * onto an already-resolved chat directory), not discovered via a Dirent, so
 * there is no Dirent to reuse the isKindFollowingSymlink check against. A
 * chat directory with no chat-messages.json yet (a brand new, still-empty
 * chat) is normal and NOT broken; only a symlink that fails to resolve is.
 */
function* statFileIfPresent(file) {
  let lst;
  try { lst = fs.lstatSync(file); }
  catch { return; }

  if (lst.isSymbolicLink()) {
    try {
      const st = fs.statSync(file);
      if (!st.isFile()) { yield { file, broken: true }; return; }
      yield { file, mtimeMs: st.mtimeMs, sizeBytes: st.size, broken: false };
    } catch {
      yield { file, broken: true };
    }
    return;
  }

  if (!lst.isFile()) return;
  yield { file, mtimeMs: lst.mtimeMs, sizeBytes: lst.size, broken: false };
}

/**
 * Yield { file, mtimeMs, sizeBytes, broken } for every chat-messages.json
 * found under every configured channel's projects root:
 * <projectsRoot>/<project>/chats/<chatId>/chat-messages.json.
 */
function* files() {
  for (const projectsRoot of codebuffProjectRoots()) {
    let projectEntries;
    try { projectEntries = fs.readdirSync(projectsRoot, { withFileTypes: true }); }
    catch { continue; }

    for (const proj of projectEntries) {
      const projDir = path.join(projectsRoot, proj.name);
      if (!isDirFollowingSymlink(projDir, proj)) {
        if (proj.isSymbolicLink()) yield { file: projDir, broken: true };
        continue;
      }

      const chatsDir = path.join(projDir, "chats");
      let chatEntries;
      try { chatEntries = fs.readdirSync(chatsDir, { withFileTypes: true }); }
      catch { continue; } // no "chats" subdir yet — normal for a project with no chat history

      for (const chat of chatEntries) {
        const chatDir = path.join(chatsDir, chat.name);
        if (!isDirFollowingSymlink(chatDir, chat)) {
          if (chat.isSymbolicLink()) yield { file: chatDir, broken: true };
          continue;
        }
        yield* statFileIfPresent(path.join(chatDir, "chat-messages.json"));
      }
    }
  }
}

// A single chat's message history has not been observed anywhere in this
// source's research to approach this size — like cursor.js's MAX_DB_BYTES,
// this is a generous, untested-against-a-real-huge-file backstop against a
// corrupted or pathological file, not an empirically derived ceiling.
const MAX_BYTES = 512 * 1024 * 1024;
const READ_TIMEOUT_MS = 60_000;

/**
 * Read the whole file as text, bounded by a wall-clock deadline the same
 * way claude-code.js bounds its line-by-line read: no timeout exists
 * natively anywhere in Node's stream stack, so a symlink retargeted onto
 * something with no natural EOF (e.g. a FIFO with no writer) would otherwise
 * hang forever with no 'error' or 'end' ever firing. Destroying the stream
 * is what actually unblocks that.
 *
 * Resolves with whatever text WAS accumulated even when the read errors or
 * times out partway — the caller (readLines) still extracts every complete
 * top-level JSON object out of that partial text rather than discarding it,
 * the same "partial read is still real content" principle claude-code.js's
 * and cursor.js's own docstrings insist on.
 */
function readWholeFileBounded(file) {
  return new Promise((resolve) => {
    const stream = fs.createReadStream(file, { encoding: "utf-8" });
    let text = "";
    let bytesRead = 0;
    let errored = false;
    const timer = setTimeout(() => stream.destroy(new Error("read timed out")), READ_TIMEOUT_MS);
    stream.on("data", (chunk) => {
      text += chunk;
      bytesRead += Buffer.byteLength(chunk, "utf-8");
    });
    stream.on("end", () => {
      clearTimeout(timer);
      resolve({ text, bytesRead, complete: true });
    });
    stream.on("error", () => {
      if (errored) return; // 'error' can fire once for the destroy() and once natively
      errored = true;
      clearTimeout(timer);
      resolve({ text, bytesRead, complete: false });
    });
  });
}

/**
 * Extract every complete top-level `{...}` object out of arbitrary JSON
 * text, tracking brace depth and string/escape state, WITHOUT requiring the
 * surrounding `[ ... ]` array to be syntactically complete.
 *
 * This is what lets a partial read (timeout, mid-write file, I/O error)
 * still surface every message that was fully written before the cutoff,
 * instead of the whole file being discarded because JSON.parse on truncated
 * input throws. It is also what lets a fully-successful read skip a real
 * JSON.parse of the whole array entirely: each returned substring is used
 * verbatim as one scanned "line", the same "don't re-serialize, keep the
 * exact bytes the regexes depend on" reasoning cursor.js's valueToText()
 * docstring gives for not round-tripping through JSON.parse/stringify.
 */
function extractTopLevelJsonObjects(text) {
  const objects = [];
  let depth = 0;
  let start = -1;
  let inString = false;
  let escape = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (inString) {
      if (escape) escape = false;
      else if (ch === "\\") escape = true;
      else if (ch === '"') inString = false;
      continue;
    }
    if (ch === '"') { inString = true; continue; }
    if (ch === "{") {
      if (depth === 0) start = i;
      depth++;
    } else if (ch === "}") {
      if (depth > 0) depth--;
      if (depth === 0 && start !== -1) {
        objects.push(text.slice(start, i + 1));
        start = -1;
      }
    }
  }
  return objects;
}

/**
 * Read one chat-messages.json as an array of raw text "lines", one per
 * top-level message object. Returns { lines, status, bytesRead } with the
 * same status vocabulary as claude-code.js/cursor.js: "complete", "partial",
 * "too-large", "failed".
 */
async function readLines(file) {
  let stat;
  try { stat = fs.statSync(file); }
  catch { return { lines: [], status: "failed", bytesRead: 0 }; }
  if (stat.size > MAX_BYTES) return { lines: [], status: "too-large", bytesRead: 0 };

  const { text, bytesRead, complete } = await readWholeFileBounded(file);
  const lines = extractTopLevelJsonObjects(text);

  if (complete) return { lines, status: "complete", bytesRead };
  // Errored or timed out partway: whatever complete objects WERE recovered
  // are real content and may contain a real secret — never discard them
  // just because the tail of the file didn't finish cleanly.
  return { lines, status: lines.length > 0 ? "partial" : "failed", bytesRead };
}

module.exports = { id, label, available, files, readLines };
