"use strict";

const fs = require("fs");
const { createInterface } = require("readline/promises");
const path = require("path");
const os = require("os");

/**
 * OpenHands (github.com/OpenHands/OpenHands, 85,900+ stars) local conversation
 * storage.
 *
 * VERIFICATION STATUS: corroborated by reading the actual, current source code
 * of two real repositories in the OpenHands org (fetched directly from GitHub
 * during this source's research, base64-decoded, not inferred from a blog
 * post) — NOT verified against a real OpenHands install on the machine this
 * source was built on (OpenHands was not installed there; see CONTRIBUTING.md).
 *
 *   1. github.com/OpenHands/OpenHands-CLI — `openhands_cli/locations.py`
 *      defines `get_persistence_dir()` as `$OPENHANDS_PERSISTENCE_DIR` or
 *      `~/.openhands`, and `get_conversations_dir()` as
 *      `<persistence_dir>/conversations`. `openhands_cli/conversations/
 *      store/local.py`'s `LocalFileStore` (the CLI's on-disk conversation
 *      store) confirms the concrete layout used to build ROOT below:
 *      `<conversations_dir>/<conversation_id>/events/event-*.json`, one JSON
 *      object per file, plus a `metadata.json`-style summary this source does
 *      NOT rely on (it derives everything from the event files themselves).
 *      NOTE: as of this research, OpenHands-CLI's own README marks the
 *      project "no longer actively maintained," pointing users at "Agent
 *      Canvas" (the browser-based control surface in the main OpenHands/
 *      OpenHands repo) instead.
 *   2. github.com/OpenHands/software-agent-sdk (1,000+ stars, actively
 *      maintained — this is the SDK OpenHands-CLI itself is "Powered by," and
 *      the same SDK Agent Canvas's agent-server is built on) confirms the
 *      event-file naming convention still current today:
 *      `openhands-sdk/openhands/sdk/conversation/persistence_const.py`
 *      defines `EVENTS_DIR = "events"` and
 *      `EVENT_FILE_PATTERN = "event-{idx:05d}-{event_id}.json"`. A shipped
 *      example, `examples/01_standalone_sdk/55_persistent_memory.py`, also
 *      independently confirms `~/.openhands/` (home-anchored, not
 *      workspace-anchored) as the SDK's own convention for user-tier
 *      persistent state, matching the CLI's `get_persistence_dir()`.
 *
 * What this source does NOT claim: that `~/.openhands/conversations` is
 * necessarily where the currently-recommended "Agent Canvas" product (which
 * can also run inside Docker, where its FILE_STORE_PATH may point inside the
 * container rather than the host) writes when run that way. What IS shared
 * and confirmed across every variant researched is the `~/.openhands` home
 * directory as OpenHands' persistence root, and the events/event-*.json shape
 * for conversation storage. Scanning that root, if present on this machine,
 * degrades gracefully (files() below simply finds nothing extra) rather than
 * scanning the wrong place, if some other run mode used a different root
 * entirely (e.g. purely inside an ephemeral Docker container never mounted to
 * the host).
 *
 * Each event-*.json file is a single JSON object (see the pattern above), not
 * JSONL — but scan.js only wants raw text lines, and a JSON file (minified or
 * pretty-printed) is exactly that, so this source reuses claude-code.js's
 * plain line-streaming readLines() unmodified in spirit.
 */
const HOME = os.homedir();
const PERSISTENCE_DIR = path.join(HOME, ".openhands");
const CONVERSATIONS_DIR = path.join(PERSISTENCE_DIR, "conversations");

const MAX_BYTES = 2 * 1024 * 1024 * 1024; // 2GB — same generous backstop as claude-code.js;
                                            // real event files are tiny (one event each), this
                                            // is a pathological-file guard, not a tuned limit.
const READ_TIMEOUT_MS = 60_000;

function id() { return "openhands"; }
function label() { return "OpenHands"; }

function available() {
  try { return fs.statSync(PERSISTENCE_DIR).isDirectory(); } catch { return false; }
}

/**
 * Same defensive symlink-following helpers as claude-code.js — see that
 * file's docstring for the full reasoning. Duplicated rather than imported:
 * every source in this project is meant to be a small, self-contained file a
 * reviewer can audit on its own (see cursor.js's docstring for the same
 * design note).
 */
function isKindFollowingSymlink(fullPath, dirent, checkFn) {
  if (checkFn(dirent)) return true;
  if (!dirent.isSymbolicLink()) return false;
  try { return checkFn(fs.statSync(fullPath)); } catch { return false; }
}
const isDirFollowingSymlink = (p, d) => isKindFollowingSymlink(p, d, (x) => x.isDirectory());
const isFileFollowingSymlink = (p, d) => isKindFollowingSymlink(p, d, (x) => x.isFile());

/**
 * Yield entries for every plain file directly inside `dir` whose name passes
 * `matchFn`, following symlinks the same way claude-code.js's files() does,
 * and reporting a symlink that resolves to neither a file nor a directory as
 * `broken: true` rather than silently skipping it. Not recursive — every
 * caller here already knows the exact directory it wants to list.
 */
function* filesInDir(dir, matchFn) {
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); }
  catch { return; } // directory doesn't exist (e.g. no events/ yet) — normal, not broken
  for (const e of entries) {
    const full = path.join(dir, e.name);
    if (isDirFollowingSymlink(full, e)) continue; // a directory where a file was expected — out of scope
    const isFile = isFileFollowingSymlink(full, e);
    if (!isFile) {
      if (e.isSymbolicLink()) yield { file: full, broken: true };
      continue;
    }
    if (!matchFn(e.name)) continue;
    let stat;
    try { stat = fs.statSync(full); } catch { yield { file: full, broken: true }; continue; }
    yield { file: full, mtimeMs: stat.mtimeMs, sizeBytes: stat.size, broken: false };
  }
}

/**
 * Yield { file, mtimeMs, sizeBytes, broken } for every conversation's
 * metadata.json and event-*.json files under ~/.openhands/conversations.
 *
 * Structure (confirmed by source, see docstring above):
 *   conversations/<conversation_id>/metadata.json          (optional, small)
 *   conversations/<conversation_id>/events/event-*.json    (one per event)
 */
function* files() {
  let conversationDirs;
  try { conversationDirs = fs.readdirSync(CONVERSATIONS_DIR, { withFileTypes: true }); }
  catch { return; }

  for (const conv of conversationDirs) {
    const convDir = path.join(CONVERSATIONS_DIR, conv.name);
    const isDir = isDirFollowingSymlink(convDir, conv);
    if (!isDir) {
      if (conv.isSymbolicLink()) yield { file: convDir, broken: true };
      continue;
    }

    yield* filesInDir(convDir, (name) => name === "metadata.json");

    const eventsDir = path.join(convDir, "events");
    yield* filesInDir(eventsDir, (name) => name.startsWith("event-") && name.endsWith(".json"));
  }
}

/**
 * Read one file (a single JSON object, metadata or event) as raw text lines.
 * Identical streaming/timeout/partial-read discipline to claude-code.js's
 * readLines() — see that file's docstring for the reasoning; not repeated
 * here since these files are individually tiny and the 818MB failure mode
 * that motivated streaming there doesn't apply, but there is no reason to be
 * less careful about a hung read or a mid-read failure just because the
 * common case is small.
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

module.exports = { id, label, available, files, readLines };
