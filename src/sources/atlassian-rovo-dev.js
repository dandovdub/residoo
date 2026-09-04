"use strict";

const fs = require("fs");
const path = require("path");
const os = require("os");

/**
 * Atlassian Rovo Dev CLI (`acli rovodev`) — Atlassian's terminal coding
 * agent. Closed-source (part of the Atlassian CLI), so unlike continue.js
 * this cannot be grounded in the project's own source code; grounded
 * instead in Atlassian's own support docs, which is the strongest source
 * available for a closed-source tool.
 *
 * VERIFICATION STATUS: not checked against a real install (no `acli` on
 * this machine, no `~/.rovodev` directory). Confirmed via
 * support.atlassian.com/rovo/docs/manage-sessions-in-rovo-dev-cli/
 * (fetched 2026-09-04): "Sessions are stored by default at
 * `~/.rovodev/sessions/`", with two named files per session:
 * `session_context.json` ("full conversation history and context") and
 * `metadata.json` ("session metadata like title, workspace, and fork
 * information"). The docs page does not explicitly state whether these
 * live directly under `sessions/` or one level down per session -- but
 * since the same two filenames are named for every session, and a flat
 * layout would mean every session's `session_context.json` collides on
 * the same path, a per-session subdirectory
 * (`sessions/<session-id>/session_context.json`) is the only layout
 * consistent with the docs as written, not a guess pulled from nowhere.
 * Ships on that reasoning per CONTRIBUTING.md rule 3; `available()`
 * requires only the root `~/.rovodev` directory, so a wrong subdirectory
 * assumption fails as "no sessions found," never a false "nothing here."
 *
 * The config file (`~/.rovodev/config.yml`, also documented) is not
 * scanned: `--project`-mode-style config coverage is deliberately scoped
 * to the handful of tools this project already has a dedicated config
 * reader for, and a single YAML settings file is a small enough surface
 * that adding it as a bespoke one-off here wasn't judged worth the
 * inconsistency with how every other tool's config gets read.
 */
const ROOT = path.join(os.homedir(), ".rovodev");
const SESSIONS_DIR = path.join(ROOT, "sessions");

function id() { return "atlassian-rovo-dev"; }
function label() { return "Atlassian Rovo Dev CLI"; }

function available() {
  try { return fs.statSync(ROOT).isDirectory(); } catch { return false; }
}

/** Same defensive symlink-following pattern used throughout src/sources -- see continue.js's docstring for the full reasoning. */
function isKindFollowingSymlink(fullPath, dirent, checkFn) {
  if (checkFn(dirent)) return true;
  if (!dirent.isSymbolicLink()) return false;
  try { return checkFn(fs.statSync(fullPath)); } catch { return false; }
}
const isDirFollowingSymlink = (p, d) => isKindFollowingSymlink(p, d, (x) => x.isDirectory());
const isFileFollowingSymlink = (p, d) => isKindFollowingSymlink(p, d, (x) => x.isFile());

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

function* yieldFileEntry(file, dirent) {
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
 * Walks sessions/<session-id>/{session_context.json,metadata.json} per the
 * inferred layout above. If a future/different real layout turns out to be
 * flat instead, this also picks up session_context.json/metadata.json
 * sitting directly in sessions/ itself (an entry that fails the
 * is-a-directory check below is just skipped as "not a session dir", never
 * reported broken), so the more conservative of the two guesses degrades
 * gracefully rather than reporting a false all-clear.
 */
function* files() {
  const state = resolveDirState(SESSIONS_DIR);
  if (state === "broken") { yield { file: SESSIONS_DIR, broken: true }; return; }
  if (state !== "ok") return; // no sessions/ yet — normal, not broken

  let entries;
  try { entries = fs.readdirSync(SESSIONS_DIR, { withFileTypes: true }); }
  catch { yield { file: SESSIONS_DIR, broken: true }; return; }

  for (const e of entries) {
    const p = path.join(SESSIONS_DIR, e.name);

    if (e.name === "session_context.json" || e.name === "metadata.json") {
      yield* yieldFileEntry(p, e);
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
      if (ie.name !== "session_context.json" && ie.name !== "metadata.json") continue;
      yield* yieldFileEntry(path.join(p, ie.name), ie);
    }
  }
}

const MAX_JSON_DOC_BYTES = 512 * 1024 * 1024; // generous backstop, no real large example to size against — see continue.js's MAX_JSON_DOC_BYTES for the same admitted status
const READ_TIMEOUT_MS = 60_000;

/**
 * Whole-document JSON read with the same streamed-read/timeout/size-cap
 * discipline as every other whole-document reader in src/sources (see
 * continue.js's readJsonDocumentFile for the full reasoning) — reused by
 * pattern, not import, per this project's one-small-self-contained-file
 * convention. A document that isn't valid JSON (corrupted, truncated, or a
 * genuinely different real format than inferred above) is scanned as one
 * raw line rather than discarded.
 */
async function readLines(file) {
  let stat;
  try { stat = fs.statSync(file); }
  catch { return { lines: [], status: "failed", bytesRead: 0 }; }
  if (stat.size > MAX_JSON_DOC_BYTES) return { lines: [], status: "too-large", bytesRead: 0 };

  let text = "";
  let tooLarge = false;
  const stream = fs.createReadStream(file, { encoding: "utf-8" });
  const timer = setTimeout(() => stream.destroy(new Error("read timed out")), READ_TIMEOUT_MS);

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
  const status = readCleanly ? "complete" : "partial";
  if (text.length === 0) return { lines: [], status, bytesRead };

  try {
    const parsed = JSON.parse(text);
    // No confirmed internal schema for session_context.json's history
    // shape (closed source, see header) -- scanned as one flattened
    // document rather than decomposed per-message the way continue.js
    // does, so nothing inside it is assumed about that isn't confirmed.
    return { lines: [JSON.stringify(parsed)], status, bytesRead };
  } catch {
    return { lines: [text], status, bytesRead };
  }
}

module.exports = { id, label, available, files, readLines };
