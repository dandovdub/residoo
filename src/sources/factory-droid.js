"use strict";

const fs = require("fs");
const { createInterface } = require("readline/promises");
const path = require("path");
const os = require("os");

/**
 * Factory AI's "droid" CLI (docs.factory.ai/droid-cli) local session
 * transcripts.
 *
 * VERIFICATION STATUS: corroborated by three independent sources, but NOT
 * checked against a real droid install on the machine this source was built
 * on (droid was not installed there — no `~/.factory` directory exists; see
 * CONTRIBUTING.md).
 *
 *   1. Factory's own official docs (docs.factory.ai/cli/configuration/settings
 *      and docs.factory.ai/droid-cli/cli-reference) confirm the root itself:
 *      `~/.factory/settings.json` on macOS/Linux, and a documented
 *      `worktreeDirectory` setting defaulting to `~/.factory/worktrees` —
 *      i.e. `~/.factory` is definitely droid's real per-user data root, from
 *      Factory itself, not a guess. The official docs do NOT spell out the
 *      session-transcript path/format, though.
 *   2. agent-safehouse.dev's sandboxed filesystem-inspection report on droid
 *      ("Droid (Factory CLI) — Sandbox Analysis Report") — a real behavioral
 *      inspection of what the CLI actually writes, not a guess — documents
 *      session transcripts at `~/.factory/projects/<project>/<session-id>
 *      .jsonl` (JSONL, one JSON object per line) alongside
 *      `~/.factory/settings.json`, `~/.factory/mcp.json`, and
 *      `~/.factory/logs/`. That it independently reports the same
 *      settings.json/worktrees layout Factory's own docs describe is what
 *      gives this source's less-official reporting (the exact transcript
 *      path/format) real weight.
 *   3. jazzyalex/agent-sessions (github.com/jazzyalex/agent-sessions, 800+
 *      stars) — a real, actively maintained macOS app built specifically to
 *      parse local AI-coding-agent session history for browsing/search —
 *      lists droid's session sources in its own README as BOTH
 *      `~/.factory/sessions` and `~/.factory/projects`, i.e. it reads two
 *      locations rather than committing to one, which is exactly the
 *      resilient stance this source also takes below (see the recursive
 *      `.jsonl` walk rather than a single hard-coded subpath).
 *
 * Given two credible-but-not-identical accounts of the exact subdirectory
 * (`projects/<project>/` per the sandbox report, `sessions/` per
 * agent-sessions — plausibly both real, e.g. different droid versions or
 * different session kinds), this source does NOT hard-code either one.
 * Instead it walks `~/.factory` recursively for any `*.jsonl` file, the same
 * "match the extension, don't guess the exact subpath" tolerance
 * claude-code.js applies within a single project directory. This is
 * deliberately broader than strictly necessary rather than narrower: a
 * `*.jsonl` file anywhere under `~/.factory` is, per every source above,
 * either a real session transcript or nothing droid would plausibly put
 * there at all.
 */
const HOME = os.homedir();
const ROOT = path.join(HOME, ".factory");

const MAX_BYTES = 2 * 1024 * 1024 * 1024; // 2GB — same backstop as claude-code.js.
const READ_TIMEOUT_MS = 60_000;
const MAX_WALK_DEPTH = 8; // generous bound against a symlink cycle or a pathologically deep tree

function id() { return "factory-droid"; }
function label() { return "Factory Droid CLI"; }

function available() {
  try { return fs.statSync(ROOT).isDirectory(); } catch { return false; }
}

/**
 * Same defensive symlink-following helpers as claude-code.js — see that
 * file's docstring. Duplicated rather than imported, per this project's
 * self-contained-source-file convention (see cursor.js's docstring).
 */
function isKindFollowingSymlink(fullPath, dirent, checkFn) {
  if (checkFn(dirent)) return true;
  if (!dirent.isSymbolicLink()) return false;
  try { return checkFn(fs.statSync(fullPath)); } catch { return false; }
}
const isDirFollowingSymlink = (p, d) => isKindFollowingSymlink(p, d, (x) => x.isDirectory());
const isFileFollowingSymlink = (p, d) => isKindFollowingSymlink(p, d, (x) => x.isFile());

/**
 * Recursively yield { file, mtimeMs, sizeBytes, broken } for every plain file
 * under `dir` whose name passes `matchFn`, following symlinks (both for
 * directories to descend into and files to yield) and reporting a symlink
 * that resolves to neither as `broken: true` — the same convention
 * claude-code.js's files() uses, generalized to arbitrary depth since
 * droid's exact directory nesting isn't pinned down by the sources above
 * (see the module docstring). Bounded by MAX_WALK_DEPTH against a symlink
 * cycle.
 */
function* walk(dir, depth, matchFn) {
  if (depth > MAX_WALK_DEPTH) return;
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); }
  catch { return; }

  for (const e of entries) {
    const full = path.join(dir, e.name);
    if (isDirFollowingSymlink(full, e)) {
      yield* walk(full, depth + 1, matchFn);
      continue;
    }
    const isFile = isFileFollowingSymlink(full, e);
    if (!isFile) {
      if (e.isSymbolicLink()) yield { file: full, broken: true };
      continue; // not a symlink, not a dir, not a file (e.g. a socket) — out of scope
    }
    if (!matchFn(e.name)) continue;
    let stat;
    try { stat = fs.statSync(full); } catch { yield { file: full, broken: true }; continue; }
    yield { file: full, mtimeMs: stat.mtimeMs, sizeBytes: stat.size, broken: false };
  }
}

function* files() {
  yield* walk(ROOT, 0, (name) => name.endsWith(".jsonl"));
}

/**
 * Read one JSONL transcript as raw text lines. Identical streaming/timeout/
 * partial-read discipline to claude-code.js's readLines() — see that file's
 * docstring for the full reasoning (V8 string-length ceiling, TOCTOU re-stat,
 * honest partial-read status).
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
