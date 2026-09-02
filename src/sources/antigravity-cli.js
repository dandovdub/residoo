"use strict";

const fs = require("fs");
const { createInterface } = require("readline/promises");
const path = require("path");
const os = require("os");

/**
 * Google Antigravity (antigravity.google) — the agentic development platform
 * Google launched at I/O 2026, whose CLI (built in Go, replacing Gemini CLI
 * for agentic use) and desktop editor both write local session state under
 * `~/.gemini/antigravity*`.
 *
 * VERIFICATION STATUS: corroborated by one detailed, credible source — NOT
 * by two independent sources of the exact schema, and NOT checked against a
 * real install on the machine this source was built on (no `~/.gemini`
 * directory exists there; see CONTRIBUTING.md). Ship this with that
 * explicitly weaker standing in mind relative to this project's other new
 * sources.
 *
 * The source: jazzyalex/agent-sessions (github.com/jazzyalex/agent-sessions,
 * 800+ stars) — a real, actively maintained macOS app built specifically to
 * parse local AI-coding-agent session history for browsing/search — ships a
 * dedicated guide page, "Antigravity CLI local history: transcripts and
 * brain artifacts under `~/.gemini`," documenting (as this tool's own
 * behavior, i.e. code the maintainer wrote and presumably ran against a real
 * Antigravity install, not a secondhand description):
 *   - CLI transcripts: `~/.gemini/antigravity-cli/brain/<conversation-id>/
 *     .system_generated/logs/transcript.jsonl` (one step per line: fields
 *     including step_index, source, type, status, created_at, content,
 *     tool_calls, thinking, truncated_fields) plus a sibling
 *     `transcript_full.jsonl` restoring content the primary file truncates.
 *   - Editor artifacts: `~/.gemini/antigravity/brain/<conversation-id>/`
 *     holding per-artifact Markdown (`task.md`, `implementation_plan.md`,
 *     `walkthrough.md`, `proposal.md`) each paired with a `.metadata.json`.
 *   - The same guide notes upgraded installs may also carry
 *     `~/.gemini/antigravity-ide/brain` and `~/.gemini/antigravity-backup/
 *     brain`, but says its own tool only scans the first two — this source
 *     follows that same, narrower choice rather than guessing at the other
 *     two directory names' internal shape.
 *
 * Real-world significance: Antigravity is a first-party Google product
 * (Google I/O 2026 launch, "the only tool in this group not built on VS
 * Code," free public preview with Gemini 3 Pro access as of that launch),
 * so — schema-verification caveat above notwithstanding — this is exactly
 * the kind of tool this project's coverage would be conspicuously incomplete
 * without.
 *
 * This source walks both brain roots recursively for `.jsonl`, `.json`, and
 * `.md` files (skipping the `.system_generated/logs` vs top-level distinction
 * rather than hard-coding it) — the same "match by extension, don't pin the
 * exact depth" tolerance claude-code.js applies to its own project-slug
 * directories, since a screenshot or other binary asset the CLI writes
 * alongside these would not match any of those three extensions anyway.
 */
const HOME = os.homedir();
const GEMINI_DIR = path.join(HOME, ".gemini");
const CLI_BRAIN_ROOT = path.join(GEMINI_DIR, "antigravity-cli", "brain");
const EDITOR_BRAIN_ROOT = path.join(GEMINI_DIR, "antigravity", "brain");

const MAX_BYTES = 2 * 1024 * 1024 * 1024; // 2GB — same backstop as claude-code.js.
const READ_TIMEOUT_MS = 60_000;
const MAX_WALK_DEPTH = 8;

function id() { return "antigravity"; }
function label() { return "Google Antigravity"; }

function available() {
  for (const root of [CLI_BRAIN_ROOT, EDITOR_BRAIN_ROOT]) {
    try { if (fs.statSync(root).isDirectory()) return true; } catch { /* try the next root */ }
  }
  return false;
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

const TEXT_EXTENSIONS = new Set([".jsonl", ".json", ".md"]);

/**
 * Recursively yield { file, mtimeMs, sizeBytes, broken } for every plain
 * text-like (see TEXT_EXTENSIONS) file under `dir` — see factory-droid.js's
 * walk() for the identical symlink-handling reasoning.
 */
function* walk(dir, depth) {
  if (depth > MAX_WALK_DEPTH) return;
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); }
  catch { return; }

  for (const e of entries) {
    const full = path.join(dir, e.name);
    if (isDirFollowingSymlink(full, e)) {
      yield* walk(full, depth + 1);
      continue;
    }
    const isFile = isFileFollowingSymlink(full, e);
    if (!isFile) {
      if (e.isSymbolicLink()) yield { file: full, broken: true };
      continue;
    }
    if (!TEXT_EXTENSIONS.has(path.extname(e.name))) continue; // e.g. a captured screenshot — out of scope
    let stat;
    try { stat = fs.statSync(full); } catch { yield { file: full, broken: true }; continue; }
    yield { file: full, mtimeMs: stat.mtimeMs, sizeBytes: stat.size, broken: false };
  }
}

function* files() {
  yield* walk(CLI_BRAIN_ROOT, 0);
  yield* walk(EDITOR_BRAIN_ROOT, 0);
}

/**
 * Read one transcript/artifact file as raw text lines. Identical streaming/
 * timeout/partial-read discipline to claude-code.js's readLines().
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
