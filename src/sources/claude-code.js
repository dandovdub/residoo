"use strict";

const fs = require("fs");
const path = require("path");
const os = require("os");

/**
 * Claude Code session transcripts.
 *
 * One JSONL file per session, one JSON object per line, under
 * ~/.claude/projects/<project-slug>/<session-id>.jsonl. This is the only
 * source shipped in v1 — it's the one path we could verify actually exists
 * and actually holds real transcript content, rather than a guessed path
 * for a tool we didn't have installed to check against. See CONTRIBUTING.md
 * for how to add a source for another tool.
 */
const ROOT = path.join(os.homedir(), ".claude", "projects");

function id() { return "claude-code"; }
function label() { return "Claude Code"; }

function available() {
  try { return fs.statSync(ROOT).isDirectory(); } catch { return false; }
}

/** Yield { file, mtimeMs } for every session transcript found. */
function* files() {
  let projectDirs;
  try { projectDirs = fs.readdirSync(ROOT, { withFileTypes: true }); }
  catch { return; }

  for (const proj of projectDirs) {
    if (!proj.isDirectory()) continue;
    const dir = path.join(ROOT, proj.name);
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); }
    catch { continue; }
    for (const e of entries) {
      if (!e.isFile() || !e.name.endsWith(".jsonl")) continue;
      const file = path.join(dir, e.name);
      let stat;
      try { stat = fs.statSync(file); } catch { continue; }
      yield { file, mtimeMs: stat.mtimeMs, sizeBytes: stat.size };
    }
  }
}

/**
 * Read one transcript as a stream of raw text lines. Kept dead simple
 * (readFileSync + split) rather than a line-reader stream: these files run
 * up to hundreds of MB, but scanning is a one-shot local operation, not a
 * hot path, and simplicity here is worth more than the memory saved.
 */
function readLines(file) {
  let raw;
  try { raw = fs.readFileSync(file, "utf-8"); }
  catch { return []; }
  return raw.split("\n");
}

module.exports = { id, label, available, files, readLines };
