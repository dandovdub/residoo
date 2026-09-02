"use strict";

const fs = require("fs");
const readline = require("readline");
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

/**
 * Dirent.isDirectory()/isFile() reflect the entry ITSELF (lstat semantics) —
 * for a symlink they both return false, even when the link resolves to a
 * real directory or file. A dotfiles manager or a project relocated onto a
 * symlink would then be silently excluded from scanning with no indication
 * anything was skipped. statSync (unlike lstatSync) follows the link, so
 * only symlinks fall through to it — the common case stays lstat-only and
 * cheap.
 */
function isDirFollowingSymlink(fullPath, dirent) {
  if (dirent.isDirectory()) return true;
  if (!dirent.isSymbolicLink()) return false;
  try { return fs.statSync(fullPath).isDirectory(); } catch { return false; }
}
function isFileFollowingSymlink(fullPath, dirent) {
  if (dirent.isFile()) return true;
  if (!dirent.isSymbolicLink()) return false;
  try { return fs.statSync(fullPath).isFile(); } catch { return false; }
}

/** Yield { file, mtimeMs, sizeBytes } for every session transcript found. */
function* files() {
  let projectDirs;
  try { projectDirs = fs.readdirSync(ROOT, { withFileTypes: true }); }
  catch { return; }

  for (const proj of projectDirs) {
    const dir = path.join(ROOT, proj.name);
    if (!isDirFollowingSymlink(dir, proj)) continue;
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); }
    catch { continue; }
    for (const e of entries) {
      if (!e.name.endsWith(".jsonl")) continue;
      const file = path.join(dir, e.name);
      if (!isFileFollowingSymlink(file, e)) continue;
      let stat;
      try { stat = fs.statSync(file); } catch { continue; }
      yield { file, mtimeMs: stat.mtimeMs, sizeBytes: stat.size };
    }
  }
}

/**
 * Read one transcript as an array of raw text lines.
 *
 * Streams line-by-line via readline rather than `readFileSync + split` —
 * verified this matters, not a theoretical concern: a real 818MB session on
 * a real machine this tool was tested against threw `ERR_STRING_TOO_LONG`
 * under the whole-file-as-one-string approach (V8's ~512M-character single
 * string limit). Individual JSONL lines stay far under that ceiling even in
 * the largest observed transcripts, so line-by-line reading has no such
 * wall — only the old "read it all as one string first" approach did.
 *
 * Returns `null` on read failure — deliberately distinct from `[]`, which
 * means "read fine, genuinely empty." A file deleted or made unreadable
 * between the files() walk and this call (plausible mid-scan, if Claude Code
 * is actively writing) must NOT be silently folded into "scanned, nothing
 * found" — that's a false clean bill of health in a tool whose one job is
 * not missing something. Callers are expected to check for null and exclude
 * it from filesScanned rather than count an unscanned file as scanned.
 */
function readLines(file) {
  return new Promise((resolve) => {
    const lines = [];
    let failed = false;
    let stream;
    try { stream = fs.createReadStream(file, { encoding: "utf-8" }); }
    catch { resolve(null); return; }

    stream.on("error", () => { failed = true; resolve(null); });
    const rl = readline.createInterface({ input: stream, crlfDelay: Infinity });
    rl.on("line", (line) => lines.push(line));
    rl.on("close", () => { if (!failed) resolve(lines); });
  });
}

module.exports = { id, label, available, files, readLines };
