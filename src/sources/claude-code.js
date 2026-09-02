"use strict";

const fs = require("fs");
const { createInterface } = require("readline/promises");
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

// Bounds for readLines(), see the docstring below for why both exist.
const MAX_BYTES = 2 * 1024 * 1024 * 1024; // 2GB — generous headroom over the
                                            // largest real transcript this
                                            // tool has been tested against (818MB).
const READ_TIMEOUT_MS = 60_000;

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
 *
 * The tradeoff, stated plainly rather than left implicit: following symlinks
 * here means residoo will read whatever a `*.jsonl`-named symlink under
 * ~/.claude/projects points at, not only files Claude Code itself wrote.
 * Before this, lstat semantics accidentally sandboxed every scan to real
 * transcript files; that sandbox is intentionally traded away for the
 * relocated-project case. Do not place a symlink to a sensitive file inside
 * ~/.claude/projects. See SECURITY.md.
 */
function isKindFollowingSymlink(fullPath, dirent, checkFn) {
  if (checkFn(dirent)) return true;
  if (!dirent.isSymbolicLink()) return false;
  try { return checkFn(fs.statSync(fullPath)); } catch { return false; }
}
const isDirFollowingSymlink = (p, d) => isKindFollowingSymlink(p, d, (x) => x.isDirectory());
const isFileFollowingSymlink = (p, d) => isKindFollowingSymlink(p, d, (x) => x.isFile());

/**
 * Yield { file, mtimeMs, sizeBytes, broken } for every session transcript
 * found — including ones that could not actually be resolved.
 *
 * `broken: true` (mtimeMs/sizeBytes absent) marks a `.jsonl`-named entry, or
 * a project directory, that looked like it should be scannable but wasn't —
 * chiefly a dangling symlink (a real, plausible case: dotfiles-sync tools
 * and moved home directories both produce these). The earlier version of
 * this fix followed valid symlinks correctly but let a BROKEN one fall
 * through its own try/catch and `continue` silently, inside this generator,
 * before the caller ever saw it — reintroducing, for exactly the entries
 * most likely to need it, the same silent exclusion this whole feature was
 * built to end. Every entry this function decides not to scan is now
 * reported, one way or another.
 */
function* files() {
  let projectDirs;
  try { projectDirs = fs.readdirSync(ROOT, { withFileTypes: true }); }
  catch { return; }

  for (const proj of projectDirs) {
    const dir = path.join(ROOT, proj.name);
    if (!proj.isDirectory()) {
      const resolved = isDirFollowingSymlink(dir, proj);
      // Only a symlink that fails to resolve is a reportable failure — a
      // stray non-directory entry that was never meant to be a project
      // folder in the first place is silently out of scope, same as before.
      if (!resolved) {
        if (proj.isSymbolicLink()) yield { file: dir, broken: true };
        continue;
      }
    }
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); }
    catch { yield { file: dir, broken: true }; continue; }

    for (const e of entries) {
      if (!e.name.endsWith(".jsonl")) continue;
      const file = path.join(dir, e.name);
      if (!e.isFile()) {
        const resolved = isFileFollowingSymlink(file, e);
        if (!resolved) {
          if (e.isSymbolicLink()) yield { file, broken: true };
          continue;
        }
      }
      let stat;
      try { stat = fs.statSync(file); } catch { yield { file, broken: true }; continue; }
      yield { file, mtimeMs: stat.mtimeMs, sizeBytes: stat.size, broken: false };
    }
  }
}

/**
 * Read one transcript as an array of raw text lines.
 *
 * Streams line-by-line via readline/promises rather than `readFileSync +
 * split` — verified this matters, not a theoretical concern: a real 818MB
 * session on a real machine this tool was tested against threw
 * `ERR_STRING_TOO_LONG` under the whole-file-as-one-string approach (V8's
 * ~512M-character single-string limit). To be precise about what this fixes
 * and what it doesn't: individual JSONL lines stay far under that ceiling,
 * so line-by-line reading removes the crash — it does NOT reduce peak
 * memory, since every line is still collected into one array before
 * returning. A true bounded-memory version would match patterns against
 * each line as it arrives instead of collecting first; not done here
 * because no transcript observed so far makes that the binding constraint.
 *
 * Re-stats the file immediately before opening it — yes, files() already
 * stat'd it once. That's deliberate, not an oversight: re-checking right
 * before open narrows the TOCTOU window between "we decided this looks
 * like a readable file" and "we actually opened it," which matters more
 * here than saving one syscall, given the entry may be a symlink whose
 * target isn't guaranteed stable between the two points.
 *
 * Returns { lines, status, bytesRead }. `status` is "complete", "partial"
 * (some lines WERE read before a failure — scan them, don't discard real
 * content just because the file didn't finish cleanly), "too-large", or
 * "failed" (nothing could be read at all — e.g. deleted between the files()
 * walk and this call, plausible mid-scan if Claude Code is actively
 * writing). Callers should scan `lines` whenever present, and treat
 * anything other than "complete" as worth surfacing to the user rather
 * than silently folding into a clean report.
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

  // No natural timeout exists anywhere in Node's stream/readline stack. A
  // symlink whose target changes between the stat above and this open
  // (e.g. retargeted onto a FIFO with no writer) can make the underlying
  // open() block forever with no 'error', 'line', or 'close' ever firing —
  // destroying the stream is what actually unblocks that. Without this, one
  // hostile or merely unlucky file hangs the entire CLI, no way out.
  const timer = setTimeout(() => stream.destroy(new Error("read timed out")), READ_TIMEOUT_MS);

  try {
    for await (const line of rl) {
      lines.push(line);
      bytesRead += Buffer.byteLength(line, "utf-8") + 1; // +1 for the stripped newline
    }
    return { lines, status: "complete", bytesRead };
  } catch {
    // Whatever WAS read before the failure is real content and may contain
    // a real secret — discarding it because the file didn't finish cleanly
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
