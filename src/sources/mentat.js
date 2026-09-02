"use strict";

const fs = require("fs");
const { createInterface } = require("readline/promises");
const path = require("path");
const os = require("os");

/**
 * Mentat (github.com/AbanteAI/mentat, originally "the AI coding assistant"
 * from AbanteAI, predates most of this project's other sources) session
 * transcripts.
 *
 * VERIFICATION STATUS: NOT checked against a real Mentat install — `mentat`
 * is not on PATH and no `~/.mentat` directory exists on the machine this
 * adapter was built on (checked PATH, pip3 show, pipx list, mdfind). Mentat
 * itself is no longer maintained: its original repo now redirects to
 * github.com/AbanteAI/archive-old-cli-mentat, archived 2025-01-07. It ships
 * here anyway per CONTRIBUTING.md rule 3 — a tool being unmaintained doesn't
 * make transcripts it already wrote to a real user's disk any less worth
 * scanning — on the strength of the single strongest kind of source this
 * project cites anywhere: the project's OWN final, real source code, read
 * directly (not summarized, not a blog post), which settles the path and
 * format questions unambiguously:
 *
 *   - `mentat/utils.py`: `mentat_dir_path = Path.home() / ".mentat"`
 *   - `mentat/logging_config.py`: `logs_path = mentat_dir_path / "logs"`,
 *     and inside `setup_logging()` (run on every real session, skipped only
 *     when `is_test_environment()`):
 *       `transcripts_handler = logging.FileHandler(logs_path /
 *        f"transcript_{timestamp}.log")`
 *     with `timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")`
 *     and the handler's formatter set to bare `"%(message)s")` — i.e. each
 *     logged line is written to the file verbatim, nothing prepended.
 *   - `mentat/transcripts.py`'s own `get_transcript_logs()` confirms the
 *     shape from the reader side: it globs `transcript_*` under `logs_path`,
 *     calls `f.readlines()`, and reconstructs a JSON array as
 *     `json.loads("[" + ", ".join(transcript) + "]")` — which only works if
 *     every physical line is already one complete, self-contained JSON
 *     object (a user turn, a model turn, or an agent-only side message; see
 *     the `TranscriptMessage`/`UserMessage`/`ModelMessage` TypedDicts in
 *     that same file). That is exactly the "one JSON object per line" shape
 *     this source reads — no different in spirit from Claude Code's own
 *     JSONL transcripts, just named `transcript_<timestamp>.log` instead of
 *     `<session-id>.jsonl`.
 *
 * Deliberately NOT scanned: `mentat_<timestamp>.log` (Mentat's general debug
 * log, same directory, same timestamp) and `costs.log` — neither is the
 * transcript log Mentat's own code defines as the conversation record; only
 * `transcript_*.log` is what `get_transcript_logs()` itself reads back.
 */
const LOGS_DIR = path.join(os.homedir(), ".mentat", "logs");
const FILENAME_RE = /^transcript_.+\.log$/;

const MAX_BYTES = 2 * 1024 * 1024 * 1024; // 2GB — same generous headroom claude-code.js uses; not
                                            // empirically tested against a real huge Mentat transcript.
const READ_TIMEOUT_MS = 60_000;

function id() { return "mentat"; }
function label() { return "Mentat"; }

function available() {
  try { return fs.statSync(LOGS_DIR).isDirectory(); } catch { return false; }
}

/**
 * Same defensive symlink-following pattern as claude-code.js's
 * isDirFollowingSymlink/isFileFollowingSymlink — duplicated rather than
 * imported per this project's one-small-self-contained-file convention.
 */
function isKindFollowingSymlink(fullPath, dirent, checkFn) {
  if (checkFn(dirent)) return true;
  if (!dirent.isSymbolicLink()) return false;
  try { return checkFn(fs.statSync(fullPath)); } catch { return false; }
}
const isFileFollowingSymlink = (p, d) => isKindFollowingSymlink(p, d, (x) => x.isFile());

/**
 * Yield { file, mtimeMs, sizeBytes, broken } for every transcript log found
 * directly under ~/.mentat/logs (a flat directory — Mentat has no
 * per-project nesting the way Claude Code does). `broken: true` marks a
 * `transcript_*.log`-named entry that looked scannable but wasn't — chiefly
 * a dangling symlink — never silently skipped, per CONTRIBUTING.md rule 5.
 */
function* files() {
  let entries;
  try { entries = fs.readdirSync(LOGS_DIR, { withFileTypes: true }); }
  catch { return; }

  for (const e of entries) {
    if (!FILENAME_RE.test(e.name)) continue;
    const file = path.join(LOGS_DIR, e.name);
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

/**
 * Read one transcript log as an array of raw text lines — same
 * streamed/bounded/timed-out shape as claude-code.js's readLines(), for the
 * same reasons (see that file's docstring): line-by-line via
 * readline/promises rather than readFileSync+split to avoid V8's
 * single-string ceiling on a large file, a wall-clock destroy() timeout
 * because nothing in Node's stream stack provides one natively, and a
 * partial read's lines are kept and reported as "partial" rather than
 * discarded, because a secret in content that WAS read is still a finding.
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
