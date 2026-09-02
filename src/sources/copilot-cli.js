"use strict";

const fs = require("fs");
const { createInterface } = require("readline/promises");
const path = require("path");
const os = require("os");

/**
 * GitHub Copilot CLI — the standalone `copilot` agentic terminal tool
 * (npm package `@github/copilot`; also reachable as `gh copilot` once
 * installed). NOT the VS Code "Copilot Chat" panel — see copilot-chat.js for
 * that genuinely different product with a genuinely different storage
 * format. Also NOT the older `gh-copilot` `gh` CLI extension (the
 * `suggest`/`explain` command-line-suggestion tool) — that predecessor is
 * unrelated and out of scope here; this adapter targets the current agentic
 * CLI whose own docs are cited below.
 *
 * VERIFICATION STATUS (read this before trusting anything below):
 * multi-source-corroborated-but-UNVERIFIED against a real install. Copilot
 * CLI is not installed on the machine this adapter was built on (checked:
 * no ~/.copilot, no `copilot` on PATH, no `gh extension list` entry, no
 * Homebrew formula/cask installed under that name — the one local
 * "copilot.rb" formula present is an unrelated AWS tool, `aws/copilot-cli`).
 * Corroborating sources, most authoritative first:
 *
 *  1. Official GitHub Docs, "GitHub Copilot CLI configuration directory"
 *     (docs.github.com/en/copilot/reference/copilot-cli-reference/
 *     cli-config-dir-reference), fetched 2026-09-02. States plainly: default
 *     location is `~/.copilot` (`$HOME/.copilot`), overridable via the
 *     `COPILOT_HOME` environment variable. Its own directory-listing table
 *     names, verbatim: `session-state/` ("Session history and workspace
 *     data"), `command-history-state/` ("Command history data"), `logs/`
 *     ("Session log files", named `process-{timestamp}-{pid}.log`), and
 *     `session-store.db` (File — "SQLite database for cross-session data").
 *     Separately also names `config.json` ("automatically managed
 *     application state including authentication"), `mcp-secrets/`, and
 *     `mcp-oauth-config/` — this tool's OWN credential/token storage, not
 *     conversation content; deliberately excluded here, same reasoning
 *     claude-code.js's scope never reaches `~/.claude.json`.
 *  2. Official GitHub Docs, "About GitHub Copilot CLI session data"
 *     (docs.github.com/en/copilot/concepts/agents/copilot-cli/chronicle),
 *     fetched 2026-09-02. States each session is persisted as "a set of
 *     files in the `~/.copilot/session-state/` directory," recording "your
 *     prompts, Copilot's responses, the tools that were used, and details of
 *     files that were modified" — i.e. exactly the transcript content this
 *     scanner exists to check, confirmed as living there by GitHub's own
 *     docs, not just inferred.
 *  3. jonmagic.com/posts/github-copilot-session-search-and-resume-cli/ — a
 *     real practitioner's own inspection of actual files on their machine,
 *     independent of GitHub's docs. Confirms the concrete shape:
 *     `~/.copilot/session-state/<uuid>/` per session, containing
 *     `workspace.yaml` (metadata) and `events.jsonl` (a newline-delimited
 *     JSON event stream — quotes real event lines: `session.start`,
 *     `user.message`, `assistant.turn_start`, `tool.execution_start` with
 *     its `arguments`, `tool.execution_complete`, `session.shutdown`), and
 *     explicitly notes "some sessions have additional files such as
 *     `session.db`, plans, checkpoints, or VS Code metadata" that "vary by
 *     Copilot version" — i.e. confirms the file set is NOT a fixed, safely
 *     allow-listable list, which is why files() below does not hard-code one
 *     (same reasoning cursor.js gives for not allow-listing its own row
 *     keys).
 *  4. dfberry.github.io/2026-04-16-session-storage-decision-guide —
 *     independently corroborates `session-state/<id>/events.jsonl` and
 *     `session-store.db`, and adds the SQLite schema: seven tables
 *     including "sessions, turns, checkpoints, session_files, session_refs"
 *     plus an FTS5 search index, and warns not to delete the `.db-wal` file
 *     while Copilot is running (confirming it's a live, WAL-mode SQLite
 *     file, not an inert export).
 *
 * `session-store.db`'s ROW-LEVEL schema (which column of which table, if
 * any, holds raw prompt/response text vs. only derived search-index data) is
 * corroborated by exactly ONE of the sources above (#4) — short of this
 * project's normal two-independent-source bar for a claim precise enough to
 * write a SQL query against, unlike cursor.js's table/column shape, which
 * had a real live install AND multiple agreeing write-ups behind it.
 * Guessing at that schema is exactly the "SQLite schema drifted, bare
 * except/continue swallowed it, tool reported a full scan as clean" failure
 * this cluster's brief calls out by name. `session-store.db` is therefore
 * DELIBERATELY NOT queried here — the actual prompts/responses/tool-args
 * this scanner cares about are independently, solidly confirmed (sources
 * #2–#4 agree) to live in `session-state/**`'s plain-text files regardless,
 * so this is a named, bounded gap rather than a load-bearing one. If a
 * future contributor confirms the exact table/column shape against a real
 * install, add it then — with that verification.
 *
 * `command-history-state` has been reported in TWO conflicting shapes across
 * the sources above and elsewhere: the official config-dir-reference table
 * (#1) lists it as a DIRECTORY (`command-history-state/`), while several
 * independent write-ups (inventivehq.com's own config-file breakdown;
 * rajeevpentyala.com's "[Quick Tip] GitHub Copilot CLI | Get Prompt History")
 * describe a single FILE, `command-history-state.json`, holding a
 * `commandHistory` array of every prompt typed. Rather than guess which is
 * current, this adapter checks for BOTH shapes and scans whichever is
 * actually present — the same "don't pick a side, read what's really there"
 * approach cursor.js takes for its own two-possible-storage-location
 * uncertainty. This is real typed-prompt content (a very plausible place for
 * a pasted secret to land) and is in scope.
 *
 * Deliberately excluded, named rather than silently skipped: `settings.json`,
 * `config.json`, `lsp-config.json`, `mcp-config.json`,
 * `permissions-config.json`, `mcp-oauth-config/`, `mcp-secrets/`,
 * `agents/`, `skills/`, `instructions/`, `extensions/`, `hooks/`,
 * `installed-plugins/`, `plugin-data/`, `ide/`, and `session-store.db`
 * (discussed above). These are Copilot CLI's OWN configuration and
 * credential/token storage, not user session transcripts — scanning and
 * potentially surfacing THOSE would run against residoo's own purpose, and
 * mirrors claude-code.js never reaching into `~/.claude/settings.json` or
 * `~/.claude.json`.
 */
function copilotHome() {
  const override = process.env.COPILOT_HOME;
  if (override) return override; // per official docs; used as given, same trust level cursor.js gives XDG_CONFIG_HOME
  return path.join(os.homedir(), ".copilot");
}

const ROOT = copilotHome();

// Storage-class extensions this adapter knows are SQLite (or its WAL/SHM/
// journal siblings) and deliberately does not treat as scannable text —
// covers both the top-level session-store.db and any per-session
// "session.db" jonmagic.com's inspection found inside session-state/<uuid>/.
// Matched case-insensitively against the file's extension only.
const BINARY_DB_EXTENSIONS = new Set([".db", ".db-wal", ".db-shm", ".db-journal", ".sqlite", ".sqlite3"]);

// Bounds for readLines() — same values as claude-code.js. Not backed by a
// real Copilot CLI transcript this tool was tested against (no install to
// test with) — see the verification-status note above.
const MAX_BYTES = 2 * 1024 * 1024 * 1024; // 2GB
const READ_TIMEOUT_MS = 60_000;

// Recursion guard for walking session-state/ and command-history-state/ —
// per-session subdirectories are one level deep in every source consulted,
// but the cap (and symlink-cycle de-dup) exists purely to bound a
// pathological or unexpectedly deep layout, same as windsurf.js's own walk.
const MAX_WALK_DEPTH = 12;

function id() { return "copilot-cli"; }
function label() { return "GitHub Copilot CLI"; }

function available() {
  try { return fs.statSync(ROOT).isDirectory(); } catch { return false; }
}

/**
 * Same defensive symlink-following pattern as claude-code.js's
 * isDirFollowingSymlink/isFileFollowingSymlink — see that file's docstring
 * for the full reasoning. Duplicated rather than imported, matching this
 * project's "small, self-contained file" convention.
 */
function isKindFollowingSymlink(fullPath, dirent, checkFn) {
  if (checkFn(dirent)) return true;
  if (!dirent.isSymbolicLink()) return false;
  try { return checkFn(fs.statSync(fullPath)); } catch { return false; }
}
const isDirFollowingSymlink = (p, d) => isKindFollowingSymlink(p, d, (x) => x.isDirectory());
const isFileFollowingSymlink = (p, d) => isKindFollowingSymlink(p, d, (x) => x.isFile());

function isBinaryDbFile(name) {
  const ext = path.extname(name).toLowerCase();
  return BINARY_DB_EXTENSIONS.has(ext);
}

/**
 * Recursively yield { file, mtimeMs, sizeBytes, broken } for every file
 * under `dir` EXCEPT ones recognized as SQLite-family by extension (see
 * BINARY_DB_EXTENSIONS and the module docstring for why those are excluded
 * rather than read as text). No further extension allow-listing is done —
 * per jonmagic.com's own real inspection (cited above), the exact set of
 * per-session files varies by Copilot CLI version, so this walks whatever is
 * actually there, the same "don't hard-code a list likely to go stale"
 * reasoning cursor.js applies to its own row keys.
 *
 * A dangling symlink (file or directory) is reported broken:true rather
 * than silently skipped, matching claude-code.js's convention.
 * `visitedRealDirs` de-dupes symlinked directories by resolved real path so
 * a symlink cycle terminates instead of recursing forever.
 */
function* walkTextFiles(dir, depth, visitedRealDirs) {
  if (depth > MAX_WALK_DEPTH) return;

  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); }
  catch { return; } // this directory doesn't exist here — normal for an unused feature, not broken

  for (const e of entries) {
    const full = path.join(dir, e.name);

    if (isDirFollowingSymlink(full, e)) {
      if (e.isSymbolicLink()) {
        let real;
        try { real = fs.realpathSync(full); }
        catch { yield { file: full, broken: true }; continue; }
        if (visitedRealDirs.has(real)) continue;
        visitedRealDirs.add(real);
      }
      yield* walkTextFiles(full, depth + 1, visitedRealDirs);
      continue;
    }

    if (isBinaryDbFile(e.name)) continue; // known SQLite-family file — deliberately out of scope, see docstring

    if (!isFileFollowingSymlink(full, e)) {
      if (e.isSymbolicLink()) yield { file: full, broken: true };
      continue;
    }

    let stat;
    try { stat = fs.statSync(full); } catch { yield { file: full, broken: true }; continue; }
    yield { file: full, mtimeMs: stat.mtimeMs, sizeBytes: stat.size, broken: false };
  }
}

/**
 * Resolve the single-file shape of command-history-state
 * (~/.copilot/command-history-state.json — see docstring for why both
 * shapes are checked) into zero or one files() entries. Same lstat-based
 * logic and broken-vs-absent convention as cursor.js's statIfPresent().
 */
function* statIfPresentFile(filePath) {
  let lst;
  try { lst = fs.lstatSync(filePath); }
  catch { return; }

  if (lst.isSymbolicLink()) {
    try {
      const st = fs.statSync(filePath);
      if (!st.isFile()) { yield { file: filePath, broken: true }; return; }
      yield { file: filePath, mtimeMs: st.mtimeMs, sizeBytes: st.size, broken: false };
    } catch {
      yield { file: filePath, broken: true };
    }
    return;
  }

  if (!lst.isFile()) return;
  yield { file: filePath, mtimeMs: lst.mtimeMs, sizeBytes: lst.size, broken: false };
}

/**
 * Yield { file, mtimeMs, sizeBytes, broken } for every candidate transcript
 * file this adapter knows how to find under $COPILOT_HOME (default
 * ~/.copilot): every non-SQLite file under session-state/ and under
 * command-history-state/ (if it exists as a directory), the single
 * command-history-state.json file (if it exists instead, as a file), and
 * every non-SQLite file under logs/.
 */
function* files() {
  yield* walkTextFiles(path.join(ROOT, "session-state"), 0, new Set());
  yield* walkTextFiles(path.join(ROOT, "command-history-state"), 0, new Set());
  yield* statIfPresentFile(path.join(ROOT, "command-history-state.json"));
  yield* walkTextFiles(path.join(ROOT, "logs"), 0, new Set());
}

/**
 * Read one file as an array of raw text lines.
 *
 * Every format this adapter's files() can yield is real UTF-8 text by
 * construction: `events.jsonl` is one JSON record per line (confirmed
 * directly from jonmagic.com's quoted real event lines), `workspace.yaml`
 * and `command-history-state.json`/`.../*.json` are ordinary structured
 * text, and `logs/process-*.log` are plain log files. The same streamed
 * readline/promises approach claude-code.js and cline.js use applies
 * unchanged here — no whole-file-as-one-string V8 length ceiling, and a
 * partial read still returns whatever lines WERE read rather than
 * discarding real content. Status vocabulary matches every other source in
 * this project: "complete", "partial", "too-large", "failed".
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

  // Same rationale as claude-code.js: no natural timeout exists anywhere in
  // Node's stream/readline stack, and a retargeted symlink can make the
  // underlying open() block forever with no event ever firing. Destroying
  // the stream is what actually unblocks that.
  const timer = setTimeout(() => stream.destroy(new Error("read timed out")), READ_TIMEOUT_MS);

  try {
    for await (const line of rl) {
      lines.push(line);
      bytesRead += Buffer.byteLength(line, "utf-8") + 1; // +1 for the stripped newline
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
