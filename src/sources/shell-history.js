"use strict";

const fs = require("fs");
const path = require("path");
const os = require("os");
const { createInterface } = require("readline/promises");

/**
 * Interactive shell and REPL/DB-client history files.
 *
 * SCOPE, stated plainly because this is the second source in this project
 * (after agent-configs.js) that is not literally "an AI agent's session
 * history": these files record what the DEVELOPER typed at a real
 * interactive prompt, not what an agent wrote to disk on their behalf. It's
 * included because it's the same failure mode, one hop away from what this
 * tool already covers: a developer tests a curl call with a bearer token
 * before pasting the working version into an agent prompt, connects to a
 * database with a password embedded in the URI, or exports a token into a
 * REPL to try a client library — plaintext, indefinitely, in a file almost
 * nobody thinks to check, the exact description this project's own README
 * opens with. It is also a real, disclosed, competitor-named gap: Medusa
 * (see docs/comparison.md's Medusa section) already scans exactly
 * bash/zsh/fish/psql/mysql/python-REPL history and residoo did not.
 *
 * Every path below is a documented default or a documented override
 * environment variable from that tool's own primary docs, fetched directly
 * (not assumed by analogy to a similar tool) on 2026-09-05:
 *
 *   - **bash**: `~/.bash_history` is bash's own long-standing built-in
 *     default (its manual page).
 *   - **zsh**: NOT a shell-level default the way bash's is — zsh's own
 *     manual (zsh.sourceforge.io/Doc/Release/Parameters.html) states
 *     plainly that if `HISTFILE` is unset, "the history is not saved" at
 *     all. `~/.zsh_history` is checked anyway because it's the exact path
 *     zsh's own bundled `zsh-newuser-install` script offers a new user who
 *     accepts history saving, and the default both Oh My Zsh's and
 *     Prezto's stock templates set — the de facto convention on most real
 *     machines, not a shell-level guarantee. `$HISTFILE`, when set, is
 *     checked once for both bash and zsh: a set value can't be attributed
 *     to one shell over the other from outside the shell itself.
 *   - **fish**: `$XDG_DATA_HOME/fish/fish_history`, defaulting to
 *     `~/.local/share/fish/fish_history` when that variable is unset —
 *     fish's own docs (fishshell.com/docs/current/interactive.html) state
 *     this exact default and XDG override.
 *   - **psql**: `~/.psql_history` (Unix) or
 *     `%APPDATA%\postgresql\psql_history` (Windows) — PostgreSQL's own
 *     psql docs (postgresql.org/docs/current/app-psql.html) state both
 *     paths as the default. No environment-variable override is
 *     documented; psql's own `\set HISTFILE ...` is an in-session psql
 *     variable, not a process environment variable residoo can read from
 *     outside the running psql process.
 *   - **mysql**: `$MYSQL_HISTFILE`, defaulting to `~/.mysql_history` —
 *     MySQL's own reference manual (dev.mysql.com/doc/refman/8.4/en/
 *     mysql-logging.html) documents both, and its own text recommends
 *     restricting this file's permissions because it "may contain
 *     sensitive information" — a vendor admission of exactly the failure
 *     mode this source exists to catch.
 *   - **Python** (interactive interpreter): `$PYTHON_HISTORY`, defaulting
 *     to `~/.python_history` — Python's own docs (docs.python.org/3/using/
 *     cmdline.html). The environment variable is Python 3.13+ only (added
 *     that release); reading it on an older interpreter simply finds it
 *     unset and falls through to the same fixed default, so no version
 *     check is needed here.
 *   - **Node.js REPL**: `$NODE_REPL_HISTORY`, defaulting to
 *     `~/.node_repl_history` — Node's own docs (nodejs.org/api/repl.html),
 *     which also document that an empty or whitespace-only value means the
 *     user explicitly disabled persistent history; honored here exactly as
 *     documented rather than treated as "unset."
 *
 * VERIFICATION STATUS: `~/.bash_history` and `~/.python_history` are
 * REAL-INSTALL-VERIFIED — both exist on this project's own build machine
 * with genuine, non-empty content (confirmed directly, read-only, before
 * this source was written). zsh/fish/psql/mysql/Node history are
 * MULTI-SOURCE-CORROBORATED-BUT-UNVERIFIED: each path above comes from
 * that tool's own primary documentation, but none of those five files
 * exist on the machine this was built on, so the schema (there isn't
 * one — every one of these is already plain line-delimited text) is
 * unverified against real content the same way most of this project's
 * other sources are. If you use zsh, fish, psql, mysql, or the Node REPL
 * with a populated history file, running `residoo scan` and confirming
 * `filesScanned` looks right is the single most useful way to firm this
 * up (see CONTRIBUTING.md).
 *
 * FORMAT: every one of these files is already plain line-delimited text —
 * zsh's optional "extended history" format (`: <ts>:<secs>;<command>`) and
 * fish's YAML-ish `- cmd: ...` / `  when: ...` records still carry the
 * actual command as a contiguous substring of one line, and every pattern
 * in `src/patterns.js` matches on `\b` word boundaries, never a `^`
 * line-start anchor — so no format-specific parsing is needed before
 * pattern matching, the same reasoning agent-configs.js's readLines()
 * docstring states for JSON/TOML config lines, and decode.js's own header
 * already anticipates this exact case ("plain-text chat logs, shell
 * history... used as-is").
 *
 * NOT covered, and why: shell history for any shell/tool not named above
 * (fish's own `fish_history` predecessor formats, csh/tcsh, sqlite3's
 * `.sqlite_history`, R's `.Rhistory`, IPython's separate SQLite-backed
 * history database) — each would need its own documented default and
 * schema check to the same bar as the seven above, not guessed by
 * analogy. A welcome follow-up PR, per CONTRIBUTING.md.
 */

const HOME = os.homedir();

function id() { return "shell-history"; }
function label() { return "Shell & REPL history"; }

/**
 * Every candidate path this source checks, deduplicated (a customized
 * override that happens to equal a default above would otherwise be
 * checked twice). Order has no behavioral meaning — statIfPresent handles
 * each independently.
 */
function candidatePaths() {
  const xdgDataHome = process.env.XDG_DATA_HOME || path.join(HOME, ".local", "share");
  const nodeReplHistory = process.env.NODE_REPL_HISTORY;
  const nodeReplDisabled = nodeReplHistory !== undefined && nodeReplHistory.trim() === "";

  const paths = [
    path.join(HOME, ".bash_history"),
    path.join(HOME, ".zsh_history"),
    ...(process.env.HISTFILE ? [process.env.HISTFILE] : []),
    path.join(xdgDataHome, "fish", "fish_history"),
    process.platform === "win32"
      ? path.join(process.env.APPDATA || path.join(HOME, "AppData", "Roaming"), "postgresql", "psql_history")
      : path.join(HOME, ".psql_history"),
    process.env.MYSQL_HISTFILE || path.join(HOME, ".mysql_history"),
    process.env.PYTHON_HISTORY || path.join(HOME, ".python_history"),
    ...(nodeReplDisabled ? [] : [nodeReplHistory || path.join(HOME, ".node_repl_history")]),
  ];

  return [...new Set(paths)];
}

/**
 * Resolve one fixed candidate path into zero or one files() entries.
 * Duplicated from agent-configs.js's statIfPresent rather than imported,
 * per this project's one-small-self-contained-file-per-source convention
 * (see cursor.js's own docstring for the same point). Absence (ENOENT/
 * ENOTDIR) is the normal, expected case for a tool the user doesn't use
 * and yields nothing; anything else that stops the path resolving (a
 * dangling symlink, a permission error) is a broken entry, not silent
 * absence — the same never-a-false-all-clear reasoning as every other
 * source here.
 */
function* statIfPresent(p) {
  let lst;
  try { lst = fs.lstatSync(p); }
  catch (err) {
    if (err && (err.code === "ENOENT" || err.code === "ENOTDIR")) return;
    yield { file: p, broken: true };
    return;
  }

  if (lst.isSymbolicLink()) {
    try {
      const st = fs.statSync(p);
      if (!st.isFile()) { yield { file: p, broken: true }; return; }
      yield { file: p, mtimeMs: st.mtimeMs, sizeBytes: st.size, broken: false };
    } catch {
      yield { file: p, broken: true };
    }
    return;
  }

  if (!lst.isFile()) return;
  yield { file: p, mtimeMs: lst.mtimeMs, sizeBytes: lst.size, broken: false };
}

/**
 * True when any candidate history file actually exists. Unlike
 * agent-configs.js (which gates on a per-tool ROOT directory so an
 * installed-but-empty tool still shows as checked), none of the files
 * here have a natural "installed" signal separate from the file's own
 * existence — there is no `~/.bash/` directory to check instead. A
 * machine with none of these files present correctly doesn't list this
 * source at all, the same as a brand-new machine with no shell history
 * yet would have nothing meaningful to report either way.
 */
function available() {
  for (const p of candidatePaths()) {
    for (const _ of statIfPresent(p)) return true;
  }
  return false;
}

/**
 * Yield { file, mtimeMs, sizeBytes, broken } for every candidate present.
 */
function* files() {
  for (const p of candidatePaths()) yield* statIfPresent(p);
}

// Real observations on this project's own build machine: ~40KB
// (~.bash_history, years of use) and ~6.6KB (~.python_history). 256MB is a
// generous, uncalibrated backstop against a corrupted or pathological file
// (the same caveat cursor.js states for its own size bound), not a measured
// ceiling — a file over it is surfaced as "too-large", never silently
// skipped.
const MAX_BYTES = 256 * 1024 * 1024;
const READ_TIMEOUT_MS = 60_000;

/**
 * Read one history file as an array of raw text lines. Identical streaming
 * shape (readline/promises, MAX_BYTES cap, READ_TIMEOUT_MS watchdog,
 * partial-read lines kept rather than discarded) to every other source
 * here — see claude-code.js's readLines() docstring for the full
 * reasoning, all of which applies unchanged since this is plain
 * line-delimited UTF-8 text on disk (see the module docstring's FORMAT
 * section for why no per-tool parsing is needed first).
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
      bytesRead += Buffer.byteLength(line, "utf-8") + 1; // +1 for the stripped newline
    }
    return { lines, status: "complete", bytesRead };
  } catch {
    // Lines read before the failure are real content and may hold a real
    // secret -- an honest "partial" beats a silent false negative.
    return { lines, status: lines.length > 0 ? "partial" : "failed", bytesRead };
  } finally {
    clearTimeout(timer);
    rl.close();
    stream.destroy();
  }
}

module.exports = { id, label, available, files, readLines };
