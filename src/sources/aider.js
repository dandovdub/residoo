"use strict";

const fs = require("fs");
const { createInterface } = require("readline/promises");
const path = require("path");
const os = require("os");

/**
 * Aider (github.com/Aider-AI/aider) session transcripts.
 *
 * VERIFICATION STATUS (read this before trusting anything below): the file
 * names, on-disk format, and location logic below are corroborated across
 * FOUR independent, current sources —
 *
 *   1. Aider's own official docs (aider.chat/docs/config/options.html),
 *      which document `--chat-history-file` (default `.aider.chat.history.md`)
 *      and `--input-history-file` (default `.aider.input.history`).
 *   2. Aider's own current GitHub source (Aider-AI/aider, `aider/args.py`,
 *      main branch — fetched directly, not from a cache or a summary):
 *        default_input_history_file = os.path.join(git_root, ".aider.input.history")
 *                                       if git_root else ".aider.input.history"
 *        default_chat_history_file  = os.path.join(git_root, ".aider.chat.history.md")
 *                                       if git_root else ".aider.chat.history.md"
 *      i.e. these are NOT under one fixed root the way Claude Code's or
 *      Cursor's storage is — they land at the root of whatever git repo the
 *      user ran `aider` inside (or the bare CWD if that wasn't a git repo).
 *      A real user independently ran into exactly this scattering, filing
 *      Aider-AI/aider#2684 ("history files accumulate ... outside git
 *      repos"), which corroborates the CWD/git-root behaviour from the
 *      outside, not just from reading the source.
 *   3. A REAL, live `.aider.chat.history.md` from an actual aider user, who
 *      committed it to their own public repo (github.com/dfeldman/
 *      operation-conundrum.github.io, file `aider-chat-history.md`, 2628
 *      lines, dated 2023-05-26 in-content). Fetched and inspected directly.
 *      It matches the documented format exactly: sessions delimited by
 *      `# aider chat started at <timestamp>`, each user message as one or
 *      more `#### `-prefixed markdown lines, tool/system notices as `> `
 *      blockquote lines, assistant replies as plain markdown including
 *      fenced code blocks and aider's own `<<<<<<< ORIGINAL / ======= /
 *      >>>>>>> UPDATED` search-replace diff blocks.
 *   4. `.aider.input.history` is not aider's own format at all — aider hands
 *      it straight to `prompt_toolkit.history.FileHistory`, a dependency of
 *      aider's. Fetched that library's own current source
 *      (python-prompt-toolkit, `src/prompt_toolkit/history.py`,
 *      `FileHistory.store_string`) directly: every stored input is appended
 *      as `\n# <datetime>\n` followed by that input's lines, each prefixed
 *      with a literal `+`. So this file is not free-form text so much as a
 *      well-known third-party library's fixed serialization — verified
 *      against that library's own code, not guessed.
 *
 * What none of the above is: a real Aider install on the machine this
 * source was built on. Checked directly and thoroughly — `which aider`,
 * `pip3 show aider-chat` / `python3 -m pip show aider-chat`, `brew list
 * aider`, `pipx list`, common config locations (`~/.config`, `~/Library/
 * Application Support`, `~/Library/Caches`, `~/Library/Preferences`), and a
 * filesystem-wide `find`/`mdfind` for `.aider*` and `*aider-chat-history*`.
 * All came back empty: aider is not installed here, and there is no real
 * session history on this machine to genuinely verify the schema against.
 * Per CONTRIBUTING.md's rule 3, this ships anyway because of the four
 * corroborating sources above, but should be treated the same way cursor.js
 * asks to be treated: real, but UNVERIFIED against a live install. If you
 * have Aider installed, running `residoo scan` and checking the results
 * against what you know is really in your `.aider.chat.history.md` /
 * `.aider.input.history` files is the single most useful way to firm this
 * up — please report back either way.
 *
 * WHERE THIS SOURCE LOOKS — the fundamentally different problem vs.
 * claude-code.js / cursor.js:
 *
 * Both of those tools keep everything under one fixed, well-known directory
 * this machine can enumerate directly (~/.claude/projects,
 * .../Cursor/User). Aider, by its own design (see source citation #2
 * above), has no such thing — its two history files can be sitting at the
 * root of literally any git repository, or any bare directory, the user has
 * ever run `aider` from. There is no manifest anywhere that lists which
 * directories those were: `~/.aider/installs.json` (see AIDER_HOME below)
 * only ever records `(version, python-executable)` pairs for "what's new"
 * notes, and `~/.aider/analytics.json` records anonymized event counters,
 * neither ever a path. Confirmed directly against aider's own
 * `is_first_run_of_new_version()` in `main.py` and `Analytics` in
 * `analytics.py`.
 *
 * So `files()` below does a bounded, best-effort walk of the user's home
 * directory looking for the two exact filenames above (plus, opportunistically,
 * the one non-default file named below) at any depth. This is an honest,
 * named engineering tradeoff, not a guess about WHERE aider's format lives
 * (that part is verified, see above) — it is a search-breadth compromise for
 * a location that is, by the tool's own design, unbounded. The walk is
 * gated behind available() (see below) so a user who has never touched
 * aider pays nothing for it, and it is bounded (MAX_DEPTH, MAX_DIRS_VISITED)
 * so a user who has pays a bounded, not unlimited, cost. Both bounds are
 * generous enough to cover realistic project layouts but this is explicitly
 * NOT an exhaustive filesystem search — a `.aider.chat.history.md` sitting
 * deeper than MAX_DEPTH below $HOME, or reachable only through a symlinked
 * directory (deliberately not followed — see walk()'s docstring), will be
 * missed. That is a real, named limitation, the same spirit as
 * claude-code.js's admitted peak-memory gap and cursor.js's admitted
 * untested-on-a-real-install gap — not a silent one.
 */

const HOME = os.homedir();

// Presence-only signal, NOT the location transcripts live in (see module
// docstring's "WHERE THIS SOURCE LOOKS" section). Aider writes into this
// directory on essentially every normal run — install-tracking
// (installs.json), opt-in anonymous analytics (analytics.json), and OAuth
// provider tokens (oauth-keys.env) — confirmed directly against
// `Path.home() / ".aider"` in aider's own main.py/analytics.py. Its mere
// existence is a reliable, cheap, fixed-path way to answer "has aider ever
// actually run on this machine" without doing the expensive home-directory
// walk files() needs for the transcripts themselves.
const AIDER_HOME = path.join(HOME, ".aider");

const CHAT_HISTORY_NAME = ".aider.chat.history.md";
const INPUT_HISTORY_NAME = ".aider.input.history";
// --llm-history-file has NO default (default=None in args.py — confirmed
// directly) — it only exists if a user explicitly opted in. It is included
// here purely opportunistically, using the exact filename aider's own
// --help text uses as its example ("for example, .aider.llm.history"): if a
// file with this exact name happens to exist alongside the other two, scan
// it too, since aider's own LLM history log is plausibly full of pasted
// code/secrets. This is NOT a verified default location the way the other
// two are — it is a zero-cost opportunistic check with no default to be
// wrong about, and its absence should never be read as "surely not opted
// in," just "not opted in under the example name."
const LLM_HISTORY_NAME = ".aider.llm.history";

const CANDIDATE_NAMES = new Set([CHAT_HISTORY_NAME, INPUT_HISTORY_NAME, LLM_HISTORY_NAME]);

function id() { return "aider"; }
function label() { return "Aider"; }

function available() {
  try { return fs.statSync(AIDER_HOME).isDirectory(); } catch { return false; }
}

// Bounds for the home-directory walk in files() — see the module docstring
// for why this walk exists at all. Not calibrated against any real, large
// aider user's directory tree (no real install on this machine — see
// module docstring); chosen as a generous-but-bounded backstop the same way
// cursor.js's MAX_DB_BYTES is, not a measured real-world ceiling the way
// claude-code.js's MAX_BYTES is.
const MAX_DEPTH = 8; // levels below $HOME a candidate file can be found at
const MAX_DIRS_VISITED = 50_000; // circuit breaker on total directories read

// Directory names never worth descending into, at any depth: version
// control internals, dependency/build output, and language/tool caches.
// This is a performance optimization only, not a correctness boundary —
// MAX_DIRS_VISITED is what actually bounds worst-case cost; skipping these
// just spends that budget on directories far more likely to matter. None of
// aider's own history files are ever written inside any of these (they live
// at a git root or a bare CWD — never inside .git/, node_modules/, etc.),
// so skipping them cannot hide a real match.
const ALWAYS_SKIP_DIR_NAMES = new Set([
  "node_modules", ".git", ".hg", ".svn", "vendor",
  ".venv", "venv", "__pycache__", ".tox", ".mypy_cache", ".pytest_cache", ".ruff_cache",
  ".next", ".nuxt", "dist", "build", "target", ".gradle", ".m2",
  ".cargo", ".rustup", ".npm", ".yarn", ".pnpm-store", ".cache",
  ".docker", ".orbstack", ".Trash", ".Trashes",
  ".Spotlight-V100", ".fseventsd", ".DocumentRevisions-V100", ".TemporaryItems",
]);

// Skipped ONLY as direct children of $HOME itself (depth 0), never at any
// deeper level — unlike the names above, these are ordinary, meaningful
// words a real project directory could legitimately be named (e.g. a repo
// literally called "build" or "Library"); they are only reliably "OS/user
// furniture, not a project" when sitting directly under the home directory.
const HOME_TOP_LEVEL_SKIP_DIR_NAMES = new Set([
  "Library", "Applications", "Pictures", "Movies", "Music", "Public", "Desktop",
  "AppData", // Windows counterpart to the above; harmless to check cross-platform
]);

/**
 * Same defensive symlink-following as claude-code.js's
 * isFileFollowingSymlink — duplicated locally rather than imported, same
 * reasoning cursor.js states: each source here is meant to be a small,
 * self-contained file a reviewer can audit on its own.
 *
 * Used only for the three known candidate filenames themselves (a single,
 * named entry) — see walk()'s docstring for why open-ended directory
 * recursion below deliberately does NOT get the same symlink-following
 * treatment.
 */
function isFileFollowingSymlink(fullPath, dirent) {
  if (dirent.isFile()) return true;
  if (!dirent.isSymbolicLink()) return false;
  try { return fs.statSync(fullPath).isFile(); } catch { return false; }
}

/**
 * Resolve one candidate-named directory entry (`.aider.chat.history.md`,
 * `.aider.input.history`, or `.aider.llm.history`) into zero or one files()
 * entries, following a symlink with that exact name the same way
 * claude-code.js follows a `*.jsonl`-named symlink. `broken: true` is
 * reserved for a symlink with one of these exact names that fails to
 * resolve — genuinely "this looked like an aider history file and wasn't
 * readable," not the general "most directories we visit aren't
 * aider-related at all" case walk() itself silently passes over (see its
 * docstring).
 */
function* candidateEntry(fullPath, dirent) {
  if (!isFileFollowingSymlink(fullPath, dirent)) {
    if (dirent.isSymbolicLink()) yield { file: fullPath, broken: true };
    return; // e.g. a directory that happens to be named exactly this — out of scope, not broken
  }
  let stat;
  try { stat = fs.statSync(fullPath); }
  catch { yield { file: fullPath, broken: true }; return; }
  yield { file: fullPath, mtimeMs: stat.mtimeMs, sizeBytes: stat.size, broken: false };
}

/**
 * Recursively walk `dir` (`depth` levels below $HOME) looking for the
 * candidate filenames above, subject to `budget` (a shared { remaining }
 * counter across the whole walk — see MAX_DIRS_VISITED).
 *
 * Two deliberate departures from claude-code.js/cursor.js's walking style,
 * both because this walk is open-ended (an unbounded, unknown directory
 * tree) rather than a listing of one specific, known, expected location:
 *
 *  1. Directory symlinks are NOT followed during recursion (only
 *     `dirent.isDirectory()`, lstat semantics). Following them here — unlike
 *     following a single, specific, known symlink such as
 *     ~/.claude/projects/<slug> — risks an infinite cycle (a symlinked
 *     directory pointing back at one of its own ancestors), which an
 *     open-ended walk has no other guard against. MAX_DIRS_VISITED still
 *     bounds worst case even if this reasoning has a gap, but not following
 *     directory symlinks is the primary defense.
 *  2. A directory that fails to list (fs.readdirSync throws — permission
 *     denied, deleted mid-walk, etc.) is silently skipped, NOT reported via
 *     `broken: true`. claude-code.js reports that for a project directory
 *     under ~/.claude/projects because every entry there is a known,
 *     expected Claude Code project folder — a read failure is anomalous and
 *     worth surfacing. Here, the overwhelming majority of directories this
 *     function visits have nothing to do with aider at all (this is a
 *     speculative, exploratory walk of $HOME) — treating every
 *     permission-denied OS directory encountered along the way as a
 *     reportable "broken" entry would flood the report with noise carrying
 *     no actionable signal. `broken` stays reserved for the specific, named
 *     candidate files themselves (see candidateEntry above), exactly
 *     mirroring how claude-code.js/cursor.js already treat "some unrelated
 *     stray entry" as silently out of scope while treating a failure on a
 *     specifically-expected entry as reportable.
 */
function* walk(dir, depth, budget) {
  if (budget.remaining <= 0) return;
  budget.remaining--;

  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); }
  catch { return; }

  const atHomeLevel = depth === 0;
  for (const e of entries) {
    const full = path.join(dir, e.name);

    if (CANDIDATE_NAMES.has(e.name)) {
      yield* candidateEntry(full, e);
      continue;
    }

    if (depth >= MAX_DEPTH) continue;
    if (!e.isDirectory()) continue; // no symlink-following in open-ended recursion — see docstring above
    if (ALWAYS_SKIP_DIR_NAMES.has(e.name)) continue;
    if (atHomeLevel && HOME_TOP_LEVEL_SKIP_DIR_NAMES.has(e.name)) continue;

    yield* walk(full, depth + 1, budget);
  }
}

/**
 * Yield { file, mtimeMs, sizeBytes, broken } for every aider history file
 * found under $HOME. See the module docstring's "WHERE THIS SOURCE LOOKS"
 * section for what this walk is and is not guaranteed to cover.
 */
function* files() {
  // available() is the cheap gate on the (unrelated) ~/.aider directory —
  // see that directory's own comment above for why checking it here, unlike
  // in claude-code.js/cursor.js, is necessary rather than redundant: this
  // function's walk root ($HOME) is not the same directory available()
  // checks, so without this line every residoo user — aider or not — would
  // pay for a full home-directory walk on every scan.
  if (!available()) return;

  const budget = { remaining: MAX_DIRS_VISITED };
  yield* walk(HOME, 0, budget);
}

// Bounds for readLines() — same rationale and same numbers as
// claude-code.js, but NOT calibrated against a real large aider file the
// way claude-code.js's MAX_BYTES was (no real install — see module
// docstring). Markdown chat transcripts and prompt_toolkit's input-history
// format are both far more compact than JSONL tool-call payloads (no
// embedded base64, no repeated schema keys), so multi-gigabyte real files
// are less likely here than for claude-code.js — but with nothing real to
// measure, this stays a generous backstop rather than a measured ceiling.
const MAX_BYTES = 2 * 1024 * 1024 * 1024; // 2GB
const READ_TIMEOUT_MS = 60_000;

/**
 * Read one aider history file as an array of raw text lines.
 *
 * Both known formats are already meaningfully line-oriented, so no
 * reformatting is needed before pattern matching:
 *   - .aider.chat.history.md is Markdown — every line (a `#### ` prompt
 *     line, a `> ` tool-notice line, a fenced-code-block line, plain
 *     assistant prose) is exactly one scanned line, same as any other text
 *     file this codebase reads.
 *   - .aider.input.history is prompt_toolkit's FileHistory serialization —
 *     each stored input's lines are written back out one per file line,
 *     each prefixed with a literal `+` (plus interleaved `# <datetime>`
 *     comment lines) — see source citation #4 in the module docstring. The
 *     leading `+` is left in place rather than stripped: every pattern in
 *     src/patterns.js matches on `\b` word boundaries, never a `^`
 *     line-start anchor (checked directly against patterns.js), so a
 *     secret on a `+`-prefixed line is matched exactly as it would be
 *     without the prefix. Stripping it would be extra code with no
 *     detection benefit.
 *
 * Implementation (streaming via readline/promises, MAX_BYTES cap,
 * READ_TIMEOUT_MS watchdog, partial-read lines kept rather than discarded)
 * is deliberately identical in shape to claude-code.js's readLines() — see
 * that file's docstring for the full reasoning on each of those choices,
 * all of which apply here unchanged (this is plain line-delimited UTF-8
 * text on disk either way, not a database or JSON blob needing cursor.js's
 * different approach). Duplicated rather than imported, per this project's
 * one-small-self-contained-file-per-source convention (see cursor.js's own
 * docstring for the same point).
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
    // Whatever WAS read before the failure is real content and may contain
    // a real secret — discarding it because the file didn't finish cleanly
    // would be a silent false negative, same reasoning as claude-code.js.
    return { lines, status: lines.length > 0 ? "partial" : "failed", bytesRead };
  } finally {
    clearTimeout(timer);
    rl.close();
    stream.destroy();
  }
}

module.exports = { id, label, available, files, readLines };
