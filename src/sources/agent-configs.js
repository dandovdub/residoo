"use strict";

const fs = require("fs");
const path = require("path");
const os = require("os");
const { createInterface } = require("readline/promises");

/**
 * Agent CONFIG and STATE files — the first source in this project that is
 * not a transcript store. Configs earned their own source because they are
 * the best-MEASURED plaintext secret sink in the 2026 evidence base:
 * GitGuardian counted 24,008 secrets inside MCP config files on public
 * GitHub (2,117 still valid); Lakera found live credentials inside
 * `.claude/settings.local.json` files shipped in ~30 npm packages because
 * Claude Code's approved-command cache accumulates tokens and no packaging
 * tool ignores `.claude/` by default; and the year's supply-chain campaigns
 * (Mini Shai-Hulud, Miasma, ChainDrop) both PLANT persistence in and STEAL
 * from exactly these files. Published stealer target lists (JFrog's
 * Bitwarden-CLI-hijack write-up, StepSecurity's Nx Console analysis, the
 * keyv/Shai-Hulud reports) name several of the paths below verbatim.
 *
 * SCOPE — home-level only, and that limitation is real, not rhetorical:
 * project-level configs (`.mcp.json`, `.claude/settings.json`,
 * `.cursor/rules/`, `.vscode/tasks.json`, per-repo CLAUDE.md/AGENTS.md —
 * the files Miasma actually planted in cloned repos) live inside arbitrary
 * repositories this tool has no way to enumerate from a home directory.
 * A clean report from this source therefore says nothing about any
 * project's own config files. v1 ships the home-level set because those
 * paths are fixed and verifiable; the project-level gap is stated here
 * rather than papered over.
 *
 * PER-PATH VERIFICATION (per CONTRIBUTING.md's no-guessed-paths rule —
 * "real install" below means the populated machine this source was built
 * on, checked read-only; "digest" means the 2026-09-02 research digest's
 * stealer target lists and campaign write-ups, which name exact paths):
 *
 *  - `~/.claude.json` — real install (present, live content) + named
 *    verbatim in JFrog's Bitwarden-CLI-hijack target list + Claude Code's
 *    own MCP docs (user-scoped MCP servers, env blocks included, are
 *    stored here).
 *  - `~/.claude.json.backup` — real install (present; Claude Code's own
 *    rewrite backup of the file above — same content, same secrets, and a
 *    scanner that reads the original but not its sibling copy would
 *    under-report).
 *  - `~/.claude/settings.json` — real install + the file Mini Shai-Hulud
 *    and Miasma planted `SessionStart` hooks into + StepSecurity's Nx
 *    Console write-up names it as a harvest target.
 *  - `~/.claude/settings.local.json` — real install + Lakera's ~30
 *    leaking npm packages are this exact filename. This file is the
 *    reason a config source exists at all: it is NOT supposed to hold
 *    secrets, and measurably does.
 *  - `~/.claude/mcp.json` — the one deliberate exception to the rule that
 *    a path must be vendor-documented or locally present: it is NEITHER
 *    (Claude Code stores user-scope MCP config inside `~/.claude.json`,
 *    and it does not exist on the real install verified against). It is
 *    included anyway because published stealer target lists hunt this
 *    exact name (JFrog's Bitwarden-CLI list: `~/.claude.json`,
 *    `.claude/mcp.json`, `~/.kiro/settings/mcp.json`) — where the file
 *    does exist (hand-written, third-party tooling, older forks), it is
 *    precisely what an attacker grabs, and when absent it yields nothing
 *    and costs one lstat.
 *  - `~/.claude/CLAUDE.md` — Claude Code's own memory docs (user memory
 *    file) + the TrapDoor campaign hid zero-width-Unicode exfiltration
 *    instructions in CLAUDE.md files + the digest's stealer roadmap names
 *    "memory files (MEMORY.md/CLAUDE.md)". Absent on the real install
 *    (the `~/.claude` root is present); scanned when it exists because
 *    memory files are where users paste the things they want remembered.
 *  - Claude Desktop `claude_desktop_config.json` — macOS
 *    `~/Library/Application Support/Claude/`: real install (present) +
 *    the official MCP docs (modelcontextprotocol.io, "Connect to local
 *    MCP servers") document it per-OS. Windows `%APPDATA%\Claude\`: same
 *    official MCP docs + multiple independent setup guides agree. Linux
 *    is deliberately NOT covered: there is no official Linux build, and
 *    the unofficial ports disagree with each other on the config location
 *    (`~/.config/Claude/` vs `~/.config/claude-desktop/`) — either pick
 *    would be a guessed path.
 *  - `~/.cursor/mcp.json` — Cursor's official MCP docs (the global,
 *    all-projects config; distinct from the per-profile storage
 *    cursor.js reads) + independent Snyk/liblab/TrueFoundry guides + the
 *    digest's ~/.cursor deep-dive. Not installed on the build machine.
 *  - `~/.gemini/settings.json` — Gemini CLI's official settings docs
 *    (user settings file) + Miasma planted `.gemini/settings.json` (the
 *    digest names the filename verbatim). Root resolution honors
 *    GEMINI_CLI_HOME exactly as gemini-cli.js does — that override was
 *    verified from the project's own source during that adapter's
 *    research, not guessed here.
 *  - `~/.codex/config.toml` — OpenAI's official docs (CODEX_HOME "sets
 *    the root directory for Codex state, including config...", and the
 *    Codex MCP docs document `mcp_servers` sections in config.toml with
 *    `env` tables — the documented way to hand an MCP server an API key)
 *    + multiple independent setup guides showing exactly that. Root
 *    resolution honors CODEX_HOME exactly as codex-cli.js does.
 *  - `~/.kiro/settings/mcp.json` — Kiro's official MCP configuration docs
 *    (global config; their own security page recommends `chmod 600` on
 *    it, a vendor admission it holds secrets) + named verbatim in JFrog's
 *    Bitwarden-CLI target list.
 *
 * DELIBERATELY NOT READ, and why:
 *  - `~/.claude/projects/**` — claude-code.js's territory. Overlapping it
 *    would double-report every finding. (Named side effect: a
 *    `projects/<slug>/memory/MEMORY.md` is covered by NEITHER source
 *    today — a real gap that belongs to the transcript source's scope
 *    discussion, recorded here so it isn't mistaken for covered.)
 *  - `~/.claude/history.jsonl`, paste-cache, file-history, session-env —
 *    transcript-adjacent conversation state, not configuration; adding
 *    them belongs in a transcript source where dedup against session
 *    files can be reasoned about.
 *  - `~/.codex/auth.json`, `~/.gemini/oauth_creds.json`, `~/.gemini/.env`,
 *    `~/.claude/.credentials.json` — credential VAULTS: files whose whole
 *    documented job is holding the user's own keys/tokens, following the
 *    precedent opencode.js set for its auth.json. Flagging those re-reports
 *    what the user put there on purpose. The line drawn: a file that holds
 *    secrets BY DESIGN is excluded; a file that accumulates secrets by
 *    accident (settings.local.json's approved-command cache — Lakera's
 *    finding) is exactly what this source is for.
 *  - `~/.gemini/GEMINI.md`, `~/.codex/AGENTS.md` — vendor-documented
 *    memory files, but the research digest never names either exact
 *    home-level path, leaving them one source short of this project's
 *    verification bar. Add-with-citation candidates, not omissions by
 *    oversight.
 *  - Windsurf/OpenClaw/other "equivalents" — the digest gestures at them
 *    without naming an exact home-level path; no path, no scan.
 *
 * If any of these tools is installed on your machine, the most useful
 * thing you can do is run `residoo scan` and confirm the per-source file
 * counts match what you know is on disk, then report back either way —
 * see CONTRIBUTING.md.
 */
function claudeDesktopConfig() {
  const home = os.homedir();
  if (process.platform === "darwin") {
    return path.join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json");
  }
  if (process.platform === "win32") {
    const appData = process.env.APPDATA || path.join(home, "AppData", "Roaming");
    return path.join(appData, "Claude", "claude_desktop_config.json");
  }
  return null; // Linux: no official build, unofficial ports disagree — see header
}

function geminiDir() {
  // GEMINI_CLI_HOME is the tool's own documented override (the CLI creates
  // a `.gemini` folder INSIDE it) — same resolution gemini-cli.js verified
  // from the project's source, duplicated per the one-file-per-source rule.
  if (process.env.GEMINI_CLI_HOME) return path.join(process.env.GEMINI_CLI_HOME, ".gemini");
  return path.join(os.homedir(), ".gemini");
}

function codexHome() {
  // CODEX_HOME per official docs covers "config", not just sessions —
  // same resolution codex-cli.js uses.
  if (process.env.CODEX_HOME) return process.env.CODEX_HOME;
  return path.join(os.homedir(), ".codex");
}

const HOME = os.homedir();
const CLAUDE_DIR = path.join(HOME, ".claude");
const DESKTOP_CONFIG = claudeDesktopConfig();
const GEMINI_DIR = geminiDir();
const CODEX_HOME = codexHome();
const CURSOR_DIR = path.join(HOME, ".cursor");
const KIRO_DIR = path.join(HOME, ".kiro");

// Every candidate is a single fixed file path (see header for what verified
// each). Absence is normal and yields nothing — most machines have a few of
// these tools at most; only a path that LOOKS present but can't be resolved
// is reported broken.
const CANDIDATES = [
  path.join(HOME, ".claude.json"),
  path.join(HOME, ".claude.json.backup"),
  path.join(CLAUDE_DIR, "settings.json"),
  path.join(CLAUDE_DIR, "settings.local.json"),
  path.join(CLAUDE_DIR, "mcp.json"),
  path.join(CLAUDE_DIR, "CLAUDE.md"),
  ...(DESKTOP_CONFIG ? [DESKTOP_CONFIG] : []),
  path.join(CURSOR_DIR, "mcp.json"),
  path.join(GEMINI_DIR, "settings.json"),
  path.join(CODEX_HOME, "config.toml"),
  path.join(KIRO_DIR, "settings", "mcp.json"),
];

// Configs are KB-scale in every real observation this source's research
// produced (the largest, a live ~/.claude.json accumulating per-project
// state, was tens of KB; community bloat reports for that file reach tens
// of MB). 64MB is a corrupted-or-pathological-file backstop, not a bound
// derived from a real file — same caveat cursor.js states for MAX_DB_BYTES.
// A file over it is surfaced as "too-large", never silently skipped.
const MAX_BYTES = 64 * 1024 * 1024;
const READ_TIMEOUT_MS = 60_000;

function id() { return "agent-configs"; }
function label() { return "Agent config files"; }

function dirExists(p) {
  try { return fs.statSync(p).isDirectory(); } catch { return false; }
}
function fileExists(p) {
  try { return fs.statSync(p).isFile(); } catch { return false; }
}

/**
 * Available when any of the config ROOTS exists — not just when a candidate
 * file does. A machine with an empty `~/.cursor` should still show this
 * source as checked (finding nothing is a result), while a machine with
 * none of these tools shouldn't list it at all.
 */
function available() {
  return (
    fileExists(path.join(HOME, ".claude.json")) ||
    dirExists(CLAUDE_DIR) ||
    (DESKTOP_CONFIG !== null && dirExists(path.dirname(DESKTOP_CONFIG))) ||
    dirExists(CURSOR_DIR) ||
    dirExists(GEMINI_DIR) ||
    dirExists(CODEX_HOME) ||
    dirExists(KIRO_DIR)
  );
}

/**
 * Resolve one fixed candidate path into zero or one files() entries — the
 * same lstat-then-follow shape as cursor.js's statIfPresent, duplicated per
 * the one-file-per-source convention. These paths are constructed, not
 * discovered by a directory listing, so there is no Dirent to reuse:
 * absence yields nothing (normal — see CANDIDATES), a dangling symlink
 * yields broken (a dotfiles manager symlinking `~/.claude/settings.json`
 * at a moved target is the realistic case, and silently skipping it is the
 * exact bug claude-code.js's files() docstring exists to prevent), and
 * something that is neither file nor symlink at the path is out of scope.
 */
function* statIfPresent(p) {
  let lst;
  try { lst = fs.lstatSync(p); }
  catch (err) {
    // ENOENT/ENOTDIR is the normal not-installed case and yields nothing.
    // Any other lstat failure (EACCES on `~/.claude` itself, ELOOP) means a
    // candidate may exist but can't be examined — that's a broken entry,
    // not absence: available() can still say true for the root, and a
    // silently empty files() would be the exact silent-exclusion bug the
    // yield-broken convention exists to prevent.
    if (err && (err.code === "ENOENT" || err.code === "ENOTDIR")) return;
    yield { file: p, broken: true };
    return;
  }

  if (lst.isSymbolicLink()) {
    try {
      const st = fs.statSync(p); // follow the link
      if (!st.isFile()) { yield { file: p, broken: true }; return; }
      yield { file: p, mtimeMs: st.mtimeMs, sizeBytes: st.size, broken: false };
    } catch {
      yield { file: p, broken: true }; // dangling symlink
    }
    return;
  }

  if (!lst.isFile()) return;
  yield { file: p, mtimeMs: lst.mtimeMs, sizeBytes: lst.size, broken: false };
}

/** Yield { file, mtimeMs, sizeBytes, broken } for every candidate present. */
function* files() {
  for (const p of CANDIDATES) yield* statIfPresent(p);
}

/**
 * Read one config file as raw text lines — the same streaming reader as
 * claude-code.js's readLines (see that docstring for the timeout rationale:
 * a symlink retargeted between stat and open can block open() forever, and
 * destroying the stream is the only way out). Configs are JSON, TOML, or
 * Markdown rather than JSONL, which changes nothing for the caller: scan.js
 * matches raw text lines, and a token inside a pretty-printed `"env"` block
 * or a TOML `env` table sits on its own line just like a JSONL record does.
 * A single-line minified JSON config arrives as one long line — still
 * within the streaming reader's per-line limits at this source's size cap.
 *
 * Same status contract as every source: "complete", "partial" (some lines
 * were read before a failure — scanned, and flagged), "too-large", "failed".
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
    // secret — an honest "partial" beats a silent false negative.
    return { lines, status: lines.length > 0 ? "partial" : "failed", bytesRead };
  } finally {
    clearTimeout(timer);
    rl.close();
    stream.destroy();
  }
}

module.exports = { id, label, available, files, readLines };
