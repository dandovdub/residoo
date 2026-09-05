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
 * SCOPE — fixed home-level paths, plus project-level Claude Code configs
 * reachable through the agent's own breadcrumbs. Project configs live
 * inside arbitrary repositories that no home-level scanner can enumerate
 * by walking a directory tree — but the agent itself records every project
 * root it has been used in, at home level: `~/.claude.json` keeps a
 * top-level `projects` map keyed by absolute project path (vendor-
 * documented per-project state), and every transcript under
 * `~/.claude/projects/<slug>/` carries the project's absolute path in its
 * records' `cwd` field (vendor JSONL schema). Following those recorded
 * roots to the vendor-FIXED per-project config filenames (`.mcp.json`,
 * `.claude/settings.json`, `.claude/settings.local.json` — the exact
 * files GitGuardian measured 24k secrets in and Lakera found shipped in
 * npm packages) is a general mechanism, not path guessing: nothing is
 * discovered by scanning repositories, only by resolving what the agent
 * already wrote down. Limits, stated: a machine whose agent state was
 * wiped yields no roots (discovery degrades to absence, the same
 * information a human reading the state would have); other agents'
 * project-level configs (`.cursor/rules/`, `.vscode/tasks.json`, per-repo
 * CLAUDE.md/AGENTS.md — the files Miasma actually planted) stay
 * uncovered until their home-level state formats are verified to the same
 * bar; and a clean report still says nothing about repositories the agent
 * was never pointed at.
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
 *  - `~/.mcp.json` (bare, directly under HOME, distinct from every
 *    subdirectory-nested path above) — Visual Studio (the full Windows
 *    IDE, not VS Code; VS Code's own MCP config is `.vscode/mcp.json`,
 *    already project-scoped below) documents this exact path as its
 *    global, all-solutions MCP config: Microsoft's own docs repo
 *    (github.com/MicrosoftDocs/visualstudio-docs, docs/ide/mcp-servers.md,
 *    fetched directly), "Serves as a global MCP server configuration for
 *    a specific user. Adding an MCP server here makes it load for all
 *    Visual Studio solutions." Visual Studio's remote-MCP OAuth tokens go
 *    through "the Visual Studio keychain" per the same doc -- an OS-backed
 *    store, not a plaintext file, so there is no separate credential
 *    vault to name here the way `.codex/auth.json` needed one.
 *
 * DELIBERATELY NOT READ, and why:
 *  - `~/.claude/projects/**` AS SCAN CONTENT — claude-code.js's territory;
 *    overlapping it would double-report every finding. The project-root
 *    discovery below does open transcripts, but only to read the `cwd`
 *    field out of the first records (a bounded probe, nothing from the
 *    content is ever reported), which indexes projects without scanning
 *    a single transcript line here. (Named side effect: a
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
  path.join(HOME, ".mcp.json"),
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
    dirExists(KIRO_DIR) ||
    // Visual Studio (the full IDE) has no dedicated root directory the way
    // every other tool above does -- its one machine-level artifact is this
    // bare file, so it needs its own direct existence check rather than a
    // dirExists() on some ~/.visualstudio root that doesn't exist.
    fileExists(path.join(HOME, ".mcp.json"))
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

// ── project-level config discovery ──────────────────────────────────────────
//
// The per-project config filenames are vendor-fixed (Claude Code's own docs:
// project-scope MCP servers in `.mcp.json`, shared settings in
// `.claude/settings.json`, local settings in `.claude/settings.local.json`);
// what varies per machine is only WHERE the project roots are, and the agent
// records exactly that in home-level state. Two independent record sources,
// both vendor artifacts, both read best-effort (a failure to discover a root
// is absence, never an error — see the SCOPE limits in the header):
//
//   1. `~/.claude.json`'s top-level `projects` object, keyed by absolute
//      project path. Already a scan candidate above; parsed here a second
//      time only for its keys.
//   2. The `cwd` field in transcript records under
//      `~/.claude/projects/<slug>/`. The slug itself also encodes the path,
//      but lossily (path separators and dashes collapse into the same
//      character), so the record field is the reliable form. Only the first
//      few records of the first few files per slug directory are probed,
//      bounded by bytes and line count: every session in a slug directory
//      shares one project root by construction.
//
// A recorded root that no longer exists usually means the project was
// deleted — except when the WHOLE home tree has been relocated (a mounted
// backup, a copied disk image, HOME pinned at a snapshot for auditing), in
// which case every recorded absolute path is stale by the same prefix. That
// case is detected generally: a missing root whose prefix is shaped like a
// home directory (macOS /Users/<u>, Linux /home/<u>, Windows
// <drive>:\Users\<u>) is retried at the same home-relative path under the
// CURRENT home, and used only if that directory actually exists. Non-default
// home locations (e.g. /srv/data/<u>) defeat the re-rooting and are a stated
// limit, not a silent one.
//
// Recorded roots are data read from transcripts and state files, which a
// hostile transcript can influence — so nothing is ever globbed or walked
// beneath them: only the three fixed basenames are lstat'd, reads stay
// read-only through the same readLines every candidate gets, and anything
// matched is redacted by the report layer like every other finding.

const CLAUDE_STATE_JSON = path.join(HOME, ".claude.json");
const CLAUDE_PROJECTS_DIR = path.join(CLAUDE_DIR, "projects");

const PROJECT_CONFIG_RELPATHS = [
  ".mcp.json",
  path.join(".claude", "settings.json"),
  path.join(".claude", "settings.local.json"),
  // Visual Studio's per-solution, VS-only MCP config: Microsoft's own docs
  // (same source cited for ~/.mcp.json above) list this as a distinct
  // location from <SOLUTIONDIR>/.mcp.json (source-controlled) --
  // "Specific to Visual Studio and loads the specified MCP servers only
  // for a specific user, for the specified solution," living inside the
  // hidden, not-source-controlled .vs/ folder Visual Studio already owns.
  path.join(".vs", "mcp.json"),
];

// Probe bounds: transcript first-records are KB-scale; 256KB and 20 lines is
// headroom, not a tuned fit. One resolving file per slug directory suffices.
const CWD_PROBE_BYTES = 256 * 1024;
const CWD_PROBE_LINES = 20;
const CWD_PROBE_FILES_PER_DIR = 3;

function rootsFromClaudeState() {
  let stat;
  try { stat = fs.statSync(CLAUDE_STATE_JSON); } catch { return []; }
  if (!stat.isFile() || stat.size > MAX_BYTES) return [];
  try {
    const doc = JSON.parse(fs.readFileSync(CLAUDE_STATE_JSON, "utf-8"));
    if (doc && typeof doc === "object" && doc.projects &&
        typeof doc.projects === "object" && !Array.isArray(doc.projects)) {
      return Object.keys(doc.projects).filter((k) => typeof k === "string" && k.length > 0);
    }
  } catch {
    // Unparseable state: discovery loses this index, but the file itself is
    // still scanned line-by-line as a fixed candidate above, so no content
    // goes unexamined because of a parse failure here.
  }
  return [];
}

/** First string `cwd` in the leading records of one transcript, or null. */
function firstCwdIn(file) {
  let fd = null;
  try {
    fd = fs.openSync(file, "r");
    const buf = Buffer.alloc(CWD_PROBE_BYTES);
    const n = fs.readSync(fd, buf, 0, buf.length, 0);
    // A line truncated at the probe boundary simply fails JSON.parse and is
    // skipped — the bound costs recall on that one record, never a crash.
    const lines = buf.toString("utf-8", 0, n).split("\n", CWD_PROBE_LINES);
    for (const line of lines) {
      try {
        const rec = JSON.parse(line);
        if (rec && typeof rec === "object" && typeof rec.cwd === "string" && rec.cwd) return rec.cwd;
      } catch { /* meta/summary records and non-JSON lines: keep looking */ }
    }
  } catch {
    // Unreadable transcript: claude-code.js owns surfacing that; a root
    // index probe must not duplicate its error reporting.
  } finally {
    if (fd !== null) { try { fs.closeSync(fd); } catch { /* already closed */ } }
  }
  return null;
}

function rootsFromTranscriptDirs() {
  let dirs;
  try { dirs = fs.readdirSync(CLAUDE_PROJECTS_DIR, { withFileTypes: true }); }
  catch { return []; }
  const roots = [];
  for (const d of dirs) {
    if (!d.isDirectory()) continue;
    const dir = path.join(CLAUDE_PROJECTS_DIR, d.name);
    let entries;
    // An unlistable slug directory is not silently swallowed overall:
    // claude-code.js's own files() walk reports that same directory as
    // broken; this index probe just loses one root.
    try { entries = fs.readdirSync(dir); } catch { continue; }
    const sessions = entries.filter((n) => n.endsWith(".jsonl")).sort();
    for (const name of sessions.slice(0, CWD_PROBE_FILES_PER_DIR)) {
      const cwd = firstCwdIn(path.join(dir, name));
      if (cwd) { roots.push(cwd); break; }
    }
  }
  return roots;
}

// Default home-directory shapes for the three platforms Claude Code ships
// on. Anchored and existence-checked, never a rewrite of arbitrary paths.
const HOME_SHAPED_PREFIX = /^(?:\/(?:Users|home)\/[^/]+|[A-Za-z]:[\\/]Users[\\/][^\\/]+)(?=[\\/]|$)/;

/** Resolve one recorded project root to an existing directory, or null. */
function resolveRecordedRoot(recorded) {
  try { if (fs.statSync(recorded).isDirectory()) return recorded; } catch { /* fall through to re-rooting */ }
  const m = HOME_SHAPED_PREFIX.exec(recorded);
  if (!m) return null;
  const rest = recorded.slice(m[0].length).split(/[\\/]+/).filter(Boolean);
  const rehomed = rest.length === 0 ? HOME : path.join(HOME, ...rest);
  try { if (fs.statSync(rehomed).isDirectory()) return rehomed; } catch { /* relocated copy absent too */ }
  return null;
}

/**
 * Yield candidate entries for every discovered project root's fixed config
 * filenames, deduplicated against paths already yielded (a recorded root
 * that resolves to the home directory itself would otherwise re-yield
 * `~/.claude/settings.json`). Sorted for deterministic output across runs —
 * readdir order is not.
 */
function* projectConfigCandidates(seenResolved) {
  const recorded = new Set([...rootsFromClaudeState(), ...rootsFromTranscriptDirs()]);
  const resolved = new Set();
  for (const r of recorded) {
    const root = resolveRecordedRoot(r);
    if (root) resolved.add(path.resolve(root));
  }
  for (const root of [...resolved].sort()) {
    for (const rel of PROJECT_CONFIG_RELPATHS) {
      const p = path.join(root, rel);
      const key = path.resolve(p);
      if (seenResolved.has(key)) continue;
      seenResolved.add(key);
      yield* statIfPresent(p);
    }
  }
}

/**
 * Yield { file, mtimeMs, sizeBytes, broken } for every candidate present:
 * the fixed home-level paths first, then per-project configs at the roots
 * the agent's own state records (see the discovery block above).
 */
function* files() {
  const seen = new Set();
  for (const p of CANDIDATES) {
    seen.add(path.resolve(p));
    yield* statIfPresent(p);
  }
  yield* projectConfigCandidates(seen);
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
