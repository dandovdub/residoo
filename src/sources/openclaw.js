"use strict";

const fs = require("fs");
const { createInterface } = require("readline/promises");
const path = require("path");
const os = require("os");

/**
 * OpenClaw (openclaw/openclaw, "your own personal AI assistant... the
 * lobster way") session transcripts. OpenClaw is a multi-channel agent
 * gateway (Discord/Slack/Telegram/iMessage/etc.) that can launch and drive
 * other coding agents (Claude Code, Codex, OpenCode, Kiro CLI, Pi) as
 * subprocesses — those tools' own transcripts are already covered by this
 * project's other sources; this source covers OpenClaw's OWN session/chat
 * logs (the conversation the user has with OpenClaw itself, across whatever
 * channel it's reached from).
 *
 * VERIFICATION STATUS: NOT checked against a real install — no `~/.openclaw`
 * (or any of the legacy names below) exists on the machine this adapter was
 * built on. Ships per CONTRIBUTING.md rule 3 on two independent
 * corroborating sources, WITH THE SAME INTEGRITY CAVEAT documented at length
 * in hermes.js's module docstring — summarized here, read that file for the
 * full reasoning: `gh api` showed openclaw/openclaw at 388,546 GitHub stars
 * for a repo created 2025-11-24 (more stars in under a year than
 * facebook/react has after 13 years, sanity-checked against real repos in
 * the same research pass), and independent search turned up a real fake-
 * GitHub-stars research paper, a Hacker News thread about a plagiarism
 * dispute between Hermes Agent and OpenClaw specifically, and a GitHub topic
 * literally describing "Two zero-human AI companies battle for GitHub stars
 * using Hermes Agent + Paperclip." That doesn't make the format below wrong,
 * but it does mean OpenClaw's own docs and Hermes' own docs may not be
 * independent of each other (Hermes' docs describe importing OpenClaw's
 * config directory directly) — treat this as
 * multi-source-corroborated-but-unverified, not stronger, and see this
 * adapter's PR description/report for the full writeup.
 *
 * The two sources:
 *
 *   1. OpenClaw's own docs (docs.openclaw.ai/cli, /gateway/configuration):
 *      default state directory `~/.openclaw`, overridable via
 *      `OPENCLAW_STATE_DIR`; `--profile <name>` isolates state under
 *      `~/.openclaw-<name>`; `--dev` uses `~/.openclaw-dev`.
 *   2. ccusage (github.com/ccusage/ccusage — see hermes.js for why this
 *      project's own star count and code were trusted) ships a tested Rust
 *      adapter for OpenClaw (rust/adapters/openclaw/src/{paths,parser}.rs),
 *      fetched and read directly. It confirms: an `OPENCLAW_DIR` env var
 *      (comma-separated list — ccusage's own name, not confirmed identical
 *      to OPENCLAW_STATE_DIR above, so this source checks both rather than
 *      betting on one), and — absent either — four candidate home-relative
 *      directories: `~/.openclaw`, `~/.clawdbot`, `~/.moltbot`, `~/.moldbot`
 *      (evidently earlier names across OpenClaw's own rebrand history).
 *      Under whichever directory exists, it recursively collects files whose
 *      name contains `.jsonl` as an exact suffix, or as
 *      `.jsonl.deleted.<...>` / `.jsonl.reset.<...>` (OpenClaw's own naming
 *      for archived/rotated session files) — confirmed by that adapter's own
 *      unit test asserting exactly these three shapes. Each line is plain
 *      JSONL: a `{"type":"model_change",...}` or
 *      `{"type":"custom","customType":"model-snapshot",...}` tracking
 *      record, or a `{"type":"message","message":{"role":...,...}}` record —
 *      confirmed directly from that adapter's own parser and fixture data.
 *
 * One deliberate departure from ccusage's own behaviour: its directory walk
 * explicitly `continue`s past any symlink it meets (`file_type.is_symlink()
 * => continue`) — reasonable for a usage-stats tool, wrong for a security
 * scanner. This source instead follows claude-code.js's own house
 * convention: follow a symlink if it resolves, report it `broken: true` if
 * it doesn't, never silently skip it either way (CONTRIBUTING.md rule 5).
 */
const OPENCLAW_STATE_DIR_ENV = "OPENCLAW_STATE_DIR"; // OpenClaw's own official docs name
const OPENCLAW_DIR_ENV = "OPENCLAW_DIR"; // ccusage's name — kept as a second, unconfirmed alias
const LEGACY_HOME_NAMES = [".openclaw", ".clawdbot", ".moltbot", ".moldbot"];

function id() { return "openclaw"; }
function label() { return "OpenClaw"; }

function envRoots() {
  for (const envVar of [OPENCLAW_STATE_DIR_ENV, OPENCLAW_DIR_ENV]) {
    const val = process.env[envVar];
    if (val && val.trim() !== "") {
      return val.split(",").map((s) => s.trim()).filter((s) => s !== "").map((p) => path.resolve(p));
    }
  }
  return null;
}

/**
 * Resolve every OpenClaw state root that actually exists on disk: either
 * both env-var overrides (checked in envRoots()), or every legacy/renamed
 * default directory under $HOME that's present, PLUS any `~/.openclaw-*`
 * sibling (covers `--profile <name>` and `--dev`, per source 1 above —
 * ccusage's own code doesn't do this, since it wasn't documented from
 * ccusage's side, only OpenClaw's own docs).
 */
function stateRoots() {
  const env = envRoots();
  if (env) return env.filter((p) => { try { return fs.statSync(p).isDirectory(); } catch { return false; } });

  const home = os.homedir();
  const roots = [];
  for (const name of LEGACY_HOME_NAMES) {
    const dir = path.join(home, name);
    try { if (fs.statSync(dir).isDirectory()) roots.push(dir); } catch { /* not present */ }
  }

  let homeEntries;
  try { homeEntries = fs.readdirSync(home, { withFileTypes: true }); }
  catch { homeEntries = []; }
  for (const e of homeEntries) {
    if (!e.name.startsWith(".openclaw-")) continue;
    const dir = path.join(home, e.name);
    if (roots.includes(dir)) continue;
    let isDir = e.isDirectory();
    if (!isDir && e.isSymbolicLink()) {
      try { isDir = fs.statSync(dir).isDirectory(); } catch { isDir = false; }
    }
    if (isDir) roots.push(dir);
  }
  return roots;
}

function available() {
  return stateRoots().length > 0;
}

function isKindFollowingSymlink(fullPath, dirent, checkFn) {
  if (checkFn(dirent)) return true;
  if (!dirent.isSymbolicLink()) return false;
  try { return checkFn(fs.statSync(fullPath)); } catch { return false; }
}
const isDirFollowingSymlink = (p, d) => isKindFollowingSymlink(p, d, (x) => x.isDirectory());
const isFileFollowingSymlink = (p, d) => isKindFollowingSymlink(p, d, (x) => x.isFile());

/**
 * True for `*.jsonl`, `*.jsonl.deleted.<...>`, `*.jsonl.reset.<...>` —
 * mirrors ccusage's own `is_openclaw_session_file` (including its own unit
 * test's exact examples) byte for byte.
 */
function isOpenClawSessionFile(name) {
  const index = name.indexOf(".jsonl");
  if (index === -1) return false;
  const suffix = name.slice(index);
  return suffix === ".jsonl" || suffix.startsWith(".jsonl.deleted.") || suffix.startsWith(".jsonl.reset.");
}

/**
 * Recursively yield { file, mtimeMs, sizeBytes, broken } for every session
 * file under one root. Depth-first, symlink-following-with-broken-reporting
 * (see module docstring for why this deliberately differs from ccusage's
 * own skip-on-symlink walk).
 */
function* walk(dir) {
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); }
  catch { yield { file: dir, broken: true }; return; }

  for (const e of entries) {
    const full = path.join(dir, e.name);
    if (e.isDirectory() || (e.isSymbolicLink() && isDirFollowingSymlink(full, e))) {
      yield* walk(full);
      continue;
    }
    if (!isOpenClawSessionFile(e.name)) continue;
    if (!e.isFile()) {
      const resolved = isFileFollowingSymlink(full, e);
      if (!resolved) {
        if (e.isSymbolicLink()) yield { file: full, broken: true };
        continue;
      }
    }
    let stat;
    try { stat = fs.statSync(full); } catch { yield { file: full, broken: true }; continue; }
    yield { file: full, mtimeMs: stat.mtimeMs, sizeBytes: stat.size, broken: false };
  }
}

function* files() {
  for (const root of stateRoots()) yield* walk(root);
}

const MAX_BYTES = 2 * 1024 * 1024 * 1024; // 2GB — same untested-against-a-real-huge-file backstop
                                            // claude-code.js uses, for the same stated reason.
const READ_TIMEOUT_MS = 60_000;

/**
 * Read one session file as an array of raw text lines — identical
 * streamed/bounded/timed-out shape to claude-code.js's own readLines(), for
 * the same reasons documented there (JSONL, so this needs no JSON-array
 * reconstruction the way codebuff.js's chat-messages.json does).
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
