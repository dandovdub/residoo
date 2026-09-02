"use strict";

const fs = require("fs");
const { createInterface } = require("readline/promises");
const path = require("path");
const os = require("os");

/**
 * Qodo Gen (formerly CodiumAI / Codium) — the VS Code and JetBrains AI chat
 * extension published by Qodo.
 *
 * VERIFICATION STATUS (read this before trusting anything below):
 * multi-source-corroborated-but-UNVERIFIED against a real install, and
 * meaningfully WEAKER corroboration than this project's other sources — read
 * this whole note before trusting it. Neither VS Code, JetBrains, nor any
 * Qodo extension is installed on the machine this adapter was built on
 * (checked: no /Applications/*Code*.app, no `code` on PATH, no ~/.qodo
 * directory, no ~/Library/Application Support/JetBrains/<product>/options
 * containing anything Qodo-named). Qodo Gen is closed-source (the public
 * `Codium-ai/codiumai-vscode-release` / `codiumai-jetbrains-release` repos
 * are release-notes/changelog mirrors only, no extension source), so unlike
 * cody.js and amazon-q.js in this project, this adapter's path claim could
 * NOT be checked against the vendor's own source code — only its docs:
 *
 *   1. Qodo's own current documentation,
 *      docs.qodo.ai/qodo-documentation/qodo-gen/chat/chat-history (fetched
 *      2026-09-02): "Qodo saves chat history locally in the user's home
 *      directory at `.qodo/history`. The file naming uses a hash of the
 *      workspace path to ensure uniqueness," plus: history not touched in
 *      90+ days is auto-deleted; VS Code does NOT migrate history across
 *      extension upgrades (a fresh install loses it) while JetBrains DOES.
 *   2. Qodo's own changelog, docs.qodo.ai/changelog, entry for "Qodo 1.0.8"
 *      (24 Apr 25): "The History file is now named `.qodo/history` and has
 *      been moved to the user folder for better file organization. The file
 *      is named using a hash of the workspace path to ensure uniqueness" —
 *      independently dated/versioned wording that agrees with (1), and
 *      implies this is a genuine change from an earlier, different layout
 *      (see the IDAHO-VAULT finding below for what that earlier layout
 *      likely looked like).
 *
 *   Both of the above are the SAME vendor (Qodo's own docs site stating the
 *   same fact twice, once in reference docs and once in a changelog) — NOT
 *   two independent parties, despite counting as two fetches. Searching
 *   specifically for independent, third-party confirmation of the exact
 *   `~/.qodo/history` BASE DIRECTORY turned up nothing conclusive: the one
 *   real, concrete GitHub artifact found (`LAF-US/IDAHO-VAULT`,
 *   `GIT-REMOVAL-COMMANDS.txt`, a real user's own repo, commits from mid/late
 *   2026, well after the v1.0.8 changelog date) shows a file
 *   `.qodo/history/<64-hex-hash>.json` committed INSIDE that repo's own
 *   project directory, not under that user's home directory — but on
 *   inspection this is very likely Qodo's separate automated code-review
 *   product (`qodo-ai/command`, the "Qodo Gen CLI" / PR-Agent lineage, whose
 *   own README describes exactly this "review your repo from the terminal,
 *   for CI/CD" use case) writing a per-repo review-report artifact, given the
 *   surrounding context ("Qodo review (...) flagged a medium-severity bug")
 *   reads as a CI/PR-review finding, not a chat transcript. That is a
 *   DIFFERENT Qodo product from the IDE chat extension this adapter targets,
 *   so it neither confirms nor contradicts the `~/.qodo/history` claim above
 *   for Qodo Gen specifically — it only corroborates that Qodo's tooling in
 *   general uses this exact `.qodo/history/<hash>.json` naming shape
 *   somewhere, which is real, but not the specific base-directory claim this
 *   adapter depends on.
 *
 * Built anyway, per CONTRIBUTING.md's allowance for a source with credible
 * corroboration but no real install — but flagged here, honestly, as this
 * project's single WEAKEST-verified source: one primary party (the vendor,
 * stated twice) rather than genuinely independent agreement, and a live
 * install is unusually likely to be needed to firm this up (there is no
 * source code to fall back on the way cody.js/amazon-q.js could). If you
 * have Qodo Gen installed, confirming `~/.qodo/history/*.json` actually
 * exists and holds real chat content — or reporting exactly where it
 * actually lives if not — is the single most useful thing you can do for
 * this source (see CONTRIBUTING.md).
 *
 * No per-OS path branching in either Qodo source read above — the docs
 * describe a plain home-directory dotfolder (`~/.qodo` /
 * `%USERPROFILE%\.qodo` on Windows), consistent with it being deliberately
 * IDE-agnostic: the same docs note JetBrains preserves this history across
 * upgrades where VS Code's own extension-local storage would not, which only
 * makes sense if both IDEs read/write ONE shared, non-IDE-specific location
 * — the same reasoning amazon-q.js documents for `~/.aws/amazonq/history`
 * and continue.js already documents for `~/.continue` in this project.
 */
function historyDir() {
  return path.join(os.homedir(), ".qodo", "history");
}

const HISTORY_DIR = historyDir();

// Bounds for readLines() — same rationale and values as claude-code.js.
// Not backed by a real Qodo Gen history file this tool was tested against
// (no install to test with) — see the verification-status note above.
const MAX_BYTES = 2 * 1024 * 1024 * 1024; // 2GB
const READ_TIMEOUT_MS = 60_000;

function id() { return "qodo-gen"; }
function label() { return "Qodo Gen"; }

function available() {
  try { return fs.statSync(HISTORY_DIR).isDirectory(); } catch { return false; }
}

/**
 * Same defensive symlink-following pattern as claude-code.js's
 * isKindFollowingSymlink — see that file's docstring for the full reasoning.
 * Duplicated rather than imported, matching this project's "small,
 * self-contained file" convention.
 */
function isKindFollowingSymlink(fullPath, dirent, checkFn) {
  if (checkFn(dirent)) return true;
  if (!dirent.isSymbolicLink()) return false;
  try { return checkFn(fs.statSync(fullPath)); } catch { return false; }
}
const isFileFollowingSymlink = (p, d) => isKindFollowingSymlink(p, d, (x) => x.isFile());

/**
 * Yield { file, mtimeMs, sizeBytes, broken } for every `*.json` file
 * directly inside `~/.qodo/history/` (flat, not recursive — every source
 * describing this layout, vendor docs and the IDAHO-VAULT artifact alike,
 * shows hash-named files as immediate children, no further nesting).
 *
 * Not filtered to a specific filename shape (e.g. requiring a hex-looking
 * name): the exact hash algorithm/length isn't confirmed (docs say "a hash
 * of the workspace path" without naming one), so — same caution cursor.js
 * documents for not hard-coding a key-name allowlist likely to drift — any
 * `*.json` found directly in this Qodo-owned directory is scanned rather
 * than pattern-matched by filename.
 */
function* files() {
  let entries;
  try { entries = fs.readdirSync(HISTORY_DIR, { withFileTypes: true }); }
  catch { return; } // no history directory at all — Qodo Gen never ran, or never opened chat

  for (const e of entries) {
    if (!e.name.endsWith(".json")) continue;
    const file = path.join(HISTORY_DIR, e.name);
    if (!isFileFollowingSymlink(file, e)) {
      if (e.isSymbolicLink()) yield { file, broken: true };
      continue;
    }
    let stat;
    try { stat = fs.statSync(file); } catch { yield { file, broken: true }; continue; }
    yield { file, mtimeMs: stat.mtimeMs, sizeBytes: stat.size, broken: false };
  }
}

/**
 * Read one `.qodo/history/*.json` file as an array of raw text lines.
 *
 * Streamed line-by-line via readline/promises, same as claude-code.js and
 * amazon-q.js — whether a given file turns out to be one flat JSON document
 * or something line-delimited, per-line scanning handles both: a flat
 * document just becomes one long "line," bounded by MAX_BYTES. Status
 * vocabulary matches every other source in this project.
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
  // underlying open() block forever with no event ever firing.
  const timer = setTimeout(() => stream.destroy(new Error("read timed out")), READ_TIMEOUT_MS);

  try {
    for await (const line of rl) {
      lines.push(line);
      bytesRead += Buffer.byteLength(line, "utf-8") + 1; // +1 for the stripped newline
    }
    return { lines, status: "complete", bytesRead };
  } catch {
    // Whatever WAS read before the failure is real content and may contain
    // a real secret — kept, not discarded, same as every other source here.
    return { lines, status: lines.length > 0 ? "partial" : "failed", bytesRead };
  } finally {
    clearTimeout(timer);
    rl.close();
    stream.destroy();
  }
}

module.exports = { id, label, available, files, readLines };
