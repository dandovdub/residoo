"use strict";

const fs = require("fs");
const { createInterface } = require("readline/promises");
const path = require("path");
const os = require("os");

/**
 * Amazon Q Developer — the AWS chat/coding-assistant IDE plugin (VS Code via
 * the AWS Toolkit / "Amazon Q" extension, and the JetBrains "Amazon Q"
 * plugin; formerly CodeWhisperer).
 *
 * VERIFICATION STATUS (read this before trusting anything below):
 * multi-source-corroborated-but-UNVERIFIED against a real install. Neither VS
 * Code, JetBrains, nor any Amazon Q plugin is installed on the machine this
 * adapter was built on (checked: no /Applications/*Code*.app, no `code` on
 * PATH, no `~/.aws/amazonq` directory — `~/.aws` itself exists here only from
 * an old, unrelated AWS CLI credentials setup, `config`/`credentials` only,
 * no `amazonq` subdirectory). What IS unusually strong here, short of a real
 * install: the storage mechanism and exact filenames were read directly out
 * of AWS's own current shipped source for BOTH clients, not inferred from a
 * blog post:
 *
 *   1. `aws/aws-toolkit-vscode` (the VS Code client), `main` branch,
 *      `packages/core/src/shared/db/chatDb/chatDb.ts`, fetched verbatim via
 *      `gh api repos/aws/aws-toolkit-vscode/contents/...` on 2026-09-02 —
 *      its own docstring states plainly: "The database is stored in the
 *      user's home directory under .aws/amazonq/history with a unique
 *      filename based on the workspace identifier," and the constructor
 *      confirms it exactly:
 *        `this.dbDirectory = path.join(fs.getUserHomeDir(), '.aws/amazonq/history')`
 *        `const dbName = \`chat-history-${workspaceId}.json\``
 *      where `getWorkspaceIdentifier()` (same file) is an MD5 hex hash of
 *      the open `.code-workspace` path, or of the sorted+joined multi-root
 *      folder paths, or of the single open folder path, or the literal
 *      string `'no-workspace'` when nothing is open — i.e. filenames are
 *      exactly `chat-history-<32-hex-md5>.json` or
 *      `chat-history-no-workspace.json`. The "database" itself is LokiJS
 *      (`import Loki from 'lokijs'`, `persistenceMethod: 'fs'`) — an
 *      embedded JS document store that serializes its entire collection set
 *      as ONE JSON document per file, not a real SQL database despite the
 *      `.json`-suffixed "chat-history-" naming — so this is ordinary,
 *      scannable JSON text on disk, no special binary/SQLite handling
 *      needed (unlike cursor.js/cody.js).
 *
 *   2. `Amazon-Q-Developer/language-servers`,
 *      `server/aws-lsp-codewhisperer/src/language-server/agenticChat/tools/chatDb/chatDb.ts`
 *      — the SAME class, byte-for-byte the same docstring and
 *      `.aws/amazonq/history` path, living in the shared "Flare" language
 *      server package both IDE clients embed. Confirmed the JetBrains client
 *      actually embeds this same language server (not a separate,
 *      JetBrains-native storage layer) by reading
 *      `Amazon-Q-Developer/amazon-q-jetbrains`,
 *      `plugins/amazonq/shared/jetbrains-community/src/software/aws/toolkits/jetbrains/services/amazonq/lsp/AmazonQLanguageClientImpl.kt`
 *      (same fetch method, same date) — the JetBrains plugin is an LSP
 *      *client* to the identical CodeWhisperer/Q language server, so its chat
 *      history lands in the exact same home-directory path as VS Code's,
 *      not a JetBrains-specific config/plugins directory. This is why this
 *      one adapter covers both IDEs with a single, IDE-agnostic path — no
 *      per-editor branching needed, unlike copilot-chat.js/cody.js.
 *
 *   Independent, non-AWS corroboration of the same exact path and filename
 *   pattern (cross-checked, all agree with each other and with the source
 *   above): a real user's own write-up at
 *   dev.to/aws/finding-and-recovering-your-amazon-q-developer-prompt-history-28j1
 *   ("In the ~/.aws/amazonq/ directory there is a history directory... json
 *   files" — names `chat-history-no-workspace.json` and several
 *   `chat-history-<hash>.json` examples verbatim); a third-party forensics
 *   tool, `ACandeias/AI-Forensicator`, `collectors/amazon_q.py`, whose own
 *   comment reads "~/.aws/amazonq/history/  -- chat history JSON files"; and
 *   a third-party agent-session spec, `YawLabs/ctxlint`,
 *   `agent-session-lint-rules.json`, recording
 *   `"historyLocation": "~/.aws/amazonq/history/chat-history-*.json"`.
 *
 * No per-OS path branching in the AWS source read above (`fs.getUserHomeDir()`
 * joined with the same relative `.aws/amazonq/history` on every platform) —
 * matching the long-standing, cross-platform AWS CLI/SDK convention of a
 * single `~/.aws` (`%USERPROFILE%\.aws` on Windows) regardless of OS, unlike
 * VS Code's own per-OS `Application Support`/`AppData`/XDG split that most
 * other sources in this project have to branch on.
 *
 * Deliberately out of scope: any Amazon Q Developer usage OUTSIDE the IDE
 * plugins covered here — the separate `q chat` CLI, the GitHub-hosted
 * "Amazon Q Developer for GitHub" integration, and Kiro (a distinct AWS
 * product that a third-party source above notes also happens to write into
 * this same directory) are different products with their own storage
 * questions, not verified here and not claimed by this adapter.
 */
function historyDir() {
  return path.join(os.homedir(), ".aws", "amazonq", "history");
}

const HISTORY_DIR = historyDir();

// Bounds for readLines() — same rationale and values as claude-code.js.
// Not backed by a real chat-history-*.json file this tool was tested
// against (no install to test with) — see the verification-status note
// above. A LokiJS-serialized history file is a single JSON document, so in
// practice this caps one very long "line," the same shape copilot-chat.js
// already handles for a flat (non-JSONL) chat session snapshot.
const MAX_BYTES = 2 * 1024 * 1024 * 1024; // 2GB
const READ_TIMEOUT_MS = 60_000;

function id() { return "amazon-q"; }
function label() { return "Amazon Q Developer"; }

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
 * Yield { file, mtimeMs, sizeBytes, broken } for every `chat-history-*.json`
 * file directly inside `~/.aws/amazonq/history/` (flat, not recursive —
 * `chatDb.ts`'s `dbDirectory` is the immediate parent of every db file, no
 * further nesting per the source read above).
 *
 * Not filtered to the exact `chat-history-` prefix: `.aws/amazonq/history`
 * is a directory this adapter treats as fully Amazon-Q-owned (per the
 * source above, nothing else writes there), so any `*.json` found there is
 * scanned — the same "don't hard-code a filename pattern likely to drift"
 * caution cursor.js documents for its own key-name filtering, applied here
 * to filenames instead of SQLite keys.
 */
function* files() {
  let entries;
  try { entries = fs.readdirSync(HISTORY_DIR, { withFileTypes: true }); }
  catch { return; } // no history directory at all — Amazon Q never ran, or never opened chat

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
 * Read one chat-history-*.json file as an array of raw text lines.
 *
 * Streamed line-by-line via readline/promises, same as claude-code.js and
 * copilot-chat.js — LokiJS's `fs` persistence adapter writes its entire
 * collection set as one JSON document (typically not pretty-printed), so in
 * the common case this yields exactly one long "line," bounded by
 * MAX_BYTES; if a given LokiJS version ever pretty-prints or the file
 * otherwise contains embedded newlines, per-line scanning still works
 * unchanged. Status vocabulary matches every other source in this project.
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
