"use strict";

const fs = require("fs");
const { createInterface } = require("readline/promises");
const path = require("path");
const os = require("os");

/**
 * Kiro IDE (AWS/Kiro's VS Code–based desktop IDE) agent chat history.
 * Distinct from Kiro CLI (see kiro-cli.js) — same product family, different
 * application, different storage.
 *
 * VERIFICATION STATUS (read this before trusting anything below): the exact
 * path and directory shape below are corroborated by THREE independent,
 * real-world sources, none of them official documentation (Kiro's own docs
 * do not appear to document this path at all — this source found none):
 *
 *   1. github.com/kirodotdev/Kiro issue #5469 — a real user's own `du -sh`
 *      output against their live install: `~/Library/Application
 *      Support/kiro/User/globalStorage/kiro.kiroagent` (13GB, broken down
 *      into per-workspace-hash subdirectories like
 *      `d1c95acd1215dbe372efb48819c04345/`).
 *   2. github.com/kirodotdev/Kiro issue #4165 — a SECOND, independent real
 *      user reporting the identical shape from their own install (6,422
 *      files, ~8.2GB), explicitly describing the content: "Each file
 *      contains the full context of a spec generation run, including your
 *      prompts and environment context" — i.e. real prompt/response text,
 *      exactly the "AI-block" content this source was scoped to find.
 *   3. github.com/kirodotdev/Kiro PR #5755 (open, unmerged, but written
 *      against a real install by a third independent contributor) — a
 *      cache-cleanup script whose actual shell logic this source fetched
 *      and read directly (`gh pr diff 5755`), which is more precise than
 *      either issue: it fixes the exact base path (with correct
 *      capitalization — `Kiro`, not `kiro`, resolving a casing
 *      inconsistency between the two issues above) and identifies which
 *      files under it are the real conversation content:
 *        `~/Library/Application Support/Kiro/User/globalStorage/kiro.kiroagent/`
 *      containing per-workspace hex-hash directories, each holding:
 *        - one or more `*.chat` files — "Chat Files (.chat): Conversation
 *          history with Kiro" (the script's own "WHAT GETS DELETED"
 *          section) — confirmed as FILES, not directories, by its actual
 *          deletion command: `find . -name "*.chat" -type f`.
 *        - other subdirectories holding "File Version Cache: Subdirectories
 *          containing snapshots of project files used for diff/restore
 *          operations."
 *      The companion script in the same PR (`clean-kiro-ide-sessions.sh`)
 *      further confirms two SIBLING directories exist —
 *      `~/Library/Application Support/Kiro/Session Storage` (its own
 *      description: "LevelDB files... window positions, open tabs,
 *      navigation history") and `.../Kiro/Workspaces` (workspace
 *      settings/state) — and that neither holds conversation content. This
 *      mirrors exactly what cursor.js already established for a sibling VS
 *      Code fork: the generic Electron/VS-Code-shell state (Session
 *      Storage, Workspaces) is separate from, and uninteresting compared
 *      to, the extension-specific data under `User/globalStorage/<extension-id>/`
 *      — here `kiro.kiroagent`, Kiro's own agent extension ID. Deliberately
 *      OUT OF SCOPE for the same reason gemini-cli.js excludes its
 *      tool's checkpoints/logs directories: `Session Storage` and
 *      `Workspaces` are confirmed to hold window/UI state, not agent
 *      conversation content.
 *
 * None of this has been checked against a real Kiro IDE install — it is not
 * installed on the machine this adapter was built on (checked: no `Kiro.app`
 * under /Applications, no matching directory under `~/Library/Application
 * Support`, not findable via `mdfind`). If you have Kiro IDE installed, the
 * most useful thing you can do is run `residoo scan` and confirm
 * `sourcesScanned`/`filesScanned` look right for what you know is actually
 * on disk under the path above, then report back either way.
 *
 * INTERNAL FORMAT OF `.chat` FILES: not independently confirmed — none of
 * the three sources above open or describe one's actual bytes, only its
 * name, size, and general subject ("conversation history", "prompts and
 * environment context"). This source treats `.chat` files as plain text
 * (streamed the same way claude-code.js treats `.jsonl`), which is
 * consistent with every comparable VS-Code-fork/agent-tool store this
 * project has examined (Cursor's cursorDiskKV values, Warp's blob columns,
 * Crush's `content` column — all JSON text, none binary) but is, honestly,
 * an inference from that pattern rather than a confirmed fact about this
 * specific file format. Per the adapter contract this is safe either way:
 * a line-by-line text read against a file that happens to be binary just
 * yields lines that don't pattern-match anything, not a crash — see
 * claude-code.js's own docstring on this exact point.
 *
 * PER-OS PATH: only the macOS path is independently confirmed (all three
 * sources are macOS reports). Windows and Linux below are filled in by
 * direct structural analogy to cursor.js's own per-OS `<App>/User/` layout
 * — the same convention this project already relies on for a sibling VS
 * Code fork, applied here because Kiro IDE is itself documented as
 * "VS Code-based" (kirodotdev/Kiro's own repo description). Flagged as
 * analogy, not independently quoted, same honesty standard as this
 * project's other per-OS gaps.
 */
function kiroUserDir() {
  const home = os.homedir();
  if (process.platform === "darwin") {
    return path.join(home, "Library", "Application Support", "Kiro", "User");
  }
  if (process.platform === "win32") {
    const appData = process.env.APPDATA || path.join(home, "AppData", "Roaming");
    return path.join(appData, "Kiro", "User");
  }
  // Linux and other XDG-following unix platforms.
  const configHome = process.env.XDG_CONFIG_HOME || path.join(home, ".config");
  return path.join(configHome, "Kiro", "User");
}

const USER_DIR = kiroUserDir();
const AGENT_STORAGE_DIR = path.join(USER_DIR, "globalStorage", "kiro.kiroagent");

// How many levels deep files() will descend under kiro.kiroagent/ looking
// for `*.chat` files. The confirmed shape is one workspace-hash level
// (`<hash>/*.chat`), but the cleanup script's own recursive `find . -name
// "*.chat"` (no depth limit, run from the kiro.kiroagent root) implies
// *.chat files are not guaranteed to sit at exactly that one depth — kept
// bounded rather than hard-coded at exactly 1 for the same reason
// gemini-cli.js's MAX_CHATS_DEPTH is bounded rather than fixed: a deeper
// nesting should still get scanned, and a symlink cycle must not turn this
// into an infinite walk.
const MAX_WALK_DEPTH = 4;

const MAX_BYTES = 2 * 1024 * 1024 * 1024; // 2GB — see claude-code.js; not independently
                                            // measured against a real .chat file here.
const READ_TIMEOUT_MS = 60_000;

function id() { return "kiro-ide"; }
function label() { return "Kiro IDE"; }

function available() {
  try { return fs.statSync(AGENT_STORAGE_DIR).isDirectory(); } catch { return false; }
}

/**
 * Same defensive symlink-following pattern as claude-code.js and cursor.js
 * — see claude-code.js's docstring for the full reasoning. Duplicated
 * rather than imported: each source here is meant to be a small,
 * self-contained file a reviewer can audit on its own (CONTRIBUTING.md).
 */
function isKindFollowingSymlink(fullPath, dirent, checkFn) {
  if (checkFn(dirent)) return true;
  if (!dirent.isSymbolicLink()) return false;
  try { return checkFn(fs.statSync(fullPath)); } catch { return false; }
}
const isDirFollowingSymlink = (p, d) => isKindFollowingSymlink(p, d, (x) => x.isDirectory());
const isFileFollowingSymlink = (p, d) => isKindFollowingSymlink(p, d, (x) => x.isFile());

/**
 * Walk kiro.kiroagent/ (or one of its subdirectories) for `*.chat` files, up
 * to MAX_WALK_DEPTH levels deep. The confirmed "file version cache"
 * subdirectories (diff/restore snapshots, unconfirmed internal format) are
 * still descended into by this walk — they are not excluded — because a
 * cache directory could itself, in principle, hold a nested `*.chat` file
 * under some Kiro version this source has no visibility into; only files
 * that don't match the `.chat` name pattern are skipped, not whole
 * directories. See the module docstring for why cache-directory CONTENTS
 * themselves (i.e. files inside them that aren't named `*.chat`) are out of
 * scope: their format was never confirmed.
 */
function* walkChatFiles(dir, depth) {
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); }
  catch { return; }

  for (const e of entries) {
    const full = path.join(dir, e.name);

    if (isDirFollowingSymlink(full, e)) {
      if (depth < MAX_WALK_DEPTH) yield* walkChatFiles(full, depth + 1);
      continue;
    }
    if (isFileFollowingSymlink(full, e)) {
      if (!e.name.endsWith(".chat")) continue;
      let stat;
      try { stat = fs.statSync(full); } catch { yield { file: full, broken: true }; continue; }
      yield { file: full, mtimeMs: stat.mtimeMs, sizeBytes: stat.size, broken: false };
      continue;
    }
    // Neither resolves as a directory nor a file: a dangling symlink is the
    // one case worth reporting.
    if (e.isSymbolicLink()) yield { file: full, broken: true };
  }
}

/**
 * Yield { file, mtimeMs, sizeBytes, broken } for every `*.chat` file found
 * under `.../User/globalStorage/kiro.kiroagent/`.
 */
function* files() {
  yield* walkChatFiles(AGENT_STORAGE_DIR, 0);
}

/**
 * Read one `.chat` file as an array of raw text lines. Identical approach to
 * claude-code.js's readLines() — streamed via readline/promises (not
 * readFileSync+split, for the same V8 string-length-ceiling reason), a
 * generous size cap, and a hard read timeout since Node's stream/readline
 * stack has no built-in one. See claude-code.js's own docstring for the
 * full reasoning; not re-derived here since nothing about it is
 * Kiro-specific. Whether `.chat` is JSON, JSONL, or something else, lines
 * don't need to be valid JSON individually per the adapter contract — they
 * just need pattern-matching against.
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
