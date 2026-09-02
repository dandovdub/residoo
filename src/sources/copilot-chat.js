"use strict";

const fs = require("fs");
const { createInterface } = require("readline/promises");
const path = require("path");
const os = require("os");

/**
 * GitHub Copilot Chat — the VS Code extension/panel (github.copilot-chat),
 * NOT the standalone `copilot`/`gh copilot` CLI (see copilot-cli.js for that,
 * a genuinely different product with a genuinely different storage format).
 *
 * VERIFICATION STATUS (read this before trusting anything below):
 * multi-source-corroborated-but-UNVERIFIED against a real install. VS Code
 * itself is not installed on the machine this adapter was built on (checked:
 * no /Applications/*Code*.app, no ~/Library/Application Support/Code, no
 * ~/Library/Application Support/Code - Insiders, no `code`/`code-insiders` on
 * PATH). What IS unusually strong here, short of a real install: the storage
 * mechanism and exact on-disk filenames below were read directly out of VS
 * Code's own current shipped source (microsoft/vscode, fetched verbatim via
 * `gh api repos/microsoft/vscode/contents/...` on 2026-09-02), not inferred
 * from a blog post — see the file-by-file citations inline below. Treat
 * findings from this source with the same caution as windsurf.js/void.js
 * until someone with VS Code + Copilot Chat installed confirms it against
 * real data (see CONTRIBUTING.md).
 *
 * WHERE THIS LIVES AND WHY (VS Code core chat storage, not Copilot-specific):
 * Chat session persistence is implemented in VS Code CORE
 * (`src/vs/workbench/contrib/chat/common/model/chatSessionStore.ts`), shared
 * by every chat participant an installed extension might register — it is
 * not a Copilot-owned table or folder the way Cursor's `cursorDiskKV` is
 * Cursor-owned (see cursor.js). Copilot Chat is simply the default,
 * overwhelmingly dominant participant that actually writes real content
 * there for the vast majority of installs, which is exactly what this
 * cluster's brief means by "may store history in VS Code's workspaceStorage."
 *
 * Read directly from `chatSessionStore.ts` (constructor and
 * handleWorkspaceTransition(), microsoft/vscode@780ea331b2861816fe6bb8215d81
 * 2933c81df83b, the file's own most recent commit as of this research,
 * 2026-08-06, "Harden chat import storage paths"):
 *   - Normal case (a folder/workspace is open): sessions live under
 *       <workspaceStorageHome>/<workspaceId>/chatSessions/
 *     where <workspaceId> is VS Code's own per-workspace hash directory name
 *     (workspaceStorage/<hash>/) — the same directory family cursor.js and
 *     void.js already walk in this project for their own state.vscdb files.
 *   - Empty window (no folder open): sessions live under the DEFAULT
 *     profile's globalStorage instead:
 *       <globalStorageHome>/emptyWindowChatSessions/
 *   - Legacy fallback, empty-window sessions from before this path existed:
 *       <workspaceStorageHome>/no-workspace/chatSessions/
 *     (read as a fallback only when a session isn't found at the current
 *     location; this adapter scans it unconditionally rather than trying to
 *     replicate that fallback logic, since "no-workspace" is simply one more
 *     literal-named entry under workspaceStorage/ that the generic walk
 *     below already visits like any other hash directory).
 *   - Sessions carried across a workspace-identity change (e.g. "Save
 *     Workspace As"):
 *       <globalStorageHome>/transferredChatSessions/
 *
 * Filenames, read directly from `getChatSessionStorageResource()` in
 * `chatUri.ts` (same commit) and its two call sites in `chatSessionStore.ts`:
 * each session is `<sessionId>.json` (a "flat" full-snapshot write) and/or,
 * when `chat.useLogSessionStorage` is enabled (VS Code's own default is
 * true), `<sessionId>.jsonl` (an append-only operation log — VS Code prefers
 * reading this one when both exist: see `readSessionFromLocation()`, which
 * tries the `.jsonl` location first and falls back to `.json`). Real user
 * reports independently corroborate this exact "workspaceStorage/<hash>/
 * chatSessions/*.json(.jsonl)" shape and the JSONL-vs-JSON split before this
 * adapter's own source-reading confirmed it directly:
 *   - microsoft/vscode issue #285059 ("chat sessions remain in old
 *     workspaceStorage hash") and #291897 ("missing chatSessions JSON in new
 *     workspaceStorage") — real user bug reports naming the exact directory.
 *   - microsoft/vscode issue #308730 ("malformed chatSessions JSONL") — a
 *     real user hitting a parse error in the `.jsonl` form specifically.
 *   - dev.to/5a9awneh's "VS Code is silently losing your Copilot chat
 *     history" write-up, independently describing the same
 *     `workspaceStorage/<hash>/chatSessions/` JSONL layout.
 * Base "User" directory per OS (official VS Code docs,
 * code.visualstudio.com/docs/getstarted/settings — "%APPDATA%\Code\User" on
 * Windows, "$HOME/Library/Application Support/Code/User" on macOS; Linux
 * follows the same XDG-config convention cursor.js documents): this adapter
 * checks both standard VS Code ("Code") and VS Code Insiders ("Code -
 * Insiders"), the same narrower-than-exhaustive scope cline.js already
 * documents and justifies for itself in this project — VSCodium, other VS
 * Code forks, and the separate ~/.vscode-server tree used by remote-SSH
 * sessions are deliberately NOT covered here.
 *
 * Explicitly out of scope, named rather than silently skipped:
 *   - Non-default VS Code profiles. A custom profile's globalStorage lives
 *     under `User/profiles/<profileId>/...` instead of `User/globalStorage`
 *     directly (per `IUserDataProfilesService.defaultProfile` vs. other
 *     profiles in the source read above) — only the default profile is
 *     walked here.
 *   - The session INDEX/title list. `chatSessionStore.ts` also persists a
 *     lightweight per-session index (session id -> `title`, via storage key
 *     `chat.ChatSessionStore.index`) through VS Code's generic
 *     IStorageService, which resolves to rows in the shared, per-profile
 *     `globalStorage/state.vscdb` `ItemTable` — the same file cursor.js and
 *     void.js already parse for their own products. That index is METADATA
 *     ONLY (an auto-generated title string per session, per
 *     `IChatSessionEntryMetadata` in chatSessionStore.ts) — actual message
 *     content, tool-call arguments, and anything pasted into the chat live
 *     exclusively in the chatSessions/*.json(.jsonl) files this adapter does
 *     read. Skipping the title index is the same call cline.js already makes
 *     for its own state.vscdb-backed task-title list, for the same reason.
 */
function vscodeUserDirs() {
  const home = os.homedir();
  const variants = ["Code", "Code - Insiders"];
  if (process.platform === "darwin") {
    return variants.map((v) => path.join(home, "Library", "Application Support", v, "User"));
  }
  if (process.platform === "win32") {
    const appData = process.env.APPDATA || path.join(home, "AppData", "Roaming");
    return variants.map((v) => path.join(appData, v, "User"));
  }
  // Linux and other XDG-following unix platforms.
  const configHome = process.env.XDG_CONFIG_HOME || path.join(home, ".config");
  return variants.map((v) => path.join(configHome, v, "User"));
}

// Bounds for readLines() — same rationale and same values as claude-code.js
// and cline.js. Not backed by a real Copilot Chat transcript this tool was
// tested against (no VS Code install to test with) — see the
// verification-status note above.
const MAX_BYTES = 2 * 1024 * 1024 * 1024; // 2GB
const READ_TIMEOUT_MS = 60_000;

function id() { return "copilot-chat"; }
function label() { return "GitHub Copilot Chat"; }

function available() {
  return vscodeUserDirs().some((dir) => {
    try { return fs.statSync(dir).isDirectory(); } catch { return false; }
  });
}

/**
 * Same defensive symlink-following pattern as claude-code.js's
 * isDirFollowingSymlink/isFileFollowingSymlink — see that file's docstring
 * for the full reasoning. Duplicated rather than imported, matching this
 * project's "small, self-contained file" convention (see cursor.js's own
 * note on this).
 */
function isKindFollowingSymlink(fullPath, dirent, checkFn) {
  if (checkFn(dirent)) return true;
  if (!dirent.isSymbolicLink()) return false;
  try { return checkFn(fs.statSync(fullPath)); } catch { return false; }
}
const isDirFollowingSymlink = (p, d) => isKindFollowingSymlink(p, d, (x) => x.isDirectory());
const isFileFollowingSymlink = (p, d) => isKindFollowingSymlink(p, d, (x) => x.isFile());

/**
 * Yield { file, mtimeMs, sizeBytes, broken } for every `*.json`/`*.jsonl`
 * session file directly inside one chatSessions-shaped directory (flat, not
 * recursive — chatSessionStore.ts writes sessions as immediate children of
 * its storage root, confirmed via getChatSessionStorageResource()'s own
 * dirname-equality check).
 *
 * A directory that simply doesn't exist yields nothing — normal, not broken:
 * most workspaceStorage/<hash> entries are for workspaces that never opened
 * the Chat view, and empty/transferred/legacy chat-session directories are
 * only ever created on first use. Only an entry that looked like it should
 * resolve and didn't (chiefly a dangling symlink) is reported broken, same
 * convention as every other source in this project.
 */
function* walkSessionFilesDir(dir) {
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); }
  catch { return; }

  for (const e of entries) {
    if (!(e.name.endsWith(".json") || e.name.endsWith(".jsonl"))) continue;
    const file = path.join(dir, e.name);
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
 * Walk every entry directly under workspaceStorage/ (each one is either a
 * per-workspace hash directory or the literal "no-workspace" legacy
 * directory — both are just directories containing an optional
 * chatSessions/ subdirectory, so no special-casing is needed) and yield
 * whatever session files are inside each one's chatSessions/.
 */
function* walkWorkspaceStorage(workspaceStorageDir) {
  let entries;
  try { entries = fs.readdirSync(workspaceStorageDir, { withFileTypes: true }); }
  catch { return; } // no workspaceStorage at all for this VS Code variant/profile — normal

  for (const e of entries) {
    const entryDir = path.join(workspaceStorageDir, e.name);
    if (!isDirFollowingSymlink(entryDir, e)) {
      if (e.isSymbolicLink()) yield { file: entryDir, broken: true };
      continue; // a stray non-directory entry under workspaceStorage/ is out of scope, not broken
    }
    yield* walkSessionFilesDir(path.join(entryDir, "chatSessions"));
  }
}

/**
 * Yield { file, mtimeMs, sizeBytes, broken } for every Copilot/VS-Code-chat
 * session file this adapter knows how to find, across every candidate VS
 * Code User dir (standard + Insiders): every workspaceStorage/<hash-or-
 * "no-workspace">/chatSessions/*.json(.jsonl), plus the default profile's
 * globalStorage/emptyWindowChatSessions/ and globalStorage/
 * transferredChatSessions/.
 */
function* files() {
  for (const userDir of vscodeUserDirs()) {
    yield* walkWorkspaceStorage(path.join(userDir, "workspaceStorage"));

    const globalStorageDir = path.join(userDir, "globalStorage");
    yield* walkSessionFilesDir(path.join(globalStorageDir, "emptyWindowChatSessions"));
    yield* walkSessionFilesDir(path.join(globalStorageDir, "transferredChatSessions"));
  }
}

/**
 * Read one chatSessions file as an array of raw text lines.
 *
 * Both known shapes are ordinary UTF-8 text — a `.jsonl` operation log is
 * one JSON record per line by construction, and a `.json` flat snapshot is
 * still real text (pretty-printed or not) rather than a binary format — so
 * the same streamed readline/promises approach claude-code.js and cline.js
 * use applies unchanged: no whole-file-as-one-string V8 length ceiling, and
 * a partial read still returns whatever lines WERE read rather than
 * discarding real content. A minified single-line `.json` file just becomes
 * one long "line," bounded the same way by MAX_BYTES.
 *
 * Status vocabulary matches every other source in this project: "complete",
 * "partial", "too-large", "failed".
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
