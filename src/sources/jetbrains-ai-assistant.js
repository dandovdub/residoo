"use strict";

const fs = require("fs");
const { createInterface } = require("readline/promises");
const path = require("path");
const os = require("os");

/**
 * JetBrains AI Assistant — the AI chat/completion plugin built into
 * IntelliJ-platform IDEs (distinct from Junie, JetBrains' separate agentic
 * tool covered by jetbrains-junie.js in this same directory).
 *
 * VERIFICATION STATUS (read this before trusting anything below): two
 * genuinely different storage locations are read here, each backed by
 * independent corroboration, plus one piece of GENUINE on-disk
 * verification:
 *
 *   1. `<config dir>/JetBrains/<product><version>/workspace/*.xml` — the AI
 *      Chat panel's own history. Each file is standard JetBrains "workspace"
 *      state XML, containing (among a project's ordinary editor/tool-window
 *      state) a `<component name="ChatSessionStateTemp">` block with
 *      `SerializedChat` entries — title, `chatModelId`, a UID, and a list of
 *      `SerializedChatMessage` (author/displayContent/internalContent).
 *
 *      GENUINE VERIFICATION: this exact path SHAPE is real and was
 *      confirmed directly on the machine this source was built on —
 *      `~/Library/Application Support/JetBrains/PyCharmCE2023.1/workspace/
 *      2QYoJ9UvZwAbMvy50zVXfkUNIlG.xml` exists, is a real workspace XML
 *      file with a cryptic (non-project-derived) filename, exactly as
 *      described below. What it does NOT contain is an actual
 *      `ChatSessionStateTemp` component (confirmed by grepping it) — that
 *      PyCharm CE install is a 2023.1-vintage install last touched mid-2023
 *      that never had AI Assistant chat used in it, so the XML *schema*
 *      inside the marker (SerializedChat/SerializedChatMessage field names)
 *      is corroborated by sources below rather than confirmed against real
 *      chat content on this machine.
 *
 *      Corroborating sources for the schema: multiple independent YouTrack
 *      threads against JetBrains' own real LLM project — "AI Losing Chats"
 *      (intellij-support.jetbrains.com community post), LLM-3605, LLM-12257,
 *      LLM-19268, LLM-26509, LLM-25178 — describe the same
 *      `ChatSessionStateTemp` component name and the same "one workspace XML
 *      per project, cryptically named" behavior independently of the tool
 *      below. And github.com/sfinktah/junie-export — a real, actively
 *      maintained ~2200-line Python tool (its actual source was read for
 *      this file, not just its README) whose entire job is parsing exactly
 *      this XML shape via `xml.etree.ElementTree`, field by field
 *      (`SerializedChatTitle`, `chatModelId`, `uid`, `statisticInformation`,
 *      `messages/list/SerializedChatMessage` with
 *      `author`/`displayContent`/`internalContent`) — matching the schema
 *      used below exactly.
 *
 *   2. `<config dir>/JetBrains/<product><version>/aia-task-history/*.events`
 *      — AI Assistant's own agent-mode task history (what junie-export
 *      recovers assistant content from when a `chatModelId` starts with
 *      `agent_` and the workspace XML's own message body is empty). Each
 *      `.events` file is newline-delimited, each line base64-encoded JSON,
 *      optionally prefixed with one literal `AUI_EVENTS_V1` header line —
 *      confirmed directly from junie-export's own decode loop
 *      (`base64.b64decode(line)`, `data[0] == b"AUI_EVENTS_V1"`). The
 *      decoded records carry real, compiled-in JetBrains class names —
 *      `com.intellij.ml.llm.chat.shared.ChatSessionUserPromptEvent`,
 *      `ChatSessionMessageBlockEvent`, and
 *      `com.intellij.ml.llm.aui.events.api.{Terminal,AgentThought,Tool,
 *      ViewFiles,FileChanges,Result}BlockUpdatedEvent` — the same kind of
 *      hard-to-fabricate signal as Junie's `matterhorn` class names (see
 *      jetbrains-junie.js).
 *
 * Both locations sit under the JetBrains "config" directory (not the
 * "system"/cache directory Junie uses) — see JetBrains' own official docs,
 * "Directories used by the IDE to store settings, caches, plugins and logs"
 * (jetbrains.com/help/idea/...), for that config/cache split and the
 * `<product><version>` per-install folder convention CONFIG_BASE_DIRS below
 * follows; the macOS root of that convention
 * (`~/Library/Application Support/JetBrains/<product><version>`) is exactly
 * what the on-disk verification above confirms is real.
 *
 * What this source has NOT been checked against: real AI Assistant chat
 * content, or a real `aia-task-history` directory, on the machine it was
 * built on — neither exists there (confirmed by search), for the same
 * "PyCharm install predates real usage of this feature" reason given in
 * jetbrains-junie.js. Treat findings accordingly until confirmed against a
 * real install with real AI Assistant history.
 */

/**
 * The two base roots this source walks, per OS. Each base root is expected
 * to contain zero or more `<product><version>` directories (e.g.
 * `PyCharm2024.3`), each of which may in turn contain a `workspace/` and/or
 * an `aia-task-history/` subdirectory.
 *
 * macOS carries a second, legacy root: pre-2020 JetBrains IDEs kept their
 * per-product config directly under `~/Library/Preferences/<product><version>`
 * rather than under a shared "JetBrains" umbrella folder (this predates the
 * unified directory layout JetBrains switched to across all OSes in the
 * 2020.1 release cycle) — corroborated by junie-export's own workspace glob
 * list, which includes exactly this path. It is included here because it is
 * cheap: `~/Library/Preferences` is one well-known, bounded directory to
 * list, not a wide filesystem walk.
 *
 * Deliberately NOT included: the equivalent pre-2020 Linux layout
 * (`~/.<product><version>/config/workspace`, a bare dot-directory directly
 * under $HOME rather than under `~/.config/JetBrains`), also referenced by
 * junie-export. Finding it requires enumerating every hidden entry in
 * $HOME to test each one for a nested `config/workspace`, which is a much
 * broader and slower walk than every other root here for a layout no
 * install after 2020 uses — six-plus years stale as of this writing. This
 * is a deliberate, documented scope limit, not an oversight.
 */
function configBaseDirs() {
  const home = os.homedir();
  if (process.platform === "win32") {
    const roaming = process.env.APPDATA || path.join(home, "AppData", "Roaming");
    return [path.join(roaming, "JetBrains")];
  }
  if (process.platform === "darwin") {
    return [
      path.join(home, "Library", "Application Support", "JetBrains"),
      path.join(home, "Library", "Preferences"), // pre-2020 legacy layout
    ];
  }
  // Linux and other XDG-following unix platforms.
  const configHome = process.env.XDG_CONFIG_HOME || path.join(home, ".config");
  return [path.join(configHome, "JetBrains")];
}

// Same bounds as claude-code.js and jetbrains-junie.js, same caveat as
// jetbrains-junie.js's MAX_BYTES: not backed by an observed real large file
// for this source, since no real AI Assistant data was available to test
// against — a generous, deliberately-reused backstop, not a measured limit.
const MAX_BYTES = 2 * 1024 * 1024 * 1024; // 2GB
const READ_TIMEOUT_MS = 60_000;

// The one literal, non-base64 header line junie-export's own decoder checks
// for at the start of an `.events` file — see EVENT_FILE FORMAT note above.
const EVENTS_HEADER = "AUI_EVENTS_V1";

function id() { return "jetbrains-ai-assistant"; }
function label() { return "JetBrains AI Assistant"; }

/**
 * Cheap and honest on purpose: only the modern, primary root per OS is
 * checked (not the macOS Preferences legacy root, which is universally
 * present on every macOS machine regardless of whether JetBrains is
 * installed at all — checking it here would make this source falsely
 * report "available" for users with no JetBrains presence whatsoever).
 * files() still walks the legacy root when it's present; the tradeoff this
 * accepts is the reverse edge case — a machine with ONLY a pre-2020 install
 * and no modern one — reporting unavailable. That is an intentional,
 * documented limitation, not an oversight.
 */
function available() {
  const primary = configBaseDirs()[0];
  try { return fs.statSync(primary).isDirectory(); } catch { return false; }
}

/** Same lstat-vs-follow reasoning as claude-code.js's isKindFollowingSymlink. */
function isKindFollowingSymlink(fullPath, dirent, checkFn) {
  if (checkFn(dirent)) return true;
  if (!dirent.isSymbolicLink()) return false;
  try { return checkFn(fs.statSync(fullPath)); } catch { return false; }
}
const isDirFollowingSymlink = (p, d) => isKindFollowingSymlink(p, d, (x) => x.isDirectory());
const isFileFollowingSymlink = (p, d) => isKindFollowingSymlink(p, d, (x) => x.isFile());

/** See jetbrains-junie.js's tryReaddir for the "not found vs broken" rationale. */
function tryReaddir(dir) {
  try { return { ok: true, entries: fs.readdirSync(dir, { withFileTypes: true }) }; }
  catch (err) { return { ok: false, enoent: Boolean(err && err.code === "ENOENT") }; }
}

function* statLeaf(filePath, dirent) {
  if (!isFileFollowingSymlink(filePath, dirent)) {
    if (dirent.isSymbolicLink()) yield { file: filePath, broken: true };
    return;
  }
  let stat;
  try { stat = fs.statSync(filePath); }
  catch { yield { file: filePath, broken: true }; return; }
  yield { file: filePath, mtimeMs: stat.mtimeMs, sizeBytes: stat.size, broken: false };
}

function* leafFiles(dir, matchName) {
  const listing = tryReaddir(dir);
  if (!listing.ok) {
    if (!listing.enoent) yield { file: dir, broken: true };
    return;
  }
  for (const entry of listing.entries) {
    if (!matchName(entry.name)) continue;
    yield* statLeaf(path.join(dir, entry.name), entry);
  }
}

/**
 * List one base root and yield `{ broken: false, path }` for every real
 * `<product><version>` install directory found under it, or
 * `{ broken: true, path }` for an entry that looked like it should resolve
 * (a symlink) and didn't. A base root that simply doesn't exist (e.g. no
 * legacy Preferences-based JetBrains subdirectories on this machine) yields
 * nothing, silently — see tryReaddir.
 */
function* eachIdeDir(baseDir) {
  const listing = tryReaddir(baseDir);
  if (!listing.ok) {
    if (!listing.enoent) yield { broken: true, path: baseDir };
    return;
  }
  for (const entry of listing.entries) {
    const dir = path.join(baseDir, entry.name);
    if (isDirFollowingSymlink(dir, entry)) { yield { broken: false, path: dir }; continue; }
    if (entry.isSymbolicLink()) yield { broken: true, path: dir };
  }
}

/**
 * Yield `{ file, mtimeMs, sizeBytes, broken }` for every AI Assistant
 * transcript-bearing file found: `workspace/*.xml` and
 * `aia-task-history/*.events` under every `<product><version>` install
 * directory under every base root from configBaseDirs().
 *
 * Every `workspace/*.xml` file is yielded, not only ones already confirmed
 * to contain a `ChatSessionStateTemp` component — deliberately, mirroring
 * cursor.js's own choice not to filter `ItemTable`/`cursorDiskKV` rows by
 * key name (see that file's docstring). Peeking file content to decide
 * relevance would also break the established files()/readLines() division
 * of labour both reference sources use, where files() is a pure stat walk
 * and only readLines() ever opens content. The cost is scanning some
 * workspace XML from projects that never used AI Assistant at all — for
 * every JetBrains user, that file exists whether or not AI features were
 * ever touched — but these files are ordinary IDE state, not bulk data, so
 * that cost is small and bounded by MAX_BYTES like everything else here.
 */
function* files() {
  for (const baseDir of configBaseDirs()) {
    for (const ide of eachIdeDir(baseDir)) {
      if (ide.broken) { yield { file: ide.path, broken: true }; continue; }
      yield* leafFiles(path.join(ide.path, "workspace"), (name) => name.endsWith(".xml"));
      yield* leafFiles(path.join(ide.path, "aia-task-history"), (name) => name.endsWith(".events"));
    }
  }
}

/**
 * Plain-text read identical in shape to claude-code.js's readLines() — used
 * for `workspace/*.xml`, which needs no decoding: it's already UTF-8 text on
 * disk, and scan.js matches raw text regardless of the XML structure it came
 * from, the same way it matches raw JSON/JSONL text from the other sources.
 */
async function readPlainTextFile(file) {
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

/**
 * Read one `.events` file: newline-delimited, each line base64-encoded
 * JSON, with an optional literal `AUI_EVENTS_V1` header as the very first
 * line (checked verbatim, not base64-decoded — matches junie-export's own
 * `data[0] == b"AUI_EVENTS_V1"` check exactly).
 *
 * This decoding step is not optional the way it might look — it is the
 * whole reason this half of the source has any value. A secret embedded in
 * an agent's tool output or terminal block is, on disk, base64 text; run
 * residoo's plain-text regexes against that base64 directly and every one
 * of them fails to match (base64 systematically destroys the literal
 * substrings — "sk-ant-...", "AKIA...", etc. — those regexes look for).
 * Skipping this step would mean silently scanning nothing here while still
 * reporting the file as scanned: exactly the false "all clear" this
 * project's own rule 5 exists to prevent. This mirrors, in spirit, exactly
 * what cursor.js's valueToText() does for its BLOB-vs-TEXT SQLite columns:
 * turn whatever the real storage encoding is back into the actual text a
 * regex can match, and do it losslessly rather than round-tripping through
 * JSON.parse/stringify (so no escaping/quoting/control-character byte the
 * regexes depend on is altered by the decode).
 *
 * `Buffer.from(line, "base64")` never throws on malformed input — invalid
 * characters are simply ignored per Node's own documented behavior — so
 * there is no failure mode here to branch on beyond the same stream-level
 * timeout/partial-read handling every other readLines() in this project
 * uses.
 */
async function readEventsFile(file) {
  let stat;
  try { stat = fs.statSync(file); }
  catch { return { lines: [], status: "failed", bytesRead: 0 }; }
  if (stat.size > MAX_BYTES) return { lines: [], status: "too-large", bytesRead: 0 };

  const lines = [];
  let bytesRead = 0;
  let isFirstLine = true;
  const stream = fs.createReadStream(file, { encoding: "utf-8" });
  const rl = createInterface({ input: stream, crlfDelay: Infinity });
  const timer = setTimeout(() => stream.destroy(new Error("read timed out")), READ_TIMEOUT_MS);

  try {
    for await (const line of rl) {
      if (isFirstLine) {
        isFirstLine = false;
        if (line === EVENTS_HEADER) continue;
      }
      if (line.length === 0) continue;
      const decoded = Buffer.from(line, "base64").toString("utf-8");
      lines.push(decoded);
      bytesRead += Buffer.byteLength(decoded, "utf-8");
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

async function readLines(file) {
  if (file.endsWith(".events")) return readEventsFile(file);
  return readPlainTextFile(file);
}

module.exports = { id, label, available, files, readLines };
