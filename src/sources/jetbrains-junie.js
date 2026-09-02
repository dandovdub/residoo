"use strict";

const fs = require("fs");
const { createInterface } = require("readline/promises");
const path = require("path");
const os = require("os");

/**
 * JetBrains Junie session history (Junie = JetBrains' own agentic coding
 * tool, bundled/installable into IntelliJ-platform IDEs: IntelliJ IDEA,
 * PyCharm, WebStorm, GoLand, etc.).
 *
 * VERIFICATION STATUS (read this before trusting anything below): the path
 * and schema here are corroborated by:
 *
 *   1. junie-explorer (github.com/dmeehan1968/junie-explorer) — a real,
 *      actively developed, ~370-file TypeScript/Bun web app whose entire
 *      purpose is reading these exact files to render a UI over them. Its
 *      path-discovery code (src/jetbrains.ts) and Zod schemas (src/schema.ts,
 *      src/schema/*.ts) were read directly (not just its README) for this
 *      source. Its schema encodes real, compiled-in JetBrains class names —
 *      e.g. `com.intellij.ml.llm.matterhorn.llm.MatterhornChatMessage` and
 *      `com.intellij.ml.llm.matterhorn.ArtifactReasoning.{Success,Failure}`
 *      — strong evidence this isn't a guess: those exact dotted package
 *      names aren't the kind of thing an outside author invents, they're
 *      read off Junie's own bytecode/plugin.xml by someone who actually
 *      inspected a real install. "Matterhorn" is Junie's internal codename,
 *      which is also why the on-disk directory is `matterhorn/.matterhorn`,
 *      not anything with "junie" in it.
 *   2. JetBrains' own official docs, "Directories used by the IDE to store
 *      settings, caches, plugins and logs" (jetbrains.com/help/idea/...),
 *      for the per-OS "system"/cache directory convention
 *      (`<product><version>` folder under a platform-specific root) that
 *      CACHE_ROOT below follows.
 *   3. Multiple YouTrack issues against the real JUNIE project (JUNIE-606
 *      "loses chat history after moving the project location", JUNIE-924
 *      "Recovering Junie history", JUNIE-498 "loses all history when
 *      updating the IDE") independently corroborate that Junie's history is
 *      local, keyed by project, and lives outside the IDE's own settings
 *      sync — consistent with a per-project cache directory rather than
 *      e.g. a cloud-synced or single-file store.
 *
 * What this source has NOT been checked against: a real Junie install with
 * real session history on the machine it was built on. PyCharm (both the
 * paid and Community editions) IS installed there, confirmed via
 * `~/Library/Application Support/JetBrains/PyCharm2023.1` and
 * `PyCharmCE2023.1` actually existing on disk — which independently
 * confirms the sibling `<product><version>`-per-install naming convention
 * this file relies on for CACHE_ROOT is real, not guessed. But that install
 * is a `2023.1`-vintage install last touched mid-2023, years before Junie
 * existed as a product, and a filesystem search of the whole home directory
 * for `matterhorn`, `Junie`, or `AIAssistant` turned up nothing — so there
 * is no real Junie history on this machine to verify the JSON/JSONL schema
 * against. Treat findings from this source accordingly until someone with
 * an actual Junie session confirms it against real data.
 */

/**
 * Junie's own data sits under each IDE's "system" (cache) directory, one
 * `<product><version>` folder per install — e.g. `PyCharm2024.3`,
 * `IntelliJIdea2025.1` — exactly mirroring claude-code.js's ROOT and
 * cursor.js's cursorUserDir(): a single well-known platform root, walked at
 * scan time rather than hard-coded per product/version.
 */
function cacheRoot() {
  const home = os.homedir();
  if (process.platform === "darwin") {
    return path.join(home, "Library", "Caches", "JetBrains");
  }
  if (process.platform === "win32") {
    const local = process.env.LOCALAPPDATA || path.join(home, "AppData", "Local");
    return path.join(local, "JetBrains");
  }
  // Linux and other XDG-following unix platforms.
  const cacheHome = process.env.XDG_CACHE_HOME || path.join(home, ".cache");
  return path.join(cacheHome, "JetBrains");
}

const CACHE_ROOT = cacheRoot();

// Same bounds as claude-code.js, for the same reasons (see its docstring).
// Unlike claude-code.js's MAX_BYTES, this is NOT backed by an observed real
// large file for this source specifically — no real Junie data was
// available to test against, per the verification note above — it is only
// a generous, deliberately-reused backstop.
const MAX_BYTES = 2 * 1024 * 1024 * 1024; // 2GB
const READ_TIMEOUT_MS = 60_000;

function id() { return "jetbrains-junie"; }
function label() { return "JetBrains Junie"; }

function available() {
  try { return fs.statSync(CACHE_ROOT).isDirectory(); } catch { return false; }
}

/**
 * Same lstat-vs-follow reasoning as claude-code.js's isKindFollowingSymlink
 * (Dirent reflects the entry itself, not what a symlink resolves to).
 * Duplicated rather than imported — see cursor.js's docstring on
 * isDirFollowingSymlink for why each source stays self-contained.
 */
function isKindFollowingSymlink(fullPath, dirent, checkFn) {
  if (checkFn(dirent)) return true;
  if (!dirent.isSymbolicLink()) return false;
  try { return checkFn(fs.statSync(fullPath)); } catch { return false; }
}
const isDirFollowingSymlink = (p, d) => isKindFollowingSymlink(p, d, (x) => x.isDirectory());
const isFileFollowingSymlink = (p, d) => isKindFollowingSymlink(p, d, (x) => x.isFile());

/**
 * List a directory, distinguishing "doesn't exist" from every other
 * failure. Reused at every directory boundary below because Junie's real
 * layout is several levels deep (cache root -> IDE install -> project ->
 * matterhorn/.matterhorn -> issues/events -> optionally one more level) and
 * each of those levels needs the same "not found is normal, anything else
 * is broken" judgment call that claude-code.js and cursor.js each make once.
 * A missing `projects` directory under one IDE install, for instance, just
 * means that IDE install predates Junie or never had it open on a project —
 * not a reportable failure. An unreadable directory that DOES exist (e.g.
 * permissions) is a real, surfaceable failure.
 */
function tryReaddir(dir) {
  try { return { ok: true, entries: fs.readdirSync(dir, { withFileTypes: true }) }; }
  catch (err) { return { ok: false, enoent: Boolean(err && err.code === "ENOENT") }; }
}

/**
 * Yield `{ file, mtimeMs, sizeBytes, broken }` for one leaf file, following
 * a symlink to see what it really is first — same convention as
 * claude-code.js's files() loop over `.jsonl` entries.
 */
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

/** List `dir` and yield statLeaf() for every entry whose name passes `matchName`. */
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
 * Walk one project's `matterhorn/.matterhorn` directory:
 *
 *   matterhorn/.matterhorn/
 *     events/
 *       <uuid>-events.jsonl        <- already line-delimited JSON, read as-is
 *     issues/
 *       chain-<issueId>.json       <- one JSON object per file
 *       chain-<issueId>/
 *         task-<index>.json        <- one JSON object per file, one level deeper
 *
 * `events/*.jsonl` holds the actual LLM request/response and tool-call
 * event stream for Junie's newer "AIA task" flow; `issues/` holds the older
 * "chain" flow's per-issue and per-task state (context.description, the
 * unified diff `patch` applied, prior agent observations, etc. — see
 * junie-explorer's schema.ts for the full shape). Both are read the exact
 * same way by readLines() below: no transform is needed for either, since
 * both are already plain text on disk (unlike cursor.js's SQLite rows, there
 * is no encoding layer here to peel back).
 *
 * Subdirectories under `issues/` are not filtered by name (e.g. requiring a
 * `chain-` prefix) — they are Junie's own internal storage, not user
 * content, so listing them broadly costs nothing and stays resilient to
 * exact naming drift across versions, the same reasoning cursor.js gives for
 * not filtering `cursorDiskKV` by key name.
 */
function* walkMatterhorn(matterhornDir) {
  yield* leafFiles(path.join(matterhornDir, "events"), (name) => name.endsWith("-events.jsonl"));

  const issuesDir = path.join(matterhornDir, "issues");
  const issuesListing = tryReaddir(issuesDir);
  if (!issuesListing.ok) {
    if (!issuesListing.enoent) yield { file: issuesDir, broken: true };
    return;
  }
  for (const entry of issuesListing.entries) {
    const entryPath = path.join(issuesDir, entry.name);
    if (isFileFollowingSymlink(entryPath, entry)) {
      if (entry.name.endsWith(".json")) yield* statLeaf(entryPath, entry);
      continue;
    }
    if (isDirFollowingSymlink(entryPath, entry)) {
      yield* leafFiles(entryPath, (name) => name.endsWith(".json"));
      continue;
    }
    if (entry.isSymbolicLink()) yield { file: entryPath, broken: true };
  }
}

/**
 * Yield `{ file, mtimeMs, sizeBytes, broken }` for every Junie transcript
 * file found across every IDE install and every project under
 * CACHE_ROOT/<product><version>/projects/<project name>/matterhorn/.matterhorn.
 *
 * Mirrors claude-code.js's files(): a missing `projects` directory under one
 * IDE install, or a missing `matterhorn/.matterhorn` under one project, is
 * the ordinary case (that install or that project never used Junie) and is
 * silently skipped, not reported broken — only entries that looked
 * resolvable and weren't (chiefly dangling symlinks) or directories that
 * exist but couldn't be listed are surfaced.
 */
function* files() {
  const top = tryReaddir(CACHE_ROOT);
  if (!top.ok) {
    if (!top.enoent) yield { file: CACHE_ROOT, broken: true };
    return;
  }

  for (const ideEntry of top.entries) {
    const ideDir = path.join(CACHE_ROOT, ideEntry.name);
    if (!isDirFollowingSymlink(ideDir, ideEntry)) {
      if (ideEntry.isSymbolicLink()) yield { file: ideDir, broken: true };
      continue;
    }

    const projectsDir = path.join(ideDir, "projects");
    const projectsListing = tryReaddir(projectsDir);
    if (!projectsListing.ok) {
      if (!projectsListing.enoent) yield { file: projectsDir, broken: true };
      continue;
    }

    for (const projEntry of projectsListing.entries) {
      const projectDir = path.join(projectsDir, projEntry.name);
      if (!isDirFollowingSymlink(projectDir, projEntry)) {
        if (projEntry.isSymbolicLink()) yield { file: projectDir, broken: true };
        continue;
      }
      yield* walkMatterhorn(path.join(projectDir, "matterhorn", ".matterhorn"));
    }
  }
}

/**
 * Read one transcript file (either an `events/*.jsonl` or an
 * `issues/**\/*.json` file) as an array of raw text lines.
 *
 * Identical in shape and reasoning to claude-code.js's readLines(): both
 * file kinds here are plain UTF-8 text on disk (pretty-printed or minified
 * JSON, or true JSONL), so the same streamed, size-capped, timed-out,
 * partial-read-preserving read applies unchanged — see that file's
 * docstring for the full rationale (ERR_STRING_TOO_LONG avoidance, the
 * TOCTOU re-stat, why a hung read needs a destroy()-based timeout). This is
 * deliberately not copy-pasted-and-modified; it just IS the same read
 * strategy, because the underlying storage shape is the same (a plain text
 * file), unlike cursor.js's SQLite source which genuinely needs different
 * machinery.
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
