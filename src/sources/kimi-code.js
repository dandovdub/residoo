"use strict";

const fs = require("fs");
const { createInterface } = require("readline/promises");
const path = require("path");
const os = require("os");

/**
 * Moonshot AI's Kimi Code CLI (github.com/MoonshotAI/kimi-code, 7,200+
 * stars; also mirrored/aliased as github.com/MoonshotAI/kimi-cli, 11,300+
 * stars) local session transcripts.
 *
 * VERIFICATION STATUS: read directly from the actual, current shipped source
 * code of the MoonshotAI/kimi-code monorepo (fetched from GitHub during this
 * source's research, not inferred from docs or a blog post) — but NOT
 * checked against a real install on the machine this source was built on (no
 * `~/.kimi-code` directory exists there; see CONTRIBUTING.md). This is the
 * same confidence tier as cursor.js's SQLite-schema verification: real
 * source, not a real install.
 *
 * The chain of evidence, file by file, all from MoonshotAI/kimi-code@main:
 *   - `packages/agent-core/src/config/path.ts`:
 *     `resolveKimiHome()` returns `$KIMI_CODE_HOME`, else
 *     `join(homedir(), '.kimi-code')` — i.e. ROOT below.
 *   - `apps/kimi-code/src/cli/telemetry.ts`'s `createCliTelemetryBootstrap()`
 *     calls `resolveKimiHome()` for the `homeDir` the CLI actually wires
 *     into its session store (via `apps/kimi-code/src/cli/sub/session.ts`'s
 *     `createDefaultSessionListDeps()`), confirming this is the real runtime
 *     value, not just an unused helper.
 *   - `packages/agent-core/src/session/store/session-store.ts`'s
 *     `SessionStore` class: `this.sessionsDir = join(homeDir, 'sessions')`,
 *     and each session's directory is
 *     `sessionsDir/<bucket>/<sessionId>` where `<bucket>` comes from
 *     `encodeWorkDirKey()` (`packages/agent-core/src/session/store/
 *     workdir-key.ts`): `wd_<slug>_<sha256(workdir).slice(0,12)>`.
 *   - `packages/agent-core/src/services/message/transcript.ts`'s own
 *     docstring: "rebuilds the FULL message history of a session agent from
 *     its `wire.jsonl` record log... The wire log... keeps every record,"
 *     confirming `wire.jsonl` (via `FileSystemAgentRecordPersistence`, an
 *     append-only JSONL writer in `packages/agent-core/src/agent/records/
 *     persistence.ts`) as the actual on-disk transcript file inside each
 *     session directory.
 *
 * Full path: `~/.kimi-code/sessions/<bucket>/<sessionId>/wire.jsonl`. This
 * source does not attempt to recompute `<bucket>` (the slug+hash scheme
 * above) — like claude-code.js not decoding Claude Code's own project-slug
 * naming, it simply walks the tree recursively for `wire.jsonl`, which needs
 * no knowledge of how the intermediate directory names are derived.
 *
 * Deliberately not honored: the `KIMI_CODE_HOME` environment-variable
 * override confirmed above. Neither claude-code.js nor cursor.js chases an
 * equivalent override for its own tool, and the plain default path is what
 * the overwhelming majority of installs actually use.
 */
const HOME = os.homedir();
const KIMI_HOME = path.join(HOME, ".kimi-code");
const SESSIONS_ROOT = path.join(KIMI_HOME, "sessions");

const MAX_BYTES = 2 * 1024 * 1024 * 1024; // 2GB — same backstop as claude-code.js.
const READ_TIMEOUT_MS = 60_000;
const MAX_WALK_DEPTH = 8;

function id() { return "kimi-code"; }
function label() { return "Kimi Code"; }

function available() {
  try { return fs.statSync(SESSIONS_ROOT).isDirectory(); } catch { return false; }
}

/**
 * Same defensive symlink-following helpers as claude-code.js — see that
 * file's docstring. Duplicated rather than imported, per this project's
 * self-contained-source-file convention (see cursor.js's docstring).
 */
function isKindFollowingSymlink(fullPath, dirent, checkFn) {
  if (checkFn(dirent)) return true;
  if (!dirent.isSymbolicLink()) return false;
  try { return checkFn(fs.statSync(fullPath)); } catch { return false; }
}
const isDirFollowingSymlink = (p, d) => isKindFollowingSymlink(p, d, (x) => x.isDirectory());
const isFileFollowingSymlink = (p, d) => isKindFollowingSymlink(p, d, (x) => x.isFile());

/**
 * Recursively yield { file, mtimeMs, sizeBytes, broken } for every plain file
 * under `dir` whose name passes `matchFn` — see factory-droid.js's walk()
 * for the identical reasoning.
 */
function* walk(dir, depth, matchFn) {
  if (depth > MAX_WALK_DEPTH) return;
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); }
  catch { return; }

  for (const e of entries) {
    const full = path.join(dir, e.name);
    if (isDirFollowingSymlink(full, e)) {
      yield* walk(full, depth + 1, matchFn);
      continue;
    }
    const isFile = isFileFollowingSymlink(full, e);
    if (!isFile) {
      if (e.isSymbolicLink()) yield { file: full, broken: true };
      continue;
    }
    if (!matchFn(e.name)) continue;
    let stat;
    try { stat = fs.statSync(full); } catch { yield { file: full, broken: true }; continue; }
    yield { file: full, mtimeMs: stat.mtimeMs, sizeBytes: stat.size, broken: false };
  }
}

function* files() {
  yield* walk(SESSIONS_ROOT, 0, (name) => name === "wire.jsonl");
}

/**
 * Read one wire.jsonl transcript as raw text lines. Identical streaming/
 * timeout/partial-read discipline to claude-code.js's readLines().
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
