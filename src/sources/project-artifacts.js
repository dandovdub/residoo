"use strict";

const fs = require("fs");
const path = require("path");
const { createInterface } = require("readline/promises");

/**
 * Committed agent artifacts inside a PROJECT directory (a repo checkout).
 *
 * Every other source scans the machine's home-level stores: what the agent
 * wrote for itself. This one scans what a repo is about to ship: transcripts,
 * agent configs, and .env files sitting inside a checkout, where `git add .`
 * and `npm publish` will carry them to everyone. The evidence that this is
 * where the bodies are buried is the strongest in the whole research base:
 * GitGuardian measured Claude Code-assisted commits leaking at 3.2% vs the
 * 1.5% GitHub baseline; Lakera found live credentials inside
 * `.claude/settings.local.json` files shipped in ~30 published npm packages
 * precisely because no packaging tool ignores `.claude/` by default; and the
 * Miasma campaign infected on repo OPEN via planted `.claude/settings.json`,
 * `.gemini/settings.json`, `.cursor/rules/setup.mdc`, and `.vscode/tasks.json`
 * (see the research digest, 2026-09-02, and integrity.js's campaign headers).
 *
 * OPT-IN BY CONSTRUCTION, never part of the default scan. The registry in
 * index.js holds one singleton per source and filters with available(); a
 * project scan needs a PARAMETER (which directory), and a singleton cannot
 * carry one honestly. Two designs were considered:
 *
 *   - setRoot() mutating this module's singleton: rejected. The registry
 *     object is shared process-wide, so one scan's --project argument would
 *     leak into any later scan in the same process, and "available() is
 *     false unless configured" would silently stop being true in a way no
 *     local reading of this file could reveal.
 *   - withRoot(root) factory: chosen. The module's default export still
 *     satisfies the full { id, label, available, files, readLines } contract
 *     (so registering it in index.js is harmless: available() is always
 *     false and files() yields nothing), while the CLI's --project handling
 *     constructs a configured instance and passes it straight into
 *     scan({ sources: [...] }). No shared mutable state, no registry change.
 *
 * WHAT IS SCANNED, with the verification trail per CONTRIBUTING.md's
 * no-guessed-paths rule ("real install" means this project's own build
 * machine, checked read-only):
 *
 * (a) Committed agent transcripts:
 *   - `*.jsonl` under any `.claude/` path component. Claude Code's own
 *     transcript layout is `<root>/projects/<slug>/<session>.jsonl` (real
 *     install, and claude-code.js's territory at home level); a copy of any
 *     part of that tree committed into a repo keeps the `.claude` component.
 *   - `*.jsonl` inside a directory whose name starts with "-": the
 *     project-slug shape Claude Code uses (the absolute project path with
 *     separators replaced by "-", e.g. `-Users-.../<uuid>.jsonl`; verified
 *     against the real install's ~/.claude/projects). A slug directory
 *     copied into a repo WITHOUT its `.claude` parent still matches this.
 *   - `rollout-*.jsonl` at any depth: Codex CLI's per-session file naming,
 *     corroborated in codex-cli.js's header (openai/codex issues #21660 and
 *     the archived-sessions issue both name `rollout-*.jsonl` verbatim).
 *   - any file under a `.specstory/` path component: SpecStory saves
 *     Cursor/Copilot chat history as Markdown into `.specstory/history/`
 *     inside the project, and its own docs describe committing that
 *     directory to share reasoning in PRs (docs.specstory.com/integrations/
 *     cursor; github.com/specstoryai/getspecstory). This is the one
 *     Cursor-export shape with a stable, citable on-disk location.
 *
 *   Deliberately NOT matched, and why:
 *   - Cursor's built-in "export chat" output: the exported Markdown carries
 *     no stable name (community exporters observed during research use
 *     "{chat title}_{session id}.md", bare timestamps, and other schemes
 *     that disagree with each other). Any filename matcher here would be a
 *     guessed path; matching all `*.md` would scan every doc in the repo.
 *     A clean run therefore says nothing about hand-exported chat files.
 *   - generic `*.jsonl` anywhere: repos legitimately hold JSONL datasets
 *     and fixtures far larger than any transcript; scanning them all would
 *     drown the honest signal. The three transcript shapes above are the
 *     ones with citable naming.
 *
 * (b) Agent config/rules files at ANY depth (monorepos nest them):
 *   - `.claude/settings*.json` (settings.json, settings.local.json: the
 *     Lakera leak vector and the Mini Shai-Hulud/Miasma plant site)
 *   - `.mcp.json` (project-scope MCP config, Claude Code's own docs; the
 *     GitGuardian 24,008-secrets-in-MCP-configs category)
 *   - `.cursor/rules/*` (Miasma's setup.mdc plant site)
 *   - `.cursorrules` (TrapDoor's zero-width carrier)
 *   - `CLAUDE.md` and `CLAUDE.local.md` (Claude Code memory files, per its
 *     own memory docs; the other TrapDoor carrier)
 *   - `AGENTS.md` (the cross-vendor agent-instructions convention Codex and
 *     others load; codex-cli.js's research trail covers it)
 *   - `.gemini/settings.json` (Miasma plant site)
 *   - `.vscode/tasks.json` (the "runOn": "folderOpen" persistence surface)
 *
 * (c) `.env` files at the ROOT only (`.env`, `.env.local`, `.env.production`,
 *     `.env.example`, any `.env.*`). The root .env is the classic accidental
 *     commit. Deeper .env files are very often fixtures, scaffold templates,
 *     and per-package samples; a monorepo's `packages/x/.env` is therefore a
 *     NAMED exclusion with a real false-negative risk, not an oversight.
 *     Revisit with evidence if deeper .envs prove to leak in practice.
 *     `.env.example` at the root IS included on purpose: a real key pasted
 *     into an example file gets committed by design, and scan.js's
 *     placeholder suppression already keeps template content quiet.
 *
 * NOT walked at all: the CONTENTS of `node_modules/` and `.git/`.
 * node_modules is other people's published code (a scan of it is an audit of
 * the npm registry, not of this repo, and it blows any node budget on every
 * real project); .git holds zlib-compressed objects the line engine cannot
 * read meaningfully. Both skips are unconditional and silent because the
 * directories are expected on virtually every repo; a skipped EXPECTED
 * directory is not a truncation. Every UNEXPECTED cut (depth cap, node cap,
 * unreadable directory) is surfaced as a broken entry instead, because a
 * bounded walk that ends quietly is a false all-clear (CONTRIBUTING.md
 * rule 5).
 *
 * Symlinks are followed like claude-code.js (see its isKindFollowingSymlink
 * docstring for the lstat-vs-stat reasoning) but CONTAINED to the project
 * root by realpath: a directory or candidate file that resolves outside the
 * root is never walked or read, and is surfaced as a broken (not fully
 * scanned) entry instead of silently skipped. Without containment a
 * committed symlink ("vendored -> ../../somewhere") would pull the invoking
 * machine's own files into the repo verdict, which is precisely the
 * wrong-thing claim project mode exists to prevent: this scan's verdict is
 * about the checkout, never about the machine around it. Directory symlink
 * loops are cut with a realpath visited-set rather than left to the node
 * cap, so a loop cannot eat the whole node budget before legitimate files
 * are reached.
 */

const MAX_DEPTH = 12;      // deep enough for any real monorepo layout; a
                           // deeper tree gets a broken entry, not silence
const MAX_NODES = 20_000;  // directory entries examined, not files yielded
const SKIP_DIRS = new Set(["node_modules", ".git"]);

// Committed transcripts are the same artifact class claude-code.js reads at
// home level, so the same bound applies: generous headroom over the largest
// real transcript this project has been tested against (818MB).
const MAX_BYTES = 2 * 1024 * 1024 * 1024;
const READ_TIMEOUT_MS = 60_000;

const ID = "project-artifacts";
const LABEL = "Project artifacts";

// Same shape as claude-code.js; duplicated per the one-file-per-source
// convention (each source stays auditable on its own).
function isKindFollowingSymlink(fullPath, dirent, checkFn) {
  if (checkFn(dirent)) return true;
  if (!dirent.isSymbolicLink()) return false;
  try { return checkFn(fs.statSync(fullPath)); } catch { return false; }
}
const isDirFollowingSymlink = (p, d) => isKindFollowingSymlink(p, d, (x) => x.isDirectory());
const isFileFollowingSymlink = (p, d) => isKindFollowingSymlink(p, d, (x) => x.isFile());

/**
 * Decide whether one regular file is a candidate, given its path segments
 * relative to the root (segs includes the basename; depth 0 means the file
 * sits directly in the root). Pure function, no filesystem access, so the
 * whole inclusion policy is testable in one place.
 */
function isCandidate(segs) {
  const name = segs[segs.length - 1];
  const parent = segs.length >= 2 ? segs[segs.length - 2] : null;
  const inClaudeDir = segs.slice(0, -1).includes(".claude");
  const inSpecstoryDir = segs.slice(0, -1).includes(".specstory");
  const inCursorRules = segs.slice(0, -1).some(
    (s, i) => s === ".cursor" && segs[i + 1] === "rules" && i + 1 < segs.length - 1
  );

  // (a) transcripts
  if (name.endsWith(".jsonl")) {
    if (inClaudeDir) return true;
    if (parent && parent.startsWith("-")) return true; // claude-projects slug shape
    if (/^rollout-.*\.jsonl$/.test(name)) return true; // Codex session naming
  }
  if (inSpecstoryDir) return true;

  // (b) configs, any depth
  if (parent === ".claude" && /^settings.*\.json$/.test(name)) return true;
  if (name === ".mcp.json") return true;
  if (inCursorRules) return true;
  if (name === ".cursorrules") return true;
  if (name === "CLAUDE.md" || name === "CLAUDE.local.md") return true;
  if (name === "AGENTS.md") return true;
  if (parent === ".gemini" && name === "settings.json") return true;
  if (parent === ".vscode" && name === "tasks.json") return true;

  // (c) root-level .env family only; see the header for why depth matters
  if (segs.length === 1 && /^\.env(\..+)?$/.test(name)) return true;

  return false;
}

/**
 * Same streaming reader as claude-code.js and agent-configs.js (see the
 * former for the timeout rationale: an open() on a retargeted symlink can
 * block forever, and destroying the stream is the only way out). Standalone
 * so both the disabled default export and every withRoot() instance share
 * one implementation.
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
    // secret; an honest "partial" beats a silent false negative.
    return { lines, status: lines.length > 0 ? "partial" : "failed", bytesRead };
  } finally {
    clearTimeout(timer);
    rl.close();
    stream.destroy();
  }
}

/**
 * Build a configured source instance for one project root. Returns a fresh
 * object satisfying the full { id, label, available, files, readLines }
 * contract, ready to be passed to scan({ sources: [...] }).
 *
 * label() deliberately does NOT embed the root path: source labels reach the
 * report, and an absolute path can carry a username or project name the rest
 * of the report is careful never to print (the same reasoning scan.js gives
 * for basenames in unreadableFiles).
 */
function withRoot(root = process.cwd()) {
  const ROOT = path.resolve(root);

  function available() {
    try { return fs.statSync(ROOT).isDirectory(); } catch { return false; }
  }

  /**
   * Iterative depth-first walk yielding { file, mtimeMs, sizeBytes, broken }
   * for every candidate. Truncation policy, restated from the header because
   * it is the load-bearing part: SKIP_DIRS vanish silently (expected on
   * every repo, not a truncation); a directory cut by MAX_DEPTH, an
   * unreadable directory, and a walk stopped by MAX_NODES each yield a
   * broken entry, so scan.js surfaces them in unreadableFiles instead of
   * folding the cut into a clean report.
   */
  function* files() {
    let nodesSeen = 0;
    const visitedDirs = new Set(); // realpaths, symlink-loop cut
    // The containment anchor: everything walked or read must resolve to
    // rootReal or below. If the root itself cannot be realpath'd the walk
    // still runs bounded, but containment cannot be enforced; that is the
    // caller's own unreadable-root situation, not an attacker-created one.
    let rootReal = null;
    try { rootReal = fs.realpathSync(ROOT); visitedDirs.add(rootReal); } catch { /* walk still bounded without it */ }
    const inRoot = (real) =>
      rootReal === null || real === rootReal || real.startsWith(rootReal + path.sep);

    const stack = [{ dir: ROOT, segs: [] }];
    while (stack.length > 0) {
      const { dir, segs } = stack.pop();

      let entries;
      try { entries = fs.readdirSync(dir, { withFileTypes: true }); }
      catch { yield { file: dir, broken: true }; continue; }

      for (const e of entries) {
        if (++nodesSeen > MAX_NODES) {
          // The walk is stopping with work left. Reported against the
          // directory being read because that is the most precise location
          // the files() contract can carry.
          yield { file: dir, broken: true };
          return;
        }
        const full = path.join(dir, e.name);
        const childSegs = segs.concat(e.name);

        if (isDirFollowingSymlink(full, e)) {
          if (SKIP_DIRS.has(e.name)) continue;
          if (childSegs.length >= MAX_DEPTH) { yield { file: full, broken: true }; continue; }
          // Every directory is deduped by realpath, not only symlinks: a
          // symlinked route and the real directory reached later would
          // otherwise both be walked, and one secret would be reported
          // twice under two paths.
          let real = null;
          try { real = fs.realpathSync(full); }
          catch {
            // A symlink whose target cannot be resolved is a reportable
            // failure; a plain directory failing realpath is unusual, and
            // the readdir above will surface it loudly if it is unreadable.
            if (e.isSymbolicLink()) { yield { file: full, broken: true }; continue; }
          }
          if (real !== null) {
            if (!inRoot(real)) {
              // A directory that resolves OUTSIDE the project root (a
              // committed symlink to the invoking machine's own tree) is
              // never walked: whatever lives there is not part of this
              // checkout, and pulling it in would make a repo verdict about
              // someone's home directory. Surfaced as broken, not skipped
              // silently, so the report says this subtree went unexamined.
              yield { file: full, broken: true };
              continue;
            }
            if (visitedDirs.has(real)) continue; // loop or duplicate route, already covered
            visitedDirs.add(real);
          }
          stack.push({ dir: full, segs: childSegs });
          continue;
        }

        if (!isFileFollowingSymlink(full, e)) {
          // A dangling symlink with a candidate name is exactly the entry
          // the broken convention exists for; any other non-file oddity is
          // out of scope, same as claude-code.js.
          if (e.isSymbolicLink() && isCandidate(childSegs)) yield { file: full, broken: true };
          continue;
        }

        if (!isCandidate(childSegs)) continue;
        if (e.isSymbolicLink()) {
          // Same containment as directories: a candidate-named symlink whose
          // target resolves outside the root is disclosed, never read. Only
          // targets inside the checkout are the checkout's content.
          let realf = null;
          try { realf = fs.realpathSync(full); }
          catch { yield { file: full, broken: true }; continue; }
          if (!inRoot(realf)) { yield { file: full, broken: true }; continue; }
        }
        let stat;
        try { stat = fs.statSync(full); }
        catch { yield { file: full, broken: true }; continue; }
        yield { file: full, mtimeMs: stat.mtimeMs, sizeBytes: stat.size, broken: false };
      }
    }
  }

  return { id: () => ID, label: () => LABEL, available, files, readLines };
}

// Default export: the registry-safe DISABLED form. index.js may register it
// like any other singleton; available() is unconditionally false, so the
// default home scan never includes it, and files() yielding nothing is a
// harmless backstop should anything iterate it anyway. A project scan only
// ever happens through withRoot().
module.exports = {
  id: () => ID,
  label: () => LABEL,
  available: () => false,
  files: function* () {},
  readLines,
  withRoot,
};
