"use strict";

const fs = require("fs");
const path = require("path");
const os = require("os");
const { PATTERNS, redact } = require("./patterns");

/**
 * Integrity checks for agent config directories.
 *
 * Every other module in residoo asks "is a secret leaking out of these
 * files?" This one asks the other half of the question the 2026 supply-chain
 * campaigns forced: "has something hostile been planted where my agent will
 * auto-execute it?" The campaigns planted persistence in exactly the
 * locations checked here — each check below cites its evidence:
 *
 * - Mini Shai-Hulud (Apr–May 2026, Sonar: "the first supply chain attack to
 *   persist through AI coding agent sessions"): SessionStart hook in
 *   .claude/settings.json + .vscode/tasks.json "runOn": "folderOpen".
 *   https://www.sonarsource.com/blog/your-secrets-are-leaking-to-ai-coding-agents/
 * - Miasma (June 2026, 73 Microsoft repos disabled): auto-exec configs
 *   planted IN CLONED REPOS — .claude/settings.json SessionStart hook,
 *   .gemini/settings.json hook, .cursor/rules/setup.mdc prompt injection,
 *   .vscode/tasks.json folderOpen task — so merely opening the repo in an
 *   AI tool detonated the harvester.
 *   https://thehackernews.com/2026/06/miasma-worm-hits-73-microsoft-github.html
 * - keyv/ChainDrop (Aug 2026, 400+ packages): dropped a script literally
 *   named setup.mjs into .claude/ (SHA1 686aa40d…) and .vscode/
 *   (f525d52c…) and wired hooks/tasks to run it.
 *   https://www.wiz.io/blog/keyv-and-cacheable-npm-supply-chain-attack
 * - TrapDoor (Phoenix Security, 2026): zero-width Unicode instructions
 *   hidden in CLAUDE.md / .cursorrules that made assistants exfiltrate
 *   local secrets — invisible in an editor, fully visible to the agent.
 *   https://phoenix.security/accelerating-supply-chain-attacks-npm-pypi-vsx-ai-enabled-2026/
 *
 * Design constraint that shapes every severity decision: legitimate hooks
 * exist. A user's own formatter hook must come out of this as a reviewable
 * "info" line, not an alarm — a tool that cries wolf on the user's own
 * config gets uninstalled, and then catches nothing. So EVERY hook is
 * reported (hooks execute automatically; the user should be able to vouch
 * for each one), but only commands matching a published campaign IOC or a
 * campaign-shaped behavior escalate to "warn".
 *
 * Read-only throughout. Nothing here modifies, quarantines, or deletes —
 * see CONTRIBUTING.md rule 3. Findings carry redacted previews only: a hook
 * command can itself embed a token (Lakera found live credentials in
 * settings.local.json in ~30 published npm packages), so command previews
 * are run through the same PATTERNS + redact() pipeline as scan findings.
 *
 * Returns { findings, filesChecked, scopeNote } — pure data, no printing;
 * the report layer renders. `filesChecked` lists every location examined
 * with an honest status ("checked" | "absent" | "unreadable" | "too-large")
 * so a renderer can never imply a file was verified when it wasn't. For the
 * name-only probes (loose scripts in .claude/, dropper filenames) "checked"
 * attests the NAME was checked against the published IOC names — arbitrary
 * script content is not analyzed, and every such file is also emitted as a
 * finding telling the user to review it, so nothing rides on the status
 * alone.
 */

// Configs are hand-written files measured in KB. The one campaign artifact
// with real bulk was the Miasma payload runner at 4.3MB — a "settings.json"
// at that size is not a settings file. Oversized configs are reported, not
// parsed: refusing to slurp an attacker-sized file into memory is also the
// robustness-safe choice.
const MAX_CONFIG_BYTES = 5 * 1024 * 1024;

// Mirrors stripControlChars in patterns.js (not exported there; adding an
// export would touch a shared file, which this change deliberately doesn't).
// Same rationale: C0 controls + DEL are where ANSI escapes live, and a hook
// command string is attacker-controllable text headed for a terminal.
function stripControlChars(s) { return s.replace(/[\x00-\x1f\x7f]/g, ""); }

// The same invisible code points scanZeroWidth flags, made visible as
// \u{XXXX} escapes. Re-emitting them raw would put TrapDoor's invisible
// carrier right back into the terminal this report protects — and into
// anything the user copy-pastes out of it to "inspect the command".
const INVISIBLES_RE = /[\u200b\u200c\u200d\u2060\ufeff\u{e0000}-\u{e007f}]/gu;
function escapeInvisibles(s) {
  return s.replace(INVISIBLES_RE, (ch) => "\\u{" + ch.codePointAt(0).toString(16).toUpperCase() + "}");
}

/**
 * A displayable, bounded preview of an attacker-controllable string from a
 * config file (a command, a matcher, an event name — anything that came out
 * of a parsed config). Control bytes stripped (terminal-injection
 * discipline), any embedded secret redacted (a hook command with
 * --token=sk-... must not put the token into this tool's own output),
 * invisible code points escaped to visible \u{XXXX} form, truncated by code
 * point (an astral character straddling a blind .slice() cut renders as a
 * broken glyph — same reasoning as redact() in patterns.js).
 */
function safePreview(command, maxCps = 160) {
  let s = stripControlChars(String(command));
  for (const rule of PATTERNS) {
    rule.re.lastIndex = 0;
    s = s.replace(rule.re, (m) => redact(m));
  }
  s = escapeInvisibles(s);
  const cps = Array.from(s);
  return cps.length > maxCps ? cps.slice(0, maxCps).join("") + "…" : s;
}

/**
 * High-suspicion hook-command signatures. Each one is tied to a published
 * campaign behavior, not guessed — see the module header for URLs. First
 * match wins; order is most-specific first.
 */
const HOOK_SUSPICION = [
  {
    id: "dropper-name",
    // The literal filename the Aug-2026 keyv/ChainDrop wave dropped into
    // .claude/ and .vscode/ (Wiz IOC list), and the artifact the Mini
    // Shai-Hulud/Miasma SessionStart hooks execute.
    re: /\bsetup\.mjs\b/i,
    reason: "references setup.mjs, the dropper filename the Aug-2026 keyv/ChainDrop wave planted in .claude/ and .vscode/ (Wiz IOC)",
  },
  {
    id: "curl-pipe-sh",
    // Bounded gap ([^|;&\n]{0,200}) instead of .* — keeps the regex
    // linear-time on adversarial input (see CONTRIBUTING.md on ReDoS) and
    // stops a curl in one shell statement matching a pipe in the next.
    re: /\b(?:curl|wget)\b[^|;&\n]{0,200}\|\s*(?:ba|z|da|fi)?sh\b/i,
    reason: "downloads from the network and pipes straight into a shell: a hook doing this re-fetches its payload on every session",
  },
  {
    id: "base64-decode",
    re: /\bbase64\b\s+(?:-d|-D|--decode)\b/,
    reason: "decodes base64 before executing: the obfuscation step the 2026 npm campaigns used to hide payloads from exactly this kind of review",
  },
  {
    id: "script-in-dot-dir",
    // node/bun/deno running a .js-family file that lives inside a
    // dot-directory (".claude/x.mjs", "~/.config/y/z.js"). The leading
    // class requires a real name character after the dot, so an ordinary
    // relative "./scripts/build.js" does NOT match. This one CAN hit a
    // user's own legitimately hand-rolled hook — the warn wording says
    // "confirm you wrote it", not "malware".
    re: /(?:^|[\s"'/=])\.[A-Za-z0-9_][A-Za-z0-9_.-]*\/[^\s"']*\.(?:mjs|cjs|js)\b/,
    requireRunner: /\b(?:node|bun|deno)\b/,
    reason: "runs a script that lives inside a dot-directory: the persistence shape of the Mini Shai-Hulud/Miasma SessionStart plants; confirm you wrote that script",
    // Claude Code's own hooks docs suggest keeping hook scripts at
    // ~/.claude/hooks/<script>.js — warning on the vendor-documented layout
    // (and failing --fail-on-find CI on it, every scan) is the cry-wolf →
    // --no-integrity spiral the module header warns about. A path anchored
    // at the user's home directory is that layout and rates info; a bare
    // repo-relative ".claude/x.mjs" — the literal campaign plant shape,
    // which resolves inside whatever repo the agent happens to run from —
    // stays warn. (setup.mjs never reaches here: dropper-name matches
    // first.)
    demoteIfHomeAnchored: true,
    reasonInfo: "runs a script from a dot-directory under your home directory: the vendor-documented hook layout; confirm you wrote that script",
  },
];

/**
 * Returns { reason, severity } for the first matching signature, or null.
 * `home` feeds the home-anchored demotion above; severity is "warn" unless
 * a signature explicitly demotes.
 */
function suspicionReason(command, home) {
  for (const sig of HOOK_SUSPICION) {
    sig.re.lastIndex = 0;
    if (sig.requireRunner) {
      sig.requireRunner.lastIndex = 0;
      if (!sig.requireRunner.test(command)) continue;
    }
    if (!sig.re.test(command)) continue;
    if (sig.demoteIfHomeAnchored && home) {
      // Strip every home-anchored occurrence ("~/.dir/x.js" or the literal
      // home path) and re-test: only a remaining bare-relative hit keeps
      // the warn.
      const esc = String(home).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      const anchored = new RegExp("(?:~|" + esc + ")/\\.[A-Za-z0-9_][A-Za-z0-9_.-]*/[^\\s\"']*\\.(?:mjs|cjs|js)\\b", "g");
      const bare = command.replace(anchored, "");
      sig.re.lastIndex = 0;
      if (!sig.re.test(bare)) return { reason: sig.reasonInfo, severity: "info" };
    }
    return { reason: sig.reason, severity: "warn" };
  }
  return null;
}

// ── zero-width / invisible Unicode (TrapDoor's technique) ─────────────────

/**
 * Scan text for characters that render as nothing but reach the agent as
 * content. Three tiers, because blanket-flagging would false-alarm on real
 * files:
 * - always-suspicious: U+200B, U+2060, the Unicode tag block U+E0000–E007F
 *   (tag characters have no legitimate use in a text file at all — they are
 *   TrapDoor's carrier), and U+FEFF anywhere but offset 0 (offset 0 is an
 *   ordinary byte-order mark).
 * - context-dependent: U+200C/U+200D between ASCII characters is invisible
 *   splicing (suspicious); the same characters adjacent to non-ASCII are
 *   how emoji sequences and joining scripts legitimately work, so those
 *   only rate an informational mention.
 * Hits are reported as U+XXXX hex names + line numbers only — never the
 * raw characters, which would put the invisible payload right back into
 * the terminal this report is trying to protect.
 */
function scanZeroWidth(text) {
  const cps = Array.from(text);
  const hits = [];
  let line = 1;
  for (let i = 0; i < cps.length; i++) {
    const cp = cps[i].codePointAt(0);
    if (cp === 0x0a) { line++; continue; }
    let suspicious = null;
    if (cp >= 0xe0000 && cp <= 0xe007f) suspicious = true;
    else if (cp === 0x200b || cp === 0x2060) suspicious = true;
    else if (cp === 0xfeff) suspicious = i === 0 ? null : true;
    else if (cp === 0x200c || cp === 0x200d) {
      const prev = i > 0 ? cps[i - 1].codePointAt(0) : 0;
      const next = i + 1 < cps.length ? cps[i + 1].codePointAt(0) : 0;
      suspicious = !(prev > 0x7f || next > 0x7f);
    }
    if (suspicious !== null) hits.push({ cp, line, suspicious });
  }
  return hits;
}

function summarizeZeroWidth(hits) {
  // Group by code point; show up to 5 line numbers per group so one laced
  // file can't flood the report.
  const byCp = new Map();
  for (const h of hits) {
    if (!byCp.has(h.cp)) byCp.set(h.cp, []);
    byCp.get(h.cp).push(h.line);
  }
  const parts = [];
  for (const [cp, lns] of byCp) {
    const name = "U+" + cp.toString(16).toUpperCase().padStart(4, "0");
    // ×N counts every hit; the line list is deduped ("lines 2, 2" for two
    // hits on one line reads like a bug).
    const uniq = [...new Set(lns)];
    const shown = uniq.slice(0, 5).join(", ") + (uniq.length > 5 ? ", …" : "");
    parts.push(`${name} ×${lns.length} (line${uniq.length === 1 ? "" : "s"} ${shown})`);
  }
  return parts.join("; ");
}

// ── tolerant config reading ───────────────────────────────────────────────

function readSmallFile(file) {
  let stat;
  try { stat = fs.statSync(file); }
  catch (err) {
    // ENOENT/ENOTDIR is genuine absence. Anything else (EACCES on a parent,
    // ELOOP) means something may well BE at the path but couldn't be
    // examined — calling that "absent" would be a false all-clear on an
    // unverified auto-execution location.
    return err && (err.code === "ENOENT" || err.code === "ENOTDIR")
      ? { status: "absent" }
      : { status: "unreadable" };
  }
  if (!stat.isFile()) return { status: "absent" };
  if (stat.size > MAX_CONFIG_BYTES) return { status: "too-large" };
  try { return { status: "ok", text: fs.readFileSync(file, "utf-8") }; }
  catch { return { status: "unreadable" }; }
}

/**
 * VS Code's tasks.json is JSONC — comments and trailing commas are valid
 * there and common in real files. Plain JSON.parse would reject legitimate
 * configs and this module would then cry "unparseable" at innocent users.
 * A single character-walk strip (string-aware, so "// not a comment" inside
 * a string survives) covers what real tasks.json files actually contain.
 */
function stripJsonc(text) {
  let out = "";
  let inStr = false, inLine = false, inBlock = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i], next = text[i + 1];
    if (inLine) { if (ch === "\n") { inLine = false; out += ch; } continue; }
    if (inBlock) { if (ch === "*" && next === "/") { inBlock = false; i++; } continue; }
    if (inStr) {
      out += ch;
      if (ch === "\\" && next !== undefined) { out += next; i++; }
      else if (ch === '"') inStr = false;
      continue;
    }
    if (ch === '"') { inStr = true; out += ch; continue; }
    if (ch === "/" && next === "/") { inLine = true; continue; }
    if (ch === "/" && next === "*") { inBlock = true; i++; continue; }
    out += ch;
  }
  // Trailing commas go in a second string-aware pass — a global regex here
  // also rewrote ",}"/",]" sequences INSIDE string values, corrupting task
  // labels/commands later shown in previews. A structural comma is buffered
  // with any following whitespace and dropped only when the next significant
  // character closes the container; single pass, no lookahead rescanning.
  let res = "";
  let inStr2 = false;
  let pending = "";
  for (let i = 0; i < out.length; i++) {
    const ch = out[i];
    if (inStr2) {
      res += ch;
      if (ch === "\\" && i + 1 < out.length) { res += out[i + 1]; i++; }
      else if (ch === '"') inStr2 = false;
      continue;
    }
    if (pending) {
      if (ch === " " || ch === "\t" || ch === "\n" || ch === "\r") { pending += ch; continue; }
      if (ch === "]" || ch === "}") pending = pending.slice(1); // trailing: drop the comma, keep its whitespace
      res += pending;
      pending = "";
    }
    if (ch === '"') { inStr2 = true; res += ch; continue; }
    if (ch === ",") { pending = ","; continue; }
    res += ch;
  }
  return res + pending;
}

// Cap for the generic JSON walks below. A hand-written config holds dozens
// of nodes; JSON.parse happily survives 50k-deep nesting, and a recursive
// walk over it blows the call stack — which would kill the whole run AFTER
// the secrets were found but BEFORE anything printed. An attacker who can
// plant configs (this feature's threat model) must not be able to suppress
// the report that way, so the walks are iterative and a structure over the
// cap degrades to a loud "unwalkable" warning, never a crash or a silent
// skip.
const MAX_WALK_NODES = 10_000;

/**
 * Pull every hook command out of a parsed settings object without
 * hard-coding one vendor's exact nesting. Claude Code uses
 * hooks.<Event>[].hooks[].command (with `matcher` on the PARENT of the
 * hooks array, so the nearest ancestor's matcher is carried down); Gemini
 * CLI's settings.json is event-keyed the same way but has drifted before.
 * Walking the "hooks" subtree for string-valued "command" properties means
 * schema drift degrades to a hook tagged "unknown event" — still reported —
 * instead of a silent miss, which for an integrity checker is the failure
 * mode that matters. A `command` that exists but isn't a string lands in
 * `unrecognized` for the same reason: not extracted is fine, not reported
 * is not.
 *
 * Returns { hooks, unrecognized, hadHooksKey, truncated, sawLeaf } —
 * `sawLeaf` says whether ANY primitive value exists under hooks, so the
 * caller can tell a legitimately empty `{"SessionStart":[]}` block from a
 * populated shape the walk couldn't decode.
 */
function extractHooks(parsed) {
  const hooks = [];
  const unrecognized = [];
  const hooksRoot = parsed && typeof parsed === "object" ? parsed.hooks : undefined;
  if (!hooksRoot || typeof hooksRoot !== "object") {
    return { hooks, unrecognized, hadHooksKey: hooksRoot !== undefined, truncated: false, sawLeaf: false };
  }
  let truncated = false;
  let sawLeaf = false;
  let visited = 0;
  const stack = [];
  for (const [event, v] of Object.entries(hooksRoot)) stack.push({ node: v, event, matcher: null });
  while (stack.length > 0) {
    if (++visited > MAX_WALK_NODES) { truncated = true; break; }
    const { node, event, matcher } = stack.pop();
    if (Array.isArray(node)) {
      for (const v of node) stack.push({ node: v, event, matcher });
      continue;
    }
    if (!node || typeof node !== "object") {
      if (node !== null && node !== undefined) sawLeaf = true;
      continue;
    }
    const m = typeof node.matcher === "string" ? node.matcher : matcher;
    if (typeof node.command === "string") {
      sawLeaf = true;
      hooks.push({ event, matcher: m, command: node.command });
    } else if ("command" in node) {
      unrecognized.push({ event });
    }
    for (const [k, v] of Object.entries(node)) {
      if (k === "command") continue;
      stack.push({ node: v, event, matcher: m });
    }
  }
  return { hooks, unrecognized, hadHooksKey: true, truncated, sawLeaf };
}

// ── the checker ───────────────────────────────────────────────────────────

/**
 * `home` and `cwd` are overridable for tests only (a synthetic planted HOME
 * beats mutating process.env mid-process); production callers pass nothing,
 * except the CLI's --project mode, which pins both anchors to the project
 * root AND sets `projectMode: true`. The flag exists because two behaviors
 * must change when the anchors stop meaning "this user's machine":
 *
 * - GEMINI_CLI_HOME is ignored. It is this MACHINE's Gemini root override;
 *   honoring it in a project scan would pull a machine-level settings file
 *   into a verdict that claims to be about the checkout only, and could
 *   fail CI on a clean repo because of the runner's (or a developer's) own
 *   environment.
 * - The home-anchored hook demotion (see HOOK_SUSPICION) is suppressed. The
 *   demotion exists to avoid crying wolf on the user's own standing config;
 *   a hook inside a COMMITTED repo config is not the user's standing config,
 *   and demoting it there would hand a hostile repo a warn-tier bypass.
 */
function checkIntegrity({ home = os.homedir(), cwd = process.cwd(), projectMode = false } = {}) {
  const findings = [];
  const filesChecked = [];
  // Home checks and project checks can name the same file (running residoo
  // from inside ~ is legal); resolve-and-dedupe keeps each file to one
  // verdict.
  const seen = new Set();

  // Findings show "~/..." or "./..." — precise enough to act on, without
  // printing an absolute path that carries the username (the same reasoning
  // scan.js gives for reporting basenames). cwd is tried first so project
  // files inside the home directory render as "./..." not a long "~/...".
  const rHome = path.resolve(home), rCwd = path.resolve(cwd);
  const display = (p) => {
    const r = path.resolve(p);
    let d;
    if (r === rCwd || r.startsWith(rCwd + path.sep)) d = "." + r.slice(rCwd.length);
    else if (r === rHome || r.startsWith(rHome + path.sep)) d = "~" + r.slice(rHome.length);
    else d = path.basename(r);
    // File names come out of readdirSync on attacker-writable directories —
    // the same terminal-injection discipline as command previews: control
    // bytes stripped, invisible code points made visible (a zero-width
    // filename would otherwise render as nothing at all).
    return escapeInvisibles(stripControlChars(d));
  };

  const mark = (file, status) => { filesChecked.push({ file: display(file), status }); };
  const add = (severity, kind, file, detail) => { findings.push({ severity, kind, file: display(file), detail }); };

  // A config that exists in an auto-execution location but can't be read or
  // parsed is UNVERIFIED, not clean — reporting it is CONTRIBUTING.md rule 5
  // applied to integrity. Returns the text on success, null otherwise.
  const readOrReport = (file) => {
    const r = path.resolve(file);
    if (seen.has(r)) return null;
    seen.add(r);
    const res = readSmallFile(file);
    mark(file, res.status === "ok" ? "checked" : res.status);
    if (res.status === "unreadable") {
      add("warn", "unreadable-config", file, "exists in an auto-execution location but could not be read; its contents are unverified, not clean");
    } else if (res.status === "too-large") {
      add("warn", "oversized-config", file, `larger than ${MAX_CONFIG_BYTES / 1024 / 1024}MB, far beyond any hand-written config (the Miasma payload runner was 4.3MB); not parsed, review it directly`);
    }
    return res.status === "ok" ? res.text : null;
  };

  // ---- 1. hooks in agent settings files ----------------------------------
  // Home-level: the user's own standing config. Project-level (cwd): the
  // exact files Miasma planted in cloned repos — a repo-local
  // .claude/settings.json the user never wrote is the campaign's signature.
  // GEMINI_CLI_HOME is Gemini CLI's own documented root override (the CLI
  // creates `.gemini` INSIDE it), the same resolution agent-configs.js and
  // gemini-cli.js use. Hard-coding ~/.gemini here made the two modules
  // disagree about the same file within one run: agent-configs would find a
  // secret in the real settings file while integrity called that location
  // absent and missed a planted hook in it. In project mode the override is
  // a MACHINE-level fact and is deliberately ignored: the anchors point at
  // the checkout, and a project verdict must never be pierced by the
  // invoking environment (see the function docstring).
  const geminiHome = !projectMode && process.env.GEMINI_CLI_HOME
    ? path.join(process.env.GEMINI_CLI_HOME, ".gemini")
    : path.join(home, ".gemini");
  // Feeds the home-anchored demotion in suspicionReason: null disables it,
  // which is the correct posture when `home` is a project root rather than
  // anyone's home directory.
  const demotionHome = projectMode ? null : home;
  const hookFiles = [
    path.join(home, ".claude", "settings.json"),
    path.join(home, ".claude", "settings.local.json"),
    path.join(geminiHome, "settings.json"),
    path.join(cwd, ".claude", "settings.json"),
    path.join(cwd, ".claude", "settings.local.json"),
    path.join(cwd, ".gemini", "settings.json"),
  ];

  for (const file of hookFiles) {
    const text = readOrReport(file);
    if (text === null) continue;

    let parsed;
    try { parsed = JSON.parse(text); } catch {
      add("warn", "unparseable-config", file, "exists in an auto-execution location but is not valid JSON; the agent's own loader would also choke on it, so corruption or tampering is worth a look; raw text was signature-checked instead");
      // The parse failing must not mean the campaign signatures go
      // unchecked — grep the raw text for the same shapes.
      const hit = suspicionReason(text, demotionHome);
      if (hit) add(hit.severity, "hook", file, `suspicious signature in raw text: ${hit.reason}`);
      continue;
    }

    const { hooks, unrecognized, hadHooksKey, truncated, sawLeaf } = extractHooks(parsed);
    if (truncated) {
      // No hand-written config is 10k nodes deep/wide — this shape exists
      // to exhaust a walker. The hooks in it are unverified, said loudly;
      // the raw text still gets signature-checked below.
      add("warn", "unwalkable-config", file, `hooks section exceeds ${MAX_WALK_NODES} nodes, far beyond any hand-written config; its hooks are unverified, not clean, review the file directly`);
      const hit = suspicionReason(text, demotionHome);
      if (hit) add(hit.severity, "hook", file, `suspicious signature in raw text: ${hit.reason}`);
    }
    for (const u of unrecognized) {
      // A `command` that isn't a string (e.g. ["node", "x.js"]) is not
      // extracted or signature-checked — schema drift must degrade to
      // still-reported, never a silent miss.
      add("info", "hook-unrecognized", file, `${u.event ? safePreview(u.event, 40) : "unknown event"} hook entry whose "command" is not a string: not extracted or signature-checked; review it manually`);
    }
    if (!truncated && hadHooksKey && hooks.length === 0 && unrecognized.length === 0 && sawLeaf) {
      // A populated hooks block this walker couldn't pull a command out of
      // is a coverage gap, and coverage gaps get said out loud. sawLeaf
      // keeps a legitimately empty {"SessionStart": []} block from tripping
      // this.
      add("info", "hook-unrecognized", file, "has a hooks section whose shape this check doesn't recognize: no commands extracted; review it manually");
      continue;
    }
    for (const h of hooks) {
      const where = `${h.event ? safePreview(h.event, 40) : "unknown event"}${h.matcher ? ` (matcher: ${safePreview(h.matcher, 40)})` : ""}`;
      const hit = suspicionReason(h.command, demotionHome);
      if (hit) {
        add(hit.severity, "hook", file, `${where} hook ${hit.reason}: "${safePreview(h.command)}"`);
      } else {
        add("info", "hook", file, `${where} hook runs automatically: "${safePreview(h.command)}}"; confirm you added this one`);
      }
    }
  }

  // ---- 2. dropper files in .claude / .vscode -----------------------------
  // Only setup.mjs gets the "known campaign artifact name" wording — it is
  // the one filename actually published in the Wiz IOC list. Any other
  // loose script at the top of an agent dot-directory is merely "a script
  // sitting where hooks execute things from"; that's a review item, not an
  // accusation.
  const scriptDirs = [path.join(home, ".claude"), path.join(cwd, ".claude")];
  for (const dir of scriptDirs) {
    const rDir = path.resolve(dir) + "\0scripts"; // dedupe key distinct from file reads
    if (seen.has(rDir)) continue;
    seen.add(rDir);
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); }
    catch (err) {
      // Same absent-vs-unreadable split as readSmallFile: a directory that
      // exists but can't be listed hides whatever is in it.
      if (!(err && (err.code === "ENOENT" || err.code === "ENOTDIR"))) {
        mark(dir, "unreadable");
        add("warn", "unreadable-config", dir, "directory exists but could not be listed; any loose scripts in it are unverified, not clean");
      }
      continue;
    }
    for (const e of entries) {
      if (!e.isFile() || !/\.(?:mjs|cjs|js)$/i.test(e.name)) continue;
      const file = path.join(dir, e.name);
      // "checked" here = the NAME was checked against the IOC list; the
      // finding below always accompanies it (see the module header).
      mark(file, "checked");
      if (/^setup\.mjs$/i.test(e.name)) {
        add("warn", "dropper-name", file, "matches the exact dropper filename the Aug-2026 keyv/ChainDrop wave planted in .claude/ (Wiz IOC); if you did not create this file, do not run the agent from here until you've read it");
      } else {
        add("info", "loose-script", file, "script at the top level of an agent config directory, an auto-execution-adjacent location; review it");
      }
    }
  }
  {
    // .vscode/setup.mjs carries its own Wiz IOC hash (f525d52c…); checked by
    // exact name, not a directory sweep — .vscode legitimately holds no
    // loose scripts to enumerate, only this planted one.
    const file = path.join(cwd, ".vscode", "setup.mjs");
    if (!seen.has(path.resolve(file))) {
      seen.add(path.resolve(file));
      let isFile = false, statFailed = false;
      try { isFile = fs.statSync(file).isFile(); }
      catch (err) { statFailed = !(err && (err.code === "ENOENT" || err.code === "ENOTDIR")); }
      // Absent gets recorded too — filesChecked must read the same way for
      // every candidate location, or a renderer summarizing it lies by
      // omission about what this probe covered. A stat failure that is NOT
      // absence (EACCES, ELOOP) is unverified, not clean.
      mark(file, isFile ? "checked" : statFailed ? "unreadable" : "absent");
      if (statFailed) {
        add("warn", "unreadable-config", file, "location could not be examined (stat failed): unverified, not clean");
      } else if (isFile) {
        add("warn", "dropper-name", file, "matches the exact dropper filename the Aug-2026 keyv/ChainDrop wave planted in .vscode/ (Wiz IOC); if you did not create this file, review it before opening this folder in VS Code");
      }
    }
  }

  // ---- 3. zero-width Unicode in agent-instruction files ------------------
  const zwFiles = [
    path.join(home, ".claude", "CLAUDE.md"),
    path.join(cwd, "CLAUDE.md"),
    path.join(cwd, ".cursorrules"),
  ];
  const zwCheck = (file, text) => {
    const hits = scanZeroWidth(text);
    if (hits.length === 0) return;
    const bad = hits.filter((h) => h.suspicious);
    const joiners = hits.filter((h) => !h.suspicious);
    if (bad.length > 0) {
      add("warn", "zero-width", file, `${bad.length} invisible character${bad.length === 1 ? "" : "s"}: ${summarizeZeroWidth(bad)} : zero-width Unicode carried hidden agent instructions in the TrapDoor campaign; inspect with a hex viewer before trusting this file`);
    }
    if (joiners.length > 0) {
      add("info", "zero-width", file, `${summarizeZeroWidth(joiners)} adjacent to non-ASCII text: usually legitimate emoji/script joiners; listed so the count above can't quietly absorb them`);
    }
  };
  for (const file of zwFiles) {
    const text = readOrReport(file);
    if (text !== null) zwCheck(file, text);
  }

  // ---- 4. project-level auto-run surfaces (CWD only) ---------------------
  // .cursor/rules/* — every file here is loaded as agent instructions on
  // its own; Miasma's plant was named setup.mdc specifically.
  {
    const rulesDir = path.join(cwd, ".cursor", "rules");
    let entries = null;
    try { entries = fs.readdirSync(rulesDir, { withFileTypes: true }); }
    catch (err) {
      if (!(err && (err.code === "ENOENT" || err.code === "ENOTDIR"))) {
        mark(rulesDir, "unreadable");
        add("warn", "unreadable-config", rulesDir, "rules directory exists but could not be listed; its contents are unverified, not clean");
      }
    }
    if (entries) {
      for (const e of entries) {
        if (!e.isFile()) continue;
        const file = path.join(rulesDir, e.name);
        if (seen.has(path.resolve(file))) continue;
        // readOrReport owns the status/warn accounting: a rules file that
        // can't be read must come out "unreadable" + warn — never "checked"
        // with the zero-width scan silently skipped, which would let
        // filesChecked lie about verification depth.
        const text = readOrReport(file);
        if (/^setup\.mdc$/i.test(e.name)) {
          add("warn", "dropper-name", file, "matches the rules filename Miasma planted (.cursor/rules/setup.mdc) to prompt-inject Cursor on repo open; confirm you created it");
        } else {
          add("info", "cursor-rule", file, "Cursor loads rules files as agent instructions automatically; confirm you added this one");
        }
        if (text !== null) zwCheck(file, text);
      }
    }
  }

  // .vscode/tasks.json "runOn": "folderOpen" — code that executes on merely
  // opening the folder; the Mini Shai-Hulud and Miasma persistence task.
  {
    const file = path.join(cwd, ".vscode", "tasks.json");
    const text = readOrReport(file);
    if (text !== null) {
      let parsed = null;
      try { parsed = JSON.parse(stripJsonc(text)); } catch {
        add("warn", "unparseable-config", file, "not valid JSON even after comment/trailing-comma stripping: unverified, not clean; raw text was signature-checked instead");
        if (/"runOn"\s*:\s*"folderOpen"/.test(text)) {
          add("warn", "autorun-task", file, 'raw text contains "runOn": "folderOpen", a task that executes on folder open (Mini Shai-Hulud/Miasma persistence); review it');
        }
      }
      if (parsed) {
        // Walk generically rather than assuming tasks[] — a folderOpen
        // buried under a nonstandard nesting still executes. Iterative with
        // the same node cap as extractHooks: a stack-overflow crash here
        // would suppress the whole report (see MAX_WALK_NODES).
        let visited = 0, truncated = false;
        const stack = [parsed];
        while (stack.length > 0) {
          if (++visited > MAX_WALK_NODES) { truncated = true; break; }
          const node = stack.pop();
          if (Array.isArray(node)) { for (const v of node) stack.push(v); continue; }
          if (!node || typeof node !== "object") continue;
          if (node.runOptions && node.runOptions.runOn === "folderOpen") {
            const what = node.label || node.command || node.script || "(unnamed task)";
            add("warn", "autorun-task", file, `task "${safePreview(what, 60)}" runs on folder open ("runOn": "folderOpen"), the Mini Shai-Hulud/Miasma persistence mechanism; confirm you added it`);
          }
          for (const v of Object.values(node)) stack.push(v);
        }
        if (truncated) {
          add("warn", "unwalkable-config", file, `structure exceeds ${MAX_WALK_NODES} nodes, far beyond any hand-written tasks.json; auto-run tasks in it are unverified, not clean, review the file directly`);
          if (/"runOn"\s*:\s*"folderOpen"/.test(text)) {
            add("warn", "autorun-task", file, 'raw text contains "runOn": "folderOpen", a task that executes on folder open (Mini Shai-Hulud/Miasma persistence); review it');
          }
        }
      }
    }
  }

  // ---- 5. credential-vault file permissions (HOME only, POSIX only) ------
  // GitGuardian's "State of Secrets Sprawl 2026" (blog.gitguardian.com,
  // published 2026-03-17) found 24,008 unique secrets in MCP-related config
  // files on public GitHub, 8.8% of them still live -- these files
  // routinely hold real, working credentials. This does not scan their
  // CONTENT: the files below are the exact "credential VAULTS ... deliberately
  // NOT read" set from agent-configs.js's own header comment, files whose
  // whole documented job is holding the user's own keys/tokens -- reporting
  // their content re-reports what the user put there on purpose. What's
  // checked instead is narrower and complementary: whether the file's own OS
  // permission bits leak that live credential to every other account on the
  // machine. Anthropic's own docs (code.claude.com/docs/en/authentication,
  // "Credential management", fetched 2026-09-04) state Claude Code writes
  // .credentials.json with file mode 0600 on Linux and as the macOS
  // Keychain-write-failure fallback, and that Windows inherits its user
  // profile directory's own access controls. Kiro's own security guidance
  // separately recommends "chmod 600" on its global mcp.json -- the
  // vendor's own admission it holds secrets (already cited in
  // agent-configs.js). Nothing here disputes that these tools do the right
  // thing by default; the point is drift AFTER that -- a WSL DrvFs mount, a
  // naive backup restore, or a shared-volume container mount can each
  // silently widen a file's mode without the tool that wrote it ever
  // knowing, the same way SSH itself checks id_rsa's permissions rather
  // than trusting whoever created it. Windows is skipped entirely, not
  // approximated: Node's fs.Stats.mode on Windows does not reflect NTFS
  // ACLs, so a POSIX-style bit check there would be meaningless rather than
  // merely imprecise. Project mode is skipped too -- none of these are ever
  // project-scoped files by any vendor's own design, so there is no
  // project-relative equivalent to check.
  if (!projectMode && process.platform !== "win32") {
    const geminiDir = process.env.GEMINI_CLI_HOME
      ? path.join(process.env.GEMINI_CLI_HOME, ".gemini")
      : path.join(home, ".gemini");
    const credentialVaultFiles = [
      {
        file: path.join(process.env.CLAUDE_CONFIG_DIR || path.join(home, ".claude"), ".credentials.json"),
        note: "Claude Code's OAuth login (code.claude.com/docs/en/authentication documents file mode 0600)",
      },
      {
        file: path.join(process.env.CODEX_HOME || path.join(home, ".codex"), "auth.json"),
        note: "Codex CLI's own auth store",
      },
      { file: path.join(geminiDir, "oauth_creds.json"), note: "Gemini CLI's own OAuth store" },
      { file: path.join(geminiDir, ".env"), note: "Gemini CLI's own credential env file" },
      {
        file: path.join(home, ".kiro", "settings", "mcp.json"),
        note: "Kiro's own security guidance recommends chmod 600 on this file",
      },
    ];
    for (const { file, note } of credentialVaultFiles) {
      const r = path.resolve(file);
      if (seen.has(r)) continue;
      seen.add(r);
      let stat;
      try { stat = fs.statSync(file); }
      catch (err) {
        mark(file, err && err.code === "ENOENT" ? "absent" : "unreadable");
        if (!(err && err.code === "ENOENT")) {
          add("warn", "unreadable-config", file, "credential file exists but its permissions could not be checked (stat failed): unverified, not clean");
        }
        continue;
      }
      mark(file, "checked");
      const openBits = stat.mode & 0o077;
      if (openBits !== 0) {
        const octal = (stat.mode & 0o777).toString(8).padStart(3, "0");
        const shown = display(file);
        add("warn", "insecure-credential-permissions", file,
          `${note}; current mode ${octal} grants group and/or other accounts on this machine access to a live credential. Fix: chmod 600 "${shown}"`);
      }
    }
  }

  return {
    findings,
    filesChecked,
    // Stated because it is a real limit, not a disclaimer: nothing here
    // walks other checkouts, and a clean run says nothing about them.
    scopeNote: "Project-level checks (CLAUDE.md, .cursorrules, .cursor/, .vscode/, repo-local .claude/ and .gemini/) cover the current working directory only.",
  };
}

module.exports = { checkIntegrity };
