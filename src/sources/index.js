"use strict";

/**
 * Registry of scan sources. Each source is a small adapter exposing
 * { id, label, available, files, readLines } — see claude-code.js for the
 * reference implementation and CONTRIBUTING.md for how to add one.
 *
 * All but one of these read TRANSCRIPT stores — the session histories agents
 * write as a side effect of working. The exception is agent-configs.js, which
 * reads agent CONFIG files (settings, MCP server configs, memory files)
 * through the identical contract: configs are where users deliberately put
 * env blocks and where approved-command caches accumulate tokens, so they
 * leak by a different mechanism than transcripts but are scanned the same
 * way. The distinction matters for scope reasoning — a transcript source
 * covers what an agent SAW, the config source covers what an agent was
 * CONFIGURED with — and each file's header states which it is.
 *
 * TRUST TIERS — read this before treating every row below the same way.
 * Each source file states its own tier plainly in its header docstring;
 * this is a summary, not a substitute for reading one before relying on it.
 *
 *   - REAL-INSTALL-VERIFIED: the adapter was run against an actual,
 *     populated installation of the tool and confirmed to find real
 *     content. Currently Claude Code, plus agent-configs.js's Claude-family
 *     paths (its non-Claude paths sit in the tier below — that file's
 *     header tracks verification per path, not per file).
 *   - MULTI-SOURCE-CORROBORATED-BUT-UNVERIFIED: the path/schema is backed by
 *     2+ independent, credible sources (official docs, the tool's own
 *     shipped source code, a real community tool that reads the same files
 *     for a living, or a real user's own reported install) but was NOT
 *     checked against a real install of the tool on any machine this project
 *     was built on. This is the tier every source below Cursor is in. A
 *     scanner that silently checks the wrong path and reports "all clear" is
 *     worse than not supporting the tool, so every adapter in this tier is
 *     built to fail loudly (`broken: true`, `status: "failed"`) rather than
 *     silently — but the PATH ITSELF could still be stale or wrong in a way
 *     only a real install can catch. If you have one of these tools
 *     installed, running `residoo scan` and reporting back whether
 *     `filesScanned` looks right for what you know is on disk is the single
 *     most useful thing you can do.
 *
 * Deliberately NOT included here, investigated and skipped rather than
 * guessed at (see each PR/commit description for the full reasoning):
 *   - Plandex — confirmed, by reading its actual CLI source, to be
 *     client-server with no local transcript content on disk at all (only
 *     auth tokens and a project-id pointer live locally); nothing to scan.
 *   - CodeGPT — an account/cloud-based product; its own docs describe
 *     conversation retention in plan-tier/account terms, and no local
 *     chat-history file (official or third-party) was ever found.
 *   - Augment Code — only local config/rules files were confirmed; no
 *     evidence anywhere (official or third-party) of local chat-transcript
 *     storage, consistent with its server-side "Context Engine" design.
 *   - Tabby, Tabnine, Zencoder, Tongyi Lingma, Berd — researched, but no
 *     source reached this project's 2-independent-source bar for a
 *     transcript-content path in the time available. Worth a follow-up PR.
 *   - Replit Agent — confirmed cloud-only (server-side storage, nothing
 *     local to scan).
 */
const claudeCode = require("./claude-code");
// Not a transcript store — agent config/state files (see module docstring
// above and that file's own header for the per-path verification trail).
const agentConfigs = require("./agent-configs");
const cursor = require("./cursor");

// The rest of these are grouped the way they were researched/built, purely
// to keep this list navigable — the grouping carries no behavioral meaning,
// every entry goes through the identical { id, label, available, files,
// readLines } contract. All are MULTI-SOURCE-CORROBORATED-BUT-UNVERIFIED —
// see each file's own header for exactly what was and wasn't checked, and
// note two partial exceptions worth naming here rather than only in the
// file: jetbrains-junie.js and jetbrains-ai-assistant.js had their directory
// *layout* (not their chat-content schema) confirmed against a real, if
// long-dormant, JetBrains install found on this project's own build machine
// — see those two files for what that does and doesn't cover. qodo-gen.js
// is flagged in its own header as the single weakest-verified source here
// (one vendor's own docs, restated twice, plus one third-party artifact that
// likely documents a different Qodo product).
const codexCli = require("./codex-cli");
const opencode = require("./opencode");

const aider = require("./aider");

const cline = require("./cline");
const rooCode = require("./roo-code");
const kiloCode = require("./kilo-code");

const windsurf = require("./windsurf");

const pearai = require("./pearai");
const trae = require("./trae");
const voidEditor = require("./void");

const geminiCli = require("./gemini-cli");
const qwenCode = require("./qwen-code");

const continueDev = require("./continue");

const openInterpreter = require("./open-interpreter");
const goose = require("./goose");

const copilotChat = require("./copilot-chat");
const copilotCli = require("./copilot-cli");

const llm = require("./llm");

const codebuff = require("./codebuff");
const mentat = require("./mentat");
const hermes = require("./hermes");
const openclaw = require("./openclaw");
// Plandex investigated and deliberately not included — see module docstring.

const warp = require("./warp");
const crush = require("./crush");
const grokCli = require("./grok-cli");
const kiroCli = require("./kiro-cli");
const kiroIde = require("./kiro-ide");

const zed = require("./zed");

const jetbrainsJunie = require("./jetbrains-junie");
const jetbrainsAiAssistant = require("./jetbrains-ai-assistant");

const cody = require("./cody");
const amazonQ = require("./amazon-q");
const qodoGen = require("./qodo-gen");
// Augment Code and CodeGPT investigated and deliberately not included —
// see module docstring.

const openhands = require("./openhands");
const factoryDroid = require("./factory-droid");
const devinCli = require("./devin-cli");
const piAgent = require("./pi-agent");
const antigravityCli = require("./antigravity-cli");
const kimiCode = require("./kimi-code");
const fx = require("./fx");

const atlassianRovoDev = require("./atlassian-rovo-dev");
// Sourcegraph Amp investigated and deliberately not included: its own docs
// describe threads as syncing to ampcode.com "across devices," and no local
// cache/offline copy of thread content is documented anywhere found — the
// same cloud-only reasoning as Augment Code/CodeGPT above, not missed.

const ALL_SOURCES = [
  claudeCode,
  agentConfigs,
  cursor,
  codexCli,
  opencode,
  aider,
  cline,
  rooCode,
  kiloCode,
  windsurf,
  pearai,
  trae,
  voidEditor,
  geminiCli,
  qwenCode,
  continueDev,
  openInterpreter,
  goose,
  copilotChat,
  copilotCli,
  llm,
  codebuff,
  mentat,
  hermes,
  openclaw,
  warp,
  crush,
  grokCli,
  kiroCli,
  kiroIde,
  zed,
  jetbrainsJunie,
  jetbrainsAiAssistant,
  cody,
  amazonQ,
  qodoGen,
  openhands,
  factoryDroid,
  devinCli,
  piAgent,
  antigravityCli,
  kimiCode,
  fx,
  atlassianRovoDev,
];

function availableSources() {
  return ALL_SOURCES.filter((s) => s.available());
}

module.exports = { ALL_SOURCES, availableSources };
