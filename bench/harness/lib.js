"use strict";

/**
 * Shared helpers for the benchmark harness. Zero dependencies.
 *
 * Fairness rules encoded here (see also README.md in this directory):
 *
 * 1. Every scanner runs against the corpus FIXTURE, never the real machine.
 *    pinnedEnv() builds the child environment from scratch: HOME and every
 *    home-resolving variable the benchmarked tools honor point INTO the
 *    fixture, and nothing from the parent environment leaks through except
 *    an explicit allow-list (PATH, TMPDIR, locale). In particular no token,
 *    key, or credential variable from the operator's shell can reach a
 *    scanner under test.
 *
 * 2. All proxy variables point at the local refuse-and-log trap, so any
 *    scan-time connection attempt that honors proxy env is observed. The
 *    lsof poller in egress.js catches attempts that bypass proxy env.
 *
 * 3. Install-time vs scan-time: nothing in this file or run.js performs
 *    package installs. Tools are installed once, beforehand, into
 *    bench/tools/ (that fetch is normal and NOT scored). A scan run only
 *    executes the already-installed tool. Only scan-time egress is scored.
 */

const fs = require("fs");
const os = require("os");
const path = require("path");

const BENCH_ROOT = path.resolve(__dirname, "..");
const REPO_ROOT = path.resolve(BENCH_ROOT, "..");
const TOOLS_DIR = path.join(BENCH_ROOT, "tools");
const RESULTS_DIR = path.join(BENCH_ROOT, "results");
const RAW_DIR = path.join(RESULTS_DIR, "raw");

/** Variables copied from the parent environment. Everything else is dropped. */
const ENV_ALLOWLIST = ["PATH", "TMPDIR", "LANG", "LC_ALL", "SHELL"];

/**
 * Build the fully pinned environment for one scanner invocation.
 *
 * fixtureHome must be the fixture's home directory (contains .claude/ etc).
 * trapPort is the local refuse-and-log proxy listener's port.
 * scratchDir, when given, receives XDG cache/state: those are WRITE
 * locations for tools (ggshield writes an update-check cache file there at
 * scan time), and pointing them into the fixture would let a scanner mutate
 * the scanned tree and break the byte-identical-corpus guarantee. The corpus
 * plants nothing under cache/state, so this costs no tool any recall. run.js
 * additionally diffs the fixture after every scan and reports any mutation.
 */
function pinnedEnv(fixtureHome, trapPort, scratchDir) {
  const env = {};
  for (const k of ENV_ALLOWLIST) {
    if (process.env[k] !== undefined) env[k] = process.env[k];
  }
  if (!env.LANG) env.LANG = "en_US.UTF-8";

  // Home resolution, POSIX and Windows spellings, plus every per-tool home
  // override honored by the benchmarked scanners' documented source lists.
  env.HOME = fixtureHome;
  env.USERPROFILE = fixtureHome;
  env.XDG_CONFIG_HOME = path.join(fixtureHome, ".config");
  env.XDG_DATA_HOME = path.join(fixtureHome, ".local", "share");
  env.XDG_STATE_HOME = scratchDir
    ? path.join(scratchDir, "state")
    : path.join(fixtureHome, ".local", "state");
  env.XDG_CACHE_HOME = scratchDir
    ? path.join(scratchDir, "cache")
    : path.join(fixtureHome, ".cache");
  env.GEMINI_CLI_HOME = fixtureHome; // Gemini CLI root override; tool joins ".gemini" itself
  env.CODEX_HOME = path.join(fixtureHome, ".codex"); // Codex CLI's own override, defaults to ~/.codex
  env.CLAUDE_CONFIG_DIR = path.join(fixtureHome, ".claude");

  // Proxy trap: every scan-time connection attempt that honors proxy env
  // hits the local refuse-and-log listener instead of the network.
  const trap = `http://127.0.0.1:${trapPort}`;
  for (const k of ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"]) {
    env[k] = trap;
  }
  env.NO_PROXY = "";
  env.no_proxy = "";

  // Deterministic, parseable output.
  env.TERM = "dumb";
  env.NO_COLOR = "1";
  env.PYTHONIOENCODING = "utf-8";
  env.CI = "1";

  // Belt and suspenders: agentsweep's own documented off-switch for its
  // pypi.org update check. The benchmarked --json piped invocation already
  // skips that check (verified in its source; see tools/VERSIONS.md), but
  // the promised harness rule is set explicitly so the scan path is
  // network-free by two independent mechanisms.
  env.AGENTSWEEP_NO_UPDATE = "1";

  return env;
}

/**
 * Refuse to run a scanner against anything that could be the operator's real
 * home. Hard rule of the benchmark: scanners only ever see the fixture.
 */
function assertSafeFixtureHome(fixtureHome) {
  const resolved = path.resolve(fixtureHome);
  const realHome = path.resolve(os.homedir());
  if (resolved === realHome || realHome.startsWith(resolved + path.sep)) {
    throw new Error(`refusing to run: fixture home ${resolved} covers the real home directory`);
  }
  if (!resolved.split(path.sep).includes("bench")) {
    throw new Error(`refusing to run: fixture home ${resolved} is not under a bench/ directory`);
  }
  if (!fs.existsSync(resolved)) {
    throw new Error(`fixture home does not exist: ${resolved} (generate it first, e.g. node bench/minifix/make-minifix.js)`);
  }
  return resolved;
}

/**
 * Map a tool-specific rule id to a coarse cross-tool rule family so recall
 * matching never depends on any one tool's naming. First match wins.
 */
const FAMILY_TABLE = [
  [/aws/i, "aws"],
  [/github|ghp|gho_|ghu_|ghs_|ghr_/i, "github"],
  [/gitlab|glpat/i, "gitlab"],
  [/slack/i, "slack"],
  [/openai|sk-proj/i, "openai"],
  [/anthropic|claude/i, "anthropic"],
  [/google|gcp|gemini/i, "google"],
  [/stripe/i, "stripe"],
  [/twilio/i, "twilio"],
  [/sendgrid/i, "sendgrid"],
  [/npm/i, "npm"],
  [/pypi/i, "pypi"],
  [/telegram/i, "telegram"],
  [/discord/i, "discord"],
  [/heroku/i, "heroku"],
  [/private[-_ ]?key|\bpem\b|\brsa\b|\bssh\b/i, "private-key"],
  [/\bjwt\b/i, "jwt"],
  // Planted families that some tools report under composite rule names.
  // These MUST come before the generic bucket: a rule like
  // "db-url-with-password" would otherwise normalize to "generic" and the
  // family tier could never match a connection-string plant, double-charging
  // the tool with a miss AND an unplanted false positive.
  [/connection[-_ ]?string|conn[-_ ]?str|db[-_ ]?url|database[-_ ]?url|postgres|mysql|mongodb|amqp|jdbc/i, "connection-string"],
  [/bearer|authorization[-_ ]?header/i, "bearer-header"],
  [/generic|entropy|password|secret|api[-_ ]?key/i, "generic"],
];

function familyFromRule(rule) {
  if (!rule) return null;
  for (const [re, fam] of FAMILY_TABLE) {
    if (re.test(rule)) return fam;
  }
  return String(rule).toLowerCase();
}

/**
 * Normalized finding shape used by every adapter parser:
 *   file       path as close to absolute as the tool allows
 *   fileBasename  always present, used when a tool emits basenames only
 *   line       1-based line number or null when the tool does not report one
 *   ruleFamily coarse family via familyFromRule, or null
 *   rawRule    the tool's own rule id, verbatim
 *   value      the matched secret text when the tool emits it, else null
 *              (residoo and whatileaked redact by design; that is matched
 *              via file+line / file+family tiers instead, never penalized)
 *   meta       tool-specific extras, kept for the raw record
 */
function makeFinding({ file, line, rawRule, value, meta }) {
  return {
    file: file || null,
    fileBasename: file ? path.basename(file) : null,
    line: Number.isInteger(line) ? line : null,
    ruleFamily: familyFromRule(rawRule),
    rawRule: rawRule || null,
    value: value || null,
    meta: meta || {},
  };
}

/** Does a claimed-classes list (glob-lite: trailing * only) cover a class id? */
function claimCovers(claimedClasses, classId) {
  for (const c of claimedClasses || []) {
    if (c === "*") return true;
    if (c.endsWith("*") ? classId.startsWith(c.slice(0, -1)) : classId === c) return true;
  }
  return false;
}

function stripAnsi(s) {
  // eslint-disable-next-line no-control-regex
  return String(s).replace(/\[[0-9;]*[A-Za-z]/g, "");
}

function loadManifest(fixtureRoot) {
  const p = path.join(fixtureRoot, "manifest.json");
  if (!fs.existsSync(p)) {
    throw new Error(
      `no manifest.json in ${fixtureRoot}. The scorer needs the corpus manifest ` +
      `(schemaVersion 1: {classes: {id: {kind}}, planted: [{id, class, kind, ruleFamily, value, file, line, distinctGroup, exposure}]}).`
    );
  }
  const m = JSON.parse(fs.readFileSync(p, "utf8"));
  if (m.schemaVersion !== 1) throw new Error(`unsupported manifest schemaVersion: ${m.schemaVersion}`);
  return m;
}

function ensureDirs() {
  fs.mkdirSync(RAW_DIR, { recursive: true });
  return { RESULTS_DIR, RAW_DIR };
}

module.exports = {
  BENCH_ROOT, REPO_ROOT, TOOLS_DIR, RESULTS_DIR, RAW_DIR,
  pinnedEnv, assertSafeFixtureHome, familyFromRule, makeFinding,
  claimCovers, stripAnsi, loadManifest, ensureDirs,
};
