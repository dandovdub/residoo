#!/usr/bin/env node
"use strict";

/**
 * Benchmark runner: executes ONE scanner adapter against a corpus fixture
 * with a fully pinned environment and the zero-egress monitor attached.
 *
 * Usage:
 *   node bench/harness/run.js <adapter> [--fixture <dir>] [--mini] [--results <dir>] [--timeout <sec>] [--list]
 *
 *   <adapter>    a name from bench/harness/adapters/ (residoo, gitleaks,
 *                agentsweep, whatileaked, ggshield)
 *   --fixture    fixture ROOT directory: must contain home/ (and, for
 *                scoring, manifest.json). Default: bench/corpus/data
 *   --mini       shorthand for --fixture bench/minifix/data; also switches
 *                the results dir to bench/results-mini so a smoke run can
 *                never clobber full-corpus results
 *   --results    override the results directory explicitly
 *   --timeout    per-run wall clock limit in seconds (default 600)
 *   --list       list adapters and availability, then exit
 *
 * What one run does, in order:
 *   1. Refuses to run unless the fixture home is a bench/ directory that is
 *      not the operator's real home (hard rule: never scan the real machine).
 *   2. Starts the local refuse-and-log proxy trap (egress.js).
 *   3. Builds a from-scratch environment: HOME, USERPROFILE, XDG_*,
 *      GEMINI_CLI_HOME, CODEX_HOME, CLAUDE_CONFIG_DIR pinned into the
 *      fixture; all proxy vars pointed at the trap; nothing else inherited
 *      beyond PATH/TMPDIR/locale.
 *   4. Detects the tool version (unmonitored, before the scan window).
 *   5. Runs the adapter's scan command(s) inside the monitored window:
 *      proxy trap + lsof polling of the scanner's own process tree.
 *   6. Writes bench/results/raw/<tool>.txt (verbatim stdout/stderr + the
 *      exact commands and env pins, so any reader can rerun) and
 *      bench/results/<tool>.findings.json (normalized findings + timing +
 *      egress record) for bench/harness/score.js.
 *
 * EGRESS FAIRNESS: install-time egress is not scored. Tools are installed
 * into bench/tools/ beforehand; the monitored window covers only the scan.
 * See egress.js and README.md for the full statement.
 *
 * SCAN-ONLY: adapters invoke each tool's scan/detect mode exclusively.
 * No adapter may call a competitor's redact/fix/wipe mode, ever.
 */

const fs = require("fs");
const path = require("path");
const { spawn, execFile } = require("child_process");
const lib = require("./lib");
const egress = require("./egress");

const ADAPTER_DIR = path.join(__dirname, "adapters");

function listAdapters() {
  return fs.readdirSync(ADAPTER_DIR).filter((f) => f.endsWith(".js")).map((f) => f.replace(/\.js$/, "")).sort();
}

function parseArgs(argv) {
  const args = { timeoutSec: 600, fixtureRoot: path.join(lib.BENCH_ROOT, "corpus", "data"), resultsDir: null };
  const rest = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--fixture") args.fixtureRoot = path.resolve(argv[++i]);
    else if (a === "--mini") {
      args.fixtureRoot = path.join(lib.BENCH_ROOT, "minifix", "data");
      // Fixture-scoped results: a --mini smoke run must never overwrite the
      // published full-corpus results.
      if (!args.resultsDir) args.resultsDir = path.join(lib.BENCH_ROOT, "results-mini");
    }
    else if (a === "--results") args.resultsDir = path.resolve(argv[++i]);
    else if (a === "--timeout") args.timeoutSec = Number(argv[++i]);
    else if (a === "--list") args.list = true;
    else rest.push(a);
  }
  args.adapter = rest[0];
  return args;
}

/**
 * Snapshot every file under a root as relpath -> {size, mtimeMs}. Used to
 * detect a scanner MUTATING the scanned fixture: a tool that writes into the
 * tree it scans is benchmark-relevant evidence, and any mutation would also
 * break the corpus's byte-identical-regeneration guarantee, so run.js
 * reports it loudly instead of letting it slip into the committed tree.
 */
function snapshotTree(root) {
  const out = new Map();
  const walk = (dir) => {
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      const p = path.join(dir, e.name);
      if (e.isDirectory()) walk(p);
      else {
        try {
          const st = fs.statSync(p);
          out.set(path.relative(root, p), { size: st.size, mtimeMs: st.mtimeMs });
        } catch { /* vanished mid-walk */ }
      }
    }
  };
  walk(root);
  return out;
}

function diffSnapshots(before, after) {
  const changes = [];
  for (const [rel, st] of after) {
    const prev = before.get(rel);
    if (!prev) changes.push({ path: rel, change: "created", size: st.size });
    else if (prev.size !== st.size || prev.mtimeMs !== st.mtimeMs) changes.push({ path: rel, change: "modified", size: st.size });
  }
  for (const rel of before.keys()) {
    if (!after.has(rel)) changes.push({ path: rel, change: "deleted" });
  }
  return changes;
}

/** List every file under a dir (relative paths); for scratch-write evidence. */
function listTree(root) {
  return [...snapshotTree(root).keys()];
}

/**
 * Spawn a command, capture stdout/stderr/exit/wall time. Returns the child's
 * pid synchronously (so the lsof poller can attach for the whole scan
 * window) plus a promise for the completed result.
 */
function runCaptured({ cmd, args, cwd, env, timeoutMs }) {
  const startedAt = Date.now();
  const out = [];
  const err = [];
  let outBytes = 0;
  let errBytes = 0;
  const CAP = 50 * 1024 * 1024;
  const child = spawn(cmd, args, { cwd, env, stdio: ["ignore", "pipe", "pipe"], detached: true });
  let timedOut = false;
  const killer = timeoutMs
    ? setTimeout(() => {
        timedOut = true;
        try { process.kill(-child.pid, "SIGKILL"); } catch { try { child.kill("SIGKILL"); } catch {} }
      }, timeoutMs)
    : null;
  const promise = new Promise((resolve) => {
    child.stdout.on("data", (b) => { if ((outBytes += b.length) < CAP) out.push(b); });
    child.stderr.on("data", (b) => { if ((errBytes += b.length) < CAP) err.push(b); });
    child.on("error", (e) => {
      if (killer) clearTimeout(killer);
      resolve({ pid: child.pid, exitCode: null, spawnError: e.message, stdout: "", stderr: "", wallMs: Date.now() - startedAt, timedOut });
    });
    child.on("close", (code, signal) => {
      if (killer) clearTimeout(killer);
      resolve({
        pid: child.pid,
        exitCode: code,
        signal: signal || null,
        stdout: Buffer.concat(out).toString("utf8"),
        stderr: Buffer.concat(err).toString("utf8"),
        wallMs: Date.now() - startedAt,
        timedOut,
      });
    });
  });
  return { pid: child.pid, promise };
}

function detectVersion(adapter, ctx) {
  const spec = adapter.version(ctx);
  if (spec.literal) return Promise.resolve(spec.literal);
  return new Promise((resolve) => {
    execFile(spec.cmd, spec.args, { env: ctx.env, timeout: 30000 }, (e, stdout, stderr) => {
      const line = ((stdout || "") + (stderr || "")).trim().split("\n")[0];
      resolve(e && !line ? `version detection failed: ${e.message}` : line);
    });
  });
}

async function main() {
  const args = parseArgs(process.argv.slice(2));

  if (args.list || !args.adapter) {
    const names = listAdapters();
    console.log("adapters: " + names.join(", "));
    if (!args.adapter) {
      console.log("usage: node bench/harness/run.js <adapter> [--fixture <dir>] [--mini] [--timeout <sec>]");
      process.exit(args.list ? 0 : 2);
    }
  }

  const adapterPath = path.join(ADAPTER_DIR, args.adapter + ".js");
  if (!fs.existsSync(adapterPath)) {
    console.error(`unknown adapter '${args.adapter}'. Available: ${listAdapters().join(", ")}`);
    process.exit(2);
  }
  const adapter = require(adapterPath);

  const fixtureHome = lib.assertSafeFixtureHome(path.join(args.fixtureRoot, "home"));
  const RESULTS_DIR = args.resultsDir || lib.RESULTS_DIR;
  const RAW_DIR = path.join(RESULTS_DIR, "raw");
  fs.mkdirSync(RAW_DIR, { recursive: true });

  // Per-run scratch dir for tool cache/state writes (XDG_CACHE_HOME,
  // XDG_STATE_HOME). Outside the fixture so no scanner write can ever land
  // in the scanned tree; inside bench/ so nothing touches the real machine.
  const scratchDir = fs.mkdtempSync(path.join(RESULTS_DIR, ".scratch-"));

  const trap = await egress.startProxyTrap();
  const env = lib.pinnedEnv(fixtureHome, trap.port, scratchDir);

  const ctx = {
    repoRoot: lib.REPO_ROOT,
    benchRoot: lib.BENCH_ROOT,
    toolsDir: lib.TOOLS_DIR,
    resultsDir: RESULTS_DIR,
    rawDir: RAW_DIR,
    fixtureRoot: args.fixtureRoot,
    fixtureHome,
    env,
  };

  const avail = adapter.available(ctx);
  if (!avail.ok) {
    await trap.close();
    fs.rmSync(scratchDir, { recursive: true, force: true });
    console.error(`adapter '${adapter.id}' unavailable: ${avail.reason}`);
    if (avail.installHint) console.error(`install hint (install-time network is fine, it is not scored): ${avail.installHint}`);
    process.exit(3);
  }

  const version = await detectVersion(adapter, ctx);

  const specs = [].concat(adapter.command(ctx));
  const invocations = [];
  const startedAt = new Date().toISOString();

  // Baseline for scanner-write detection: the fixture must be byte-stable
  // across a scan. Diffed after the scan window (outside the timed region,
  // so wall times stay pure tool time).
  const fixtureSnapshot = snapshotTree(fixtureHome);

  const scanWindowStart = Date.now();

  for (const spec of specs) {
    const { pid, promise } = runCaptured({
      cmd: spec.cmd,
      args: spec.args,
      cwd: spec.cwd || ctx.benchRoot,
      env,
      timeoutMs: args.timeoutSec * 1000,
    });
    // The poller attaches immediately after spawn, so it covers the whole
    // scan window. Very fast commands may finish between poll ticks; the
    // proxy trap layer still covers those end to end.
    const poller = pid ? egress.startLsofPoller(pid, trap.port) : null;
    const result = await promise;
    if (poller) poller.stop();
    result.lsofSockets = poller ? poller.sockets : [];

    invocations.push({
      cmd: spec.cmd,
      args: spec.args,
      cwd: spec.cwd || ctx.benchRoot,
      note: spec.note || null,
      expectedExitCodes: spec.expectedExitCodes || [0],
      ...result,
    });
    if (result.spawnError) break;
  }
  const scanWindowMs = Date.now() - scanWindowStart;

  await new Promise((res) => setTimeout(res, 150)); // drain late trap connections
  await trap.close();

  // Scanner-write evidence, both directions:
  // - fixtureMutations: any file the tool created/modified/deleted INSIDE
  //   the scanned fixture (must be empty; reported loudly if not, because it
  //   is benchmark-relevant conduct and would dirty the committed corpus).
  // - scratchWrites: files the tool wrote into its per-run cache/state
  //   scratch (e.g. ggshield's update-check cache); recorded as evidence,
  //   then the scratch is removed.
  const fixtureMutations = diffSnapshots(fixtureSnapshot, snapshotTree(fixtureHome));
  const scratchWrites = listTree(scratchDir);
  fs.rmSync(scratchDir, { recursive: true, force: true });

  const nonProxySockets = invocations.flatMap((i) => i.lsofSockets || []);
  const egressRecord = {
    scoredWindow: "scan-time only: from scan process spawn to exit. Install-time package fetches (npm/pip/uv/brew) happen before any monitored run and are NOT scored.",
    layers: {
      proxyTrap: `HTTP_PROXY/HTTPS_PROXY/ALL_PROXY pinned to refuse-and-log listener on 127.0.0.1:${trap.port}`,
      lsofPoll: "lsof -a -p <scanner pid tree> -i, ~150ms cadence, own processes, no sudo",
      staticGrep: "informational only, never scored",
    },
    ...egress.verdictFor({
      proxyAttempts: trap.attempts,
      nonProxySockets,
      byDesign: adapter.byDesignEgress || null,
    }),
    staticNetworkPrimitives: egress.staticNetworkGrep(adapter.staticGrepRoots(ctx)),
  };

  const parsed = adapter.parse(invocations, ctx);

  const unexpectedExits = invocations.filter(
    (i) => i.exitCode === null || !(i.expectedExitCodes || [0]).includes(i.exitCode)
  );

  const record = {
    tool: adapter.id,
    displayName: adapter.displayName,
    version,
    startedAt,
    fixtureRoot: args.fixtureRoot,
    fixtureHome,
    wallMs: scanWindowMs,
    invocations: invocations.map(({ cmd, args: a, cwd, note, expectedExitCodes, exitCode, signal, wallMs, timedOut, spawnError }) => ({
      cmd, args: a, cwd, note, expectedExitCodes, exitCode, signal, wallMs, timedOut, spawnError: spawnError || null,
    })),
    unexpectedExit: unexpectedExits.length > 0,
    fixtureMutations,
    scratchWrites,
    claimedClasses: adapter.claimedClasses,
    claimsNote: adapter.claimsNote,
    notScoredForRecall: adapter.notScoredForRecall || null,
    findings: parsed.findings,
    parseNotes: parsed.notes || [],
    egress: egressRecord,
    envPins: {
      HOME: env.HOME, USERPROFILE: env.USERPROFILE,
      XDG_CONFIG_HOME: env.XDG_CONFIG_HOME, XDG_DATA_HOME: env.XDG_DATA_HOME,
      XDG_STATE_HOME: env.XDG_STATE_HOME, XDG_CACHE_HOME: env.XDG_CACHE_HOME,
      GEMINI_CLI_HOME: env.GEMINI_CLI_HOME, CODEX_HOME: env.CODEX_HOME,
      CLAUDE_CONFIG_DIR: env.CLAUDE_CONFIG_DIR,
      HTTP_PROXY: env.HTTP_PROXY, HTTPS_PROXY: env.HTTPS_PROXY, ALL_PROXY: env.ALL_PROXY,
    },
  };

  const rawLines = [];
  rawLines.push(`# ${adapter.displayName} raw run record`);
  rawLines.push(`# started: ${startedAt}`);
  rawLines.push(`# version: ${version}`);
  rawLines.push(`# fixture home: ${fixtureHome}`);
  rawLines.push(`# env pins: ${JSON.stringify(record.envPins)}`);
  rawLines.push(`# egress verdict: ${egressRecord.verdict}`);
  rawLines.push(`# NOTE: install-time egress (package fetch) is not scored; this record covers scan time only.`);
  for (const inv of invocations) {
    rawLines.push("");
    rawLines.push(`## command: ${inv.cmd} ${inv.args.join(" ")}`);
    rawLines.push(`## cwd: ${inv.cwd}   exit: ${inv.exitCode}${inv.signal ? " signal:" + inv.signal : ""}   wall: ${inv.wallMs}ms${inv.timedOut ? "   TIMED OUT" : ""}`);
    if (inv.spawnError) rawLines.push(`## spawn error: ${inv.spawnError}`);
    rawLines.push("### stdout");
    rawLines.push(inv.stdout || "(empty)");
    rawLines.push("### stderr");
    rawLines.push(inv.stderr || "(empty)");
  }
  rawLines.push("");
  rawLines.push("### egress observations");
  rawLines.push(JSON.stringify({ verdict: egressRecord.verdict, detail: egressRecord.detail, observed: egressRecord.observed }, null, 2));
  rawLines.push("");
  rawLines.push("### scanner writes");
  rawLines.push(JSON.stringify({
    fixtureMutations,
    fixtureMutationsNote: "files the tool created/modified/deleted inside the scanned fixture during this run; must be empty",
    scratchWrites,
    scratchWritesNote: "files the tool wrote into its per-run XDG cache/state scratch (outside the fixture; removed after the run)",
  }, null, 2));

  const rawPath = path.join(RAW_DIR, `${adapter.id}.txt`);
  const findingsPath = path.join(RESULTS_DIR, `${adapter.id}.findings.json`);
  fs.writeFileSync(rawPath, rawLines.join("\n") + "\n");
  fs.writeFileSync(findingsPath, JSON.stringify(record, null, 2) + "\n");

  console.log(`${adapter.id}: ${parsed.findings.length} normalized finding(s), egress=${egressRecord.verdict}, wall=${scanWindowMs}ms`);
  console.log(`raw:      ${rawPath}`);
  console.log(`findings: ${findingsPath}`);
  if (scratchWrites.length) {
    console.log(`note: tool wrote ${scratchWrites.length} file(s) into its cache/state scratch (recorded in the raw record, scratch removed)`);
  }
  if (fixtureMutations.length) {
    console.error(`WARNING: the tool MUTATED the scanned fixture (${fixtureMutations.length} change(s), listed in the raw record). Regenerate the corpus before committing or scoring further runs.`);
    process.exitCode = 1;
  }
  if (unexpectedExits.length) {
    console.error(`WARNING: ${unexpectedExits.length} invocation(s) exited outside the adapter's expected codes; inspect the raw record.`);
    process.exitCode = 1;
  }
}

main().catch((e) => {
  // Safety refusals and fixture problems are expected operator feedback,
  // not crashes; show the message, not a stack trace.
  const msg = String(e && e.message || e);
  if (/refusing to run|fixture home does not exist|manifest/.test(msg)) console.error(msg);
  else console.error(e.stack || msg);
  process.exit(2);
});
