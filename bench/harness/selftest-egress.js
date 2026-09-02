#!/usr/bin/env node
"use strict";

/**
 * Positive control for the zero-egress monitor. A monitor that never fires
 * is unfalsifiable, so this test proves each dynamic layer catches what it
 * claims to catch, using only loopback traffic (nothing leaves the machine):
 *
 *   1. proxy-trap layer: spawn curl with the pinned proxy env pointing at
 *      the trap. curl honors HTTPS_PROXY and attempts CONNECT through the
 *      trap, which logs and refuses it. Expect exactly that attempt, with
 *      the target visible in the recorded first line.
 *   2. lsof-poll layer: spawn a child that opens a plain TCP connection to
 *      a local listener that is NOT the trap and holds it open long enough
 *      for a poll tick. Expect the poller to record that socket.
 *
 * Exit 0 when both layers fire, 1 otherwise. Run:
 *   node bench/harness/selftest-egress.js
 *
 * The transcript is also persisted to bench/results/raw/selftest-egress.txt
 * so "positive control verified first" is evidenced in the published raw
 * records, not just claimed.
 */

const fs = require("fs");
const path = require("path");
const net = require("net");
const { spawn } = require("child_process");
const egress = require("./egress");

const LOG_LINES = [];
function log(line) { LOG_LINES.push(line); console.log(line); }
function logErr(line) { LOG_LINES.push(line); console.error(line); }
function persist() {
  try {
    const rawDir = path.join(__dirname, "..", "results", "raw");
    fs.mkdirSync(rawDir, { recursive: true });
    fs.writeFileSync(
      path.join(rawDir, "selftest-egress.txt"),
      `# egress monitor positive control transcript\n# ran: ${new Date().toISOString()}\n` + LOG_LINES.join("\n") + "\n"
    );
  } catch { /* persisting the transcript must never mask the test result */ }
}

function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }

async function testProxyTrap() {
  const trap = await egress.startProxyTrap();
  const env = {
    PATH: process.env.PATH,
    HTTPS_PROXY: `http://127.0.0.1:${trap.port}`,
    HTTP_PROXY: `http://127.0.0.1:${trap.port}`,
    ALL_PROXY: `http://127.0.0.1:${trap.port}`,
  };
  await new Promise((resolve) => {
    // The target host is never contacted: curl sends CONNECT to the trap,
    // the trap logs and refuses, curl fails. Loopback only.
    const c = spawn("curl", ["-s", "--max-time", "5", "https://egress-selftest.invalid/"], { env });
    c.on("close", resolve);
    c.on("error", resolve);
  });
  await sleep(150);
  await trap.close();
  const ok = trap.attempts.length > 0;
  const firstLine = ok ? trap.attempts[0].firstLine : null;
  log(`proxy-trap layer: ${ok ? "PASS" : "FAIL"} (${trap.attempts.length} attempt(s) recorded${firstLine ? ", first line: " + JSON.stringify(firstLine) : ""})`);
  return ok;
}

async function testLsofPoll() {
  // Local listener that is not the trap; the child connects and holds.
  const server = net.createServer((s) => { /* hold the socket open */ });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const port = server.address().port;

  const child = spawn(process.execPath, ["-e", `
    const net = require("net");
    const s = net.connect(${port}, "127.0.0.1", () => {
      setTimeout(() => { s.destroy(); process.exit(0); }, 800);
    });
    s.on("error", () => process.exit(0));
  `]);

  const fakeTrapPort = 1; // nothing filters as trap traffic in this test
  const poller = egress.startLsofPoller(child.pid, fakeTrapPort);
  await new Promise((resolve) => child.on("close", resolve));
  poller.stop();
  server.close();

  const hit = poller.sockets.find((s) => s.name && s.name.includes(`:${port}`));
  log(`lsof-poll layer:  ${hit ? "PASS" : "FAIL"} (${poller.sockets.length} socket record(s)${hit ? ", e.g. " + hit.name : ""})`);
  return Boolean(hit);
}

async function main() {
  const a = await testProxyTrap();
  const b = await testLsofPoll();
  if (a && b) {
    log("egress monitor positive control: both layers fire. A clean verdict from a real run is falsifiable evidence, not silence.");
    persist();
    process.exit(0);
  }
  logErr("egress monitor positive control FAILED; do not trust none-observed verdicts until this passes.");
  persist();
  process.exit(1);
}

main();
