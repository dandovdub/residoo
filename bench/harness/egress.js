"use strict";

/**
 * Zero-egress monitor: observes what a scanner tries to send off the machine
 * DURING A SCAN. Three layers, none needing sudo:
 *
 *  (a) proxy trap    HTTP_PROXY / HTTPS_PROXY / ALL_PROXY point at a local
 *                    listener that logs every connection attempt (including
 *                    the CONNECT target when one is sent) and then refuses
 *                    it. Catches every proxy-honoring HTTP client.
 *  (b) lsof poll     every ~150ms, list the scanner's own process tree and
 *                    ask lsof for its open TCP/UDP sockets. Catches clients
 *                    that ignore proxy env. Own processes only, so no sudo.
 *  (c) static grep   informational only, never scored: grep the tool's
 *                    installed source for network primitives. For compiled
 *                    binaries this layer is reported as not applicable.
 *
 * FAIRNESS RULE (the one that matters): INSTALL-time egress is not scored.
 * Fetching a package via npm, pip, uv, or brew is how software is delivered
 * and says nothing about scan conduct. All tools are installed into
 * bench/tools/ BEFORE any monitored run; the monitored window covers only
 * the scan itself, from process spawn to process exit. Only what a tool
 * does inside that window counts.
 *
 * Verdict enum per tool:
 *   none-observed               no connection attempt in either dynamic layer
 *   attempted                   at least one scan-time attempt, details listed
 *   by-design-requires-server   the tool's own documentation states scanning
 *                               requires its server; citation included
 */

const fs = require("fs");
const net = require("net");
const path = require("path");
const { execFile } = require("child_process");

/**
 * Start the refuse-and-log proxy trap on 127.0.0.1, ephemeral port.
 * Resolves to { port, attempts, close() }. Every connection is recorded
 * with a timestamp and up to 200 bytes of its first data (enough to see
 * "CONNECT api.example.com:443" without storing payloads), then destroyed.
 */
function startProxyTrap() {
  const attempts = [];
  return new Promise((resolve, reject) => {
    const server = net.createServer((socket) => {
      const at = new Date().toISOString();
      const remote = `${socket.remoteAddress}:${socket.remotePort}`;
      let settled = false;
      const record = (firstBytes) => {
        if (settled) return;
        settled = true;
        attempts.push({
          at,
          from: remote,
          firstLine: firstBytes
            ? firstBytes.toString("latin1", 0, Math.min(firstBytes.length, 200)).split(/\r?\n/)[0]
            : null,
        });
        socket.destroy();
      };
      socket.once("data", (buf) => record(buf));
      // A client that connects but never writes still counts as an attempt.
      const t = setTimeout(() => record(null), 300);
      socket.once("close", () => { clearTimeout(t); record(null); });
      socket.on("error", () => {});
    });
    server.on("error", reject);
    server.listen(0, "127.0.0.1", () => {
      resolve({
        port: server.address().port,
        attempts,
        close: () => new Promise((res) => server.close(res)),
      });
    });
  });
}

function execFileP(cmd, args) {
  return new Promise((resolve) => {
    execFile(cmd, args, { maxBuffer: 8 * 1024 * 1024 }, (err, stdout) => {
      resolve({ err, stdout: stdout || "" });
    });
  });
}

/** All descendant pids of rootPid (inclusive), from one `ps` snapshot. */
async function pidTree(rootPid) {
  const { stdout } = await execFileP("ps", ["-axo", "pid=,ppid="]);
  const children = new Map();
  for (const line of stdout.split("\n")) {
    const m = line.trim().match(/^(\d+)\s+(\d+)$/);
    if (!m) continue;
    const [pid, ppid] = [Number(m[1]), Number(m[2])];
    if (!children.has(ppid)) children.set(ppid, []);
    children.get(ppid).push(pid);
  }
  const out = [];
  const queue = [rootPid];
  while (queue.length) {
    const p = queue.shift();
    out.push(p);
    for (const c of children.get(p) || []) queue.push(c);
  }
  return out;
}

/**
 * Start polling lsof for the scanner's process tree. trapPort connections
 * are excluded here (the proxy trap already records them); everything else
 * with a network channel is recorded, loopback included, so nothing is
 * silently filtered. Returns { sockets, stop() }.
 */
function startLsofPoller(rootPid, trapPort, intervalMs = 150) {
  const sockets = [];
  const seen = new Set();
  let running = true;
  let timer = null;

  const tick = async () => {
    if (!running) return;
    try {
      const pids = await pidTree(rootPid);
      if (pids.length) {
        const { stdout } = await execFileP("lsof", ["-a", "-p", pids.join(","), "-i", "-n", "-P", "-FpcnT"]);
        let pid = null;
        let cmd = null;
        for (const line of stdout.split("\n")) {
          if (!line) continue;
          const tag = line[0];
          const rest = line.slice(1);
          if (tag === "p") pid = Number(rest);
          else if (tag === "c") cmd = rest;
          else if (tag === "n") {
            // rest looks like: "127.0.0.1:53411->127.0.0.1:9999" or "*:8080"
            const toTrap = rest.includes(`->127.0.0.1:${trapPort}`) || rest.includes(`->[::1]:${trapPort}`);
            if (toTrap) continue; // already recorded by the proxy trap layer
            const key = `${pid}|${cmd}|${rest}`;
            if (seen.has(key)) continue;
            seen.add(key);
            sockets.push({ at: new Date().toISOString(), pid, command: cmd, name: rest });
          }
        }
      }
    } catch {
      // A vanished pid between ps and lsof is normal at scan end; never fatal.
    }
    if (running) timer = setTimeout(tick, intervalMs);
  };
  timer = setTimeout(tick, 0);

  return {
    sockets,
    stop: () => { running = false; if (timer) clearTimeout(timer); },
  };
}

const NETWORK_PRIMITIVES = [
  /require\(["'](?:node:)?(?:https?|net|dgram|tls|http2)["']\)/,
  /from ["'](?:node:)?(?:https?|net|dgram|tls|http2)["']/,
  /\bfetch\s*\(/,
  /XMLHttpRequest/,
  /\baxios\b/,
  /\bimport\s+(?:urllib|requests|httpx|aiohttp|socket|http\.client)\b/,
  /\bfrom\s+(?:urllib|requests|httpx|aiohttp|socket|http\.client)[\s.]/,
  /urllib\.request/,
  /requests\.(?:get|post|put|delete|request|Session)/,
  /httpx\.(?:get|post|Client|AsyncClient)/,
  /socket\.socket\s*\(/,
];

const SOURCE_EXT = new Set([".js", ".mjs", ".cjs", ".ts", ".py"]);
const MAX_STATIC_HITS = 40;
const MAX_STATIC_FILES = 4000;

/**
 * Informational static layer: which files in the tool's installed source
 * mention network primitives. NOT scored; a network primitive in the source
 * is capability, not conduct. The dynamic layers above measure conduct.
 */
function staticNetworkGrep(roots) {
  if (!roots || roots.binary) {
    return { status: "not-applicable-compiled-binary", hits: [], note: "informational only, never scored" };
  }
  const hits = [];
  let filesScanned = 0;
  const walk = (dir) => {
    if (hits.length >= MAX_STATIC_HITS || filesScanned >= MAX_STATIC_FILES) return;
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      if (hits.length >= MAX_STATIC_HITS || filesScanned >= MAX_STATIC_FILES) return;
      const p = path.join(dir, e.name);
      if (e.isDirectory()) {
        if (e.name === "node_modules" && dir.includes("node_modules")) continue; // one level deep is enough
        if (e.name === ".git" || e.name === "__pycache__" || e.name === "tests" || e.name === "test") continue;
        walk(p);
      } else if (e.isFile() && SOURCE_EXT.has(path.extname(e.name))) {
        filesScanned++;
        let text;
        try { text = fs.readFileSync(p, "utf8"); } catch { continue; }
        const lines = text.split("\n");
        for (let i = 0; i < lines.length && hits.length < MAX_STATIC_HITS; i++) {
          for (const re of NETWORK_PRIMITIVES) {
            if (re.test(lines[i])) {
              hits.push({ file: p, line: i + 1, match: lines[i].trim().slice(0, 160) });
              break;
            }
          }
        }
      }
    }
  };
  for (const root of Array.isArray(roots) ? roots : [roots]) walk(root);
  return {
    status: "scanned",
    filesScanned,
    hits,
    truncated: hits.length >= MAX_STATIC_HITS,
    note: "informational only, never scored: a network primitive in source is capability, not conduct; the dynamic layers measure conduct",
  };
}

/**
 * Final per-tool verdict. byDesign (adapter-supplied citation) wins because
 * it is the honest description even when the unauthenticated run makes no
 * connection: the tool's documented operating mode requires its server.
 */
function verdictFor({ proxyAttempts, nonProxySockets, byDesign }) {
  if (byDesign) {
    // A by-design verdict must never hide what was actually observed: any
    // live attempt during the scan window is folded into the human-facing
    // detail (and kept verbatim in observed), so the one tool with a
    // by-design citation gets the same observational scrutiny as the rest.
    const observedBits = [];
    for (const a of proxyAttempts || []) {
      observedBits.push(`proxy CONNECT attempt${a.firstLine ? " " + JSON.stringify(a.firstLine) : ""}`);
    }
    for (const s of nonProxySockets || []) {
      observedBits.push(`non-proxy socket ${s.name}`);
    }
    const observedLine = observedBits.length
      ? ` Observed during the scan window: ${observedBits.join("; ")}.`
      : " Observed during the scan window: no connection attempts.";
    return {
      verdict: "by-design-requires-server",
      citation: byDesign.citation,
      detail: (byDesign.detail || "") + observedLine,
      observed: { proxyConnectAttempts: proxyAttempts, nonProxySockets },
    };
  }
  if ((proxyAttempts && proxyAttempts.length) || (nonProxySockets && nonProxySockets.length)) {
    return {
      verdict: "attempted",
      detail: `${(proxyAttempts || []).length} proxy connection attempt(s), ${(nonProxySockets || []).length} non-proxy socket(s) observed during the scan window`,
      observed: { proxyConnectAttempts: proxyAttempts, nonProxySockets },
    };
  }
  return {
    verdict: "none-observed",
    detail: "no connection attempts through the proxy trap and no non-loopback-trap sockets in lsof polling during the scan window",
    observed: { proxyConnectAttempts: [], nonProxySockets: [] },
  };
}

module.exports = { startProxyTrap, startLsofPoller, staticNetworkGrep, verdictFor };
