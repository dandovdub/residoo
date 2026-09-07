"use strict";

const http = require("http");
const crypto = require("crypto");
// Not destructured: `cp.spawn(...)` at the call site, matching notify.js's
// own documented reasoning -- a test can monkey-patch
// `require("child_process").spawn` on the shared module object.
const cp = require("child_process");
const { renderHtml } = require("./report");

/**
 * `residoo dashboard`'s engine: a local, read-only HTTP server serving the
 * exact same self-contained page `residoo scan --html` writes to disk
 * (`renderHtml`, unmodified -- see report.js), except regenerated fresh on
 * every request instead of written once. No new rendering code, no new
 * data model: this is `--html`'s own output, served live instead of saved.
 *
 * SECURITY, taken as seriously as this project takes everything else it
 * ships -- this is the first HTTP server residoo has ever run, and this
 * project spent the last two releases cataloguing exactly what goes wrong
 * when a local MCP server gets this wrong (see cve.js: CVE-2025-66414 and
 * CVE-2025-66416, both "DNS rebinding protection not enabled by default"
 * in the MCP TypeScript/Python SDKs). The same lesson, applied here:
 *
 *   - **DNS rebinding**: binding to 127.0.0.1 alone does NOT stop a
 *     malicious webpage's browser tab from reaching this server -- an
 *     attacker-controlled domain can be made to resolve to 127.0.0.1
 *     after an initial same-origin check passes, letting page JavaScript
 *     read the response as if it were same-origin. The actual fix (the
 *     one those two CVEs shipped) is validating the `Host` header
 *     server-side on every request: rejected outright unless it's
 *     exactly `127.0.0.1:<this server's port>` or `localhost:<port>`.
 *   - **A random per-run token**, required on every request (checked
 *     AFTER the Host check, so a wrong-Host request never even reaches
 *     token comparison) -- the same well-established local-security model
 *     Jupyter Notebook has used for years. Defense in depth beyond DNS
 *     rebinding: it also stops another local process or another user
 *     account on a shared machine from stumbling onto the port and
 *     reading a scan (already-redacted, but still real file paths and
 *     rotation status) without ever being invited to.
 *   - **Response headers** a static file has no mechanism to carry at
 *     all: `X-Frame-Options: DENY` and `frame-ancestors 'none'` (no
 *     clickjacking-by-iframe), `X-Content-Type-Options: nosniff`, a CSP
 *     that blocks any REMOTE resource load (`default-src 'self'`) while
 *     still allowing the page's own inline `<style>`/`<script>` --
 *     which is server-generated, not reflecting unescaped request data
 *     (every finding field already goes through `escapeHtml()` in
 *     report.js). This makes the dashboard strictly more defended than
 *     the plain `--html` file it's built from, which ships with none of
 *     these headers because a file on disk has nowhere to put them.
 *   - **No write path at all**: every request is a GET of `/`; nothing
 *     here can mutate state, matching this release's own scoped-down
 *     "visualize existing data, take no actions" decision. A future
 *     action-taking dashboard (ack/dismiss/seal from the UI) is a
 *     separate, later decision -- see README/features.md.
 *   - **No CORS headers are ever sent.** The browser's own same-origin
 *     policy already blocks a different-origin page's JavaScript from
 *     reading this response; adding a permissive
 *     `Access-Control-Allow-Origin` would undo that for no benefit here.
 */

/**
 * Cross-platform "open this URL in the default browser," best-effort only
 * -- the terminal always prints the URL too, so a failure here just means
 * the user clicks/copies it instead of it opening automatically. Never
 * throws, matching notify.js's own "a UI convenience must never affect
 * the caller" contract.
 */
function openBrowser(url) {
  try {
    if (process.platform === "darwin") {
      const child = cp.spawn("open", [url], { stdio: "ignore" });
      child.on("error", () => {});
      child.unref();
    } else if (process.platform === "win32") {
      // cmd's built-in `start` treats its first quoted argument as the
      // window TITLE, not the target -- the empty "" is required so `url`
      // is parsed as the target instead.
      const child = cp.spawn("cmd.exe", ["/c", "start", "", url], { stdio: "ignore", windowsHide: true });
      child.on("error", () => {});
      child.unref();
    } else {
      const child = cp.spawn("xdg-open", [url], { stdio: "ignore" });
      child.on("error", () => {});
      child.unref();
    }
  } catch {
    // Best-effort only -- see function docstring.
  }
}

const CSP =
  "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; " +
  "frame-ancestors 'none'; connect-src 'self'; img-src 'self' data:";

/**
 * Start the dashboard's HTTP server. `gatherData()` is an async function
 * returning `{ result, integrity, rotation }` (the same three arguments
 * `renderHtml` already takes) -- called fresh on every request, so
 * reloading the page in the browser re-scans rather than showing a
 * cached-at-startup snapshot. `port` 0 (the default) lets the OS assign
 * an ephemeral port; a caller-chosen port is used verbatim.
 *
 * Resolves to `{ url, stop }` once the server is actually listening --
 * `url` already carries the per-run token as a query parameter, ready to
 * open directly. `stop()` closes the server and resolves once fully shut
 * down (never leaves a lingering listener behind on Ctrl-C).
 */
function startDashboardServer({ port = 0, gatherData }) {
  const token = crypto.randomBytes(16).toString("hex");

  const server = http.createServer(async (req, res) => {
    try {
      const hostHeader = String(req.headers.host || "");
      const hostname = hostHeader.split(":")[0];
      if (hostname !== "127.0.0.1" && hostname !== "localhost") {
        res.writeHead(403, { "Content-Type": "text/plain" });
        res.end("Forbidden: unexpected Host header");
        return;
      }

      let url;
      try { url = new URL(req.url, `http://${hostHeader || "localhost"}`); }
      catch { res.writeHead(400, { "Content-Type": "text/plain" }); res.end("Bad request"); return; }

      if (url.searchParams.get("token") !== token) {
        res.writeHead(403, { "Content-Type": "text/plain" });
        res.end("Forbidden: missing or incorrect token");
        return;
      }

      if (req.method !== "GET" || url.pathname !== "/") {
        res.writeHead(404, { "Content-Type": "text/plain" });
        res.end("Not found");
        return;
      }

      const { result, integrity, rotation } = await gatherData();
      const html = renderHtml(result, integrity, rotation);
      res.writeHead(200, {
        "Content-Type": "text/html; charset=utf-8",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Content-Security-Policy": CSP,
        // Every response is a fresh scan; a cached stale one defeats the
        // whole point of reloading to see current state.
        "Cache-Control": "no-store",
      });
      res.end(html);
    } catch {
      // A scan/render failure must not crash the server or hang the
      // request -- degrade to a visible 500, the same "never a silent
      // all-clear, never a silent crash" discipline every other part of
      // this project already holds to.
      try {
        res.writeHead(500, { "Content-Type": "text/plain" });
        res.end("residoo dashboard: the scan failed while rendering this page. Check the terminal residoo is running in for details.");
      } catch { /* response already sent/destroyed */ }
    }
  });

  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, "127.0.0.1", () => {
      const actualPort = server.address().port;
      const url = `http://127.0.0.1:${actualPort}/?token=${token}`;
      resolve({
        url,
        stop: () => new Promise((r) => server.close(() => r())),
      });
    });
  });
}

module.exports = { startDashboardServer, openBrowser };
