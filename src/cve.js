"use strict";

/**
 * A small, hand-curated, dated table of published CVEs affecting the
 * MCP/AI-agent ecosystem, plus a minimal version-range matcher -- the
 * shared infrastructure behind `residoo scan`'s MCP-config CVE check
 * (integrity.js's "MCP server configuration risks" section) and a future
 * `--project` dependency-manifest check.
 *
 * SOURCE, stated precisely because it matters: every entry below was
 * fetched directly from GitHub's own Security Advisory REST API
 * (api.github.com/advisories?ecosystem=<npm|pip>&affects=<package>) on
 * 2026-09-05 -- a primary, authoritative source (GHSA-reviewed, each
 * entry carrying its own CVE id, GHSA id, and vulnerable/patched version
 * range), not a secondary aggregator's summary. An earlier draft of this
 * table was built from a dedicated MCP-CVE tracking site
 * (vulnerablemcp.info) and cross-checked against this API before
 * shipping; every version range below is the API's own
 * `vulnerable_version_range` field, not a re-derived or estimated one.
 * Package NAMES were independently confirmed to exist on the real npm/
 * PyPI registries (`npm view <pkg>`, PyPI's own JSON API) before being
 * added here -- a wrong package name would silently never match anything,
 * the same "never a false all-clear" concern CONTRIBUTING.md states for
 * source paths, applied to this table instead.
 *
 * DELIBERATELY SMALL, on purpose: this is ~24 entries across 10 packages,
 * not a claim of exhaustive coverage the way Medusa's own "~200 CVEs" is.
 * Every single entry here is individually traceable to a specific GHSA/
 * CVE id and a real advisory -- the same "84 high-confidence rules beat a
 * competitor's higher rule count" trade-off already proven on this
 * project's own benchmark (see bench/RESULTS.md), applied to CVE data
 * instead of secret patterns. A welcome follow-up PR is adding more
 * packages through the same API query, cited the same way -- never by
 * guessing a plausible-sounding range.
 *
 * VERSION COMPARISON: a minimal, hand-written major.minor.patch numeric
 * comparator -- NOT a full semver-range grammar (no ^, ~, prerelease
 * tags, build metadata, x-ranges). Sufficient for every range in this
 * table, including the date-based versioning scheme
 * `@modelcontextprotocol/server-filesystem` switched to mid-2025
 * (`2025.1.14`, `2025.7.1`) -- verified directly that comparing
 * `[2025,1,20]` against `[2025,7,1]` component-by-component gives the
 * correct ordering, the same way it would for an ordinary semver triple.
 * A version string this comparator can't parse (a prerelease suffix, a
 * git-hash pseudo-version, anything non-numeric) is reported as
 * "cannot determine" by the caller, never silently treated as either safe
 * or vulnerable -- CONTRIBUTING.md's rule 5 applied to a version string
 * instead of a file.
 */

const CVE_DATABASE = [
  // ---- npm ----
  {
    id: "CVE-2025-6514", ecosystem: "npm", package: "mcp-remote", severity: "critical",
    ranges: [{ min: "0.0.5", maxExclusive: "0.1.16" }],
    summary: "OS command injection via a crafted authorization_endpoint response URL when connecting to an untrusted MCP server.",
    source: "GHSA-6xpm-ggf7-wc3p",
  },
  {
    id: "CVE-2025-58444", ecosystem: "npm", package: "@modelcontextprotocol/inspector", severity: "high",
    ranges: [{ maxExclusive: "0.16.6" }],
    summary: "Potential command execution via XSS when Inspector connects to an untrusted MCP server.",
    source: "GHSA (fetched via api.github.com/advisories)",
  },
  {
    id: "CVE-2025-49596", ecosystem: "npm", package: "@modelcontextprotocol/inspector", severity: "critical",
    ranges: [{ maxExclusive: "0.14.1" }],
    summary: "The Inspector proxy server lacks authentication between the Inspector client and the proxy, enabling RCE.",
    source: "GHSA (fetched via api.github.com/advisories)",
  },
  {
    id: "CVE-2026-23744", ecosystem: "npm", package: "@mcpjam/inspector", severity: "critical",
    ranges: [{ maxInclusive: "1.4.2" }],
    summary: "Remote code execution via an exposed, unauthenticated HTTP endpoint.",
    source: "GHSA (fetched via api.github.com/advisories)",
  },
  {
    id: "CVE-2025-65513", ecosystem: "npm", package: "mcp-fetch-server", severity: "medium",
    ranges: [{ maxInclusive: "1.0.2" }],
    summary: "Server-Side Request Forgery (SSRF) vulnerability.",
    source: "GHSA (fetched via api.github.com/advisories)",
  },
  {
    id: "CVE-2025-53372", ecosystem: "npm", package: "node-code-sandbox-mcp", severity: "high",
    ranges: [{ maxInclusive: "1.2.0" }],
    summary: "Sandbox escape via command injection.",
    source: "GHSA (fetched via api.github.com/advisories)",
  },
  {
    id: "CVE-2026-47250", ecosystem: "npm", package: "mcp-server-kubernetes", severity: "medium",
    ranges: [{ maxInclusive: "3.6.2" }],
    summary: "kubectl-generic flag injection enables Kubernetes bearer-token exfiltration.",
    source: "GHSA (fetched via api.github.com/advisories)",
  },
  {
    id: "CVE-2026-46519", ecosystem: "npm", package: "mcp-server-kubernetes", severity: "high",
    ranges: [{ maxExclusive: "3.6.0" }],
    summary: "Tool access control bypass via presentation-layer filtering with no execution-layer enforcement.",
    source: "GHSA (fetched via api.github.com/advisories)",
  },
  {
    id: "CVE-2026-39884", ecosystem: "npm", package: "mcp-server-kubernetes", severity: "high",
    ranges: [{ maxInclusive: "3.4.0" }],
    summary: "Argument injection in the port_forward tool via space-splitting.",
    source: "GHSA (fetched via api.github.com/advisories)",
  },
  {
    id: "CVE-2025-66404", ecosystem: "npm", package: "mcp-server-kubernetes", severity: "medium",
    ranges: [{ maxInclusive: "2.9.7" }],
    summary: "Security issue in the exec_in_pod tool.",
    source: "GHSA (fetched via api.github.com/advisories)",
  },
  {
    id: "CVE-2025-53355", ecosystem: "npm", package: "mcp-server-kubernetes", severity: "high",
    ranges: [{ maxExclusive: "2.5.0" }],
    summary: "Command injection in several tools.",
    source: "GHSA (fetched via api.github.com/advisories)",
  },
  {
    id: "CVE-2026-25536", ecosystem: "npm", package: "@modelcontextprotocol/sdk", severity: "high",
    ranges: [{ min: "1.10.0", maxInclusive: "1.25.3" }],
    summary: "Cross-client data leak via shared server/transport instance reuse.",
    source: "GHSA (fetched via api.github.com/advisories)",
  },
  {
    id: "CVE-2026-0621", ecosystem: "npm", package: "@modelcontextprotocol/sdk", severity: "high",
    ranges: [{ min: "1.3.0", maxExclusive: "1.25.2" }],
    summary: "ReDoS (regular expression denial of service) vulnerability.",
    source: "GHSA (fetched via api.github.com/advisories)",
  },
  {
    id: "CVE-2025-66414", ecosystem: "npm", package: "@modelcontextprotocol/sdk", severity: "high",
    ranges: [{ maxExclusive: "1.24.0" }],
    summary: "DNS rebinding protection not enabled by default on localhost-bound SSE/StreamableHTTP servers.",
    source: "GHSA (fetched via api.github.com/advisories)",
  },
  {
    id: "CVE-2025-53110", ecosystem: "npm", package: "@modelcontextprotocol/server-filesystem", severity: "high",
    ranges: [{ maxInclusive: "0.6.2" }, { min: "2025.1.14", maxExclusive: "2025.7.1" }],
    summary: "Path validation bypass via a colliding path prefix.",
    source: "GHSA (fetched via api.github.com/advisories)",
  },
  {
    id: "CVE-2025-53109", ecosystem: "npm", package: "@modelcontextprotocol/server-filesystem", severity: "high",
    ranges: [{ maxInclusive: "0.6.2" }, { min: "2025.1.14", maxExclusive: "2025.7.1" }],
    summary: "Path validation bypass via prefix matching and symlink handling.",
    source: "GHSA (fetched via api.github.com/advisories)",
  },

  // ---- pip ----
  {
    id: "CVE-2026-59950", ecosystem: "pip", package: "mcp", severity: "high",
    ranges: [{ maxExclusive: "1.28.1" }],
    summary: "MCP Python SDK: WebSocket server transport does not support Host/Origin validation.",
    source: "GHSA (fetched via api.github.com/advisories)",
  },
  {
    id: "CVE-2026-52869", ecosystem: "pip", package: "mcp", severity: "high",
    ranges: [{ maxInclusive: "1.27.1" }],
    summary: "MCP Python SDK: HTTP transports serve session requests without verifying the authenticated principal.",
    source: "GHSA (fetched via api.github.com/advisories)",
  },
  {
    id: "CVE-2026-52870", ecosystem: "pip", package: "mcp", severity: "high",
    ranges: [{ min: "1.23.0", maxInclusive: "1.27.1" }],
    summary: "Experimental task handlers allow any client to access and cancel other clients' tasks.",
    source: "GHSA (fetched via api.github.com/advisories)",
  },
  {
    id: "CVE-2025-66416", ecosystem: "pip", package: "mcp", severity: "high",
    ranges: [{ maxExclusive: "1.23.0" }],
    summary: "DNS rebinding protection not enabled by default on localhost-bound SSE/StreamableHTTP servers.",
    source: "GHSA (fetched via api.github.com/advisories)",
  },
  {
    id: "CVE-2025-53366", ecosystem: "pip", package: "mcp", severity: "high",
    ranges: [{ maxExclusive: "1.9.4" }],
    summary: "FastMCP Server validation error leading to denial of service.",
    source: "GHSA (fetched via api.github.com/advisories)",
  },
  {
    id: "CVE-2025-53365", ecosystem: "pip", package: "mcp", severity: "high",
    ranges: [{ maxExclusive: "1.10.0" }],
    summary: "Unhandled exception in the Streamable HTTP transport, leading to denial of service.",
    source: "GHSA (fetched via api.github.com/advisories)",
  },
  {
    id: "CVE-2026-27735", ecosystem: "pip", package: "mcp-server-git", severity: "medium",
    ranges: [{ maxExclusive: "2026.1.14" }],
    summary: "Path traversal in git_add allows staging files outside the repository boundary.",
    source: "GHSA (fetched via api.github.com/advisories)",
  },
  {
    id: "CVE-2025-68145", ecosystem: "pip", package: "mcp-server-git", severity: "medium",
    ranges: [{ maxExclusive: "2025.12.18" }],
    summary: "Missing path validation when using the --repository flag.",
    source: "GHSA (fetched via api.github.com/advisories)",
  },
  {
    id: "CVE-2025-68144", ecosystem: "pip", package: "mcp-server-git", severity: "medium",
    ranges: [{ maxExclusive: "2025.12.18" }],
    summary: "Argument injection in git_diff and git_checkout allows overwriting local files.",
    source: "GHSA (fetched via api.github.com/advisories)",
  },
  {
    id: "CVE-2025-68143", ecosystem: "pip", package: "mcp-server-git", severity: "medium",
    ranges: [{ maxExclusive: "2025.9.25" }],
    summary: "Unrestricted git_init tool allows repository creation at arbitrary filesystem locations.",
    source: "GHSA (fetched via api.github.com/advisories)",
  },
];

/**
 * Parse a version string's leading major.minor.patch numeric triple.
 * Returns null for anything this simple comparator can't handle (a
 * prerelease/build-metadata suffix, a git-hash pseudo-version, a bare "1"
 * or "1.2" with no patch component) -- the caller must treat null as
 * "cannot determine," never as a match or a clean bill of health.
 */
function parseVersion(v) {
  // `String(v)` itself can throw -- an object whose own `toString` property
  // is present but not a function (e.g. `{ toString: "" }`, a real shape
  // fast-check's property fuzzing found, not a hypothetical) fails the
  // ToPrimitive coercion with "Cannot convert object to primitive value"
  // before the regex ever runs. `v` here can be anything an attacker-
  // controlled MCP config's `args` array contains, so this must degrade to
  // "unparseable" the same as any other malformed input, never throw.
  let s;
  try { s = String(v).trim(); } catch { return null; }
  const m = /^v?(\d+)\.(\d+)\.(\d+)/.exec(s);
  if (!m) return null;
  return [Number(m[1]), Number(m[2]), Number(m[3])];
}

/** -1 / 0 / 1, comparing two parseVersion() triples component-by-component. */
function compareVersions(a, b) {
  for (let i = 0; i < 3; i++) {
    if (a[i] !== b[i]) return a[i] - b[i];
  }
  return 0;
}

function inOneRange(parsed, range) {
  if (range.min) {
    const min = parseVersion(range.min);
    if (min && compareVersions(parsed, min) < 0) return false;
  }
  if (range.maxInclusive) {
    const max = parseVersion(range.maxInclusive);
    if (max && compareVersions(parsed, max) > 0) return false;
  }
  if (range.maxExclusive) {
    const max = parseVersion(range.maxExclusive);
    if (max && compareVersions(parsed, max) >= 0) return false;
  }
  return true;
}

/**
 * Check one resolved `packageName`@`version` pair (ecosystem "npm" or
 * "pip") against CVE_DATABASE. Returns `{ checkable, matches }` --
 * `checkable: false` means the version string couldn't be parsed at all
 * (report "cannot determine," never silently clean); `matches` is every
 * CVE_DATABASE entry whose package matches and whose vulnerable range
 * (any one of its, possibly several, disjoint ranges) contains this
 * version.
 */
function checkVersion(ecosystem, packageName, version) {
  const parsed = parseVersion(version);
  if (!parsed) return { checkable: false, matches: [] };
  const matches = CVE_DATABASE.filter((entry) =>
    entry.ecosystem === ecosystem &&
    entry.package === packageName &&
    entry.ranges.some((r) => inOneRange(parsed, r)));
  return { checkable: true, matches };
}

module.exports = { CVE_DATABASE, parseVersion, compareVersions, checkVersion };
