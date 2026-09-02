"use strict";

const fs = require("fs");
const path = require("path");
const { makeFinding } = require("../lib");

/**
 * Betterleaks (betterleaks/betterleaks), the Gitleaks successor from the
 * Gitleaks author (its README: "It is maintained by the folks who made
 * Gitleaks, including the original author"; development supported by Aikido
 * Security). Filesystem mode, mirroring the gitleaks adapter:
 *
 *   betterleaks dir <fixture home> --report-format json
 *       --report-path <raw>/betterleaks.report.json --no-banner
 *
 * `dir` is its documented subcommand for plain directories ("scan
 * directories or files for secrets", --help), the same spelling as modern
 * gitleaks. The JSON report format is gitleaks-compatible (RuleID / File /
 * StartLine / Secret / Entropy / Fingerprint, verified on the mini-fixture
 * sample), so the parser is the same shape as gitleaks'.
 *
 * NO DUAL MODE NEEDED: unlike TruffleHog and Kingfisher, Betterleaks does
 * NOT validate findings over the network by default. Validation is opt-in
 * via `--validation` ("enable validation of findings against live APIs",
 * --help), which this benchmark never passes; the scored run is the
 * documented default mode and must show no observed egress.
 *
 * Exit codes: 0 clean, 1 when leaks found (its --exit-code default,
 * documented in --help and observed).
 *
 * REGEX ENGINE, a scanner-write finding: with its default engine
 * (`--regex-engine` "regex engine (stdlib, re2) (default \"re2\")"), the
 * re2-over-wasm implementation (wasilibs/go-re2 via wazero) writes a
 * compilation cache to Library/Caches/com.github.wasilibs under HOME on
 * macOS, which the harness pins INSIDE the scanned fixture, and no flag or
 * environment variable redirects it (verified: no WASILIBS/cache env var in
 * the binary; Go's os.UserCacheDir on darwin ignores XDG). The benchmark's
 * write-protection rule keeps the scanned tree byte-stable, so the adapter
 * passes the tool's own documented alternative, --regex-engine stdlib,
 * VERIFIED to produce an identical finding set on this corpus (66/66
 * findings, zero symmetric difference on rule+file+line+secret) before the
 * adapter was aligned to it, the same verification precedent as the
 * gitleaks dir-vs-detect alignment. Honest cost: the corpus scan measured
 * ~11.3 s with stdlib vs ~7.1 s with re2 (cold cache), so wall time
 * reflects the non-default engine; both numbers are in tools/VERSIONS.md.
 *
 * Detection notes from the observed runs, recorded so a reader does not
 * mistake tool design for an invocation bug:
 * - its aws-access-token rule is a COMPOSITE ("Identified an AWS access key
 *   ID paired with a secret access key"; components require an
 *   aws-secret-access-key within 5 lines, per `betterleaks config show`),
 *   so a bare access-key-id plant is not reported. Same design direction as
 *   TruffleHog's pair-oriented AWS detector; gitleaks 8.30.1 reports the
 *   bare key id. This shows up honestly in the per-family table.
 * - it keeps gitleaks' documented-example allowlist behavior (filter
 *   `.+EXAMPLE$` on aws-access-token, per `betterleaks config show`), which
 *   the corpus's suppress class is designed around.
 * - overall corpus-probe finding counts were comparable to gitleaks (66 vs
 *   69), with the aws composite rule accounting for the gap and its
 *   generic-credential-uri rule adding connection-string coverage.
 */

function binaryPath(ctx) {
  const pinned = path.join(ctx.toolsDir, "bin", "betterleaks");
  if (fs.existsSync(pinned)) return pinned;
  return "betterleaks"; // PATH fallback
}

function reportPath(ctx) {
  return path.join(ctx.rawDir, "betterleaks.report.json");
}

module.exports = {
  id: "betterleaks",
  displayName: "Betterleaks",
  homepage: "https://github.com/betterleaks/betterleaks",
  kind: "binary",

  claimedClasses: ["*"],
  claimsNote:
    "Betterleaks --help: 'Betterleaks scans code, past or present, for secrets'; README: 'Betterleaks is a configurable, " +
    "fast, and thorough secrets scanner.' Its `dir` subcommand scans plain directories and files, format-agnostic, so " +
    "every corpus class is in its claimed scope (the gitleaks precedent).",

  available(ctx) {
    const pinned = path.join(ctx.toolsDir, "bin", "betterleaks");
    if (fs.existsSync(pinned)) return { ok: true };
    return {
      ok: false,
      reason: "no pinned betterleaks at bench/tools/bin/betterleaks and none guaranteed on PATH",
      installHint:
        "download betterleaks_1.8.1_darwin_arm64.tar.gz from github.com/betterleaks/betterleaks releases, verify its " +
        "sha256 against the published checksums.txt, and extract the binary to bench/tools/bin/betterleaks (exact " +
        "commands in bench/tools/VERSIONS.md; install-time network fetch, not part of any scored scan)",
    };
  },

  version(ctx) {
    return { cmd: binaryPath(ctx), args: ["version"] };
  },

  command(ctx) {
    return {
      cmd: binaryPath(ctx),
      args: [
        "dir", ctx.fixtureHome,
        "--report-format", "json",
        "--report-path", reportPath(ctx),
        "--no-banner",
        "--regex-engine", "stdlib",
      ],
      cwd: ctx.benchRoot,
      expectedExitCodes: [0, 1], // 1 = leaks found, by its own contract (--exit-code default 1)
      note:
        "filesystem (dir) mode over the fixture home; JSON report parsed from the report file. Validation stays OFF: " +
        "it is opt-in via --validation per its own docs and this benchmark never passes it (scan-only rule). " +
        "--regex-engine stdlib (its documented alternative engine) keeps the default engine's wasm compilation cache " +
        "write out of the scanned fixture; finding-set parity between the engines was verified on this corpus first.",
    };
  },

  parse(results, ctx) {
    const notes = [];
    const rp = reportPath(ctx);
    if (!fs.existsSync(rp)) {
      return { findings: [], notes: [`no report file at ${rp}; stderr: ${results[0].stderr.slice(0, 300)}`] };
    }
    let doc;
    try {
      doc = JSON.parse(fs.readFileSync(rp, "utf8"));
    } catch (e) {
      return { findings: [], notes: [`report file was not valid JSON: ${e.message}`] };
    }
    const findings = (doc || []).map((f) =>
      makeFinding({
        file: path.isAbsolute(f.File) ? f.File : path.resolve(ctx.benchRoot, f.File),
        line: f.StartLine,
        rawRule: f.RuleID,
        value: f.Secret || null,
        meta: {
          entropy: f.Entropy,
          fingerprint: f.Fingerprint,
          confidence: f.Attributes ? f.Attributes.confidence : null,
        },
      })
    );
    return { findings, notes };
  },

  staticGrepRoots() {
    return { binary: true }; // compiled Go binary; static source grep not applicable
  },
};
