"use strict";

const fs = require("fs");
const path = require("path");

/**
 * ggshield (GitGuardian CLI): the honest treatment of a scanner whose
 * scanning is server-side by design.
 *
 * DESIGN DECISION, stated in full so a hostile reader finds it answered:
 *
 * - No GitGuardian account is created for this benchmark. Scoring ggshield's
 *   recall would require sending the corpus content to GitGuardian's server,
 *   which is exactly the behavior axis this benchmark measures. Its recall
 *   column therefore reads "not scored (requires server account)". It is
 *   NEVER reported as zero recall; zero would be false and unfair.
 *
 * - The adapter runs ggshield's own scan command unauthenticated and records
 *   the observed behavior verbatim. Observed on v1.54.0: exit code 3 and
 *   "Error: A GitGuardian API key is needed to use ggshield." before any
 *   scanning. That observed auth demand is the evidence of server
 *   dependency, recorded in the raw output.
 *
 * - The PRIMARY by-design citation is ggshield's own README, which describes
 *   exactly the subcommand this benchmark invokes (secret scan): "ggshield
 *   uses our public API through py-gitguardian to scan and detect potential
 *   vulnerabilities in files and other text content." (verbatim in the
 *   installed package's dist-info METADATA and in tools/VERSIONS.md). The
 *   v1.53.0 changelog quote about the AI-activity feature ("ships it to
 *   GitGuardian, which scans the content and strips secrets server-side")
 *   is kept as the SECONDARY citation for the AI-agent surface specifically;
 *   it describes `ggshield ai discover --activity`, not the invoked
 *   `secret scan path`. Egress verdict: by-design-requires-server.
 *
 * - Fairness nuance carried from the research round: ggshield can point at a
 *   self-hosted GitGuardian instance (--instance), so "requires server" does
 *   not necessarily mean "requires GitGuardian's cloud". The citation field
 *   carries this nuance too.
 */

const CITATION =
  "ggshield README (GitGuardian), describing the invoked `secret scan` command: \"ggshield uses our public API through " +
  "py-gitguardian to scan and detect potential vulnerabilities in files and other text content.\" " +
  "For the AI-agent surface specifically, the ggshield v1.53.0 changelog on `ai discover --activity`: it collects raw agent " +
  "activity and \"ships it to GitGuardian, which scans the content and strips secrets server-side\". " +
  "Nuance: ggshield supports self-hosted instances via --instance, so the required server need not be GitGuardian's cloud.";

function binPath(ctx) {
  return path.join(ctx.toolsDir, "uv", "bin", "ggshield");
}

module.exports = {
  id: "ggshield",
  displayName: "ggshield (GitGuardian)",
  homepage: "https://github.com/GitGuardian/ggshield",
  kind: "python",

  claimedClasses: ["*"],
  claimsNote:
    "ggshield docs: 'secret scan path -r' scans any directory tree, and since v1.53 it parses AI-agent transcripts explicitly. " +
    "Claim scope is everything; recall is still not scored here because scanning requires a server account (see notScoredForRecall).",

  notScoredForRecall: {
    reason: "not scored (requires server account)",
    citation: CITATION,
  },

  byDesignEgress: {
    citation: CITATION,
    detail:
      "Observed unauthenticated on this harness: the scan command refuses to run without a GitGuardian API key " +
      "(exit 3, 'A GitGuardian API key is needed to use ggshield'), which is the server dependency demonstrated live.",
  },

  available(ctx) {
    const bin = binPath(ctx);
    return fs.existsSync(bin)
      ? { ok: true }
      : {
          ok: false,
          reason: `ggshield not installed at ${bin}`,
          installHint:
            "UV_TOOL_DIR=bench/tools/uv/tools UV_TOOL_BIN_DIR=bench/tools/uv/bin uv tool install ggshield==1.54.0 " +
            "(pinned to the benchmarked version; install-time network fetch, not part of any scored scan)",
        };
  },

  version(ctx) {
    return { cmd: binPath(ctx), args: ["--version"] };
  },

  command(ctx) {
    return {
      cmd: binPath(ctx),
      args: ["secret", "scan", "path", "-r", ctx.fixtureHome],
      cwd: ctx.benchRoot,
      // 3 = its observed "no API key" refusal; 0/1 kept in case a future
      // version scans without auth (that would be new evidence to record).
      expectedExitCodes: [0, 1, 3],
      note: "run UNAUTHENTICATED on purpose; the auth refusal is the recorded evidence of server dependency",
    };
  },

  parse(results) {
    const r = results[0];
    const notes = [
      `unauthenticated run exit=${r.exitCode}`,
      (r.stderr || r.stdout).trim().split("\n")[0] || "(no output)",
      "recall not scored: scanning requires a server account; see notScoredForRecall citation",
    ];
    return { findings: [], notes };
  },

  staticGrepRoots(ctx) {
    return [path.join(ctx.toolsDir, "uv", "tools", "ggshield")];
  },
};
