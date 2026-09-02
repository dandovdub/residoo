"use strict";

const fs = require("fs");
const path = require("path");

/**
 * detect-secrets DEFAULT-MODE egress observation run (the dual-mode rule).
 *
 * detect-secrets has two documented modes: default (some plugins verify
 * candidate secrets over the network during the scan) and offline via its own
 * -n / --no-verify flag ("Disables additional verification of secrets via
 * network call.", its CLI help). Recall is scored ONLY from the offline run
 * (adapter detect-secrets.js); scoring recall in a mode that phones out would
 * conflate the recall axis with the egress axis.
 *
 * This companion adapter executes the DEFAULT mode against the same fixture
 * under the same monitored window (proxy trap + lsof), so the benchmark can
 * report factually what a default-mode scan attempts to send and where. The
 * verifying plugins in the installed 1.5.0 package (each defines verify() and
 * names its endpoint in source): aws (sts.amazonaws.com), slack
 * (slack.com/api/auth.test, hooks.slack.com), stripe (api.stripe.com),
 * telegram (api.telegram.org), mailchimp (usN.api.mailchimp.com), softlayer
 * (api.softlayer.com), ibm_cloud_iam (iam.cloud.ibm.com), ibm_cos_hmac,
 * cloudant.
 *
 * FAKE-VALUES-ONLY NOTE, stated so nobody can claim secrets were transmitted:
 * the corpus contains only pattern-true FAKE credentials that no provider
 * ever issued, so a default-mode verification attempt sends only fake values
 * at worst, and on this harness the refuse-and-log proxy trap refuses every
 * connection anyway, so no verification request ever left the machine.
 *
 * EGRESS-ONLY RECORD: findings from this run are never scored (the parser
 * returns none). The record's egressOnly field tells the scorer to attach
 * this run's observed egress to the detect-secrets row as a second, clearly
 * labeled mode line instead of scoring it as a ninth tool.
 */

const CITATION =
  "detect-secrets' own CLI help documents scan-time verification and its off-switch: " +
  "\"-n, --no-verify  Disables additional verification of secrets via network call.\" and " +
  "\"--only-verified  Only flags secrets that can be verified.\" " +
  "In the installed 1.5.0 package, detect_secrets/filters/common.py enables the verification filter " +
  "(is_ignored_due_to_verification_policies, which calls each plugin's verify()) unless -n is passed.";

function binPath(ctx) {
  return path.join(ctx.toolsDir, "uv", "bin", "detect-secrets");
}

module.exports = {
  id: "detect-secrets-default-verification",
  displayName: "detect-secrets (default mode, egress observation)",
  homepage: "https://github.com/Yelp/detect-secrets",
  kind: "python",

  // Egress-only companion run: the scorer attaches this record's observed
  // egress to the named tool's row as a second labeled mode line and never
  // scores its findings.
  egressOnly: {
    forTool: "detect-secrets",
    modeLabel: "default mode (network verification enabled)",
    citation: CITATION,
    fakeValuesNote:
      "the corpus contains only pattern-true fake credentials, so a verification attempt sends only fake values at worst; " +
      "on this harness the refuse-and-log proxy trap refuses all connections, so no verification request can leave the machine",
  },

  // Defensive: if this record is ever fed to a scorer without egress-mode
  // support, the honest rendering is a not-scored reason, never zeroes.
  notScoredForRecall: {
    reason: "egress observation run only; recall is scored from the documented offline mode (adapter detect-secrets, its -n flag)",
    citation: CITATION,
  },

  claimedClasses: ["*"],
  claimsNote:
    "same tool and claims as the detect-secrets adapter; this run exists only to observe default-mode (verification-enabled) egress " +
    "under the dual-mode rule and is never scored for recall.",

  available(ctx) {
    const bin = binPath(ctx);
    return fs.existsSync(bin)
      ? { ok: true }
      : {
          ok: false,
          reason: `detect-secrets not installed at ${bin}`,
          installHint:
            "UV_TOOL_DIR=bench/tools/uv/tools UV_TOOL_BIN_DIR=bench/tools/uv/bin uv tool install detect-secrets==1.5.0 " +
            "(pinned to the benchmarked version; install-time network fetch, not part of any scored scan)",
        };
  },

  version(ctx) {
    return { cmd: binPath(ctx), args: ["--version"] };
  },

  command(ctx) {
    return {
      cmd: binPath(ctx),
      args: ["scan", "--all-files", ctx.fixtureHome],
      cwd: ctx.benchRoot,
      expectedExitCodes: [0],
      note:
        "DEFAULT mode on purpose (no -n): observes what verification-enabled scanning attempts to send; " +
        "recall comes from the offline-mode run, never from this one",
    };
  },

  parse(results) {
    const r = results[0];
    const notes = [
      "egress observation run: findings from this mode are NOT scored; recall is scored from the offline (-n) run",
      "corpus values are pattern-true fakes and the refuse-and-log proxy trap refuses all connections, so no verification request can leave the machine",
    ];
    try {
      const doc = JSON.parse(r.stdout);
      const n = Object.values(doc.results || {}).reduce((a, v) => a + v.length, 0);
      notes.push(`default-mode baseline reported ${n} result entries (unscored; kept in the raw record for comparison with the offline run)`);
    } catch (e) {
      notes.push(`stdout was not a valid baseline JSON document: ${e.message}`);
    }
    return { findings: [], notes };
  },

  staticGrepRoots(ctx) {
    return [path.join(ctx.toolsDir, "uv", "tools", "detect-secrets")];
  },
};
