"use strict";

const base = require("./trufflehog");

/**
 * TruffleHog DEFAULT-MODE egress observation run (the second half of the
 * dual-mode rule; the scored offline run is adapters/trufflehog.js).
 *
 * What this run is: `trufflehog filesystem <fixture home> --json` with no
 * offline flags, i.e. the tool's out-of-the-box behavior, executed against
 * the corpus inside the monitored window (proxy trap + lsof). Verification
 * is on by default per TruffleHog's own README: "For every potential
 * credential that is detected, we've painstakingly implemented programmatic
 * verification against the API that we think it belongs to." The startup
 * update check is also on by default (--no-update exists to disable it).
 * Whatever connection attempts occur are recorded with their destinations
 * and reported factually; the CONNECT targets in the raw record let a
 * reader distinguish verification endpoints from the update check.
 *
 * Methodology facts, stated so nobody can claim this benchmark transmitted
 * secrets: every credential in the corpus is a pattern-true FAKE that no
 * provider ever issued, so a verification attempt could at worst transmit a
 * fake value; and the harness proxy trap refuses every connection, so no
 * request body leaves the machine on this harness at all. What is recorded
 * is the ATTEMPT and its destination, which is exactly the egress axis.
 *
 * This run's recall is deliberately NOT scored (notScoredForRecall below):
 * scoring recall in a mode that phones out would conflate the two axes.
 * Findings are still parsed and persisted as evidence of what default mode
 * reports on this harness (with verification refused by the trap, findings
 * fall under its documented "unknown (verification failed due to error)"
 * result type, which is in the default --results set).
 */

module.exports = {
  id: "trufflehog-default-verification",
  displayName: "TruffleHog (default mode, egress observation)",
  homepage: base.homepage,
  kind: base.kind,

  claimedClasses: base.claimedClasses,
  claimsNote: base.claimsNote,

  // Dual-mode companion record: the scorer attaches this run's observed
  // egress to the trufflehog row as a second, clearly labeled mode line
  // (egressModes in scoreboard.json) and never scores it as a separate tool.
  egressOnly: {
    forTool: "trufflehog",
    modeLabel: "default mode (verification enabled)",
    citation:
      "TruffleHog README (shipped in the release tarball): 'For every potential credential that is detected, we've " +
      "painstakingly implemented programmatic verification against the API that we think it belongs to.' Offline flag " +
      "per its --help: --no-verification, 'Don't verify the results.'",
    fakeValuesNote:
      "every planted credential is a pattern-true fake no provider ever issued, and the refuse-and-log proxy trap " +
      "refuses all connections, so at worst an ATTEMPT carrying fake values is observed; nothing reaches any provider " +
      "on this harness",
  },

  notScoredForRecall: {
    reason:
      "not scored for recall: egress-observation run of the tool's default mode (live verification on). Recall is " +
      "scored in its documented offline mode by the trufflehog adapter.",
    citation:
      "TruffleHog README (shipped in the release tarball): 'For every potential credential that is detected, we've " +
      "painstakingly implemented programmatic verification against the API that we think it belongs to.' Offline flag " +
      "per its --help: --no-verification, 'Don't verify the results.' This run omits that flag on purpose and reports " +
      "observed connection attempts factually. Corpus note: every planted credential is a pattern-true fake no provider " +
      "ever issued, and the harness proxy trap refuses every connection, so at worst an ATTEMPT carrying fake values is " +
      "observed; nothing reaches any provider on this harness.",
  },

  available: base.available,
  version: base.version,

  command(ctx) {
    return {
      cmd: base.version(ctx).cmd,
      args: ["filesystem", ctx.fixtureHome, "--json"],
      cwd: ctx.benchRoot,
      expectedExitCodes: [0],
      note:
        "DEFAULT MODE on purpose (no --no-verification, no --no-update): observes what an out-of-the-box run attempts " +
        "to send, with destinations recorded by the proxy trap and lsof layers",
    };
  },

  parse(results) {
    const notes = [];
    const findings = base.parseJsonlFindings(results, notes);
    notes.push(
      "default-mode run: findings recorded as evidence only (recall scored by the trufflehog adapter's offline run); " +
      "verification attempts against the refuse-and-log trap surface findings as its 'unknown' result type"
    );
    return { findings, notes };
  },

  staticGrepRoots: base.staticGrepRoots,
};
