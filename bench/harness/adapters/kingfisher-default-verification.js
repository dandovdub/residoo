"use strict";

const base = require("./kingfisher");

/**
 * Kingfisher DEFAULT-MODE egress observation run (the second half of the
 * dual-mode rule; the scored offline run is adapters/kingfisher.js).
 *
 * What this run is: `kingfisher scan <fixture home> --format jsonl
 * --no-dedup --no-rule-cache` with validation and the update check left at
 * their defaults, executed against the corpus inside the monitored window
 * (proxy trap + lsof). Validation is on by default per Kingfisher's own
 * README: "Validate discovered credentials against provider APIs to reduce
 * false positives"; the automatic update check is also on by default
 * (--no-update-check exists to disable it, and a --no-validate run on this
 * machine still reported update_check_status "ok" in its scan summary).
 * Whatever connection attempts occur are recorded with their destinations
 * and reported factually; CONNECT targets in the raw record let a reader
 * distinguish validation endpoints from the update check.
 *
 * Two flags are kept from the offline invocation because they do not touch
 * the network axis: --format jsonl (output parity with the scored run) and
 * --no-rule-cache (without it Kingfisher writes its compiled-rule cache
 * under HOME, which the harness pins inside the scanned fixture; the
 * benchmark's write-protection rule keeps the scanned tree byte-stable in
 * every mode). --no-dedup is likewise reporting-only.
 *
 * Methodology facts, stated so nobody can claim this benchmark transmitted
 * secrets: every credential in the corpus is a pattern-true FAKE that no
 * provider ever issued, so a validation attempt could at worst transmit a
 * fake value; and the harness proxy trap refuses every connection, so no
 * request body leaves the machine on this harness at all. What is recorded
 * is the ATTEMPT and its destination, which is exactly the egress axis.
 *
 * This run's recall is deliberately NOT scored (notScoredForRecall below):
 * scoring recall in a mode that phones out would conflate the two axes.
 * Findings are still parsed and persisted as evidence of what default mode
 * reports on this harness.
 */

module.exports = {
  id: "kingfisher-default-verification",
  displayName: "Kingfisher (default mode, egress observation)",
  homepage: base.homepage,
  kind: base.kind,

  claimedClasses: base.claimedClasses,
  claimsNote: base.claimsNote,

  // Dual-mode companion record: the scorer attaches this run's observed
  // egress to the kingfisher row as a second, clearly labeled mode line
  // (egressModes in scoreboard.json) and never scores it as a separate tool.
  egressOnly: {
    forTool: "kingfisher",
    modeLabel: "default mode (validation enabled)",
    citation:
      "Kingfisher README: 'Validate discovered credentials against provider APIs to reduce false positives'; its " +
      "top-level help: 'Detect and validate secrets across files and full Git history'. Offline flag per its --help: " +
      "--no-validate, 'Disable secret validation'.",
    fakeValuesNote:
      "every planted credential is a pattern-true fake no provider ever issued, and the refuse-and-log proxy trap " +
      "refuses all connections, so at worst an ATTEMPT carrying fake values is observed; nothing reaches any provider " +
      "on this harness",
  },

  notScoredForRecall: {
    reason:
      "not scored for recall: egress-observation run of the tool's default mode (live validation on). Recall is " +
      "scored in its documented offline mode by the kingfisher adapter.",
    citation:
      "Kingfisher README: 'Validate discovered credentials against provider APIs to reduce false positives'; its " +
      "top-level help: 'Detect and validate secrets across files and full Git history'. Offline flag per its --help: " +
      "--no-validate, 'Disable secret validation'. This run omits that flag on purpose and reports observed connection " +
      "attempts factually. Corpus note: every planted credential is a pattern-true fake no provider ever issued, and " +
      "the harness proxy trap refuses every connection, so at worst an ATTEMPT carrying fake values is observed; " +
      "nothing reaches any provider on this harness.",
  },

  available: base.available,
  version: base.version,

  command(ctx) {
    return {
      cmd: base.version(ctx).cmd,
      args: [
        "scan", ctx.fixtureHome,
        "--format", "jsonl",
        "--no-dedup",
        "--no-rule-cache",
      ],
      cwd: ctx.benchRoot,
      // 205 = "Validated findings discovered" per its README; reachable here
      // in principle, though not expected against fake values and a
      // refusing trap. 200 = findings, 0 = none.
      expectedExitCodes: [0, 200, 205],
      note:
        "DEFAULT MODE on purpose (no --no-validate, no --no-update-check): observes what an out-of-the-box run " +
        "attempts to send, with destinations recorded by the proxy trap and lsof layers; --no-rule-cache kept only to " +
        "keep the scanned fixture byte-stable (its cache default lives under HOME)",
    };
  },

  parse(results) {
    const notes = [];
    const findings = base.parseJsonlFindings(results, notes);
    notes.push(
      "default-mode run: findings recorded as evidence only (recall scored by the kingfisher adapter's offline run); " +
      "the summary line's validation counters and update_check_status are quoted above"
    );
    return { findings, notes };
  },

  staticGrepRoots: base.staticGrepRoots,
};
