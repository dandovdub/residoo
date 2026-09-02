"use strict";

const fs = require("fs");
const path = require("path");
const { makeFinding } = require("../lib");

/**
 * TruffleHog (trufflesecurity/trufflehog) in filesystem mode, OFFLINE:
 *
 *   trufflehog filesystem <fixture home> --json --no-verification
 *       --results=verified,unknown,unverified --no-update
 *
 * DUAL-MODE RULE (see also adapters/trufflehog-default-verification.js):
 * TruffleHog verifies findings against provider APIs by default (its README:
 * "For every potential credential that is detected, we've painstakingly
 * implemented programmatic verification against the API that we think it
 * belongs to."). Scoring recall in that default mode would conflate the
 * recall axis with the egress axis, so recall is scored in the tool's OWN
 * documented offline mode: `--no-verification` ("Don't verify the results.",
 * its --help). The default mode's scan-time egress is observed separately by
 * the trufflehog-default-verification adapter and reported factually.
 *
 * RESULTS FLAG, load-bearing for fairness: some TruffleHog versions printed
 * only verified findings by default, which would zero an offline run. On the
 * benchmarked 3.97.2 the --results help text reads "Defaults to
 * verified,unverified,unknown", so unverified findings ARE printed; the
 * adapter still passes --results=verified,unknown,unverified explicitly so
 * the invocation stays correct even on versions with a different default,
 * and so the intent is visible in the raw record.
 *
 * --no-update is TruffleHog's own documented off-switch ("Don't check for
 * updates.") for its startup update check; the scored offline scan must be
 * network-free by the tool's own flags, and the update check's default-on
 * behavior is observed and reported on the egress axis by the
 * default-verification run instead (same treatment as agentsweep's TTY
 * update check in v1).
 *
 * Exit code: 0 observed both with and without findings (183 is opt-in via
 * --fail, which this adapter does not pass).
 *
 * Output: JSON Lines on stdout, one object per finding:
 *   SourceMetadata.Data.Filesystem.{file,line}  absolute path, 1-based line
 *   DetectorName                                e.g. Github, Slack, Postgres
 *   Raw / RawV2                                 the matched secret text
 *   DecoderName                                 PLAIN, BASE64, ...
 *   Verified                                    false in offline mode
 * Logs go to stderr (kept verbatim in the raw record).
 *
 * Parser notes from the observed sample runs (bench/tools/samples/):
 * - line is 1-based and matches planted lines exactly for PLAIN findings;
 *   for BASE64-decoded findings (DecoderName: BASE64) the reported line was
 *   observed one below the encoded line, but Raw carries the DECODED value,
 *   so the exact-value tier credits those correctly.
 * - for structured detectors (e.g. Postgres) Raw can be a normalized
 *   reconstruction rather than the verbatim planted text; the file+line tier
 *   catches those.
 * - its AWS detector is pair-oriented (key id verified together with a
 *   secret key); a bare access-key-id plant was not reported in sample runs.
 *   That is detector design, reported as recall, not an invocation error.
 */

function binaryPath(ctx) {
  const pinned = path.join(ctx.toolsDir, "bin", "trufflehog");
  if (fs.existsSync(pinned)) return pinned;
  return "trufflehog"; // PATH fallback
}

function parseJsonlFindings(results, notes) {
  const findings = [];
  for (const r of results) {
    for (const line of (r.stdout || "").split("\n")) {
      if (!line.trim()) continue;
      let f;
      try {
        f = JSON.parse(line);
      } catch (e) {
        notes.push(`stdout line was not valid JSON (skipped): ${line.slice(0, 120)}`);
        continue;
      }
      const fsMeta =
        (f.SourceMetadata && f.SourceMetadata.Data && f.SourceMetadata.Data.Filesystem) || {};
      findings.push(
        makeFinding({
          file: fsMeta.file || null,
          line: fsMeta.line,
          rawRule: f.DetectorName,
          value: f.Raw || null,
          meta: {
            rawV2: f.RawV2 || null,
            decoder: f.DecoderName,
            verified: f.Verified,
            detectorType: f.DetectorType,
          },
        })
      );
    }
  }
  return findings;
}

module.exports = {
  id: "trufflehog",
  displayName: "TruffleHog",
  homepage: "https://github.com/trufflesecurity/trufflehog",
  kind: "binary",

  claimedClasses: ["*"],
  claimsNote:
    "TruffleHog README (shipped in the release tarball): 'Find leaked credentials.' and 'TruffleHog can look for secrets in " +
    "many places including Git, chats, wikis, logs, API testing platforms, object stores, filesystems and more.' Its " +
    "`filesystem` subcommand ('Find credentials in a filesystem.', --help) scans any directory tree, so every corpus class " +
    "is in its claimed scope.",

  available(ctx) {
    const pinned = path.join(ctx.toolsDir, "bin", "trufflehog");
    if (fs.existsSync(pinned)) return { ok: true };
    return {
      ok: false,
      reason: "no pinned trufflehog at bench/tools/bin/trufflehog and none guaranteed on PATH",
      installHint:
        "download trufflehog_3.97.2_darwin_arm64.tar.gz from github.com/trufflesecurity/trufflehog releases, verify its " +
        "sha256 against the published trufflehog_3.97.2_checksums.txt, and extract the binary to bench/tools/bin/trufflehog " +
        "(exact commands in bench/tools/VERSIONS.md; install-time network fetch, not part of any scored scan)",
    };
  },

  version(ctx) {
    return { cmd: binaryPath(ctx), args: ["--version"] };
  },

  command(ctx) {
    return {
      cmd: binaryPath(ctx),
      args: [
        "filesystem", ctx.fixtureHome,
        "--json",
        "--no-verification",
        "--results=verified,unknown,unverified",
        "--no-update",
      ],
      cwd: ctx.benchRoot,
      expectedExitCodes: [0], // 0 observed with and without findings; 183 only with the --fail opt-in, which is not passed
      note:
        "SCORED OFFLINE MODE per the dual-mode rule: --no-verification is TruffleHog's own documented offline flag; " +
        "--results passed explicitly so unverified findings are always printed; --no-update is its documented " +
        "update-check off-switch. Default-mode egress is observed by the trufflehog-default-verification adapter.",
    };
  },

  parse(results) {
    const notes = [];
    const findings = parseJsonlFindings(results, notes);
    notes.push(
      "JSONL stdout parsed (SourceMetadata.Data.Filesystem file/line, DetectorName, Raw); BASE64-decoded findings carry " +
      "the decoded value in Raw and can report the line one below the encoded site (observed), so they match at the " +
      "exact-value tier"
    );
    return { findings, notes };
  },

  // Shared with the default-verification variant so the two modes can never
  // drift apart in parsing.
  parseJsonlFindings,

  staticGrepRoots() {
    return { binary: true }; // compiled Go binary; static source grep not applicable
  },
};
