"use strict";

/**
 * Opt-in live credential verification (--verify).
 *
 * Everything else in residoo is detection only: a shape matched a pattern,
 * nothing more, zero network calls, by design (see README's "What it does
 * not do"). This module is the one deliberate exception, and only when a
 * user explicitly passes --verify: it takes an AWS access key id and its
 * paired secret (see pairing.js) and asks AWS itself whether they still
 * authenticate, via sts:get-caller-identity, the same free, read-only,
 * permission-less call AWS's own docs and tools like the AWS CLI and
 * aws-vault use for exactly this "is this credential still alive" check.
 *
 * Implemented by shelling out to the user's own `aws` CLI rather than
 * hand-rolling AWS SigV4 request signing. Two reasons, not one: first,
 * residoo ships zero runtime dependencies, and a correct SigV4
 * implementation is real, easy-to-get-subtly-wrong cryptographic code this
 * project cannot verify against a live AWS account in CI; a signing bug
 * here would silently report every real key as "invalid," which is actively
 * worse than not verifying at all. Second, the AWS CLI is exactly the
 * client AWS itself maintains and tests against its own service, so
 * whether a credential is live is answered by AWS's own tooling, not a
 * reimplementation of it.
 *
 * Every environment variable the aws CLI reads is built from scratch here,
 * never inherited from process.env: AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY
 * are set to the exact values found in the scan, and AWS_CONFIG_FILE/
 * AWS_SHARED_CREDENTIALS_FILE point at /dev/null so the CLI cannot fall
 * back to the user's own real default profile if the found credential is
 * malformed in some way that would otherwise trigger a fallback. A failed
 * verification must never silently become "verified as the operator's own
 * real AWS account" instead.
 */

const { spawnSync } = require("child_process");

const DEFAULT_TIMEOUT_MS = 8000;

/**
 * Test-only escape hatch: when RESIDOO_TEST_AWS_CLI is set, every spawnSync
 * call below runs that path instead of "aws" on PATH. Same pattern as
 * keychain.js's RESIDOO_TEST_KEYCHAIN_FILE — crosses a spawned child
 * process boundary (this project's own CLI e2e tests) via env var, so a
 * test can point at a small fixture script and exercise the real spawnSync
 * + argv + env + exit-code + stdout/stderr plumbing without ever spawning
 * the real aws CLI or touching the network. Not a documented flag: no real
 * user has a reason to set this.
 */
function awsBinary() {
  return process.env.RESIDOO_TEST_AWS_CLI || "aws";
}

/** Strip control bytes and cap length: any text here may echo an AWS error message to a terminal. */
function sanitizeDetail(s) {
  return String(s || "").replace(/[\x00-\x1f\x7f]/g, "").slice(0, 200);
}

/**
 * True if an `aws` binary is reachable on PATH and runs. Checked once per
 * scan (not once per credential) so a missing CLI produces one clear
 * message instead of N identical failures.
 */
function isAwsCliAvailable(spawnFn = spawnSync) {
  try {
    const r = spawnFn(awsBinary(), ["--version"], {
      timeout: 5000,
      env: { PATH: process.env.PATH || "" },
      stdio: ["ignore", "ignore", "ignore"],
    });
    return !r.error && r.status === 0;
  } catch {
    return false;
  }
}

/**
 * Ask AWS whether this exact access key id / secret access key pair still
 * authenticates. Returns { status, detail } where status is one of:
 *   "active"    AWS accepted the credentials (sts:get-caller-identity
 *               succeeded, or failed only on a follow-up permission check,
 *               which still proves authentication succeeded)
 *   "invalid"   AWS rejected the credentials outright (revoked, deleted,
 *               or never valid)
 *   "error"     could not determine either way (CLI missing, timeout,
 *               network failure, or an AWS error this function does not
 *               recognize) — never conflated with "invalid": an inability
 *               to check is not evidence the credential is dead.
 * Synchronous: spawnSync itself is synchronous, and calling this from a
 * plain loop (not Promise.all) means verifications run one at a time, not
 * as a burst of concurrent requests against one account.
 */
function verifyAwsCredential(accessKeyId, secretAccessKey, { spawnFn = spawnSync, timeoutMs = DEFAULT_TIMEOUT_MS } = {}) {
  let r;
  try {
    r = spawnFn(awsBinary(), ["sts", "get-caller-identity", "--output", "json"], {
      timeout: timeoutMs,
      encoding: "utf-8",
      env: {
        PATH: process.env.PATH || "",
        AWS_ACCESS_KEY_ID: accessKeyId,
        AWS_SECRET_ACCESS_KEY: secretAccessKey,
        AWS_DEFAULT_REGION: "us-east-1",
        AWS_EC2_METADATA_DISABLED: "true",
        AWS_CONFIG_FILE: "/dev/null",
        AWS_SHARED_CREDENTIALS_FILE: "/dev/null",
      },
    });
  } catch (e) {
    return { status: "error", detail: `aws CLI failed to run (${sanitizeDetail(e && e.message)})` };
  }
  if (r.error) {
    if (r.error.code === "ENOENT") return { status: "error", detail: "aws CLI not found on PATH" };
    return { status: "error", detail: `aws CLI failed to run (${sanitizeDetail(r.error.code || r.error.message)})` };
  }
  if (r.status === 0) {
    return { status: "active", detail: "AWS accepted these credentials (sts:get-caller-identity)" };
  }
  const stderr = String(r.stderr || "");
  if (/InvalidClientTokenId|SignatureDoesNotMatch|UnrecognizedClientException/.test(stderr)) {
    return { status: "invalid", detail: "AWS rejected these credentials" };
  }
  if (/AccessDenied/.test(stderr)) {
    // GetCallerIdentity needs no IAM permissions at all; an AccessDenied
    // here (rare — e.g. an explicit deny policy) still means the
    // credentials themselves authenticated before that policy was checked.
    return { status: "active", detail: "AWS accepted these credentials (denied only on a follow-up permission check)" };
  }
  return { status: "error", detail: `could not verify: ${sanitizeDetail(stderr).slice(0, 120) || `aws exited ${r.status}`}` };
}

module.exports = { isAwsCliAvailable, verifyAwsCredential };
