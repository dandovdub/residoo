"use strict";

/**
 * Opt-in live credential verification (--verify).
 *
 * Everything else in residoo is detection only: a shape matched a pattern,
 * nothing more, zero network calls, by design (see README's "What it does
 * not do"). This module is the one deliberate exception, and only when a
 * user explicitly passes --verify: it asks the credential's own vendor
 * whether it still authenticates, via whatever free, read-only check that
 * vendor documents for exactly this "is this still alive" question.
 *
 * Two different implementation strategies live in this one file, chosen
 * per vendor by how risky it would be to get wrong:
 *
 * AWS (verifyAwsCredential) shells out to the user's own `aws` CLI rather
 * than hand-rolling AWS SigV4 request signing. Two reasons, not one: first,
 * residoo ships zero runtime dependencies, and a correct SigV4
 * implementation is real, easy-to-get-subtly-wrong cryptographic code this
 * project cannot verify against a live AWS account in CI; a signing bug
 * here would silently report every real key as "invalid," which is actively
 * worse than not verifying at all. Second, the AWS CLI is exactly the
 * client AWS itself maintains and tests against its own service. Every
 * environment variable the aws CLI reads is built from scratch, never
 * inherited from process.env: AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY are
 * set to the exact values found in the scan, and AWS_CONFIG_FILE/
 * AWS_SHARED_CREDENTIALS_FILE point at /dev/null so the CLI cannot fall
 * back to the user's own real default profile if the found credential is
 * malformed in some way that would otherwise trigger a fallback.
 *
 * Slack (verifySlackToken) calls the API directly with the built-in fetch
 * instead: unlike AWS, Slack's auth check (auth.test) is a single bearer-
 * token HTTP call with no request signing at all, so there is no signing
 * bug to be worried about, and no CLI most residoo users would already
 * have installed the way they'd have the aws CLI. Direct fetch is both
 * simpler and more portable here; shelling out to a hypothetical "slack
 * CLI" would add a dependency for no safety benefit. This is the pattern
 * for any future vendor: shell out to that vendor's own official CLI only
 * when the auth scheme itself is complex enough to be worth not
 * reimplementing (AWS's SigV4); call directly for a plain bearer token.
 *
 * OpenAI, Anthropic, and GitHub (verifyOpenAiKey, verifyAnthropicKey,
 * verifyGithubToken) share one implementation (verifyByStatusCode): each is
 * a plain GET to a free, side-effect-free, already-authenticated endpoint
 * (that vendor's own "list what I can see" call), where the HTTP status
 * code alone says whether the credential authenticated. Slack needed its
 * own function because auth.test always returns HTTP 200 and signals
 * failure inside the JSON body instead of the status code.
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

/**
 * Test-only escape hatch, same purpose as RESIDOO_TEST_AWS_CLI above but for
 * an HTTP call instead of a subprocess: when RESIDOO_TEST_SLACK_API_URL is
 * set, verifySlackToken calls that URL instead of Slack's real API, so a
 * test can point at a small local HTTP server and exercise the real fetch +
 * header + JSON-parsing plumbing without ever reaching slack.com.
 */
function slackAuthTestUrl() {
  return process.env.RESIDOO_TEST_SLACK_API_URL || "https://slack.com/api/auth.test";
}

// Slack's own documented error codes for auth.test that mean the token
// itself is dead (revoked, expired, or never valid), not merely rate
// limited or a transient server problem.
const SLACK_DEAD_TOKEN_ERRORS = new Set([
  "invalid_auth", "not_authed", "token_revoked", "token_expired", "account_inactive",
]);

/**
 * Ask Slack whether this exact token still authenticates, via auth.test
 * (api.slack.com/methods/auth.test): a bearer-token-only call Slack's own
 * docs recommend for checking token validity, needing no scope of its own.
 * Same three-way { status, detail } contract as verifyAwsCredential.
 */
async function verifySlackToken(token, { fetchFn = fetch, timeoutMs = DEFAULT_TIMEOUT_MS } = {}) {
  let res;
  try {
    res = await fetchFn(slackAuthTestUrl(), {
      method: "POST",
      headers: { Authorization: `Bearer ${token}` },
      signal: AbortSignal.timeout(timeoutMs),
    });
  } catch (e) {
    return { status: "error", detail: `could not reach Slack (${sanitizeDetail(e && e.message)})` };
  }
  let body;
  try {
    body = await res.json();
  } catch (e) {
    return { status: "error", detail: `Slack returned a non-JSON response (HTTP ${res.status})` };
  }
  if (body && body.ok === true) {
    return { status: "active", detail: "Slack accepted this token (auth.test)" };
  }
  const err = body && typeof body.error === "string" ? body.error : null;
  if (err && SLACK_DEAD_TOKEN_ERRORS.has(err)) {
    return { status: "invalid", detail: `Slack rejected this token (${sanitizeDetail(err)})` };
  }
  return { status: "error", detail: `could not verify: ${sanitizeDetail(err) || `HTTP ${res.status}`}` };
}

/**
 * Shared implementation for every vendor below Slack: a plain GET to a
 * free, side-effect-free, already-authenticated endpoint (each vendor's own
 * "list what I can see" call), where the HTTP status code alone says
 * whether the credential authenticated. 200 is active; 401/403 is a real
 * rejection; anything else (429 rate limited, 5xx, a network failure) is
 * inconclusive, never guessed as either active or invalid. Slack needed its
 * own function above because its auth.test always returns HTTP 200 and
 * signals failure inside the JSON body instead.
 */
async function verifyByStatusCode(vendorName, url, buildHeaders, { fetchFn = fetch, timeoutMs = DEFAULT_TIMEOUT_MS } = {}) {
  let res;
  try {
    res = await fetchFn(url, {
      method: "GET",
      headers: buildHeaders(),
      signal: AbortSignal.timeout(timeoutMs),
    });
  } catch (e) {
    return { status: "error", detail: `could not reach ${vendorName} (${sanitizeDetail(e && e.message)})` };
  }
  if (res.status === 200) {
    return { status: "active", detail: `${vendorName} accepted this key` };
  }
  if (res.status === 401 || res.status === 403) {
    return { status: "invalid", detail: `${vendorName} rejected this key (HTTP ${res.status})` };
  }
  return { status: "error", detail: `could not verify: HTTP ${res.status} from ${vendorName}` };
}

// Test-only escape hatches, same purpose and pattern as
// RESIDOO_TEST_SLACK_API_URL above: when set, the matching verify function
// calls that URL instead of the vendor's real one.
function openAiModelsUrl() {
  return process.env.RESIDOO_TEST_OPENAI_API_URL || "https://api.openai.com/v1/models";
}
function anthropicModelsUrl() {
  return process.env.RESIDOO_TEST_ANTHROPIC_API_URL || "https://api.anthropic.com/v1/models";
}
function githubUserUrl() {
  return process.env.RESIDOO_TEST_GITHUB_API_URL || "https://api.github.com/user";
}

/** OpenAI: GET /v1/models, a free, read-only call that needs only a valid key, no usage cost. */
function verifyOpenAiKey(key, opts) {
  return verifyByStatusCode("OpenAI", openAiModelsUrl(), () => ({ Authorization: `Bearer ${key}` }), opts);
}

/**
 * Anthropic: GET /v1/models. Two headers, not one, and NOT an Authorization
 * Bearer header: Anthropic's API takes the key as x-api-key, and every
 * request needs an anthropic-version header regardless of endpoint.
 */
function verifyAnthropicKey(key, opts) {
  return verifyByStatusCode("Anthropic", anthropicModelsUrl(), () => ({
    "x-api-key": key,
    "anthropic-version": "2023-06-01",
  }), opts);
}

/** GitHub: GET /user with the token, a free, read-only call that needs no scopes. */
function verifyGithubToken(token, opts) {
  return verifyByStatusCode("GitHub", githubUserUrl(), () => ({ Authorization: `Bearer ${token}` }), opts);
}

module.exports = {
  isAwsCliAvailable, verifyAwsCredential, verifySlackToken,
  verifyOpenAiKey, verifyAnthropicKey, verifyGithubToken,
};
