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
 * whether the credential authenticated. 200 is active by default; 401/403
 * is a real rejection by default; anything else (429 rate limited, 5xx, a
 * network failure) is inconclusive, never guessed as either active or
 * invalid. Slack needed its own function above because its auth.test
 * always returns HTTP 200 and signals failure inside the JSON body
 * instead.
 *
 * invalidStatuses/activeExtra override the defaults for the handful of
 * vendors whose docs document a DIFFERENT meaning for a given code: Discord
 * signals a dead webhook with 404, not 401/403; Pinecone, SendGrid, and
 * GitLab each document 403 as "the credential is real but this specific
 * call is out of scope," not "dead" — treating that as invalid would be
 * exactly the false-negative-in-the-dangerous-direction failure this
 * module exists to avoid, so those three pass 403 in activeExtra instead.
 */
async function verifyByStatusCode(vendorName, url, buildHeaders, {
  fetchFn = fetch, timeoutMs = DEFAULT_TIMEOUT_MS,
  invalidStatuses = [401, 403], activeExtra = [],
} = {}) {
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
  if (res.status === 200 || activeExtra.includes(res.status)) {
    return { status: "active", detail: `${vendorName} accepted this key` };
  }
  if (invalidStatuses.includes(res.status)) {
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

// ── The rest of this file: 18 more vendors added after researching ~65
// candidates against real vendor docs and open-source scanner source (see
// the project's verification coverage research). Each one below already
// has a residoo detection rule (src/patterns.js) with a specific enough
// prefix that wiring it to a vendor is safe; several confirmed-viable
// vendors from that research are deliberately NOT here, for reasons worth
// stating precisely rather than silently omitting:
//   - google_api_key, perplexity_key: DETECTED, but not wired. A Google API
//     key can belong to any Google product (Maps, Firebase, Gemini, ...),
//     and residoo's detection can't tell which; testing it against
//     Gemini's endpoint specifically would report a perfectly valid Maps
//     key as "invalid" — the exact false-negative-in-the-dangerous-
//     direction failure this file exists to avoid. Perplexity has no free,
//     side-effect-free endpoint at all (only a paid /chat/completions).
//   - Cohere, Mistral, Together AI, Fireworks, DeepSeek: not detected in
//     the first place (see patterns.js's own comment on this), so wiring a
//     verifier would be dead code — verification needs detection first.
//   - Linode / Akamai Cloud: researched twice, ruled out both times, the
//     second time more conclusively than the first: its own OpenAPI schema
//     documents the token as a bare opaque string with no prefix
//     whatsoever, not merely an undocumented one, so this is not something
//     a future docs update could fix.
// Two vendors that were deferred in an earlier pass are no longer on this
// list, once their real formats or engineering were worked out: PlanetScale
// (see verifyPlanetScaleToken below and pairing.js's findNearbyCandidate,
// generalized from AWS's own pairing mechanism to cover its id/secret
// pair) and Fly.io's fo1_ token family (see verifyFlyioBearerToken below).
// Fly.io's OTHER token family, fm1a_/fm1r_/fm2_ "macaroons," stays
// undetected: caught live on this project's own real-machine testing, that
// shape's short prefix plus a wide, unstructured base64 body produced
// dozens of apparent matches inside an unrelated real file that just
// happened to contain a lot of embedded base64 data. See patterns.js's own
// comment on flyio_bearer_token for the measured false-positive rate.
//
// A second, independent research pass (11 candidate vendors, each
// researched and then adversarially cross-checked by a separate reviewer
// before being trusted) added three more: Neon (verifyNeonKey), MongoDB
// Atlas Service Account credentials (verifyMongoDbAtlasCredential, a third
// paired vendor alongside AWS and PlanetScale), and PostHog
// (verifyPostHogKey). The other eight were rejected, each for a documented,
// vendor-specific reason rather than lack of trying:
//   - Clerk, Auth0, Upstash, Turso, Railway, Segment, Algolia: no
//     distinguishing, documented credential prefix could be confirmed from
//     the vendor's own current docs (some have a prefix on one credential
//     type but no working verify endpoint for it, or a prefix that isn't
//     actually vendor-specific enough to trust).
//   - Convex: the researcher's own first pass recommended adding it, but
//     the adversarial reviewer refuted that recommendation on independent
//     re-checking of the same sources — the exact reason this project runs
//     research and verification as two separate, disagreeing passes rather
//     than trusting one agent's first read of the docs.

function huggingfaceUrl() { return process.env.RESIDOO_TEST_HUGGINGFACE_API_URL || "https://huggingface.co/api/whoami-v2"; }
function sendgridUrl() { return process.env.RESIDOO_TEST_SENDGRID_API_URL || "https://api.sendgrid.com/v3/scopes"; }
function replicateUrl() { return process.env.RESIDOO_TEST_REPLICATE_API_URL || "https://api.replicate.com/v1/account"; }
function digitaloceanUrl() { return process.env.RESIDOO_TEST_DIGITALOCEAN_API_URL || "https://api.digitalocean.com/v2/account"; }
function pineconeUrl() { return process.env.RESIDOO_TEST_PINECONE_API_URL || "https://api.pinecone.io/indexes"; }
function groqUrl() { return process.env.RESIDOO_TEST_GROQ_API_URL || "https://api.groq.com/openai/v1/models"; }
function xaiUrl() { return process.env.RESIDOO_TEST_XAI_API_URL || "https://api.x.ai/v1/api-key"; }
function openrouterUrl() { return process.env.RESIDOO_TEST_OPENROUTER_API_URL || "https://openrouter.ai/api/v1/key"; }
function stripeUrl() { return process.env.RESIDOO_TEST_STRIPE_API_URL || "https://api.stripe.com/v1/balance"; }
function npmUrl() { return process.env.RESIDOO_TEST_NPM_API_URL || "https://registry.npmjs.org/-/whoami"; }
function notionUrl() { return process.env.RESIDOO_TEST_NOTION_API_URL || "https://api.notion.com/v1/users"; }
function gitlabUrl() { return process.env.RESIDOO_TEST_GITLAB_API_URL || "https://gitlab.com/api/v4/user"; }
function supabaseUrl() { return process.env.RESIDOO_TEST_SUPABASE_API_URL || "https://api.supabase.com/v1/projects"; }
function elevenlabsUrl() { return process.env.RESIDOO_TEST_ELEVENLABS_API_URL || "https://api.elevenlabs.io/v1/user"; }
function circleciUrl() { return process.env.RESIDOO_TEST_CIRCLECI_API_URL || "https://circleci.com/api/v2/me"; }
function airtableUrl() { return process.env.RESIDOO_TEST_AIRTABLE_API_URL || "https://api.airtable.com/v0/meta/whoami"; }
function cloudflareUrl() { return process.env.RESIDOO_TEST_CLOUDFLARE_API_URL || "https://api.cloudflare.com/client/v4/user/tokens/verify"; }
function herokuUrl() { return process.env.RESIDOO_TEST_HEROKU_API_URL || "https://api.heroku.com/account"; }
function netlifyUrl() { return process.env.RESIDOO_TEST_NETLIFY_API_URL || "https://api.netlify.com/api/v1/sites"; }
function linearUrl() { return process.env.RESIDOO_TEST_LINEAR_API_URL || "https://api.linear.app/graphql"; }
function telegramUrl(token) {
  const base = process.env.RESIDOO_TEST_TELEGRAM_API_URL || "https://api.telegram.org";
  return `${base}/bot${token}/getMe`;
}

function verifyHuggingFaceToken(token, opts) {
  return verifyByStatusCode("Hugging Face", huggingfaceUrl(), () => ({ Authorization: `Bearer ${token}` }), opts);
}
function verifyReplicateToken(token, opts) {
  return verifyByStatusCode("Replicate", replicateUrl(), () => ({ Authorization: `Bearer ${token}` }), opts);
}
function verifyDigitalOceanToken(token, opts) {
  return verifyByStatusCode("DigitalOcean", digitaloceanUrl(), () => ({ Authorization: `Bearer ${token}` }), opts);
}
/** 403 from SendGrid's own /v3/scopes means the key is real but lacks the scope for this call, not that it's dead — trufflehog's own detector treats it identically. */
function verifySendgridKey(key, opts) {
  return verifyByStatusCode("SendGrid", sendgridUrl(), () => ({ Authorization: `Bearer ${key}` }), { ...opts, activeExtra: [403] });
}
/** 403 from Pinecone means the key is real but lacks control-plane permissions, not that it's dead. */
function verifyPineconeKey(key, opts) {
  return verifyByStatusCode("Pinecone", pineconeUrl(), () => ({ "Api-Key": key }), { ...opts, activeExtra: [403] });
}
function verifyGroqKey(key, opts) {
  return verifyByStatusCode("Groq", groqUrl(), () => ({ Authorization: `Bearer ${key}` }), opts);
}
function verifyXaiKey(key, opts) {
  return verifyByStatusCode("xAI", xaiUrl(), () => ({ Authorization: `Bearer ${key}` }), opts);
}
function verifyOpenRouterKey(key, opts) {
  return verifyByStatusCode("OpenRouter", openrouterUrl(), () => ({ Authorization: `Bearer ${key}` }), opts);
}
/** Stripe: HTTP Basic auth, the key as username and an empty password — NOT a Bearer header. */
function verifyStripeKey(key, opts) {
  return verifyByStatusCode("Stripe", stripeUrl(), () => ({
    Authorization: `Basic ${Buffer.from(`${key}:`).toString("base64")}`,
  }), opts);
}
function verifyNpmToken(token, opts) {
  return verifyByStatusCode("npm", npmUrl(), () => ({ Authorization: `Bearer ${token}` }), opts);
}
/** Notion requires an explicit API version header on every request, regardless of endpoint. */
function verifyNotionToken(token, opts) {
  return verifyByStatusCode("Notion", notionUrl(), () => ({
    Authorization: `Bearer ${token}`,
    "Notion-Version": "2022-06-28",
  }), opts);
}
/**
 * GitLab's own docs recommend PRIVATE-TOKEN over a Bearer header for
 * personal access tokens. 403 there means valid token, wrong scope for
 * this specific call (trufflehog's own detector treats it the same way,
 * except when the response body says the account itself is blocked — a
 * rare enough edge case, and one where reporting "active" instead of
 * "invalid" is the safe direction to be wrong in, that this doesn't
 * special-case it further).
 */
function verifyGitlabToken(token, opts) {
  return verifyByStatusCode("GitLab", gitlabUrl(), () => ({ "PRIVATE-TOKEN": token }), { ...opts, activeExtra: [403] });
}
/** The Supabase Management API personal access token (sbp_ prefix) only — project-scoped anon/service_role keys need a project URL residoo doesn't have and are not verifiable this way. */
function verifySupabaseToken(token, opts) {
  return verifyByStatusCode("Supabase", supabaseUrl(), () => ({ Authorization: `Bearer ${token}` }), opts);
}
function verifyElevenLabsKey(key, opts) {
  return verifyByStatusCode("ElevenLabs", elevenlabsUrl(), () => ({ "xi-api-key": key }), opts);
}
function verifyCircleciToken(token, opts) {
  return verifyByStatusCode("CircleCI", circleciUrl(), () => ({ "Circle-Token": token }), opts);
}
function verifyAirtableToken(token, opts) {
  return verifyByStatusCode("Airtable", airtableUrl(), () => ({ Authorization: `Bearer ${token}` }), opts);
}
/**
 * Cloudflare's own /user/tokens/verify endpoint exists for exactly this
 * check (its whole purpose, per Cloudflare's docs, is confirming a
 * token's validity), so treating any HTTP 200 from THIS SPECIFIC endpoint
 * as active is a documented guarantee, not an approximation the way it
 * would be for a generic "list resources" endpoint.
 */
function verifyCloudflareToken(token, opts) {
  return verifyByStatusCode("Cloudflare", cloudflareUrl(), () => ({ Authorization: `Bearer ${token}` }), opts);
}
function verifyHerokuKey(key, opts) {
  return verifyByStatusCode("Heroku", herokuUrl(), () => ({
    Authorization: `Bearer ${key}`,
    Accept: "application/vnd.heroku+json; version=3",
  }), opts);
}
function verifyNetlifyToken(token, opts) {
  return verifyByStatusCode("Netlify", netlifyUrl(), () => ({ Authorization: `Bearer ${token}` }), opts);
}

function planetscaleUrl() { return process.env.RESIDOO_TEST_PLANETSCALE_API_URL || "https://api.planetscale.com/v1/organizations"; }
/**
 * PlanetScale: a paired credential (like AWS), not a single token — the
 * Authorization header is the literal "<id>:<token>", no Bearer/Basic
 * prefix, verbatim from PlanetScale's own docs' curl example.
 */
function verifyPlanetScaleToken(id, secret, opts) {
  return verifyByStatusCode("PlanetScale", planetscaleUrl(), () => ({ Authorization: `${id}:${secret}` }), opts);
}

function mongodbAtlasUrl() { return process.env.RESIDOO_TEST_MONGODB_ATLAS_API_URL || "https://cloud.mongodb.com/api/oauth/token"; }
/**
 * MongoDB Atlas Service Account credentials: also a paired credential (like
 * AWS and PlanetScale), but the actual verify call is an OAuth2 client-
 * credentials token exchange, not a plain bearer-token GET -- POST, Basic-
 * auth-encoded clientId:clientSecret, grant_type=client_credentials in the
 * body -- so it needs its own function rather than verifyByStatusCode,
 * which is GET-only.
 *
 * A bare 403 is NOT treated as "invalid" here: MongoDB Atlas's own docs
 * confirm it also returns 403 when the caller's IP isn't on the service
 * account's access list, which says nothing about whether the credential
 * itself is still alive -- the same "real but out of scope" ambiguity
 * GitLab/CircleCI/Airtable get elsewhere via activeExtra, except MongoDB
 * signals it in the response BODY, not a separate status code. Only the
 * documented invalid_client body is treated as a genuine "this credential
 * is dead" signal; every other 403 stays "error", never a false "invalid" --
 * the false-negative-in-the-dangerous-direction failure this whole module
 * exists to avoid.
 */
async function verifyMongoDbAtlasCredential(clientId, clientSecret, { fetchFn = fetch, timeoutMs = DEFAULT_TIMEOUT_MS } = {}) {
  let res;
  try {
    res = await fetchFn(mongodbAtlasUrl(), {
      method: "POST",
      headers: {
        Authorization: `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString("base64")}`,
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: "grant_type=client_credentials",
      signal: AbortSignal.timeout(timeoutMs),
    });
  } catch (e) {
    return { status: "error", detail: `could not reach MongoDB Atlas (${sanitizeDetail(e && e.message)})` };
  }
  if (res.status === 200) return { status: "active", detail: "MongoDB Atlas accepted this service account" };
  let body = null;
  try {
    body = await res.json();
  } catch {
    // Non-JSON body: fall through to the generic error below.
  }
  if (res.status === 403 && body && body.error === "invalid_client") {
    return { status: "invalid", detail: "MongoDB Atlas rejected this service account (invalid_client)" };
  }
  return { status: "error", detail: `could not verify: HTTP ${res.status} from MongoDB Atlas` };
}

function neonUrl() { return process.env.RESIDOO_TEST_NEON_API_URL || "https://console.neon.tech/api/v2/projects"; }
function verifyNeonKey(key, opts) {
  return verifyByStatusCode("Neon", neonUrl(), () => ({ Authorization: `Bearer ${key}` }), opts);
}

function posthogUrl() { return process.env.RESIDOO_TEST_POSTHOG_API_URL || "https://us.posthog.com/api/users/@me/"; }
function verifyPostHogKey(key, opts) {
  return verifyByStatusCode("PostHog", posthogUrl(), () => ({ Authorization: `Bearer ${key}` }), opts);
}

function vercelUrl() { return process.env.RESIDOO_TEST_VERCEL_API_URL || "https://api.vercel.com/v2/user"; }
function verifyVercelToken(token, opts) {
  return verifyByStatusCode("Vercel", vercelUrl(), () => ({ Authorization: `Bearer ${token}` }), opts);
}

function cerebrasUrl() { return process.env.RESIDOO_TEST_CEREBRAS_API_URL || "https://api.cerebras.ai/v1/models"; }
function verifyCerebrasKey(key, opts) {
  return verifyByStatusCode("Cerebras", cerebrasUrl(), () => ({ Authorization: `Bearer ${key}` }), opts);
}

function renderUrl() { return process.env.RESIDOO_TEST_RENDER_API_URL || "https://api.render.com/v1/owners"; }
function verifyRenderKey(key, opts) {
  return verifyByStatusCode("Render", renderUrl(), () => ({ Authorization: `Bearer ${key}` }), opts);
}

function flyioUrl() { return process.env.RESIDOO_TEST_FLYIO_API_URL || "https://api.fly.io/graphql"; }
/**
 * Fly.io: one GraphQL endpoint, Bearer header (the scheme flyctl-issued
 * fo1_ tokens use; Fly's other token family, fm1a_/fm1r_/fm2_ "macaroons",
 * uses a different literal "FlyV1 <token>" scheme instead, but that family
 * is not detected — see patterns.js's own comment on why). Like Linear, a
 * GraphQL 200 can still carry an auth failure in the body, so this checks
 * for a populated data.viewer instead of trusting the status code alone,
 * except for 401, which Fly's own API does use for an outright missing or
 * malformed token.
 */
async function verifyFlyioBearerToken(token, { fetchFn = fetch, timeoutMs = DEFAULT_TIMEOUT_MS } = {}) {
  let res;
  try {
    res = await fetchFn(flyioUrl(), {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({ query: "{ viewer { email } }" }),
      signal: AbortSignal.timeout(timeoutMs),
    });
  } catch (e) {
    return { status: "error", detail: `could not reach Fly.io (${sanitizeDetail(e && e.message)})` };
  }
  if (res.status === 401) return { status: "invalid", detail: "Fly.io rejected this token (HTTP 401)" };
  let body;
  try {
    body = await res.json();
  } catch {
    return { status: "error", detail: `Fly.io returned a non-JSON response (HTTP ${res.status})` };
  }
  if (body && body.data && body.data.viewer && body.data.viewer.email) {
    return { status: "active", detail: "Fly.io accepted this token" };
  }
  return { status: "error", detail: `could not verify: ${sanitizeDetail(JSON.stringify(body && body.errors)).slice(0, 120) || `HTTP ${res.status}`}` };
}

/**
 * Linear: a GraphQL API, one POST endpoint for everything, not a plain GET.
 * A GraphQL server can answer HTTP 200 even for some authorization-level
 * failures (the error lives in the response body's `errors` field, not the
 * status code), so this checks for a populated `data.viewer` instead of
 * trusting status code alone — the same reasoning that gave Slack its own
 * function above. Linear's own docs confirm no "Bearer" prefix on personal
 * API keys (Bearer is reserved for OAuth tokens).
 */
async function verifyLinearKey(key, { fetchFn = fetch, timeoutMs = DEFAULT_TIMEOUT_MS } = {}) {
  let res;
  try {
    res = await fetchFn(linearUrl(), {
      method: "POST",
      headers: { Authorization: key, "Content-Type": "application/json" },
      body: JSON.stringify({ query: "{ viewer { id } }" }),
      signal: AbortSignal.timeout(timeoutMs),
    });
  } catch (e) {
    return { status: "error", detail: `could not reach Linear (${sanitizeDetail(e && e.message)})` };
  }
  if (res.status === 401) return { status: "invalid", detail: "Linear rejected this key (HTTP 401)" };
  let body;
  try {
    body = await res.json();
  } catch {
    return { status: "error", detail: `Linear returned a non-JSON response (HTTP ${res.status})` };
  }
  if (body && body.data && body.data.viewer && body.data.viewer.id) {
    return { status: "active", detail: "Linear accepted this key" };
  }
  return { status: "error", detail: `could not verify: ${sanitizeDetail(JSON.stringify(body && body.errors)).slice(0, 120) || `HTTP ${res.status}`}` };
}

/**
 * Telegram: the token is embedded directly in the URL path, not a header,
 * and (like Slack) the response is always HTTP 200 with an `ok` boolean in
 * the body signaling success or failure — never a 401.
 */
async function verifyTelegramToken(token, { fetchFn = fetch, timeoutMs = DEFAULT_TIMEOUT_MS } = {}) {
  let res;
  try {
    res = await fetchFn(telegramUrl(token), { method: "GET", signal: AbortSignal.timeout(timeoutMs) });
  } catch (e) {
    return { status: "error", detail: `could not reach Telegram (${sanitizeDetail(e && e.message)})` };
  }
  let body;
  try {
    body = await res.json();
  } catch {
    return { status: "error", detail: `Telegram returned a non-JSON response (HTTP ${res.status})` };
  }
  if (body && body.ok === true) return { status: "active", detail: "Telegram accepted this bot token (getMe)" };
  if (body && body.ok === false && typeof body.error_code === "number") {
    return { status: "invalid", detail: `Telegram rejected this token (${sanitizeDetail(body.description) || body.error_code})` };
  }
  return { status: "error", detail: `could not verify: HTTP ${res.status} from Telegram` };
}

/**
 * Discord webhooks: the credential IS a full URL, not a token to attach to
 * a fixed endpoint elsewhere. A plain GET on that URL is Discord's own
 * documented read-only "fetch webhook info" call, distinct from POSTing to
 * it (which would send a real, visible message — never done here).
 */
function verifyDiscordWebhook(webhookUrl, opts) {
  return verifyByStatusCode("Discord", webhookUrl, () => ({}), { ...opts, invalidStatuses: [404] });
}

module.exports = {
  isAwsCliAvailable, verifyAwsCredential, verifySlackToken,
  verifyOpenAiKey, verifyAnthropicKey, verifyGithubToken,
  verifyHuggingFaceToken, verifyReplicateToken, verifyDigitalOceanToken, verifyPineconeKey,
  verifySendgridKey, verifyGroqKey, verifyXaiKey, verifyOpenRouterKey, verifyStripeKey, verifyNpmToken,
  verifyNotionToken, verifyGitlabToken, verifySupabaseToken, verifyElevenLabsKey,
  verifyCircleciToken, verifyAirtableToken, verifyCloudflareToken, verifyHerokuKey,
  verifyNetlifyToken, verifyLinearKey, verifyTelegramToken, verifyDiscordWebhook,
  verifyPlanetScaleToken, verifyVercelToken, verifyCerebrasKey, verifyRenderKey,
  verifyFlyioBearerToken, verifyMongoDbAtlasCredential, verifyNeonKey, verifyPostHogKey,
};
