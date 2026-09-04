"use strict";

const path = require("path");
const { PATTERNS, NOISY_PATTERNS, redact } = require("./patterns");
const { findDecodedMatches, findBoundaryMatches, contentProjection } = require("./decode");
const { findPairedSecret, findNearbyCandidate } = require("./pairing");
const { looksRandom } = require("./rarity");
const { decodeJwtExpiryMs } = require("./jwtExpiry");
const {
  isAwsCliAvailable, verifyAwsCredential,
  verifySlackToken, verifyOpenAiKey, verifyAnthropicKey, verifyGithubToken,
  verifyHuggingFaceToken, verifyReplicateToken, verifyDigitalOceanToken, verifyPineconeKey,
  verifySendgridKey, verifyGroqKey, verifyXaiKey, verifyOpenRouterKey, verifyStripeKey, verifyNpmToken,
  verifyNotionToken, verifyGitlabToken, verifySupabaseToken, verifyElevenLabsKey,
  verifyCircleciToken, verifyAirtableToken, verifyCloudflareToken, verifyHerokuKey,
  verifyNetlifyToken, verifyLinearKey, verifyTelegramToken, verifyDiscordWebhook,
  verifyPlanetScaleToken, verifyVercelToken, verifyCerebrasKey, verifyRenderKey,
  verifyFlyioBearerToken, verifyMongoDbAtlasCredential, verifyNeonKey, verifyPostHogKey,
} = require("./verify");
const { c, makePaint } = require("./color");
const { fingerprintFinding } = require("./rotation");

// PlanetScale's id half: 12 lowercase alphanumeric characters, no prefix —
// confirmed via planetscale.com/docs/api/reference/service-tokens. Searched
// for near an already-confirmed planetscale_secret match the same way AWS's
// secret is searched for near an access key id (see pairing.js).
const PLANETSCALE_ID_RE = /\b[a-z0-9]{12}\b/g;
// A tighter window than AWS's: PlanetScale's own docs show the id and
// secret adjacent, joined by a colon ("<id>:<token>"), not spread across a
// config file the way an AWS access key and secret often are. A 12-char
// lowercase-alnum candidate is also a much more common shape to collide
// with by accident (a hash fragment, a short id) than AWS's 40-char one, so
// a smaller window reduces how often an unrelated nearby string creates a
// false ambiguous match.
const PLANETSCALE_PAIR_WINDOW = 100;

// MongoDB Atlas Service Account client id: fully specified by MongoDB's own
// OpenAPI schema (mdb_sa_id_ + exactly 24 hex characters) — the ONE paired
// candidate regex in this file precise enough to have a confirmed exact
// length rather than a shape-only guess, since it carries its own
// distinguishing prefix too (unlike AWS's secret or PlanetScale's id, which
// have no prefix of their own and rely entirely on nearby-anchor context).
const MONGODB_ATLAS_ID_RE = /\bmdb_sa_id_[a-fA-F0-9]{24}\b/g;
// MongoDB's own docs show the id and secret as sibling fields in the same
// JSON credentials block or adjacent env vars, not spread across a file —
// same reasoning as PlanetScale's tighter window, not AWS's wider one.
const MONGODB_ATLAS_PAIR_WINDOW = 150;

// Never verify more than this many distinct credentials of ONE vendor in a
// single scan: a pathological transcript with dozens of distinct
// credentials should not turn --verify into a long burst of outbound calls.
// Real scans see 0-2 per vendor; this is a backstop, not the expected path.
const MAX_VERIFICATIONS_PER_VENDOR = 10;

// Every vendor whose credential is a single, unpaired bearer token: no
// AWS-style "two halves make one credential" pairing step, so these all
// share one collection/verification path below (see pendingSimpleVerifications).
// Deliberately NOT here despite being detected: google_api_key (a key can
// belong to any Google product; testing it against one product's endpoint
// would misreport a valid key for a DIFFERENT product as invalid) and
// perplexity_key (no free, side-effect-free endpoint exists at all).
// PlanetScale and MongoDB Atlas are ALSO not here despite being verified:
// both need pairing (see pendingPlanetScaleVerifications and
// pendingMongoDbAtlasVerifications below), the same reason AWS isn't here
// either. See verify.js's own header comment for the fuller reasoning
// behind every vendor left out.
const SIMPLE_VERIFY_FNS = {
  slack_token: verifySlackToken,
  openai_key: verifyOpenAiKey,
  anthropic_key: verifyAnthropicKey,
  github_pat: verifyGithubToken,
  huggingface_token: verifyHuggingFaceToken,
  replicate_token: verifyReplicateToken,
  digitalocean_token: verifyDigitalOceanToken,
  pinecone_key: verifyPineconeKey,
  sendgrid_key: verifySendgridKey,
  groq_key: verifyGroqKey,
  xai_key: verifyXaiKey,
  openrouter_key: verifyOpenRouterKey,
  stripe_key: verifyStripeKey,
  stripe_test_key: verifyStripeKey,
  npm_token: verifyNpmToken,
  notion_token: verifyNotionToken,
  gitlab_pat: verifyGitlabToken,
  supabase_token: verifySupabaseToken,
  elevenlabs_key: verifyElevenLabsKey,
  circleci_token: verifyCircleciToken,
  airtable_token: verifyAirtableToken,
  cloudflare_api_token: verifyCloudflareToken,
  heroku_api_key: verifyHerokuKey,
  netlify_token: verifyNetlifyToken,
  linear_key: verifyLinearKey,
  telegram_bot_token: verifyTelegramToken,
  discord_webhook: verifyDiscordWebhook,
  vercel_token: verifyVercelToken,
  cerebras_key: verifyCerebrasKey,
  render_key: verifyRenderKey,
  flyio_bearer_token: verifyFlyioBearerToken,
  neon_key: verifyNeonKey,
  posthog_key: verifyPostHogKey,
};
const SIMPLE_VERIFY_VENDOR_LABEL = {
  slack_token: "Slack's auth.test",
  openai_key: "OpenAI's models endpoint",
  anthropic_key: "Anthropic's models endpoint",
  github_pat: "GitHub's user endpoint",
  huggingface_token: "Hugging Face's whoami endpoint",
  replicate_token: "Replicate's account endpoint",
  digitalocean_token: "DigitalOcean's account endpoint",
  pinecone_key: "Pinecone's indexes endpoint",
  sendgrid_key: "SendGrid's scopes endpoint",
  groq_key: "Groq's models endpoint",
  xai_key: "xAI's api-key endpoint",
  openrouter_key: "OpenRouter's key endpoint",
  stripe_key: "Stripe's balance endpoint",
  stripe_test_key: "Stripe's balance endpoint",
  npm_token: "npm's whoami endpoint",
  notion_token: "Notion's users endpoint",
  gitlab_pat: "GitLab's user endpoint",
  supabase_token: "Supabase's projects endpoint",
  elevenlabs_key: "ElevenLabs' user endpoint",
  circleci_token: "CircleCI's me endpoint",
  airtable_token: "Airtable's whoami endpoint",
  cloudflare_api_token: "Cloudflare's token-verify endpoint",
  heroku_api_key: "Heroku's account endpoint",
  netlify_token: "Netlify's sites endpoint",
  linear_key: "Linear's GraphQL API",
  telegram_bot_token: "Telegram's getMe endpoint",
  discord_webhook: "Discord's webhook-info endpoint",
  vercel_token: "Vercel's user endpoint",
  cerebras_key: "Cerebras's models endpoint",
  render_key: "Render's owners endpoint",
  flyio_bearer_token: "Fly.io's GraphQL API",
  neon_key: "Neon's projects endpoint",
  posthog_key: "PostHog's users endpoint",
};

// Rule ids that findPairedSecret's window search applies to (see pairing.js):
// AWS access key ids and STS session tokens both pair with the same shape
// of 40-char base64 secret value.
const AWS_PAIR_RULE_IDS = new Set(["aws_access_key_id", "aws_session_token"]);

// The two NOISY_PATTERNS ids (see patterns.js): the only rules the rarity
// check (rarity.js) ever touches. Never applied to the default 38 rules.
const NOISY_RULE_IDS = new Set(["generic_password_assignment", "generic_secret_assignment"]);

/**
 * Text immediately before a match that strongly suggests "this is an example
 * or a UI hint," not a real credential — verified against residoo's own
 * first real run, which flagged HTML `placeholder="AKIA..."` attributes in
 * an unrelated codebase's connector form (a UI hint showing the expected
 * key SHAPE) as if they were leaked keys. Suppressed by default, reported
 * separately rather than silently dropped, and re-includable with
 * --include-suppressed — a scanner that hides its own uncertainty is worse
 * than one that shows it.
 */
const SUPPRESS_CONTEXT_RE = /(placeholder|example|sample|dummy|<REDACTED>|xxxxxxxx|your[_-]?(api[_-]?)?key|EXAMPLE)/i;
const CONTEXT_WINDOW = 40;

/**
 * Exact literals that vendors publish in their own documentation as example
 * credentials. These pass every shape check by construction (they ARE the
 * documented shape), and the context heuristic above can't be relied on to
 * catch them: it only looks at the 40 characters BEFORE a match, so "the
 * docs show AKIAIOSFODNN7EXAMPLE as the placeholder" sails straight through.
 * The value itself is the signal here. Same policy as the context heuristic:
 * suppressed by default, counted, re-includable with --include-suppressed.
 * gitleaks and other production scanners filter the AWS pair the same way.
 *
 * Every literal below was verified against the vendor's own published docs
 * (2026-09), not copied from another scanner's allowlist:
 *   - AWS's two documented example access key ids, used across the IAM and
 *     STS docs (e.g. the GetAccessKeyInfo API reference).
 *   - GitHub's documented example tokens from docs.github.com: the REST API
 *     getting-started guide's PAT, and the OAuth-apps guide's access +
 *     refresh token pair (the same body appears under ghp_ and gho_).
 *   - jwt.io's default demo token (header {"alg":"HS256","typ":"JWT"},
 *     payload sub 1234567890 / John Doe), the canonical example JWT quoted
 *     in tutorials everywhere.
 */
/**
 * A trailing run of 12+ identical characters inside a matched value. No
 * vendor issues credentials with a repeated-character body — key material is
 * random, and 12 identical characters in a row in a real random body is a
 * ~62^-11 event — but placeholder keys built as prefix + XXXX.../0000... are
 * everywhere in docs and templates, and they match the shape rules by
 * construction. This is a property of the VALUE, so unlike the context
 * heuristic it also works where no surrounding text exists: a placeholder
 * that arrives base64-encoded or split across lines is still zero-entropy
 * after decoding/joining. gitleaks ships equivalent repeated-character
 * allowlists. Anchored to the END of the value on purpose: an INTERIOR run
 * can occur inside a real token (base64 of a zero-byte run is a run of
 * "A"s, so a genuine JWT payload can contain one), but real key material
 * never ends in one, and prefix+XXXX placeholders always do. Same policy
 * as every suppression: counted, re-includable with --include-suppressed,
 * never silently dropped.
 *
 * Implemented as a fixed 12-character look at the END of the value, not as
 * the equivalent anchored-backreference regex /(.)\1{11,}$/ — that regex is
 * O(n^2) on a matched value containing a long INTERIOR identical-character
 * run (the greedy backreference re-tests the anchor at every start
 * position), and such values are reachable: base64 of zero-heavy bytes is a
 * long run of "A"s inside a prefix-matched value. Checking only the last 12
 * code units is exactly equivalent to "ends in 12 or more identical
 * characters" and O(1) whatever the value looks like.
 */
function zeroEntropyTail(value) {
  if (value.length < 12) return false;
  const last = value.charCodeAt(value.length - 1);
  for (let i = value.length - 12; i < value.length - 1; i++) {
    if (value.charCodeAt(i) !== last) return false;
  }
  return true;
}

const VENDOR_EXAMPLE_VALUES = new Set([
  "AKIAIOSFODNN7EXAMPLE",
  "AKIAI44QH8DHBEXAMPLE",
  "ghp_16C7e42F292c6912E7710c838347Ae178B4a",
  "gho_16C7e42F292c6912E7710c838347Ae178B4a",
  "ghr_1B4a2e77838347a7E420ce178F2E7c6912E169246c34E1ccbF66C46812d16D5B1A9Dc86A1498",
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
  // Stripe's two published sample test keys, verified against Stripe's own
  // material (2026-09): the API reference authentication page
  // (docs.stripe.com/api/authentication) embeds the first in its curl
  // example under "A sample test API key is included in all the examples
  // here"; the second is Stripe's long-running docs sample key, present
  // verbatim in Stripe's own repositories (stripe/stripe-java and
  // stripe/stripe-dotnet test suites) and echoed by virtually every Stripe
  // tutorial a transcript might read. Both match stripe_test_key by
  // construction, so without this entry each is reported at high confidence.
  // Written split (prefix + body) so the faithful example literals do not
  // trip GitHub push protection; the Set still holds the whole values.
  "sk_test_" + "BQokikJOvBiI2HlWgH4olfQ2",
  "sk_test_" + "4eC39HqLyjWDarjtT1zdp7dc",
]);

/** Matches every finding's own `relFile` convention — never the full path. See SECURITY.md. */
function safeName(file) { return path.basename(file); }

// Same format as report.js's own localTimestamp, duplicated rather than
// imported: this is a 3-line pure function, and report.js is the
// presentation layer for stdout while this file's own --verify results
// table is stderr, the same reasoning pairing.js gives for its own small
// duplicated helper (looksZeroEntropy) rather than cross-importing.
function localTimestamp(d) {
  const p2 = (n) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p2(d.getMonth() + 1)}-${p2(d.getDate())} ${p2(d.getHours())}:${p2(d.getMinutes())}`;
}

/**
 * Scan every transcript from every available source.
 *
 * Matches raw text lines directly rather than parsing each line as JSON and
 * walking specific fields — transcript schemas vary by tool and change over
 * time, but a leaked key looks the same either way. This is also exactly the
 * method verified against a real, populated transcript directory while this
 * tool was built, so it's a known-working default rather than a redesign.
 *
 * Returns { findings, filesScanned, sourcesScanned, bytesScanned,
 * suppressedCount, distinctCounts, unreadableFiles }. `findings` never
 * contains the raw matched secret — only a redacted preview — because a
 * security tool's own report output is itself a place secrets could leak
 * from (a screenshot, a copied terminal log, a CI artifact). Same reasoning
 * is why `unreadableFiles` holds basenames only, not full paths — an
 * absolute path can itself carry a username or a project name the rest of
 * this report is careful never to print.
 */
async function scan({ sources, includeNoisy = false, includeSuppressed = false, onProgress = null, verify = false, verifyOnlyFingerprint = null, onBeforeVerify = null, noColor = false } = {}) {
  const rules = includeNoisy ? PATTERNS.concat(NOISY_PATTERNS) : PATTERNS;
  // The decode pass (see decode.js) only applies high-confidence, vendor-
  // prefixed rules to decoded bytes: random binary that decodes to printable
  // text can shape-match a generic rule, but not a vendor prefix. NOISY rules
  // are low confidence and never qualify.
  const highRules = rules.filter((r) => r.confidence === "high");
  const findings = [];
  let suppressedCount = 0;
  let filesScanned = 0;
  let bytesScanned = 0;
  const sourcesScanned = [];
  const unreadableFiles = [];
  // Raw values live ONLY in this in-process Set, for counting how many
  // DISTINCT secrets exist vs. how many times one got echoed back across
  // tool calls (a token re-surfacing in every screenshot/read_page during a
  // browser-testing run is one leak, not ten) — never written to a report,
  // never leaves this function.
  const distinctByRule = new Map();
  // --verify only (see verify.js): accessKeyValue -> { secretValue, refs }.
  // Keyed by the RAW access key so the map itself dedupes distinct
  // credentials for the AWS call (one call per key, no matter how many
  // times it was echoed) while `refs` accumulates EVERY occurrence's
  // finding-object pair, so the result reaches all of them, not only the
  // first: an access key re-echoed across several lines gets several
  // finding objects, and every one of them needs the same answer. Like
  // distinctByRule above, this lives only for the duration of this scan()
  // call; nothing in it is ever written to a finding until verification has
  // REPLACED the raw values with a status string.
  const pendingAwsVerifications = new Map();
  // Same shape as pendingAwsVerifications, for PlanetScale's paired
  // credential (see the planetscale_secret match branch below): keyed by
  // the secret value (the confirmed, prefixed anchor) -> { idValue, refs }.
  const pendingPlanetScaleVerifications = new Map();
  // Same shape again, for MongoDB Atlas Service Account credentials (see
  // the mongodb_atlas_secret match branch below): keyed by the secret value
  // -> { idValue, refs }.
  const pendingMongoDbAtlasVerifications = new Map();
  // --verify only (see verify.js): ruleId -> (token value -> { refs }), for
  // every SIMPLE_VERIFY_FNS vendor. Unlike AWS/PlanetScale, none of these
  // need pairing (the token itself is the complete credential), so this is
  // simpler: one entry per distinct value per rule, `refs` accumulating
  // every finding object that value produced.
  const pendingSimpleVerifications = new Map();

  // One place raw matched text turns into a recorded finding: counts the
  // distinct value and pushes the redacted record. `extra` carries the
  // encoding / split markers for the decode and boundary passes; the raw pass
  // passes none. Returns the finding object itself so a caller (the pairing
  // and --verify logic) can attach more fields onto it later, after the
  // fields that need real work (an AWS API round-trip) finish.
  const record = (rule, value, relFile, file, lineNo, mtimeMs, confidence, suppressedReason, extra) => {
    if (!distinctByRule.has(rule.id)) distinctByRule.set(rule.id, new Set());
    distinctByRule.get(rule.id).add(value);
    findings.push({
      ruleId: rule.id,
      label: rule.label,
      confidence,
      suppressedReason: suppressedReason || null,
      source: relFile.source,
      file, relFile: relFile.name,
      line: lineNo,
      preview: redact(value),
      fileMTimeMs: mtimeMs,
      ...(extra || {}),
    });
    return findings[findings.length - 1];
  };

  // One suppression policy for all three passes (raw, decoded, boundary).
  // The value-based checks run first: they are exact properties of the match
  // itself, so they apply identically to a value found raw, decoded out of
  // base64, or reconstructed across a line boundary — a decoded vendor
  // example is the same non-secret as a plain one. The context heuristic is
  // last and only where surrounding text exists (`before` is null for the
  // decode and boundary passes, whose transforms have no stable "40 chars
  // before" in the original line).
  const suppressionReason = (value, before, ruleId) => {
    if (VENDOR_EXAMPLE_VALUES.has(value)) return "vendor-documented example value";
    if (zeroEntropyTail(value)) return "zero-entropy body";
    if (before !== null && SUPPRESS_CONTEXT_RE.test(before)) return "placeholder-like context";
    // Rarity check (rarity.js): only the two opt-in NOISY_PATTERNS rules ever
    // reach here with a matching ruleId. A generic password/secret
    // assignment whose value reads as English (a placeholder, a variable
    // name, a pasted sentence) is exactly the false-positive class those
    // rules are known for; a value that reads as machine-random is not.
    if (ruleId && NOISY_RULE_IDS.has(ruleId) && !looksRandom(value)) return "reads like natural language, not random";
    return null;
  };

  // Confidence for a NOISY_PATTERNS match that survives every suppression
  // check is bumped from the rule's default "low" to "medium" when the
  // value also reads as machine-random (rarity.js): passing both "not a
  // known placeholder shape" AND "doesn't read like language" is a real
  // signal boost, not just the absence of a red flag. Never touches any of
  // the default 38 rules' own confidence.
  const resolveConfidence = (ruleId, value, defaultConfidence, suppressedReason) => {
    if (suppressedReason) return "low";
    if (NOISY_RULE_IDS.has(ruleId) && looksRandom(value)) return "medium";
    return defaultConfidence;
  };

  const matchLine = (line, file, relFile, lineNo, mtimeMs) => {
    for (const rule of rules) {
      rule.re.lastIndex = 0; // rules are reused across files; reset global regex state
      let m;
      while ((m = rule.re.exec(line)) !== null) {
        const before = line.slice(Math.max(0, m.index - CONTEXT_WINDOW), m.index);
        const suppressedReason = suppressionReason(m[0], before, rule.id);
        if (suppressedReason && !includeSuppressed) {
          suppressedCount++;
        } else {
          // Feature 3: paired-secret detection (see pairing.js), computed
          // BEFORE the access-key-id finding is recorded so that finding can
          // carry the paired secret's own redacted preview. An access key id
          // alone cannot authenticate anything (see pairing.js's docstring);
          // it is only a usable credential once its secret is known too, so
          // a report showing several access-key-id findings needs to say,
          // on each one's own line, which one actually has a secret sitting
          // next to it in the transcript, not just that a secret exists
          // somewhere in the scan.
          let pairedSecretPreview = null;
          let secretFinding = null;
          let rawPairedSecret = null;
          if (!suppressedReason && AWS_PAIR_RULE_IDS.has(rule.id)) {
            const paired = findPairedSecret(line, m[0], m.index);
            if (paired) {
              const pairedSuppressedReason = suppressionReason(paired, null);
              if (pairedSuppressedReason && !includeSuppressed) {
                suppressedCount++;
              } else {
                pairedSecretPreview = redact(paired);
                rawPairedSecret = paired;
                secretFinding = record({ id: "aws_secret_access_key_paired", label: "AWS Secret Access Key (paired with access key id)" },
                  paired, relFile, file, lineNo, mtimeMs,
                  pairedSuppressedReason ? "low" : "high", pairedSuppressedReason,
                  { paired: true, pairedAccessKeyPreview: redact(m[0]) });
              }
            }
          }
          // PlanetScale: the opposite pairing direction from AWS (see
          // pairing.js's findNearbyCandidate) — the SECRET is the
          // confirmed, prefixed anchor here, and the unprefixed id is the
          // nearby candidate. Uses the generic pairedOtherPreview/
          // pairedOtherLabel fields rather than AWS's pairedSecretPreview/
          // pairedAccessKeyPreview, since neither of those names fits ("the
          // secret is paired with an id", not a second secret or an access
          // key) — a future paired vendor reuses these same generic fields
          // rather than growing a new AWS-shaped pair each time.
          let planetScaleIdFinding = null;
          let rawPlanetScaleId = null;
          if (!suppressedReason && rule.id === "planetscale_secret") {
            const pairedId = findNearbyCandidate(line, m[0], m.index, PLANETSCALE_ID_RE, PLANETSCALE_PAIR_WINDOW);
            if (pairedId) {
              const idSuppressedReason = suppressionReason(pairedId, null);
              if (idSuppressedReason && !includeSuppressed) {
                suppressedCount++;
              } else {
                rawPlanetScaleId = pairedId;
                planetScaleIdFinding = record({ id: "planetscale_id", label: "PlanetScale service token id (paired with secret)" },
                  pairedId, relFile, file, lineNo, mtimeMs,
                  idSuppressedReason ? "low" : "high", idSuppressedReason,
                  { paired: true, pairedOtherPreview: redact(m[0]), pairedOtherLabel: "secret" });
              }
            }
          }
          // MongoDB Atlas: same shape as PlanetScale (secret is the
          // confirmed, prefixed anchor; the id is the nearby candidate),
          // except the id here ALSO carries its own distinguishing prefix
          // (mdb_sa_id_) rather than being a bare unprefixed shape — a
          // stronger candidate signal than PlanetScale's or AWS's, but the
          // same pairing mechanism and the same generic pairedOtherPreview/
          // pairedOtherLabel display fields.
          let mongoDbIdFinding = null;
          let rawMongoDbId = null;
          if (!suppressedReason && rule.id === "mongodb_atlas_secret") {
            const pairedId = findNearbyCandidate(line, m[0], m.index, MONGODB_ATLAS_ID_RE, MONGODB_ATLAS_PAIR_WINDOW);
            if (pairedId) {
              const idSuppressedReason = suppressionReason(pairedId, null);
              if (idSuppressedReason && !includeSuppressed) {
                suppressedCount++;
              } else {
                rawMongoDbId = pairedId;
                mongoDbIdFinding = record({ id: "mongodb_atlas_client_id", label: "MongoDB Atlas Service Account client id (paired with secret)" },
                  pairedId, relFile, file, lineNo, mtimeMs,
                  idSuppressedReason ? "low" : "high", idSuppressedReason,
                  { paired: true, pairedOtherPreview: redact(m[0]), pairedOtherLabel: "secret" });
              }
            }
          }
          // Local, offline JWT expiry (see jwtExpiry.js): only ever reads
          // the `exp` claim out of the decoded payload, nothing else, and
          // only for the unsuppressed default `jwt` rule, since a
          // suppressed placeholder/example match is not worth decoding.
          const jwtExtra = (!suppressedReason && rule.id === "jwt")
            ? { jwtExpiresAtMs: decodeJwtExpiryMs(m[0]) }
            : null;
          const primaryFinding = record(rule, m[0], relFile, file, lineNo,
            mtimeMs,
            resolveConfidence(rule.id, m[0], rule.confidence, suppressedReason),
            suppressedReason,
            {
              ...(pairedSecretPreview ? { pairedSecretPreview } : {}),
              ...(planetScaleIdFinding ? { pairedOtherPreview: redact(rawPlanetScaleId), pairedOtherLabel: "id" } : {}),
              ...(mongoDbIdFinding ? { pairedOtherPreview: redact(rawMongoDbId), pairedOtherLabel: "id" } : {}),
              ...(jwtExtra || {}),
            });

          // --verify only, and only for a DEMONSTRATED pair (both halves
          // present, neither suppressed): queue it for the verification pass
          // that runs once, after every file has been scanned (see below).
          // The Map key dedupes the actual AWS call to one per distinct
          // credential; `refs` still grows on every occurrence, so a key
          // re-echoed across several lines gets several finding objects, and
          // the eventual result is applied to every one of them, not only
          // the first.
          //
          // verifyOnlyFingerprint (residoo_verify_finding, src/mcpTools.js):
          // when set, this scan still WALKS every file as normal, but only
          // the one finding whose fingerprint matches is ever queued for a
          // real network call -- every other eligible credential on the
          // machine is silently skipped, matching that MCP tool's own
          // documented "one credential per call" promise exactly. Computed
          // from primaryFinding, not secretFinding/idFinding, because the
          // fingerprint a caller holds always names the record they saw in
          // a prior scan/check result, which is always the primary one.
          const matchesTarget = !verifyOnlyFingerprint || fingerprintFinding(primaryFinding) === verifyOnlyFingerprint;
          if (verify && matchesTarget && secretFinding && rawPairedSecret) {
            if (!pendingAwsVerifications.has(m[0]) && pendingAwsVerifications.size < MAX_VERIFICATIONS_PER_VENDOR) {
              pendingAwsVerifications.set(m[0], { secretValue: rawPairedSecret, refs: [] });
            }
            const entry = pendingAwsVerifications.get(m[0]);
            if (entry) entry.refs.push({ akiaFinding: primaryFinding, secretFinding });
          }
          // --verify, PlanetScale: same dedup-by-anchor-value shape as AWS
          // above, keyed by the secret (the confirmed anchor) this time.
          if (verify && matchesTarget && planetScaleIdFinding && rawPlanetScaleId) {
            if (!pendingPlanetScaleVerifications.has(m[0]) && pendingPlanetScaleVerifications.size < MAX_VERIFICATIONS_PER_VENDOR) {
              pendingPlanetScaleVerifications.set(m[0], { idValue: rawPlanetScaleId, refs: [] });
            }
            const psEntry = pendingPlanetScaleVerifications.get(m[0]);
            if (psEntry) psEntry.refs.push({ secretFinding: primaryFinding, idFinding: planetScaleIdFinding });
          }
          // --verify, MongoDB Atlas: same dedup-by-anchor-value shape as
          // AWS/PlanetScale above, keyed by the secret this time.
          if (verify && matchesTarget && mongoDbIdFinding && rawMongoDbId) {
            if (!pendingMongoDbAtlasVerifications.has(m[0]) && pendingMongoDbAtlasVerifications.size < MAX_VERIFICATIONS_PER_VENDOR) {
              pendingMongoDbAtlasVerifications.set(m[0], { idValue: rawMongoDbId, refs: [] });
            }
            const mdbEntry = pendingMongoDbAtlasVerifications.get(m[0]);
            if (mdbEntry) mdbEntry.refs.push({ secretFinding: primaryFinding, idFinding: mongoDbIdFinding });
          }
          // --verify, single-token vendors (Slack, OpenAI, Anthropic,
          // GitHub): none of these need pairing (the value IS the complete
          // credential), so queue every unsuppressed match directly, same
          // dedup-by-value / accumulate-all-refs shape as the AWS map above,
          // just one level deeper (keyed by rule id too, since several
          // vendors share this path).
          if (verify && matchesTarget && !suppressedReason && SIMPLE_VERIFY_FNS[rule.id]) {
            let byValue = pendingSimpleVerifications.get(rule.id);
            if (!byValue) {
              byValue = new Map();
              pendingSimpleVerifications.set(rule.id, byValue);
            }
            if (!byValue.has(m[0]) && byValue.size < MAX_VERIFICATIONS_PER_VENDOR) {
              byValue.set(m[0], { refs: [] });
            }
            const entry = byValue.get(m[0]);
            if (entry) entry.refs.push(primaryFinding);
          }
        }
        if (m.index === rule.re.lastIndex) rule.re.lastIndex++; // guard zero-width matches
      }
    }
  };

  // Feature 1: base64 decode-then-rescan. A finding here means a credential
  // was present only encoded on this line. It redacts from the DECODED value
  // (the encoded run is treated as secret material and never appears in the
  // preview), and carries an `encoding` marker the report renders as
  // "base64-wrapped".
  const decodeLine = (line, file, relFile, lineNo, mtimeMs) => {
    for (const d of findDecodedMatches(line, highRules)) {
      const suppressedReason = suppressionReason(d.value, null);
      if (suppressedReason && !includeSuppressed) {
        suppressedCount++;
        continue;
      }
      record({ id: d.ruleId, label: d.label }, d.value, relFile, file, lineNo,
        mtimeMs, suppressedReason ? "low" : "high", suppressedReason, { encoding: d.encoding });
    }
  };

  // Feature 2: split-line boundary join. A finding here means one credential
  // was split across this line and the next and is contiguous on neither. It
  // is recorded against BOTH contributing lines (each holds a fragment of the
  // exposed secret) and carries a `spanLines` marker. `contentA`/`contentB`
  // are the two lines' content projections, computed once per line by the
  // caller and reused across both of a line's pairs.
  const boundaryPair = (contentA, contentB, file, relFile, lineNoA, mtimeMs) => {
    for (const b of findBoundaryMatches(contentA, contentB, rules)) {
      const suppressedReason = suppressionReason(b.value, null, b.ruleId);
      if (suppressedReason && !includeSuppressed) {
        // One straddling match is one suppressed match, even though an
        // unsuppressed one records against both contributing lines.
        suppressedCount++;
        continue;
      }
      const span = [lineNoA, lineNoA + 1];
      const conf = resolveConfidence(b.ruleId, b.value, b.confidence, suppressedReason);
      record({ id: b.ruleId, label: b.label }, b.value, relFile, file, lineNoA, mtimeMs, conf, suppressedReason, { spanLines: span });
      record({ id: b.ruleId, label: b.label }, b.value, relFile, file, lineNoA + 1, mtimeMs, conf, suppressedReason, { spanLines: span });
    }
  };

  for (const source of sources) {
    let sourceScannedAnything = false;

    for (const entry of source.files()) {
      if (onProgress) onProgress({ source: source.id(), file: entry.file });

      // files() itself can now report an entry it couldn't resolve at all —
      // chiefly a dangling symlink. Surfaced the same way an unreadable file
      // is: visibly, never silently dropped inside the walk.
      if (entry.broken) {
        unreadableFiles.push({ file: safeName(entry.file), reason: "could not be resolved" });
        continue;
      }
      const { file, mtimeMs, sizeBytes } = entry;

      // Any unexpected throw here (a source's readLines behaving outside its
      // documented contract, a future bug) must not take down the rest of
      // the scan and discard every finding already collected from other
      // files — one bad file degrading to "unreadable" is the correct
      // failure mode; the whole run crashing is not.
      let result;
      try {
        result = await source.readLines(file);
      } catch (err) {
        unreadableFiles.push({ file: safeName(file), reason: "unexpected error" });
        continue;
      }

      const { lines, status, bytesRead } = result;
      if (status === "failed") {
        unreadableFiles.push({ file: safeName(file), reason: "could not be read" });
        continue;
      }
      if (status === "too-large") {
        unreadableFiles.push({ file: safeName(file), reason: "too large to scan" });
        continue;
      }
      // "partial" means the read failed partway through, but real lines WERE
      // captured before that — those lines get scanned normally below (a
      // secret in the part that succeeded is still a real finding), and the
      // file is ALSO flagged so the user knows it wasn't fully checked.
      if (status === "partial") {
        unreadableFiles.push({ file: safeName(file), reason: "only partially read" });
      }

      sourceScannedAnything = true;
      filesScanned++;
      // Actual bytes streamed, not the pre-read stat() snapshot — matters
      // for a file Claude Code is actively appending to mid-scan, where the
      // two can genuinely differ.
      bytesScanned += bytesRead || sizeBytes || 0;

      const relFile = { name: safeName(file), source: source.id() };
      // Content projection of the PREVIOUS line, kept so each line is
      // projected once and reused for both pairs it belongs to.
      let prevContent = null;
      // Per-file degradation flag, surfaced at most once so a pathological
      // file produces one visible entry, not thousands.
      let lineMatchFailed = false;
      // Each pass gets its own try/catch: every rule quantifier is bounded
      // (see patterns.js) so none of these should throw on adversarial input
      // any more, but this is the second, independent layer against that
      // failure mode — a throw in one pass must never suppress the other
      // two for the same line. Without this, a bug reintroduced in any one
      // pass silently blinds the other two for that line rather than
      // degrading loudly on its own. One unmatched line must degrade to a
      // visible per-file flag, never abort the scan and discard every
      // finding already collected (same contract as the readLines catch
      // above).
      const flagFailed = () => {
        if (!lineMatchFailed) {
          lineMatchFailed = true;
          unreadableFiles.push({ file: safeName(file), reason: "some lines could not be matched" });
        }
      };
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (line) {
          try {
            matchLine(line, file, relFile, i + 1, mtimeMs);
          } catch (err) {
            flagFailed();
          }
          try {
            decodeLine(line, file, relFile, i + 1, mtimeMs);
          } catch (err) {
            flagFailed();
          }
          try {
            const content = contentProjection(line);
            // Boundary join with the previous line (2-way splits only; see
            // decode.js). Both lines must be non-empty so a blank separator
            // never forms a spurious pair.
            if (prevContent !== null) {
              boundaryPair(prevContent, content, file, relFile, i, mtimeMs);
            }
            prevContent = content;
          } catch (err) {
            flagFailed();
            prevContent = null;
          }
        } else {
          prevContent = null;
        }
      }
    }

    if (sourceScannedAnything) sourcesScanned.push(source.id());
  }

  // --verify: runs once, here, after every file has been scanned, never
  // interleaved with the matching pass above. A real network call per
  // distinct credential, one at a time (not concurrent), so this is the one
  // place a scan's wall-clock time depends on something other than disk
  // I/O; that tradeoff only exists when a caller explicitly asked for it.
  //
  // onBeforeVerify exists so a caller with its own stderr chatter (the
  // progress spinner) can clear it first: this pass writes its own stderr
  // lines below, and the spinner's own stop() doesn't run until scan()
  // fully returns, which is AFTER those lines have already printed. Without
  // this, the last spinner frame sits uncleared on screen and the first
  // --verify line gets appended directly onto the end of it with no
  // separator, a real rendering bug caught live. Only called when there is
  // actually something to verify, so a plain --verify with nothing to check
  // never clears a spinner line for no reason.
  const anyPending = pendingAwsVerifications.size > 0 || pendingPlanetScaleVerifications.size > 0 ||
    pendingMongoDbAtlasVerifications.size > 0 ||
    [...pendingSimpleVerifications.values()].some((byValue) => byValue.size > 0);
  if (verify && anyPending && typeof onBeforeVerify === "function") onBeforeVerify();

  // Same field names (verified/verifiedDetail) regardless of which vendor
  // produced the result: rotation.js and report.js render them identically,
  // and the finding's own ruleId already says which vendor answered.
  const applyVerifyResult = (refs, result) => {
    for (const ref of refs) {
      ref.verified = result.status;
      ref.verifiedDetail = result.detail;
    }
  };
  const awsAvailable = pendingAwsVerifications.size === 0 || isAwsCliAvailable();
  // stderr, not stdout: color.js's supportsColor checks whichever stream is
  // passed to it, and this table is never written to stdout, so it must
  // check stderr's own TTY status, not borrow stdout's (piping stdout to a
  // file while stderr still reaches a real terminal is a real case: `scan
  // --verify --json > out.json` should still color this table).
  const paint = makePaint(noColor, process.stderr);
  // Populated inside the disclosure block below (when there's something to
  // verify), then read again once every verify loop below has finished, to
  // print the results table. Declared out here, not inside that block, so
  // it survives to that second read.
  let verifyRows = [];
  if (verify && anyPending) {
    // One disclosure, not one per vendor: this used to print a full
    // "this is a real network request..." paragraph for EACH vendor in
    // turn, so a scan touching nine vendors put nine near-identical
    // paragraphs on screen before any results — a wall of repeated
    // boilerplate, caught live as bad UX. The safety-relevant fact (real
    // outbound calls, using the exact matched value, one at a time) only
    // needs saying once; per-vendor detail becomes a compact count table.
    // Deliberately not gated on isTTY like the scan spinner: a script
    // piping through a pager or into a log still needs this disclosure.
    //
    // Went through two earlier shapes, each missing what mattered: first a
    // bare vendor+count ("AWS  2", which credential?), then vendor+endpoint
    // +count ("AWS  sts:get-caller-identity  2", still no way to tell WHICH
    // two). What answers "which needs to be handled" is the same redacted
    // preview (first/last 4 characters) already shown for that finding
    // everywhere else in the report — reusing redact() on the same raw
    // value record() was called with, not a second display convention.
    // One line per vendor+endpoint header, one indented line per credential.
    //
    // Each row also carries a `resultFinding` per credential: a direct
    // reference to the finding object applyVerifyResult mutates below (the
    // access-key/secret finding for AWS, the secret finding for
    // PlanetScale/MongoDB Atlas, the finding itself for a simple vendor).
    // Captured now, read after the verify loops run, so the results table
    // further down needs no second vendor-shape dispatch of its own.
    verifyRows = [];
    if (pendingAwsVerifications.size > 0 && awsAvailable) {
      verifyRows.push(["AWS", "sts:get-caller-identity",
        [...pendingAwsVerifications.entries()].map(([value, { refs }]) => ({ value, resultFinding: refs[0].akiaFinding }))]);
    }
    if (pendingPlanetScaleVerifications.size > 0) {
      verifyRows.push(["PlanetScale", "organizations endpoint",
        [...pendingPlanetScaleVerifications.entries()].map(([value, { refs }]) => ({ value, resultFinding: refs[0].secretFinding }))]);
    }
    if (pendingMongoDbAtlasVerifications.size > 0) {
      verifyRows.push(["MongoDB Atlas", "oauth/token endpoint",
        [...pendingMongoDbAtlasVerifications.entries()].map(([value, { refs }]) => ({ value, resultFinding: refs[0].secretFinding }))]);
    }
    for (const [ruleId, byValue] of pendingSimpleVerifications) {
      if (byValue.size === 0) continue;
      const [vendor, endpoint] = SIMPLE_VERIFY_VENDOR_LABEL[ruleId].split("'s ");
      verifyRows.push([vendor, endpoint,
        [...byValue.entries()].map(([value, { refs }]) => ({ value, resultFinding: refs[0] }))]);
    }
    if (verifyRows.length > 0) {
      const table = verifyRows
        .map(([vendor, endpoint, credentials]) =>
          `    ${paint(c.bold + c.cyan, vendor)} ${paint(c.dim, "·")} ${paint(c.dim, endpoint)}\n` +
          credentials.map(({ value }) => `        ${redact(value)}`).join("\n"))
        .join("\n");
      process.stderr.write(
        paint(c.yellow + c.bold, "residoo --verify:") +
        " checking whether these credentials are still active. Real network " +
        "calls, using the exact value found in your transcript, one at a time. Nothing is cached " +
        "or sent anywhere but the endpoint listed below.\n\n" +
        table + "\n\n"
      );
    }
    if (pendingAwsVerifications.size > 0 && !awsAvailable) {
      process.stderr.write(
        paint(c.yellow + c.bold, "residoo --verify:") +
        " the aws CLI was not found on PATH, so the " +
        `${pendingAwsVerifications.size} AWS credential(s) found in this scan could not be checked. ` +
        "Install it (https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html) to use --verify.\n"
      );
    }
  }
  if (verify && pendingAwsVerifications.size > 0) {
    const applyPair = (refs, result) => {
      for (const ref of refs) {
        applyVerifyResult([ref.akiaFinding, ref.secretFinding], result);
      }
    };
    if (!awsAvailable) {
      const result = { status: "error", detail: "aws CLI not found on PATH" };
      for (const { refs } of pendingAwsVerifications.values()) applyPair(refs, result);
    } else {
      for (const [accessKeyValue, { secretValue, refs }] of pendingAwsVerifications) {
        const result = verifyAwsCredential(accessKeyValue, secretValue);
        applyPair(refs, result);
      }
    }
  }
  if (verify && pendingPlanetScaleVerifications.size > 0) {
    for (const [secretValue, { idValue, refs }] of pendingPlanetScaleVerifications) {
      const result = await verifyPlanetScaleToken(idValue, secretValue);
      for (const ref of refs) applyVerifyResult([ref.secretFinding, ref.idFinding], result);
    }
  }
  if (verify && pendingMongoDbAtlasVerifications.size > 0) {
    for (const [secretValue, { idValue, refs }] of pendingMongoDbAtlasVerifications) {
      const result = await verifyMongoDbAtlasCredential(idValue, secretValue);
      for (const ref of refs) applyVerifyResult([ref.secretFinding, ref.idFinding], result);
    }
  }
  if (verify) {
    for (const [ruleId, byValue] of pendingSimpleVerifications) {
      if (byValue.size === 0) continue;
      const verifyFn = SIMPLE_VERIFY_FNS[ruleId];
      for (const [value, { refs }] of byValue) {
        const result = await verifyFn(value);
        applyVerifyResult(refs, result);
      }
    }
  }

  if (verify && verifyRows.length > 0) {
    // Same vendor/endpoint grouping as the disclosure table above, now
    // showing what each call actually found. An ACTIVE credential is a
    // real, present-tense risk, colored the same red/bold the Rotation
    // section below uses for the identical fact ("rotate immediately");
    // "could not verify" gets the same red/bold too, on purpose, matching
    // this project's fail-safe-direction policy of treating "unknown" as
    // "assume risk" rather than as reassuring silence. Stamped with when
    // this check actually ran, so a report read later (pasted into a
    // ticket, screenshotted) doesn't silently imply "still true right now."
    const checkedAt = localTimestamp(new Date());
    const describeResult = (finding) => {
      if (finding.verified === "active") {
        return paint(c.red + c.bold, `⚠ ACTIVE: real working credential`) + paint(c.dim, ` (checked ${checkedAt})`);
      }
      if (finding.verified === "invalid") {
        return paint(c.green, `✓ inactive: vendor rejected it`) + paint(c.dim, ` (checked ${checkedAt})`);
      }
      return paint(c.red + c.bold, `⚠ could not verify`) + paint(c.dim, ` (checked ${checkedAt}${finding.verifiedDetail ? `: ${finding.verifiedDetail}` : ""})`);
    };
    const resultsTable = verifyRows
      .map(([vendor, endpoint, credentials]) =>
        `    ${paint(c.bold + c.cyan, vendor)} ${paint(c.dim, "·")} ${paint(c.dim, endpoint)}\n` +
        credentials.map(({ value, resultFinding }) => `        ${redact(value)}  ${describeResult(resultFinding)}`).join("\n"))
      .join("\n");
    process.stderr.write(
      paint(c.yellow + c.bold, "residoo --verify:") + " results\n\n" +
      resultsTable + "\n\n"
    );
  }

  const distinctCounts = {};
  for (const [ruleId, set] of distinctByRule) distinctCounts[ruleId] = set.size;
  return { findings, filesScanned, sourcesScanned, bytesScanned, suppressedCount, distinctCounts, unreadableFiles };
}

/**
 * The shape of a scan() result with nothing in it — exported so callers with
 * a "nothing to scan" path (no sources on this machine) can reuse the exact
 * result shape instead of hand-typing a duplicate literal that has to be
 * remembered and kept in sync every time a new field is added here.
 */
function emptyResult() {
  return {
    findings: [], filesScanned: 0, sourcesScanned: [], bytesScanned: 0,
    suppressedCount: 0, distinctCounts: {}, unreadableFiles: [],
  };
}

// VENDOR_EXAMPLE_VALUES is exported for the smoke tests, which assert every
// literal in it is still matched IN FULL by some detection rule — a literal
// no rule can produce as a whole match is dead weight that suppresses nothing.
// Rule ids `scan({verify: true})` knows how to check live, for callers (the
// residoo_verify_finding MCP tool) that need to tell a caller upfront
// whether a given finding's ruleId is even eligible, without attempting a
// scan first. AWS/PlanetScale/MongoDB Atlas pairs are deliberately excluded
// here even though `scan()` itself does verify them: each needs BOTH halves
// of a pair in hand at once, which a single fingerprint alone can't express,
// so residoo_verify_finding's v1 only supports the single-token vendors below.
const VERIFIABLE_RULE_IDS = new Set(Object.keys(SIMPLE_VERIFY_FNS));

module.exports = { scan, emptyResult, VENDOR_EXAMPLE_VALUES, VERIFIABLE_RULE_IDS };
