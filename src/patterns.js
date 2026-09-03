"use strict";

/**
 * Detection rules for residoo.
 *
 * Every rule is high-confidence by design: a security tool that cries wolf gets
 * uninstalled. Broad, noisy patterns (bare "password=" style matches) are
 * deliberately left out of the default set rather than included and caveated —
 * see NOISY_PATTERNS below if you want them anyway via --include-noisy.
 *
 * `confidence: "high"` = the shape is specific enough that a match is almost
 * certainly real (a vendor-prefixed token format). `confidence: "medium"` =
 * shape-based, occasionally a placeholder or test fixture.
 */

const PATTERNS = [
  { id: "aws_access_key_id", label: "AWS Access Key ID", confidence: "high",
    re: /\bAKIA[0-9A-Z]{16}\b/g },
  { id: "aws_session_token", label: "AWS Temporary Access Key ID", confidence: "high",
    re: /\bASIA[0-9A-Z]{16}\b/g },
  { id: "private_key_block", label: "Private key block", confidence: "high",
    re: /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/g },
  { id: "github_pat", label: "GitHub personal access token", confidence: "high",
    re: /\bgh[pousr]_[A-Za-z0-9]{36,255}\b/g },
  { id: "gitlab_pat", label: "GitLab personal access token", confidence: "high",
    re: /\bglpat-[A-Za-z0-9_-]{20,100}\b/g },
  { id: "slack_token", label: "Slack token", confidence: "high",
    re: /\bxox[baprs]-[0-9A-Za-z-]{10,500}\b/g },
  { id: "stripe_key", label: "Stripe API key (live mode)", confidence: "high",
    re: /\b(sk|rk)_live_[A-Za-z0-9]{20,250}\b/g },
  // The sandbox-mode twin of the rule above, same body charset and the same
  // 20-char floor. Format verified against two production detectors plus the
  // vendor (2026-09-02): gitleaks' stripe-access-token rule matches
  // (sk|rk)_(test|live|prod)_[a-zA-Z0-9]{10,99}; trufflehog's Stripe
  // detector is [rs]k_live_[a-zA-Z0-9]{20,247} with an explicit
  // "doesn't include test keys" comment (a scope choice, not a format
  // claim); and Stripe's own docs (docs.stripe.com/keys) name sk_test_ and
  // rk_test_ as the sandbox secret/restricted prefixes. A separate rule
  // rather than a widened live regex so a report can say WHICH mode leaked
  // and rotation guidance can differ. A test key in a transcript is a real
  // finding, not noise: the prefix is vendor-unique, the key grants full
  // API access to the sandbox account (Stripe's docs: a secret key has
  // unrestricted permissions on all Stripe APIs in its mode, and sandbox
  // mode exposes ALL of the account's keys to whoever can call it), and a
  // transcript that pastes sk_test today is the same workflow that will
  // paste sk_live at go-live.
  { id: "stripe_test_key", label: "Stripe API key (test mode)", confidence: "high",
    re: /\b(sk|rk)_test_[A-Za-z0-9]{20,250}\b/g },
  // The negative lookahead keeps this rule mutually exclusive with anthropic_key
  // and openrouter_key below — without it, "sk-ant-..." or "sk-or-v1-..." match
  // BOTH this pattern and the more specific one, and get reported twice under
  // two different (one wrong) provider labels. Verified: all three regexes
  // independently matched their overlapping synthetic keys before this fix.
  { id: "openai_key", label: "OpenAI API key", confidence: "high",
    re: /\bsk-(?!ant-|or-)(proj-)?[A-Za-z0-9_-]{20,300}\b/g },
  { id: "anthropic_key", label: "Anthropic API key", confidence: "high",
    re: /\bsk-ant-[A-Za-z0-9_-]{20,300}\b/g },
  { id: "google_api_key", label: "Google / Firebase API key", confidence: "high",
    re: /\bAIza[0-9A-Za-z_-]{35}\b/g },
  { id: "npm_token", label: "npm access token", confidence: "high",
    re: /\bnpm_[A-Za-z0-9]{36}\b/g },
  { id: "sendgrid_key", label: "SendGrid API key", confidence: "high",
    re: /\bSG\.[A-Za-z0-9_-]{16,100}\.[A-Za-z0-9_-]{16,100}\b/g },
  { id: "twilio_key", label: "Twilio API key", confidence: "high",
    re: /\bSK[a-f0-9]{32}\b/g },
  { id: "jwt", label: "JWT-shaped token", confidence: "medium",
    re: /\beyJ[A-Za-z0-9_-]{10,2000}\.eyJ[A-Za-z0-9_-]{10,20000}\.[A-Za-z0-9_-]{10,2000}\b/g },
  { id: "connection_string_with_password", label: "Database connection string with embedded password", confidence: "high",
    re: /\b(postgres(?:ql)?|mysql|mongodb(?:\+srv)?):\/\/[^\s:@\/]{1,255}:[^\s@\/]{3,255}@[^\s\/]{1,255}/g },
  { id: "bearer_header", label: "Authorization: Bearer header with a real-looking token", confidence: "medium",
    re: /\bauthorization["']?\s*[:=]\s*["']?bearer\s+[A-Za-z0-9._-]{16,1000}/gi },
  { id: "refresh_token_field", label: "refresh_token field", confidence: "medium",
    re: /"refresh_token"\s*:\s*"[^"\s]{20,4000}"/gi },
  { id: "access_token_field", label: "access_token field", confidence: "medium",
    re: /"access_token"\s*:\s*"[^"\s]{20,4000}"/gi },

  // ── AI / LLM providers (added: competitive gap-close, see project history) ─
  // Every regex body below was checked against a production, field-tested
  // detector — trufflehog's (github.com/trufflesecurity/trufflehog,
  // pkg/detectors/<vendor>) — not guessed from a blog post, as of 2026-09.
  // Cohere, Mistral, Together AI, Fireworks and DeepSeek were researched too
  // and deliberately left out: none has a trufflehog detector, official docs
  // describe them as unprefixed/opaque tokens, and DeepSeek's "sk-" prefix is
  // provably indistinguishable from OpenAI's (trufflehog's own DeepSeek
  // detector only fires with a nearby "deepseek" keyword as extra context,
  // which this flat-regex model doesn't have) — exactly the shaky-prefix case
  // this file's own header comment says to leave out rather than force.
  { id: "groq_key", label: "Groq API key", confidence: "high",
    re: /\bgsk_[a-zA-Z0-9]{52}\b/g },
  { id: "xai_key", label: "xAI (Grok) API key", confidence: "high",
    re: /\bxai-[0-9a-zA-Z_]{80}\b/g },
  { id: "openrouter_key", label: "OpenRouter API key", confidence: "high",
    re: /\bsk-or-v1-[0-9a-f]{64}\b/g },
  { id: "huggingface_token", label: "Hugging Face access token", confidence: "high",
    re: /\b(?:hf_|api_org_)[a-zA-Z0-9]{34}\b/g },
  { id: "pinecone_key", label: "Pinecone API key", confidence: "high",
    re: /\bpcsk_[A-Za-z0-9]{5,6}_[A-Za-z0-9]{63}\b/g },
  // No trufflehog detector exists for this one, so it leans on a second,
  // independent signal instead: Perplexity's own product is literally named
  // "pplx-api" (see their "Introducing pplx-api" launch post), and every
  // integration doc that shows a real key (liteLLM, apideck, etc.) agrees on
  // "pplx-" + a >=40-char body — consistent across independent sources even
  // without one canonical spec page.
  { id: "perplexity_key", label: "Perplexity API key", confidence: "high",
    re: /\bpplx-[A-Za-z0-9]{40,200}\b/g },
  { id: "replicate_token", label: "Replicate API token", confidence: "high",
    re: /\br8_[0-9A-Za-z_-]{37}\b/g },
  // Confirmed via ElevenLabs' own docs (elevenlabs.io/docs/api-reference/authentication):
  // sk_ + 48 hex. Distinct from the sk-/sk_live_/sk_test_ families above —
  // underscore not hyphen, and no "_live_"/"_test_" substring, so it cannot
  // collide with any of them.
  { id: "elevenlabs_key", label: "ElevenLabs API key", confidence: "high",
    re: /\bsk_[a-f0-9]{48}\b/g },

  // ── Cloud / infra ──────────────────────────────────────────────────────
  { id: "digitalocean_token", label: "DigitalOcean access token", confidence: "high",
    re: /\b(?:dop|doo|dor)_v1_[a-f0-9]{64}\b/g },
  { id: "supabase_token", label: "Supabase personal access token", confidence: "high",
    re: /\bsbp_[a-z0-9]{40}\b/g },
  // Confirmed via planetscale.com/docs/api/reference/service-tokens: the
  // secret half of a service token pair. The id half (12 lowercase
  // alphanumeric characters, no prefix) is not a rule on its own for the
  // same reason AWS's secret access key isn't: on its own it is
  // indistinguishable from any other short id. Instead it is found the
  // same way AWS's secret is (see pairing.js's findNearbyCandidate), just
  // with the anchor and candidate roles swapped — this prefixed secret is
  // the confirmed anchor, and the id is the nearby unprefixed candidate.
  { id: "planetscale_secret", label: "PlanetScale service token", confidence: "high",
    re: /\bpscale_tkn_[A-Za-z0-9_]{43}\b/g },
  // Current CircleCI PAT format only (CCIPAT_<22 alnum>_<40 hex>, confirmed
  // via circleci.com/docs/api/v2). The legacy format is a bare 40-char hex
  // string with no prefix at all — nowhere near specific enough to be a
  // vendor signal, so deliberately left out, same reasoning as Vault's
  // legacy "s." format above.
  { id: "circleci_token", label: "CircleCI personal API token", confidence: "high",
    re: /\bCCIPAT_[A-Za-z0-9]{22}_[a-f0-9]{40}\b/g },
  // Confirmed via airtable.com/developers/web/api: pat + 14 alnum + "." + 64 hex.
  { id: "airtable_token", label: "Airtable personal access token", confidence: "high",
    re: /\bpat[A-Za-z0-9]{14}\.[a-f0-9]{64}\b/g },
  // Current Cloudflare API Token format only (cfat_/cfut_, confirmed via
  // developers.cloudflare.com). The legacy format is a bare 40-char string
  // with no prefix, left out for the same reason as CircleCI's legacy form.
  { id: "cloudflare_api_token", label: "Cloudflare API token", confidence: "high",
    re: /\bcf[au]t_[a-zA-Z0-9]{40}[a-f0-9]{8}\b/g },
  // Current Heroku API key format only (HRKU-AA + 58 chars, confirmed via
  // Heroku's own help docs). The legacy format is a bare UUID, left out:
  // "any UUID-shaped string" is exactly the noisy, unspecific shape this
  // file's header says to avoid.
  { id: "heroku_api_key", label: "Heroku API key", confidence: "high",
    re: /\bHRKU-AA[0-9a-zA-Z_-]{58}\b/g },
  // Current Netlify PAT format only (nfp_ + 36, confirmed via trufflehog's
  // live netlify/v2 detector). The legacy format is a bare 43-45 char
  // opaque string with no prefix, left out for the same reason as above.
  { id: "netlify_token", label: "Netlify personal access token", confidence: "high",
    re: /\bnfp_[a-zA-Z0-9_]{36}\b/g },
  // Confirmed via vercel.com/docs/accounts/access-tokens (updated 2026-08):
  // "Personal access tokens begin with the prefix vcp_", 24-char alnum
  // body shown in the docs' own example. A recent format rollout — an
  // earlier research pass on this vendor found no confirmed prefix at all,
  // since the vendor had not yet published this shape.
  { id: "vercel_token", label: "Vercel personal access token", confidence: "high",
    re: /\bvcp_[A-Za-z0-9]{24}\b/g },
  // Fly.io issues a second token family too (fm1a_/fm1r_/fm2_
  // "macaroons"), confirmed straight from Fly's own macaroon library
  // source (github.com/superfly/macaroon, format.go). Deliberately NOT a
  // rule here: caught live on this project's own real-machine testing, the
  // macaroon shape (a short 4-5 char prefix plus a WIDE 100-700 char plain
  // base64 body, no further structure) produced 16 distinct apparent
  // matches inside a single real, unrelated job-queue log file that simply
  // contained a lot of embedded base64 data — a real false-positive rate,
  // not a hypothetical one, and exactly the noisy-shape case this file's
  // own header says to leave out. fo1_ below did not show this problem
  // (its body is a FIXED 43-char requirement, far less permissive), so
  // that half of Fly.io's tokens is still covered.
  { id: "flyio_bearer_token", label: "Fly.io API token", confidence: "high",
    re: /\bfo1_[\w-]{43}\b/g },
  // Prefix confirmed via Cerebras' own docs (inference-docs.cerebras.ai:
  // "API Key (starts with csk-)"), but Cerebras has not published an exact
  // body length — same situation as notion_token's ntn_ format above, so
  // the bound here is a floor and a generous ceiling, not a verified exact
  // count.
  { id: "cerebras_key", label: "Cerebras API key", confidence: "high",
    re: /\bcsk-[A-Za-z0-9]{20,200}\b/g },
  // Prefix confirmed via Render's own docs (render.com, appears 6 times in
  // the full-text docs dump), body length not published — same
  // floor/ceiling treatment as Cerebras above.
  { id: "render_key", label: "Render API key", confidence: "high",
    re: /\brnd_[A-Za-z0-9]{20,200}\b/g },
  { id: "vault_token", label: "HashiCorp Vault service token", confidence: "high",
    // Vault 1.10+ format only (hvs.<90-120 chars>). The pre-1.10 legacy
    // format is a bare "s." + 18-40 chars — "s." is nowhere near specific
    // enough to be a vendor prefix, so that older shape is deliberately left
    // out rather than turned into a noisy 2-character trigger.
    re: /\bhvs\.[A-Za-z0-9_-]{90,120}\b/g },
  { id: "onepassword_service_token", label: "1Password service account token", confidence: "high",
    // Confirmed against 1Password's own developer docs (developer.1password.com
    // -> 1password.dev/service-accounts/security): the token is "ops_" plus a
    // base64-encoded JWT, so it always continues "eyJ" (base64 of `{"`).
    re: /\bops_eyJ[A-Za-z0-9+/=_-]{40,2000}\b/g },

  // ── Comms / SaaS ───────────────────────────────────────────────────────
  { id: "discord_webhook", label: "Discord webhook URL", confidence: "high",
    re: /\bhttps:\/\/discord\.com\/api\/webhooks\/[0-9]{18,19}\/[0-9a-zA-Z_-]{68}\b/g },
  { id: "telegram_bot_token", label: "Telegram bot token", confidence: "high",
    re: /\b[0-9]{8,10}:[a-zA-Z0-9_-]{35}\b/g },
  { id: "mailgun_key", label: "Mailgun API key", confidence: "high",
    re: /\bkey-[a-z0-9]{32}\b/g },
  // Notion's own docs explicitly warn against regex-matching its tokens,
  // since the format has changed before and may again — noted, not ignored,
  // and worth restating here rather than treating this as equally solid as
  // the others. secret_ (legacy, exactly 43 chars) is trufflehog-verified;
  // ntn_ (current format since 2024-09-25) is vendor-confirmed as a prefix
  // but Notion has not published an exact body length for it, so its bound
  // below is a floor, not a verified exact count.
  { id: "notion_token", label: "Notion integration token", confidence: "high",
    re: /\b(?:secret_[A-Za-z0-9]{43}|ntn_[A-Za-z0-9]{20,200})\b/g },
  { id: "linear_key", label: "Linear API key", confidence: "high",
    re: /\blin_api_[0-9A-Za-z]{40}\b/g },
  { id: "sentry_token", label: "Sentry auth token", confidence: "high",
    // Covers both current Sentry token shapes: org-scoped (sntrys_, base64
    // JWT-like body) and user-scoped (sntryu_, hex body).
    re: /\b(?:sntrys_eyJ[A-Za-z0-9+/=_]{100,4000}|sntryu_[a-f0-9]{64})\b/g },
];

/**
 * Broader, shape-based patterns that catch more but false-positive more often —
 * a bare `password = "..."` line is frequently a placeholder, a variable name,
 * or documentation. Opt-in only, never part of the headline count.
 */
const NOISY_PATTERNS = [
  { id: "generic_password_assignment", label: "password / pwd assignment", confidence: "low",
    re: /\b(password|passwd|pwd)\s*[:=]\s*["']?[^\s"']{6,500}["']?/gi },
  { id: "generic_secret_assignment", label: "generic secret / apikey assignment", confidence: "low",
    re: /\b(api[_-]?key|secret)\s*[:=]\s*["']?[A-Za-z0-9_\-\/+=]{12,500}["']?/gi },
];

/**
 * Strip C0 control characters (0x00-0x1F) and DEL (0x7F) — this is where ANSI
 * escape sequences live. Two of the rules above (connection strings, the
 * *_token_field rules) match against a negated character class that excludes
 * whitespace and quotes but NOT control bytes, so a crafted or malformed
 * transcript line could otherwise put a raw terminal-control sequence into
 * this tool's own report output. Verified: an unsanitized preview containing
 * "\x1b[2J" actually clears the screen when printed. Applied here, at the
 * one place raw matched text turns into displayable text, rather than left
 * to every call site to remember.
 */
// A plain regex, not a manual code-point loop: control characters (0x00-0x1F,
// 0x7F) are single UTF-16 units that never overlap a surrogate-pair half
// (those live at 0xD800-0xDFFF), so stripping them by regex can't split or
// corrupt a multi-unit character — no code-point-aware iteration needed here.
function stripControlChars(s) { return s.replace(/[\x00-\x1f\x7f]/g, ""); }

/** Mask a matched value for display: never print secret material to a terminal. */
function redact(value) {
  const v = stripControlChars(String(value));
  // Split by code point (Array.from, not .slice/.length) — several rules
  // match via a negated character class that doesn't exclude non-ASCII, so a
  // matched value CAN contain an astral character (surrogate pair)
  // straddling a UTF-16 cut point. .slice(0,4) on the raw string can then
  // return one half of a pair, rendering as a broken glyph.
  const cps = Array.from(v);
  // Every number in this function's OUTPUT — the count included — must come
  // from the same stripped, code-point-split value the preview itself is
  // built from. An earlier version reported String(value).length (the raw,
  // pre-strip, UTF-16-unit count) here: whenever a match actually contained
  // stripped control bytes, or an astral character, the parenthetical count
  // visibly didn't match what the preview showed — the exact kind of
  // internal inconsistency this function exists to avoid.
  if (cps.length === 0) return "";
  if (cps.length <= 10) return "*".repeat(cps.length);
  return cps.slice(0, 4).join("") + "…" + cps.slice(-4).join("") + `  (${cps.length} chars)`;
}

module.exports = { PATTERNS, NOISY_PATTERNS, redact };
