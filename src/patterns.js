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
  // Widened twice from the original gh[pousr]_[A-Za-z0-9]{36,255}, both
  // confirmed via GitHub's own docs (docs.github.com, authentication
  // overview): (1) fine-grained PATs use an entirely disjoint literal
  // prefix, github_pat_, not gh[pousr]_ at all -- the original regex
  // could never match one; (2) GitHub's own 2026-04-24 changelog post
  // shows App installation tokens (ghs_) rolling out to a new
  // ghs_<appid>_<3-segment-JWT> shape, whose dots fell outside the old
  // [A-Za-z0-9] body class. The distinctive prefix carries the FP
  // protection, so widening the body to include . _ - is safe.
  { id: "github_pat", label: "GitHub personal access token", confidence: "high",
    re: /\b(?:gh[pousr]_|github_pat_)[A-Za-z0-9_.-]{20,600}\b/g },
  { id: "gitlab_pat", label: "GitLab personal access token", confidence: "high",
    re: /\bglpat-[A-Za-z0-9_-]{20,100}\b/g },
  // GitLab's OTHER token kinds, beyond the personal access token above --
  // deploy, runner, CI/CD job, trigger, feed, incoming-mail, agent,
  // workspace, SCIM, feature-flags-client, and OAuth-app-secret tokens.
  // All prefixes taken directly from GitLab's own published table
  // (docs.gitlab.com/security/tokens/), which gives every prefix but no
  // exact body length for any of them -- one bundled rule rather than
  // eleven near-identical ones, since they share the same risk profile
  // (repo/registry/CI access) and the same rotation path (Settings >
  // Access Tokens for the relevant scope).
  { id: "gitlab_other_token", label: "GitLab token (deploy/runner/CI/other)", confidence: "high",
    re: /\bgl(?:oas|dt|rtr|rt|cbt|ptt|ft|imt|agent|wt|soat|ffct)-[A-Za-z0-9_-]{16,100}\b/g },
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
  // Stripe webhook signing secret. Found missing by reading TruffleHog's
  // own open-issue tracker (trufflesecurity/trufflehog#4711 and #4609,
  // both open, both unaddressed) -- a real, disclosed gap, not unique to
  // residoo: neither TruffleHog nor gitleaks (checked gitleaks.toml
  // directly) has this rule either, and no exact-length spec is published
  // anywhere found (Stripe's own docs name the whsec_ prefix but not a
  // length). Shipped anyway on the strength of the prefix alone: "whsec_"
  // is distinctive enough on its own that a generous length bound carries
  // negligible false-positive risk even without a confirmed exact count,
  // unlike a short/generic prefix where that same generosity would matter.
  { id: "stripe_webhook_secret", label: "Stripe webhook signing secret", confidence: "high",
    re: /\bwhsec_[A-Za-z0-9]{24,64}\b/g },
  // Azure AD (Entra ID) client secret. Found missing by cross-checking
  // gitleaks' own open-issue tracker (gitleaks/gitleaks#1687), which
  // asked for Azure coverage generally -- gitleaks itself already has a
  // rule (id "azure-ad-client-secret" in its own gitleaks.toml), so this
  // is adapted directly from that battle-tested pattern rather than
  // designed from scratch: 2-4 chars, one digit, the literal "Q~"
  // marker, then 28-36 more chars. No capture group (unlike gitleaks'
  // Go regex), to match every other rule in this file using the whole
  // match as the value; zero-width lookaround used instead of gitleaks'
  // literal delimiter character classes for the same reason -- the
  // charset includes non-word characters (~ .) that a plain \b boundary
  // can't reliably bound. Azure Storage Account keys were investigated
  // and NOT added: they're a bare, unprefixed base64 blob (~88 chars,
  // confirmed via learn.microsoft.com), the same unsafe generic shape
  // already excluded for Weights & Biases' classic key format.
  { id: "azure_ad_client_secret", label: "Azure AD (Entra ID) client secret", confidence: "high",
    re: /(?<![A-Za-z0-9_.~-])[A-Za-z0-9_.~]{2,4}\dQ~[A-Za-z0-9_.~-]{28,36}(?![A-Za-z0-9_.~-])/g },
  // Azure DevOps PAT. Microsoft's own current docs (learn.microsoft.com,
  // .../use-personal-access-tokens-to-authenticate, updated 2026-07-08)
  // state: "Tokens are 84 characters long, with 52 characters being
  // randomized data... Tokens issued by Azure DevOps include a fixed AZDO
  // signature at positions 76-80." That description is imprecise about
  // the exact byte offset (a 4-char literal can't cleanly occupy a
  // 5-position range), so rather than hard-code a single offset that
  // might be off by one and never match a real token, this allows a
  // window for where AZDO can sit while still requiring both the fixed
  // literal anchor and a close-to-84 overall length -- the anchor is what
  // actually carries the false-positive protection.
  { id: "azure_devops_pat", label: "Azure DevOps personal access token", confidence: "high",
    re: /\b[A-Za-z0-9]{65,75}AZDO[A-Za-z0-9]{5,15}\b/g },
  // Atlassian Cloud API token (classic/scoped). Prefix and structure from
  // noseyparker's own shipped rule; independently confirmed current via
  // an Atlassian staff reply on Atlassian's own community forum naming
  // the three current token families and their prefixes (API Token:
  // ATAT, App Password: ATBB, Access Tokens: ATCT) -- this rule covers
  // only the first, most common one. The newer Access Token family
  // (ATCTT3xFfGN0...) exists per that same staff reply but with no
  // length/charset spec found anywhere, so it isn't guessed at here.
  { id: "atlassian_api_token", label: "Atlassian Cloud API token", confidence: "high",
    re: /\bATATT3xFfGF0[A-Za-z0-9_-]{20,200}=[0-9A-F]{8}\b/g },
  // Tailscale auth key. Found missing via gitleaks/gitleaks#1778 (still
  // open there too). No fully authoritative current spec found: Tailscale's
  // own kb/1085/auth-keys page shows an older bare "tskey-<hex>" example,
  // while more recent third-party usage consistently shows a newer
  // "tskey-auth-<id>-<secret>" two-segment form -- genuine format
  // evolution, not a single confirmed shape. Covers both on the strength
  // of the "tskey-" prefix alone, which carries negligible false-positive
  // risk regardless of which era's exact body shape is present, same
  // reasoning as whsec_ above.
  { id: "tailscale_auth_key", label: "Tailscale auth key", confidence: "high",
    re: /\btskey-(?:auth-)?[A-Za-z0-9-]{15,80}\b/g },
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
  // Found via a competitor research pass mining noseyparker/ggshield/
  // detect-secrets (2026-09-04). PyPI publishes its own regex directly
  // (docs.pypi.org/api/secrets/): "pypi-[A-Za-z0-9-_]{85,}", no stated
  // upper bound ("can be arbitrarily long") -- capped here at 700 as a
  // practical ceiling, not a vendor limit.
  { id: "pypi_token", label: "PyPI API token", confidence: "high",
    re: /\bpypi-[A-Za-z0-9_-]{85,700}\b/g },
  // Verified against crates.io's own current token-generation source
  // (rust-lang/crates.io, crates/crates_io_database/src/utils/token.rs):
  // TOKEN_PREFIX = "cio", TOKEN_LENGTH = 32, generated via
  // rand::distr::Alphanumeric -- the strongest sourcing in this batch,
  // read from the vendor's actual live code rather than its docs.
  { id: "crates_io_key", label: "crates.io API token", confidence: "high",
    re: /\bcio[A-Za-z0-9]{32}\b/g },
  // Exact length independently counted against RubyGems' own guide
  // (guides.rubygems.org/rubygems-org-api/), whose worked example shows
  // the body as exactly 48 lowercase hex characters after the prefix.
  { id: "rubygems_key", label: "RubyGems API key", confidence: "high",
    re: /\brubygems_[a-f0-9]{48}\b/g },
  // Docker's own OpenAPI spec (docker/docs, content/reference/api/
  // ai-governance/api.yaml) names both prefixes explicitly -- Personal
  // Access Token dckr_pat_*, Organization Access Token dckr_oat_* -- but
  // gives no exact body length/charset for either, hence the generous
  // bound already used elsewhere in this file for the same situation.
  { id: "docker_hub_token", label: "Docker Hub access token", confidence: "high",
    re: /\bdckr_(?:pat|oat)_[A-Za-z0-9_-]{20,200}\b/g },
  { id: "sendgrid_key", label: "SendGrid API key", confidence: "high",
    re: /\bSG\.[A-Za-z0-9_-]{16,100}\.[A-Za-z0-9_-]{16,100}\b/g },
  { id: "twilio_key", label: "Twilio API key", confidence: "high",
    re: /\bSK[a-f0-9]{32}\b/g },
  { id: "jwt", label: "JWT-shaped token", confidence: "medium",
    re: /\beyJ[A-Za-z0-9_-]{10,2000}\.eyJ[A-Za-z0-9_-]{10,20000}\.[A-Za-z0-9_-]{10,2000}\b/g },
  { id: "connection_string_with_password", label: "Database connection string with embedded password", confidence: "high",
    re: /\b(postgres(?:ql)?|mysql|mongodb(?:\+srv)?):\/\/[^\s:@\/]{1,255}:[^\s@\/]{3,255}@[^\s\/]{1,255}/g },
  // \b alone missed a real shape: transcript text that embeds a literal
  // newline as a JSON string escape ("\n", two characters: backslash then
  // the letter n) leaves that trailing "n" glued directly to the "A" of
  // "Authorization" with no actual whitespace between them on the scanned
  // line, and \b never fires between two word characters. (?<=\\n) is the
  // fix: it also accepts the position right after a literal "\n" escape as
  // a valid left edge, alongside \b's normal boundary — found via this
  // project's own benchmark (bench/RESULTS.md), not a hypothetical.
  { id: "bearer_header", label: "Authorization: Bearer header with a real-looking token", confidence: "medium",
    re: /(?:\b|(?<=\\n))authorization["']?\s*[:=]\s*["']?bearer\s+[A-Za-z0-9._-]{16,1000}/gi },
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
  // Third batch from the 2026-09-04 competitor research pass. NVIDIA's own
  // docs (docs.nvidia.com) confirm the nvapi- prefix ("Keys typically start
  // with nvapi-") without stating an exact length.
  { id: "nvidia_api_key", label: "NVIDIA API key", confidence: "high",
    re: /\bnvapi-[A-Za-z0-9_-]{40,200}\b/g },
  // Jina AI: prefix confirmed via Jina's own GitHub org/SDKs and broad
  // ecosystem documentation; exact 60-char length taken from noseyparker's
  // own shipped rule, not independently pinned by a Jina spec page.
  { id: "jina_key", label: "Jina AI API key", confidence: "high",
    re: /\bjina_[A-Za-z0-9]{60}\b/g },
  // Tavily: tvly- prefix confirmed via Tavily's own official SDK repos
  // (tavily-python, tavily-js); exact 32-char length not independently
  // pinned by a dedicated format spec page.
  { id: "tavily_key", label: "Tavily API key", confidence: "high",
    re: /\btvly-[A-Za-z0-9]{32}\b/g },
  // Firecrawl: fc- prefix appears in Firecrawl's own docs and SDKs, but
  // only as illustrative placeholders -- no page independently confirms
  // the exact 32-lowercase-hex body. Shipped anyway on the combination of
  // the prefix plus a strict hex-only body requirement right after it.
  { id: "firecrawl_key", label: "Firecrawl API key", confidence: "high",
    re: /\bfc-[a-f0-9]{32}\b/g },
  // Databricks PAT: Databricks' own docs deliberately show only placeholder
  // tokens, no real format. Corroborated by two independent secondary
  // sources instead -- Microsoft Purview's own Sensitive-Information-Type
  // definition for Azure Databricks PATs, and TruffleHog's shipped OSS
  // detector -- both agreeing on dapi + 32 lowercase hex, optionally a
  // trailing -<digits>. Not Databricks-primary-sourced, so flagged medium
  // rather than high like the rest of this file. The strict lowercase-hex
  // body avoids the one real collision risk found during research: Binance
  // also uses a "dapi" naming convention for its COIN-margined futures API
  // (e.g. dapiDataGetTopLongShortPositionRatio), but that never matches
  // since it isn't hex.
  { id: "databricks_pat", label: "Databricks personal access token", confidence: "medium",
    re: /\bdapi[a-f0-9]{32}(?:-[0-9]+)?\b/g },
  // Sourcegraph: sgp_ prefix confirmed via Sourcegraph's own docs ("Access
  // tokens now begin with the prefix sgp_"); exact body shape (an optional
  // 16-hex instance-id infix, or a local_ marker, before the 40-hex body)
  // taken from noseyparker's worked examples, not independently pinned.
  // NOTE for future additions: Segment's own "Public API Token" also uses
  // an sgp_ prefix (sgp_[a-zA-Z0-9]{64}) -- not added here, but if it ever
  // is, the two rules are already mutually exclusive (hex-only 40 vs.
  // mixed-case 64), just worth testing explicitly at that point.
  { id: "sourcegraph_token", label: "Sourcegraph access token", confidence: "high",
    re: /\bsgp_(?:[a-fA-F0-9]{16}_|local_)?[a-fA-F0-9]{40}\b/g },

  // ── Cloud / infra ──────────────────────────────────────────────────────
  { id: "digitalocean_token", label: "DigitalOcean access token", confidence: "high",
    re: /\b(?:dop|doo|dor)_v1_[a-f0-9]{64}\b/g },
  // The optional v0_ infix is NOT confirmed by Supabase's own docs -- found
  // via a gitleaks feature request (gitleaks/gitleaks#2225) whose author
  // cites real tokens seen in the wild, and cross-checked that trufflehog's
  // own supabase detector has the identical blind spot for the same
  // reason. Same honesty tier as tailscale_auth_key: shipped despite
  // imperfect vendor documentation because the addition is a narrow,
  // low-risk optional segment, not a guessed body shape.
  { id: "supabase_token", label: "Supabase personal access token", confidence: "high",
    re: /\bsbp_(?:v0_)?[a-z0-9]{40}\b/g },
  // Supabase's newer "secret key" replaces the JWT-based service_role key
  // and, unlike it, bypasses Row Level Security -- full database/storage/
  // auth access. Confirmed via supabase.com/docs/guides/api/api-keys,
  // which names sb_secret_ explicitly ("not JWTs") but does not publish an
  // exact suffix length, hence the generous floor/ceiling bound already
  // used elsewhere in this file (cerebras_key, render_key) for the same
  // situation.
  { id: "supabase_secret_key", label: "Supabase secret API key", confidence: "high",
    re: /\bsb_secret_[A-Za-z0-9_-]{20,200}\b/g },
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
  // Current Cloudflare credential formats only (cfat_/cfut_/cfk_, all three
  // confirmed via developers.cloudflare.com/fundamentals/api/get-started/token-formats,
  // which describes all three with the identical "<prefix>_[40 characters]
  // [checksum]" shape). cfk_ (Global API Key, full account access) found
  // missing by cross-checking agentsweep's own open issue tracker -- it had
  // cfat_/cfut_ before this project did, cfk_ after. The legacy formats are
  // bare unprefixed strings, left out for the same reason as CircleCI's
  // legacy form.
  { id: "cloudflare_api_token", label: "Cloudflare API token", confidence: "high",
    re: /\bcf(?:[au]t|k)_[a-zA-Z0-9]{40}[a-f0-9]{8}\b/g },
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
  // Confirmed via Neon's own changelog (neon.com/docs/changelog/2025-01-31):
  // keys created after that date are prefixed napi_ (personal), or
  // neon_org_key_ / neon_project_key_ (org and project-scoped), specifically
  // "to use secret scanning mechanisms that rely on identifiable markers" —
  // about as direct an endorsement as a vendor gives. Length/charset are
  // not published (only "randomly-generated 64-bit token," and the docs'
  // own example is a transparently synthetic placeholder), so the bound
  // here is a floor, same treatment as Cerebras/Render above. Keys created
  // before 2025-01-31 have no prefix and are not covered — a real but
  // bounded coverage gap, not a false negative in this rule's own logic.
  { id: "neon_key", label: "Neon API key", confidence: "high",
    re: /\b(?:napi_|neon_org_key_|neon_project_key_)[A-Za-z0-9]{20,}\b/g },
  // MongoDB Atlas has two distinct credential systems; only one is a rule
  // here. The legacy Programmatic API Key pair (Public Key / Private Key,
  // HTTP Digest auth) has NO prefix at all -- an 8-char alnum string and a
  // bare UUID, confirmed via MongoDB's own OpenAPI spec -- and is exactly
  // the noisy, unspecific shape this file's header says to leave out. The
  // newer Service Account pair does have a distinguishing prefix on BOTH
  // halves (confirmed in the same OpenAPI spec): mdb_sa_sk_ for the client
  // secret (this rule; length not published beyond the prefix, same
  // floor-only treatment as Cerebras/Render) and mdb_sa_id_ for the client
  // id (fully specified as exactly 24 hex characters by the spec's own
  // schema pattern, matched only as a paired candidate near this secret --
  // see pairing.js's findNearbyCandidate and PlanetScale's identical
  // secret-is-the-anchor structure above -- never as a standalone rule,
  // since verification needs both halves together).
  { id: "mongodb_atlas_secret", label: "MongoDB Atlas Service Account secret", confidence: "high",
    re: /\bmdb_sa_sk_[A-Za-z0-9]{16,}\b/g },
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
  // Discord BOT token -- a different, more sensitive credential than the
  // webhook URL above (full bot API access vs. a single channel post).
  // Three dot-separated base64url segments, first starting with M/N/O
  // (the base64 encoding of a Discord user-id snowflake's leading byte
  // range). Confirmed via Discord's own current developer docs
  // (docs.discord.com/developers/reference, shows a live example token in
  // this exact shape); same structure as detect-secrets' own shipped
  // plugin. Never collides with the jwt rule below since a JWT's first two
  // segments must start with the literal "eyJ", not M/N/O.
  { id: "discord_bot_token", label: "Discord bot token", confidence: "high",
    re: /\b[MNO][A-Za-z0-9_-]{23,25}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27}\b/g },
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
  // phx_ is PostHog's Personal API Key prefix, confirmed directly in
  // PostHog's own docs (the masked example "phx_***1234" on the personal-
  // api-keys page, and phx_ named explicitly in the API overview's GitHub
  // secret-scanning section alongside sibling prefixes for its OTHER token
  // types: phc_ is the PUBLIC project token and must never be targeted as a
  // secret, phs_/pha_/phr_ are other PostHog token families not covered
  // here). Exact length (~48 chars) is sourced from PostHog's own OSS
  // source, not prose docs, so the bound below is a generous floor rather
  // than a doc-confirmed exact count.
  { id: "posthog_key", label: "PostHog personal API key", confidence: "high",
    re: /\bphx_[A-Za-z0-9]{40,}\b/g },
  // Claude Code Remote Control session URL -- not a vendor API key, a URL
  // that IS a bearer credential: opening it in a browser grants full
  // read/write/execute access to a live local Claude Code session, no
  // further auth. Anthropic's own docs (code.claude.com/docs/en/remote-control,
  // fetched 2026-09-04) confirm this URL is printed directly into the
  // conversation ("Claude Code also posts the session URL in the
  // conversation") -- i.e. this genuinely lands in the exact transcripts
  // this project scans, not a hypothetical risk. Found via a gitleaks
  // open-issue request (gitleaks/gitleaks#2094) that proposed a
  // `session_<id>` prefix as "illustrative," unconfirmed. That guess was
  // checked against this project's own installed `claude` binary (macOS,
  // `strings /usr/local/bin/claude`) rather than assumed correct: the
  // literal web-URL template is `` `/code/${sessionId}` `` with NO prefix
  // at all, and `sessionId:mqH.randomUUID()` confirms the ID is a
  // standard UUID v4 -- both directly present in the shipped binary's own
  // strings, not inferred. The gitleaks issue's proposed pattern would
  // have MISSED every real instance of this URL.
  { id: "claude_code_remote_control_url", label: "Claude Code Remote Control session URL", confidence: "high",
    re: /\bclaude\.ai\/code\/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b/g },
  // LangSmith personal access token (lsv2_pt_) / service key (lsv2_sk_).
  // Found missing by cross-checking agentsweep's own open-issue tracker.
  // The first segment (32 hex, UUID-shaped) is consistent across every
  // real example checked (docs.langchain.com and independent citations of
  // it); the trailing segment's exact length is NOT confirmed by any
  // primary source found (two secondary citations of the same example
  // key disagreed by one character), so it's a generous bound, not a
  // doc-confirmed exact count -- same honesty standard as posthog_key
  // above. "lsv2_" itself is distinctive enough that this bound doesn't
  // meaningfully raise false-positive risk either way.
  { id: "langsmith_key", label: "LangSmith API key", confidence: "high",
    re: /\blsv2_(?:pt|sk)_[a-f0-9]{32}_[a-f0-9]{6,16}\b/g },
  // Resend API key (re_). Found missing the same way. No primary source
  // publishes an exact length spec; the one real example seen (Resend's
  // own docs) is an 8-char id segment + a 24-char secret segment, both
  // mixed-case alphanumeric, joined by one underscore. Bounded generously
  // around that shape rather than pinned to it exactly. The two-segment,
  // underscore-joined, both-high-entropy structure is deliberately what
  // makes this safe as a DEFAULT (non-noisy) rule despite the short,
  // otherwise-generic "re_" prefix: tested against realistic re_-prefixed
  // code identifiers (re_try, re_send, re_connect, re_validate...) and
  // none match, since none of them have a second underscore-delimited
  // random-looking segment.
  { id: "resend_key", label: "Resend API key", confidence: "high",
    re: /\bre_[A-Za-z0-9]{6,12}_[A-Za-z0-9]{18,32}\b/g },
  // Shopify Admin API access token: shpat_/shppa_ prefixes confirmed via
  // Shopify's own current developer docs. Exact body length not stated on
  // that page (a since-404'd Shopify changelog described it, quoted only
  // by secondary sources), hence a generous floor/ceiling bound. Legacy
  // shpca_/shpss_/shpua_ prefixes are real (Shopify community forum) but
  // not on the current primary page, so left out here.
  { id: "shopify_admin_token", label: "Shopify Admin API access token", confidence: "high",
    re: /\bshp(?:at|pa)_[A-Za-z0-9]{32,40}\b/g },
  // HubSpot private app token: HubSpot's own docs show only a masked
  // example (pat-**-***...), corroborated by real (redacted) examples on
  // HubSpot's own community forum showing the pat-<region>-<UUID-shaped
  // body> structure. Medium confidence: the shape is real but the exact
  // per-segment lengths are inferred, not vendor-pinned.
  { id: "hubspot_token", label: "HubSpot private app access token", confidence: "medium",
    re: /\bpat-[a-z]{2}\d-[a-f0-9-]{30,60}\b/gi },
  // Grafana service account token: exact shape read directly off Grafana's
  // own docs example token (grafana.com/docs/grafana/latest/administration/service-accounts/),
  // not inferred -- two independently-random underscore-delimited segments
  // behind a distinctive 5-char prefix.
  { id: "grafana_service_account_token", label: "Grafana service account token", confidence: "high",
    re: /\bglsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8}\b/g },
  // New Relic: NRAK- prefix confirmed via New Relic's own migration-notice
  // doc ("If your API key starts with NRAK, no update is required").
  // Exact body length/charset not published; generously bounded.
  { id: "new_relic_api_key", label: "New Relic API key", confidence: "high",
    re: /\bNRAK-[A-Z0-9]{27,64}\b/g },
  // Mailchimp: 32 lowercase hex + a literal -us<datacenter digits> suffix,
  // read directly off a live example in Mailchimp's own docs. The suffix
  // is what makes this safe as a default rule -- a bare 32-hex string
  // alone would be indistinguishable from countless unrelated hashes, but
  // the specific "-usN" tail is Mailchimp-specific.
  { id: "mailchimp_key", label: "Mailchimp API key", confidence: "high",
    re: /\b[0-9a-f]{32}-us[0-9]{1,2}\b/g },
  // Akamai EdgeGrid access_token / client_token: akab- prefix and the
  // hyphen-separated two-segment shape confirmed via Akamai's own current
  // docs (literal examples shown), independently corroborated by a
  // detect-secrets maintainer's own reproduction. Neither source states
  // hard segment-length bounds, so the ranges here are a reasonable
  // envelope, not vendor-pinned. Akamai's client_secret was investigated
  // and NOT added: no distinctive prefix in Akamai's own examples, the
  // same bare/opaque shape already excluded elsewhere in this file.
  { id: "akamai_edgegrid_token", label: "Akamai EdgeGrid token", confidence: "high",
    re: /\bakab-[a-z0-9]{16,32}-[a-z0-9]{6,32}\b/g },
  // Doppler: seven distinct token kinds, all sharing the same dp.<tag>.
  // structure. Confirmed via Doppler's own docs
  // (docs.doppler.com/reference/auth-token-formats), which state plainly
  // that "each token type uses a distinct prefix to enable identification
  // during secret scanning operations" -- a format designed to be
  // regex-detected, not inferred. Service tokens (dp.st.) alone carry an
  // optional environment segment between the tag and the body; every other
  // kind goes straight from the tag to the 40-44-char body.
  { id: "doppler_token", label: "Doppler token", confidence: "high",
    re: /\bdp\.(?:ct|pt|sa|said|scim|audit)\.[A-Za-z0-9]{40,44}\b|\bdp\.st\.(?:[a-z0-9_-]{2,35}\.)?[A-Za-z0-9]{40,44}\b/g },
  // Postman API key. Postman's own docs describe how to generate one but
  // not its literal format; sourced instead from gitleaks' own
  // production-tested rule (config/gitleaks.toml, id "postman-api-token"),
  // same tier as azure_ad_client_secret's sourcing earlier in this file.
  { id: "postman_token", label: "Postman API key", confidence: "high",
    re: /\bPMAK-[a-f0-9]{24}-[a-f0-9]{34}\b/gi },
  // Figma personal access token. Figma's own docs don't publish the
  // format either; sourced from trufflehog's own shipped detectors, which
  // track two real, distinct generations: figd_ (the long-established
  // form, trufflehog's v2 detector) and figp_ (a newer form, trufflehog's
  // v3 detector, no keyword-proximity needed unlike v1's bare UUID shape,
  // which is NOT included here for the same reason Bitbucket's keyword-
  // dependent Client ID/Secret rules were declined -- no distinctive
  // standalone prefix).
  { id: "figma_token", label: "Figma personal access token", confidence: "high",
    re: /\bfig[dp]_[A-Za-z0-9_=-]{40,54}\b/g },
  // Bitbucket App Password (distinct from Bitbucket's Client ID/Secret,
  // declined elsewhere in this file's history for being keyword-dependent
  // with no standalone prefix). Confirmed via an Atlassian staff reply on
  // Atlassian's own community forum naming ATBB as the current App
  // Password prefix -- the same source already used for atlassian_api_token.
  { id: "bitbucket_app_password", label: "Bitbucket App Password", confidence: "high",
    re: /\bATBB[a-zA-Z0-9]{32}\b/g },
  // SonarQube/SonarCloud token. gitleaks' own rule needs "sonar" keyword
  // proximity because its body class also has to catch a bare unprefixed
  // 40-char fallback -- unsafe as a standalone rule, so only the three
  // confirmed literal prefixes are used here, which need no such context.
  // squ_/sqp_/sqa_ confirmed real and current via SonarSource's own docs
  // (docs.sonarsource.com), whose own worked example (sqp_ followed by
  // 1aa323...8a1d13) is added to VENDOR_EXAMPLE_VALUES in scan.js as a
  // documented example, not a findable secret.
  { id: "sonarqube_token", label: "SonarQube/SonarCloud token", confidence: "high",
    re: /\b(?:squ|sqp|sqa)_[a-z0-9=_-]{40}\b/g },
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
