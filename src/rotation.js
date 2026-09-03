"use strict";

const crypto = require("crypto");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { PATTERNS, NOISY_PATTERNS, redact } = require("./patterns");

/**
 * The rotation exit-path: turn every finding into a next step.
 *
 * Detection without rotation is theater, in the field's own numbers: 64% of
 * secrets leaked in 2022 were still valid years later, 88% of re-verified
 * leaked AWS keys still authenticated, and the median remediation time for
 * GitHub-leaked secrets is 94 days (residoo-research/NIGHT-RESEARCH-2026-09-02.md,
 * P3). This module maps every detection rule to the vendor's real rotation
 * path, and keeps a local pending/acknowledged ledger so "found it" can
 * become "closed it".
 *
 * URL DISCIPLINE (the bar every entry below was held to): a `rotateUrl` is
 * present ONLY if that exact URL was fetched during development (2026-09-02)
 * and confirmed to document rotation/revocation of that credential type; the
 * per-entry comment says what was checked. Where the vendor's management
 * surface is login-walled, bot-walled, or client-rendered (unverifiable end
 * to end), the entry ships a `consolePath` in words instead, with the
 * corroboration noted. A dead link in a security tool's remediation advice
 * is a credibility wound; an honest console path is not.
 *
 * STATE FILE WRITE DISCIPLINE (~/.residoo/rotations.json):
 *   - This is the ONLY file residoo ever writes outside an explicit --seal.
 *     It is residoo's own state file, in residoo's own directory; the
 *     CONTRIBUTING.md rule that nothing modifies an existing file is about
 *     the user's files, and this carve-out is stated here in the open rather
 *     than slipped past it.
 *   - It never contains a raw secret. Keys are fingerprints (hashes of
 *     already-redacted material, see fingerprintFinding); user-supplied ack
 *     notes are run through PATTERNS plus NOISY_PATTERNS with redact, the
 *     same pipeline previews get, so even a note with a pasted secret in it
 *     is stored redacted. The noisy rules are included here even though
 *     scans only run them behind --include-noisy: a user acking a noisy
 *     finding is exactly the user likely to paste that value into a note.
 *   - Writes are atomic: full content to a temp file in the same directory,
 *     then rename over the target. A crash mid-write leaves the old state
 *     intact, never a half-written JSON.
 *   - A corrupt or unreadable state file degrades to "no acks" with a note
 *     on stderr, never a crash and never a silent pretend-empty. The next
 *     successful ack starts a fresh store; the stderr note is the user's
 *     cue that prior acks were lost to corruption.
 *
 * Everything else here is pure data in, pure data out: renderRotation()
 * returns a structure for the report layer to print, it prints nothing
 * itself.
 */

// ── ordering advisory ───────────────────────────────────────────────────────

/**
 * For the report layer to show whenever one scan carries BOTH integrity
 * warnings and secret findings. Evidence: the ChainDrop/keyv campaign
 * (Aug 2026, 400+ npm packages) included a token monitor that fires an
 * attacker payload at the moment the stolen GitHub token is revoked, which
 * makes remediation ORDER safety-critical. Source: residoo-research/
 * NIGHT-RESEARCH-2026-09-02.md section 2, and its sources-digest.json entry
 * "The ChainDrop npm attack" (eon.io/blog/chaindrop-npm-supply-chain-attack,
 * StepSecurity finding). Naive "rotate everything now" advice can itself
 * trigger the damage.
 */
const ROTATION_ORDER_ADVISORY =
  "This scan found both integrity warnings and leaked credentials. Remove the " +
  "planted persistence BEFORE rotating anything: the ChainDrop campaign " +
  "(Aug 2026) shipped a token monitor that fires an attacker payload the " +
  "moment the stolen GitHub token is revoked. Review and remove the flagged " +
  "hooks, tasks, and scripts first; rotate credentials second, starting with " +
  "any GitHub token.";

// ── rotation guidance map ───────────────────────────────────────────────────

/**
 * One entry per rule id in src/patterns.js (all 36 of PATTERNS, plus the two
 * NOISY_PATTERNS ids so an --include-noisy run still renders guidance).
 * Shape: { label, rotateUrl?, consolePath?, steps: [1..3 strings],
 * revokeNote, generic? }. `generic: true` marks entries that cannot name a
 * vendor because the pattern itself cannot (a JWT, a bearer header); their
 * guidance says so honestly instead of pretending precision.
 */
const ROTATION_GUIDANCE = {
  // Fetched https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html
  // (2026-09-02): "Manage access keys for IAM users", links "Update access
  // keys" for the deactivate-then-delete flow.
  aws_access_key_id: {
    label: "AWS IAM access key",
    rotateUrl: "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html",
    steps: [
      "Console: IAM > Users > your user > Security credentials > Access keys",
      "Create a replacement key and switch your tooling to it",
      "Deactivate the leaked key, verify nothing broke, then delete it",
    ],
    revokeNote: "Deactivate before delete: a deactivated key can be re-enabled while you hunt down stragglers, a deleted one cannot.",
  },
  // The secret half of the same pair (see pairing.js): reported only when
  // found near a matched aws_access_key_id, so the same key is the one that
  // needs deactivating. Same console flow, called out separately because the
  // finding itself is a distinct rule id and deserves its own runbook rather
  // than silently reusing aws_access_key_id's guidance under a different name.
  aws_secret_access_key_paired: {
    label: "AWS IAM secret access key (paired with a leaked access key id)",
    rotateUrl: "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html",
    steps: [
      "This is the secret half of the access key id also found on this line",
      "Console: IAM > Users > your user > Security credentials > Access keys",
      "Deactivate and delete the paired access key; its secret dies with it",
    ],
    revokeNote: "An AWS secret key cannot be revoked on its own: deactivating its paired access key id is what invalidates it.",
  },
  // Fetched https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_revoke-sessions.html
  // (2026-09-02): "Revoke IAM role temporary security credentials", console
  // path IAM > Roles > role > Revoke sessions tab.
  aws_session_token: {
    label: "AWS temporary credentials (STS session)",
    rotateUrl: "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_revoke-sessions.html",
    steps: [
      "Temporary credentials expire on their own, but do not wait if leaked",
      "Console: IAM > Roles > the role > Revoke sessions > Revoke active sessions",
      "Then rotate whatever long-term credential minted the session",
    ],
    revokeNote: "Revoking sessions denies every session issued for that role before now; legitimate users re-authenticate and continue.",
  },
  // No vendor: a PEM block does not say what trusts it. Guidance names the
  // three common cases instead of guessing one.
  private_key_block: {
    label: "Private key (PEM block)",
    generic: true,
    consolePath: "Depends on the key type: read the PEM header and the surrounding context to identify it",
    steps: [
      "SSH key: generate a new pair, replace the public key everywhere it is authorized (GitHub, GitLab, servers), remove the old one",
      "TLS key: reissue the certificate and revoke the old one at your CA",
      "Cloud service-account key: delete the key in that provider's IAM console and mint a new one",
    ],
    revokeNote: "A private key cannot be rotated in place; every system trusting its public half needs the update.",
  },
  // Fetched https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens
  // (2026-09-02): documents creating and deleting PATs, Settings > Developer
  // settings > Personal access tokens.
  github_pat: {
    label: "GitHub personal access token",
    rotateUrl: "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens",
    steps: [
      "github.com > Settings > Developer settings > Personal access tokens",
      "Delete the leaked token; create a fine-grained replacement with the narrowest scopes",
      "Review the account's security log for activity you do not recognize",
    ],
    revokeNote: "If this scan also raised integrity warnings, clean those FIRST: ChainDrop's monitor fires when the stolen token is revoked.",
  },
  // Fetched https://docs.gitlab.com/user/profile/personal_access_tokens/
  // (2026-09-02): sections "Rotate a personal access token" and "Revoke a
  // personal access token", path avatar > Edit profile > Access.
  gitlab_pat: {
    label: "GitLab personal access token",
    rotateUrl: "https://docs.gitlab.com/user/profile/personal_access_tokens/",
    steps: [
      "GitLab > avatar > Edit profile > Access > Personal access tokens",
      "Use the token row's menu to Rotate (or Revoke) it",
      "Update everything that used the old value",
    ],
    revokeNote: "Rotate revokes the old token and issues its replacement in one step.",
  },
  // Fetched https://docs.slack.dev/reference/methods/auth.revoke (2026-09-02):
  // "This method revokes an access token." (api.slack.com/methods/auth.revoke
  // now 302s here.) App-level management lives at api.slack.com/apps.
  slack_token: {
    label: "Slack token",
    rotateUrl: "https://docs.slack.dev/reference/methods/auth.revoke",
    steps: [
      "Revoke the token via the auth.revoke API method, or from your app's settings at api.slack.com/apps",
      "Reinstall the app to mint fresh tokens",
      "Review the workspace access logs for use you do not recognize",
    ],
    revokeNote: "Revoking a bot token deactivates that bot user and drops its channel memberships; the app itself stays installed.",
  },
  // Fetched https://docs.stripe.com/keys (2026-09-02): "Rotate an API key"
  // section, Dashboard API keys page, overflow menu > Rotate key.
  stripe_key: {
    label: "Stripe API key",
    rotateUrl: "https://docs.stripe.com/keys",
    steps: [
      "Dashboard > Developers > API keys",
      "Overflow menu on the key > Rotate key; choose expiration Now for a compromised key",
      "Update your servers with the replacement value",
    ],
    revokeNote: "Rotating with expiration Now kills the old key immediately; a scheduled rotation keeps both valid for up to 7 days for zero-downtime migration.",
  },
  // Same URL as stripe_key, and the same fetch check covers it (2026-09-02):
  // docs.stripe.com/keys documents the Rotate key flow for both modes, the
  // API keys page's sandbox/live toggle, and that sandbox mode exposes all
  // of the account's keys to anyone who can open it.
  stripe_test_key: {
    label: "Stripe API key (test mode)",
    rotateUrl: "https://docs.stripe.com/keys",
    steps: [
      "Dashboard > Developers > API keys, toggled to sandbox (test) mode",
      "Overflow menu on the key > Rotate key; choose expiration Now for a compromised key",
      "Check how the key leaked: test and live keys usually travel the same channel, so verify no live key was exposed alongside it",
    ],
    revokeNote: "Test mode is not harmless: the key grants full API access to the sandbox account, and its leak marks a workflow that will handle live keys the same way.",
  },
  // help.openai.com articles 5112595 and 8304786 exist (surfaced by search)
  // but the help center serves HTTP 403 to this project's fetcher, so no URL
  // is shipped: unverifiable end to end fails the bar above.
  openai_key: {
    label: "OpenAI API key",
    consolePath: "OpenAI Platform (platform.openai.com) > API keys",
    steps: [
      "Sign in to the OpenAI Platform and open the API keys page",
      "Delete the leaked key and create a replacement",
      "Check usage for activity you do not recognize",
    ],
    revokeNote: "OpenAI disables keys it finds published on the public internet on its own; treat that as a backstop, not the fix.",
  },
  // Fetched https://support.claude.com/en/articles/9767949-api-key-best-practices-keeping-your-keys-safe-and-secure
  // (2026-09-02): official article, quotes the Console path (API keys page,
  // three-dots menu, Delete API Key) and the rotate-by-replace advice.
  anthropic_key: {
    label: "Anthropic API key",
    rotateUrl: "https://support.claude.com/en/articles/9767949-api-key-best-practices-keeping-your-keys-safe-and-secure",
    steps: [
      "Claude Console (console.anthropic.com) > API keys",
      "Three-dots menu next to the key > Delete API Key",
      "Create a replacement and update your configs",
    ],
    revokeNote: "Deletion is immediate; anything still sending the old key starts failing authentication at once.",
  },
  // Fetched https://docs.cloud.google.com/docs/authentication/api-keys
  // (2026-09-02; cloud.google.com/docs/authentication/api-keys 301s here):
  // documents rotate-by-replace and delete, Credentials console page.
  google_api_key: {
    label: "Google / Firebase API key",
    rotateUrl: "https://docs.cloud.google.com/docs/authentication/api-keys",
    steps: [
      "Console: APIs & Services > Credentials (console.cloud.google.com/apis/credentials)",
      "Create a replacement key with the same restrictions and move apps to it",
      "Delete the leaked key (restorable for 30 days if that turns out wrong)",
    ],
    revokeNote: "A Firebase web API key is a Google Cloud API key; even if it must stay public by design, apply application restrictions to it.",
  },
  // Fetched https://docs.npmjs.com/revoking-access-tokens (2026-09-02):
  // "Revoking tokens on the website" (profile > Access Tokens) and the
  // token CLI flow.
  npm_token: {
    label: "npm access token",
    rotateUrl: "https://docs.npmjs.com/revoking-access-tokens",
    steps: [
      "npmjs.com > profile > Access Tokens > delete the leaked token",
      "Or CLI: npm token list, then npm token revoke <id>",
      "Mint a granular replacement with a short expiry",
    ],
    revokeNote: "Check your packages' recent publishes afterward: a leaked npm token is a supply-chain foothold, not just an account problem.",
  },
  // Fetched https://www.twilio.com/docs/sendgrid/ui/account-and-settings/api-keys
  // (2026-09-02): Settings > API Keys, action menu > Delete API Key,
  // delete-then-recreate as the regeneration flow.
  sendgrid_key: {
    label: "SendGrid API key",
    rotateUrl: "https://www.twilio.com/docs/sendgrid/ui/account-and-settings/api-keys",
    steps: [
      "SendGrid dashboard > Settings > API Keys",
      "Action menu on the key > Delete API Key",
      "Create a minimal-scope replacement and update your senders",
    ],
    revokeNote: "Deletion is immediate; sends using the old key fail from the moment you confirm.",
  },
  // Fetched https://www.twilio.com/docs/iam/api-keys/keys-in-console
  // (2026-09-02): create/delete flows, path Settings > Account settings >
  // API keys & auth tokens.
  twilio_key: {
    label: "Twilio API key",
    rotateUrl: "https://www.twilio.com/docs/iam/api-keys/keys-in-console",
    steps: [
      "Console: Settings > Account settings > API keys & auth tokens",
      "Delete the leaked key",
      "Create a replacement (Standard or Restricted) and update your apps",
    ],
    revokeNote: "If the account's Auth Token leaked alongside the key, it has its own rotation flow on the same console page.",
  },
  // No vendor: the pattern matches a shape, not an issuer.
  jwt: {
    label: "JWT (issuer unknown)",
    generic: true,
    consolePath: "Identify the issuing service first; a JWT names its issuer in the payload",
    steps: [
      "Base64-decode the token's middle segment and read the iss and aud claims (it already leaked; decoding it locally adds no exposure)",
      "Revoke the session, grant, or signing key at that issuer",
      "If a refresh token leaked alongside it, treat that as the primary leak",
    ],
    revokeNote: "A JWT usually cannot be revoked by itself; the issuer invalidates whatever produced it, and short expiry is not revocation.",
  },
  // No single vendor: the URL scheme names the engine, the host names the
  // operator.
  connection_string_with_password: {
    label: "Database connection string",
    generic: true,
    consolePath: "The URL scheme names the engine (postgres, mysql, mongodb); rotate at that database",
    steps: [
      "Change that database user's password, or drop and recreate the user",
      "Update every consumer of the connection string",
      "Review the database's auth logs for connections you do not recognize",
    ],
    revokeNote: "If the host is a managed service (RDS, Atlas, Supabase, and the like), its console has a reset-credentials flow; use that.",
  },
  // No vendor: residoo saw the header shape, not who accepts it.
  bearer_header: {
    label: "Bearer token (service unknown)",
    generic: true,
    consolePath: "Identify the service from the code or transcript around the match; the request URL usually names it",
    steps: [
      "Find the request the header was attached to; its host is the issuer",
      "Rotate or revoke at that service's credential settings",
      "If it is an OAuth access token, revoke the grant, not just the token",
    ],
    revokeNote: "Generic by design: an Authorization header match cannot name its vendor, so this guidance cannot either.",
  },
  // No vendor: a "refresh_token" JSON field could come from any OAuth
  // provider.
  refresh_token_field: {
    label: "OAuth refresh token",
    generic: true,
    consolePath: "Revoke the OAuth grant at the provider that issued it (its connected-apps or authorized-applications page)",
    steps: [
      "Identify the provider from the surrounding transcript or config",
      "Revoke the application grant; that invalidates refresh and access tokens together",
      "Re-authorize the app to mint fresh tokens",
    ],
    revokeNote: "A refresh token outlives every access token it mints; rotating only access tokens leaves the leak alive.",
  },
  access_token_field: {
    label: "OAuth access token",
    generic: true,
    consolePath: "Revoke at the issuing provider; the token's surroundings usually name it",
    steps: [
      "Identify the provider from the surrounding transcript or config",
      "Revoke the token or its parent grant at that provider",
      "If a refresh_token leaked alongside, treat that as the primary leak",
    ],
    revokeNote: "Access tokens expire, but expiry is not revocation; do not wait it out.",
  },

  // ── AI / LLM providers ────────────────────────────────────────────────
  // Fetched https://console.groq.com/docs/production-readiness/security-onboarding
  // (2026-09-02): "Revoke the key immediately from the Groq Console", keys
  // page console.groq.com/keys. (console.groq.com/docs/api-keys is a 404.)
  groq_key: {
    label: "Groq API key",
    rotateUrl: "https://console.groq.com/docs/production-readiness/security-onboarding",
    steps: [
      "console.groq.com/keys (API Keys page)",
      "Revoke the leaked key and create a replacement",
      "Redeploy the new secret everywhere the old one lived",
    ],
    revokeNote: "Key values are unrecoverable after creation, so the replacement must be re-copied everywhere; nothing can read the old one back.",
  },
  // Fetched https://docs.x.ai/console/faq/security (2026-09-02): compromise
  // flow is console API Keys > three-dots > Disable key / Delete key.
  xai_key: {
    label: "xAI (Grok) API key",
    rotateUrl: "https://docs.x.ai/console/faq/security",
    steps: [
      "xAI Console (console.x.ai) > API Keys",
      "Three-dots menu on the key > Disable key, then Delete key once confirmed",
      "Create a replacement and update your configs",
    ],
    revokeNote: "Disable takes effect immediately and is reversible; delete once you are sure nothing legitimate still uses the key.",
  },
  // Fetched https://openrouter.ai/docs/api-keys (2026-09-02): compromised-key
  // advice is "immediately visit your key settings page to delete the
  // compromised key and create a new one" (openrouter.ai/settings/keys).
  openrouter_key: {
    label: "OpenRouter API key",
    rotateUrl: "https://openrouter.ai/docs/api-keys",
    steps: [
      "openrouter.ai/settings/keys",
      "Delete the compromised key and create a replacement",
      "Check credit usage for spend you do not recognize",
    ],
    revokeNote: "OpenRouter emails you when it detects an exposed key; that detection is a backstop, not the remediation.",
  },
  // Fetched https://huggingface.co/docs/hub/security-tokens (2026-09-02):
  // manage/delete/refresh at settings/tokens; documents the anonymous
  // POST /api/credentials/revoke endpoint for someone else's leaked token.
  huggingface_token: {
    label: "Hugging Face access token",
    rotateUrl: "https://huggingface.co/docs/hub/security-tokens",
    steps: [
      "huggingface.co/settings/tokens",
      "Manage > invalidate and refresh (or delete) the leaked token",
      "Found someone else's token? The docs' POST /api/credentials/revoke endpoint kills it without needing their account",
    ],
    revokeNote: "Refresh invalidates the old value immediately; prefer a fine-grained replacement so the next leak is scoped.",
  },
  // Fetched https://docs.pinecone.io/guides/projects/manage-api-keys
  // (2026-09-02): console > project > API keys tab > ellipsis > Delete,
  // confirm by typing the key name.
  pinecone_key: {
    label: "Pinecone API key",
    rotateUrl: "https://docs.pinecone.io/guides/projects/manage-api-keys",
    steps: [
      "Pinecone console > your project > API keys tab",
      "Actions column > ellipsis menu > Delete (typing the key name confirms)",
      "Create a replacement and update clients",
    ],
    revokeNote: "Deletion is irreversible and cuts off applications using the key the moment you confirm.",
  },
  // The help-center article ("API settings", article 10352995) exists but
  // perplexity.ai serves HTTP 403 to this fetcher, so no URL is shipped. The
  // settings/api path is the one every integration guide agrees on, the same
  // multi-source bar patterns.js already argues for this vendor.
  perplexity_key: {
    label: "Perplexity API key",
    consolePath: "perplexity.ai > Settings > API (perplexity.ai/settings/api) > API Keys",
    steps: [
      "Open the API settings page and delete the leaked key",
      "Generate a replacement (shown once, store it safely)",
      "Update every client with the new value",
    ],
    revokeNote: "Key values are shown once at creation; there is nothing to re-copy later, only replace.",
  },
  // Fetched https://replicate.com/docs/topics/security/api-tokens
  // (2026-09-02): "you can disable it from the web interface", management at
  // replicate.com/account/api-tokens.
  replicate_token: {
    label: "Replicate API token",
    rotateUrl: "https://replicate.com/docs/topics/security/api-tokens",
    steps: [
      "replicate.com/account/api-tokens",
      "Disable the exposed token",
      "Create a replacement and update your applications",
    ],
    revokeNote: "Disabling stops all API requests with that token immediately.",
  },
  // Fetched https://elevenlabs.io/docs/api-reference/authentication
  // (2026-09-03): keys are managed and deleted from the Profile + API keys
  // page in the ElevenLabs dashboard.
  elevenlabs_key: {
    label: "ElevenLabs API key",
    consolePath: "elevenlabs.io > Profile + API keys",
    steps: [
      "Open Profile + API keys in the ElevenLabs dashboard",
      "Delete the leaked key",
      "Create a replacement and update the applications using it",
    ],
    revokeNote: "A key grants full account access (voices, generations, billing); deletion is immediate.",
  },

  // ── Cloud / infra ─────────────────────────────────────────────────────
  // docs.digitalocean.com/reference/api/create-personal-access-token/
  // resolves but its body is client-rendered and unreadable to this fetcher,
  // so no URL is shipped. The control-panel location is DigitalOcean's own:
  // their blog "Updated API Management Tokens" names
  // cloud.digitalocean.com/account/api/tokens as where tokens are deleted.
  digitalocean_token: {
    label: "DigitalOcean access token",
    consolePath: "cloud.digitalocean.com > API > Tokens (cloud.digitalocean.com/account/api/tokens)",
    steps: [
      "Open the control panel's API > Tokens page",
      "Delete the leaked personal access token",
      "Generate a replacement with the narrowest scopes and a short expiry",
    ],
    revokeNote: "DigitalOcean auto-revokes tokens it detects published publicly; treat that as a backstop, not the fix.",
  },
  // supabase.com/docs/guides/platform/access-control (fetched 2026-09-02)
  // points at supabase.com/dashboard/account/tokens as the PAT location; the
  // dashboard itself is login-walled, so the path ships in words.
  supabase_token: {
    label: "Supabase personal access token",
    consolePath: "supabase.com/dashboard > Account > Access Tokens (supabase.com/dashboard/account/tokens)",
    steps: [
      "Open the account Access Tokens page",
      "Delete the leaked token and generate a replacement for your tooling",
      "Review recent project changes made via the API",
    ],
    revokeNote: "This is the account-level token (sbp_); a project's anon and service_role keys rotate separately in that project's API settings.",
  },
  // Fetched https://developer.hashicorp.com/vault/docs/commands/token/revoke
  // (2026-09-02): "token revoke revokes authentication tokens and their
  // children", -accessor and -mode flags.
  vault_token: {
    label: "HashiCorp Vault service token",
    rotateUrl: "https://developer.hashicorp.com/vault/docs/commands/token/revoke",
    steps: [
      "vault token revoke <token>, or -accessor <accessor> if you only have that",
      "Revocation cascades to the token's children by default",
      "Audit what the token touched via Vault's audit log",
    ],
    revokeNote: "If the token was long-lived or highly privileged, rotate the secrets it could READ as well, not just the token.",
  },
  // Fetched https://www.1password.dev/service-accounts/manage-service-accounts/
  // (2026-09-02; developer.1password.com 301s here): Rotate Token and Revoke
  // Token flows, path Developer > Service accounts.
  onepassword_service_token: {
    label: "1Password service account token",
    rotateUrl: "https://www.1password.dev/service-accounts/manage-service-accounts/",
    steps: [
      "1Password.com > Developer > Service accounts > the account",
      "Rotate Token (expire the old one immediately) or Revoke Token",
      "Update the workloads that used it",
    ],
    revokeNote: "Revoking immediately removes the token's access to every vault the service account could reach.",
  },
  // Fetched https://circleci.com/docs/managing-api-tokens/ (2026-09-03):
  // Personal API Tokens tab under User Settings, revoke deletes it
  // immediately.
  circleci_token: {
    label: "CircleCI personal API token",
    consolePath: "circleci.com > User Settings > Personal API Tokens",
    steps: [
      "Open Personal API Tokens under your CircleCI user settings",
      "Revoke the leaked token",
      "Create a replacement and update whatever used the old one",
    ],
    revokeNote: "Revocation is immediate; the token stops authenticating on the next request.",
  },
  // Fetched https://airtable.com/developers/web/guides/personal-access-tokens
  // (2026-09-03): tokens are managed and deleted from the Personal access
  // tokens page in the Airtable developer hub (airtable.com/create/tokens).
  airtable_token: {
    label: "Airtable personal access token",
    consolePath: "airtable.com/create/tokens",
    steps: [
      "Open the Personal access tokens page in the developer hub",
      "Delete the leaked token",
      "Create a replacement scoped only to what your integration needs",
    ],
    revokeNote: "Deletion is immediate and applies to every base the token could reach.",
  },
  // Fetched https://developers.cloudflare.com/fundamentals/api/get-started/create-token/
  // (2026-09-03): tokens are managed and revoked from My Profile > API
  // Tokens.
  cloudflare_api_token: {
    label: "Cloudflare API token",
    consolePath: "dash.cloudflare.com > My Profile > API Tokens",
    steps: [
      "Open My Profile > API Tokens in the Cloudflare dashboard",
      "Roll (regenerate) or delete the leaked token",
      "Update whatever used the old token with the replacement",
    ],
    revokeNote: "Deleting is immediate; a scoped token only affects the zones/permissions it was granted.",
  },
  // Fetched https://help.heroku.com/PBGP6IDE (2026-09-03): API keys are
  // regenerated from Account Settings, which invalidates the previous key.
  heroku_api_key: {
    label: "Heroku API key",
    consolePath: "dashboard.heroku.com/account > API Key",
    steps: [
      "Open Account Settings in the Heroku dashboard",
      "Regenerate the API key (this immediately invalidates the old one)",
      "Update the CLI/CI configs and tools that used the old key",
    ],
    revokeNote: "Regeneration is the only way to invalidate a Heroku API key; there is no separate revoke action.",
  },
  // Fetched https://docs.netlify.com/api/get-started/#authentication
  // (2026-09-03): personal access tokens are managed from User settings >
  // Applications > Personal access tokens.
  netlify_token: {
    label: "Netlify personal access token",
    consolePath: "app.netlify.com/user/applications#personal-access-tokens",
    steps: [
      "Open User settings > Applications > Personal access tokens",
      "Delete the leaked token",
      "Create a replacement and update whatever used the old one",
    ],
    revokeNote: "Deletion is immediate; the token stops authenticating on the next request.",
  },

  // ── Comms / SaaS ──────────────────────────────────────────────────────
  // The user-facing support article (support.discord.com article 228383668)
  // serves HTTP 403 to this fetcher. The developer docs below WERE fetched
  // (2026-09-02; discord.com/developers/docs/resources/webhook 301s to
  // docs.discord.com) and document the Delete Webhook endpoint.
  discord_webhook: {
    label: "Discord webhook URL",
    rotateUrl: "https://docs.discord.com/developers/resources/webhook",
    steps: [
      "Server Settings (or the channel's settings) > Integrations > Webhooks",
      "Delete the leaked webhook; creating a new one issues a new URL",
      "Programmatic alternative: the Delete Webhook API endpoint (requires MANAGE_WEBHOOKS)",
    ],
    revokeNote: "The URL is the entire credential: anyone holding it can post to the channel until the webhook is deleted.",
  },
  // Fetched https://core.telegram.org/bots/features (2026-09-02): "If your
  // existing token is compromised or you lost it for some reason, use the
  // /token command to generate a new one."
  telegram_bot_token: {
    label: "Telegram bot token",
    rotateUrl: "https://core.telegram.org/bots/features",
    steps: [
      "Message @BotFather in Telegram",
      "Send /token and select the bot to issue a replacement; treat the old value as dead",
      "Update your bot's config with the new token",
    ],
    revokeNote: "BotFather is the only management surface for bot tokens; there is no web console.",
  },
  // help.mailgun.com serves HTTP 403 to this fetcher, so no URL is shipped.
  // The path is corroborated by Mailgun's own blog ("Swap Out Your API Keys
  // With No Downtime") and two help-center articles surfaced in search:
  // profile menu > API Security is where keys are regenerated.
  mailgun_key: {
    label: "Mailgun API key",
    consolePath: "app.mailgun.com > profile menu (top right) > API Security",
    steps: [
      "Open API Security in the Mailgun control panel",
      "Delete or regenerate the compromised key; create a scoped replacement",
      "Update senders and check sending logs for abuse",
    ],
    revokeNote: "A Mailgun key can send mail as your domains; check outbound activity, not just the key itself.",
  },
  // Fetched https://developers.notion.com/guides/get-started/internal-connections
  // (2026-09-02): "If your token is accidentally exposed, you can refresh it
  // from the connection's Configuration tab."
  notion_token: {
    label: "Notion integration token",
    rotateUrl: "https://developers.notion.com/guides/get-started/internal-connections",
    steps: [
      "notion.so/my-integrations > select the integration",
      "Configuration tab > refresh the secret (the old value dies immediately)",
      "Update everything that used the old secret",
    ],
    revokeNote: "Notion has changed its token format before; whatever the prefix, the refresh flow is the same.",
  },
  // Fetched https://linear.app/docs/api-and-webhooks (2026-09-02): personal
  // API keys are created under Settings > Account > Security & Access, and
  // existing keys can be viewed and revoked.
  linear_key: {
    label: "Linear API key",
    rotateUrl: "https://linear.app/docs/api-and-webhooks",
    steps: [
      "Linear > Settings > Account > Security & Access",
      "Revoke the leaked personal API key",
      "Create a replacement restricted to the permissions and teams it needs",
    ],
    revokeNote: "A personal key inherits its creator's workspace access; a workspace admin can also revoke members' keys.",
  },
  // Fetched https://docs.sentry.io/account/auth-tokens/ (2026-09-02):
  // organization tokens under Settings > Developer Settings > Organization
  // Tokens, personal tokens under the account dropdown; both revocable.
  sentry_token: {
    label: "Sentry auth token",
    rotateUrl: "https://docs.sentry.io/account/auth-tokens/",
    steps: [
      "Organization token (sntrys_): Settings > Developer Settings > Organization Tokens",
      "Personal token (sntryu_): Account dropdown > Personal Tokens",
      "Revoke the leaked token and create a replacement",
    ],
    revokeNote: "The redacted preview cannot distinguish the two prefixes; check the original file for sntrys_ (organization) vs sntryu_ (personal).",
  },

  // ── NOISY_PATTERNS (only reachable via --include-noisy) ───────────────
  generic_password_assignment: {
    label: "Password assignment (noisy rule)",
    generic: true,
    consolePath: "Rotate wherever that password authenticates",
    steps: [
      "Confirm it is a real credential and not a placeholder (this rule false-positives by design)",
      "Change the password at the system it belongs to",
      "Move it to a secrets manager so it stops living in config text",
    ],
    revokeNote: "Low-confidence match: verify before rotating anything.",
  },
  generic_secret_assignment: {
    label: "Secret / API key assignment (noisy rule)",
    generic: true,
    consolePath: "Rotate at whatever service issued the value",
    steps: [
      "Confirm it is a real credential and not a placeholder (this rule false-positives by design)",
      "Identify the issuing service from the variable name and surrounding code",
      "Rotate or revoke there and move the value to a secrets manager",
    ],
    revokeNote: "Low-confidence match: verify before rotating anything.",
  },
};
Object.freeze(ROTATION_GUIDANCE);

/**
 * Guidance for a rule id, with an honest fallback for ids this map does not
 * know (a future pattern added without a guidance entry). The fallback SAYS
 * it is a gap; silently generic guidance under a vendor rule's name would be
 * the false-all-clear failure mode in remediation clothing.
 */
function guidanceFor(ruleId) {
  const g = ROTATION_GUIDANCE[ruleId];
  if (g) return g;
  return {
    label: String(ruleId || "unknown rule"),
    generic: true,
    consolePath: "No rotation guidance is shipped for this rule id yet",
    steps: [
      "Identify the issuing service from the finding's file and context",
      "Rotate or revoke the credential there",
    ],
    revokeNote: "This is a guidance gap in residoo, not a judgment that rotation is unneeded. Please open an issue naming the rule id.",
  };
}

// ── fingerprints ────────────────────────────────────────────────────────────

// Mirrors stripControlChars in patterns.js (not exported there; integrity.js
// makes the same copy for the same reason: adding an export would touch a
// shared file).
function stripControlChars(s) { return s.replace(/[\x00-\x1f\x7f]/g, ""); }

/**
 * Stable identity for a finding, derived ONLY from already-redacted
 * material: ruleId + the redacted preview + the source file's basename.
 * Deliberately NOT derived from the raw secret (which never leaves scan())
 * and NOT from the line number (a transcript that gets appended to shifts
 * every line, and an ack must survive that). Tradeoffs, stated: two distinct
 * secrets of the same rule, length, first four and last four characters in
 * the same file collapse into one fingerprint (undercounts pending rotations
 * by merging near-twins); and because the basename is in the identity, ONE
 * secret present in two differently-named files is two fingerprints, so the
 * Rotation section can count more pending rotations than scan's raw-value
 * distinctCounts says there are distinct values. Both are the price of the
 * alternative being worse: hashing raw secrets into a state file would put
 * secret-derived material on disk, which rule 4 exists to prevent.
 */
function fingerprintFinding(finding) {
  if (!finding || typeof finding !== "object") {
    throw new TypeError("fingerprintFinding expects a finding object");
  }
  // relFile is scan.js's basename convention; fall back to computing it so a
  // caller holding only {ruleId, preview, file} still gets the same identity.
  const base = finding.relFile != null
    ? String(finding.relFile)
    : path.basename(String(finding.file || ""));
  const material = [String(finding.ruleId || ""), String(finding.preview || ""), base].join("\n");
  const h = crypto.createHash("sha256").update(material, "utf-8").digest("hex");
  // 128 bits is plenty for a local dedup key; the rf1- prefix versions the
  // scheme so a future change can coexist with old state files.
  return "rf1-" + h.slice(0, 32);
}

const FINGERPRINT_RE = /^rf1-[0-9a-f]{32}$/;

// ── ack state (~/.residoo/rotations.json) ───────────────────────────────────

function statePath() {
  return path.join(os.homedir(), ".residoo", "rotations.json");
}

/**
 * Parse one map (acks, or dismissed) out of the already-JSON-parsed state
 * file body. Shared by loadFullState() for both keys: same validation, same
 * per-entry degrade-not-discard behavior, so a hand-edited or foreign
 * ledger loses only its malformed entries, never the whole file.
 */
function parseFpMap(raw) {
  const out = {};
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return out;
  for (const [fp, v] of Object.entries(raw)) {
    if (!FINGERPRINT_RE.test(fp)) continue;
    if (!v || typeof v !== "object") continue;
    // Control bytes stripped on READ as well as on write: this file sits on
    // disk between the two, and a hand-edited or foreign ledger must not be
    // able to put a terminal escape into the report via a note.
    out[fp] = {
      at: typeof v.at === "string" ? stripControlChars(v.at) : null,
      note: typeof v.note === "string" ? stripControlChars(v.note) : null,
    };
  }
  return out;
}

/**
 * Load the full rotation state: { acks, dismissed }, both shaped
 * { "<fingerprint>": { at, note } }. Missing file is the normal first-run
 * case and returns both empty silently. A corrupt or unreadable file
 * returns both empty too, but LOUDLY: one note on stderr, because "your
 * acks are gone" must never be silent, and because the next write will
 * start a fresh store over the corrupt one.
 */
function loadFullState({ file = statePath() } = {}) {
  const empty = { acks: {}, dismissed: {} };
  let text;
  try {
    text = fs.readFileSync(file, "utf-8");
  } catch (err) {
    if (err && (err.code === "ENOENT" || err.code === "ENOTDIR")) return empty;
    process.stderr.write(`residoo: rotation state ${path.basename(file)} could not be read; continuing with no acknowledgements or dismissals\n`);
    return empty;
  }
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    process.stderr.write(`residoo: rotation state ${path.basename(file)} is corrupt; continuing with no acknowledgements or dismissals (the next write will start a fresh store)\n`);
    return empty;
  }
  if (!parsed || typeof parsed !== "object" || parsed.v !== 1) {
    process.stderr.write(`residoo: rotation state ${path.basename(file)} has an unrecognized shape; continuing with no acknowledgements or dismissals\n`);
    return empty;
  }
  // dismissed is a later addition to this same file (v stays 1: additive,
  // tolerant of a file written by an older residoo that never had this key).
  return { acks: parseFpMap(parsed.acks), dismissed: parseFpMap(parsed.dismissed) };
}

/** Backward-compatible: the acks half of loadFullState(), same call shape as before dismiss existed. */
function loadAcks({ file = statePath() } = {}) {
  return loadFullState({ file }).acks;
}

/** The dismissed half of loadFullState(). */
function loadDismissed({ file = statePath() } = {}) {
  return loadFullState({ file }).dismissed;
}

/** Atomic write of the full state: temp file in the same directory, then rename; 0o600/0o700, same as before. */
function writeFullState(file, { acks, dismissed }) {
  const dir = path.dirname(file);
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const tmp = path.join(dir, `.rotations.json.tmp-${process.pid}-${crypto.randomBytes(4).toString("hex")}`);
  const body = JSON.stringify({ v: 1, acks, dismissed }, null, 2) + "\n";
  fs.writeFileSync(tmp, body, { mode: 0o600 });
  try {
    fs.renameSync(tmp, file);
  } catch (err) {
    // The rename failing must not strand a temp file next to the state.
    try { fs.unlinkSync(tmp); } catch {}
    throw err;
  }
}

/**
 * An ack note is user-supplied free text headed for a plaintext state file,
 * so it goes through the same discipline as every preview: control bytes
 * stripped, anything matching a detection pattern redacted (a user pasting
 * the leaked key into their own note must not re-leak it into this file),
 * bounded by code point.
 */
function sanitizeNote(note) {
  if (note == null) return null;
  let s = stripControlChars(String(note));
  // NOISY_PATTERNS included on purpose: a note like `password = "..."` from
  // someone acking an --include-noisy finding must not land on disk raw.
  for (const rule of PATTERNS.concat(NOISY_PATTERNS)) {
    rule.re.lastIndex = 0;
    s = s.replace(rule.re, (m) => redact(m));
  }
  const cps = Array.from(s);
  return cps.length > 500 ? cps.slice(0, 500).join("") + "…" : s;
}

/**
 * Record that the user acknowledged (rotated) one finding, or dismissed it
 * (decided it was never a real secret, a test fixture, a vendor example not
 * already on the suppression list, etc.) — two DIFFERENT resolutions of the
 * same "this is no longer pending" question, kept as separate maps in one
 * file rather than a single status field: acked and dismissed have
 * different guidance implications (an acked finding's guidance stays
 * relevant if you ever need to re-check the rotation; a dismissed one
 * never needed guidance in the first place) and different --fail-on-find
 * semantics may want to diverge later. Shared helper for both:
 * ackFinding(fp, note) / dismissFinding(fp, note).
 *
 * Atomic: temp file in the same directory, then rename; 0o600 on the file,
 * 0o700 on the directory, since even a redacted rotation ledger is nobody
 * else's business.
 *
 * Atomic is not serialized: two concurrent `residoo ack`/`dismiss` runs
 * each load-modify-write, and the last rename wins, silently dropping the
 * other run's change. Accepted as a single-writer design: these are typed
 * by a human one at a time, the ledger is per-user state, and the failure
 * direction is fail-safe (a dropped entry reverts that finding to pending,
 * never the reverse). A lockfile would add a stale-lock recovery path for
 * a race that a person cannot realistically produce.
 */
function resolveFinding(kind, fp, note, { file = statePath() } = {}) {
  if (typeof fp !== "string" || !FINGERPRINT_RE.test(fp)) {
    throw new TypeError(`${kind}Finding expects a fingerprint from fingerprintFinding() (rf1-<32 hex>)`);
  }
  const state = loadFullState({ file });
  const entry = { at: new Date().toISOString(), note: sanitizeNote(note) };
  const key = kind === "ack" ? "acks" : "dismissed";
  state[key][fp] = entry;
  writeFullState(file, state);
  return { fingerprint: fp, ...entry, file };
}

function ackFinding(fp, note, opts) { return resolveFinding("ack", fp, note, opts); }
function dismissFinding(fp, note, opts) { return resolveFinding("dismiss", fp, note, opts); }

// ── summaries for the report layer ──────────────────────────────────────────

/**
 * Counts plus per-finding status. `statuses[i]` describes `findings[i]`;
 * counts are over DISTINCT fingerprints, because five re-echoes of one token
 * across a transcript are one rotation to do, not five (the same
 * distinct-vs-re-exposed reasoning scan.js applies to counting).
 */
function pendingSummary(findings, acks, dismissed = {}) {
  const list = Array.isArray(findings) ? findings : [];
  const ackMap = acks && typeof acks === "object" ? acks : {};
  const dismissMap = dismissed && typeof dismissed === "object" ? dismissed : {};
  const statuses = [];
  const distinctStatus = new Map(); // fp -> "acked" | "dismissed" | "pending"
  for (const f of list) {
    const fp = fingerprintFinding(f);
    const ack = ackMap[fp] || null;
    const dismiss = dismissMap[fp] || null;
    // Precedence when a fingerprint somehow has both (not reachable through
    // the CLI today, but the state file is hand-editable): acked wins. "I
    // rotated it" is the more thorough resolution of the two, and reverting
    // to "acked" from a stray dismissed entry is the fail-safe direction —
    // it keeps guidance attached rather than silently dropping a real
    // rotation's record.
    const status = ack ? "acked" : dismiss ? "dismissed" : "pending";
    const resolved = ack || dismiss;
    statuses.push({
      fingerprint: fp,
      status,
      ackedAt: resolved ? resolved.at : null,
      ackNote: resolved ? resolved.note : null,
    });
    if (!distinctStatus.has(fp)) distinctStatus.set(fp, status);
  }
  let acked = 0, dismissedCount = 0;
  for (const status of distinctStatus.values()) {
    if (status === "acked") acked++;
    else if (status === "dismissed") dismissedCount++;
  }
  return {
    counts: {
      findings: list.length,
      distinct: distinctStatus.size,
      pending: distinctStatus.size - acked - dismissedCount,
      acked,
      dismissed: dismissedCount,
    },
    statuses,
  };
}

const STATUS_ORDER = { pending: 0, acked: 1, dismissed: 2 };

/**
 * Pure data for the report layer: one entry per distinct fingerprint, with
 * rotation guidance attached and pending entries first. Prints nothing.
 */
function renderRotation(findings, acks, dismissed = {}) {
  const list = Array.isArray(findings) ? findings : [];
  const { counts, statuses } = pendingSummary(list, acks, dismissed);

  const byFp = new Map();
  for (let i = 0; i < list.length; i++) {
    const f = list[i];
    const st = statuses[i];
    let e = byFp.get(st.fingerprint);
    if (!e) {
      e = {
        fingerprint: st.fingerprint,
        ruleId: String(f.ruleId || ""),
        label: String(f.label || f.ruleId || ""),
        preview: String(f.preview || ""),
        occurrences: 0,
        files: [],
        sources: [],
        guidance: guidanceFor(f.ruleId),
        status: st.status,
        ackedAt: st.ackedAt,
        ackNote: st.ackNote,
        lastSeenMs: null,
        // An access key id and an AWS secret are only dangerous TOGETHER
        // (see pairing.js): one is useless to an attacker without the
        // other. These carry the OTHER half's redacted preview when
        // scan.js found one sitting next to this value, so a report with
        // several access-key-id findings can say which one is an actual
        // usable credential pair, not just that a secret exists somewhere.
        pairedSecretPreview: null,
        pairedAccessKeyPreview: null,
        // A JWT's own `exp` claim, decoded locally (see jwtExpiry.js): the
        // one credential type residoo can say "still valid" or "expired"
        // about with zero network calls, since expiry is inside the signed
        // payload. null for every non-JWT finding, and for a JWT that
        // failed to decode or carries no exp claim.
        jwtExpiresAtMs: null,
        // --verify only (see verify.js): whether the credential's own
        // vendor (AWS, Slack) still accepts it. null unless the scan was
        // run with --verify AND this value is one residoo knows how to
        // check; residoo makes no network calls otherwise. Same two fields
        // regardless of vendor: the ruleId already says which one answered.
        verified: null,
        verifiedDetail: null,
      };
      byFp.set(st.fingerprint, e);
    }
    e.occurrences++;
    const rel = f.relFile != null ? String(f.relFile) : path.basename(String(f.file || ""));
    if (rel && !e.files.includes(rel)) e.files.push(rel);
    const src = f.source != null ? String(f.source) : null;
    if (src && !e.sources.includes(src)) e.sources.push(src);
    // Most recent occurrence across all files this value showed up in: the
    // honest, locally-derivable signal for "how stale is this." NOT proof a
    // credential was rotated or revoked, only that residoo hasn't seen it
    // paste anywhere more recently than this. residoo makes no network
    // calls in the default path, so this alone never checks a provider for
    // whether a key is still live (see verified above for the opt-in
    // exception, and jwtExpiresAtMs for the zero-network JWT case).
    if (typeof f.fileMTimeMs === "number" && (e.lastSeenMs === null || f.fileMTimeMs > e.lastSeenMs)) {
      e.lastSeenMs = f.fileMTimeMs;
    }
    // Take the first pairing seen across this fingerprint's occurrences: if
    // the same value ever appeared next to its pair on ANY line, that's
    // enough to flag it, even if a later re-echo of the same value elsewhere
    // (e.g. Claude confirming "got it") dropped the neighboring secret.
    if (e.pairedSecretPreview === null && typeof f.pairedSecretPreview === "string") {
      e.pairedSecretPreview = f.pairedSecretPreview;
    }
    if (e.pairedAccessKeyPreview === null && typeof f.pairedAccessKeyPreview === "string") {
      e.pairedAccessKeyPreview = f.pairedAccessKeyPreview;
    }
    if (e.jwtExpiresAtMs === null && typeof f.jwtExpiresAtMs === "number") {
      e.jwtExpiresAtMs = f.jwtExpiresAtMs;
    }
    if (e.verified === null && typeof f.verified === "string") {
      e.verified = f.verified;
      e.verifiedDetail = typeof f.verifiedDetail === "string" ? f.verifiedDetail : null;
    }
  }

  // Within a status tier, order by how demonstrated-urgent an entry is, not
  // just its rule id: a real pair (see pairing.js) is a DEMONSTRATED usable
  // credential, and --verify confirming the vendor still accepts it is
  // stronger evidence still; either way this entry must never be the one
  // the display cap (see renderRotationSection) pushes into "N more."
  //
  // isConfirmedDead is the other direction, PROOF rather than a guess:
  // --verify got a real "no" from the vendor, or a JWT's own signed exp
  // claim is already in the past (decoded locally, no network call, always
  // attempted; see jwtExpiry.js). Deliberately NOT "unverified" or "no
  // pairing found": those mean residoo doesn't know, a weaker claim than
  // residoo knows this one specific value needs no action. Sorts LOWER
  // than an ordinary finding within its tier, and (see confirmedDead below)
  // is subtracted from what the report tells a human still needs a look.
  const isConfirmedDead = (e) => e.verified === "invalid" || (e.jwtExpiresAtMs !== null && e.jwtExpiresAtMs < Date.now());
  const priorityScore = (e) => {
    if (e.verified === "active") return -2;
    if (e.pairedSecretPreview !== null || e.pairedAccessKeyPreview !== null) return -1;
    if (isConfirmedDead(e)) return 1;
    return 0;
  };
  const entries = [...byFp.values()].sort((a, b) => {
    if (a.status !== b.status) return STATUS_ORDER[a.status] - STATUS_ORDER[b.status];
    const pa = priorityScore(a), pb = priorityScore(b);
    if (pa !== pb) return pa - pb;
    if (a.ruleId !== b.ruleId) return a.ruleId < b.ruleId ? -1 : 1;
    return a.fingerprint < b.fingerprint ? -1 : 1;
  });

  // A per-VALUE fact, never rolled up into a per-RULE label: only the
  // specific values residoo actually checked (or that carry their own
  // signed exp claim) ever count here, so this can never overstate what was
  // proven about the rest of a rule's unverified findings. Counted only
  // among PENDING entries: one already acked or dismissed is excluded from
  // "needs review" for its own reason already, and double-subtracting would
  // make the arithmetic in the report not add up.
  const confirmedDead = entries.filter((e) => e.status === "pending" && isConfirmedDead(e)).length;

  return { counts: { ...counts, confirmedDead }, entries };
}

module.exports = {
  ROTATION_GUIDANCE,
  ROTATION_ORDER_ADVISORY,
  guidanceFor,
  fingerprintFinding,
  statePath,
  loadAcks,
  loadDismissed,
  ackFinding,
  dismissFinding,
  pendingSummary,
  renderRotation,
};
