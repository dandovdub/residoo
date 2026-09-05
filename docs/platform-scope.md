# Why desktop-only: mobile and the consumer market, researched and declined for now

residoo is a developer tool today: a CLI that scans a machine's own AI
coding agent session files at rest. Two adjacent directions come up
naturally -- extending toward non-developer consumers, and toward mobile
phones -- and both were researched properly rather than assumed. This is
that record, kept for the same reason `docs/comparison.md` documents
NuGet's CASK format and Segment's token as researched-and-declined rather
than silently skipped: so the question doesn't get re-asked, or worse,
re-guessed, without an answer already on file.

## Consumer market: a real gap, but an unproven one

No established consumer security vendor -- password manager, antivirus
suite, identity-monitoring service, VPN bundle -- has shipped a "warn
before you paste sensitive data into ChatGPT/Claude" feature. The only
live product found addressing this directly is a single-developer Chrome
extension, "ChatGPT Secure," scoped to `chat.openai.com` only (not
Claude, Gemini, or Copilot), with 139 installs. Two other extensions that
looked more promising in initial search results, "PasteSecure" and
"SafePasteToAI," did not survive adversarial verification and should be
treated as unconfirmed, not real prior art.

The pricing question has a real answer, just not from this exact niche:
narrow, single-purpose consumer privacy tools do sustain a paid
subscription with no freemium core tier -- DeleteMe ($129/year) and
Incogni (paid from signup) both prove people will pay a recurring fee for
one well-defined privacy job. That's a viable pricing precedent *if*
demand for this specific job exists.

Whether it does is the open question. The solid survey evidence found
(NCA/CybSafe, n=1,074 people who share sensitive data with AI tools: 50%
share internal company documents, 44% client/customer data, 42%
financial data) is about **employees sharing workplace data**, not
ordinary consumers pasting their own personal PII into a chat. Several
consumer-specific statistics that looked relevant (a NymVPN 30%/26%/18%
breakdown, a 43% and a 38% figure from other survey write-ups) did not
survive verification and are not cited here as fact. Net: a real, thin
gap with a viable pricing model *if* proven, but the consumer-specific
demand case is not proven yet -- pursuing it without validating that
demand first would be building on an assumption, not evidence.

## Mobile (iPhone): a definitive, unfavorable technical verdict

This is the load-bearing finding, and it's clear enough to act on:
**residoo's current architecture -- scanning another app's files at rest
-- cannot port to stock, non-jailbroken iOS.** Apple's own sandboxing
model (confirmed against Apple's own security documentation, not a
third-party summary) prevents any third-party app from reading another
app's on-device files or data. There is no equivalent of `~/.claude/projects`
that a second app can simply open on iOS.

Every alternative mechanism was checked on its own merits, and each has a
specific, disqualifying problem:

- **Custom keyboard extensions** are the only mechanism that could
  plausibly intercept text *before* it's sent. By default, a keyboard
  extension runs fully sandboxed -- no network access, no exfiltration
  path of any kind. The only way to change that is the user granting
  "Allow Full Access," which Apple's own in-Settings copy describes to
  the user as making every keystroke visible to the keyboard's developer.
  That's a real, structural irony for a security product specifically:
  the one permission that would let residoo do its job is the exact
  permission a security-conscious user is most trained to refuse.
- **A local VPN / Network Extension content filter** cannot see the body
  of an HTTPS request -- only the hostname and port -- so it structurally
  cannot see a pasted secret in a request to Claude or ChatGPT. This
  holds even for Apple's newest filtering API (the iOS 26 URL Filter
  API, confirmed via Apple's own WWDC 2025 session): the requesting app
  never sees the traffic or URL content itself, by design. Seeing actual
  content would require a separate, user-installed MITM root
  certificate -- a distinct, much higher-trust ask that no NetworkExtension
  API provides on its own.
- **Share extensions, Shortcuts/App Intents pre-send review, and
  Screen-Time-style content filtering** were checked for a viable
  mechanism and none was substantiated with verified evidence either way
  -- an open gap in this research, not a ruled-out option, but nothing
  found supports treating any of them as a real path today.

Corroborating the verdict rather than just Apple's own docs: no shipping
enterprise MDM profile (checked: Jamf, Mosyle, Microsoft Intune, Kandji)
offers an "AI app" or generative-AI data-loss-prevention feature for iOS,
and the one real, shipping example of "AI prompt DLP" found anywhere --
Microsoft Purview for Microsoft 365 Copilot -- is implemented entirely as
a first-party, server-side policy check inside Microsoft's own backend,
not as an on-device or third-party mechanism at all. Nobody, anywhere,
has solved this the way residoo solves it on desktop. That is not
evidence residoo is behind; it's evidence the platform doesn't currently
allow it.

Two questions this research could not answer, stated openly rather than
glossed over: what data format the Claude and ChatGPT iOS apps actually
store on-device (no public teardown was found), and whether any
documented incident in the last 12 months involves a secret leaking via
those apps' iOS-specific behavior (a local cache, a crash log, a backup)
rather than the desktop or web versions. Both remain genuinely open.

## What would change this conclusion

Not treated as permanently closed. Two things would be worth a fresh
look if either happens:

1. **A Safari Web Extension angle, specifically not yet researched.**
   This pass checked native iOS mechanisms (keyboard extensions, share
   extensions, NetworkExtension) but not Safari Web Extensions running
   on iOS Safari against `claude.ai` or `chatgpt.com` in the *browser*,
   as opposed to the native apps. Browser extensions are a materially
   different, much more mature technology than anything checked above,
   and residoo's own detection engine (plain JavaScript, zero
   dependencies) is architecturally reusable as a content script with no
   rewrite. Whether iOS Safari's current WebExtension support actually
   exposes reliable content-script injection and form-submission
   interception the way desktop Safari does is unverified -- worth a
   dedicated research pass before assuming it works, not before ruling
   it out.
2. **Apple shipping a real on-device DLP/content-filtering framework for
   third-party apps.** Nothing in this research suggests that's planned,
   but it's the one platform change that would reopen the native-app
   question directly.
