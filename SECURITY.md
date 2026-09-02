# Security policy

## Reporting a vulnerability

If you find a security issue in residoo — including "this finding shouldn't
have been suppressed," "this output leaked more than it should have," or
anything in the redaction logic — please report it privately rather than as
a public issue. Open a [GitHub Security Advisory](../../security/advisories/new)
on this repository, or email the maintainer listed in `package.json`.

Please include:
- What you ran and what you expected vs. what happened
- Whether real secret material was involved (if so, a redacted/synthetic
  reproduction is preferred over the real value)

You'll get an acknowledgment within a few days. There's no bug bounty —
this is a small open-source tool, not a funded program — but every report
gets read and taken seriously, and credited in the fix unless you'd rather
stay anonymous.

## What's already been checked, and how

This isn't a claim taken on faith. Every property below was tested, not
just asserted — see the git history for the actual commands run:

- **No network calls.** Grepped for every network-capable primitive
  (`http`, `https`, `fetch`, `child_process`, etc.) across the full source.
- **Read-only.** Grepped for every filesystem write/delete primitive.
- **Output can't leak more than it shows.** The one raw matched value is
  used in exactly two places: an in-memory dedup count (never serialized)
  and the redaction function. Verified with a crafted input containing a
  raw ANSI escape sequence that a real terminal would execute — confirmed
  it rendered live (a working clear-screen) before the fix, confirmed it
  doesn't after.
- **Not vulnerable to regex denial-of-service.** Every pattern checked
  against the nested-quantifier shape behind real, dated CVEs in adjacent
  tooling (e.g. CVE-2026-0621, a ReDoS in Anthropic's own MCP SDK from
  catastrophic backtracking on an exploded template pattern). Also stress-
  tested directly against multi-megabyte adversarial inputs.
- **No supply-chain surface.** Zero runtime dependencies, zero
  pre/post-install lifecycle scripts — check `package.json` yourself,
  there's nothing to hide behind a `postinstall` hook.

## Verifying you have the real thing

Fake clones of security tools are a real, active pattern — not a
hypothetical. In the last year alone: a self-propagating npm worm that
typosquatted common package names and injected malicious config into AI
coding tools' own settings files; a fake installer for a well-known AI
agent tuned to rank highly in AI-assisted search results; and a campaign
that cloned roughly 10,000 GitHub repositories with fabricated commit
history to smuggle malware behind a README download link. A tool whose
entire premise is "trust me with what I find in your secrets" is exactly
the kind of thing worth impersonating.

- The only npm package is **`residoo`**, published from **this** GitHub
  repository via CI, not uploaded by hand from a maintainer's laptop.
- The only GitHub org is the one this file lives in. If you found residoo
  through a link, a blog post, or a search result rather than directly on
  npm or GitHub, cross-check the org name before running it.
- Nothing here needs a postinstall script, a config change to another
  tool, or elevated permissions. If a "residoo" you found asks for any of
  those, it isn't this project.
