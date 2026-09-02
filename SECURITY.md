# Security policy

## Reporting a vulnerability

If you find a security issue in residoo, including "this finding shouldn't
have been suppressed," "this output leaked more than it should have," or
anything in the redaction logic, please report it privately rather than as
a public issue. Open a [GitHub Security Advisory](../../security/advisories/new)
on this repository, or email the maintainer listed in `package.json`.

Please include:
- What you ran and what you expected vs. what happened
- Whether real secret material was involved (if so, a redacted/synthetic
  reproduction is preferred over the real value)

You'll get an acknowledgment within a few days. There's no bug bounty
(this is a small open-source tool, not a funded program), but every report
gets read and taken seriously, and credited in the fix unless you'd rather
stay anonymous.

## What's already been checked, and how

This isn't a claim taken on faith. Every property below was tested, not
just asserted. See the git history for the actual commands run:

- **No network calls in the scan path.** Grepped for every network-capable
  primitive (`http`, `https`, `fetch`, `child_process`, etc.) across the
  scanning code. The codebase's single `fetch` lives in `src/sealvault.js`,
  is reachable only behind the explicit `--upload-cloudroam` flag, and
  transmits ciphertext only. The vault is fully sealed before that code
  can run.
- **Scanning is read-only.** Grepped for every filesystem write/delete
  primitive in the scan path. Sealing (`--seal`) writes NEW files into a
  vault directory it creates; nothing in the codebase modifies or deletes
  an existing file, including the plaintext originals a seal just
  encrypted. Removing those is deliberately left to the human.
- **Output can't leak more than it shows.** The one raw matched value is
  used in exactly two places: an in-memory dedup count (never serialized)
  and the redaction function. Verified with a crafted input containing a
  raw ANSI escape sequence that a real terminal would execute. It rendered
  live (a working clear-screen) before the fix, and doesn't after. The
  integrity checker applies the same discipline to attacker-controlled
  config content: control characters are stripped and invisible Unicode is
  rewritten as visible escapes before anything reaches your terminal.
- **Not vulnerable to regex denial-of-service.** Every pattern checked
  against the nested-quantifier shape behind real, dated CVEs in adjacent
  tooling (e.g. CVE-2026-0621, a ReDoS in Anthropic's own MCP SDK from
  catastrophic backtracking on an exploded template pattern). A second,
  distinct failure mode was found and fixed during a pre-launch audit: an
  open-ended quantifier (`{n,}`) matching a multi-megabyte same-charset run
  can overflow V8's regex engine on stack depth alone, independent of
  catastrophic backtracking. The raw-match, base64-decode, and split-line
  passes shared one try/catch at the time, so a crash partway through the
  rule list could silently skip every rule after it for that line. Every
  rule's quantifier is now explicitly bounded to its format's real maximum
  length (a credential shape has a knowable ceiling), each of the three
  passes has its own try/catch as a second, independent layer, and a
  regression test asserts a real secret placed immediately after a
  multi-megabyte adversarial run is still found. Stress-tested directly
  against multi-megabyte adversarial inputs, including that exact shape.
- **No supply-chain surface.** Zero runtime dependencies, zero
  pre/post-install lifecycle scripts. Check `package.json` yourself;
  there's nothing to hide behind a `postinstall` hook.

## Verifying you have the real thing

Fake clones of security tools are a real, active pattern, not a
hypothetical. In the last year alone: a self-propagating npm worm that
typosquatted common package names and injected malicious config into AI
coding tools' own settings files; a fake installer for a well-known AI
agent tuned to rank highly in AI-assisted search results; and a campaign
that cloned roughly 10,000 GitHub repositories with fabricated commit
history to smuggle malware behind a README download link. A tool whose
entire premise is "trust me with what I find in your secrets" is exactly
the kind of thing worth impersonating.

- The canonical repository is **`github.com/dandovdub/residoo`**, the one
  named in this package's own `repository` field. A GitHub account named
  "residoo" exists and is NOT this project.
- The only npm package is **`residoo`**. Releases are published from this
  repository through CI with npm's provenance attestation, which
  cryptographically ties each release to the exact repo and workflow that
  built it; check the provenance badge on the npm page. One honest
  exception, stated rather than hidden: the very first release (v0.1.0)
  was a manual upload to claim the name, so provenance starts at the first
  CI-published version after it.
- The only PyPI package is **`residoo`**: a thin official launcher whose
  entire job is running the npm CLI via `npx`. Its source lives in this
  repository under `pypi/`. It exists partly so nobody else can hold the
  name.
- Nothing here needs a postinstall script, a config change to another
  tool, or elevated permissions. If a "residoo" you found asks for any of
  those, it isn't this project.
