# residoo vs. the rest of the field

The README keeps this to a few lines on purpose. This is the full version,
for anyone deciding between residoo and an adjacent tool.

## Quick comparison

| | residoo | gitleaks | trufflehog | agentsweep |
|---|---|---|---|---|
| Scans | AI-agent transcripts, configs | git commits | git commits, cloud, more | AI-agent transcripts |
| Detection rules | 50, high-confidence only | broad | 800+ detectors | 209 |
| Verification | opt-in, 35 vendors | none | on **by default**, 700+ vendors | none |
| Remediation | `--seal` (encrypted copy) | none | none | in-place redaction |
| Runtime deps | 0 (Node only) | 0 (Go binary) | 0 (Go binary) | Python 3.11+, 3 pip packages |
| Agent sources covered | 43 | n/a | n/a | 31 |

## Why not just use a git scanner

gitleaks and trufflehog are excellent at what they do, and what they do is
scan **commits**. That's a different, well-covered space. Nobody was looking
at the **conversation transcripts** AI agents leave behind, which contain a
superset of everything a commit does: not just code, but file contents,
terminal output, and whatever got pasted into a prompt.

Two newer categories are adjacent but solve a different problem:

- **Real-time hooks** (GitGuardian's `ggshield` AI hook, GitHub's secret
  scanning via its MCP server) intercept a prompt or a code change *as it
  happens*, going forward, only in a session that has the hook installed.
  They do nothing for months of transcripts already on disk, or for any
  session run without the hook active. residoo scans **retroactively, at
  rest**: every file already there, from every past session.
- This isn't a gap Anthropic plans to close upstream either: a
  [request to scrub secrets from `~/.claude/projects` natively](https://github.com/anthropics/claude-code/issues/50014)
  was filed and closed as **not planned**.

## agentsweep: a genuine peer

Broader on detection rules (209 to residoo's smaller, deliberately
high-confidence set) and it does in-place redaction, where residoo's
`--seal` makes an encrypted copy instead. residoo has more agent sources (43
to 31), and both now ship SARIF output and a pre-commit hook.

The tradeoffs are worth naming precisely:

- It needs Python 3.11+ and three pip packages (all clean on inspection, no
  known CVEs); residoo needs nothing beyond Node.
- Its own README documents that in-place redaction leaves the pre-redaction
  original in a **plaintext** `.bak` file, and its issue tracker shows the
  real cost: a merged fix
  ([PR #13](https://github.com/Ishannaik/agent-sweep/pull/13)) for a case
  where redacting a WAL-mode SQLite database left the secret recoverable
  from a leftover journal file. `--seal` takes a different tradeoff (encrypt
  a copy, touch nothing, never claim a file is "cleaned") specifically to
  avoid that failure class.
- Its tracker also shows several real, since-fixed false-*clean* reports:
  schema drift and malformed lines silently skipped, `--root` pointed at a
  file scanning nothing and exiting 0. That's the exact failure mode
  residoo's `broken`/`partial` status contract (see `CONTRIBUTING.md`)
  exists to make structurally hard to reproduce.

None of this makes agentsweep bad: it's a legitimately different set of
choices, and its README is honest about its own tradeoffs too. Worth a look
if broader source coverage matters more to you than a minimal dependency
footprint.

## Verifying a found value is still live

The field splits into two real postures, and residoo picked a side.
[trufflehog](https://github.com/trufflesecurity/trufflehog) verifies **by
default** (an opt-out, `--no-verification`, rather than an opt-in) across
700+ vendor-specific checks, so a plain, unconfigured trufflehog run makes
network calls. gitleaks never added verification and is now feature-complete
(security patches only); its declared successor,
[betterleaks](https://github.com/betterleaks/betterleaks), added it the
other way: **off by default**, one global `--validation` flag, each rule's
own validate expression deciding whether and how it calls out, repeated
occurrences of the same value deduped to one request. agentsweep has none
either, and says so directly: its own README scores trufflehog's
verification with a checkmark and its own with an X.

residoo's `--verify` follows betterleaks' posture, not trufflehog's: off by
default, an explicit flag, 35 vendors today (short of trufflehog's 700+),
deduped the same way, and gated the same way `patterns.js`'s own detection
rules are: only added where a real, cited endpoint exists, never assumed by
analogy to a similar vendor. Every vendor clears a two-stage bar before
being wired up: independent research against that vendor's own current
docs, then a second, adversarial pass that tries to refute the first before
it's trusted. See [`src/verify.js`](../src/verify.js) for exactly what it
touches and when.
