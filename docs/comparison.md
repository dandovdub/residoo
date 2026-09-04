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
| Continuous mode | `residoo watch` | none | none | none |

The rows above (rule counts, deps, sources) are documented facts, not
measured ones, and "Detection rules" specifically is the one most likely
to mislead if read alone: more rules is not the same claim as finding
more credentials, and the benchmark shows the two diverging for every
tool in this row. gitleaks' broad, generic rule set is tuned for git
commits, not the transcript-specific disguises (JSON-nested, base64,
split-across-lines) this corpus plants — it found 71% of distinct
credentials. TruffleHog's 800+ detectors span every domain it scans
(cloud infra, git, chats, more), not this one specifically — it found
64%. agentsweep is the most directly comparable, since it targets this
exact niche: 209 rules to residoo's 50, and it still found fewer
credentials, 79% to residoo's 100%. residoo's 50 are "high-confidence
only" by deliberate design (see [`src/patterns.js`](../src/patterns.js)'s
own header), trading rule-count breadth for a lower false-positive rate;
the benchmark, not the row above, is the actual answer to "does more
rules mean it works better." Full methodology, per-class breakdown, and
how to reproduce it: [`bench/`](../bench/) and
[`bench/RESULTS.md`](../bench/RESULTS.md).

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

## Continuous mode: nobody else in the field has one

Every tool in the table above, and every tool in residoo's own benchmark
field (gitleaks, trufflehog, betterleaks, kingfisher, agentsweep,
whatileaked, detect-secrets, ggshield), is scan-once-and-exit: verified
directly against each installed binary's own `--help` output, not assumed
by reputation. `residoo watch` polls the same sources `scan` covers and
alerts the moment a new secret lands in a transcript, instead of waiting
for the next manual run.

The one adjacent thing is GitGuardian's `ggshield` AI hook, and it works a
genuinely different way: a per-agent-tool hook that has to be installed
into each tool's own hook system separately, intercepting a prompt or
completion as it happens and shipping that content to GitGuardian's server
for inspection. `residoo watch` is one local process, watching every known
agent source at once, with no network call at all in its default path
(same posture as `scan`; see [What it does not do](../README.md#what-it-does-not-do)).
It doesn't replace a hook wired into a specific tool's own event stream,
but it doesn't need one installed per tool either, and it covers every
transcript store residoo already knows about, not just the one tool a hook
happens to be attached to.

## Sieve: same niche, different shape

[Sieve](https://apps.apple.com/us/app/sieve-secret-scanner/id6767409365) is
a macOS GUI app ($9.99, App Store) scanning the same class of target
(Claude Code, Cursor, VS Code Copilot, Windsurf, Codex, and more local
agent session state) for leaked secrets, with a pitch nearly identical to
residoo's own: local-only, no telemetry, no cloud sync. It also ships an
MCP server for Claude Code, and now so does residoo, including the same
injected-credential-execution idea Sieve's own tool schema documents:
Claude runs a command with a stored credential injected as an environment
variable, never seeing the raw value before, during, or after.

The two implementations differ in ways that matter, based on what Sieve's
own public tool schema (its `sieve-mcp` stub repo) actually shows: Sieve's
tool takes a single `command` string, implying shell interpretation, and
documents no allow-list or execution-time enforcement mechanism anywhere.
residoo's `residoo_run_with_cred` (see
[Cred](features.md#cred-run-commands-with-injected-credentials))
takes a structured argument list, never a shell string, and the command
name is resolved *only* against an operator-configured, absolute-path-pinned
allow-list read fresh on every call, closing a real vulnerability class
(CVE-2026-12537, Gemini CLI, CVSS 10.0: an allow-list checked at setup but
never enforced at execution time let a prompt-injected agent read a
credential from the environment) that a first, less careful draft of this
same residoo feature was itself found to be exposed to during an
adversarial design review before it ever shipped. Both tools suppress the
executed command's own output for the same reason: it's a channel the
injected secret could otherwise leak through.

Sieve is GUI-only and macOS-only, with no CLI, CI, or cross-platform
story, and (as of its last update) no continuous/watch mode either.

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
