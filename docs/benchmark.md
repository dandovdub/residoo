# Benchmark: measured, not claimed

A reproducible benchmark against 8 real competing tools, on a synthetic-but-
pattern-true corpus (72 Claude Code sessions, 45 planted credentials, zero
real secrets), with live egress monitoring so "no network calls" is
observed, not just documented. Re-run against every meaningful release,
most recently v0.8.0:

| | residoo | best of the rest |
|---|---|---|
| Distinct credentials found (all claimed classes) | **45/45 (100%)** | agentsweep 33/42 (79%) |
| Precision (false positives) | **100%** (0 of 55 flags wrong) | gitleaks, whatileaked, trufflehog also 100% |
| Network egress during the scan | **none-observed** | 3 of 8 tools attempt real outbound calls in their *default* mode (trufflehog: 50 connection attempts to github.com, slack.com, api.anthropic.com, gitlab.com, npmjs.org) |

No single blended score, on purpose: a blend would hide exactly the class-
level differences (base64-wrapped, split-across-lines, JSON-nested) the
benchmark exists to measure. GitGuardian's `ggshield` is documented rather
than scored, since it refuses to run without a server account — a real
design choice, reported factually rather than counted as a loss or a win.

This benchmark was published while losing rows, not after residoo already
won. The first published run had residoo at 71%, behind agentsweep, and
beaten five-to-zero by gitleaks on base64-encoded plants. Every fix since
has been a general, documented mechanism, re-run in public against the
classes it was losing, with the before-and-after numbers kept in the
history rather than only publishing the final score. Most recently, this
project's own stress-testing of the benchmark's 100% precision claim
(using real false-positive patterns from gitleaks' and TruffleHog's own
issue trackers) found and fixed a genuine bug in residoo's own boundary-
join logic — the benchmark exists to catch residoo's problems too, not
just the competition's.

Full per-class breakdown, fairness rules, the exact reproduce commands,
and every dated rerun's history: [`bench/`](../bench/) (start with
[`bench/RESULTS.md`](../bench/RESULTS.md)). Self-run, pending independent
reproduction; everything needed to rerun it — the corpus generator, the
harness, the raw per-tool output — ships in this repo.

See also: [docs/comparison.md](comparison.md) for how residoo's scanned
surface (conversation transcripts) differs from what gitleaks and
TruffleHog scan (commits), and how its continuous `watch` mode compares to
GitGuardian's `ggshield` AI hook.
