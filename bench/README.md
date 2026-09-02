# The transcript-shaped secrets benchmark

A reproducible benchmark for one question the classic secret-scanner corpora never ask:
**how well do scanners find credentials at rest in AI coding-agent transcripts, and what
leaves your machine while they look?**

Agent transcripts are a distinct surface. Secrets arrive there by paste, by tool stdout,
by file-read echo, nested inside JSON-in-JSON tool structures, re-exposed across several
records of the same session, base64-encoded in command output, or split across adjacent
records. Config files sit next to them (`settings.local.json`, `.mcp.json`). A scanner
tuned for git diffs meets none of this shape. This benchmark measures that gap, per
class, on a fully synthetic corpus, and it measures the second axis most benchmarks
ignore: observed network egress during the scan.

## What is measured

- **Recall per class**, at two levels: exposure sites found, and distinct credentials
  found (a credential counts as found when any of its exposure sites matched). Both are
  always shown, because tools that dedupe re-exposed credentials score differently at
  the two levels and both views are honest.
- **Precision**: flags on chaff (credential-shaped non-secrets: git SHAs, UUIDs, sha256
  hex, base64 image fragments), flags on suppress instances (vendor-style placeholder
  and example values), and findings matching nothing planted.
- **Scan-time egress**, observed live by two dynamic layers (a refuse-and-log proxy trap
  plus lsof polling of the scanner's own process tree), with a positive-control self
  test proving both layers fire before any silence is trusted.
- **Wall time** per scan.

There is deliberately no single blended headline number. A blend would hide exactly the
class differences this benchmark exists to show.

## The corpus

100% synthetic and deterministic from a seed (`SEED = 20260902`): 72 Claude Code session
`.jsonl` files (7,548 records) across 4 project slugs, plus agent config side-fixtures.
Record shapes were derived from real Claude Code transcripts by structure extraction
only; no real content or real value appears anywhere. Every planted credential is a
pattern-true fake in the CredData (Samsung) style: correct prefix, charset, and length
for its family, never a value any provider issued. Pattern-true includes charset
strictness, for example AWS access key ids use the real base32 charset, because a
charset-correct scanner must never be penalized for rejecting an impossible value.

Classes: plain exposures (transcript and agent-config surfaces), JSON-nested,
multi-record echo re-exposure, base64-encoded, split-across-records, a suppress class of
placeholder/example values (flagging them is a false positive), and tracked chaff.
Ground truth (`corpus/truth.json`) and the scoring manifest (`corpus/data/manifest.json`)
live outside the scanned fixture home so they can never contaminate a scan.

## Fairness rules, stated up front

1. **Claimed-scope scoring.** A tool is scored on a class only if its own documentation
   claims that surface (each adapter quotes its source). Unclaimed classes are reported
   as "out of claimed scope", never as zero. This is why per-tool denominators differ.
2. **Install-time vs scan-time egress.** Tools are installed once into `bench/tools/`
   before any monitored run; package-manager fetches are normal and unscored. The
   monitored window covers exactly the scan process, spawn to exit.
3. **Hard classes are scored separately.** The base64 and split classes ("hard" =
   commonly missed by line-oriented scanners; gitleaks defeats base64 by decoding in
   place) are reported as their own rows and never blended into any per-class headline
   row. The one cross-class line, distinct credentials found, is explicitly labeled as
   covering all claimed classes with the hard classes included, and a
   headline-classes-only variant is always printed beside it.
4. **ggshield's recall is "not scored (requires server account)", never zero.** Its
   detection is server-side by its own documentation; scoring it would require shipping
   the corpus to a server, which is the egress axis itself. Its observed unauthenticated
   refusal (exit 3) is recorded verbatim as evidence, with the by-design citation, and
   the nuance that self-hosted instances exist.
5. **Redacting tools are never penalized for redacting.** Matching runs through tiers:
   exact value, then file+line, then file+rule-family. The ambiguity rule in the
   family tier prefers crediting recall over assigning false positives, which is the
   pro-competitor direction on purpose.
6. **Re-reporting is not double-counted.** Precision counts planted instances, not raw
   findings, so a tool that reports one site under two rules is neither doubly right
   nor doubly wrong.
7. **Scan-only invocations.** No adapter ever invokes a tool's redact, fix, or wipe
   mode. Every scanner runs with HOME and every home-resolving variable pinned into the
   fixture; the harness refuses to run against anything covering a real home directory.
8. **The fixture is write-protected in practice.** XDG cache and state point at a
   per-run scratch directory outside the fixture (a tool's own cache writes are
   recorded as evidence, then removed), and the runner diffs the fixture tree after
   every scan: any file a scanner creates, modifies, or deletes inside the scanned
   tree is reported loudly in the raw record. The committed corpus therefore always
   equals generator output, byte for byte.
9. **Dual-mode tools are scored offline, observed in both modes.** Some scanners
   verify candidate secrets against provider APIs during the scan by default and
   document an offline switch (TruffleHog `--no-verification`, Kingfisher
   `--no-validate`, detect-secrets `-n`). Recall is scored ONLY in the documented
   offline mode, because scoring recall in a mode that phones out would conflate
   the recall axis with the egress axis. Egress is then observed in BOTH modes:
   the offline run must show none-observed, and the default mode is executed
   against the same corpus under the same monitor, with its observed connection
   attempts reported factually (destinations listed) next to a citation of the
   vendor's own documentation describing verification. Neither mode's conduct is
   editorialized: verification is a documented feature, and the report states
   what was observed and what the vendor's docs say. Because every planted
   credential is a pattern-true fake no provider ever issued, a default-mode
   verification attempt sends only fake values at worst, and the refuse-and-log
   proxy trap refuses the connections anyway, so no verification request can
   leave the machine; both facts are stated so nobody can claim the benchmark
   transmitted secrets.
10. **Suppress-class design order, disclosed.** The smoke tests that produced
   `tools/VERSIONS.md` established which tools report the AWS documented example key
   BEFORE the suppress class was finalized. The class was kept because
   vendor-documented placeholders are a real precision hazard in transcripts, and the
   contested philosophy is handled two ways: suppress flags live in their own row, and
   precision is always published both with and without them.

Full matching rules: header of `harness/score.js`. Full egress design:
`harness/README.md`. Adapter invocations and claim citations: `harness/adapters/*.js`.
Tool versions and install notes: `tools/VERSIONS.md`.

## Reproduce

Install the tools once per `bench/tools/VERSIONS.md` (install-time network is expected
and unscored), then from the repository root:

```
node bench/corpus/generate.js && node bench/corpus/make-manifest.js
node bench/harness/selftest-egress.js
for t in residoo gitleaks agentsweep whatileaked detect-secrets ggshield \
         trufflehog betterleaks kingfisher \
         detect-secrets-default-verification trufflehog-default-verification \
         kingfisher-default-verification; do
  node bench/harness/run.js "$t"
done
node bench/harness/score.js --md
```

The `<tool>-default-verification` runs are the dual-mode egress observations (fairness rule
9): they execute each dual-mode tool's default (verification-enabled) mode
under the same monitor and are never scored for recall; `run.js --list` shows
which adapters are available on this machine.

The corpus is byte-identical on every regeneration, and the runner verifies after
every scan that no tool mutated it. Raw scanner output, exact commands, and env pins
are written to `results/raw/` so every number can be traced to verbatim tool output
(note: raw records contain the absolute fixture paths of the machine they were
captured on). Run `node bench/harness/selftest-egress.js` first to prove the egress
monitor fires; its transcript is persisted to `results/raw/selftest-egress.txt`.
Current numbers: `RESULTS.md`.

## Challenge this methodology

If you believe any scoring choice is unfair to any tool, file an issue against this
repository with the plant id or adapter line in question. The bar this benchmark holds
itself to: a hostile reader can rerun everything, get the same numbers, and find the
fairness questions answered rather than dodged. Methodology issues are treated as bugs.

## Honest limitations

- **The corpus is synthetic.** Plants are placed where real leaks are observed to occur,
  but distributional realism is a model, not a measurement.
- **Per-class recall mixes rule-family coverage with transcript shape.** Some gaps are
  a tool simply shipping no rule for a family, not a shape failure. The per-family
  recall table in `RESULTS.md` (and `perFamily` in `scoreboard.json`) exists so any
  reader can recompute any class with any family subset and separate the two effects;
  the transcript-plain analysis in `RESULTS.md` does that decomposition explicitly.
- **Claude Code transcript schema only in v1.** Codex, Cursor, Gemini CLI and other
  agent formats are future work; conclusions here are about this surface.
- **Self-run, pending independent reproduction.** The benchmark is published by
  residoo's author. Everything needed to reproduce it independently ships in this
  directory, and independent reruns are invited; until then, treat the numbers
  accordingly.
- **Benign-suppression heuristics differ by tool.** The suppress class rewards
  example-value filtering, which some tools implement deliberately and others do not;
  reasonable people can weigh that trade-off differently, so it is reported as its own
  row, not blended.
- **residoo is measured by the same harness it ships with.** Its own weaknesses on this
  corpus (base64 0/5, split 1/6, agent-config 1/3, 3 suppress false positives) are
  reported unfixed, exactly as scored on the published v0.3.0.
