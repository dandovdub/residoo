# Results: the transcript-shaped secrets benchmark

- Date: 2026-09-02
- Corpus: seed 20260902, 72 Claude Code session `.jsonl` files (7,548 records) plus
  agent config side-fixtures; 45 planted distinct credentials over 56 secret exposure
  sites, plus 10 suppress placeholders (vendor-style example values whose flagging is a
  false positive) at 10 sites and 45 tracked chaff instances. 100% synthetic
  pattern-true fakes (see `bench/README.md`).
- Harness: `bench/harness/run.js` + `score.js`; HOME and every home-resolving variable
  pinned into the fixture (tool cache/state redirected to a per-run scratch outside
  it); scan-only invocations; egress monitored live; fixture diffed after every scan
  for scanner writes.
- Machine: macOS (darwin arm64), Node v26.8.1. Wall times are a single run per tool
  (N=1), indicative only.
- Positive control: `harness/selftest-egress.js` was run first and both monitor layers
  fired; its transcript is persisted at `bench/results/raw/selftest-egress.txt`.
- Raw evidence: `bench/results/raw/<tool>.txt` (verbatim output, exact commands, env
  pins, scanner-write records), normalized findings in
  `bench/results/<tool>.findings.json`, machine-readable scores in
  `bench/results/scoreboard.json`. Raw records contain the absolute fixture paths of
  the machine they were captured on.

## Tool versions

| tool | version | invocation (scan-only) |
|---|---|---|
| residoo | 0.3.0 (this repo, `node bin/residoo.js scan --json`) | machine scan, HOME pinned |
| gitleaks | 8.30.1 (pinned official darwin_arm64 binary, sha256 verified) | `dir <fixture home> --report-format json` (the legacy `detect --no-git --source` spelling was verified to produce an identical finding set) |
| AgentSweep | 0.1.9 (PyPI, uv-managed) | `scan --source claude-code --json` (one run per agent root present) |
| whatileaked | 0.3.0 (npm, pinned copy, no npx at scan time) | `scan` (its only scan form; no flags exist) |
| ggshield | 1.54.0 (PyPI) | `secret scan path -r <fixture home>`, unauthenticated on purpose |

## Recall and precision per class

Site recall = exposure sites found / planted sites. Value recall = distinct credentials
found / planted distinct credentials. "Out of scope" = the tool's own documentation does
not claim that surface, so it is not scored there (never counted as zero). Denominators
for the cross-class rows differ because claimed scope differs.

"Hard class" = commonly missed by line-oriented scanners; the label describes the class,
not an excuse for any tool: gitleaks defeats the base64 class outright by decoding in
place (5/5) and whatileaked decodes most of it (4/5), while residoo and AgentSweep score
zero there. Hard classes are reported as their own rows and are excluded from the
headline-classes row; the all-classes row explicitly includes them.

### Secret classes (site recall, with value recall in parentheses where it differs)

| class | sites | residoo 0.3.0 | gitleaks 8.30.1 | AgentSweep 0.1.9 | whatileaked 0.3.0 |
|---|---|---|---|---|---|
| transcript-plain | 24 | 21/24 (88%) | 18/24 (75%) | 22/24 (92%) | 18/24 (75%) |
| agent-config-plain | 3 | 1/3 (33%) | 3/3 (100%) | out of scope | out of scope |
| transcript-json-nested | 6 | 5/6 (83%) | 2/6 (33%) | 6/6 (100%) | 2/6 (33%) |
| transcript-echo | 12 | 12/12 (100%) | 12/12 (100%) | 12/12 (100%) | 5/12 (42%, values 4/4) |
| transcript-b64 (hard class) | 5 | 0/5 (0%) | 5/5 (100%) | 0/5 (0%) | 4/5 (80%) |
| transcript-split (hard class) | 6 | 1/6 (17%, values 1/3) | 0/6 (0%) | 1/6 (17%, values 1/3) | 0/6 (0%) |
| distinct credentials, headline classes only | | 31/37 (84%) | 27/37 (73%) | 32/34 (94%) | 24/34 (71%) |
| distinct credentials, all claimed classes (hard classes included) | | 32/45 (71%) | 32/45 (71%) | 33/42 (79%) | 28/42 (67%) |
| re-exposed sites found | 8 | 8/8 | 8/8 | 8/8 | 1/8 |

### Per-family site recall (all claimed secret classes)

So any reader can recompute any class with any family subset, and separate rule-family
coverage from transcript shape. Same data machine-readable in `scoreboard.json`
(`perFamily`).

| family | residoo | gitleaks | AgentSweep | whatileaked |
|---|---|---|---|---|
| aws | 5/8 | 6/8 | 5/8 | 4/8 |
| github | 7/10 | 8/10 | 6/9 | 5/9 |
| anthropic | 7/9 | 6/9 | 7/8 | 4/8 |
| slack | 6/7 | 7/7 | 6/6 | 4/6 |
| stripe | 0/4 | 3/4 | 3/4 | 3/4 |
| npm | 3/4 | 3/4 | 3/4 | 2/4 |
| gitlab | 2/3 | 3/3 | 2/3 | 3/3 |
| connection-string | 3/3 | 0/3 | 3/3 | 0/3 |
| discord | 2/2 | 0/2 | 2/2 | 0/2 |
| bearer-header | 1/2 | 0/2 | 0/2 | 0/2 |
| private-key | 2/2 | 2/2 | 2/2 | 2/2 |
| jwt | 2/2 | 2/2 | 2/2 | 2/2 |

Per-tool denominators differ where a family has sites in a class outside that tool's
claimed scope (the three agent-config sites, one each in github, slack, and anthropic,
are not scored for AgentSweep or whatileaked).

### What the family mix does and does not explain (the strongest counter-argument, answered)

The transcript-plain ordering between residoo and gitleaks/whatileaked is family
coverage, not transcript shape. All 6 of gitleaks' and whatileaked's transcript-plain
misses fall in exactly the three families they ship no rules for at all:
connection-string (2 sites), discord-webhook (2), bearer-header (2). Restricted to the
nine families all four tools have rules for, transcript-plain becomes gitleaks 18/18
(100%) versus residoo 16/18, and residoo's plain-class edge disappears. The
transcript-shape claim rests on the classes where shape is the variable:
json-nested (residoo 5/6 and AgentSweep 6/6 versus gitleaks and whatileaked 2/6, with
the keyword-adjacency mechanism reproduced in isolation below) and the split class.

Why those families are planted anyway: DB connection strings and bearer Authorization
headers in verbose curl or tool output are among the most transcript-typical leak
shapes there are; the Discord webhook is the weakest inclusion and is named as such.
And the mix demonstrably was not tuned to residoo's rule list: residoo goes 0-for-4 on
the stripe family across every class it appears in, AgentSweep beats residoo on both
transcript-plain and json-nested, and gitleaks ties residoo on the all-classes
distinct-credentials row.

### False positives and precision

Precision is published twice because whether flagging a vendor-documented example value
(the suppress class) is a false positive is a philosophy reasonable people weigh
differently; the benchmark's design-order disclosure on this class is in
`bench/README.md`, fairness rule 9.

| metric | residoo | gitleaks | AgentSweep | whatileaked |
|---|---|---|---|---|
| chaff flagged (of 45) | 0 | 0 | 0 | 0 |
| suppress/placeholder flagged (of 10) | 3 | 0 | 5 | 0 |
| findings matching nothing planted | 0 | 0 | 0 | 0 |
| precision (matched sites / matched + all FP) | 93% | 100% | 89% | 100% |
| precision excluding suppress FP | 100% | 100% | 100% | 100% |

ggshield: recall **not scored (requires server account)**, never zero. Observed
unauthenticated: exit 3, "Error: A GitGuardian API key is needed to use ggshield."
before any scanning (verbatim in `results/raw/ggshield.txt`).

## Egress during the scan (the second axis)

Monitored per scan, spawn to exit, by two dynamic layers: a refuse-and-log proxy trap
(all proxy env pinned to it) and lsof polling of the scanner's own process tree at
~150ms. Positive control: `harness/selftest-egress.js`, run before the benchmark,
recorded a deliberate canary connection on both layers ("CONNECT
egress-selftest.invalid:443" on the trap; a live socket in the lsof poll), so a clean
verdict below is falsifiable evidence, not silence; its transcript is persisted at
`results/raw/selftest-egress.txt`. Install-time package fetches happen before any
monitored run and are not scored. Update-check behavior is reported symmetrically for
every tool that has any.

| tool | verdict | evidence |
|---|---|---|
| residoo | none-observed | 0 trap attempts, 0 non-trap sockets |
| gitleaks | none-observed | 0 trap attempts, 0 non-trap sockets |
| AgentSweep | none-observed | 0 trap attempts, 0 non-trap sockets. Update-check behavior: on an interactive TTY without `--json`, agentsweep 0.1.9 fires a background pypi.org version check (verified in its source); the benchmarked `--json` piped invocation skips it, the harness additionally sets its documented `AGENTSWEEP_NO_UPDATE=1` off-switch, and none was observed. |
| whatileaked | none-observed | 0 trap attempts, 0 non-trap sockets |
| ggshield | by-design-requires-server | Refused to scan without a GitGuardian API key (exit 3, live). **Observed during the scan window: one proxy CONNECT attempt to api.github.com:443** (update-check behavior: its version self-check, `ggshield/core/check_updates.py` in the installed package; caught and refused by the trap; no corpus content was sent since the scan never began). By-design citation: ggshield's own README, describing the invoked `secret scan` command: "ggshield uses our public API through py-gitguardian to scan and detect potential vulnerabilities in files and other text content." For the AI-agent surface specifically, its v1.53.0 changelog on `ai discover --activity`: it collects raw agent activity and "ships it to GitGuardian, which scans the content and strips secrets server-side". Nuance: `--instance` supports self-hosted servers, so "requires a server" need not mean GitGuardian's cloud. |

### Scanner writes (fixture integrity)

The runner diffs the scanned fixture against a pre-scan snapshot after every run, and
redirects tool cache/state (XDG) to a per-run scratch directory outside the fixture.
This run: zero fixture mutations by any tool; ggshield wrote one file into its scratch
cache (`cache/ggshield/update_check.yaml`, its update-check timestamp, recorded in
`results/raw/ggshield.txt` and then removed with the scratch). Without the scratch
redirect that write would have landed inside the scanned fixture, which is why the
harness treats scanner writes as first-class evidence.

## Wall time (full corpus, single run each, N=1, indicative only)

| tool | wall |
|---|---|
| residoo | 194 ms |
| ggshield | 297 ms (auth refusal, no scan performed) |
| whatileaked | 450 ms |
| gitleaks | 614 ms |
| AgentSweep | 663 ms |

## Notable observations, verified against raw output

- **gitleaks decodes base64 in place** (8.30.1): on the 5 base64-encoded plants it
  reported the exact decoded secret for 4, and for the fifth (the npm token) a
  truncated decode (24 of the 40 characters, under its generic-api-key rule) that the
  scorer credited through the file+line tier; either way, 5/5 sites found. Verified by
  isolating the planted lines and rerunning; the decoded values appear as `Secret` in
  its report.
- **gitleaks' keyword-gated rules break on transcript-shaped nesting.** Its
  prefix-identifiable rules (github-pat, slack-bot-token) match inside JSON-in-JSON
  escaped strings, but keyword-adjacency rules (stripe, npm, anthropic) fail there
  because escaped quotes sit between the key name and the value. Reproduced in
  isolation on the exact planted lines. This is the clearest evidence that git-diff
  scanners and transcripts are different surfaces.
- **whatileaked dedupes by design**: one representative file per distinct credential,
  no line numbers. Its value recall (4/4 on the echo class) with partial site recall
  (5/12) is that design honestly represented at both levels, and the all-classes
  distinct-credential row guards it against value-level undercounting.
- **The suppress class splits the field**: gitleaks and whatileaked filter placeholder
  and example values (0 false positives), AgentSweep flags 5/10, residoo flags 3/10
  (`npm_XXXX...`, `AKIAIOSFODNN7EXAMPLE`, `ghp_xxxx...`). residoo's misses here were
  filed as a fix task and are published unfixed in these numbers.
- **residoo's other weaknesses, unhidden**: 0/4 on the stripe family everywhere it
  appears, 0/5 on base64, 1/6 on split halves, 1/3 on agent-config (it missed the
  project-level `settings.local.json` and `.mcp.json` in this fixture; its own docs
  claim those only via the unrun `--project` mode, and it is charged the miss anyway).
  No corpus or scoring choice was adjusted in residoo's favor; the one corpus
  correction made during assembly went the other way (see below).
- **Corpus correction during assembly (pro-competitor)**: the first corpus draft
  generated AWS key ids with an impossible charset (digits 0/1/8/9 never appear in real
  AKIA ids, which are base32). Charset-correct scanners (gitleaks, whatileaked)
  rightly rejected those values and were being unfairly penalized. The generator was
  fixed to emit pattern-true base32 ids and every tool was rerun; gitleaks' AWS recall
  rose accordingly. Kept here as a worked example of the fake-fidelity bar.

## Reproduce

```
node bench/corpus/generate.js && node bench/corpus/make-manifest.js
node bench/harness/selftest-egress.js
for t in residoo gitleaks agentsweep whatileaked ggshield; do node bench/harness/run.js "$t"; done
node bench/harness/score.js --md
```

Tool installs (one-time, unscored, pinned versions): `bench/tools/VERSIONS.md`.
