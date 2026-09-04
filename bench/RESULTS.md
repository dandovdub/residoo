# Results: the transcript-shaped secrets benchmark

**Latest numbers: residoo 0.8.0, still 45/45 (100%) distinct credentials,
100% precision, none-observed egress** — see "residoo 0.8.0: two new
capabilities, zero scan-path behavior change by construction" near the end
of this file. The `0.3.0`/commit `16c911f` details right below are the
ORIGINAL publication, kept unchanged on purpose for reproducibility; every
dated section after it is a full rerun on a freshly regenerated corpus,
not an edit to what came before. If you only want the current numbers,
skip to the bottom; if you want the full history of how residoo got there
(including the bugs found and fixed along the way), read straight through.

Eight scored tools (residoo, gitleaks, AgentSweep, whatileaked, TruffleHog,
Betterleaks, Kingfisher, detect-secrets) plus ggshield
(documented, not scored: server-side detection by design). All eight were run
against the identical regenerated corpus in one session; the v1 four
reproduced their published v1 recall and precision numbers exactly, which is
the determinism claim demonstrated rather than asserted.

- Date: 2026-09-02 (full 8-tool field; the v1 four first published earlier the same day).
- Later the same day, after these numbers were published: residoo 0.3.1 was
  measured in a full fresh rerun (corpus regenerated, positive control
  re-passed, all 12 invocations re-run; every other tool reproduced its rows
  exactly). The 0.3.0 rows below are retained unchanged; the before/after is
  in the section "residoo 0.3.1: post-publication fixes, rerun on the same
  corpus".
- residoo version: 0.3.0, run from this repository at commit 16c911f
  (`node bin/residoo.js scan --json`; the working tree's only changes beyond
  that commit are under `bench/` and do not touch residoo's scan code).
- Corpus: seed 20260902, 72 Claude Code session `.jsonl` files (7,548 records) plus
  agent config side-fixtures; 45 planted distinct credentials over 56 secret exposure
  sites, plus 10 suppress placeholders (vendor-style example values whose flagging is a
  false positive) at 10 sites and 45 tracked chaff instances. 100% synthetic
  pattern-true fakes (see `bench/README.md`). Regenerated for this run; the by-family
  plant summary matches v1 exactly.
- Harness: `bench/harness/run.js` + `score.js`; HOME and every home-resolving variable
  pinned into the fixture (tool cache/state redirected to a per-run scratch outside
  it); scan-only invocations; egress monitored live; fixture diffed after every scan
  for scanner writes. Result: zero fixture mutations by any tool across all 12
  monitored runs (8 scored + 3 default-mode egress observations + the ggshield
  refusal run). All 12 raw records were captured back to back inside one
  21-second window of one session, immediately after the corpus regeneration
  and the positive control, so every number and every piece of egress evidence
  in this document comes from the same corpus bytes and the same conditions.
- Machine: macOS (darwin arm64), Node v26.8.1. Wall times are a single run per tool
  (N=1) captured under moderate ambient load (1-minute load average ~7 on 8 cores
  just after the window), so absolute times are indicative only and NOT comparable
  to times published from other windows; within this run every tool saw roughly the
  same conditions, so relative comparisons are indicative only.
- Positive control: `harness/selftest-egress.js` was run first and both monitor layers
  fired; its transcript is persisted at `bench/results/raw/selftest-egress.txt`. (The
  self test's canary socket hold was lengthened from 800ms to 4000ms earlier on this
  benchmark day, after a heavily loaded run measured one poll tick, which shells out
  to ps and lsof, at more than the old 800ms hold; a longer hold only strengthens the
  positive control and changes nothing in the monitor itself.)
- Raw evidence: `bench/results/raw/<tool>.txt` (verbatim output, exact commands, env
  pins, scanner-write records), normalized findings in
  `bench/results/<tool>.findings.json`, machine-readable scores in
  `bench/results/scoreboard.json`. Raw records contain the absolute fixture paths of
  the machine they were captured on.

## Tool versions

This table documents the original v1 baseline run (2026-09-02). residoo's
own row is superseded by every dated rerun section later in this file (most
recently 0.8.0) — it advances every release. Every OTHER tool's version
below was pinned once here and reused unchanged in every rerun since: none
of them were reinstalled or upgraded between runs, so gitleaks 8.30.1,
TruffleHog 3.97.2, and the rest are still the exact versions behind every
later result in this document too, not just this first one.

| tool | version | invocation (scan-only) |
|---|---|---|
| residoo | 0.3.0 (this repo at commit 16c911f, `node bin/residoo.js scan --json`) | machine scan, HOME pinned |
| gitleaks | 8.30.1 (pinned official darwin_arm64 binary, sha256 verified) | `dir <fixture home> --report-format json` (the legacy `detect --no-git --source` spelling was verified to produce an identical finding set) |
| AgentSweep | 0.1.9 (PyPI, uv-managed) | `scan --source claude-code --json` (one run per agent root present) |
| whatileaked | 0.3.0 (npm, pinned copy, no npx at scan time) | `scan` (its only scan form; no flags exist) |
| TruffleHog | 3.97.2 (pinned official darwin_arm64 binary, sha256 verified) | `filesystem <fixture home> --json --no-verification --results=verified,unknown,unverified --no-update`; scored in its documented offline mode (`--no-verification`), default mode observed for egress only |
| Betterleaks | 1.8.1 (pinned official darwin_arm64 binary, sha256 verified) | `dir <fixture home> --report-format json --no-banner --regex-engine stdlib` (its README's filesystem form; the stdlib engine keeps its default engine's cache write out of the scanned fixture, finding-set parity verified first) |
| Kingfisher | 2.1.0 (pinned official darwin-arm64 binary, sha256 verified against the release's sigstore attestation) | `scan <fixture home> --no-validate --format jsonl --no-dedup --no-rule-cache --no-update-check`; scored in its documented offline mode (`--no-validate`), default mode observed for egress only |
| detect-secrets | 1.5.0 (PyPI, uv-managed) | `scan --all-files -n <fixture home>` (baseline JSON on stdout); scored in its documented offline mode (`-n` / `--no-verify`), default mode observed for egress only |
| ggshield | 1.54.0 (PyPI) | `secret scan path -r <fixture home>`, unauthenticated on purpose |

## Claimed scope, in each tool's own words

The claimed-scope rule (a tool is scored on a class only if its own docs claim
that surface) needs the claims on the record. Quotes are from each tool's
README or CLI help as installed at the pinned version; full context in
`bench/tools/VERSIONS.md` and each adapter's `claimsNote`.

| tool | claimed scope | its own words |
|---|---|---|
| residoo | transcript, agent-config, and agent-memory classes | its `--help`: scans coding-agent session transcripts and agent config locations on the machine; repo-resident files are claimed only by the unrun `--project` mode |
| gitleaks | every class (generic file scanner) | "detecting secrets like passwords, API keys, and tokens in git repos, files, and whatever else you wanna throw at it via stdin" |
| AgentSweep | transcript classes only | "Find and redact secrets in your AI coding agent's local history. Fully offline." |
| whatileaked | transcript + agent-memory classes only | "Scan your local Claude Code, Codex and Cursor transcripts for credentials you already sent to a model provider." |
| TruffleHog | every class (generic file scanner) | "TruffleHog can look for secrets in many places including Git, chats, wikis, logs, API testing platforms, object stores, filesystems and more." |
| Betterleaks | every class (generic file scanner) | "Betterleaks is a configurable, fast, and thorough secrets scanner. It is maintained by the folks who made Gitleaks, including the original author." README documents `# Scan local filesystem` / `betterleaks dir /path/to/file/or/dir` |
| Kingfisher | every class (generic file scanner) | "Kingfisher - Detect and validate secrets across files and full Git history" (its own CLI help; `scan [PATH_INPUTS]...`) |
| detect-secrets | every class (generic file scanner) | "detect-secrets is an aptly named module for (surprise, surprise) detecting secrets within a code base." with the documented non-git form "detect-secrets scan test_data/ --all-files" |
| ggshield | every class claimed; recall not scored (requires server account) | "ggshield uses our public API through py-gitguardian to scan and detect potential vulnerabilities in files and other text content." |

None of the four generic file scanners added in this extension claims AI-agent
transcripts as a named surface; like gitleaks in v1, each is aimed at the
fixture directory explicitly, which its documentation supports, and scored on
every class.

## Recall and precision per class

Site recall = exposure sites found / planted sites. Value recall = distinct credentials
found / planted distinct credentials. "Out of scope" = the tool's own documentation does
not claim that surface, so it is not scored there (never counted as zero). Denominators
for the cross-class rows differ because claimed scope differs.

"Hard class" = commonly missed by line-oriented scanners; the label describes the class,
not an excuse for any tool: gitleaks defeats the base64 class outright by decoding in
place (5/5), whatileaked and Betterleaks decode most of it (4/5 each), TruffleHog and
Kingfisher decode part of it (2/5 each), while residoo, AgentSweep, and detect-secrets
score zero there. Hard classes are reported as their own rows and are excluded from the
headline-classes row; the all-classes row explicitly includes them.

### Secret classes (site recall, with value recall in parentheses where it differs)

Column headers are tool names only; versions are pinned in the Tool versions
table above.

| class | sites | residoo | gitleaks | AgentSweep | whatileaked | TruffleHog | Betterleaks | Kingfisher | detect-secrets |
|---|---|---|---|---|---|---|---|---|---|
| transcript-plain | 24 | 21/24 (88%) | 18/24 (75%) | 22/24 (92%) | 18/24 (75%) | 12/24 (50%) | 18/24 (75%) | 16/24 (67%) | 14/24 (58%) |
| agent-config-plain | 3 | 1/3 (33%) | 3/3 (100%) | out of scope | out of scope | 3/3 (100%) | 3/3 (100%) | 3/3 (100%) | 3/3 (100%) |
| transcript-json-nested | 6 | 5/6 (83%) | 2/6 (33%) | 6/6 (100%) | 2/6 (33%) | 5/6 (83%) | 2/6 (33%) | 3/6 (50%) | 3/6 (50%) |
| transcript-echo | 12 | 12/12 (100%) | 12/12 (100%) | 12/12 (100%) | 5/12 (42%, values 4/4) | 7/12 (58%, values 3/4) | 9/12 (75%, values 3/4) | 9/12 (75%, values 3/4) | 3/12 (25%, values 3/4) |
| transcript-b64 (hard class) | 5 | 0/5 (0%) | 5/5 (100%) | 0/5 (0%) | 4/5 (80%) | 2/5 (40%) | 4/5 (80%) | 2/5 (40%) | 0/5 (0%) |
| transcript-split (hard class) | 6 | 1/6 (17%, values 1/3) | 0/6 (0%) | 1/6 (17%, values 1/3) | 0/6 (0%) | 0/6 (0%) | 0/6 (0%) | 0/6 (0%) | 3/6 (50%, values 3/3) |
| distinct credentials, headline classes only | | 31/37 (84%) | 27/37 (73%) | 32/34 (94%) | 24/34 (71%) | 23/37 (62%) | 26/37 (70%) | 25/37 (68%) | 23/37 (62%) |
| distinct credentials, all claimed classes (hard classes included) | | 32/45 (71%) | 32/45 (71%) | 33/42 (79%) | 28/42 (67%) | 25/45 (56%) | 30/45 (67%) | 27/45 (60%) | 26/45 (58%) |
| re-exposed sites found | 8 | 8/8 | 8/8 | 8/8 | 1/8 | 4/8 | 6/8 | 6/8 | 0/8 |

Reporting-style note on the echo and re-exposure rows: whatileaked reports one
representative file per distinct credential by design, and detect-secrets'
baseline dedupes re-occurrences of the same secret within one file at the
first line, so both can show full value recall with partial site recall; both
levels are always shown, and the all-classes distinct-credentials row guards
dedup-style reporters against value-level undercounting.

detect-secrets' split-class credit (3/6 sites, 3/3 values) deserves its
context: each credited site is its Base64 high-entropy plugin flagging one
half of a split credential at the planted line, credited through the
file+line tier exactly as the matching rules promise. The same plugin is
responsible for its precision row below; the two are one behavior, reported
on both axes.

### Per-family site recall (all claimed secret classes)

So any reader can recompute any class with any family subset, and separate rule-family
coverage from transcript shape. Same data machine-readable in `scoreboard.json`
(`perFamily`).

| family | residoo | gitleaks | AgentSweep | whatileaked | TruffleHog | Betterleaks | Kingfisher | detect-secrets |
|---|---|---|---|---|---|---|---|---|
| aws | 5/8 | 6/8 | 5/8 | 4/8 | 0/8 | 0/8 | 0/8 | 4/8 |
| github | 7/10 | 8/10 | 6/9 | 5/9 | 7/10 | 8/10 | 8/10 | 6/10 |
| anthropic | 7/9 | 6/9 | 7/8 | 4/8 | 6/9 | 6/9 | 6/9 | 2/9 |
| slack | 6/7 | 7/7 | 6/6 | 4/6 | 7/7 | 7/7 | 7/7 | 5/7 |
| stripe | 0/4 | 3/4 | 3/4 | 3/4 | 0/4 | 3/4 | 0/4 | 0/4 |
| npm | 3/4 | 3/4 | 3/4 | 2/4 | 3/4 | 3/4 | 3/4 | 0/4 |
| gitlab | 2/3 | 3/3 | 2/3 | 3/3 | 3/3 | 3/3 | 3/3 | 2/3 |
| connection-string | 3/3 | 0/3 | 3/3 | 0/3 | 3/3 | 2/3 | 2/3 | 3/3 |
| discord | 2/2 | 0/2 | 2/2 | 0/2 | 0/2 | 0/2 | 0/2 | 0/2 |
| bearer-header | 1/2 | 0/2 | 0/2 | 0/2 | 0/2 | 0/2 | 0/2 | 0/2 |
| private-key | 2/2 | 2/2 | 2/2 | 2/2 | 0/2 | 2/2 | 2/2 | 2/2 |
| jwt | 2/2 | 2/2 | 2/2 | 2/2 | 0/2 | 2/2 | 2/2 | 2/2 |

Per-tool denominators differ where a family has sites in a class outside that tool's
claimed scope (the three agent-config sites, one each in github, slack, and anthropic,
are not scored for AgentSweep or whatileaked).

Rows where a probe isolated the mechanism (full probe details in
`tools/VERSIONS.md`; every probe used freshly made fakes or generated-and-discarded
key material, never corpus values in new locations):

- **TruffleHog and Kingfisher aws 0/8 is pair-oriented detector design,
  verified**: a bare AKIA-style key id alone in a probe file was not reported
  by either tool, and the same id was reported once a secret-key-shaped
  string sat nearby. The corpus's aws plants are bare key ids. Betterleaks'
  own `aws-access-token` is the same composite design (per
  `betterleaks config show`); gitleaks 8.30.1 reports bare ids. A bare key
  id is an identifier rather than a usable credential, so pair-oriented
  detection reflects a defensible threat model; pairing a secret-key-shaped
  value at a subset of aws sites is queued for the next corpus version
  (alongside the private-key body fix below), while this run keeps the v1
  plants unchanged for byte-reproducibility and readers can exclude the
  family entirely using the per-family table above.
- **TruffleHog and Kingfisher stripe 0/4 is live-keys-only pattern scope,
  verified**: a probe `sk_live_` fake was reported by both; the corpus's
  `sk_test_` plants were not. Betterleaks 1.8.1 itself reports `sk_test_`
  keys (3/4 here), so Kingfisher's shipped `betterleaks.*` rule variants are
  not byte-identical to Betterleaks' own rules. Treating test-mode keys as
  non-secrets is a defensible threat-model choice; it is reported as recall,
  not corrected for.
- **TruffleHog private-key 0/2 is partly a corpus-fidelity gap, disclosed
  pro-competitor**: probes showed its PrivateKey detector validates key
  STRUCTURE and reports a structurally valid OpenSSH key even inside a
  transcript-shaped JSON line with escaped newlines, while the corpus's
  private-key plants carry random base64 bodies that do not parse as
  openssh-key-v1. By the benchmark's own pattern-true bar (the v1 AWS-base32
  precedent: a scanner must never be penalized for rejecting an impossible
  value) the corpus is at fault here, not the tool. The plants are kept
  unchanged in this run so the v1 numbers stay reproducible, the row is
  published with this disclosure attached, and a structurally valid key body
  is queued for the next corpus version. Marker-matching tools (all seven
  others score 2/2) are unaffected either way.
- **TruffleHog jwt 0/2 is a family-coverage gap, verified**: a structurally
  valid HS256 JWT probe was not reported; 3.97.2 ships no generic JWT
  detector.
- **detect-secrets anthropic 2/9 and npm 0/4**: it ships no Anthropic or npm
  plugin; its two anthropic credits come from entropy/keyword flags landing
  on planted lines.

### What the family mix does and does not explain (the strongest counter-argument, answered)

The transcript-plain ordering between residoo and gitleaks/whatileaked is family
coverage, not transcript shape. All 6 of gitleaks' and whatileaked's transcript-plain
misses fall in exactly the three families they ship no rules for at all:
connection-string (2 sites), discord-webhook (2), bearer-header (2). Restricted to the
nine families all four v1 tools have rules for, transcript-plain becomes gitleaks 18/18
(100%) versus residoo 16/18, and residoo's plain-class edge disappears.

The same decomposition holds perfectly for all four added tools: on
transcript-plain every one of them scores either 2/2 or 0/2 in every family,
i.e. their plain-class misses are entirely families their rules do not cover
in this corpus's shapes (TruffleHog: aws, stripe, private-key, jwt, discord,
bearer-header; Betterleaks: aws, discord, bearer-header; Kingfisher: aws,
stripe, discord, bearer-header; detect-secrets: anthropic, npm, stripe,
discord, bearer-header), with zero shape failures inside a covered family on
the plain class. The transcript-shape claim rests on the classes where shape
is the variable: json-nested (residoo 5/6, AgentSweep 6/6, and TruffleHog 5/6
versus gitleaks and Betterleaks 2/6, with the keyword-adjacency mechanism
reproduced in isolation in v1), the echo class (Betterleaks and Kingfisher
drop the aws echo sites their composite rule cannot see), and the split
class.

TruffleHog's json-nested 5/6 is worth naming: it is the only generic file
scanner in the field that parses through JSON-in-JSON escaping about as well
as the transcript-native tools, consistent with its "chats, wikis, logs"
self-description.

Why the uncovered families are planted anyway: DB connection strings and bearer
Authorization headers in verbose curl or tool output are among the most
transcript-typical leak shapes there are; the Discord webhook is the weakest inclusion
and is named as such. And the mix demonstrably was not tuned to residoo's rule list:
residoo goes 0-for-4 on the stripe family across every class it appears in, AgentSweep
beats residoo on both transcript-plain and json-nested, and gitleaks ties residoo on
the all-classes distinct-credentials row.

### False positives and precision

Precision is published twice because whether flagging a vendor-documented example value
(the suppress class) is a false positive is a philosophy reasonable people weigh
differently; the benchmark's design-order disclosure on this class is in
`bench/README.md`, fairness rule 10.

| metric | residoo | gitleaks | AgentSweep | whatileaked | TruffleHog | Betterleaks | Kingfisher | detect-secrets |
|---|---|---|---|---|---|---|---|---|
| chaff flagged (of 45) | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 44 |
| suppress/placeholder flagged (of 10) | 3 | 0 | 5 | 0 | 0 | 2 | 1 | 5 |
| findings matching nothing planted | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 1645 |
| precision (matched sites / matched + all FP) | 93% | 100% | 89% | 100% | 100% | 95% | 97% | 2% |
| precision excluding suppress FP | 100% | 100% | 100% | 100% | 100% | 100% | 100% | 2% |

detect-secrets' precision row, hand-verified rather than taken on faith: of
its 3,660 findings, 3,634 come from one plugin (`Base64HighEntropyString`)
firing on transcript-structural identifiers (message ids, request ids,
session UUIDs) on nearly every line of every session file; sampled flagged
lines contain exactly such identifiers and no planted value. All 26 of its
matched secret sites come from its structured plugins (GitHub, Slack, AWS,
Basic Auth, GitLab, Private Key, JWT, Keyword). This is the honest result of
pointing its documented default plugin set at a transcript tree: agent
transcripts are pathological input for entropy heuristics tuned on source
code. Nothing was tuned away, exactly as the fairness rules require.

Suppress-class detail (which placeholders got flagged): detect-secrets flags
the AWS documented example key `AKIAIOSFODNN7EXAMPLE` itself, plus
`ghp_xxxx...`, a placeholder DB URL, a placeholder bearer header, and
`changeme` (it ships no example-value allowlist, confirmed in
`tools/VERSIONS.md`); Betterleaks flags the placeholder DB URL and
`changeme` (its EXAMPLE allowlist covers the aws rule, not those);
Kingfisher flags the npm placeholder; TruffleHog flags none of the ten.

ggshield: recall **not scored (requires server account)**, never zero. Observed
unauthenticated: exit 3, "Error: A GitGuardian API key is needed to use ggshield."
before any scanning (verbatim in `results/raw/ggshield.txt`).

## residoo 0.3.1: post-publication fixes, rerun on the same corpus (added 2026-09-02)

Order of events, because it is the whole credibility argument: the benchmark
and every 0.3.0 number above were published first (commits 16c911f and
18df770), and residoo was improved second, in public, against the classes the
benchmark showed it losing. One dated exception, on the record because a
`git log --all` shows it anyway: the vendor-example suppression layer
(commit 4fc76f0) was written alongside the benchmark, before v1 was
committed; every other 0.3.1 mechanism postdates publication. The 0.3.1 code
this rerun measures is commits e382476, cc19835, 4fc76f0, 1f8e921, and
9e64f6f (the last being post-review hardening: a greedy-extension guard on
the boundary join, per-line crash containment, and base64 candidate
splitting at padding), pinned here the way the 0.3.0 run was pinned to
16c911f. The 0.3.0 rows throughout this document are retained unchanged;
this section is the new measurement. Every fix is a general mechanism whose
design and limits are documented in the source, none is keyed to this
corpus's generator, and none reads planted values:

- base64 decode-then-rescan (`src/decode.js`): locate base64/base64url runs
  per line, wrap-break tolerant (RFC 2045 style wrapping, including wrap
  newlines serialized as JSON escapes), decode bounded candidates, rescan the
  decoded text with the vendor-prefixed high-confidence rules only, redact
  the decoded value. Limits stated in code: one decode level, no blocks
  spanning physical lines, no hex.
- split-line boundary join (`src/decode.js`): project each line to its
  free-text payload (the longest JSON string value, a schema-agnostic
  property of message-wrapping records), join tail and head windows of
  adjacent lines, credit only matches that straddle the seam, and drop a
  straddling match that merely extends a complete match ending flush at the
  seam (the greedy-extension guard: without it, any open-ended rule
  fabricates token-plus-neighbor chimera values on real transcripts, which
  is exactly what the first real-machine run of the unguarded join did).
  Limits stated in code: two-way splits only, longest-string assumption,
  and a split whose first fragment is by itself a complete match of the
  same rule is reported as that fragment rather than reconstructed.
- Stripe test-mode keys as their own rule (`src/patterns.js`), with the
  vendor citations (gitleaks and Stripe's own docs treat `sk_test_` as
  reportable; TruffleHog's live-only scope is quoted as a scope choice).
- Project-level agent configs discovered from the agent's own home-level
  records (`src/sources/agent-configs.js`): project roots come from
  `~/.claude.json` and transcript `cwd` fields, re-rooted under the current
  home when recorded under a foreign one; only vendor-fixed per-project
  config filenames are read.
- Suppression generalized (`src/scan.js`): vendor-documented example
  literals by exact match (now including Stripe's two published sample test
  keys, verified against Stripe's own docs and repositories), plus a
  zero-entropy check (a value ending in a run of 12+ identical characters
  is no vendor's key material); both are value properties and therefore
  apply identically to raw, decoded, and boundary-joined findings.

The rerun regenerated the corpus (byte-identical by-family summary),
re-passed the egress positive control, and re-ran all 12 monitored
invocations. Every other tool's recall and precision rows reproduced their
published numbers cell for cell, which is the determinism claim
demonstrated again; their tables above are simultaneously the retained
originals and the fresh rerun. (Single-run wall times and TruffleHog's
default-mode verification attempt count, 50, 48, and 50 across this day's
three windows, vary run to run and are labeled as indicative wherever
they appear.) residoo 0.3.1, same harness, same rules of scoring:

| class | sites | residoo 0.3.0 (retained above) | residoo 0.3.1 | best other tool |
|---|---|---|---|---|
| transcript-plain | 24 | 21/24 (88%) | **23/24 (96%)** | 22/24 AgentSweep |
| agent-config-plain | 3 | 1/3 (33%) | **3/3 (100%)** | 3/3 (five tools) |
| transcript-json-nested | 6 | 5/6 (83%) | **6/6 (100%)** | 6/6 AgentSweep |
| transcript-echo | 12 | 12/12 (100%) | **12/12 (100%)** | 12/12 gitleaks, AgentSweep |
| transcript-b64 (hard class) | 5 | 0/5 (0%) | **5/5 (100%)** | 5/5 gitleaks |
| transcript-split (hard class) | 6 | 1/6 (17%) | **5/6 (83%, values 3/3)** | 3/6 detect-secrets |
| distinct credentials, headline classes only | | 31/37 (84%) | **36/37 (97%)** | 32/34 (94%) AgentSweep |
| distinct credentials, all claimed classes | | 32/45 (71%) | **44/45 (98%)** | 33/42 (79%) AgentSweep |
| suppress/placeholder flagged (of 10) | | 3 | **0** | 0 (gitleaks, whatileaked, TruffleHog) |
| chaff flagged (of 45) | | 0 | **0** | |
| findings matching nothing planted | | 0 | **0** | |
| precision including suppress FP | | 93% | **100%** | |

The one remaining distinct-credential miss is the same bearer-header site
0.3.0 missed (per-family bearer-header 1/2): an Authorization-header shape
residoo's bearer rule does not cover. It is left on the table, named,
rather than patched by a corpus-shaped rule, which is exactly the line this
section is drawing. The split row's 5/6 is the greedy-extension guard's
stated cost paid in the open: one split site's first fragment is by itself
a complete match of its rule, so the raw pass reports the fragment on its
own line and the guard refuses the straddle (the value is still found and
counted; the second exposure site is not credited). The guard is kept
because its absence is far worse than one uncredited site, per the next
paragraph. Wall time in this rerun's window: residoo 0.3.1 at 0.41s, in
the same band as gitleaks (0.59s) and Betterleaks (0.58s) under the same
load; not comparable to the 21-second window's absolute times above.
Egress: none-observed, both layers armed, positive control re-passed first.

Three more things the corpus could not have taught, all met on real
machines and none visible in a 45/45-style score: (1) the first
real-machine run of the merged 0.3.1 engine crashed on a 7MB single
transcript line (V8's regex backtrack stack overflows even on a plain
character-class quantifier at that scale), so the base64 candidate finder
shipped as a hand-rolled single-pass character scan instead of a regex;
(2) the unguarded boundary join scored 6/6 on this corpus's split class
while fabricating 32 chimera findings (complete tokens greedily extended
into the next line's text) on the first real machine it touched; the
greedy-extension guard above exists because review caught that on real
data, and this rerun's 5/6 is the honest post-guard number; (3) the same
backtrack overflow lives in rule regexes themselves when a vendor prefix
precedes a multi-megabyte same-charset run, so one unmatched line now
degrades to a visible per-file flag instead of aborting the scan and
discarding every finding already collected. A fix tuned to the corpus
would never have met any of the three.

Same-day addendum, v0.3.2 (commit a7a5608): the first full-machine scan
after tagging v0.3.1 added a fourth lesson of the same kind. v0.3.1
bounded base64 decode candidates at 256 per line and flagged lines past
the bound as partially checked; on 1.2 GB of real transcripts that flag
fired on 96 of 102 files, because real transcript lines routinely carry
hundreds of decode-sized alnum runs (uuids, hashes, request ids), and the
same bound had been silently skipping any genuine blob sitting past it.
v0.3.2 removes the cap outright: per-line decode work is linear in line
length with or without one (each character belongs to at most one
candidate), so the cap bought nothing and cost either silence or noise.
The full benchmark was then re-run a third time on v0.3.2: every residoo
row in the table above and every other tool's scored rows reproduced
exactly (the committed scoreboard files are that third run, labeled
0.3.2), so the table stands for both versions. npm latest is 0.3.2.

## Corpus v1.1.0: two disclosed fidelity gaps closed (2026-09-03)

Two corpus limitations disclosed earlier in this document ("residoo's own
weaknesses" and the TruffleHog private-key note above) were filed as
public issues (#10, #11) and closed by fixing the corpus generator itself,
not any scanner:

- **Private-key plants now use a real, structurally-valid (but never used)
  OpenSSH key body**, generated once with `ssh-keygen`, instead of random
  base64. The random body was shape-true (right marker, right line width)
  but did not decode as `openssh-key-v1`, which is exactly what
  TruffleHog's PrivateKey detector validates: a corpus-fidelity gap, not
  a TruffleHog miss, per the disclosure earlier in this document. Two
  distinct fixed keys are used (one per plant site), cycled by call order,
  so the family's two sites keep the same "each planted value is unique"
  property every other family already has.
- **A subset of AWS access-key-id plants (2 of 8) are now paired with a
  nearby secret access key**, matching how a real leaked env dump looks.
  TruffleHog, Kingfisher, and Betterleaks all scored 0/8 on this family
  because their AWS detectors are pair-oriented by design (probe-verified
  earlier in this document: a bare id alone is not reported; the same id
  IS reported once a secret sits nearby): a defensible threat model the
  corpus never tested. residoo's own `pairing.js` mechanism was equally
  untested by this family. The other 6 AWS sites stay bare-id-only, so the
  "id alone" case is still covered.

Both fixes keep the corpus's determinism invariant (same SEED, generator
code changed intentionally, corpus version bumped 1.0.0 → 1.1.0, exactly
what that version constant exists for). The full 12-invocation reproduce
sequence was re-run (all 8 scored tools, 3 dual-mode egress observations,
the ggshield refusal), confirming the egress positive control first.

Outcomes, closing exactly the two disclosed gaps and nothing else assumed:

| family | before | after |
|---|---|---|
| TruffleHog private-key | 0/2 | **2/2** |
| TruffleHog aws | 0/8 | **2/8** |
| Betterleaks aws | 0/8 | **2/8** |
| Kingfisher aws | 0/8 | **2/8** |
| detect-secrets aws | 4/8 | **5/8** |
| residoo aws / private-key | 8/8 / 2/2 (already full) | unchanged |

residoo's own row is unaffected end to end: still 45/45 (100%) distinct
credentials across all claimed classes, 100% precision, none-observed
egress. The two fixed gaps were never residoo's own weakness, and the
new AWS pairing site was confirmed detected by residoo's own scan before
the full rerun (`node bin/residoo.js scan --project bench/corpus/data`
against the regenerated fixture, `pairedSecretPreview` present on both
sites).

**Disclosed honestly, not hidden**: regenerating the corpus reshuffles
every value downstream of the two changed factories, since all randomness
in the generator flows through one sequential seeded stream (stated in
`bench/corpus/generate.js`'s own header): a corpus-VERSION change, like
any other code change, is not expected to hold every unrelated byte fixed,
only to be deterministic FROM that version's code and seed. Two visible,
checked, and explained side effects:
- Total chaff instance count moved 45 → 44 (a downstream random count
  decision shifted with the reshuffled stream; not a chaff-generation
  logic change).
- detect-secrets' `transcript-split` value recall moved 3/3 → 2/3 for a
  documented reason already disclosed above in this file: its split-class
  credit comes from an entropy heuristic (`Base64HighEntropyString`)
  sensitive to the exact random bytes at that site, which are now
  different (still pattern-true, just different). TruffleHog's precision
  moved 100% → 97% (1 new unplanted finding); checked directly against
  both new AWS pair sites specifically, neither produced an extra
  TruffleHog finding, and traced instead to an `NpmToken` finding on an
  unrelated file, the same reshuffling effect on a different family's
  now-different random content, not a consequence of the AWS or
  private-key fixes.

Every other row for every other tool reproduced unchanged.

## residoo 0.7.2: a false-positive bug in the boundary-join guard itself, found by adversarially stress-testing this benchmark's own claim (added 2026-09-03)

The 0.3.1 section above documents the split-line boundary join and its
greedy-extension guard: without that guard, "any open-ended rule
fabricates token-plus-neighbor chimera values on real transcripts, which
is exactly what the first real-machine run of the unguarded join did."
That guard only recognizes one shape of false positive: a straddling
match that merely extends a complete match already sitting flush at the
seam. Stress-testing this benchmark's own 100%-precision claim against
documented false-positive patterns from gitleaks' and TruffleHog's own
issue trackers (not hypothetical inputs) found a second, narrower shape
the original guard does not cover: a **near-miss**, sitting one or more
characters short of a variable-length rule's own minimum at a line's
end, is not a complete match, so the guard never sees it. If the very
next line's content happens to start with even a few more characters the
rule's class allows, the straddle pass stitches two unrelated, benign
lines into a fabricated value that exists in neither. Reproduced
concretely: a line ending in a bearer-shaped placeholder
(`Authorization: Bearer YOUR_TOKEN_HERE`, 14 characters past `Bearer `,
two short of `bearer_header`'s `{16,1000}` minimum) followed by an
unrelated line starting with `' https://api.example.com`, whose leading
apostrophe and space alone push the straddle over the 16-character floor
and get reported as a bearer token that was never typed by either line.

Fix (`src/decode.js`): `BOUNDARY_MIN_CONTRIBUTION = 4`, a floor on how
many characters EACH side of the seam must contribute to a straddling
match before it is trusted as a genuine split rather than coincidence,
applied symmetrically alongside the existing greedy-extension guard, not
in place of it. Two regression tests added to `tests/smoke.js`: the near
miss above is confirmed NOT fabricated into a finding, and a genuine
cross-line split with a real contribution on each side (a 41-character
token cut 10 characters from its start, comfortably clear of the new
floor) is confirmed still correctly reconstructed. Limit stated in code:
a legitimate chunked-streaming split landing with fewer than 4 characters
on one side, while possible, is far rarer than the coincidental-
concatenation failure mode this closes, and such a fragment is still
caught by the raw single-line pass once enough of it lands on either side
to satisfy the rule outright.

The full 12-invocation reproduce sequence was rerun on a freshly
regenerated corpus (same determinism guarantee as every section above:
72 session files, 55 plant sites, 44 chaff, byte-identical family
counts). residoo's own row is unaffected end to end: still 45/45 (100%)
distinct credentials across all claimed classes, 100% precision (0
chaff/suppress/unplanted false positives), none-observed egress, and the
pre-existing, already-disclosed `transcript-split` 5/6 (83%) gap
(unrelated to this fix, present unchanged since 0.3.1 and confirmed via
`git diff`/`git show` against the previously committed scoreboard) is
exactly where it was. Every other tool's row reproduced unchanged.
Nothing in this fix trades recall for precision; it closes a fabrication
path the benchmark's own methodology exists to catch, the same way the
0.3.1 guard it extends was found the same way.

## residoo 0.8.0: two new capabilities, zero scan-path behavior change by construction (added 2026-09-04)

This release adds `residoo_verify_finding` (a narrowly-scoped MCP tool that
asks a credential's own vendor, live, whether it is still active, one
credential per call) and `residoo guard` (a Claude Code `PreToolUse` hook
that blocks an obviously-sensitive file read before it happens). Included
here only because the first of those two required a small change to
`src/scan.js` itself: a new optional `verifyOnlyFingerprint` parameter that
scopes an existing `verify: true` pass to one specific finding instead of
every eligible credential on the machine, so an MCP tool call asking about
one fingerprint can never trigger a live network check against unrelated
credentials it was never asked about.

This parameter defaults to `null`, and every one of the four places
`scan.js` decides whether to queue a credential for a real verification
call was changed from `if (verify && ...)` to `if (verify && matchesTarget
&& ...)`, where `matchesTarget` is `!verifyOnlyFingerprint || ...` --
unconditionally `true` whenever the parameter is absent. Neither the CLI
nor the benchmark harness ever passes it, so the scan path this benchmark
measures is unreachable by this change: not "believed unaffected," but
structurally incapable of taking a different branch. The full 12-invocation
reproduce sequence was still run rather than trusting that reasoning alone,
on a freshly regenerated corpus (same 72 files, 55 plants, 44 chaff as
every prior run): residoo's own table is byte-identical to 0.7.2's, still
45/45 (100%) distinct credentials, 100% precision, none-observed egress.
Every other tool's row reproduced unchanged. `residoo guard` touches no
file this benchmark scores at all -- it is a separate hook binary path,
not part of `scan()`.

## residoo 0.8.2: one detection gap closed by reading a competitor's own issue tracker (added 2026-09-04)

Cross-checking agentsweep's open GitHub issues (a direct competitor, not
a hypothetical exercise) found three tracked issues for Cloudflare's
current credential prefixes: `cfat_` and `cfut_`, which residoo's
`cloudflare_api_token` rule already covered, and `cfk_` (the Global API
Key -- full account access, arguably the most dangerous of the three),
which it did not. Verified directly against Cloudflare's own docs
(developers.cloudflare.com/fundamentals/api/get-started/token-formats,
which describes all three with the identical `<prefix>_[40 characters]
[checksum]` shape) before writing the fix, not assumed from the issue
text alone. `src/patterns.js`'s regex extended from `cf[au]t_` to
`cf(?:[au]t|k)_`; three new matching tests added (one per prefix,
confirming each matches only `cloudflare_api_token` and no other rule).

This corpus has no planted Cloudflare-family site (its planted families
are anthropic/stripe/aws/slack/bearer/github/gitlab/connection-string/
generic-password/npm/discord/private-key/jwt), so the full reproduce
sequence -- still run rather than skipped, corpus regenerated, same
72/55/44 counts -- confirms no regression rather than a new win: residoo
stays 45/45 (100%), 100% precision, none-observed egress, byte-identical
to 0.8.1 except the version label. Every other tool's row reproduced
unchanged. A Cloudflare-family corpus addition (covering all three
prefixes) is a natural next corpus update, not done here to keep this
change scoped to the one real gap found.

## residoo 0.8.3: two more vendors closed the same way (added 2026-09-04)

Continuing the same cross-check against agentsweep's open issues: LangSmith
(`lsv2_pt_`/`lsv2_sk_`) and Resend (`re_`) API keys, both entirely missing
from residoo before this release. Neither vendor publishes an exact-length
spec for its key format (checked LangSmith's own docs directly, and
Resend's -- neither states one), so both rules use a generously-bounded
length rather than a doc-confirmed exact count, stated plainly in
`src/patterns.js`'s own comments rather than presented as more certain
than it is. Resend's short, otherwise-generic `re_` prefix was tested
against realistic `re_`-prefixed code identifiers (`re_try`, `re_send`,
`re_connect`, `re_validate`...) before being trusted as a DEFAULT
(non-noisy) rule -- none match, since none have the second underscore-
delimited high-entropy segment a real key has.

Same corpus-coverage caveat as 0.8.2: no LangSmith- or Resend-family
plant exists in this corpus yet, so the full reproduce sequence (still
run, corpus regenerated, same 72/55/44 counts) confirms no regression,
not a new win: residoo stays 45/45 (100%), 100% precision, none-observed
egress, byte-identical to 0.8.2 except the version label. Every other
tool's row reproduced unchanged.

## residoo 0.8.4: one new source, one more vendor, plus reading TruffleHog's and Snyk's own trackers (added 2026-09-04)

Continued the competitor cross-check, this time against TruffleHog's and
Snyk's own public issue trackers rather than agentsweep's. Findings:

- **Stripe webhook signing secret** (`whsec_`) -- TruffleHog has two open,
  unaddressed issues for this (#4711, #4609); gitleaks doesn't have it
  either (checked `gitleaks.toml` directly). A real, disclosed, industry-
  wide gap, not unique to residoo. No exact-length spec exists anywhere
  found, shipped anyway on the strength of the `whsec_` prefix alone,
  which carries negligible false-positive risk regardless of the exact
  bound chosen -- unlike a short/generic prefix, where that same
  generosity would matter.
- **Weights & Biases** was investigated and NOT added: its classic key
  format is a bare, unprefixed 40-character string (confirmed via a real
  W&B GitHub issue), exactly the generic, unsafe-as-a-default-rule shape
  this project's own header comment already says to leave out (same
  reasoning as the existing Together AI/DeepSeek exclusions). The newer
  `wandb_v1_`-prefixed format cited in TruffleHog's own open feature
  request isn't independently confirmed by any primary source, so it
  wasn't guessed at either.
- **Atlassian Rovo Dev CLI** added as a new source
  (`src/sources/atlassian-rovo-dev.js`), moving the total from 43 to 44.
  Grounded in Atlassian's own support docs (session storage path and the
  two per-session filenames), with the per-session-subdirectory layout
  stated plainly as an inference from those docs, not a confirmed
  structure -- no real install exists to check it against.
- **Sourcegraph Amp investigated and NOT added**: its own docs describe
  threads syncing to ampcode.com "across devices," with no documented
  local cache -- the same cloud-only reasoning as the existing Augment
  Code/CodeGPT exclusions.
- Snyk's own trackers (`snyk/cli`'s issues are disabled entirely;
  `snyk-code-extension-secrets` has exactly one open issue) had nothing
  actionable. Snyk's real, current AI-agent-security product
  (`snyk/agent-scan`) scans agent skill files and MCP configs, not
  session transcripts -- confirms residoo's niche remains unclaimed by
  either competitor checked tonight.

Pattern rule count moved 52 to 53 (`stripe_webhook_secret`, `cfk_`
extended an existing rule rather than adding one). Full reproduce
sequence run (this corpus has no Stripe-webhook-secret-family plant, and
Atlassian Rovo Dev CLI is a source addition a synthetic transcript corpus
can't exercise the same way a pattern rule can): residoo stays 45/45
(100%), 100% precision, none-observed egress, byte-identical to 0.8.3
except the version label. Every other tool's row reproduced unchanged.

## residoo 0.8.5: a gitleaks feature request checked against residoo's own installed binary, and found wrong (added 2026-09-04)

The most interesting fix in this release didn't come from research alone.
gitleaks/gitleaks#2094 requests a rule for Claude Code's Remote Control
session URLs -- a real, high-impact target: Anthropic's own docs
(code.claude.com/docs/en/remote-control) confirm this URL is a bearer
credential (opening it grants full read/write/execute access to a live
session, no further auth) AND that Claude Code "posts the session URL in
the conversation" -- i.e. it genuinely lands in the exact transcripts this
project scans, not a hypothetical. The issue's own proposed pattern
(`claude.ai/code/session_<id>`) is explicitly hedged as "illustrative."

Rather than ship that guess, it was checked against this machine's own
installed `claude` binary directly (`strings /usr/local/bin/claude`,
read-only inspection of locally-installed software, the same kind of
plain-text-string check any diagnostic tool performs). Two things came
back straight from the shipped binary's own strings, not inferred: the
literal URL template is `` `/code/${sessionId}` `` -- no `session_`
prefix at all -- and `sessionId:mqH.randomUUID()` confirms the ID is a
standard UUID v4. The gitleaks issue's proposed pattern would have missed
every real instance of this URL. Shipped as `claude_code_remote_control_url`,
anchored on the confirmed template and ID shape.

Two more vendor rules closed the same cross-check session, this time
against gitleaks' own tracker specifically:

- **Azure AD (Entra ID) client secret** (gitleaks/gitleaks#1687) --
  gitleaks already has this rule in its own `gitleaks.toml`
  (`azure-ad-client-secret`), so it was adapted directly from that
  battle-tested pattern (anchored on the token's distinctive `Q~` marker)
  rather than designed from scratch. Azure Storage Account keys were
  investigated and NOT added: they're a bare, unprefixed ~88-char base64
  blob, the same unsafe generic shape already excluded for Weights &
  Biases' classic key format.
- **Tailscale auth key** (gitleaks/gitleaks#1778, still open there too)
  -- no single authoritative current spec found (Tailscale's own docs
  show an older bare `tskey-<hex>` example; recent real-world usage
  consistently shows a newer `tskey-auth-<id>-<secret>` form), covered
  on the strength of the `tskey-` prefix alone, same reasoning as
  `whsec_` in 0.8.4.

GCP Service Account keys were investigated and found to need no new rule
at all: the existing `private_key_block` rule already matches the real
PEM-formatted private key material inside a leaked service-account JSON
file (confirmed directly -- a synthetic service-account JSON was
constructed and scanned), even embedded in a single JSON-escaped line. A
dedicated rule would only improve labeling, not add real coverage, and
wasn't judged worth the added complexity tonight.

Pattern rule count moved 53 to 56. Full reproduce sequence run (none of
these three families has a corpus plant yet): residoo stays 45/45 (100%),
100% precision, none-observed egress, byte-identical to 0.8.4 except the
version label. Every other tool's row reproduced unchanged.

Monitored per scan, spawn to exit, by two dynamic layers: a refuse-and-log proxy trap
(all proxy env pinned to it) and lsof polling of the scanner's own process tree at
~150ms. Cadence honesty: ~150ms is the sleep between poll ticks, and each tick shells
out to ps and then lsof, so the effective resolution degrades under machine load (a
heavily loaded window earlier on this benchmark day measured one tick at more than
800ms; this run's window carried moderate load). A socket opened and closed inside
one tick can be missed by this layer, as the known-limits note in
`harness/README.md` states. That gap matters only for a client that ignores proxy
environment variables, and the tools with network behavior at issue here
demonstrably honor it: the three dual-mode default runs routed all 94 of their
observed CONNECT attempts through the gap-free trap layer with zero non-proxy
sockets, so the trap covered exactly the binaries whose egress needed observing.
Positive control: `harness/selftest-egress.js`, run before the benchmark,
recorded a deliberate canary connection on both layers ("CONNECT
egress-selftest.invalid:443" on the trap; a live socket in the lsof poll), so a clean
verdict below is falsifiable evidence, not silence; its transcript is persisted at
`results/raw/selftest-egress.txt`. Install-time package fetches happen before any
monitored run and are not scored. Update-check behavior is reported symmetrically for
every tool that has any.

The dual-mode rule (`bench/README.md`, fairness rule 9), applied to TruffleHog,
Kingfisher, and detect-secrets: each has a default mode that verifies candidate
secrets against provider APIs during the scan, and documents an offline switch
(`--no-verification`, `--no-validate`, `-n` respectively). Recall is scored only
in the documented offline mode, so the recall axis is never conflated with the
egress axis. Each such tool then gets TWO egress rows below: the offline
(scored) run, which must show none-observed, and the default-mode run, executed
against the same corpus under the same monitor, whose observed connection
attempts and destinations are reported factually next to the vendor's own
documentation of verification. Verification is a documented feature of these
tools; the rows describe what was observed and what their docs say, nothing
more. Fake values only: every planted credential is a pattern-true fake no
provider ever issued, so a default-mode verification attempt sends only fake
values at worst, and the refuse-and-log proxy trap refuses the connections
anyway, so no verification request can leave the machine.

| tool | verdict | evidence |
|---|---|---|
| residoo | none-observed | 0 trap attempts, 0 non-trap sockets |
| gitleaks | none-observed | 0 trap attempts, 0 non-trap sockets |
| AgentSweep | none-observed | 0 trap attempts, 0 non-trap sockets. Update-check behavior: on an interactive TTY without `--json`, agentsweep 0.1.9 fires a background pypi.org version check (verified in its source); the benchmarked `--json` piped invocation skips it, the harness additionally sets its documented `AGENTSWEEP_NO_UPDATE=1` off-switch, and none was observed. |
| whatileaked | none-observed | 0 trap attempts, 0 non-trap sockets |
| TruffleHog, offline mode (`--no-verification --no-update`, scored) | none-observed | 0 trap attempts, 0 non-trap sockets |
| TruffleHog, default mode (verification enabled, egress observation only) | attempted | 50 proxy CONNECT attempts, 0 non-trap sockets. Destinations: api.github.com:443 (15), slack.com:443 (12), api.anthropic.com:443 (10), gitlab.com:443 (6), registry.npmjs.org:443 (6), oss.trufflehog.org:443 (1, its startup update check; `--no-update` is the documented off-switch the scored run uses). Its README documents the behavior: "For every potential credential that is detected, we've painstakingly implemented programmatic verification against the API that we think it belongs to."; the offline flag is its own `--no-verification` ("Don't verify the results."). |
| Betterleaks | none-observed | 0 trap attempts, 0 non-trap sockets. Not dual-mode: validation is opt-in via `--validation` per its own help and is never passed (scan-only rule), so the scored run IS its default mode. No update check observed in any run. |
| Kingfisher, offline mode (`--no-validate --no-update-check`, scored) | none-observed | 0 trap attempts, 0 non-trap sockets; its own scan summary reports `update_check: disabled` and validations ok/fail/skip 0/0/3 (zero attempted; both modes' summaries report 3 skips) |
| Kingfisher, default mode (validation enabled, egress observation only) | attempted | 22 proxy CONNECT attempts, 0 non-trap sockets. Destinations: registry.npmjs.org:443 (8), api.github.com:443 (7, shared by its release update check and GitHub credential validation), api.anthropic.com:443 (4), gitlab.com:443 (3). Its own scan summary for this run reports `update_check: failed` and validations ok/fail/skip 0/7/3 (all refused by the trap). Its README documents the behavior: "Validate discovered credentials against provider APIs to reduce false positives"; the offline flag is its own `--no-validate` ("Disable secret validation"). |
| detect-secrets, offline mode (`-n`, scored) | none-observed | 0 trap attempts, 0 non-trap sockets |
| detect-secrets, default mode (verification enabled, egress observation only) | attempted | 22 proxy CONNECT attempts, 0 non-trap sockets. Destinations: slack.com:443 (19), sts.amazonaws.com:443 (3). Its own CLI help documents the behavior and the off-switch: "-n, --no-verify  Disables additional verification of secrets via network call."; the verifying plugins in the installed 1.5.0 name their endpoints in source (sts.amazonaws.com, slack.com, api.stripe.com, api.telegram.org, api.mailchimp.com, api.softlayer.com, iam.cloud.ibm.com). Only the aws and slack plugins had candidate findings to verify on this corpus. |
| ggshield | by-design-requires-server | Refused to scan without a GitGuardian API key (exit 3, live). **Observed during the scan window: one proxy CONNECT attempt to api.github.com:443** (update-check behavior: its version self-check, `ggshield/core/check_updates.py` in the installed package; caught and refused by the trap; no corpus content was sent since the scan never began). By-design citation: ggshield's own README, describing the invoked `secret scan` command: "ggshield uses our public API through py-gitguardian to scan and detect potential vulnerabilities in files and other text content." For the AI-agent surface specifically, its v1.53.0 changelog on `ai discover --activity`: it collects raw agent activity and "ships it to GitGuardian, which scans the content and strips secrets server-side". Nuance: `--instance` supports self-hosted servers, so "requires a server" need not mean GitGuardian's cloud. |

### Scanner writes (fixture integrity)

The runner diffs the scanned fixture against a pre-scan snapshot after every run, and
redirects tool cache/state (XDG) to a per-run scratch directory outside the fixture.
This run: zero fixture mutations by any tool across all 12 monitored runs; ggshield
wrote one file into its scratch cache (`cache/ggshield/update_check.yaml`, its
update-check timestamp, recorded in `results/raw/ggshield.txt` and then removed with
the scratch). Two write hazards were neutralized by the tools' own documented flags
BEFORE the scored runs, verified and recorded in `tools/VERSIONS.md`: Kingfisher's
compiled rule cache defaults to `Library/Caches/kingfisher/` under HOME (inside the
pinned fixture; `--no-rule-cache` is passed in both modes), and Betterleaks' default
re2-wasm engine writes `Library/Caches/com.github.wasilibs/` under HOME with no
redirecting flag or env var (`--regex-engine stdlib` is used instead, after verifying
an identical finding set on this corpus). macOS cache resolution ignores the
XDG_CACHE_HOME scratch pin for both, which is why the flags are load-bearing.

## Wall time (full corpus, single run each, N=1, indicative only)

Captured under moderate ambient load in the same 21-second window as every other
number in this document; absolute numbers are single-run and indicative only, and
not comparable to times published from other windows. Every tool ran under roughly
the same conditions, so the ordering is meaningful within this table.

| tool | wall |
|---|---|
| residoo | 0.2 s |
| ggshield | 0.3 s (auth refusal, no scan performed) |
| whatileaked | 0.4 s |
| Betterleaks | 0.5 s (stdlib regex engine; its default re2 engine writes a cache under HOME, see Scanner writes) |
| gitleaks | 0.6 s |
| AgentSweep | 0.6 s |
| TruffleHog (offline mode) | 1.1 s |
| detect-secrets (offline mode) | 2.9 s |
| Kingfisher (offline mode) | 3.7 s (includes rule compilation every run, the honest cost of `--no-rule-cache`) |

Dual-mode tools are timed in their scored offline mode; a default-mode egress
observation's wall time is not comparable (it includes refused verification
attempts) and is reported in its raw record instead.

## Notable observations, verified against raw output

- **The v1 four reproduced exactly.** After regenerating the corpus from seed and
  rerunning residoo, gitleaks, AgentSweep, and whatileaked, every recall, precision,
  and per-family number matches the published v1 tables cell for cell. Determinism is
  demonstrated in this run's raw records, not just claimed.
- **gitleaks decodes base64 in place** (8.30.1): 5/5 on the base64 class, unchanged
  from v1 (see v1 notes for the truncated-npm-decode detail). Betterleaks keeps most
  of that ability (4/5); TruffleHog's BASE64 decoder and Kingfisher recover 2/5 each,
  with TruffleHog's decoded findings carrying the decoded value in `Raw` and matching
  at the exact-value tier.
- **gitleaks' keyword-gated rules break on transcript-shaped nesting** (v1 finding,
  reproduced): prefix-identifiable rules match inside JSON-in-JSON escaped strings,
  keyword-adjacency rules fail there. Betterleaks inherits the same 2/6 nested
  behavior. TruffleHog is the standout generic scanner on that class (5/6).
- **Betterleaks lands where a gitleaks successor should**, which is the sanity bar the
  extension demanded: identical transcript-plain (18/24), identical nested (2/6),
  near-identical base64 (4/5 vs 5/5), and the whole aws gap (0/8 vs 6/8) plus the echo
  difference (9/12 vs 12/12, exactly the three aws echo sites) explained by its
  composite aws-access-token rule requiring a nearby secret key (per
  `betterleaks config show`), offset by `generic-credential-uri` wins on
  connection-string (2/3) where gitleaks scores 0/3.
- **Kingfisher loads Betterleaks' rule namespace but not its exact rules**: its
  `betterleaks.stripe-access-token` variant matches live-mode keys only
  (probe-verified) while Betterleaks 1.8.1 itself reports the corpus's `sk_test_`
  plants; hence Kingfisher stripe 0/4 vs Betterleaks 3/4.
- **TruffleHog's five zero families are three different mechanisms**, each isolated by
  probe rather than asserted: pair-oriented aws (bare ids unreported), live-only
  stripe patterns, no jwt detector, structure-validated private keys (see the next
  item), and no discord/bearer rules. Its `--results` flag was confirmed live: all 31
  findings printed with `Verified: false` in the scored offline run, so the classic
  verified-only-output mistake did not occur.
- **One corpus-fidelity gap found and disclosed, pro-competitor**: the corpus's two
  private-key plants have random base64 bodies that do not parse as openssh-key-v1,
  and TruffleHog's PrivateKey detector validates structure (probe: a freshly
  generated, never-used, structurally valid key IS reported, even embedded
  transcript-style with escaped newlines; the corpus plants are not). By the
  benchmark's own pattern-true bar this penalizes TruffleHog unfairly on that row;
  the v1 AWS-base32 correction is the precedent. The plants stay unchanged in this
  run to keep v1 byte-reproducibility, the TruffleHog private-key cell carries this
  disclosure, and a structurally valid key body is queued for the next corpus
  version (no other tool's number would change: all seven others match the BEGIN
  marker and score 2/2).
- **detect-secrets is the field's cautionary tale on both axes at once**: strong
  structured-plugin coverage (agent-config 3/3, connection-string 3/3 via its Basic
  Auth detector, split 3/6 where six tools score 0), drowned by its entropy plugin
  producing 1,645 findings matching nothing planted and flagging 44/45 chaff
  instances on transcript-structural identifiers. Precision 2%. Its baseline also
  dedupes same-file re-occurrences (re-exposed sites 0/8 while echo value recall is
  3/4), and it flags the AWS documented example key itself (no example allowlist,
  confirmed in its shipped filters).
- **The suppress class still splits the field**: gitleaks, whatileaked, and
  TruffleHog flag none of the ten placeholders; Kingfisher flags 1, Betterleaks 2,
  residoo 3, AgentSweep and detect-secrets 5 each. residoo's three (npm placeholder,
  `AKIAIOSFODNN7EXAMPLE`, `ghp_xxxx...`) are unchanged from v1 and published unfixed.
- **residoo's weaknesses, unhidden and unchanged from v1**: 0/4 stripe everywhere,
  0/5 base64, 1/6 split, 1/3 agent-config, 3 suppress false positives. On the new
  8-tool field residoo still leads no per-family row uniquely and is beaten by
  AgentSweep on transcript-plain and json-nested; its edge remains the combination
  of transcript-shape classes with none-observed egress, not any single row.
- **Corpus correction during v1 assembly (pro-competitor), kept on the record**: the
  first corpus draft generated AWS key ids with an impossible charset; charset-correct
  scanners rightly rejected them and the generator was fixed to emit pattern-true
  base32 ids before v1 publication. The private-key disclosure above is the same
  policy applied to this extension's findings.

## residoo 0.8.6: a major research pass across four more competitor trackers found two real bugs, not just new coverage (added 2026-09-04)

Following the same "check open-items on other scanners" instruction that produced
0.8.2-0.8.5, this pass ran four research agents in parallel against sources not yet
mined this session: Yelp's detect-secrets, AWS Labs' git-secrets, Bloomberg's
noseyparker (browsing its shipped rule YAML directly, not just its issue tracker),
GitGuardian's ggshield (cross-checked against vendor docs rather than trusted, since
ggshield's own detection is server-side and its issues aren't a source of truth for
a regex), plus a fifth check for new direct competitors and anything filed more
recently than the gitleaks/TruffleHog issues already actioned in 0.8.2-0.8.5.

Two findings this round are false-negative BUGS in rules residoo already ships, not
new-vendor gaps:

- **`github_pat` could never match a GitHub fine-grained PAT.** Fine-grained tokens
  use the entirely disjoint literal prefix `github_pat_`, not `gh[pousr]_` -- the
  old regex had zero overlap with it. Confirmed directly against GitHub's own docs
  (docs.github.com's authentication overview). Found via detect-secrets issue #894.
- **`github_pat` also couldn't match GitHub's new App installation token shape.**
  GitHub's own 2026-04-24 changelog post describes `ghs_` tokens rolling out to
  `ghs_<appid>_<3-segment-JWT>` -- the JWT's dots fell outside the old
  `[A-Za-z0-9]`-only body class, so a real leaked installation token in this new
  format would have been silently missed. Found via detect-secrets issue #958.

Both are fixed by widening the body character class to include `. _ -` and raising
the ceiling (the distinctive prefix, unchanged, carries the false-positive
protection either way -- widening what follows it doesn't loosen that).

One more, lower-confidence rule fix: `supabase_token`'s regex only matched the bare
`sbp_<40 hex>` form. A gitleaks feature request (#2225) reports real-world tokens
also appearing as `sbp_v0_<40 hex>` -- not confirmed by Supabase's own docs, only by
the issue author's own code search and a cross-check that TruffleHog's detector has
the identical blind spot for the same structural reason. Shipped anyway (same
honesty tier as 0.8.5's Tailscale rule) since it's a narrow, low-risk optional
infix, not a guessed body shape.

One genuinely new rule: **Supabase secret API key** (`sb_secret_`), the newer
non-JWT replacement for the `service_role` key that bypasses Row Level Security the
same way. Confirmed via supabase.com's own current API-keys doc, which names the
prefix explicitly but not an exact length -- generously bounded, same treatment as
`cerebras_key`/`render_key` for the same situation. Zero prior coverage, confirmed
by grepping `src/patterns.js` before writing it.

Everything else these four agents surfaced (~18 additional vendor candidates,
individually verified against a primary source, spanning package registries,
dev-platform tokens, AI/ML vendors, and other SaaS) is being held for the next two
releases rather than shipped in one batch -- described there, not here. One new
direct competitor was also found and confirmed active: DidILeak
(github.com/frangelbarrera/DidILeak), same "scan your own AI chat history" framing
residoo uses, launched 2026-07 and still being pushed to as of this writing.

Pattern rule count moved 56 to 59 (one new rule, two existing rules widened). The
corpus's `github-pat` family plants are all classic `ghp_`-style (no fine-grained or
new-installation-token-shaped plant exists yet), so the full reproduce sequence
confirms no regression on the classic form rather than exercising the actual fix --
the fix itself is covered by dedicated smoke tests instead (`tests/smoke.js`), which
plant the exact fine-grained and dotted-JWT shapes and confirm both match `github_pat`
alone. Full reproduce run: residoo stays 45/45 (100%), 100% precision, none-observed
egress, byte-identical to 0.8.5 except the version label. Every other tool's row
reproduced unchanged.

## residoo 0.8.7: package registries and dev-platform tokens, second batch from the same research pass (added 2026-09-04)

The second of three batches from 0.8.6's four-agent research pass. Eight new
rules, all individually verified against a primary source rather than ported
from a competitor's regex on trust:

- **PyPI API token** (`pypi-`) -- PyPI publishes its own regex directly
  (docs.pypi.org/api/secrets/): `pypi-[A-Za-z0-9-_]{85,}`, no stated upper
  bound. This one converged independently across three of the four research
  agents (noseyparker, detect-secrets, ggshield all surfaced it separately),
  the strongest cross-corroboration of this whole research pass.
- **crates.io API token** (`cio`) -- verified against crates.io's own live
  token-generation source code (rust-lang/crates.io), not its docs: exact
  prefix and length read straight from `TOKEN_PREFIX`/`TOKEN_LENGTH`
  constants.
- **RubyGems API key** (`rubygems_`) -- exact 48-hex-char length independently
  counted against RubyGems' own guide's example token, not assumed from a
  competitor's rule.
- **Docker Hub access token** (`dckr_pat_`/`dckr_oat_`) -- confirmed via
  Docker's own OpenAPI spec file, which names both the personal and
  organization-scoped prefixes explicitly. (Two research agents disagreed on
  whether Docker documents this at all; the OpenAPI spec file settled it --
  checked directly before shipping, not just trusted from one agent's report.)
- **GitLab's other token kinds** (deploy/runner/CI-job/trigger/etc, `gldt-`
  through `gloas-`) -- one bundled rule for eleven prefixes GitLab's own docs
  publish in a table (docs.gitlab.com/security/tokens/), on top of the
  existing `glpat-` personal-access-token rule. Bundled rather than split
  eleven ways since they share both risk profile and rotation path.
- **Azure DevOps PAT** -- anchored on the fixed `AZDO` signature Microsoft's
  own docs describe as sitting at "positions 76-80" of an 84-character token.
  That description doesn't cleanly fit a 4-character literal into a 5-position
  range, so rather than risk a hard-coded offset that's off by one and never
  matches a real token, the rule allows a window around where AZDO can sit.
  Disclosed as an imprecise vendor description, not treated as more certain
  than it is.
- **Atlassian Cloud API token** (`ATATT3xFfGF0...=<8 hex>`) -- structure from
  noseyparker's shipped rule, independently confirmed current via an
  Atlassian staff reply on Atlassian's own community forum.
- **Discord bot token** -- three dot-separated segments, first starting with
  M/N/O, confirmed via Discord's own current developer docs. A materially
  different, more sensitive credential than the webhook URL residoo already
  covered (full bot API access vs. a single channel post). Verified it can
  never collide with the existing `jwt` rule: a JWT's first two segments must
  start with the literal `eyJ`, never M/N/O.

Pattern count moved 59 to 67. This corpus has no plant for any of these eight
families yet, so the full reproduce sequence confirms no regression, not a new
win: residoo stays 45/45 (100%), 100% precision, none-observed egress,
byte-identical to 0.8.6 except the version label. Every other tool's row
reproduced unchanged. One more batch (AI/ML vendors and other SaaS) from the
same research pass is still queued for the next release.

## residoo 0.8.8: AI/ML vendors and other SaaS, the last batch from the same research pass (added 2026-09-04)

The third and final batch from 0.8.6's four-agent research pass. Twelve new
rules, closing out the AI/ML-vendor and other-SaaS candidates that pass
surfaced:

- **NVIDIA** (`nvapi-`), **Tavily** (`tvly-`), **Jina AI** (`jina_`),
  **Firecrawl** (`fc-`) -- four AI-agent tool-integration API keys, prefixes
  confirmed via each vendor's own docs or official SDK repos, exact body
  lengths not independently pinned for three of the four (stated plainly in
  each rule's own comment rather than presented as more certain than it is).
- **Databricks PAT** (`dapi` + 32 hex) -- the one "medium" confidence rule
  in this batch. Databricks' own docs deliberately show only placeholder
  tokens; this rests on two independent secondary sources agreeing
  (Microsoft Purview's own Sensitive-Information-Type definition, and
  TruffleHog's shipped detector) rather than a Databricks-primary source.
  The strict lowercase-hex body was checked against a real false-positive
  noseyparker's own maintainers had already found and fixed: Binance uses
  the same "dapi" naming convention for its futures API
  (`dapiDataGetTopLongShortPositionRatio`), which this rule's hex-only body
  requirement never matches (confirmed by a dedicated smoke test).
- **Sourcegraph** (`sgp_`) -- prefix vendor-confirmed; noted in the rule's
  own comment (not shipped, since it's out of scope, just disclosed) that
  Segment's own "Public API Token" also uses an `sgp_` prefix with a
  different, non-overlapping body shape -- worth an explicit collision test
  if Segment is ever added.
- **Shopify Admin API token** (`shpat_`/`shppa_`), **Grafana service account
  token** (`glsa_`, exact shape read straight off Grafana's own docs
  example), **New Relic** (`NRAK-`) -- all vendor-prefix-confirmed.
- **HubSpot private app token** (`pat-<region>-...`) -- the other "medium"
  confidence rule: HubSpot's own docs only show a masked example, so the
  shape is corroborated via real (redacted) examples on HubSpot's own
  community forum rather than a fully primary-sourced spec.
- **Mailchimp** (`<32 hex>-us<N>`) -- the one rule in this batch with no
  distinctive prefix at all; safety comes entirely from the literal `-usN`
  datacenter suffix, read directly off a live example in Mailchimp's own
  docs, not from an opaque body alone.
- **Akamai EdgeGrid token** (`akab-...-...`) -- confirmed via Akamai's own
  docs (literal examples shown) plus an independent detect-secrets
  maintainer reproduction.

Pattern count moved 67 to 79. As with 0.8.6 and 0.8.7, this corpus has no
plant for any of these twelve families yet, so the full reproduce sequence
confirms no regression rather than exercising the new coverage directly:
residoo stays 45/45 (100%), 100% precision, none-observed egress,
byte-identical to 0.8.7 except the version label. Every other tool's row
reproduced unchanged.

This closes out the four-agent research pass started in 0.8.6: three
releases (0.8.6, 0.8.7, 0.8.8), two real bugs fixed in already-shipped
rules, one confirmed live gap closed (Supabase secret key), and 27 total
new/widened rules from ~40 candidates the four agents originally surfaced
-- the remainder either declined outright (no primary source, or a
structurally unsafe bare/unprefixed shape) or already covered by an
existing rule, each with its reasoning disclosed in the relevant commit
and in `src/patterns.js`'s own comments.

## Reproduce

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

The `<tool>-default-verification` runs are the dual-mode egress observations; they are
never scored for recall. Tool installs (one-time, unscored, pinned versions):
`bench/tools/VERSIONS.md`.
