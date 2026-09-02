# Results: the transcript-shaped secrets benchmark

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
default-mode verification attempt count, 48 in this window against the 50
above, vary run to run and are labeled as indicative wherever they
appear.) residoo 0.3.1, same harness, same rules of scoring:

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

## Egress during the scan (the second axis)

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
