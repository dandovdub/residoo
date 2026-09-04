# Scoreboard

Per-class scores. There is no blended headline number by design: a blend would hide the class differences the benchmark exists to show.

## Cross-tool summary

Site recall per class (sites found / planted sites). Full per-tool detail, value recall, precision, and notes are in the sections below. oos = out of the tool's claimed scope (not scored, never zero); n/s = recall not scored (reason in the tool's section); FP = flagged instances of a non-secret class (false positives).

| class | agentsweep | betterleaks | detect-secrets | ggshield | gitleaks | kingfisher | residoo | trufflehog | whatileaked |
|---|---|---|---|---|---|---|---|---|---|
| transcript-plain | 22/24 | 20/24 | 14/24 | n/s | 18/24 | 18/24 | 24/24 | 16/24 | 18/24 |
| agent-config-plain | oos | 3/3 | 3/3 | n/s | 3/3 | 3/3 | 3/3 | 3/3 | oos |
| transcript-json-nested | 6/6 | 2/6 | 3/6 | n/s | 2/6 | 3/6 | 6/6 | 5/6 | 2/6 |
| transcript-echo | 12/12 | 9/12 | 3/12 | n/s | 12/12 | 9/12 | 12/12 | 7/12 | 5/12 |
| transcript-b64 (hard class) | 0/5 | 4/5 | 0/5 | n/s | 5/5 | 2/5 | 5/5 | 2/5 | 4/5 |
| transcript-split (hard class) | 1/6 | 0/6 | 3/6 | n/s | 0/6 | 0/6 | 5/6 | 0/6 | 0/6 |
| suppress-placeholder (suppress) | 5/10 FP | 2/10 FP | 5/10 FP | n/s | 0/10 FP | 1/10 FP | 0/10 FP | 0/10 FP | 0/10 FP |
| chaff-shaped (chaff) | 0/44 FP | 0/44 FP | 43/44 FP | n/s | 0/44 FP | 0/44 FP | 0/44 FP | 0/44 FP | 0/44 FP |
| distinct credentials, all claimed classes | 33/42 | 32/45 | 25/45 | n/s | 32/45 | 29/45 | 45/45 | 29/45 | 28/42 |
| precision (suppress FP included) | 89% | 95% | 2% | n/s | 100% | 97% | 100% | 97% | 100% |
| egress verdict (offline / default where dual-mode) | none-observed | none-observed | none-observed / attempted | by-design-requires-server | none-observed | none-observed / attempted | none-observed | none-observed / attempted | none-observed |

## AgentSweep (agentsweep 0.1.9)

- wall time: 605ms
- egress (scan-time only): **none-observed** no connection attempts through the proxy trap and no non-loopback-trap sockets in lsof polling during the scan window

| class | kind | sites found | site recall | distinct values | value recall | false positives |
|---|---|---|---|---|---|---|
| transcript-plain | secret | 22/24 | 92% | 22/24 | 92% | |
| agent-config-plain | | out of claimed scope (not scored) | | | | |
| transcript-json-nested | secret | 6/6 | 100% | 6/6 | 100% | |
| transcript-echo | secret | 12/12 | 100% | 4/4 | 100% | |
| transcript-b64 | secret | 0/5 | 0% | 0/5 | 0% | |
| transcript-split | secret | 1/6 | 17% | 1/3 | 33% | |
| suppress-placeholder | suppress | | | | | 5/10 |
| chaff-shaped | chaff | | | | | 0/44 |

Precision: 89% (matched sites 41, chaff FP 0, suppress FP 5, unplanted FP 0); 100% with suppress flags excluded. Distinct credentials found, all claimed classes (hard classes included): 33/42; headline classes only: 32/34. Re-exposed sites found: 8/8.

Per-family site recall (claimed secret classes):

| family | sites found |
|---|---|
| stripe | 3/4 |
| anthropic | 7/8 |
| aws | 5/8 |
| slack | 6/6 |
| github | 6/9 |
| gitlab | 2/3 |
| npm | 3/4 |
| connection-string | 3/3 |
| bearer-header | 0/2 |
| discord | 2/2 |
| private-key | 2/2 |
| jwt | 2/2 |

## Betterleaks (1.8.1)

- wall time: 493ms
- egress (scan-time only): **none-observed** no connection attempts through the proxy trap and no non-loopback-trap sockets in lsof polling during the scan window

| class | kind | sites found | site recall | distinct values | value recall | false positives |
|---|---|---|---|---|---|---|
| transcript-plain | secret | 20/24 | 83% | 20/24 | 83% | |
| agent-config-plain | secret | 3/3 | 100% | 3/3 | 100% | |
| transcript-json-nested | secret | 2/6 | 33% | 2/6 | 33% | |
| transcript-echo | secret | 9/12 | 75% | 3/4 | 75% | |
| transcript-b64 | secret | 4/5 | 80% | 4/5 | 80% | |
| transcript-split | secret | 0/6 | 0% | 0/3 | 0% | |
| suppress-placeholder | suppress | | | | | 2/10 |
| chaff-shaped | chaff | | | | | 0/44 |

Precision: 95% (matched sites 38, chaff FP 0, suppress FP 2, unplanted FP 0); 100% with suppress flags excluded. Distinct credentials found, all claimed classes (hard classes included): 32/45; headline classes only: 28/37. Re-exposed sites found: 6/8.

Per-family site recall (claimed secret classes):

| family | sites found |
|---|---|
| stripe | 3/4 |
| anthropic | 6/9 |
| aws | 2/8 |
| slack | 7/7 |
| github | 8/10 |
| gitlab | 3/3 |
| npm | 3/4 |
| connection-string | 2/3 |
| bearer-header | 0/2 |
| discord | 0/2 |
| private-key | 2/2 |
| jwt | 2/2 |

## detect-secrets (Yelp) (1.5.0)

- wall time: 2572ms (offline mode)
- egress (scan-time only), offline mode (scored for recall): **none-observed** (0 proxy CONNECT attempt(s), 0 non-proxy socket(s))
- egress (scan-time only), default mode (network verification enabled): **attempted** (24 proxy CONNECT attempt(s), 0 non-proxy socket(s); CONNECT targets: slack.com:443, sts.amazonaws.com:443)
  - citation: detect-secrets' own CLI help documents scan-time verification and its off-switch: "-n, --no-verify  Disables additional verification of secrets via network call." and "--only-verified  Only flags secrets that can be verified." In the installed 1.5.0 package, detect_secrets/filters/common.py enables the verification filter (is_ignored_due_to_verification_policies, which calls each plugin's verify()) unless -n is passed.
  - note: the corpus contains only pattern-true fake credentials, so a verification attempt sends only fake values at worst; on this harness the refuse-and-log proxy trap refuses all connections, so no verification request can leave the machine

| class | kind | sites found | site recall | distinct values | value recall | false positives |
|---|---|---|---|---|---|---|
| transcript-plain | secret | 14/24 | 58% | 14/24 | 58% | |
| agent-config-plain | secret | 3/3 | 100% | 3/3 | 100% | |
| transcript-json-nested | secret | 3/6 | 50% | 3/6 | 50% | |
| transcript-echo | secret | 3/12 | 25% | 3/4 | 75% | |
| transcript-b64 | secret | 0/5 | 0% | 0/5 | 0% | |
| transcript-split | secret | 3/6 | 50% | 2/3 | 67% | |
| suppress-placeholder | suppress | | | | | 5/10 |
| chaff-shaped | chaff | | | | | 43/44 |

Precision: 2% (matched sites 26, chaff FP 43, suppress FP 5, unplanted FP 1359); 2% with suppress flags excluded. Distinct credentials found, all claimed classes (hard classes included): 25/45; headline classes only: 23/37. Re-exposed sites found: 0/8.

Per-family site recall (claimed secret classes):

| family | sites found |
|---|---|
| stripe | 0/4 |
| anthropic | 2/9 |
| aws | 5/8 |
| slack | 5/7 |
| github | 5/10 |
| gitlab | 2/3 |
| npm | 0/4 |
| connection-string | 3/3 |
| bearer-header | 0/2 |
| discord | 0/2 |
| private-key | 2/2 |
| jwt | 2/2 |

## ggshield (GitGuardian) (ggshield, version 1.54.0)

- wall time: 260ms
- egress (scan-time only): **by-design-requires-server** Observed unauthenticated on this harness: the scan command refuses to run without a GitGuardian API key (exit 3, 'A GitGuardian API key is needed to use ggshield'), which is the server dependency demonstrated live. Observed during the scan window: proxy CONNECT attempt "CONNECT api.github.com:443 HTTP/1.1".
- recall: **not scored (requires server account)**
- citation: ggshield README (GitGuardian), describing the invoked `secret scan` command: "ggshield uses our public API through py-gitguardian to scan and detect potential vulnerabilities in files and other text content." For the AI-agent surface specifically, the ggshield v1.53.0 changelog on `ai discover --activity`: it collects raw agent activity and "ships it to GitGuardian, which scans the content and strips secrets server-side". Nuance: ggshield supports self-hosted instances via --instance, so the required server need not be GitGuardian's cloud.

## gitleaks (8.30.1)

- wall time: 578ms
- egress (scan-time only): **none-observed** no connection attempts through the proxy trap and no non-loopback-trap sockets in lsof polling during the scan window

| class | kind | sites found | site recall | distinct values | value recall | false positives |
|---|---|---|---|---|---|---|
| transcript-plain | secret | 18/24 | 75% | 18/24 | 75% | |
| agent-config-plain | secret | 3/3 | 100% | 3/3 | 100% | |
| transcript-json-nested | secret | 2/6 | 33% | 2/6 | 33% | |
| transcript-echo | secret | 12/12 | 100% | 4/4 | 100% | |
| transcript-b64 | secret | 5/5 | 100% | 5/5 | 100% | |
| transcript-split | secret | 0/6 | 0% | 0/3 | 0% | |
| suppress-placeholder | suppress | | | | | 0/10 |
| chaff-shaped | chaff | | | | | 0/44 |

Precision: 100% (matched sites 40, chaff FP 0, suppress FP 0, unplanted FP 0); 100% with suppress flags excluded. Distinct credentials found, all claimed classes (hard classes included): 32/45; headline classes only: 27/37. Re-exposed sites found: 8/8.

Per-family site recall (claimed secret classes):

| family | sites found |
|---|---|
| stripe | 3/4 |
| anthropic | 6/9 |
| aws | 6/8 |
| slack | 7/7 |
| github | 8/10 |
| gitlab | 3/3 |
| npm | 3/4 |
| connection-string | 0/3 |
| bearer-header | 0/2 |
| discord | 0/2 |
| private-key | 2/2 |
| jwt | 2/2 |

## Kingfisher (kingfisher 2.1.0)

- wall time: 3584ms (offline mode)
- egress (scan-time only), offline mode (scored for recall): **none-observed** (0 proxy CONNECT attempt(s), 0 non-proxy socket(s))
- egress (scan-time only), default mode (validation enabled): **attempted** (49 proxy CONNECT attempt(s), 0 non-proxy socket(s); CONNECT targets: api.github.com:443, api.anthropic.com:443, gitlab.com:443, registry.npmjs.org:443, sts.us-east-1.amazonaws.com:443)
  - citation: Kingfisher README: 'Validate discovered credentials against provider APIs to reduce false positives'; its top-level help: 'Detect and validate secrets across files and full Git history'. Offline flag per its --help: --no-validate, 'Disable secret validation'.
  - note: every planted credential is a pattern-true fake no provider ever issued, and the refuse-and-log proxy trap refuses all connections, so at worst an ATTEMPT carrying fake values is observed; nothing reaches any provider on this harness

| class | kind | sites found | site recall | distinct values | value recall | false positives |
|---|---|---|---|---|---|---|
| transcript-plain | secret | 18/24 | 75% | 18/24 | 75% | |
| agent-config-plain | secret | 3/3 | 100% | 3/3 | 100% | |
| transcript-json-nested | secret | 3/6 | 50% | 3/6 | 50% | |
| transcript-echo | secret | 9/12 | 75% | 3/4 | 75% | |
| transcript-b64 | secret | 2/5 | 40% | 2/5 | 40% | |
| transcript-split | secret | 0/6 | 0% | 0/3 | 0% | |
| suppress-placeholder | suppress | | | | | 1/10 |
| chaff-shaped | chaff | | | | | 0/44 |

Precision: 97% (matched sites 35, chaff FP 0, suppress FP 1, unplanted FP 0); 100% with suppress flags excluded. Distinct credentials found, all claimed classes (hard classes included): 29/45; headline classes only: 27/37. Re-exposed sites found: 6/8.

Per-family site recall (claimed secret classes):

| family | sites found |
|---|---|
| stripe | 0/4 |
| anthropic | 6/9 |
| aws | 2/8 |
| slack | 7/7 |
| github | 8/10 |
| gitlab | 3/3 |
| npm | 3/4 |
| connection-string | 2/3 |
| bearer-header | 0/2 |
| discord | 0/2 |
| private-key | 2/2 |
| jwt | 2/2 |

## residoo (residoo 0.8.3)

- wall time: 440ms
- egress (scan-time only): **none-observed** no connection attempts through the proxy trap and no non-loopback-trap sockets in lsof polling during the scan window

| class | kind | sites found | site recall | distinct values | value recall | false positives |
|---|---|---|---|---|---|---|
| transcript-plain | secret | 24/24 | 100% | 24/24 | 100% | |
| agent-config-plain | secret | 3/3 | 100% | 3/3 | 100% | |
| transcript-json-nested | secret | 6/6 | 100% | 6/6 | 100% | |
| transcript-echo | secret | 12/12 | 100% | 4/4 | 100% | |
| transcript-b64 | secret | 5/5 | 100% | 5/5 | 100% | |
| transcript-split | secret | 5/6 | 83% | 3/3 | 100% | |
| suppress-placeholder | suppress | | | | | 0/10 |
| chaff-shaped | chaff | | | | | 0/44 |

Precision: 100% (matched sites 55, chaff FP 0, suppress FP 0, unplanted FP 0); 100% with suppress flags excluded. Distinct credentials found, all claimed classes (hard classes included): 45/45; headline classes only: 37/37. Re-exposed sites found: 8/8.

Per-family site recall (claimed secret classes):

| family | sites found |
|---|---|
| stripe | 4/4 |
| anthropic | 8/9 |
| aws | 8/8 |
| slack | 7/7 |
| github | 10/10 |
| gitlab | 3/3 |
| npm | 4/4 |
| connection-string | 3/3 |
| bearer-header | 2/2 |
| discord | 2/2 |
| private-key | 2/2 |
| jwt | 2/2 |

## TruffleHog (trufflehog 3.97.2)

- wall time: 1054ms (offline mode)
- egress (scan-time only), offline mode (scored for recall): **none-observed** (0 proxy CONNECT attempt(s), 0 non-proxy socket(s))
- egress (scan-time only), default mode (verification enabled): **attempted** (64 proxy CONNECT attempt(s), 4 non-proxy socket(s); CONNECT targets: oss.trufflehog.org:443, sts.us-east-1.amazonaws.com:443, slack.com:443, gitlab.com:443, registry.npmjs.org:443, api.anthropic.com:443, api.github.com:443, keychecker.trufflesecurity.com:443)
  - citation: TruffleHog README (shipped in the release tarball): 'For every potential credential that is detected, we've painstakingly implemented programmatic verification against the API that we think it belongs to.' Offline flag per its --help: --no-verification, 'Don't verify the results.'
  - note: every planted credential is a pattern-true fake no provider ever issued, and the refuse-and-log proxy trap refuses all connections, so at worst an ATTEMPT carrying fake values is observed; nothing reaches any provider on this harness

| class | kind | sites found | site recall | distinct values | value recall | false positives |
|---|---|---|---|---|---|---|
| transcript-plain | secret | 16/24 | 67% | 16/24 | 67% | |
| agent-config-plain | secret | 3/3 | 100% | 3/3 | 100% | |
| transcript-json-nested | secret | 5/6 | 83% | 5/6 | 83% | |
| transcript-echo | secret | 7/12 | 58% | 3/4 | 75% | |
| transcript-b64 | secret | 2/5 | 40% | 2/5 | 40% | |
| transcript-split | secret | 0/6 | 0% | 0/3 | 0% | |
| suppress-placeholder | suppress | | | | | 0/10 |
| chaff-shaped | chaff | | | | | 0/44 |

Precision: 97% (matched sites 33, chaff FP 0, suppress FP 0, unplanted FP 1); 97% with suppress flags excluded. Distinct credentials found, all claimed classes (hard classes included): 29/45; headline classes only: 27/37. Re-exposed sites found: 4/8.

Per-family site recall (claimed secret classes):

| family | sites found |
|---|---|
| stripe | 0/4 |
| anthropic | 6/9 |
| aws | 2/8 |
| slack | 7/7 |
| github | 7/10 |
| gitlab | 3/3 |
| npm | 3/4 |
| connection-string | 3/3 |
| bearer-header | 0/2 |
| discord | 0/2 |
| private-key | 2/2 |
| jwt | 0/2 |

## whatileaked (whatileaked 0.3.0)

- wall time: 392ms
- egress (scan-time only): **none-observed** no connection attempts through the proxy trap and no non-loopback-trap sockets in lsof polling during the scan window

| class | kind | sites found | site recall | distinct values | value recall | false positives |
|---|---|---|---|---|---|---|
| transcript-plain | secret | 18/24 | 75% | 18/24 | 75% | |
| agent-config-plain | | out of claimed scope (not scored) | | | | |
| transcript-json-nested | secret | 2/6 | 33% | 2/6 | 33% | |
| transcript-echo | secret | 5/12 | 42% | 4/4 | 100% | |
| transcript-b64 | secret | 4/5 | 80% | 4/5 | 80% | |
| transcript-split | secret | 0/6 | 0% | 0/3 | 0% | |
| suppress-placeholder | suppress | | | | | 0/10 |
| chaff-shaped | chaff | | | | | 0/44 |

Precision: 100% (matched sites 29, chaff FP 0, suppress FP 0, unplanted FP 0); 100% with suppress flags excluded. Distinct credentials found, all claimed classes (hard classes included): 28/42; headline classes only: 24/34. Re-exposed sites found: 1/8.

Per-family site recall (claimed secret classes):

| family | sites found |
|---|---|
| stripe | 3/4 |
| anthropic | 4/8 |
| aws | 4/8 |
| slack | 4/6 |
| github | 5/9 |
| gitlab | 3/3 |
| npm | 2/4 |
| connection-string | 0/3 |
| bearer-header | 0/2 |
| discord | 0/2 |
| private-key | 2/2 |
| jwt | 2/2 |

