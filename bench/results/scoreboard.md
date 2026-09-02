# Scoreboard

Per-class scores. There is no blended headline number by design: a blend would hide the class differences the benchmark exists to show.

## AgentSweep (agentsweep 0.1.9)

- wall time: 663ms
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
| chaff-shaped | chaff | | | | | 0/45 |

Precision: 89% (matched sites 41, chaff FP 0, suppress FP 5, unplanted FP 0); 100% with suppress flags excluded. Distinct credentials found, all claimed classes (hard classes included): 33/42; headline classes only: 32/34. Re-exposed sites found: 8/8.

Per-family site recall (claimed secret classes):

| family | sites found |
|---|---|
| aws | 5/8 |
| anthropic | 7/8 |
| slack | 6/6 |
| stripe | 3/4 |
| github | 6/9 |
| gitlab | 2/3 |
| npm | 3/4 |
| connection-string | 3/3 |
| private-key | 2/2 |
| discord | 2/2 |
| bearer-header | 0/2 |
| jwt | 2/2 |

## ggshield (GitGuardian) (ggshield, version 1.54.0)

- wall time: 297ms
- egress (scan-time only): **by-design-requires-server** Observed unauthenticated on this harness: the scan command refuses to run without a GitGuardian API key (exit 3, 'A GitGuardian API key is needed to use ggshield'), which is the server dependency demonstrated live. Observed during the scan window: proxy CONNECT attempt "CONNECT api.github.com:443 HTTP/1.1".
- recall: **not scored (requires server account)**
- citation: ggshield README (GitGuardian), describing the invoked `secret scan` command: "ggshield uses our public API through py-gitguardian to scan and detect potential vulnerabilities in files and other text content." For the AI-agent surface specifically, the ggshield v1.53.0 changelog on `ai discover --activity`: it collects raw agent activity and "ships it to GitGuardian, which scans the content and strips secrets server-side". Nuance: ggshield supports self-hosted instances via --instance, so the required server need not be GitGuardian's cloud.

## gitleaks (8.30.1)

- wall time: 614ms
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
| chaff-shaped | chaff | | | | | 0/45 |

Precision: 100% (matched sites 40, chaff FP 0, suppress FP 0, unplanted FP 0); 100% with suppress flags excluded. Distinct credentials found, all claimed classes (hard classes included): 32/45; headline classes only: 27/37. Re-exposed sites found: 8/8.

Per-family site recall (claimed secret classes):

| family | sites found |
|---|---|
| aws | 6/8 |
| anthropic | 6/9 |
| slack | 7/7 |
| stripe | 3/4 |
| github | 8/10 |
| gitlab | 3/3 |
| npm | 3/4 |
| connection-string | 0/3 |
| private-key | 2/2 |
| discord | 0/2 |
| bearer-header | 0/2 |
| jwt | 2/2 |

## residoo (residoo 0.3.0)

- wall time: 194ms
- egress (scan-time only): **none-observed** no connection attempts through the proxy trap and no non-loopback-trap sockets in lsof polling during the scan window

| class | kind | sites found | site recall | distinct values | value recall | false positives |
|---|---|---|---|---|---|---|
| transcript-plain | secret | 21/24 | 88% | 21/24 | 88% | |
| agent-config-plain | secret | 1/3 | 33% | 1/3 | 33% | |
| transcript-json-nested | secret | 5/6 | 83% | 5/6 | 83% | |
| transcript-echo | secret | 12/12 | 100% | 4/4 | 100% | |
| transcript-b64 | secret | 0/5 | 0% | 0/5 | 0% | |
| transcript-split | secret | 1/6 | 17% | 1/3 | 33% | |
| suppress-placeholder | suppress | | | | | 3/10 |
| chaff-shaped | chaff | | | | | 0/45 |

Precision: 93% (matched sites 40, chaff FP 0, suppress FP 3, unplanted FP 0); 100% with suppress flags excluded. Distinct credentials found, all claimed classes (hard classes included): 32/45; headline classes only: 31/37. Re-exposed sites found: 8/8.

Per-family site recall (claimed secret classes):

| family | sites found |
|---|---|
| aws | 5/8 |
| anthropic | 7/9 |
| slack | 6/7 |
| stripe | 0/4 |
| github | 7/10 |
| gitlab | 2/3 |
| npm | 3/4 |
| connection-string | 3/3 |
| private-key | 2/2 |
| discord | 2/2 |
| bearer-header | 1/2 |
| jwt | 2/2 |

## whatileaked (whatileaked 0.3.0)

- wall time: 450ms
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
| chaff-shaped | chaff | | | | | 0/45 |

Precision: 100% (matched sites 29, chaff FP 0, suppress FP 0, unplanted FP 0); 100% with suppress flags excluded. Distinct credentials found, all claimed classes (hard classes included): 28/42; headline classes only: 24/34. Re-exposed sites found: 1/8.

Per-family site recall (claimed secret classes):

| family | sites found |
|---|---|
| aws | 4/8 |
| anthropic | 4/8 |
| slack | 4/6 |
| stripe | 3/4 |
| github | 5/9 |
| gitlab | 3/3 |
| npm | 2/4 |
| connection-string | 0/3 |
| private-key | 2/2 |
| discord | 0/2 |
| bearer-header | 0/2 |
| jwt | 2/2 |

