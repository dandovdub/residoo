# Benchmark harness

Runner, scorer, and zero-egress monitor for the transcript-shaped secrets benchmark. Zero dependencies, Node only, no sudo anywhere.

The benchmark's entire value is credibility. Every scoring choice below is stated so that a hostile reader can rerun everything, get the same numbers, and find the fairness questions answered here rather than dodged.

## Quick start

```sh
node bench/minifix/make-minifix.js                 # tiny deterministic fixture (dev/smoke)
node bench/harness/run.js --list                   # adapters and availability
node bench/harness/run.js residoo --mini           # one tool, one monitored run
node bench/harness/score.js --mini --md            # per-class scoreboard
node bench/harness/selftest-egress.js              # prove the monitor can fire
```

For the real corpus, drop `--mini` (default fixture root is `bench/corpus/data`, expected to contain `home/` and `manifest.json`). Results are fixture-scoped: `--mini` runs read and write `bench/results-mini/`, full-corpus runs use `bench/results/`, so a smoke run can never clobber published numbers (`--results <dir>` overrides either). The scorer also refuses to write a scoreboard when no results match the requested fixture.

## What a run does

`run.js <adapter>`:

1. Refuses to run unless the fixture home is under a `bench/` directory and is not the operator's real home. Scanners in this benchmark never see the real machine.
2. Starts the refuse-and-log proxy trap on 127.0.0.1.
3. Builds the child environment from scratch. Pinned into the fixture: `HOME`, `USERPROFILE`, `XDG_CONFIG_HOME`, `XDG_DATA_HOME`, `GEMINI_CLI_HOME`, `CODEX_HOME`, `CLAUDE_CONFIG_DIR`. `XDG_CACHE_HOME` and `XDG_STATE_HOME` are pinned to a per-run scratch directory OUTSIDE the fixture (still under bench/): they are write locations for tools, and a scanner's own cache write must never mutate the scanned tree (ggshield demonstrably writes an update-check cache file at scan time). All proxy variables point at the trap; `AGENTSWEEP_NO_UPDATE=1` is set as a second, documented off-switch for agentsweep's TTY update check. Nothing else is inherited beyond `PATH`, `TMPDIR`, and locale, so no credential from the operator's shell can reach a scanner under test.
4. Records the tool version, then runs the adapter's scan command(s) inside the monitored window with lsof polling of the scanner's own process tree.
5. Diffs the fixture tree against a pre-scan snapshot: any file a tool created, modified, or deleted inside the scanned fixture is reported loudly (`fixtureMutations` in the findings record, a WARNING on the console, and a nonzero exit), because a scanner writing into the tree it scans is benchmark-relevant conduct and would break the corpus's byte-identical guarantee. Files the tool wrote into its cache/state scratch are recorded as `scratchWrites` evidence, then the scratch is removed.
6. Writes `bench/results/raw/<tool>.txt` (verbatim output plus the exact commands and env pins) and `bench/results/<tool>.findings.json` (normalized findings, timing, egress record). Raw records contain the absolute fixture paths of the machine they were captured on.

Scan-only, always: no adapter invokes any tool's redact, fix, or wipe mode.

## Zero-egress monitor

Three layers, none needing sudo (see `egress.js`):

- proxy trap: `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY` point at a local listener that logs every connection attempt (CONNECT target included) and refuses it. Catches proxy-honoring clients.
- lsof poll: every ~150ms, `lsof -a -p <scanner pid tree> -i` on the scanner's own processes. Catches clients that ignore proxy env. Connections to the trap itself are excluded here because the trap layer already records them; everything else, loopback included, is recorded, so nothing is silently filtered. Deliberate consequence, stated: a scanner that opens ANY non-trap socket during the scan, even loopback IPC, is verdicted `attempted` with the socket listed. That is conservative by design; the evidence is always printed so a reader can judge a loopback-only record for themselves.
- static grep: informational only, never scored. Network primitives in a tool's installed source are capability, not conduct; the dynamic layers measure conduct. For compiled binaries this layer reports not applicable.

Verdict per tool: `none-observed`, `attempted` (with details), or `by-design-requires-server` (with citation).

### Install-time vs scan-time: the fairness rule that matters

Fetching a package with npm, pip, uv, or brew is how software is delivered and says nothing about scan conduct. All tools are installed once, beforehand, into `bench/tools/` (pinned binary for gitleaks, `bench/tools/node` for whatileaked, `bench/tools/uv` for agentsweep and ggshield). The monitored window covers only the scan itself, from process spawn to process exit. Only scan-time egress is scored. Install-time egress is expected and unscored, and every results file says so.

### Known limits, stated rather than hidden

- The lsof poll samples at ~150ms; a socket opened and closed inside one tick can be missed. The proxy trap layer has no such gap for proxy-honoring clients.
- DNS lookups made through the system resolver can be too fast for the poll. A tool doing DNS but no connection would look clean to the poll layer; it would still have to open a real socket to move data, which the layers above would see.
- The monitor observes conduct on this run, on this corpus. It cannot prove a tool never phones home under other conditions. Verdicts are worded as observations for exactly that reason.
- `selftest-egress.js` is the positive control: it proves both dynamic layers fire (loopback-only traffic). A clean verdict is falsifiable evidence, not silence from a dead monitor. Its transcript is persisted to `bench/results/raw/selftest-egress.txt` so the "positive control verified first" claim is itself evidenced in the raw records.

## Adapters

One file per tool in `adapters/`, each declaring: the exact command, version detection, an output parser built against the tool's real observed output, and `claimedClasses` taken from the tool's own documentation (quoted in `claimsNote`).

- `residoo`: `node <repo>/bin/residoo.js scan --json`, machine mode. Output is redacted by design (basename, line, rule), so it is matched by location, never by value.
- `gitleaks`: pinned binary, `dir <fixture home>` (its modern plain-directory subcommand; the legacy `detect --no-git --source` spelling was verified to produce an identical finding set on this corpus), JSON report. Exit 1 means leaks found and is expected. Claims every class (general-purpose file scanner).
- `agentsweep`: installed via uv into `bench/tools/uv`. Scans one agent per invocation (its CLI has no all-sources mode), so the adapter probes the fixture for each agent root in its `--source` list and runs one scan per present root, all inside one monitored window. Claims transcript classes only.
- `whatileaked`: installed into `bench/tools/node`, run directly via node so the scan window contains no npx registry resolution. Text output parsed from the real observed format; it reports distinct credentials with one representative file and no line numbers, which the scorer handles via the file+family tier and the site-vs-value metrics. Claims transcript classes only.
- `ggshield`: see the design decision below.

## Scoring

`score.js` emits per-tool, per-class scores. There is no blended headline number by design; a blend would hide exactly the class differences the benchmark exists to show.

Matching tiers (full statement at the top of `score.js`): exact planted value, then file+line, then file+rule-family. Tools that redact output are never penalized for redacting; they match by location. When the family tier is ambiguous inside one file, attribution prefers real secrets over suppress instances over chaff, which is the pro-competitor direction on purpose: an ambiguous finding counts as recall before it counts as a false positive.

Per class: secret classes get site recall and distinct-value recall (they differ exactly when a tool dedupes re-exposed credentials; both are always shown). The one cross-class line, distinct credentials found, is computed twice and labeled: all claimed classes with the hard classes included (this guards dedup-style reporters against value-level undercounting), and headline classes only. Chaff and suppress classes count false positives. Precision combines matched planted instances against chaff, suppress, and unplanted findings, with every term filtered to claimed scope (credit and charge alike), and is published both with and without suppress flags because the example-value philosophy is genuinely contested. A per-family site-recall breakdown is emitted for every tool so family-coverage effects can be separated from transcript-shape effects.

Claimed scope: a tool is scored on a class only if its own documentation claims that surface. Unclaimed classes are reported as "out of claimed scope", never as zero. Chaff and suppress instances carry the surface class they are embedded in (`surfaceClass`) for the same decision.

## The ggshield decision

No GitGuardian account is created for this benchmark. Scoring ggshield's recall would require sending the corpus to GitGuardian's server, which is the behavior axis this benchmark measures. So:

- Its recall column reads "not scored (requires server account)". Never zero; zero would be false and unfair.
- The adapter runs `ggshield secret scan path -r` unauthenticated and records the observed behavior verbatim (observed on v1.54.0: exit 3, "A GitGuardian API key is needed to use ggshield").
- Its egress verdict is `by-design-requires-server`, with the primary citation aimed at the exact subcommand invoked: ggshield's own README states "ggshield uses our public API through py-gitguardian to scan and detect potential vulnerabilities in files and other text content" (verbatim in the installed package metadata; see `tools/VERSIONS.md`). The v1.53.0 changelog quote about `ai discover --activity` (it collects raw agent activity and "ships it to GitGuardian, which scans the content and strips secrets server-side") is the secondary citation for the AI-agent surface specifically; it is not a description of `secret scan path`. Nuance included: ggshield can point at a self-hosted instance via `--instance`, so the required server need not be GitGuardian's cloud.
- Anything observed live during its scan window is still reported alongside the citation, never hidden behind it: on this harness the unauthenticated run attempted one proxy CONNECT to api.github.com:443 (its version self-check) before refusing to scan, and that attempt appears in its egress row.

## Corpus manifest contract

`<fixture root>/manifest.json`, `schemaVersion: 1`:

```json
{
  "schemaVersion": 1,
  "seed": 123,
  "classes": { "<class id>": { "kind": "secret|chaff|suppress", "hard": false, "description": "..." } },
  "planted": [
    {
      "id": "p001",
      "class": "<class id>",
      "kind": "secret|chaff|suppress",
      "ruleFamily": "aws",
      "value": "<pattern-true fake>",
      "file": "home/relative/path",
      "line": 12,
      "distinctGroup": "g01",
      "exposure": "first|re-exposed",
      "surfaceClass": "<secret class this chaff/suppress instance is embedded in>"
    }
  ]
}
```

Constraints the scorer enforces or relies on:

- Every planted value is a pattern-true fake (CredData style: correct prefix, charset, and length, never a real value; `AKIAIOSFODNN7EXAMPLE` is the canonical model for the suppress class), and the whole corpus is deterministic from `seed`.
- Planted basename+line pairs must be unique across the corpus, because redacting tools emit basenames only and are matched at basename+line; the scorer hard-fails on collisions instead of guessing. Bare basename repeats are legitimate (real agent layouts repeat names like settings.local.json); the line disambiguates, and the family tier only ever sees full paths.
- `ruleFamily` values come from `familyFromRule` in `lib.js` so matching never depends on any one tool's rule naming.

## Reproducing

Everything a rerun needs is in this repo: the fixture generator is seeded, the adapters name their exact commands, `bench/results/raw/` holds verbatim output with the env pins, and the scorer is deterministic. Install the tools per each adapter's `installHint` (install-time network, unscored), then run the commands in Quick start.
