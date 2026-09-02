# Competitor tools: versions, invocations, and observed behavior

Ground-truth notes for the benchmark harness. Everything below was verified by
running each tool on this machine (macOS 26.5.2, Apple Silicon arm64) on
2026-09-02 against the tiny synthetic fixture in `fixture-smoke/` (two files,
one planted fake AWS documented-example access key, `AKIAIOSFODNN7EXAMPLE`,
inside a Claude Code shaped transcript at
`home/.claude/projects/demo/session.jsonl`; the second file,
`home/demo-project/notes.md`, is benign). A second fixture variant,
`fixture-smoke/home2/`, is identical except the key is a pattern-true
non-example value (`AKIAQ3EG...TW5V (redacted pattern-true fake)`).

Every scan invocation pinned `HOME` (and `XDG_CONFIG_HOME`, `XDG_DATA_HOME`,
`XDG_CACHE_HOME`, `USERPROFILE`, and where relevant `GEMINI_CLI_HOME`,
`CODEX_HOME`) into the fixture via `env -i`. No competitor redact, fix, or
wipe mode was ever invoked; scan tier only.

Raw output samples are in `samples/`. Note: sample files contain the absolute
fixture paths of the machine they were captured on.

The local installs the HARNESS ADAPTERS use live in exactly three places
(all gitignored; reproduce them with the install commands below, which are
the same commands each adapter prints as its installHint):

- `bin/gitleaks`, `bin/trufflehog`, `bin/kingfisher`, `bin/betterleaks`
  (pinned official release binaries, checksum verified per each tool's
  section below; the release tarballs and published checksum files are kept
  alongside them in `bin/`)
- `uv/bin/agentsweep`, `uv/bin/ggshield`, and `uv/bin/detect-secrets`
  (uv tool installs with
  `UV_TOOL_DIR=bench/tools/uv/tools UV_TOOL_BIN_DIR=bench/tools/uv/bin`)
- `node/node_modules/whatileaked` (`npm install` inside `bench/tools/node`)

Install-time network fetches are normal and never scored; only scan-time
egress is.

## Headline corpus-design finding

Two of the four tools deliberately suppress the canonical AWS documented
example key `AKIAIOSFODNN7EXAMPLE`:

- gitleaks skips it via a rule-level allowlist on `aws-access-token`
  (trace log: `skipping finding: rule allowlist allowed-regex=true`) and via
  the stopword `example` on `generic-api-key`.
- whatileaked ships the allowlist regex `.+EXAMPLE$` (visible in its bundled
  `dist/cli.js`), so any candidate ending in `EXAMPLE` is dropped.
- agentsweep has no such allowlist and reports the example key.
- detect-secrets 1.5.0 also has no example allowlist: it reports the
  documented example key on the smoke fixture (and the pattern-true variant),
  `samples/detect-secrets-smoke.json` / `-nonexample.json`.
- betterleaks 1.8.1 keeps the `.+EXAMPLE$` allowlist on `aws-access-token`
  (visible in `betterleaks config show`), and kingfisher 2.1.0 loads the
  Betterleaks rule set (`--load-builtins`, default true), so both drop
  EXAMPLE-suffixed candidates; both also make `aws-access-token` a composite
  rule (key id paired with a nearby secret key), so a BARE access key id,
  example or pattern-true, is not reported at all. trufflehog 3.97.2's AWS
  detector is likewise pair-oriented: neither the bare documented example
  key nor the bare pattern-true key id was reported in its sample runs.
- ggshield could not be tested (refuses to scan without an account, see below).

Consequence for the corpus: planted secrets must be CredData-style
pattern-true fakes with random bodies (correct prefix, charset, and length,
for example `AKIAQ3EG...TW5V (redacted pattern-true fake)`), never the literal documented example
values. Using `AKIAIOSFODNN7EXAMPLE` as a planted secret would charge
gitleaks and whatileaked with false misses for behavior that is reasonable
in their threat model. Both tools detect the pattern-true variant correctly.
The documented example keys remain the model for how fakes are constructed,
not values to plant.

## gitleaks 8.30.1

- Version: 8.30.1 (`gitleaks version` prints `8.30.1`).
- Install: official binary release
  `gitleaks_8.30.1_darwin_arm64.tar.gz` from
  github.com/gitleaks/gitleaks releases, sha256 verified against the
  published `gitleaks_8.30.1_checksums.txt`
  (`b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5`),
  extracted to `bench/tools/bin/gitleaks` (where the harness adapter looks).
- Invocation used:
  `gitleaks dir <root> --report-format json --report-path out.json --no-banner`
  (the `dir` subcommand scans plain directories and files, no git required).
- Exit codes: 0 when no leaks, 1 when leaks found (default, configurable via
  `--exit-code`). Errors use other codes.
- Output: JSON array of finding objects with `RuleID`, `Description`,
  `StartLine`/`EndLine`, `StartColumn`/`EndColumn`, `Match`, `Secret`
  (the raw secret, unmasked by default; `--redact` exists but was not used
  since redaction here is output masking, not file modification), `File`,
  `Entropy`, `Fingerprint` (`<file>:<rule>:<line>`), and empty git fields
  (`Commit`, `Author`, ...) in dir mode. Empty report is `[]`.
  Samples: `samples/gitleaks-smoke.json` (example key run, empty),
  `samples/gitleaks-smoke-nonexample.json` (1 finding).
- Line numbers are 1-based JSONL line numbers; no JSON-path awareness
  (a transcript line is treated as one long text line, column offsets given).
- Scan-time network: none observed. Go binary, offline detection engine.
  Rigorous egress verification deferred to the harness.
- Claimed scope (its README, shipped in the release tarball): "detecting
  secrets like passwords, API keys, and tokens in git repos, files, and
  whatever else you wanna throw at it via stdin". Subcommands: `git`, `dir`,
  `stdin`. No claims about AI agents, transcripts, or agent config
  directories; scanning a transcript tree requires the user to aim `dir` at
  it explicitly.

## agentsweep 0.1.9

- Version: 0.1.9 (`agentsweep --version`), from PyPI.
- Install (what the harness adapter uses):
  `UV_TOOL_DIR=bench/tools/uv/tools UV_TOOL_BIN_DIR=bench/tools/uv/bin uv tool install agentsweep==0.1.9`
  (pinned; run from the repo root). Binary: `bench/tools/uv/bin/agentsweep`.
  Interpreter: uv-managed CPython 3.12.14. Requires Python >=3.11
  (PyPI metadata), so it does NOT run on the macOS system Python 3.9.6;
  plain `pip install --user agentsweep` fails on a stock Mac.
  Runtime deps: pyahocorasick, rich.
- Invocation used:
  `agentsweep scan --source claude-code --root <dir> --json`
  (also `-o out.json` to write findings to a file). `--source` selects one
  agent at a time from a 29-agent list; default is `claude-code`.
  `--root` overrides the source's default root (which lives under `HOME`).
- Exit codes: 1 when findings, 0 when clean (also 0 with "No history files
  found" and `[]` when the root has no recognized history files).
- Output (`--json`): JSON array of objects with `fingerprint`
  (`<relpath>:<line>:<rule>`), `file` (absolute), `line`, `keypath` (the JSON
  path inside the transcript line, e.g. `["message","content",0,"text"]`),
  `rule`, `display`, `masked` (e.g. `AKIAIO********MPLE`). The raw secret
  value is never printed. Sample: `samples/agentsweep-smoke.json`; the
  human-readable TTY rendering is `samples/agentsweep-smoke-tty.txt`.
- JSON-path aware: `keypath` shows it parses transcript JSONL structurally,
  not just as text lines.
- Detects the AWS documented example key (no example allowlist observed).
- Scan-time network: the CLI contains a PyPI version check
  (`https://pypi.org/pypi/agentsweep/json`, urllib, ~1.5 s timeout,
  background thread). Verified in source (`cli.py`): it is skipped when
  `--json` is passed, when stdout is not a TTY, or when
  `AGENTSWEEP_NO_UPDATE` is set; it fires on interactive TTY runs. It
  fetches version metadata only and sends no scan content, but note the
  README's "fully offline" badge next to this behavior. Harness rule: set
  `AGENTSWEEP_NO_UPDATE=1` and use `--json` so its scan path is network-free,
  and document the TTY default separately on the egress axis.
- Claimed scope (PyPI README): "Find and redact secrets in your AI coding
  agent's local history. Fully offline." Claims 29 agents (Claude Code,
  Codex, OpenCode, Cursor, Windsurf, Aider, Cline, Kilo Code, Roo Code,
  PearAI, Trae, Void, Gemini CLI, Qwen Code, Continue, Open Interpreter,
  GitHub Copilot Chat, OpenClaw, Hermes, Goose, Warp, Grok CLI, Kiro CLI,
  Zed, Codebuff, Plandex, Junie, Mentat, JetBrains AI) and 191 detection
  rules. Its own README flags 13 of the 29 sources as "experimental"
  (storage paths "derived from research but not yet verified against a real
  install", may under-report). Transcripts: yes, explicitly. Configs: history
  and session storage, not general dotfile configs.

## whatileaked 0.3.0

- Version: 0.3.0 (npm registry; `package.json` in the installed package).
  There is no `--version` flag.
- Install (what the harness adapter uses):
  `cd bench/tools/node && npm install whatileaked@0.3.0`
  so pinned-HOME runs do not depend on the real user's npx cache (its README
  recommends `npx --yes whatileaked`, but npx resolution inside a monitored
  scan window would be registry traffic the tool did not cause). Zero runtime
  dependencies. Node >=20 per its README (Node v26.8.1 used here). Bin:
  `dist/cli.js`.
- Invocation used (pinned copy):
  `node bench/tools/node/node_modules/whatileaked/dist/cli.js scan`
  with `HOME` pinned. Roots are derived from `os.homedir()` (so `HOME`
  pinning works): `~/.claude`, `~/.codex`, `~/.cursor`.
- CLI surface: exactly two commands, `scan` and `wipe`, and NO options.
  There is no `--help`, no `--version`, no `--json`, no root override.
- FOOTGUN, verified: `whatileaked scan --help` does not print help. Unknown
  arguments after `scan` are ignored and it immediately scans the real home
  directory with no confirmation prompt. A bare `whatileaked` (no command)
  prints usage; `whatileaked --help` prints an unknown-command error. The
  harness must never assume `--help` is safe on this tool and must always
  pin `HOME` before the binary ever runs.
- Exit codes: 0 in every observed case, including when credentials are found.
  Exit code carries no signal; the text output must be parsed.
- Output: human text only. Header
  `scanned N transcripts · M messages · K memory files`, then per-rule groups
  (e.g. `* aws-access-token  1 secret`) with an 8-hex-char fingerprint
  (truncated SHA-256 of the secret), a context snippet ending in `***`, and
  the file path with `~` abbreviation. Secrets are never printed. Samples:
  `samples/whatileaked-smoke.txt` (example key, no findings),
  `samples/whatileaked-smoke-nonexample.txt` (1 finding).
- Suppresses the AWS documented example key via allowlist regex `.+EXAMPLE$`
  (found in the bundle); detects the pattern-true variant.
- Scan-time network: none observed; no http/fetch references found in the
  bundle. Its README claims "no network connection is made at any point" and
  the tool prints "This tool sends nothing anywhere". Rigorous verification
  deferred to the harness.
- Claimed scope (npm README and package description): "Scan your local
  Claude Code, Codex and Cursor transcripts for credentials you already sent
  to a model provider." Also scans "memory files" (counted in the header).
  Three agents only; no config-file claims beyond those roots. Built by
  Selan (selan.ai) as a funnel for their redaction proxy.

## ggshield 1.54.0

- Version: 1.54.0 (`ggshield --version` prints `ggshield, version 1.54.0`),
  from PyPI. Requires Python >=3.9; uv tool installs keep it isolated from
  agentsweep's dependency tree.
- Install (what the harness adapter uses):
  `UV_TOOL_DIR=bench/tools/uv/tools UV_TOOL_BIN_DIR=bench/tools/uv/bin uv tool install ggshield==1.54.0`
  (pinned; run from the repo root). Binary: `bench/tools/uv/bin/ggshield`.
- Invocation attempted:
  `ggshield secret scan path -r -y <root>` with `HOME` pinned.
- Unauthenticated behavior, verified with no account and no API key: it
  refuses to scan at all. Exit code 3. Exact message
  (`samples/ggshield-unauth.txt`):

  ```
  Error: A GitGuardian API key is needed to use ggshield.
  To get one, authenticate to your dashboard by running:

      ggshield auth login

  If you are using an on-prem version of GitGuardian, use the --instance option to point to it.
  Read the following documentation for more information: https://docs.gitguardian.com/ggshield-docs/reference/auth/login
  ```

- Architecture note for the egress axis, from its own README: "ggshield uses
  our public API through py-gitguardian to scan and detect potential
  vulnerabilities in files and other text content." Detection is
  server-side by design: scanned content is sent to GitGuardian's API. The
  README states only metadata (call time, request size, scan mode) is stored
  and "your files and secrets won't be stored". The benchmark must score it
  honestly on both axes: recall requires an authenticated run (harness
  decision pending), and "what leaves the machine" is: the scanned content
  itself, per vendor documentation.
- Exit codes (documented): 0 no incident, 1 incidents found, 2 usage error,
  3 authentication or API error (matches the observed refusal).
- Scan-time side behavior observed under the harness, both reported in the
  benchmark's egress and scanner-write evidence: even the unauthenticated
  refusing run fires a version self-check toward api.github.com
  (`ggshield/core/check_updates.py` in the installed package; caught as a
  proxy CONNECT attempt by the trap) and writes an `update_check.yaml`
  cache file under `XDG_CACHE_HOME` (which the harness points at a per-run
  scratch directory outside the fixture for exactly this reason).
- Claimed scope (PyPI README): 500+ secret types; scans commits, branches,
  repos, paths, archives, docker images, pypi packages, CI environments. No
  claims about AI agent transcripts or agent config directories; scanning a
  transcript tree requires aiming `secret scan path` at it explicitly.

## detect-secrets 1.5.0 (Yelp)

- Version: 1.5.0 (`detect-secrets --version` prints `1.5.0`), from PyPI.
- Install (what the harness adapter uses):
  `UV_TOOL_DIR=bench/tools/uv/tools UV_TOOL_BIN_DIR=bench/tools/uv/bin uv tool install detect-secrets==1.5.0`
  (pinned; run from the repo root). Binary: `bench/tools/uv/bin/detect-secrets`.
  Interpreter: uv-managed CPython 3.12. Runtime deps include pyyaml and
  requests (requests is what its verification plugins use; capability noted
  for the static layer, conduct measured by the dynamic layers).
- Invocation used (scored, offline mode):
  `detect-secrets scan --all-files -n <root>`. Its README documents the
  non-git form ("Scanning non-git tracked files:
  `detect-secrets scan test_data/ --all-files`"); `--all-files` means "Scan
  all files recursively (as compared to only scanning git tracked files)".
- DUAL MODE, verified in the installed package: by default the scan verifies
  some candidate secrets over the network. Its own help documents the
  off-switch: "-n, --no-verify  Disables additional verification of secrets
  via network call." and the stricter "--only-verified  Only flags secrets
  that can be verified." In source, `detect_secrets/filters/common.py`
  enables `is_ignored_due_to_verification_policies` (which calls each
  plugin's `verify()`) unless `-n` is passed. Verifying plugins in 1.5.0,
  each naming its endpoint in source: aws (sts.amazonaws.com), slack
  (slack.com/api/auth.test, hooks.slack.com), stripe (api.stripe.com),
  telegram (api.telegram.org), mailchimp (usN.api.mailchimp.com), softlayer
  (api.softlayer.com), ibm_cloud_iam (iam.cloud.ibm.com), ibm_cos_hmac,
  cloudant. Harness rule (the dual-mode rule): recall is scored with `-n`;
  the default mode is executed separately by the
  `detect-secrets-default-verification` adapter purely to observe egress.
- Exit codes: 0 with or without findings (observed on the smoke fixture and
  the mini-fixture; nonzero signaling belongs to its pre-commit hook, not
  `scan`).
- Output: a baseline JSON document on stdout: `{version, plugins_used,
  filters_used, results, generated_at}`. `results` is keyed by file path
  (relative to the invocation cwd) with entries
  `{type, filename, hashed_secret, is_verified, line_number}`. The raw
  secret is never printed; `hashed_secret` is a SHA-1 of the value, so the
  harness matches by file+line. `line_number` is the physical 1-based line
  (verified against the fixtures). One entry per (file, hashed secret,
  plugin type); re-occurrences of the same secret in the same file are
  deduped at the first line. 27 plugins enabled by default (plus
  KeywordDetector and the two high-entropy detectors, which can flag
  arbitrary text; their behavior on chaff is a scored result, not tuned
  away). Samples: `samples/detect-secrets-smoke.json` (documented example
  key, 1 finding: no example allowlist) and
  `samples/detect-secrets-smoke-nonexample.json` (pattern-true variant,
  1 finding).
- Scan-time network: none observed in the scored `-n` mode. Default mode is
  the dual-mode egress observation documented above.
- Claimed scope (its README): "detect-secrets is an aptly named module for
  (surprise, surprise) detecting secrets within a code base." plus the
  documented `--all-files` directory form. A generic file scanner like
  gitleaks: no AI-agent or transcript claims, scanning a transcript tree
  requires aiming it at the directory explicitly, and every corpus class is
  in its claimed scope.

## TruffleHog 3.97.2

- Version: 3.97.2 (`trufflehog --version` prints `trufflehog 3.97.2`).
- Install: official binary release from
  github.com/trufflesecurity/trufflehog releases, sha256 verified against
  the published `trufflehog_3.97.2_checksums.txt`
  (`8d4e7a3d28785de0a8ccee14d195e9e387b3e664f80c41437cb7a74708a542f5` for
  `trufflehog_3.97.2_darwin_arm64.tar.gz`), extracted to
  `bench/tools/bin/trufflehog`. The release README travels in the tarball
  and is kept at `bin/trufflehog_README.md` so every quote below is
  verifiable offline against the exact shipped version. Reproduce:

  ```
  cd bench/tools/bin
  curl -sSLO https://github.com/trufflesecurity/trufflehog/releases/download/v3.97.2/trufflehog_3.97.2_darwin_arm64.tar.gz
  curl -sSLO https://github.com/trufflesecurity/trufflehog/releases/download/v3.97.2/trufflehog_3.97.2_checksums.txt
  grep darwin_arm64 trufflehog_3.97.2_checksums.txt && shasum -a 256 trufflehog_3.97.2_darwin_arm64.tar.gz
  tar xzf trufflehog_3.97.2_darwin_arm64.tar.gz trufflehog
  ```

- Invocation used (scored, OFFLINE mode):
  `trufflehog filesystem <root> --json --no-verification --results=verified,unknown,unverified --no-update`
  (`filesystem` per its README usage `trufflehog filesystem path/to/dir`;
  "Find credentials in a filesystem." per `filesystem --help`).
- THE RESULTS FLAG, load-bearing: some TruffleHog versions printed only
  verified findings by default, which would unfairly zero an offline run.
  On 3.97.2 its own `--help` documents `--results` as "Specifies which
  type(s) of results to output: verified (confirmed valid by API), unknown
  (verification failed due to error), unverified (detected but not
  verified), filtered_unverified (unverified but would have been filtered
  out). Defaults to verified,unverified,unknown." So unverified findings
  ARE in the 3.97.2 default; the harness passes
  `--results=verified,unknown,unverified` explicitly anyway so the
  invocation stays correct on versions with a different default and the
  intent is visible in the raw record.
- DUAL MODE (the benchmark's rule for tools with optional live
  verification): TruffleHog verifies by default. Its README:
  "For every potential credential that is detected, we've painstakingly
  implemented programmatic verification against the API that we think it
  belongs to." Recall is scored in its own documented offline mode
  (`--no-verification`, "Don't verify the results."), because scoring
  recall in a mode that phones out would conflate the recall and egress
  axes. The default mode is executed separately by the
  `trufflehog-default-verification` adapter purely to observe egress.
  Observed on the mini-fixture default-mode run (one GitHub PAT finding):
  one proxy CONNECT to `oss.trufflehog.org:443` (its startup update check;
  `--no-update`, "Don't check for updates.", is the documented off-switch
  the scored run uses) and one to `api.github.com:443` (GitHub credential
  verification). The corpus contains only pattern-true FAKE credentials no
  provider ever issued, and the refuse-and-log proxy trap refuses every
  connection, so at worst an ATTEMPT carrying fake values is observed;
  nothing reaches any provider on this harness.
- Exit codes: 0 observed both with and without findings. 183 on findings is
  opt-in via `--fail` and is not used.
- Output: JSON Lines on stdout (`--json`), logs on stderr. Per finding:
  `SourceMetadata.Data.Filesystem.{file,line}` (absolute path, 1-based
  line, exact against planted lines for PLAIN findings), `DetectorName`,
  `DecoderName`, `Raw`/`RawV2` (the secret text, unmasked by default),
  `Verified`. For BASE64-decoded findings (`DecoderName: BASE64`) the line
  was observed one below the encoded site but `Raw` carries the DECODED
  value, so the scorer's exact-value tier credits them. For structured
  detectors (e.g. Postgres) `Raw` can be a normalized reconstruction of the
  connection string rather than the verbatim planted text; the file+line
  tier catches those. Samples: `samples/trufflehog-smoke.json` (mini
  fixture, 1 finding) and `samples/trufflehog-smoke.stderr.txt`.
- Detector-design observations (recall results, not invocation errors),
  each isolated by probe on this machine at 3.97.2:
  - AWS is pair-oriented: a bare access key id alone in a file was NOT
    reported; the same id WAS reported when a 40-character
    secret-key-charset string sat in the same chunk. The corpus's aws
    plants are bare key ids, so its 0 aws findings match the detector's
    documented-by-behavior pairing requirement.
  - Stripe covers live-mode keys only: a probe `sk_live_` fake was
    reported, the corpus's `sk_test_` plants were not. Test-mode keys
    being out of pattern scope is a defensible threat-model choice and is
    reported as recall, not corrected for.
  - PrivateKey validates key STRUCTURE, not just the BEGIN/END markers: a
    freshly generated (structurally valid, never-used) OpenSSH key was
    reported both as a plain file and embedded in a transcript-shaped
    JSON line with escaped newlines, while the corpus's private-key
    plants (random base64 bodies that do not parse as openssh-key-v1)
    were not. This is a corpus-fidelity gap by the benchmark's own
    pattern-true bar (the v1 AWS-base32 precedent), disclosed in
    RESULTS.md next to TruffleHog's private-key row and queued as a
    corpus fix for the next corpus version.
  - No generic JWT detector: a structurally valid HS256 JWT probe was not
    reported (family-coverage gap, not shape).
  Detector names observed on the corpus: `Github`, `Gitlab`, `Slack`,
  `Anthropic`, `Postgres`, `NpmToken` (all normalize correctly via
  `familyFromRule`).
- Scan-time network in the scored offline mode: none observed
  (harness mini-fixture run, proxy trap plus lsof).
- Claimed scope (shipped README): "Find leaked credentials." and
  "TruffleHog can look for secrets in many places including Git, chats,
  wikis, logs, API testing platforms, object stores, filesystems and more."
  A generic filesystem scanner: no AI-agent or transcript claims, scanning
  a transcript tree requires aiming `filesystem` at it explicitly, and
  every corpus class is in its claimed scope.

## Kingfisher 2.1.0

- Version: 2.1.0 (`kingfisher --version` prints `kingfisher 2.1.0`), from
  github.com/mongodb/kingfisher releases (MongoDB's scanner, built on
  Vectorscan; Rust binary).
- Install and checksum: the release publishes no plain checksums.txt;
  its integrity channel is the sigstore/in-toto attestation
  `multiple.intoto.jsonl`, whose DSSE payload lists a sha256 per asset.
  Verified for `kingfisher-darwin-arm64.tgz`:
  `42cbbdc58257d9abedc88c6fb76d2c1b7a41193f0f5ac292b7b09c76f0570893`. The
  tarball additionally embeds `CHECKSUM-darwin-arm64.txt` for the inner
  binary (`6b628eb9dbb51c62c83ac79292d51fd8ee8996a328ab54b3cc085351306f4e15`,
  `shasum -a 256 -c` OK). Both checksum artifacts are kept in `bin/` as
  `kingfisher_2.1.0_multiple.intoto.jsonl` and
  `kingfisher_2.1.0_CHECKSUM-darwin-arm64.txt`. Binary:
  `bench/tools/bin/kingfisher`. Unlike the TruffleHog and Betterleaks
  tarballs, the Kingfisher tarball ships no README, so the repository README
  at the release tag is kept at `bin/kingfisher_README.md` (fetched from
  `raw.githubusercontent.com/mongodb/kingfisher/v2.1.0/README.md`) so every
  README quote below is verifiable offline against the tagged version; the
  CLI-help quotes verify against the pinned binary itself. Reproduce:

  ```
  cd bench/tools/bin
  curl -sSLO https://github.com/mongodb/kingfisher/releases/download/v2.1.0/kingfisher-darwin-arm64.tgz
  curl -sSL -o kingfisher_2.1.0_multiple.intoto.jsonl https://github.com/mongodb/kingfisher/releases/download/v2.1.0/multiple.intoto.jsonl
  curl -sSL -o kingfisher_README.md https://raw.githubusercontent.com/mongodb/kingfisher/v2.1.0/README.md
  shasum -a 256 kingfisher-darwin-arm64.tgz   # compare against the attestation's subject digest
  tar xzf kingfisher-darwin-arm64.tgz kingfisher CHECKSUM-darwin-arm64.txt
  shasum -a 256 -c CHECKSUM-darwin-arm64.txt
  ```

- Invocation used (scored, OFFLINE mode):
  `kingfisher scan <root> --no-validate --format jsonl --no-dedup --no-rule-cache --no-update-check`.
  Every flag from its own `--help`: `--no-validate` "Disable secret
  validation"; `--format jsonl` "JSON Lines (one JSON object per line)";
  `--no-dedup` "Display every occurrence of a finding" (it dedupes by
  default; this benchmark scores exposure sites and the tool documents this
  flag for exactly that reporting mode, detection unchanged);
  `--no-rule-cache` "Disable the compiled Vectorscan rule database cache";
  `--no-update-check` "Disable automatic update checks".
- SCANNER-WRITE FINDING, verified on this machine: without
  `--no-rule-cache`, kingfisher writes its compiled rule cache to
  `Library/Caches/kingfisher/rule-cache/*.vscdb` under HOME, which the
  harness pins INSIDE the scanned fixture (macOS cache resolution ignores
  the XDG_CACHE_HOME scratch pin). The benchmark's write-protection rule
  keeps the scanned tree byte-stable, so `--no-rule-cache` is passed in
  BOTH modes; the honest cost is that wall time includes rule compilation
  on every run (roughly 38 s of the mini-fixture probe scan, measured under
  a heavily loaded window; absolute probe timings are indicative only).
- UPDATE CHECK, verified: on by default even under `--no-validate` (the
  scan summary reported `update_check_status: "ok"` on the first probe
  run; with the flag it reports "disabled"). The scored offline run uses
  the documented off-switch, the same treatment as agentsweep's TTY update
  check in v1; the default-on check shows up factually in the default-mode
  egress observation below.
- DUAL MODE: Kingfisher validates by default. Its README: "Validate
  discovered credentials against provider APIs to reduce false positives";
  its top-level help: "Detect and validate secrets across files and full
  Git history". Recall is scored offline (`--no-validate`); the default
  mode is executed separately by the `kingfisher-default-verification`
  adapter purely to observe egress. Observed on the mini-fixture
  default-mode run (one GitHub PAT finding): two proxy CONNECT attempts to
  `api.github.com:443` (its release update check and GitHub credential
  validation both target that host). Same fake-values and refusing-trap
  facts as stated for TruffleHog above.
- Exit codes (its README, observed): 0 no findings, 200 findings
  discovered, 205 validated findings discovered (unreachable offline).
- Output: JSONL, one object per finding with `rule.{id,name,title}` and
  `finding.{snippet,line,path,confidence,entropy,fingerprint,validation}`;
  a trailing summary object (no `rule` key) carries scan and update-check
  counters and is parsed into the notes, not the findings. `snippet` is the
  raw secret text (unredacted by default; `--redact` exists and is not
  used, since redaction is output masking and the value enables exact-value
  matching). Lines are 1-based and matched planted lines exactly (59/59 on
  the corpus probe). Rule ids are namespaced, e.g. `betterleaks.github-pat`
  and `veles.secrets/npmjsaccesstoken`, because kingfisher loads the
  built-in Betterleaks rule set (`--load-builtins`, default true) plus
  Google's Veles rules. Samples: `samples/kingfisher-smoke.jsonl`,
  `samples/kingfisher-smoke.stderr.txt`.
- Rule-design observations, each isolated by probe on this machine at
  2.1.0 (recall results, not invocation errors): its
  `betterleaks.aws-access-token` variant is composite like Betterleaks'
  own (a bare AKIA-style key id alone was NOT reported; the same id WAS
  reported with an `aws_secret_access_key` on the next line), and its
  `betterleaks.stripe-access-token` variant covers live-mode keys only (a
  probe `sk_live_` fake was reported; the corpus's `sk_test_` plants were
  not, unlike Betterleaks 1.8.1 itself, which reports `sk_test_` keys).
  The shipped rule variants are not byte-identical to Betterleaks 1.8.1's
  rule set.
- Never invoked, scan-only rule: `kingfisher update` / `--self-update`
  (binary self-modification), `validate`, `revoke`, `blast-radius`
  (network actions by definition), `--manage-baseline`, `--alert-webhook`.
- Scan-time network in the scored offline mode: none observed
  (harness mini-fixture run, proxy trap plus lsof).
- Claimed scope (its README, pinned at `bin/kingfisher_README.md`;
  the original bolds "live secret validation"): "Kingfisher is an open
  source secret scanner and live secret validation tool built in Rust." Its scan command takes
  any "file, directory, or local Git repository" (`--help`) and the README
  quickstart scans a plain directory. A generic file scanner: no AI-agent
  or transcript claims, and every corpus class is in its claimed scope.

## Betterleaks 1.8.1

- Canonical source, researched: Betterleaks is the Gitleaks successor from
  the original gitleaks author (its README: "It is maintained by the folks
  who made Gitleaks, including the original author"), with development
  supported by Aikido Security (README badge and Aikido's own launch
  post). The canonical repository and release channel is
  github.com/betterleaks/betterleaks; that is where the pinned binary
  comes from. MIT licensed.
- Version: 1.8.1 (`betterleaks version` prints `1.8.1`).
- Install: official binary release, sha256 verified against the published
  `checksums.txt`
  (`8e80f33b5f2a7426b390347b9fd466033723cb94b6bdffa7572632e2eaec964e` for
  `betterleaks_1.8.1_darwin_arm64.tar.gz`, kept locally as
  `bin/betterleaks_1.8.1_checksums.txt`), extracted to
  `bench/tools/bin/betterleaks`; the shipped README is kept at
  `bin/betterleaks_README.md`. Reproduce:

  ```
  cd bench/tools/bin
  curl -sSLO https://github.com/betterleaks/betterleaks/releases/download/v1.8.1/betterleaks_1.8.1_darwin_arm64.tar.gz
  curl -sSL -o betterleaks_1.8.1_checksums.txt https://github.com/betterleaks/betterleaks/releases/download/v1.8.1/checksums.txt
  grep darwin_arm64 betterleaks_1.8.1_checksums.txt && shasum -a 256 betterleaks_1.8.1_darwin_arm64.tar.gz
  tar xzf betterleaks_1.8.1_darwin_arm64.tar.gz betterleaks
  ```

- Invocation used:
  `betterleaks dir <root> --report-format json --report-path out.json --no-banner --regex-engine stdlib`.
  Gitleaks-successor semantics as expected: `dir` is its documented
  plain-directory subcommand ("scan directories or files for secrets",
  with aliases `file` and `directory`), the drop-in analogue of
  `gitleaks dir` / legacy `detect --no-git`.
- SCANNER-WRITE FINDING and the regex-engine choice: with its default
  engine (`--regex-engine` "regex engine (stdlib, re2) (default re2)"),
  the re2-over-wasm implementation (wasilibs/go-re2 via wazero) writes a
  compilation cache to `Library/Caches/com.github.wasilibs/` under HOME on
  macOS, which the harness pins INSIDE the scanned fixture; no flag or env
  var redirects it (no WASILIBS/cache env var in the binary strings, and
  Go's os.UserCacheDir on darwin ignores XDG_CACHE_HOME). To keep the
  scanned tree byte-stable, the harness uses the tool's own documented
  alternative engine, `--regex-engine stdlib`, after verifying on this
  corpus that the two engines produce an IDENTICAL finding set (66
  findings each, zero symmetric difference on rule+file+line+secret).
  Honest cost, recorded: the engine-parity probe measured the corpus scan
  at ~11.3 s with stdlib vs ~7.1 s with re2 (cold cache) under a heavily
  loaded window (absolute probe timings are indicative only; the relative
  cost is the point), so published wall times reflect the non-default
  engine.
- NO DUAL MODE NEEDED: validation is opt-in, not default. Its `--help`:
  `--validation` "enable validation of findings against live APIs"; its
  README lists "Secrets Validation: Validate if a detected secret is active
  by making asynchronous HTTP requests directly from within the rule
  definition using Expr." The benchmark never passes `--validation`
  (scan-only rule), so the scored run IS the documented default mode and
  must show none-observed egress. Verified: none observed on the harness
  mini-fixture run.
- Exit codes: 0 clean, 1 when leaks found (`--exit-code` "exit code when
  leaks have been encountered (default 1)", observed).
- Output: gitleaks-compatible JSON report file (`RuleID`, `File`,
  `StartLine`, `Match`, `Secret` raw and unmasked by default, `Entropy`,
  `Fingerprint`, empty git fields in dir mode) plus an `Attributes` object
  with `confidence` and `path`. Lines are 1-based and matched planted
  lines exactly (66/66 on the corpus probe). Samples:
  `samples/betterleaks-smoke.json`, `samples/betterleaks-smoke.stdout.txt`.
- Sanity bar against gitleaks, checked as required: corpus-probe totals are
  comparable (betterleaks 66 findings vs gitleaks 69). The whole gap is
  rule design, not invocation: its `aws-access-token` is a COMPOSITE rule
  ("Identified an AWS access key ID paired with a secret access key";
  `components` require an `aws-secret-access-key` within 5 lines, per
  `betterleaks config show`), so the corpus's bare access-key-id plants are
  not reported (gitleaks reports 11 aws sites), while its
  `generic-credential-uri` and `generic-password` rules add sites gitleaks
  lacks. `--confidence low` was tested and does not change the aws
  behavior; the composite requirement is the mechanism.
- Rule naming observed: gitleaks-style ids (`github-pat`,
  `slack-bot-token`, `anthropic-api-key`, `npm-access-token`, `gitlab-pat`,
  `private-key`, `stripe-access-token`, `jwt`, `generic-api-key`,
  `generic-password`) plus `generic-credential-uri`, which maps to the
  connection-string family in `harness/lib.js` (see the FAMILY_TABLE
  comment; without that mapping a correct connection-string detection
  would be double-charged).
- Scan-time network: none observed (harness mini-fixture run, proxy trap
  plus lsof). No update check was observed in any run.
- Claimed scope (its own help and README): "Betterleaks scans code, past or
  present, for secrets"; "Betterleaks is a configurable, fast, and thorough
  secrets scanner." A generic file scanner like gitleaks: no AI-agent or
  transcript claims in the shipped 1.8.1 README, scanning a transcript tree
  requires aiming `dir` at it explicitly, and every corpus class is in its
  claimed scope.

## Fairness inputs for the harness (claimed-scope rule)

| Tool | Transcript claims | Agents claimed | Offline claim | Findings exit code | Machine-readable output | Secret in output |
|---|---|---|---|---|---|---|
| gitleaks 8.30.1 | none (generic files/dirs/git) | n/a | offline engine | 1 | JSON report | raw secret |
| agentsweep 0.1.9 | yes, primary purpose | 29 (13 experimental) | "fully offline" badge, but TTY update check hits pypi.org | 1 | `--json` | masked only |
| whatileaked 0.3.0 | yes, primary purpose | 3 (Claude Code, Codex, Cursor) | "no network at any point" | always 0 | none (text only) | fingerprint only |
| detect-secrets 1.5.0 | none (generic code base / `--all-files` dirs) | n/a | dual mode: network verification by default, offline via its own `-n` | always 0 (scan) | baseline JSON on stdout | SHA-1 hash only |
| trufflehog 3.97.2 | none (generic: git, chats, wikis, logs, filesystems) | n/a | dual mode: API verification by default plus startup update check, offline via its own `--no-verification` and `--no-update` | 0 always (183 only with the `--fail` opt-in) | `--json` JSONL | raw secret |
| kingfisher 2.1.0 | none (generic files/dirs/git and platforms) | n/a | dual mode: API validation by default plus default-on update check, offline via its own `--no-validate` and `--no-update-check` | 200 (0 clean, 205 validated) | `--format jsonl` | raw secret (snippet) |
| betterleaks 1.8.1 | none (generic code/dirs, gitleaks successor) | n/a | offline by default; validation is opt-in via `--validation` (never passed) | 1 | JSON report | raw secret |
| ggshield 1.54.0 | none (generic content) | n/a | server-side detection by design | 1 (documented) | `--json` (documented) | untested unauthenticated |
