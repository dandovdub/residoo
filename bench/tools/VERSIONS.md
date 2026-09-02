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

- `bin/gitleaks` (pinned official binary, sha256 verified)
- `uv/bin/agentsweep` and `uv/bin/ggshield` (uv tool installs with
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

## Fairness inputs for the harness (claimed-scope rule)

| Tool | Transcript claims | Agents claimed | Offline claim | Findings exit code | Machine-readable output | Secret in output |
|---|---|---|---|---|---|---|
| gitleaks 8.30.1 | none (generic files/dirs/git) | n/a | offline engine | 1 | JSON report | raw secret |
| agentsweep 0.1.9 | yes, primary purpose | 29 (13 experimental) | "fully offline" badge, but TTY update check hits pypi.org | 1 | `--json` | masked only |
| whatileaked 0.3.0 | yes, primary purpose | 3 (Claude Code, Codex, Cursor) | "no network at any point" | always 0 | none (text only) | fingerprint only |
| ggshield 1.54.0 | none (generic content) | n/a | server-side detection by design | 1 (documented) | `--json` (documented) | untested unauthenticated |
