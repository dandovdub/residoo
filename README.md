<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/logo-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="docs/logo-light.svg">
  <img src="docs/logo-light.svg" alt="residoo" width="280">
</picture>

**Find secrets leaking through your AI coding agent's session history.**

[![npm version](https://img.shields.io/npm/v/residoo)](https://www.npmjs.com/package/residoo)
[![CI](https://github.com/dandovdub/residoo/actions/workflows/ci.yml/badge.svg)](https://github.com/dandovdub/residoo/actions/workflows/ci.yml)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![node >=18](https://img.shields.io/badge/node-%3E%3D18-339933)](package.json)
[![runtime dependencies: 0](https://img.shields.io/badge/runtime_dependencies-0-brightgreen)](package.json)

<img src="docs/demo.svg" alt="residoo scan terminal output: 17 potential secrets found across 3 files, 87 files scanned (1.2 GB), values redacted to first/last 4 characters, no network calls" width="760">

</div>

Every time Claude Code, Cursor, or a similar tool reads a file, runs a
command, or browses a page for you, it writes the whole session to disk,
including whatever it touched. A `.env` file, a config with a real key, a
login token captured during testing: that credential is now sitting in
plaintext, indefinitely, somewhere almost nobody thinks to check.

residoo scans those transcripts and tells you what's in them.

```
$ residoo scan

⚠  17 potential secrets found across 3 files
   87 files scanned (1.2 GB) · sources: claude-code
   oldest match ~8d old · most recent ~0d old

    16  [high]  AWS Access Key ID   (1 distinct value, re-exposed 15× across tool output)
     1  [high]  Private key block

Values are redacted in this report (first/last 4 characters only). Nothing
scanned here left your machine; residoo makes no network calls.
```

> [!NOTE]
> gitleaks and trufflehog scan **commits**. residoo scans the **conversation
> transcripts** an AI agent leaves behind: a different, previously
> uncovered surface. Full comparison, including agentsweep and
> trufflehog/betterleaks' verification postures, in
> [docs/comparison.md](docs/comparison.md).

## What it does

- Scans your local AI-agent session transcripts for 50 high-confidence
  secret patterns: cloud provider keys, private key blocks, OAuth/API
  tokens, database connection strings, and more. See
  [`src/patterns.js`](src/patterns.js).
- Sees through two transcript-specific disguises: a credential dumped only
  as base64 on a line, or split across two adjacent streaming records, is
  decoded/rejoined and rescanned, then reported as `base64-wrapped` or
  `split across lines` so you know it was hidden. See
  [`src/decode.js`](src/decode.js).
- Pairs an AWS secret access key (no vendor prefix of its own) with a
  nearby confirmed access key id and reports both at high confidence: the
  *pairing* is the signal, not the shape alone. Ambiguous pairings are
  reported as nothing rather than a guess. Same mechanism now also covers
  PlanetScale and MongoDB Atlas Service Account credentials. See
  [`src/pairing.js`](src/pairing.js).
- Decodes a JWT's own `exp` claim locally (no network call, since the
  claim is inside the signed payload) and reports "valid until" or
  "expired" instead of just "last seen." See
  [`src/jwtExpiry.js`](src/jwtExpiry.js).
- **`--verify`** (opt-in, makes a real network call): asks a credential's
  own vendor whether it still authenticates, using the exact value found in
  your transcript. 35 vendors today, off by default. See
  [Verifying credentials are still live](#verifying-credentials-are-still-live)
  below.
- With `--include-noisy`, filters broad generic-secret rules by how
  machine-random the matched value looks; never applied to the default
  rules. See [`src/rarity.js`](src/rarity.js).
- Redacts everything in its own output, including `--json`: you get a
  shape and a first/last-4 preview, never the real value.
- `--sarif` emits SARIF 2.1.0 for GitHub code scanning; `--json` carries
  the full picture (findings, integrity, rotation) together.
- `--seal --keychain` stores the vault key in the OS's own credential store
  instead of a typed passphrase. See [Sealing](#sealing-what-it-finds).
- Tells you how many **distinct** secrets it found versus how many times
  one got echoed back across tool calls, so the headline number reflects
  real exposure, not repetition.
- Flags likely placeholder/example matches separately from real findings,
  rather than hiding them or inflating the count.
- Also scans agent **config files** and checks for **planted persistence**
  (hooks, droppers, invisible Unicode); see the next section.
- Attaches a **rotation runbook** to every finding, plus a local
  acknowledgement ledger. See [Rotation](#rotation-from-found-to-closed).
- `--project <dir>` scans a repository checkout instead of the machine, for
  CI and pre-commit. See [CI and pre-commit](#ci-and-pre-commit).

## Beyond transcripts: configs and planted persistence

Transcripts leak what your agent *saw*. Config files leak what it was
*configured with*, and that's the better-measured problem: GitGuardian
counted 24,008 secrets inside MCP config files on public GitHub (2,117
still valid), and Lakera found live credentials inside
`.claude/settings.local.json` shipped in ~30 published npm packages. So
`residoo scan` also covers the home-level config files of Claude Code,
Claude Desktop, Cursor, Gemini CLI, Codex, and Kiro, plus project-level
Claude Code configs (`.mcp.json`, `.claude/settings*.json`) resolved from
project roots the agent itself recorded, never by guessing directories.

Those same files are where 2026's supply-chain campaigns (Mini Shai-Hulud,
Miasma, the keyv/ChainDrop wave, TrapDoor) planted hooks, dropper scripts,
and zero-width-Unicode prompt injection. Every scan now also runs
**integrity checks** over those exact locations:

- Every auto-executing hook is listed; only a published campaign IOC or
  campaign-shaped behavior (piping a download into a shell, base64-decode-
  then-execute) escalates to a warning.
- Loose scripts in `.claude/` and known planted filenames are flagged by
  name.
- `CLAUDE.md`, `.cursorrules`, and `.cursor/rules/*` are checked for
  zero-width Unicode.
- `.vscode/tasks.json` is parsed for folder-open auto-run tasks.

Read-only like everything else. `--no-integrity` skips it entirely. A
config that can't be read is reported as unverified, never silently
counted clean.

## How it works

```
                    YOUR MACHINE · no network calls
  ┌───────────────────────────────────────────────────────────────┐
  │                                                               │
  │   42 transcript sources           agent config files          │
  │   ~/.claude, Cursor, Codex…       settings · MCP · memory     │
  │   (--project <dir>: a repo checkout instead of the machine)   │
  │            │                              │                   │
  │            ├──────────────┬───────────────┤                   │
  │            ▼              │               ▼                   │
  │   stream + match          │        integrity checks           │
  │   50 verified rules       │        hooks · droppers ·         │
  │            │              │        zero-width unicode         │
  │            ▼              ▼               │                   │
  │        redacted report (first/last 4 chars only) ◀────────────┤
  │            │                                                  │
  │            ├─▶ rotation hints per finding · explain / ack     │
  │            │   ledger: ~/.residoo/rotations.json              │
  │            │                                                  │
  │            ▼  --seal (only if you ask)                        │
  │        AES-256-GCM vault · scrypt key · encrypted manifest    │
  │            │                              │                   │
  │            ▼  unseal --restore            ▼  --upload-cloudroam
  │        SHA-256 verified copy          ciphertext only ┄┄┄┄┄┄┄┄┄▶
  │                                                               │
  └───────────────────────────────────────────────────────────────┘
```

The `--seal` and `--upload-cloudroam` legs never run unless you pass their
flag. Nothing in the diagram ever modifies or deletes an existing file. The
one exception, stated in the open: `residoo ack` writes residoo's own
rotation ledger at `~/.residoo/rotations.json` (atomic, redacted, never a
user file).

## Sealing what it finds

Finding a leaked key raises the obvious next question: *now what?*

```bash
residoo scan --seal
```

Every transcript that carried a finding is encrypted into a local vault
directory: AES-256-GCM, key derived from your passphrase with scrypt,
streamed so an 800MB transcript never touches memory whole. The vault's own
manifest is encrypted too, so it doesn't advertise what's inside even by
name. **Originals are never touched.** Once you've verified a restore works
(`residoo unseal <vault> --restore 0001.sealed --out /tmp/check`, checked
byte-identical via a recorded SHA-256), deleting the plaintext is your
decision, made by you.

Optionally, `--upload-cloudroam` (with `CLOUDROAM_API_KEY`, `--connector`,
`--bucket`) copies the sealed vault to [CloudRoam](https://cloudroam.io) for
durable, cross-cloud storage.

> [!IMPORTANT]
> `--upload-cloudroam` is the *only* feature in residoo that touches the
> network to send your data anywhere. It never runs unless you pass the
> flag, and only ciphertext is transmitted: the vault is sealed before any
> upload code executes.

## Verifying credentials are still live

`--verify` asks a credential's own vendor whether it still authenticates,
using the exact value found in your transcript. Off by default, one real
network call per distinct credential.

Three vendors need a paired id+secret: **AWS** (via `sts:get-caller-identity`,
shelling out to your own `aws` CLI rather than reimplementing request
signing), **PlanetScale**, and **MongoDB Atlas** (Service Account
credentials only, the legacy Public/Private Key pair has no distinguishing
prefix and isn't detected at all). The other 32 are a single credential
each, one direct API call:

Slack · OpenAI · Anthropic · GitHub · Hugging Face · Replicate ·
DigitalOcean · Pinecone · SendGrid · Groq · xAI · OpenRouter · Stripe · npm ·
Notion · GitLab · Supabase · ElevenLabs · CircleCI · Airtable · Cloudflare ·
Heroku · Netlify · Linear · Telegram · Discord webhooks · Vercel · Cerebras ·
Render · Neon · PostHog · Fly.io

Every vendor clears the same two-stage bar before being wired up:
independent research against that vendor's own current docs, then a
separate, adversarial pass that tries to refute the first before it's
trusted. A real, sourced reason (no free endpoint, needs context the
credential doesn't carry, or a format not confirmed specifically enough to
detect safely) is why some detected credential types aren't wired to
`--verify` at all, not an oversight (Fly.io's `fm1a_`/`fm1r_`/`fm2_`
"macaroon" tokens are the clearest example: real-machine testing produced a
measured false-positive rate, so that family is detected nowhere in
residoo). A verified-active credential is escalated to "rotate
immediately"; a verified-invalid one is reported already dead, no action
needed. See [`src/verify.js`](src/verify.js).

## Rotation: from found to closed

Detection without rotation is theater: 64% of secrets leaked publicly in
2022 were still valid years later, 88% of re-verified leaked AWS keys still
authenticated, and the median time to remediate a GitHub-leaked secret is
94 days. Every finding in a residoo report comes with the way out:

- **A rotation hint per finding**, from a guidance map covering all 50
  detection rules. Where shown, a rotation URL was fetched and confirmed to
  document revoking that exact credential type.
- **`residoo explain <rule-id>`** prints the full runbook: where to revoke,
  the steps, what revocation does. `residoo explain --list` shows the whole
  catalogue.
- **`residoo ack <fingerprint>`** records that you rotated a finding.
  **`residoo dismiss <fingerprint>`** records that it was never a real
  secret. Both live in `~/.residoo/rotations.json`, residoo's own ledger,
  written atomically, redacted through the same pipeline as previews.
- **"Recommended actions" leads the report**: how many *distinct* values
  still need a decision, versus how many are already resolved (acked,
  dismissed, or `--verify`-confirmed dead).
- **The rotation list groups by credential type**, so the URL prints once
  per type. Each value's own line shows its redacted preview, file, and
  when it was last seen.
- **Order matters, and the report says so.** The ChainDrop campaign (Aug
  2026) shipped a token monitor that fires an attacker payload the moment a
  stolen GitHub token is revoked. When a scan finds both integrity warnings
  and leaked credentials, the report tells you to remove the planted
  persistence first, rotate second.

Acks and dismissals change what the report *says*, never what CI *does*:
`--fail-on-find` fails on every finding, resolved or not, unless you pass
`--allow-acked` (integrity warnings always fail either way).

## CI and pre-commit

`residoo scan --project <dir>` scans a repository checkout instead of the
machine it runs on: committed transcripts, agent configs, root `.env`
files, plus integrity checks anchored at that directory. It never touches
the machine's home-level sources, so a clean CI run means the checkout is
clean and claims nothing about anyone's laptop.

As a GitHub Action (this repo doubles as a composite action):

```yaml
steps:
  - uses: actions/checkout@v4
  - uses: dandovdub/residoo@v0.4.12
```

As a pre-commit hook:

```yaml
repos:
  - repo: https://github.com/dandovdub/residoo
    rev: v0.4.12
    hooks:
      - id: residoo
```

Or with no integration at all:
`npm install -g residoo && residoo scan --project . --fail-on-find`.
Exit codes and exactly what project mode does and doesn't see are in
[docs/ci.md](docs/ci.md).

## What it does not do

> [!IMPORTANT]
> **No network calls in the default path, and none at all unless you pass
> `--upload-cloudroam` or `--verify`.** A secret scanner that phones home
> is not a tool you should trust with your secrets. Every network-capable
> call in the codebase lives behind one of those two flags: verify it
> yourself in [`src/sealvault.js`](src/sealvault.js) and
> [`src/verify.js`](src/verify.js).

- **Nothing destructive, ever.** Scanning is read-only. Sealing creates
  *new* files and modifies or deletes nothing, not even the plaintext it
  just encrypted a copy of.
- **No telemetry, no analytics, no update-check ping.**

## Install

```bash
npx residoo scan
```

or install it properly:

```bash
npm install -g residoo
residoo scan
```

```bash
brew tap dandovdub/residoo
brew install residoo
```

The Homebrew formula installs the exact tarball published to npm (sha256
verified): same bits, not a second build.

Requires Node.js 18+ (22.5+ for the SQLite-backed sources listed below;
residoo still runs fine without it). Zero runtime dependencies: check
`package.json` rather than take that on faith.

## Usage

```
residoo scan [options]

  --json                  machine-readable output (full detail, still redacted)
  --project [dir]         scan a repository checkout instead of this machine
                          (committed transcripts, agent configs, root .env)
  --include-noisy         also run broad, false-positive-prone rules
  --include-suppressed    also show matches that looked like placeholder/example text
  --fail-on-find          exit code 1 if anything is found (for CI): secret
                          findings and integrity warnings count, review items don't
  --allow-acked           with --fail-on-find: acknowledged findings no longer
                          fail the run (pending ones and warnings still do)
  --no-integrity          skip the integrity checks
  --no-color              disable ANSI colour
  --verify                ask each credential's own vendor if it still authenticates
                          (real network call; see "Verifying credentials are still live")

  --seal                  encrypt every transcript with findings into a local vault
  --vault-dir <dir>       vault location (default ./residoo-vault-<stamp>)
  --upload-cloudroam      also upload the sealed vault (needs CLOUDROAM_API_KEY,
                          --connector <id>, --bucket <name>; ciphertext only)

residoo explain <rule-id>                           full rotation runbook for one rule
residoo explain --list                              every rule id and label
residoo ack <fingerprint> [--note <text>]           mark one finding rotated

residoo unseal <vault-dir>                          list a vault's contents
residoo unseal <vault-dir> --restore <n> --out <p>  restore one file, hash-verified
```

The vault passphrase comes from `RESIDOO_PASSPHRASE` or a hidden interactive
prompt. There is no recovery if you lose it, so pick one you keep.

## Sources supported today

43 sources: 42 transcript stores plus the agent-config source above, in two
honestly-distinct tiers. `--project` adds one more, opt-in source that
scans a checkout instead of the machine.

**Real-install-verified**: run against an actual, populated installation
and confirmed to find real content: **Claude Code**
(`~/.claude/projects/**/*.jsonl`) and **agent config files** for its
Claude-family paths.

**Multi-source-corroborated-but-unverified**: backed by 2+ independent,
credible sources but not checked against a real install on any machine this
project was built on. Still built to fail loudly rather than silently
report "all clear":

Cursor, Codex CLI, OpenCode, Aider, Cline, Roo Code, Kilo Code, Windsurf,
PearAI, Trae, Void, Gemini CLI, Qwen Code, Continue, Open Interpreter,
Goose, GitHub Copilot Chat/CLI, `llm`, Codebuff, Mentat, Hermes, OpenClaw,
Warp, Crush, Grok Build, Kiro CLI/IDE, Zed, JetBrains Junie/AI Assistant,
Sourcegraph Cody, Amazon Q Developer, Qodo Gen, OpenHands, Factory Droid
CLI, Devin CLI, Pi, Google Antigravity, Kimi Code, and `fx`.

A few are SQLite-backed (Cursor, Crush, Cody, Devin CLI, Hermes, Kiro CLI,
`llm`, Trae, Void, Warp, Zed) and need Node.js 22.5+ for the built-in
`node:sqlite` module. On an older Node, each reports as detected-but-not-
scanned rather than silently dropping.

**Investigated and deliberately not included:** Plandex (client-server,
nothing local to scan), CodeGPT and Augment Code (account/cloud-based, no
local transcript file), Replit Agent (cloud-only). Tabby, Tabnine,
Zencoder, Tongyi Lingma, and Berd didn't clear the 2-independent-source bar
in the time available. A verified adapter for any of these is a welcome PR.

See [`src/sources/index.js`](src/sources/index.js) for the full list, and
each source file's own header for exactly what was and wasn't checked.

## Adding a source

A source is a small object with four methods: `id()`, `label()`,
`available()`, `files()`, `readLines(file)`.
[`src/sources/claude-code.js`](src/sources/claude-code.js) is the reference
implementation: copy it, point it at your tool's real local storage path,
open a PR. Two contracts worth getting right:

- **`files()`** yields `{ file, mtimeMs, sizeBytes, broken }`. Set
  `broken: true` for an entry that looked scannable but wasn't (a dangling
  symlink); don't just skip past it silently.
- **`readLines(file)`** is `async`, returning `{ lines, status, bytesRead }`
  with `status` one of `"complete"`, `"partial"`, `"too-large"`, `"failed"`.
  Whatever's in `lines` for a non-`"complete"` status still gets scanned.

Please verify the path actually exists and holds real content before
submitting.

## A known limitation, stated plainly

Shape-based detection can't tell a real secret from a realistic-looking
example in a fetched web page or documentation your agent read back to
you. Three suppression layers narrow the gap (known vendor-documented
example values, placeholder bodies built from one repeated character, and
placeholder-looking surrounding context), but none catches every case, and
all are re-includable with `--include-suppressed`. Treat every finding as a
lead to check, not a certainty. The same is true of every tool in this
category, including the well-established ones.

## License

MIT. See `LICENSE`.

---

Built and maintained by the team behind [CloudRoam](https://cloudroam.io),
client-side encrypted, cross-cloud backup. residoo has no dependency on
CloudRoam and never will need one to be useful. If a scan turns up something
you want stored somewhere durable and encrypted going forward, that's the
kind of problem CloudRoam solves, but it's an entirely separate choice from
running this tool.
