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

Every time Claude Code, Cursor, or a similar tool reads a file, runs a command, or
browses a page on your behalf, it writes a transcript of the whole session to
disk, including the contents of whatever it touched. If that ever included a
`.env` file, a config with a real key in it, or a login token captured during
testing, that credential is now sitting in plaintext, indefinitely, in a place
almost nobody thinks to check.

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

## Why this, and not a git secret scanner

Tools like `gitleaks` and `trufflehog` are excellent at what they do, and what
they do is scan **commits**. That's a different, well-covered space. Nobody was
looking at the **conversation transcripts** these agents leave behind, which
contain a superset of everything a commit does: not just code, but file
contents, terminal output, and whatever got pasted into a prompt.

Two newer categories are adjacent but solve a different problem, worth being
precise about rather than lumping together:

- **Real-time hooks** (e.g. GitGuardian's `ggshield` AI hook, GitHub's secret
  scanning via its MCP server) intercept a prompt or a code change *as it
  happens*, going forward, in the session that has the hook installed. They
  do nothing for the months of transcripts already sitting on disk, or for
  any session run without the hook active. residoo scans **retroactively, at
  rest**: every file already there, from every past session.
- **agentsweep** is a genuine, welcome peer covering similar ground. Broader
  on detection rules (209 to residoo's smaller, deliberately high-confidence
  set) and it does in-place redaction, where residoo's `--seal` makes an
  encrypted copy instead. residoo has more agent sources (43 to 31), and
  both now ship SARIF output and a pre-commit hook. The tradeoffs are worth
  naming precisely rather than either dismissing it or copying it blindly.
  It needs Python 3.11+ and three pip packages (all clean ones, on
  inspection; no known CVEs), where residoo needs nothing beyond Node. Its
  own README documents that its in-place redaction leaves the pre-redaction
  original sitting in a **plaintext** `.bak` file, and its issue tracker shows
  the real cost of that design: a merged fix
  ([PR #13](https://github.com/Ishannaik/agent-sweep/pull/13)) for a case
  where redacting a WAL-mode SQLite database left the secret recoverable from
  a leftover journal file. residoo's `--seal` takes a different tradeoff
  (encrypt a copy, touch nothing, never claim a file is "cleaned") precisely
  to avoid that failure class. Its tracker also shows several real,
  since-fixed false-*clean* reports: schema drift and malformed lines
  silently skipped, `--root` pointed at a file scanning nothing and exiting
  0. That is the exact failure mode residoo's `broken`/`partial` status
  contract (see `CONTRIBUTING.md`) exists to make structurally hard to
  reproduce. None of this makes agentsweep bad; it makes for a legitimately
  different set of choices, and its README is honest about its own tradeoffs
  too. Worth a look if broader source coverage matters more to you than a
  minimal dependency footprint.

This isn't a gap Anthropic is planning to close upstream, either: a
[request to scrub secrets from `~/.claude/projects` natively](https://github.com/anthropics/claude-code/issues/50014)
was filed and closed as **not planned**. Whatever scans this directory, it
won't be built into the tool that writes it.

## What it does

- Scans your local AI-agent session transcripts for high-confidence secret
  patterns: cloud provider keys, private key blocks, OAuth/API tokens,
  database connection strings, and more (see `src/patterns.js`).
- Sees through two transcript-specific disguises. A credential present only
  base64-encoded on a line (an env dump piped through `base64`, wrap
  newlines included) is decoded and rescanned with the high-confidence
  vendor-prefixed rules; the report marks it `base64-wrapped` and redacts
  the decoded value. A credential split across two adjacent streaming
  records, contiguous on neither line, is rejoined at the content boundary
  and rescanned; the report marks it `split across lines` with the line
  pair. Both are general mechanisms with stated limits (one decode level,
  no base64 blocks spanning physical lines, two-way splits only; see
  `src/decode.js`).
- Covers Stripe keys in both modes: live (`sk_live`/`rk_live`) and test
  (`sk_test`/`rk_test`), because a leaked test key still holds real
  permissions in its sandbox and reveals account structure.
- Pairs an AWS secret access key (40 base64 characters, no vendor prefix, not
  a rule on its own) with a nearby confirmed access key id, and reports both
  at high confidence: the pairing is the vendor-specific signal, not the
  shape alone. Ambiguous pairings (more than one candidate nearby) are
  reported as nothing rather than a guess. See `src/pairing.js`.
- With `--include-noisy`, filters the broad generic-secret rules by how
  machine-random the matched value actually looks (a lightweight, offline
  approximation of BPE-tokenization rarity checks): ordinary English, a
  placeholder, or a variable name is suppressed with its own stated reason
  instead of padding the count; a value that reads as random gets its
  confidence raised to `medium`. Never applied to the default high-confidence
  rules. See `src/rarity.js`.
- Redacts everything in its own output. You get a shape and a first/last-4
  preview, never the real value, including in `--json` mode. A decoded or
  rejoined secret is redacted exactly like a plain one.
- `--sarif` emits SARIF 2.1.0 for GitHub code scanning's Security tab and
  inline pull-request annotations, the same format gitleaks/trufflehog/
  agentsweep already speak, so residoo's own Action and pre-commit hook plug
  straight into GitHub's native UI. `--json` remains the format for the full
  picture (findings, integrity, rotation) together.
- `--seal --keychain` stores the vault key in the OS's own secure credential
  store (macOS today, Linux with `secret-tool` installed) instead of a typed
  passphrase: nothing to remember, and a truly random key instead of one
  whose strength depends on what you typed. Tradeoff stated plainly: a
  keychain-backed vault lives on that machine/account only, a passphrase
  travels, a keychain-backed key does not. See `src/keychain.js`.
- Tells you how many **distinct** secrets it found versus how many times one
  got echoed back across tool calls, so the headline number reflects real
  exposure, not repetition.
- Flags likely placeholder/example matches (an HTML form's
  `placeholder="AKIA..."` hint, a doc's example key) separately from real
  findings, rather than either hiding them or inflating the count with them.
- Scans agent **config** files too (settings, MCP server configs, memory
  files), and checks the places the 2026 supply-chain campaigns planted
  persistence: hooks, dropper scripts, auto-run tasks, invisible Unicode.
  See the next section.
- Attaches a **rotation runbook** to every finding: the vendor's real
  revocation path, verified against their own docs, plus a local
  acknowledgement ledger so "found it" can become "closed it". See
  [Rotation](#rotation-from-found-to-closed).
- Scans a **repository checkout** instead of the machine with
  `--project <dir>`: committed transcripts, agent configs, and root `.env`
  files, built for CI and pre-commit. See
  [CI and pre-commit](#ci-and-pre-commit).

## Beyond transcripts: configs and planted persistence

Transcripts leak what your agent *saw*. Config files leak what your agent was
*configured with*, and it turns out that is the better-measured problem.
GitGuardian counted 24,008 secrets inside MCP config files on public GitHub
(2,117 still valid when checked), and Lakera found live credentials inside
`.claude/settings.local.json` files shipped in roughly 30 published npm
packages, because Claude Code's approved-command cache quietly accumulates
tokens and no packaging tool ignores `.claude/` by default. So as of v0.2.0,
`residoo scan` includes an **agent config source** covering the home-level
config files of Claude Code, Claude Desktop, Cursor, Gemini CLI, Codex, and
Kiro. As of v0.3.1 it also reaches project-level Claude Code configs
(`.mcp.json`, `.claude/settings.json`, `.claude/settings.local.json`) by
resolving the project roots the agent itself recorded at home level
(`~/.claude.json` and transcript `cwd` fields) rather than by walking or
guessing directories; only those vendor-fixed per-project filenames are read. Every path is verified against a real install or published sources (one
disclosed exception, a stealer-target path backed by a single published
list, argued openly in the source header), with the full verification trail
written into `src/sources/agent-configs.js`.

The same files are also where the year's supply-chain campaigns planted
their persistence. Mini Shai-Hulud wrote a `SessionStart` hook into
`.claude/settings.json` and a `"runOn": "folderOpen"` task into
`.vscode/tasks.json`. Miasma reused both plants and added
`.gemini/settings.json` hooks and `.cursor/rules/setup.mdc` prompt-injection
files. The keyv/ChainDrop wave dropped a script literally named `setup.mjs`
into `.claude/` and `.vscode/`. And TrapDoor hid instructions in
`CLAUDE.md`/`.cursorrules` as zero-width Unicode: invisible in your editor,
fully visible to the agent. So every scan now also runs **integrity checks**
over those exact locations:

- Every auto-executing hook found in the checked locations is listed (hooks
  run without asking; you should be able to vouch for each one). Only
  commands matching a published campaign IOC (`setup.mjs`) or a
  campaign-shaped behavior escalate to warnings: piping a download straight
  into a shell, decoding base64 before executing, running repo-local scripts
  out of dot-directories.
- Loose scripts in `.claude/`, and the exact planted filenames from the
  published IOC lists, are flagged by name.
- `CLAUDE.md`, `.cursorrules`, and `.cursor/rules/*` are checked for
  zero-width Unicode, with legitimate emoji/script joiners kept to an
  informational tier so the warning count stays meaningful.
- `.vscode/tasks.json` is parsed (as JSONC, comments and all) for tasks that
  execute on folder open.

The checks are read-only like everything else, warnings (not review items)
count toward `--fail-on-find`, project-level checks cover the directory you
run from, and `--no-integrity` skips the whole thing. A config that exists
but can't be read or parsed is reported as unverified, never silently
counted as clean.

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
  │   36 verified rules       │        hooks · droppers ·         │
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
flag. Everything above the vault happens on every scan; nothing in the
diagram ever modifies or deletes an existing file. The one exception, stated
in the open: `residoo ack` writes residoo's own rotation ledger at
`~/.residoo/rotations.json` (atomic, redacted, never a user file).

## Sealing what it finds

Finding a leaked key in a transcript raises the obvious next question: *now
what?* `--seal` is the answer:

```bash
residoo scan --seal
```

Every transcript that carried a finding is encrypted into a local vault
directory. AES-256-GCM, key derived from your passphrase with scrypt,
streamed, so an 800MB transcript never touches memory whole. The vault's
manifest (the mapping from numbered blobs back to real paths) is itself
encrypted, so the vault doesn't advertise what's inside it even by name.
**Originals are never touched.** Once you've verified a restore works
(`residoo unseal <vault> --restore 0001.sealed --out /tmp/check`, verified
byte-identical via a recorded SHA-256), deleting the plaintext is your
decision, made by you, not by this tool.

Optionally, `--upload-cloudroam` (with `CLOUDROAM_API_KEY`, `--connector`,
`--bucket`) copies the sealed vault to [CloudRoam](https://cloudroam.io) for
durable, cross-cloud storage. **This is the only feature in residoo that
touches the network, it never runs unless you pass the flag, and only
ciphertext is transmitted.** The vault is sealed before upload code ever
executes.

## Rotation: from found to closed

Detection without rotation is theater, and the field's own numbers say so:
64% of secrets leaked publicly in 2022 were still valid years later, 88% of
re-verified leaked AWS keys still authenticated, and the median time to
remediate a GitHub-leaked secret is 94 days. A scanner that stops at "found
it" leaves all of that untouched. So every finding in a residoo report comes
with the way out:

- **A rotation hint per finding**, from a per-rule guidance map covering all
  36 detection rules (plus the opt-in noisy ones). Where a rotation URL is
  shown, that exact URL was fetched and confirmed to document rotating or
  revoking that credential type; where a vendor's docs are login-walled or
  unfetchable, the report gives the console path in words instead of a link
  it could not verify. Generic shapes (a JWT, a bearer header) get honest
  generic guidance that says how to identify the issuer, never a pretend
  vendor.
- **`residoo explain <rule-id>`** prints the full runbook for one credential
  type: where to revoke, the steps, and what revocation actually does at
  that vendor. `residoo explain --list` shows the whole catalogue.
- **`residoo ack <fingerprint>`** records that you rotated one finding.
  Every finding carries a stable fingerprint (derived only from
  already-redacted material, so the ledger can never leak), shown in the
  report and in `--json`. Acknowledged findings are reported as such on the
  next scan instead of re-alarming forever. The ledger lives at
  `~/.residoo/rotations.json`: residoo's own file, written atomically, ack
  notes redacted through the same pipeline as previews.
- **Order matters, and the report says so when it does.** The ChainDrop
  campaign (Aug 2026) shipped a token monitor that fires an attacker payload
  the moment the stolen GitHub token is revoked. When one scan finds both
  integrity warnings and leaked credentials, the report tells you to remove
  the planted persistence first and rotate second, because "rotate
  everything now" advice can itself trigger the damage.

Acks change what the report says, never what CI does: `--fail-on-find`
fails on every finding, acknowledged or not, unless you explicitly pass
`--allow-acked` (integrity warnings always fail either way).

## CI and pre-commit

`residoo scan --project <dir>` scans a repository checkout instead of the
machine it runs on: committed agent transcripts (Claude Code `.jsonl`
trees, Codex `rollout-*.jsonl`, SpecStory histories), agent config and
rules files at any depth, and root-level `.env` files, plus the integrity
checks anchored at that directory. It deliberately does not touch the
machine's home-level sources, so a clean CI run means the checkout is
clean and claims nothing about anyone's laptop.

As a GitHub Action (this repository doubles as a composite action):

```yaml
steps:
  - uses: actions/checkout@v4
  - uses: dandovdub/residoo@v0.3.7
```

As a pre-commit hook:

```yaml
repos:
  - repo: https://github.com/dandovdub/residoo
    rev: v0.3.7
    hooks:
      - id: residoo
```

Or with no integration at all: `npm install -g residoo && residoo scan --project . --fail-on-find`
(more reliable in CI than `npx --yes`, which failed consistently in real
GitHub Actions runs while working fine locally; see the design note at the
top of `action.yml`).
Exit codes, inputs, and exactly what project mode does and does not see are
documented in [docs/ci.md](docs/ci.md).

## What it does not do

- **No network calls in the default path, and none at all unless you
  explicitly pass `--upload-cloudroam`.** A secret scanner that phones home is
  not a tool you should trust with your secrets. Verify this yourself: the one
  `fetch` call in the codebase is in `src/sealvault.js`, reachable only behind
  that flag, and sends only encrypted bytes.
- **Nothing destructive, ever.** Scanning is read-only. Sealing creates *new*
  files and modifies or deletes nothing, not even the plaintext it just
  encrypted a copy of. That last step is deliberately left to a human.
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

A Homebrew formula ships in this repo at `packaging/homebrew/`. It installs
the exact tarball published to npm (same bits, sha256 verified), so Homebrew
is a second door to the same release, not a second build. Once the tap
repository (`dandovdub/homebrew-residoo`) is published, installation is:

```bash
brew tap dandovdub/residoo
brew install residoo
```

Until the tap is up, npm above is the way in. The formula always points at
the latest *published* npm release (its sha256 is computed from the real
tarball), so it can lag a fresh tag by one publish cycle.

Requires Node.js 18+. The SQLite-backed sources listed below additionally
need 22.5+; residoo still runs and scans every line-delimited/JSON source,
including Claude Code, fine without it. Zero runtime dependencies, and you
can check `package.json` rather than take that on faith.

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
prompt. There is no recovery if you lose it. That is the point of the design,
so pick one you keep.

## Sources supported today

43 sources as of this writing (42 transcript stores plus the agent-config
source described above), in two honestly-distinct tiers. Project mode
(`--project`) adds one more, opt-in source (`src/sources/project-artifacts.js`)
that scans a repository checkout rather than the machine and never
participates in a default scan. See
`src/sources/index.js` for the full list and grouping, and each source file's
own header for exactly what was and wasn't checked.

**Real-install-verified.** The adapter was run against an actual, populated
installation and confirmed to find real content:

- **Claude Code** (`~/.claude/projects/**/*.jsonl`)
- **Agent config files**, for its Claude-family paths (`~/.claude.json` and
  its `.backup`, `~/.claude/settings*.json`, Claude Desktop's
  `claude_desktop_config.json`). Its Cursor/Gemini/Codex/Kiro paths are in
  the tier below; `src/sources/agent-configs.js` tracks verification per
  path, not per file.

**Multi-source-corroborated-but-unverified.** The path/schema is backed by
2+ independent, credible sources (official docs, the tool's own shipped
source code, a real community tool that reads the same files for a living,
or a real user's own reported install) but was **not** checked against a real
install of the tool on any machine this project was built on. Every adapter
in this tier is still built to fail loudly (`broken: true`, `status:
"failed"`) rather than silently report "all clear", but the path itself
could still be stale or wrong in a way only a real install can catch. If you
use one of these and can confirm `residoo scan`'s file counts look right for
what's actually on your disk, that report is exactly what moves a source out
of this tier:

Cursor, Codex CLI, OpenCode, Aider, Cline, Roo Code, Kilo Code, Windsurf,
PearAI, Trae, Void, Gemini CLI, Qwen Code, Continue, Open Interpreter, Goose,
GitHub Copilot Chat, GitHub Copilot CLI, `llm` (Simon Willison's Datasette-
adjacent CLI), Codebuff, Mentat, Hermes, OpenClaw, Warp, Crush, Grok Build,
Kiro CLI, Kiro IDE, Zed, JetBrains Junie, JetBrains AI Assistant, Sourcegraph
Cody, Amazon Q Developer, Qodo Gen, OpenHands, Factory Droid CLI, Devin CLI,
Pi, Google Antigravity, Kimi Code, and `fx`.

A few of these are SQLite-backed (Cursor, Crush, Cody, Devin CLI, Hermes,
Kiro CLI, `llm`, Trae, Void, Warp, Zed) and need Node.js 22.5+ for the
built-in `node:sqlite` module (not a dependency; see `package.json`). On an
older Node, `residoo scan` reports each of those as detected-but-not-scanned
rather than silently dropping it or crashing.

**Investigated and deliberately not included**, rather than guessed at:
Plandex (confirmed, from its own source, to be client-server with nothing
local to scan), CodeGPT and Augment Code (both account/cloud-based, no
evidence of a local transcript file), and Replit Agent (confirmed
cloud-only). Tabby, Tabnine, Zencoder, Tongyi Lingma, and Berd were
researched but didn't clear this project's 2-independent-source bar in the
time available. A verified adapter for any of these is a welcome PR.

## Adding a source

A source is a small object with four methods: `id()`, `label()`,
`available()`, `files()`, and `readLines(file)`. `src/sources/claude-code.js`
is the reference implementation. Copy it, point it at the real local
storage path for your tool, and open a PR. Two contracts scan.js actually
depends on, worth getting right rather than guessing from a quick skim:

- **`files()`** is a generator yielding `{ file, mtimeMs, sizeBytes, broken }`.
  Set `broken: true` (other fields can be omitted) for an entry that looked
  like it should be scannable but wasn't; a dangling symlink is the main
  case. Don't just `continue` past it inside the generator. An early version
  of the Claude Code source did exactly that, and a real, non-hypothetical
  case (a project directory relocated via a symlink whose target no longer
  exists) went completely invisible: not in the scan count, not in any
  warning, nothing. Surfacing it as `broken` is what lets scan.js report it
  instead.
- **`readLines(file)`** is `async`, returning `{ lines, status, bytesRead }`.
  `status` is `"complete"`, `"partial"` (some real lines WERE read before a
  failure partway through; return them, don't discard real content because
  the rest of the file didn't finish cleanly), `"too-large"`, or `"failed"`.
  Whatever you return in `lines` for a non-"complete" status still gets
  scanned normally.

Please verify the path actually exists and holds real content before
submitting. See the note above on why that matters here specifically.

## A known limitation, stated plainly

Shape-based detection can't tell a real secret from a realistic-looking
example in a fetched web page or a piece of documentation your agent read
aloud back to you. Three suppression layers narrow the gap: known
vendor-documented example values (AWS's `AKIAIOSFODNN7EXAMPLE` and its
siblings, GitHub's docs tokens, jwt.io's demo token) are suppressed by
exact match; a placeholder body built from one repeated character (no
vendor issues zero-entropy key material) is suppressed by value; and
placeholder-looking context around a match catches the common UI-hint
case. The two value-based layers apply identically to base64-decoded and
boundary-joined findings, since a decoded example is the same non-secret
as a plain one. None of the three catches every case, and all are
re-includable with `--include-suppressed`. Treat every finding as a lead
to check, not a
certainty. The same is true of every tool in this category, including the
well-established ones.

## License

MIT. See `LICENSE`.

---

Built and maintained by the team behind [CloudRoam](https://cloudroam.io),
client-side encrypted, cross-cloud backup. residoo has no dependency on
CloudRoam and never will need one to be useful. If a scan turns up something
you want stored somewhere durable and encrypted going forward, that's the
kind of problem CloudRoam solves, but it's an entirely separate choice from
running this tool.
