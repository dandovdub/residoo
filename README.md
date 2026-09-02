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
browses a page on your behalf, it writes a transcript of the whole session to disk —
including the contents of whatever it touched. If that ever included a `.env` file,
a config with a real key in it, or a login token captured during testing, that
credential is now sitting in plaintext, indefinitely, in a place almost nobody
thinks to check.

residoo scans those transcripts and tells you what's in them.

```
$ residoo scan

⚠  17 potential secrets found across 3 files
   87 files scanned (1.2 GB) · sources: claude-code
   oldest match ~8d old · most recent ~0d old

    16  [high]  AWS Access Key ID   (1 distinct value, re-exposed 15× across tool output)
     1  [high]  Private key block

Values are redacted in this report — first/last 4 characters only. Nothing scanned
here left your machine; residoo makes no network calls.
```

## Why this, and not a git secret scanner

Tools like `gitleaks` and `trufflehog` are excellent at what they do — and what
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
  rest** — every file already there, from every past session.
- **agentsweep** is a genuine, welcome peer covering similar ground — broader,
  in fact: 31 agent sources and 209 detection rules to residoo's smaller set,
  plus in-place redaction, SARIF output, and a pre-commit hook. Worth naming
  the tradeoffs precisely rather than either dismissing it or copying it
  blindly: it needs Python 3.11+ and three pip packages (all clean ones, on
  inspection — no known CVEs), where residoo needs nothing beyond Node. Its
  own README documents that its in-place redaction leaves the pre-redaction
  original sitting in a **plaintext** `.bak` file, and its issue tracker shows
  the real cost of that design: a merged fix
  ([PR #13](https://github.com/Ishannaik/agent-sweep/pull/13)) for a case
  where redacting a WAL-mode SQLite database left the secret recoverable from
  a leftover journal file. residoo's `--seal` takes a different tradeoff —
  encrypt a copy, touch nothing, never claim a file is "cleaned" — precisely
  to avoid that failure class. Its tracker also shows several real,
  since-fixed false-*clean* reports (schema drift and malformed lines
  silently skipped, `--root` pointed at a file scanning nothing and exiting
  0) — the exact failure mode residoo's `broken`/`partial` status contract
  (see `CONTRIBUTING.md`) exists to make structurally hard to reproduce. None
  of this makes agentsweep bad; it makes for a legitimately different set of
  choices, and its README is honest about its own tradeoffs too — worth a
  look if broader source coverage matters more to you than a minimal
  dependency footprint.

This isn't a gap Anthropic is planning to close upstream, either: a
[request to scrub secrets from `~/.claude/projects` natively](https://github.com/anthropics/claude-code/issues/50014)
was filed and closed as **not planned**. Whatever scans this directory, it
won't be built into the tool that writes it.

## What it does

- Scans your local AI-agent session transcripts for high-confidence secret
  patterns (cloud provider keys, private key blocks, OAuth/API tokens,
  database connection strings, and more — see `src/patterns.js`).
- Redacts everything in its own output. You get a shape and a first/last-4
  preview, never the real value — including in `--json` mode.
- Tells you how many **distinct** secrets it found versus how many times one
  got echoed back across tool calls, so the headline number reflects real
  exposure, not repetition.
- Flags likely placeholder/example matches (an HTML form's
  `placeholder="AKIA..."` hint, a doc's example key) separately from real
  findings, rather than either hiding them or inflating the count with them.
- Scans agent **config** files too (settings, MCP server configs, memory
  files), and checks the places the 2026 supply-chain campaigns planted
  persistence — hooks, dropper scripts, auto-run tasks, invisible Unicode.
  See the next section.

## Beyond transcripts: configs and planted persistence

Transcripts leak what your agent *saw*. Config files leak what your agent was
*configured with* — and it turns out that is the better-measured problem.
GitGuardian counted 24,008 secrets inside MCP config files on public GitHub
(2,117 still valid when checked), and Lakera found live credentials inside
`.claude/settings.local.json` files shipped in roughly 30 published npm
packages, because Claude Code's approved-command cache quietly accumulates
tokens and no packaging tool ignores `.claude/` by default. So as of v0.2.0,
`residoo scan` includes an **agent config source** covering the home-level
config files of Claude Code, Claude Desktop, Cursor, Gemini CLI, Codex, and
Kiro — every path verified against a real install or published sources (one
disclosed exception, a stealer-target path backed by a single published
list, argued openly in the source header), with the full verification trail
written into `src/sources/agent-configs.js`.

The same files are also where the year's supply-chain campaigns planted
their persistence: Mini Shai-Hulud wrote a `SessionStart` hook into
`.claude/settings.json` and a `"runOn": "folderOpen"` task into
`.vscode/tasks.json`; Miasma reused both plants and added
`.gemini/settings.json` hooks and `.cursor/rules/setup.mdc` prompt-injection
files; the keyv/ChainDrop wave dropped a script literally named `setup.mjs`
into `.claude/` and `.vscode/`; and TrapDoor hid instructions in
`CLAUDE.md`/`.cursorrules` as zero-width Unicode — invisible in your editor,
fully visible to the agent. So every scan now also runs **integrity checks**
over those exact locations:

- Every auto-executing hook found in the checked locations is listed (hooks
  run without asking; you should be able to vouch for each one). Only
  commands matching a published campaign IOC (`setup.mjs`) or a
  campaign-shaped behavior — piping a download straight into a shell,
  decoding base64 before executing, running repo-local scripts out of
  dot-directories — escalate to warnings.
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
but can't be read or parsed is reported as unverified — never silently
counted as clean.

## How it works

```mermaid
flowchart LR
    subgraph machine["Your machine — no network calls"]
        A["Discover transcripts<br/>+ agent configs<br/>43 sources"] --> B["Stream + pattern-match<br/>35 high-confidence rules"]
        A --> G["Integrity checks<br/>planted hooks, droppers,<br/>zero-width Unicode"]
        B --> C["Redacted report<br/>first/last 4 chars only"]
        G --> C
        B -.->|"--seal (optional)"| D["AES-256-GCM vault<br/>scrypt key, encrypted manifest"]
        D --> E["unseal --restore<br/>SHA-256-verified"]
    end
    D -.->|"--upload-cloudroam<br/>optional, explicit flag,<br/>ciphertext only"| F["CloudRoam<br/>encrypted copy"]
```

The dotted legs never run unless you pass their flag.

## Sealing what it finds

Finding a leaked key in a transcript raises the obvious next question: *now
what?* `--seal` is the answer:

```bash
residoo scan --seal
```

Every transcript that carried a finding is encrypted into a local vault
directory — AES-256-GCM, key derived from your passphrase with scrypt, streamed
(an 800MB transcript never touches memory whole). The vault's manifest — the
mapping from numbered blobs back to real paths — is itself encrypted, so the
vault doesn't advertise what's inside it even by name. **Originals are never
touched**: once you've verified a restore works (`residoo unseal <vault> --restore
0001.sealed --out /tmp/check` — verified byte-identical via a recorded SHA-256),
deleting the plaintext is your decision, made by you, not by this tool.

Optionally, `--upload-cloudroam` (with `CLOUDROAM_API_KEY`, `--connector`,
`--bucket`) copies the sealed vault to [CloudRoam](https://cloudroam.io) for
durable, cross-cloud storage. **This is the only feature in residoo that touches
the network, it never runs unless you pass the flag, and only ciphertext is
transmitted** — the vault is sealed before upload code ever executes.

## What it does not do

- **No network calls in the default path — and none at all unless you
  explicitly pass `--upload-cloudroam`.** A secret scanner that phones home is
  not a tool you should trust with your secrets. Verify this yourself: the one
  `fetch` call in the codebase is in `src/sealvault.js`, reachable only behind
  that flag, and sends only encrypted bytes.
- **Nothing destructive, ever.** Scanning is read-only. Sealing creates *new*
  files and modifies or deletes nothing — not even the plaintext it just
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

Requires Node.js 18+ (the SQLite-backed sources listed above additionally
need 22.5+; residoo still runs and scans every line-delimited/JSON source,
including Claude Code, fine without it). Zero runtime dependencies — check
`package.json`.

## Usage

```
residoo scan [options]

  --json                  machine-readable output (full detail, still redacted)
  --include-noisy         also run broad, false-positive-prone rules
  --include-suppressed    also show matches that looked like placeholder/example text
  --fail-on-find          exit code 1 if anything is found (for CI) — secret
                          findings and integrity warnings count, review items don't
  --no-integrity          skip the integrity checks
  --no-color              disable ANSI colour

  --seal                  encrypt every transcript with findings into a local vault
  --vault-dir <dir>       vault location (default ./residoo-vault-<stamp>)
  --upload-cloudroam      also upload the sealed vault (needs CLOUDROAM_API_KEY,
                          --connector <id>, --bucket <name>; ciphertext only)

residoo unseal <vault-dir>                          list a vault's contents
residoo unseal <vault-dir> --restore <n> --out <p>  restore one file, hash-verified
```

The vault passphrase comes from `RESIDOO_PASSPHRASE` or a hidden interactive
prompt. There is no recovery if you lose it — that is the point of the design,
so pick one you keep.

## Sources supported today

43 sources as of this writing — 42 transcript stores plus the agent-config
source described above — in two honestly-distinct tiers. See
`src/sources/index.js` for the full list and grouping, and each source file's
own header for exactly what was and wasn't checked.

**Real-install-verified** — the adapter was run against an actual, populated
installation and confirmed to find real content:

- **Claude Code** (`~/.claude/projects/**/*.jsonl`)
- **Agent config files**, for its Claude-family paths (`~/.claude.json` and
  its `.backup`, `~/.claude/settings*.json`, Claude Desktop's
  `claude_desktop_config.json`); its Cursor/Gemini/Codex/Kiro paths are in
  the tier below — `src/sources/agent-configs.js` tracks verification per
  path, not per file

**Multi-source-corroborated-but-unverified** — the path/schema is backed by
2+ independent, credible sources (official docs, the tool's own shipped
source code, a real community tool that reads the same files for a living,
or a real user's own reported install) but was **not** checked against a real
install of the tool on any machine this project was built on. Every adapter
in this tier is still built to fail loudly (`broken: true`, `status:
"failed"`) rather than silently report "all clear" — but the path itself
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
built-in `node:sqlite` module (not a dependency — see `package.json`); on an
older Node, `residoo scan` reports each of those as detected-but-not-scanned
rather than silently dropping it or crashing.

**Investigated and deliberately not included**, rather than guessed at:
Plandex (confirmed, from its own source, to be client-server with nothing
local to scan), CodeGPT and Augment Code (both account/cloud-based, no
evidence of a local transcript file), and Replit Agent (confirmed
cloud-only). Tabby, Tabnine, Zencoder, Tongyi Lingma, and Berd were
researched but didn't clear this project's 2-independent-source bar in the
time available — a verified adapter for any of these is a welcome PR.

## Adding a source

A source is a small object with four methods: `id()`, `label()`,
`available()`, `files()`, and `readLines(file)`. `src/sources/claude-code.js`
is the reference implementation — copy it, point it at the real local
storage path for your tool, and open a PR. Two contracts scan.js actually
depends on, worth getting right rather than guessing from a quick skim:

- **`files()`** is a generator yielding `{ file, mtimeMs, sizeBytes, broken }`.
  Set `broken: true` (other fields can be omitted) for an entry that looked
  like it should be scannable but wasn't — a dangling symlink is the main
  case. Don't just `continue` past it inside the generator: an early version
  of the Claude Code source did exactly that, and a real, non-hypothetical
  case (a project directory relocated via a symlink whose target no longer
  exists) went completely invisible — not in the scan count, not in any
  warning, nothing. Surfacing it as `broken` is what lets scan.js report it
  instead.
- **`readLines(file)`** is `async`, returning `{ lines, status, bytesRead }`.
  `status` is `"complete"`, `"partial"` (some real lines WERE read before a
  failure partway through — return them, don't discard real content because
  the rest of the file didn't finish cleanly), `"too-large"`, or `"failed"`.
  Whatever you return in `lines` for a non-"complete" status still gets
  scanned normally.

Please verify the path actually exists and holds real content before
submitting — see the note above on why
that matters here specifically.

## A known limitation, stated plainly

Shape-based detection can't tell a real secret from a realistic-looking
example in a fetched web page or a piece of documentation your agent read
aloud back to you. The `--include-suppressed`/placeholder-context heuristic
catches the common UI-hint case, not every case. Treat every finding as a
lead to check, not a certainty — the same is true of every tool in this
category, including the well-established ones.

## License

MIT. See `LICENSE`.

---

Built and maintained by the team behind [CloudRoam](https://cloudroam.io) —
client-side encrypted, cross-cloud backup. residoo has no dependency on
CloudRoam and never will need one to be useful; if a scan turns up something
you want stored somewhere durable and encrypted going forward, that's the
kind of problem CloudRoam solves, but it's an entirely separate choice from
running this tool.
