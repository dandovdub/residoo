# How it works, and what happens once it finds something

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

The vault passphrase comes from `RESIDOO_PASSPHRASE` or a hidden interactive
prompt. There is no recovery if you lose it, so pick one you keep.

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
needed. See [`src/verify.js`](../src/verify.js).

The same mechanism, scoped to one credential per call, is also available
from inside a Claude Code conversation via the `residoo_verify_finding` MCP
tool — see [features.md](features.md#mcp-query-findings-from-inside-claude-code).

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
