# Contributing to residoo

Thanks for considering it. This project is small on purpose. The whole value
proposition is that a stranger can audit it in one sitting, so the bar for
changes is "keeps it auditable," not "adds more."

## Ground rules (these are the product, not preferences)

1. **Zero runtime dependencies.** No exceptions. A secret scanner asking users
   to trust a dependency tree defeats its own purpose. If a feature needs a
   package, the feature changes until it doesn't.
2. **No network calls in the scan path, ever.** The single permitted network
   feature is the explicit `--upload-cloudroam` flag, which transmits
   ciphertext only. Anything that phones home, checks for updates, or collects
   telemetry will be rejected regardless of intent.
3. **Scanning stays read-only; nothing is ever destructive.** Sealing creates
   new files. No code in this repo may modify or delete an existing file.
   One disclosed carve-out: `residoo ack` maintains residoo's own state file,
   `~/.residoo/rotations.json` (the rotation acknowledgement ledger). It is
   residoo's file in residoo's directory, written atomically (temp file plus
   rename, mode 0600), it never contains a raw secret (ack notes go through
   the same redaction pipeline as previews), and it is the only file residoo
   ever writes outside an explicit `--seal`. Nothing else may claim this
   carve-out; a change that writes anywhere else will be rejected.
4. **Output stays redacted.** The raw matched value may exist in memory for
   dedup counting and inside `redact()`. Nowhere else, and never in any
   output format, error message, or log line.
5. **Never a false "all clear."** A file that couldn't be read, a dangling
   symlink, a source at a guessed path: all of it must be *surfaced*, not
   silently skipped. This principle has caught real bugs here more than once.

## Adding a transcript source (the most-wanted contribution)

Copy `src/sources/claude-code.js` as your template. It is the reference
implementation and its comments explain the two contracts `scan.js` depends on:

- `files()` yields `{ file, mtimeMs, sizeBytes, broken }`, and reports
  unresolvable entries as `broken: true` rather than skipping them silently.
- `readLines(file)` is async and returns `{ lines, status, bytesRead }` with
  status `"complete" | "partial" | "too-large" | "failed"`. On a partial
  failure it returns the lines it DID read, because a secret in the part that
  succeeded is still a finding.

Then register it in `src/sources/index.js`.

A source does not have to be a transcript store. `src/sources/agent-configs.js`
scans agent **config** files (settings, MCP server configs, memory files)
through the identical `{ id, label, available, files, readLines }` contract;
the engine matches raw text lines either way, so JSON/TOML/Markdown configs
need no special handling. What a config source changes is the *scope
reasoning*, not the code: its header must state which files are deliberately
excluded and why (credential vaults that hold secrets by design, paths
another source already covers), because a config source that silently
overlaps a transcript source double-reports every finding. The verification
bar is unchanged: every path scanned needs a real install or 2+ independent
published sources behind it, cited in the header. `agent-configs.js` carries
the one disclosed exception, a path hunted by a published stealer target
list but backed by only that single source, argued explicitly in its
header. An exception has to be argued in the open like that, never slipped
past the bar.

**Verify the real path before opening the PR.** Run your adapter against an
actual installation of the tool and confirm it finds real transcript content.
A PR that guesses at a storage path will be declined even if the code is
clean: a scanner that checks the wrong place and reports "no secrets found"
is worse than one that admits it doesn't support the tool. Say in the PR what
you verified against (tool + version + OS).

One source lives outside the registry on purpose: `src/sources/
project-artifacts.js`, the `--project` (repo checkout) source. A project scan
needs a parameter (which directory), and the registry holds parameterless
singletons, so its default export is permanently unavailable and the CLI
builds a configured instance via its `withRoot(root)` factory instead. Read
its header before extending it; the inclusion and exclusion lists are
evidence-cited line by line.

**43 sources are supported as of this writing** (42 transcript stores plus
agent-configs, not counting the opt-in project source above). See `src/sources/index.js` for the full registry and its
trust-tier note, and README.md's "Sources supported today" for the same list
from a user's perspective. Only Claude Code and agent-configs' Claude-family
paths are real-install-verified; every other source, Cursor included, is
**multi-source-corroborated-but-unverified**: its path/schema is backed by
2+ independent, credible sources (official docs, the tool's own shipped
source, a real community tool reading the same files, or a real user's
reported install) but has not been checked against a real installation on
any machine this project was built on. This is a real, named gap for all of
them, not glossed over. See each file's own header docstring for exactly
what was and wasn't checked, and its PR/commit description for the research
trail. **If you have any of these tools installed, running `residoo scan`
and confirming the file counts look right for what's actually on your disk
is the single most useful way to move a source out of this tier.** Please
report back either way; a "looks right" is as useful as a bug report.

**Cursor** (`src/sources/cursor.js`) is the reference example for a source
backed by SQLite rather than line-delimited text. Its history lives in
`state.vscdb`, which the line-based engine can't read directly, so it's
handled via the built-in `node:sqlite` module (stable without a flag since
Node 22.5), feature-detected at runtime so a Node runtime older than that
gets a clear "detected but not scanned" message instead of a crash. This
keeps residoo at zero runtime dependencies (rule 1), since `node:sqlite`
ships inside the `node` binary itself, not as a package. Ten more sources
(Crush, Cody, Devin CLI, Hermes, Kiro CLI, `llm`, Trae, Void, Warp, Zed)
follow the identical pattern. Use any of these as the template for a new
SQLite-backed source.

Sources investigated and deliberately **not** included, rather than guessed
at (see `src/sources/index.js`'s docstring for the one-line reason each):
Plandex, CodeGPT, Augment Code, Replit Agent, Tabby, Tabnine, Zencoder,
Tongyi Lingma, Berd. A verified adapter for any of these, or for a tool not
listed anywhere in this file, is a welcome PR. The verification bar above
applies.

## Adding a detection pattern

Patterns live in `src/patterns.js`. High-confidence, vendor-prefixed formats
go in `PATTERNS`; broad shape-based rules go in `NOISY_PATTERNS` (opt-in via
`--include-noisy`). Before submitting:

- Check your regex against the nested-quantifier ReDoS shape (`(x+)+`-style).
  CVE-2026-0621 was exactly this, in a widely used SDK.
- Make sure it can't overlap an existing rule (see the openai/anthropic
  negative-lookahead fix for what that costs when missed: one secret,
  double-counted, one label wrong).
- Add a case to `tests/smoke.js` using synthetic material only. AWS's
  documented example key id (`AKIAIOSFODNN7EXAMPLE`) is the model: officially
  fake, correctly shaped.
- Add a matching entry to `ROTATION_GUIDANCE` in `src/rotation.js`. Every
  rule id must map to rotation guidance, and the smoke tests fail if one is
  missing. A `rotateUrl` may only ship if you fetched that exact URL and
  confirmed it documents rotating or revoking that credential type (cite the
  check in a comment next to the entry); where the vendor's page is
  login-walled or unfetchable, ship a `consolePath` in words instead, with
  the corroboration noted. A guessed URL in remediation advice will be
  rejected outright.
- House style for anything user-facing (labels, steps, notes, help text,
  docs): no em-dashes. Use periods, commas, colons, semicolons, or
  parentheses instead.

## Tests

`npm test` runs `tests/smoke.js`: zero-dep, synthetic fixtures, exits
nonzero on failure. CI runs it on Node 18/20/22 plus a syntax check of every
file. If your change touches sealing or redaction, extend the smoke tests to
cover it; the deeper adversarial passes recorded in `SECURITY.md` are run
before releases, not per-PR.

## Security issues

Not in the public tracker. See [SECURITY.md](SECURITY.md).
