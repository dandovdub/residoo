# Contributing to residoo

Thanks for considering it. This project is small on purpose — the whole value
proposition is that a stranger can audit it in one sitting — so the bar for
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
4. **Output stays redacted.** The raw matched value may exist in memory for
   dedup counting and inside `redact()` — nowhere else, and never in any
   output format, error message, or log line.
5. **Never a false "all clear."** A file that couldn't be read, a dangling
   symlink, a source at a guessed path — all of it must be *surfaced*, not
   silently skipped. This principle has caught real bugs here more than once.

## Adding a transcript source (the most-wanted contribution)

Copy `src/sources/claude-code.js` as your template — it is the reference
implementation and its comments explain the two contracts `scan.js` depends on:

- `files()` yields `{ file, mtimeMs, sizeBytes, broken }` — and reports
  unresolvable entries as `broken: true` rather than skipping them silently.
- `readLines(file)` is async and returns `{ lines, status, bytesRead }` with
  status `"complete" | "partial" | "too-large" | "failed"` — and on a partial
  failure it returns the lines it DID read, because a secret in the part that
  succeeded is still a finding.

Then register it in `src/sources/index.js`.

**Verify the real path before opening the PR.** Run your adapter against an
actual installation of the tool and confirm it finds real transcript content.
A PR that guesses at a storage path will be declined even if the code is
clean: a scanner that checks the wrong place and reports "no secrets found"
is worse than one that admits it doesn't support the tool. Say in the PR what
you verified against (tool + version + OS).

Note for Cursor/Copilot specifically: their history lives in SQLite
(`state.vscdb`), which the current line-based engine cannot read. Supporting
them properly is an architecture discussion (built-in `node:sqlite` needs
Node 22.5+; a dependency violates rule 1) — open an issue first so the
tradeoff gets decided deliberately, not inside a PR.

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

## Tests

`npm test` runs `tests/smoke.js` — zero-dep, synthetic fixtures, exits
nonzero on failure. CI runs it on Node 18/20/22 plus a syntax check of every
file. If your change touches sealing or redaction, extend the smoke tests to
cover it; the deeper adversarial passes recorded in `SECURITY.md` are run
before releases, not per-PR.

## Security issues

Not in the public tracker — see [SECURITY.md](SECURITY.md).
