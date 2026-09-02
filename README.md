# residoo

**Find secrets leaking through your AI coding agent's session history.**

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

Requires Node.js 18+. Zero runtime dependencies — check `package.json`.

## Usage

```
residoo scan [options]

  --json                  machine-readable output (full detail, still redacted)
  --include-noisy         also run broad, false-positive-prone rules
  --include-suppressed    also show matches that looked like placeholder/example text
  --fail-on-find          exit code 1 if anything is found (for CI)
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

**Claude Code** (`~/.claude/projects/**/*.jsonl`) — verified against real,
populated transcript directories while building this.

Cursor, GitHub Copilot, and Windsurf all keep local session history too, and
support for them is very much wanted — but shipping a scanner that checks a
guessed path and reports "all clear" when it simply didn't know where to
look is worse than not supporting a tool at all. If you use one of these and
want to add a verified adapter, see below — it's a small, self-contained
file.

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
