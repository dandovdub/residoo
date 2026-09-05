# Beyond scan: watch, MCP, cred, guard

`residoo scan` is one snapshot. The four commands below extend that same
engine to run continuously, to be queried from inside Claude Code itself,
to remove the reason a credential gets pasted into chat in the first
place, and to block one narrow class of leak before it happens at all.

## Watch: continuous scanning

`residoo scan` is a snapshot. `residoo watch` is the same engine run
continuously: it polls every source `scan` already covers, and the moment a
new secret lands in a transcript, prints an alert with the redacted value,
the rule, the file, and the same rotation runbook a scan finding carries,
instead of waiting for you to remember to run `scan` again.

```
$ residoo watch
watching 44 sources, 118 files (61 tailed, 57 rescanned on change)
polling every 5s; fs.watch is not used, every alert comes from polling

2026-09-03 14:02:11  [high]  AWS Access Key ID  AKIA****ABCD
  claude-code · session-9f2c.jsonl:214 · rf1-8a3e91  Rotate: https://.../access_keys
```

It is watch-from-**now**: run `residoo scan` first for anything already on
disk, since a fresh `residoo watch` baselines whatever it finds on its first
sweep silently and only alerts on content written after it starts. A finding
already acknowledged or dismissed (`residoo ack` / `residoo dismiss`) stays
suppressed, checked against the same `~/.residoo/rotations.json` ledger, and
a ledger change made mid-watch takes effect within one poll interval, no
restart needed. A findings-free sweep prints nothing at all, including to
its own watched Claude Code session, by design: no other tool in this
project's own benchmark ([`bench/`](../bench/)) has a continuous mode at all,
verified directly against each one's own `--help` output rather than
assumed; see [comparison.md](comparison.md) for how the one adjacent thing,
GitGuardian's `ggshield` AI hook, works differently.

A genuinely new finding also fires an OS desktop notification by default --
`osascript` on macOS, `notify-send` on Linux if installed, and on Windows,
`System.Windows.Forms.NotifyIcon`'s balloon-tip API (chosen over WinRT
toast interop after research found toasts need a registered
AppUserModelID as a hard prerequisite for any desktop app; NotifyIcon has
no such requirement). The terminal line above is still written either
way; the notification is decoration on top of it, for the realistic case
that nobody is staring at the terminal a background watch process runs in.
A re-exposure of a secret already alerted on never notifies again --
otherwise a single leaked value re-appearing on every future scan would
turn a quiet, healthy watch into a notification-spamming one -- and neither
does `--json` mode, since that output is for a pipe or a log shipper, not a
human at a desktop.

```
residoo watch [options]

  --interval <seconds>    how often to check for new content (default 5, minimum 1)
  --json                  NDJSON events on stdout, one line per finding/re-exposure
  --verify                same opt-in vendor check as scan --verify, applied to
                          each newly found credential once
  --no-notify             skip the desktop notification, keep the terminal line
  --include-noisy, --include-suppressed, --include-pii, --no-color   same meaning as scan
```

## MCP: query findings from inside Claude Code

`residoo mcp` runs residoo as an MCP server over stdio, so Claude Code can
query findings and manage the rotation ledger conversationally instead of
you running the CLI in a terminal:

```bash
claude mcp add residoo -- residoo mcp
```

or run `scripts/install-mcp.sh` (also in this repo), which installs residoo
itself first if it isn't already, then registers it and verifies the
connection.

or add it directly to `.mcp.json`:

```json
{
  "mcpServers": {
    "residoo": { "type": "stdio", "command": "residoo", "args": ["mcp"] }
  }
}
```

residoo's own repo ships both `.mcp.json` (above) and a
`.claude-plugin/plugin.json` at its root, so `claude mcp list` run from
inside a clone of this repo already finds and connects to it with no
setup at all -- verified directly (`claude plugin validate .` passes,
`claude mcp list` reports `residoo: residoo mcp - ✓ Connected`). Once
listed in Claude Code's community plugin marketplace, installation
becomes `/plugin install residoo@claude-community` from any project,
no `.mcp.json` of your own needed; until then, the two methods above
work from anywhere `residoo` is already on PATH (npm or Homebrew).

Five read-only tools, mirroring the CLI exactly: `residoo_scan` (a fresh
scan, merged with rotation status), `residoo_check` (only what's new
since the last check in this conversation, backed by the same engine as
`watch`), `residoo_explain` (a rule's rotation runbook), and
`residoo_ack` / `residoo_dismiss` (append to the local ledger). Every
value returned is redacted the same way the CLI's own output is; nothing
here makes a network call or touches the transcript files themselves.
Like the rest of residoo, this is hand-rolled against the MCP spec
directly, not built on `@modelcontextprotocol/sdk`: zero runtime
dependencies stays true here too. A sixth, opt-in tool exists for
injected-credential execution, covered below under Cred.

A seventh tool, `residoo_verify_finding`, is genuinely different from the
other six: it asks a credential's own vendor, live, whether it's still
active (the same mechanism as `scan --verify`, scoped to exactly one
credential per call). This is the one MCP tool that makes a real network
call, so it does not exist at all unless you set
`RESIDOO_MCP_ALLOW_VERIFY=1` in the environment `residoo mcp` runs in — a
default install stays true to "zero network calls" without a caveat.
Once enabled, pass a `fingerprint` from a prior `residoo_scan`; you get
back `active`, `invalid`, or `unknown`, never the raw value. Paired
credentials (AWS access key + secret, PlanetScale, MongoDB Atlas) aren't
supported yet — use `residoo scan --verify` from a terminal for those.

## Cred: run commands with injected credentials

The usual way an AI coding agent ends up able to use a real credential is
you pasting it into the chat, which puts it in that conversation's
transcript forever, indistinguishable from any other leak `residoo scan`
finds. `residoo cred` is the alternative: store the credential once in
your OS keychain, then let Claude run one allow-listed command with it
injected as environment variables. Claude never sees the raw value,
before, during, or after, and it's never written into a script either.

```bash
residoo cred set aws-prod --env AWS_ACCESS_KEY_ID --env AWS_SECRET_ACCESS_KEY
# hidden-typed input, once per --env flag; interactive TTY only, no
# scripted entry, since a live credential is more sensitive than a vault
# passphrase and should never be typeable into a script or env var.

RESIDOO_CRED_ALLOWED_COMMANDS="aws=/usr/local/bin/aws" residoo mcp
# now residoo_run_with_cred exists as an MCP tool; it does not exist at
# all (won't appear in the tool list) until this is set.

residoo cred run aws-prod -- aws s3 ls
# same operation from a terminal, for testing without an MCP client.
```

### Why a pasted credential doesn't actually go away when the conversation compacts

A long AI coding session eventually gets **compacted**: older turns are
summarized down so the conversation can keep going inside a limited
context window. That summarization changes what the *model* sees, not
what's on *disk* — the original transcript file is append-only, and
compaction never edits or deletes a line already written to it. That's the
same reason `residoo scan` can still find a credential pasted weeks or
months ago: it never left. A summary is also, by nature, lossy: an exact,
character-for-character secret is precisely the kind of detail a summary
drops even while preserving the gist of what happened, so the practical
result is the model can no longer reliably reproduce the value it was
given earlier. The common failure mode that follows is pasting the same
credential back in again, which just creates a second copy sitting in a
second file. `residoo cred` breaks that loop at the source: the credential
lives once, outside any conversation, and gets injected fresh on every
`cred run` — nothing for compaction to lose, nothing to paste back in.

**Why this is safer than it looks, stated precisely, not just asserted:**

- `RESIDOO_CRED_ALLOWED_COMMANDS` (`name=/absolute/path,...`) is an
  environment variable the operator sets outside any conversation, read
  fresh on every single invocation. Empty or unset means **nothing may
  run, by design**: this is the actual, sole security boundary.
- The `command` a caller (human or model) supplies is used **only as a
  lookup key** into that map, never as a path, never resolved via
  `PATH`. This was not always true: a first draft matched by binary
  *name* alone (checked fresh every call, but only verifying the name the
  caller claimed, not the binary that actually ran), and an adversarial
  review found two concrete ways around that: a caller-supplied path
  smuggled straight past the check, and a same-named malicious binary
  planted earlier on the server process's own inherited `PATH`. Both are
  closed structurally now: `command` cannot cause any file other than the
  operator-pinned absolute path to execute, full stop.
- Arguments are always a structured list, never a shell string, so no
  shell metacharacter ever gets interpreted.
- The executed command's own stdout/stderr content is **never returned**,
  only exit status and line counts, because that output is itself a
  channel the injected secret could leak through in ways no redaction
  pass can guarantee to catch (an echoed variable, a stack trace).
- A hung command is killed after 30 seconds, not configurable by the
  caller (letting a model choose its own timeout has no legitimate use
  and only helps an attacker keep a process alive longer).
- One line goes to `residoo mcp`'s own **stderr** per credential use
  (timestamp, credential name, command, exit code, never the value or
  the arguments). This is **not durable by default**: redirect the MCP
  server's stderr at launch (`residoo mcp 2>> ~/.residoo-cred-audit.log`,
  or your MCP client's equivalent) if you want a persistent trail.

**Only ever allow-list narrow, single-purpose CLIs**, never a tool that
can itself run arbitrary third-party code as part of normal operation
(`npm`, `npx`, `pip`, `make`, `cargo`, any build tool). Watch out even for
a seemingly narrow tool with its own plugin system: an allow-listed `gh`
still receives the injected credential as an inherited environment
variable in whatever `gh extension exec` or `gh alias` runs, which is
untrusted the moment it's a third-party extension. This is a residual
risk allow-listing alone doesn't remove, so narrow the tools you allow-list
accordingly, and prefer credentials scoped as tightly as the vendor
allows.

Storage is macOS (`security`) or Linux (`secret-tool`) only -- genuinely
unsupported on Windows, not just undone yet: `cmdkey.exe` (Windows
Credential Manager's own CLI) is confirmed write/list-only by Microsoft's
own documentation, never returning a stored password back out, so there
is no named store-then-retrieve mechanism to use without adding a
dependency. Refused with a clear message rather than half-built. This is
now DIFFERENT from `--seal --keychain`'s own platform support (see
[Sealing what it finds](architecture.md#sealing-what-it-finds)), which
Windows does support via DPAPI -- that feature only ever needs to wrap and
unwrap a key living inside its own vault directory, never a named lookup
by credential name the way `residoo cred` needs. There is no `residoo cred
list` in v1: you need to already know the name you set.

## Guard: block a sensitive read, a sensitive prompt, or a sensitive output

Everything above finds a leak after it's already written to disk. `residoo
guard` is one binary covering three Claude Code hooks, dispatched on the
payload's own `hook_event_name` field, that all try to stop a leak from
happening (or from reaching the model at all) instead of finding it
afterward.

**`PreToolUse`** blocks an obviously-sensitive file read (`.env`,
`id_rsa`, `.aws/credentials`, and similar) before the command runs at all
— based on WHAT you're about to touch (a path), not what actually comes
back.

**`UserPromptSubmit`** closes the "typed directly into a prompt" gap
`PreToolUse` can't: Claude Code's own docs (`code.claude.com/docs/en/hooks`,
read directly, not summarized secondhand) confirm it "runs before every
prompt and blocks model processing until it completes," and a JSON
response with `"decision": "block"` "prevents the prompt from being
processed and erases it from context" — a real prevention point, not an
after-the-fact alert. It checks the user's own typed text against
residoo's 84 high-confidence rules only — never `--verify` (a network
call), never `--ocr` (irrelevant to text anyway, and both are too slow):
this event has no matcher support, so it fires on **every single prompt**
with a default 30-second budget, confirmed to run in practice in well
under 5ms even against a 220KB pasted block (measured directly, not
assumed). Because a wrong block here erases the user's *entire* typed
message — a materially higher cost than denying one tool call — this path
is deliberately more conservative than `PreToolUse`'s: a documented
vendor-example key or an obvious placeholder is suppressed before ever
blocking, the same suppression `residoo scan` itself applies.

**`PostToolUse`** closes the "arriving through a command's output" gap,
for the `Bash` tool specifically. An earlier version of this section
claimed that gap was uncatchable — wrong, corrected after a competitive
research pass found GitGuardian's `ggshield` already scans tool output at
this exact stage. Claude Code's own docs (same page, `PostToolUse decision
control`) confirm a hook can return `hookSpecificOutput.updatedToolOutput`
to replace what the model sees, and give the Bash tool's exact output
shape (`{stdout, stderr, interrupted, isImage}`) needed to build a
replacement that Claude Code will actually accept — a mismatched shape is
silently ignored, not reported as a failure, so this is the one built-in
tool whose shape is documented precisely enough to target safely. It scans
the command's actual stdout/stderr against the same 84 rules and redacts
any match in place — catching a secret in `git log`, `env`, or a build
log, none of which `PreToolUse`'s path-based check was ever going to see.
The command has already run by the time this fires (Claude Code's own
docs, same section): this cannot undo a file write, a command's side
effect, or a network call it made — only keep the raw value out of the
model's context, and so out of the transcript `residoo scan` exists to
check. Every other built-in tool's output shape is undocumented at this
precision; scanning it is a stated, disclosed gap, not silently assumed
covered.

Best-effort, stated plainly rather than oversold: per Claude Code's own
docs, a `command`-type hook (what this is) that times out on
`UserPromptSubmit` has its output discarded and the prompt still reaches
Claude unscanned — the same "never stall the session over uncertainty"
posture `PreToolUse` already has, not a new risk introduced here.
`residoo scan` / `watch` / `mcp` remain the actual safety net either way;
this is prevention layered on top of detection, not a replacement for it.

```json
{
  "hooks": {
    "PreToolUse": [
      { "matcher": "Bash|Read", "hooks": [{ "type": "command", "command": "residoo guard" }] }
    ],
    "UserPromptSubmit": [
      { "hooks": [{ "type": "command", "command": "residoo guard" }] }
    ],
    "PostToolUse": [
      { "matcher": "Bash", "hooks": [{ "type": "command", "command": "residoo guard" }] }
    ]
  }
}
```
in `.claude/settings.json` (no `matcher` on `UserPromptSubmit` — Claude
Code doesn't support one there). Same binary, same behavior either way: it
reads one hook payload from stdin and writes a decision to stdout only
when something matches; anything it doesn't recognize falls through
untouched, with zero output, exit 0.

Don't want to hand-write that JSON? `residoo guard --print-config` computes
and prints the exact same merged config — reading your existing
`~/.claude/settings.json` if you have one, adding whatever of the three
hooks is missing (never duplicating one already there), and printing the
result. It never writes the file itself: residoo never writes any file but
its own rotation ledger and an explicit `--seal` vault (`CONTRIBUTING.md`'s
own hard rule), so saving it is a deliberate, visible step you take
yourself:

```bash
residoo guard --print-config > ~/.claude/settings.json
```

`--project` targets `./.claude/settings.json` (the repo-local config)
instead.

### Audit trail

Every BLOCK or REDACT decision (any of the three hooks) also writes one
structured JSON line to **stderr** — never a file. `CONTRIBUTING.md`'s own
rule names `~/.residoo/rotations.json` as the only file residoo ever
writes outside an explicit `--seal`; a new persistent log file would need
to break that rule, so this makes the same choice `residoo cred`'s own
audit trail already made for the identical reason. Durability is the
operator's choice: redirect the hook's own stderr at launch if you want it
kept.

```json
{"ts":"2026-09-04T23:06:07.828Z","tool":"residoo guard","event":"UserPromptSubmit","decision":"block","label":"Stripe API key (live mode)","preview":"sk_l…C6yH  (32 chars)","sessionId":"...","cwd":"..."}
{"ts":"2026-09-05T03:13:25.328Z","tool":"residoo guard","event":"PostToolUse","decision":"redact","label":"GitHub personal access token","preview":"ghp_…4567  (38 chars)","sessionId":"...","cwd":"..."}
```

`preview` is the same `redact()`'d, first/last-4-characters value every
other output format already uses — never the raw match. A `PreToolUse`
block carries a `label` (which path pattern matched) but no `preview`
field at all: a file path isn't a secret value, so there's nothing to
redact. `PostToolUse`'s `decision` reads `"redact"`, not `"block"` — the
tool already ran, nothing was actually blocked, and the log should say
what really happened. Allowed events write nothing — this is a log of
what got acted on, not a record of every prompt or every tool call.

### Measured, not claimed

The numbers below are for `PreToolUse`'s path-pattern list specifically.
`UserPromptSubmit` and `PostToolUse`'s own detection accuracy is not
separately re-measured on a dedicated corpus — both reuse residoo's 84
high-confidence rules exactly as `residoo scan` already scores them (see
[docs/benchmark.md](benchmark.md)), and the new code on top of that (the
dispatch, and the vendor-example/placeholder suppression) is covered by
`tests/smoke.js` and a `tests/fuzz.js` property, not a scored benchmark of
its own — stated plainly rather than implying a number that wasn't
measured.

Within `PreToolUse`'s own scope — does the pattern list itself catch what
it should, without wrongly blocking ordinary work — this is measured the
same way `scan()` is, on its own scored corpus:

| metric | result |
|---|---|
| Recall (sensitive reads correctly blocked) | **35/35 (100%)** |
| False-positive rate (safe commands wrongly blocked) | **0/46 (0%)** |

That number is not a cherry-picked best case: building this corpus found
five real bugs on the first two runs (blocking `.env.example`, blocking a
public SSH key, blocking a filename that says "public.pem", missing a
hyphen-prefixed service-account filename, and one corpus miscategorization
found and fixed along the way) — all disclosed, with the exact before/after,
in [`bench/guard/RESULTS.md`](../bench/guard/RESULTS.md). Reproduce it
yourself: `node bench/guard/run.js`.
