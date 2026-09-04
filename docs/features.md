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
watching 43 sources, 118 files (61 tailed, 57 rescanned on change)
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

```
residoo watch [options]

  --interval <seconds>    how often to check for new content (default 5, minimum 1)
  --json                  NDJSON events on stdout, one line per finding/re-exposure
  --verify                same opt-in vendor check as scan --verify, applied to
                          each newly found credential once
  --include-noisy, --include-suppressed, --no-color   same meaning as scan
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

Storage is macOS (`security`) or Linux (`secret-tool`) only, matching
`--seal --keychain`'s own existing platform support; Windows is refused
with a clear message rather than half-built. There is no `residoo cred
list` in v1: you need to already know the name you set.

## Guard: block a sensitive read before it happens

Everything above finds a leak after it's already written to disk. `residoo
guard` is the one piece of residoo that tries to stop one from happening in
the first place — a Claude Code `PreToolUse` hook that blocks an obviously-
sensitive file read (`.env`, `id_rsa`, `.aws/credentials`, and similar)
before the command runs at all.

```json
{
  "hooks": {
    "PreToolUse": [
      { "matcher": "Bash|Read", "hooks": [{ "type": "command", "command": "residoo guard" }] }
    ]
  }
}
```
in `.claude/settings.json`. It reads one hook payload from stdin and writes
a deny decision to stdout only when the proposed command or file path
matches; anything it doesn't recognize falls through untouched, with zero
output, exit 0.

This is narrower than it might sound, and the gap is worth stating
plainly rather than implying more than it does: Claude Code's hooks API
lets a `PreToolUse` hook see the proposed tool INPUT (a Bash command
string, a Read file path) before it runs, but there is no documented
mechanism for a hook to see or redact a tool's OUTPUT — by the time a
`PostToolUse` hook fires, that output is already committed to the
transcript. So this can only block on the shape of the request, never
clean up what a command already printed. It will not catch a secret typed
directly into a prompt, or one arriving in the output of an otherwise
unremarkable command (`curl`, a build log). `residoo scan` / `watch` /
`mcp` remain the actual safety net; this is a best-effort tripwire on top
of them, not a replacement.
