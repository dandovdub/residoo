# Sources supported today, and adding a new one

## Sources supported today

43 sources: 42 transcript stores plus the agent-config source, in two
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

See [`src/sources/index.js`](../src/sources/index.js) for the full list, and
each source file's own header for exactly what was and wasn't checked.

## Adding a source

A source is a small object with four methods: `id()`, `label()`,
`available()`, `files()`, `readLines(file)`.
[`src/sources/claude-code.js`](../src/sources/claude-code.js) is the reference
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
