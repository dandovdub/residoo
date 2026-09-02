# residoo (PyPI launcher)

**Find secrets leaking through your AI coding agent's session history.**

residoo is a zero-dependency **Node.js** CLI. This PyPI package is its official
thin launcher: `pip install residoo` gives you a `residoo` command that locates
Node's `npx` and runs the real tool, passing all arguments through.

```bash
pip install residoo
residoo scan
```

is exactly equivalent to:

```bash
npx residoo scan
```

Requires Node.js 18+ on the machine. If Node is missing, the launcher says so
and points you at the install, rather than pretending to scan.

Everything else — what it scans (42 agent-transcript sources), what it detects
(35 verified vendor patterns), the `--seal` encrypted vault, the security
model, and why it makes zero network calls — is documented at the canonical
repository: **https://github.com/dandovdub/residoo**

This launcher also exists to hold the `residoo` name on PyPI against
impersonation — a real, current attack pattern for security tools, documented
in the project's own SECURITY.md. If you found a "residoo" anywhere other than
this package, npm's `residoo`, or that GitHub repository, don't run it.

MIT, same as the main project.
