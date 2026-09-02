# CI and pre-commit integration

residoo's project mode scans a repository checkout instead of the machine it runs on:

```
residoo scan --project . --fail-on-find
```

## What project mode does and does not scan

It scans the checkout for committed agent artifacts (agent session transcripts, agent config, memory and rules files that were committed into the repo) and for repo-level planted persistence (auto-executing hooks, dropper scripts, folder-open tasks, hidden Unicode instructions in repo files).

It does not see the runner's home directory, and it does not scan any developer's machine. That holds against a hostile checkout too: a committed symlink pointing outside the repository is never followed (it is surfaced as not fully scanned instead), and machine-level environment overrides such as `GEMINI_CLI_HOME` are ignored in project mode. A clean CI run means this checkout is clean; it says nothing about the laptops of the people who work on it. For those, developers run `residoo scan` locally, which checks the agent transcript and config locations on that machine.

The scan is read-only, makes zero network calls, and redacts every finding in every output format. Fetching the CLI from npm (via npx or pre-commit's installer) is the only network activity, and it happens before the scan starts.

Exit codes with `--fail-on-find`: 0 when clean, 1 when there is a secret finding or an integrity warning. Info-level review items (your own hooks, listed for review) do not fail the run. If part of the check cannot complete, that is surfaced as a warning, never as a silent all-clear.

## pre-commit

Add to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/dandovdub/residoo
    rev: v0.3.0
    hooks:
      - id: residoo
```

The pre-commit framework installs this repo with npm in its own isolated environment and runs the scan on every commit. The hook ignores the staged file list on purpose: it always scans the whole checkout, because a planted hook or a committed transcript is dangerous whether or not it is part of the current commit.

## GitHub Action

The repository doubles as a composite action. The action tag and the CLI version move together: `@v0.3.0` runs residoo 0.3.0 from npm.

```yaml
name: residoo
on:
  push:
    branches: [main]
  pull_request:

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dandovdub/residoo@v0.3.0
```

Inputs, all optional:

| Input | Default | Meaning |
| --- | --- | --- |
| `fail-on-find` | `true` | Fail the job on any secret finding or integrity warning. Set to `false` to report without failing. |
| `project-dir` | `.` | Directory to scan, relative to the workspace. |
| `version` | the CLI release matching the action tag | residoo version fetched from npm. Override only if you need the action tag and CLI version to differ. |

## Plain workflow, no action

If you prefer not to depend on the action, the whole integration is one command:

```yaml
name: residoo
on:
  push:
    branches: [main]
  pull_request:

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: "20"
      - run: npx --yes residoo@0.3.0 scan --project . --fail-on-find
```
