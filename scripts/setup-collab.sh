#!/usr/bin/env bash
# One-time GitHub collaboration setup for residoo: labels + 5 good-first-issues.
# Run this AFTER `gh auth login` as dandovdub (or export GH_TOKEN for that account).
# Safe to re-run: gh label/issue create fail loudly on duplicates, nothing silently doubles.
set -euo pipefail
cd "$(dirname "$0")/.."

gh label create "source-verification" --color "0E8A16" --description "Verify a source against a real, populated install" --force
gh label create "benchmark"           --color "5319E7" --description "bench/ methodology or corpus"                    --force

gh issue create --title "Verify Cursor source against a real install" \
  --label "good first issue,help wanted,source-verification" \
  --body-file "$(dirname "$0")/issue-bodies/verify-cursor.md"

gh issue create --title "Verify Windsurf, Cline, or Continue against a real install" \
  --label "good first issue,help wanted,source-verification" \
  --body-file "$(dirname "$0")/issue-bodies/verify-windsurf-cline-continue.md"

gh issue create --title "Verify a source not yet on this list against a real install" \
  --label "good first issue,help wanted,source-verification" \
  --body-file "$(dirname "$0")/issue-bodies/verify-any-source.md"

gh issue create --title "Benchmark corpus: replace random-body private-key plants with structurally valid key bodies" \
  --label "help wanted,benchmark" \
  --body-file "$(dirname "$0")/issue-bodies/corpus-valid-privatekey.md"

gh issue create --title "Benchmark corpus: pair a secret key at a subset of AWS plant sites" \
  --label "help wanted,benchmark" \
  --body-file "$(dirname "$0")/issue-bodies/corpus-aws-pairing.md"

echo "=== done — issues: ==="
gh issue list --limit 10
