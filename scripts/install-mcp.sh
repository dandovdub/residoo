#!/usr/bin/env bash
# Installs residoo (via Homebrew if available, else npm) and registers it as
# an MCP server with Claude Code. Safe to re-run: `claude mcp add` overwrites
# an existing "residoo" entry with the same command rather than duplicating it.
set -euo pipefail

SCOPE="${1:-user}"   # user (default, available in every project) or local/project

if ! command -v claude >/dev/null 2>&1; then
  echo "error: Claude Code CLI ('claude') not found on PATH. Install it first: https://claude.com/claude-code" >&2
  exit 1
fi

if command -v residoo >/dev/null 2>&1; then
  echo "residoo already installed: $(command -v residoo)"
elif command -v brew >/dev/null 2>&1; then
  echo "Installing residoo via Homebrew..."
  brew tap dandovdub/residoo >/dev/null 2>&1 || true
  brew install dandovdub/residoo/residoo
elif command -v npm >/dev/null 2>&1; then
  echo "Homebrew not found, installing residoo via npm..."
  npm install -g residoo
else
  echo "error: neither Homebrew nor npm found. Install one, or install residoo yourself: https://github.com/dandovdub/residoo" >&2
  exit 1
fi

echo
echo "residoo version: $(residoo --help | head -1)"
echo

echo "Registering residoo as an MCP server (scope: $SCOPE)..."
claude mcp add --scope "$SCOPE" residoo -- residoo mcp

echo
echo "Verifying (spawns the server for a live handshake + tool list)..."
claude mcp get residoo

echo
echo "Done. Start a Claude Code session and run /mcp to see it connected,"
echo "or ask Claude to run a residoo scan."
