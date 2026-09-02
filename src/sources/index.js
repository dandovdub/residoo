"use strict";

/**
 * Registry of transcript sources. Each source is a small adapter exposing
 * { id, label, available, files, readLines } — see claude-code.js for the
 * reference implementation and CONTRIBUTING.md for how to add one.
 *
 * Deliberately NOT included here: guessed paths for Cursor, GitHub Copilot,
 * or Windsurf. Their local history formats are real but weren't verified
 * against an actual installation while building this — shipping a scanner
 * that silently checks the wrong path and reports "all clear" is worse than
 * not supporting the tool at all. PRs adding a verified adapter are the
 * fastest way to get a tool covered.
 */
const claudeCode = require("./claude-code");

const ALL_SOURCES = [claudeCode];

function availableSources() {
  return ALL_SOURCES.filter((s) => s.available());
}

module.exports = { ALL_SOURCES, availableSources };
