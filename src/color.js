"use strict";

/**
 * Minimal raw ANSI — no chalk, no deps. A security tool asking you to trust
 * a pile of third-party packages before it's even scanned anything is a bad
 * first impression; residoo ships with zero runtime dependencies.
 *
 * Shared between report.js (stdout: the findings/rotation report) and
 * scan.js (stderr: the --verify disclosure table), which is why `stream` is
 * a parameter here rather than a hardcoded process.stdout: stdout and
 * stderr can be redirected independently of each other (piping stdout to a
 * file while stderr still reaches a real terminal, or the reverse), so each
 * caller's own stream decides its own color support instead of one
 * borrowing the other's answer.
 */
const c = {
  reset: "\x1b[0m", bold: "\x1b[1m", dim: "\x1b[2m",
  red: "\x1b[31m", yellow: "\x1b[33m", green: "\x1b[32m", cyan: "\x1b[36m",
};

// `forceNoColor` read fresh on every call, not captured once at require()
// time — a module-level const would freeze whatever the environment was
// before cli.js has even parsed argv. This is how cli.js's --no-color flag
// actually reaches these functions: as an explicit per-call argument, not
// by mutating process.env.NO_COLOR, so a mutated env var can never leak
// into a later call in the same process (a test runner, a wrapper CLI
// reusing this module) and silently disable color for a call that never
// asked for that.
function supportsColor(forceNoColor, stream = process.stdout) {
  return !forceNoColor && stream.isTTY && process.env.NO_COLOR === undefined;
}
function makePaint(forceNoColor, stream = process.stdout) {
  return (code, s) => (supportsColor(forceNoColor, stream) ? `${code}${s}${c.reset}` : s);
}

module.exports = { c, supportsColor, makePaint };
