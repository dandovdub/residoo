#!/usr/bin/env node
"use strict";

const { main } = require("../src/cli");

main(process.argv).then(
  (code) => { process.exitCode = code; },
  (err) => {
    // Reaching here means a genuine bug, not an expected failure mode — every
    // expected failure (an unreadable file, no sources, bad args) is caught
    // inside main()/scan() and turned into a result or an exit code, never a
    // throw. This is the backstop for whatever that didn't anticipate.
    //
    // err isn't guaranteed to be an Error instance — `err && err.message`
    // silently prints "undefined" for a bare string/object rejection, which
    // would defeat the one job this handler has. String(err) works for both.
    process.stderr.write(`residoo crashed unexpectedly: ${err instanceof Error ? err.message : String(err)}\n`);
    process.exitCode = 1;
  }
);
