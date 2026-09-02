#!/usr/bin/env node
"use strict";

const { main } = require("../src/cli");

main(process.argv).then(
  (code) => { process.exitCode = code; },
  (err) => {
    // Anything reaching here is a genuine bug, not an expected failure mode —
    // every expected failure (unreadable file, no sources, bad args) is
    // handled inside main() and returns a code, never throws. Print plainly;
    // do not let a raw stack trace risk echoing scanned content.
    process.stderr.write(`residoo crashed unexpectedly: ${err && err.message}\n`);
    process.exitCode = 1;
  }
);
