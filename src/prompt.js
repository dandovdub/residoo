"use strict";

const readline = require("readline");
const { Writable } = require("stream");

/**
 * Hidden passphrase prompt — echoes nothing while typing. Falls back to the
 * RESIDOO_PASSPHRASE env var for scripted/CI use, and refuses to prompt when
 * stdin isn't a TTY (a scanner hanging silently in a pipeline waiting for
 * input nobody can see is worse than failing with instructions).
 */
function promptHidden(question) {
  return new Promise((resolve, reject) => {
    if (process.env.RESIDOO_PASSPHRASE) { resolve(process.env.RESIDOO_PASSPHRASE); return; }
    if (!process.stdin.isTTY) {
      reject(new Error("No TTY for a passphrase prompt. Set RESIDOO_PASSPHRASE in the environment for non-interactive use."));
      return;
    }
    const muted = new Writable({ write(_chunk, _enc, cb) { cb(); } });
    const rl = readline.createInterface({ input: process.stdin, output: muted, terminal: true });
    process.stderr.write(question);
    rl.question("", (answer) => {
      rl.close();
      process.stderr.write("\n");
      resolve(answer);
    });
  });
}

module.exports = { promptHidden };
