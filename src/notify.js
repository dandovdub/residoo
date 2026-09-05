"use strict";

const cp = require("child_process");

/**
 * Best-effort OS desktop notification for `residoo watch`. macOS via
 * `osascript` (always present, no new dependency -- the same shell-out
 * precedent `keychain.js`'s `security` and `ocr.js`'s `tesseract` already
 * set), Linux via `notify-send` (commonly present on a desktop session,
 * NOT guaranteed -- `watch` also runs on headless/server machines with no
 * notification daemon at all).
 *
 * Windows: no built-in, dependency-free mechanism was found that doesn't
 * either need an external module (BurntToast) or pop a blocking, modal
 * MessageBox in front of a background process -- a disclosed scope limit,
 * not silently assumed covered, the same posture `keychain.js` already
 * takes for its own Windows refusal.
 *
 * Decoration, never the report itself: `watch`'s own `emit()` already
 * writes every finding to stdout/stderr before this is ever called, so a
 * missing binary, no display server, or a spawn error here must never
 * throw, block, or affect the caller in any way -- it can only make an
 * already-reported finding easier to notice sooner.
 *
 * `cp.spawn` (not destructured at module load) so a test can monkey-patch
 * `require("child_process").spawn` directly and restore it after, without
 * this module needing its own injectable-dependency parameter.
 */
function notifyDesktop(title, message) {
  try {
    if (process.platform === "darwin") {
      // osascript's -e takes one AppleScript source string; spawn (no
      // shell:true) passes it as a single argv entry, so there is no shell
      // to inject into -- but the string still has to be valid AppleScript
      // source, so its own quote/backslash characters need escaping or a
      // stray one just breaks the script into a harmless no-op.
      const esc = (s) => String(s).replace(/[\\"]/g, "\\$&");
      const script = `display notification "${esc(message)}" with title "${esc(title)}"`;
      const child = cp.spawn("osascript", ["-e", script], { stdio: "ignore" });
      child.on("error", () => {}); // binary missing or spawn failed: never throw
      child.unref();
    } else if (process.platform === "linux") {
      const child = cp.spawn("notify-send", [String(title), String(message)], { stdio: "ignore" });
      child.on("error", () => {});
      child.unref();
    }
    // Windows and anything else: no-op, disclosed above, not attempted.
  } catch {
    // Never let a notification failure affect the caller.
  }
}

module.exports = { notifyDesktop };
