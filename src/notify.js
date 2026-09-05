"use strict";

const cp = require("child_process");

/**
 * Best-effort OS desktop notification for `residoo watch`. macOS via
 * `osascript` (always present, no new dependency -- the same shell-out
 * precedent `keychain.js`'s `security` and `ocr.js`'s `tesseract` already
 * set), Linux via `notify-send` (commonly present on a desktop session,
 * NOT guaranteed -- `watch` also runs on headless/server machines with no
 * notification daemon at all), Windows via `System.Windows.Forms.NotifyIcon`'s
 * balloon-tip API (see the Windows-specific docstring below).
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
    } else if (process.platform === "win32") {
      notifyWindows(title, message);
    }
    // Anything else: no-op, not attempted.
  } catch {
    // Never let a notification failure affect the caller.
  }
}

/**
 * Windows desktop notification via `System.Windows.Forms.NotifyIcon`'s
 * balloon-tip API, shelled out to `powershell.exe` -- an earlier version
 * of this module considered WinRT toast interop
 * (`[Windows.UI.Notifications.ToastNotificationManager]`) instead and
 * declined it after research found a real, disqualifying prerequisite:
 * Microsoft's own docs make a Start-menu shortcut carrying a registered
 * AppUserModelID a hard requirement for ANY desktop app's toast to
 * display at all, explicitly including unpackaged/scripted apps. NotifyIcon
 * has no such requirement -- confirmed against Microsoft's own current API
 * reference (no [Obsolete] marker, listed through the windowsdesktop-10.0/
 * 11.0 monikers) and multiple independently-converging technique
 * write-ups, one of which states plainly it "requires no Start-menu
 * shortcuts, AUMID registration, or external PowerShell modules." Not
 * live-tested against a real Windows install, the same disclosed
 * limitation `keychain.js`'s DPAPI functions and `integrity.js`'s Get-Acl
 * check already carry.
 *
 * Two real caveats, disclosed rather than smoothed over: Windows ignores
 * the millisecond value passed to `ShowBalloonTip` (actual on-screen
 * duration is governed by the user's own accessibility settings, not this
 * script), and the tray icon does NOT self-remove -- every reference
 * implementation found demonstrates disposal via an interactive
 * double-click handler, not an automatic one, which does not exist for a
 * non-interactive script. This is why the script below explicitly
 * `Start-Sleep`s before calling `.Dispose()` itself, inside the SAME
 * spawned process: `notifyDesktop` never blocks its caller (the sleep
 * happens in a detached, `unref()`'d child, exactly like the macOS/Linux
 * branches above), but something has to keep the icon alive long enough
 * to actually be seen before removing it, and nothing outside that one
 * process is positioned to send a follow-up "now dispose" signal.
 */
function notifyWindows(title, message) {
  const esc = (s) => String(s).replace(/'/g, "''");
  const script =
    "Add-Type -AssemblyName System.Windows.Forms; " +
    "Add-Type -AssemblyName System.Drawing; " +
    "$ni = New-Object System.Windows.Forms.NotifyIcon; " +
    "$ni.Icon = [System.Drawing.SystemIcons]::Information; " +
    `$ni.BalloonTipTitle = '${esc(title)}'; ` +
    `$ni.BalloonTipText = '${esc(message)}'; ` +
    "$ni.Visible = $true; " +
    "$ni.ShowBalloonTip(10000); " +
    "Start-Sleep -Seconds 10; " +
    "$ni.Dispose()";
  const child = cp.spawn("powershell.exe", ["-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", script], { stdio: "ignore" });
  child.on("error", () => {});
  child.unref();
}

module.exports = { notifyDesktop };
