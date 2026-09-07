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

/**
 * A PERSISTENT Windows tray icon -- genuinely different from `notifyWindows`
 * above, not a variant of it: that function is fire-and-forget (one balloon,
 * then the process disposes itself and exits); this one stays alive and
 * visible for as long as the CALLER wants it to (`residoo watch --tray`,
 * the standing-presence "residoo is watching" indicator this project's own
 * platform-scope.md records as a real, scoped follow-up). The two are
 * deliberately DECOUPLED, not merged into one mechanism: this function only
 * shows a static icon + tooltip; actual per-finding alerts keep firing
 * through the existing, already-proven `notifyWindows` balloon-tip path,
 * completely independently. Combining them into one process would mean
 * finding a way to push live UPDATES into an already-running PowerShell
 * process (a named pipe, a polled state file) -- real inter-process-
 * communication complexity this project has no way to verify without a
 * real Windows machine, so it was deliberately left out of scope rather
 * than shipped unverified. A static presence icon needs no such channel.
 *
 * API surface verified directly against Microsoft's own current docs
 * (learn.microsoft.com, fetched 2026-09-07), the same bar every other
 * Windows-specific function in this project holds to, and likewise NOT
 * live-tested against a real Windows install:
 *   - `NotifyIcon.ContextMenuStrip` (not the older, pre-.NET-2.0
 *     `ContextMenu`/`MenuItem` classes) is the current, non-deprecated
 *     property, listed through the windowsdesktop-11.0 moniker.
 *   - `SystemIcons.Shield` is a real, current static property ("an Icon
 *     object that contains the shield icon") -- used here instead of
 *     bundling a custom .ico file, matching zero-dependency the same way
 *     `notifyWindows` reuses `SystemIcons.Information`.
 *   - `NotifyIcon.Text` (the tooltip) has a REAL, documented, THROWING
 *     limit: Microsoft's own docs give an exact table -- 63 characters
 *     for .NET Framework and .NET 5/Core 3.0-3.1, 127 for .NET 6+. Windows
 *     PowerShell (`powershell.exe`, what this project shells out to
 *     everywhere, never `pwsh.exe`) runs on .NET Framework, so 63 is the
 *     applicable limit, and exceeding it throws `ArgumentException` --
 *     not a cosmetic detail, a real crash this function truncates against
 *     before it can happen.
 *
 * Lifecycle, the one place this genuinely departs from every other spawn
 * in this file: NOT `.unref()`'d, because the caller (`watch.js`) needs
 * to `.kill()` this exact child process on its own SIGINT/SIGTERM
 * shutdown -- an unref'd handle a caller has already discarded can't be
 * reached again later. `[System.Windows.Forms.Application]::Run()` blocks
 * the spawned PowerShell process in its own message loop for as long as
 * the icon should stay visible; the "Hide icon" context-menu item calls
 * `Application.Exit()` so a user can dismiss it independently of whether
 * `residoo watch` itself keeps running.
 */
function startWindowsTray(tooltip) {
  if (process.platform !== "win32") return null;
  // Unlike notifyDesktop's callers, nothing wraps a call to this function
  // in an outer try/catch -- runWatch calls it directly, and this returns
  // a real value (the child, or null) callers branch on, so the "never
  // throw" contract has to be enforced right here, not borrowed from a
  // caller the way notifyWindows borrows notifyDesktop's. The whole body
  // is inside this one try, not just the spawn call: `String(tooltip)`
  // itself can throw -- an object whose own `toString` property isn't a
  // function fails JavaScript's ToPrimitive coercion before anything else
  // runs, the exact real (fast-check-found, not hypothetical) shape
  // cve.js's parseVersion hit and was fixed for earlier this same
  // project -- confirmed directly here too before shipping, not assumed
  // fixed by analogy.
  try {
    const esc = (s) => String(s).replace(/'/g, "''");
    const truncated = String(tooltip).slice(0, 63); // NotifyIcon.Text's real, throwing limit on .NET Framework -- see docstring
    const script =
      "Add-Type -AssemblyName System.Windows.Forms; " +
      "Add-Type -AssemblyName System.Drawing; " +
      "$ni = New-Object System.Windows.Forms.NotifyIcon; " +
      "$ni.Icon = [System.Drawing.SystemIcons]::Shield; " +
      `$ni.Text = '${esc(truncated)}'; ` +
      "$ni.Visible = $true; " +
      "$menu = New-Object System.Windows.Forms.ContextMenuStrip; " +
      "$hideItem = New-Object System.Windows.Forms.ToolStripMenuItem 'Hide icon'; " +
      "$hideItem.add_Click({ $ni.Visible = $false; $ni.Dispose(); [System.Windows.Forms.Application]::Exit() }); " +
      "[void]$menu.Items.Add($hideItem); " +
      "$ni.ContextMenuStrip = $menu; " +
      "[System.Windows.Forms.Application]::Run()";
    const child = cp.spawn("powershell.exe", ["-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", script], { stdio: "ignore" });
    child.on("error", () => {}); // binary missing or spawn failed: never throw
    return child;
  } catch {
    return null;
  }
}

module.exports = { notifyDesktop, startWindowsTray };
