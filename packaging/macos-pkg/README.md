# macOS .pkg distribution

`residoo-<version>.pkg` is a script-only macOS installer (`pkgbuild --nopayload` -- no files are copied by the package mechanism itself) whose entire job is running `scripts/postinstall`, which runs `npm install -g residoo` on the user's behalf. What this buys someone who isn't comfortable in a terminal: double-click the `.pkg`, click through the standard macOS installer wizard, done -- no `npm`/Homebrew knowledge required for the install step itself.

**What this does NOT remove**, disclosed rather than glossed over: Node.js is still a real prerequisite. residoo's own zero-runtime-dependency rule (CONTRIBUTING.md) is about what residoo ships, not the Node runtime it's written in -- bundling a full Node runtime into this installer would be a much bigger, different undertaking (and arguably works against residoo's own "small, auditable" identity), so `scripts/postinstall` detects Node's absence and tells the user clearly what to do next (install Node from nodejs.org, then run `npm install -g residoo` themselves) rather than pretending to succeed.

**Unsigned**, disclosed plainly: this package is not signed with an Apple Developer ID, so macOS Gatekeeper shows an "unidentified developer" warning on first open -- the user needs to right-click > Open once (or System Settings > Privacy & Security > Open Anyway). Real signing and notarization need an Apple Developer Program enrollment (a paid account under the maintainer's own identity) -- a separate, later step, not attempted here.

## Building

```sh
bash packaging/macos-pkg/build.sh
```

Reads the version from `package.json`, writes `residoo-<version>.pkg` into this same directory (gitignored -- the built binary is never committed, only the source that builds it). Requires `pkgbuild`, which ships with every macOS install (Xcode Command Line Tools, no extra install needed).

CI builds and attaches this automatically: `.github/workflows/publish.yml`'s `build-macos-pkg` job runs on a `macos-latest` GitHub-hosted runner after every tagged release, builds the `.pkg`, and uploads it to that release's GitHub Release page via `gh release upload`.

## What `scripts/postinstall` actually does

Installer postinstall scripts run as root, with a minimal environment (no user `$PATH`). Two things follow from that, both handled explicitly:

- **npm is located by checking real install paths directly** (`/opt/homebrew/bin/npm`, `/usr/local/bin/npm`, `/usr/bin/npm`), falling back to a `$PATH` lookup only if none of those exist -- a bare `command -v npm` alone cannot be trusted in this minimal environment.
- **The actual `npm install -g` runs as the logged-in console user, not root** (`stat -f%Su /dev/console`, Apple's own documented pattern for this exact situation) -- a root-owned global npm install would be a real permissions mess for that user afterward.
- **If residoo is already installed** (checked directly, the same way npm is), the script skips straight to a friendly "already installed, nothing to do" message instead of attempting (and failing with a confusing `EEXIST`) an install that was never going to be needed. Found by testing this script against this project's own real, Homebrew-installed residoo before shipping -- not assumed.
- Every path (missing Node, already installed, install succeeded, install failed) writes to `/tmp/residoo-installer.log` and shows a native `osascript` dialog/notification -- the user is never left guessing what happened.

## Testing without touching a real global install

`npm install -g` was tested against an **isolated `--prefix`** (a throwaway directory), never the real global Homebrew-managed install on the build machine -- confirmed both that the isolated install actually worked (`residoo --help` ran from the throwaway prefix) and that the real global `/opt/homebrew/bin/residoo` symlink was untouched afterward. The "already installed" detection path was verified directly against this same real machine (which does have residoo installed via Homebrew) and confirmed to exit cleanly without attempting any install.

The full `.pkg` (via `pkgutil --expand`) was confirmed to carry the correct identifier, version, and postinstall script with no payload files. Running it through the real macOS Installer framework end to end (`sudo installer -pkg ... -target /`, or an actual double-click) needs a real terminal password prompt / GUI session this automated build environment doesn't have -- that final step is the one thing left for a human to confirm.

## Verification

- `bash packaging/macos-pkg/build.sh` produces a `.pkg` with no payload files (`pkgutil --payload-files` empty) and the correct version/identifier (`pkgutil --expand`, `PackageInfo`).
- `pkgutil --check-signature` correctly reports "no signature" (expected, disclosed above).
- `scripts/postinstall`'s logic verified via isolated copies (redirected `$NPM_CONFIG_PREFIX`/log path), never against the real global install: npm detection across all three candidate paths, the already-installed short-circuit, a real (isolated) `npm install -g` succeeding, and log/dialog output on each path.
