# macOS .pkg distribution

Two script-only macOS packages (`pkgbuild --nopayload` -- no files are copied by the package mechanism itself), a matched install/uninstall pair:

- **`residoo-<version>.pkg`** runs `scripts/postinstall`, which runs `npm install -g residoo` on the user's behalf.
- **`residoo-uninstall-<version>.pkg`** runs `scripts-uninstall/postinstall`, which reverses it.

What this buys someone who isn't comfortable in a terminal: double-click to install, double-click the other one to remove -- no `npm`/Homebrew knowledge required for either step.

**What this does NOT remove**, disclosed rather than glossed over: Node.js is still a real prerequisite. residoo's own zero-runtime-dependency rule (CONTRIBUTING.md) is about what residoo ships, not the Node runtime it's written in -- bundling a full Node runtime into this installer would be a much bigger, different undertaking (and arguably works against residoo's own "small, auditable" identity), so `scripts/postinstall` detects Node's absence and tells the user clearly what to do next (install Node from nodejs.org, then run `npm install -g residoo` themselves) rather than pretending to succeed.

**Unsigned**, disclosed plainly: neither package is signed with an Apple Developer ID, so macOS Gatekeeper shows an "unidentified developer" warning on first open -- the user needs to right-click > Open once (or System Settings > Privacy & Security > Open Anyway). Real signing and notarization need an Apple Developer Program enrollment (a paid account under the maintainer's own identity) -- a separate, later step, not attempted here.

## Building

```sh
bash packaging/macos-pkg/build.sh
```

Reads the version from `package.json`, writes both `residoo-<version>.pkg` and `residoo-uninstall-<version>.pkg` into this same directory (gitignored -- built binaries are never committed, only the source that builds them). Requires `pkgbuild`, which ships with every macOS install (Xcode Command Line Tools, no extra install needed).

CI builds and attaches both automatically: `.github/workflows/publish.yml`'s `build-macos-pkg` job runs on a `macos-latest` GitHub-hosted runner after every tagged release and uploads both to that release's GitHub Release page via `gh release upload`.

## What `scripts/postinstall` (the installer) actually does

Installer postinstall scripts run as root, with a minimal environment (no user `$PATH`). Two things follow from that, both handled explicitly:

- **npm is located by checking real install paths directly** (`/opt/homebrew/bin/npm`, `/usr/local/bin/npm`, `/usr/bin/npm`), falling back to a `$PATH` lookup only if none of those exist -- a bare `command -v npm` alone cannot be trusted in this minimal environment.
- **The actual `npm install -g` runs as the logged-in console user, not root** (`stat -f%Su /dev/console`, Apple's own documented pattern for this exact situation) -- a root-owned global npm install would be a real permissions mess for that user afterward.
- **If residoo is already installed** (checked directly, the same way npm is), the script skips straight to a friendly "already installed, nothing to do" message instead of attempting (and failing with a confusing `EEXIST`) an install that was never going to be needed. Found by testing this script against this project's own real, Homebrew-installed residoo before shipping -- not assumed.
- Every path (missing Node, already installed, install succeeded, install failed) writes to `/tmp/residoo-installer.log` and shows a native `osascript` dialog/notification -- the user is never left guessing what happened.

## What `scripts-uninstall/postinstall` (the uninstaller) actually does

Mirrors the installer's shape (no payload, root-vs-console-user, real-path npm detection) with one genuine difference, not a copy-paste oversight: **`npm uninstall -g residoo` only removes an install `npm install -g` itself created.** residoo installed via Homebrew lives inside Homebrew's own Cellar, built by Homebrew's own internal `npm install` run inside an isolated prefix -- invisible to a plain `npm ls -g` / `npm uninstall -g` from outside it. Running the uninstall command against a Homebrew-managed install would report success while doing nothing at all, a false "it's gone."

So the uninstaller resolves the installed binary's real path first (`readlink -f`) and checks whether it lives under `/Cellar/residoo/` -- if so, it tells the user to run `brew uninstall residoo` themselves instead of attempting anything (correctly invoking `brew` -- which prefix, whether it needs `sudo`, first-run behavior -- is a different, larger scope than mirroring the plain-npm path this uninstaller was built to reverse). Otherwise it runs the real `npm uninstall -g residoo`, same user/logging discipline as the installer.

## Testing without touching a real global install

`npm install -g` / `npm uninstall -g` were tested against an **isolated `--prefix`** (a throwaway directory), never the real global Homebrew-managed install on the build machine -- confirmed both that the isolated install/uninstall actually worked and that the real global `/opt/homebrew/bin/residoo` symlink was untouched afterward, checked before and after every test run. The installer's "already installed" short-circuit and the uninstaller's Homebrew-detection branch were both verified directly against this same real machine (which does have residoo installed via Homebrew) and confirmed to exit cleanly without attempting any install/uninstall in either case.

Both full `.pkg` files (via `pkgutil --expand`) were confirmed to carry the correct, DISTINCT identifiers (`com.dandovdub.residoo` / `com.dandovdub.residoo.uninstall` -- deliberately different, so macOS's own package-receipt tracking never conflates the two), correct version, and their respective postinstall script, with no payload files in either. Running either through the real macOS Installer framework end to end (`sudo installer -pkg ... -target /`, or an actual double-click) needs a real terminal password prompt / GUI session this automated build environment doesn't have -- that final step is the one thing left for a human to confirm.

## Verification

- `bash packaging/macos-pkg/build.sh` produces both `.pkg` files with no payload files (`pkgutil --payload-files` empty on each) and the correct version/identifier (`pkgutil --expand`, `PackageInfo`).
- `pkgutil --check-signature` correctly reports "no signature" on both (expected, disclosed above).
- `scripts/postinstall`'s logic verified via isolated copies (redirected `$NPM_CONFIG_PREFIX`/log path), never against the real global install: npm detection across all three candidate paths, the already-installed short-circuit, a real (isolated) `npm install -g` succeeding, and log/dialog output on each path.
- `scripts-uninstall/postinstall`'s logic verified the same way: the Homebrew-detection branch against this machine's real (Homebrew-managed) install -- confirmed it correctly stops without attempting anything -- and the plain-npm uninstall path against a separate isolated install, confirmed it actually removed the isolated binary while leaving the real Homebrew-managed one untouched.
