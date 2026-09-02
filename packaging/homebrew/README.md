# Homebrew distribution

`residoo.rb` is the Homebrew formula. It installs the exact tarball already published to npm (same bits, verified by sha256), so Homebrew is a second door to the same release, not a second build. Homebrew 6 refuses to install loose formula files, so the formula has to live in a tap repository.

The formula tracks PUBLISHED releases, not tags: its `url` and `sha256` pin the newest tarball that actually exists on the npm registry, and the sha256 is computed from that real tarball. A tarball for a freshly pushed tag does not exist until the tag-triggered publish completes, so the formula is bumped AFTER each publish (see "On each release" below), never speculatively. At the time of writing it pins 0.2.0, the latest published version.

## One-time tap setup (about 5 minutes)

1. Create a public GitHub repo named exactly `homebrew-residoo` under `dandovdub`. The `homebrew-` prefix is what makes `brew tap dandovdub/residoo` resolve to it.

   ```sh
   gh repo create dandovdub/homebrew-residoo --public --clone
   ```

2. Put the formula at `Formula/residoo.rb` (copied unchanged from this directory):

   ```sh
   cd homebrew-residoo
   mkdir -p Formula
   cp ../residoo/packaging/homebrew/residoo.rb Formula/residoo.rb
   git add Formula/residoo.rb
   git commit -m "residoo 0.2.0"
   git push
   ```

3. Done. Users install with:

   ```sh
   brew tap dandovdub/residoo
   brew install residoo
   ```

   or in one line: `brew install dandovdub/residoo/residoo`.

## On each release

After the tag-triggered npm publish of version X.Y.Z:

1. Compute the checksum of the new npm tarball:

   ```sh
   curl -sL https://registry.npmjs.org/residoo/-/residoo-X.Y.Z.tgz | shasum -a 256
   ```

2. In the tap repo, edit `Formula/residoo.rb`: change the version inside `url` and replace `sha256` with the new value. Commit and push. Users pick it up via `brew update && brew upgrade residoo`.

Also update the copy in this directory so the two stay in sync.

Future automation: `publish.yml` can grow a job that runs after the npm publish, computes the sha256, and pushes the bump to `homebrew-residoo` (needs a repo-scoped token as a secret; `dawidd6/action-homebrew-bump-formula` does this off the shelf). The manual bump takes under a minute, so this can wait.

## Notes

- The formula compiles nothing: `npm install` with Homebrew's standard arguments unpacks the package into `libexec` with lifecycle scripts disabled, then symlinks the `residoo` bin stub. residoo has zero dependencies, so nothing else is fetched.
- Homebrew still classifies any non-bottled formula as a from-source install, so macOS users need current Xcode Command Line Tools. If `brew install` says "Your Command Line Tools are too outdated", that is the machine, not the formula; updating CLT via Software Update fixes it.
- Verified 2026-09-02 against Homebrew 6.0.21, using a LOCAL tap built from this directory (the public `dandovdub/homebrew-residoo` repo did not exist yet): full tap, install, `residoo --help`, `brew test`, and uninstall cycle passed in the official `homebrew/brew` image, `brew audit --strict --online` passed clean, and `brew fetch` on macOS confirmed the sha256 of the published 0.2.0 tarball.
