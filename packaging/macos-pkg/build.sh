#!/bin/bash
# Builds two script-only macOS installer packages (pkgbuild --nopayload:
# no files are copied anywhere by the package mechanism itself):
#
#   residoo-<version>.pkg            runs `npm install -g residoo`
#   residoo-uninstall-<version>.pkg  runs `npm uninstall -g residoo`,
#                                    or points at `brew uninstall residoo`
#                                    if Homebrew installed it instead --
#                                    see scripts-uninstall/postinstall's
#                                    own header for why that split exists
#
# See scripts/postinstall's own header for the shared reasoning and
# honest limits (Node.js itself is still a real prerequisite; neither of
# these bundles a Node runtime).
#
# UNSIGNED, disclosed plainly: neither package is signed with an Apple
# Developer ID, so macOS Gatekeeper will show an "unidentified developer"
# warning on first open -- the user needs to right-click > Open (or
# System Settings > Privacy & Security > Open Anyway) once. Real signing
# and notarization need an Apple Developer Program enrollment (a paid
# account under the project maintainer's own identity), which is a
# separate, later step this script does not attempt.

set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERSION=$(node -p "require('$DIR/../../package.json').version")

pkgbuild \
  --nopayload \
  --scripts "$DIR/scripts" \
  --identifier "com.dandovdub.residoo" \
  --version "$VERSION" \
  --install-location "/tmp/residoo-pkg-noop" \
  "$DIR/residoo-${VERSION}.pkg"
echo "Built: $DIR/residoo-${VERSION}.pkg (unsigned -- see this script's own header)"

pkgbuild \
  --nopayload \
  --scripts "$DIR/scripts-uninstall" \
  --identifier "com.dandovdub.residoo.uninstall" \
  --version "$VERSION" \
  --install-location "/tmp/residoo-pkg-noop" \
  "$DIR/residoo-uninstall-${VERSION}.pkg"
echo "Built: $DIR/residoo-uninstall-${VERSION}.pkg (unsigned -- see this script's own header)"
