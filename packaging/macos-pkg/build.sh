#!/bin/bash
# Build residoo-<version>.pkg -- a script-only macOS installer package
# (pkgbuild --nopayload: no files are copied anywhere) whose entire job is
# running scripts/postinstall, which runs `npm install -g residoo` on the
# user's behalf. See scripts/postinstall's own header for the full
# reasoning and its honest limits (Node.js itself is still a real
# prerequisite; this is not a bundled-runtime installer).
#
# UNSIGNED, disclosed plainly: this package is not signed with an Apple
# Developer ID, so macOS Gatekeeper will show an "unidentified developer"
# warning on first open -- the user needs to right-click > Open (or
# System Settings > Privacy & Security > Open Anyway) once. Real signing
# and notarization need an Apple Developer Program enrollment (a paid
# account under the project maintainer's own identity), which is a
# separate, later step this script does not attempt.

set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERSION=$(node -p "require('$DIR/../../package.json').version")
OUT="$DIR/residoo-${VERSION}.pkg"

pkgbuild \
  --nopayload \
  --scripts "$DIR/scripts" \
  --identifier "com.dandovdub.residoo" \
  --version "$VERSION" \
  --install-location "/tmp/residoo-pkg-noop" \
  "$OUT"

echo "Built: $OUT (unsigned -- see this script's own header)"
