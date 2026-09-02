# residoo demo recording script for VHS (https://github.com/charmbracelet/vhs)
#
# To (re)generate the animated demo GIF:
#
#   brew install vhs            # or: go install github.com/charmbracelet/vhs@latest
#   vhs scripts/demo.tape       # writes docs/demo.gif
#
# Run it from the repo root, on a machine where `residoo` is installed
# (`npm install -g residoo` or `npm link`) and where there are real agent
# transcripts to scan — the recording shows whatever `residoo scan` actually
# finds, redacted exactly as the tool always redacts. Nothing is staged.
#
# docs/demo.gif is intentionally not checked in until someone records it;
# the README does not reference it until then.

Output docs/demo.gif

Set FontSize 20
Set Width 1200
Set Height 680
Set Padding 24
Set Theme "Catppuccin Mocha"
Set TypingSpeed 60ms

Sleep 800ms
Type "residoo scan"
Sleep 600ms
Enter
Sleep 6s
Type "residoo scan --json | head -n 20"
Sleep 600ms
Enter
Sleep 6s
