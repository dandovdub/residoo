residoo's Cursor adapter (`src/sources/cursor.js`) is built and tested, but per CONTRIBUTING.md's verification bar, it has **not** been checked against a real Cursor installation on any machine this project was built on. It reads SQLite chat history (`state.vscdb`) via `node:sqlite`, corroborated by 2+ independent published sources, but that is one tier below "real-install-verified."

**If you use Cursor:** run `node bin/residoo.js scan` (or `npx residoo scan` from this repo) and tell us whether the file counts and any findings look right for what you know is actually in your own history. A "looks right, found N files, here's what they were" report is exactly as useful as a bug report, see CONTRIBUTING.md's "Adding a transcript source" section for what "real-install-verified" means and how one report moves a source out of the unverified tier.

No code changes needed unless something's actually broken.
