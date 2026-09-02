"""Official PyPI launcher for residoo.

residoo itself is a zero-dependency Node.js CLI (github.com/dandovdub/residoo,
npm package `residoo`). This package exists so `pip install residoo` does the
right thing for Python-first users: it locates Node's `npx` and delegates to
the real tool, passing every argument through untouched.

It is deliberately tiny and makes no network calls of its own — `npx` fetches
the npm package exactly as if the user had typed `npx residoo` themselves.
This package also protects the name on PyPI against impersonation, which
residoo's own SECURITY.md documents as a real attack pattern for security
tools.
"""

import os
import shutil
import sys

__version__ = "0.1.0"


def main() -> None:
    npx = shutil.which("npx")
    if npx is None:
        sys.stderr.write(
            "residoo is a Node.js tool, and Node was not found on this machine.\n"
            "\n"
            "Install Node.js 18+ (https://nodejs.org or `brew install node`),\n"
            "then either re-run this command or use npm directly:\n"
            "\n"
            "    npx residoo scan\n"
            "\n"
            "Source and docs: https://github.com/dandovdub/residoo\n"
        )
        sys.exit(1)
    args = [npx, "--yes", "residoo"] + sys.argv[1:]
    if os.name == "nt":
        # Windows has no true exec(); run as a child and mirror its exit code.
        import subprocess

        sys.exit(subprocess.call(args))
    os.execv(npx, args)
