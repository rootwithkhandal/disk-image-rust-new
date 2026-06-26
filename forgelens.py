#!/usr/bin/env python
"""
ForgeLens CLI launcher.
Run from project root: python forgelens.py <command>

Authentication:
  When auth is enabled, you must log in before any command runs.
  Enable:  python forgelens.py auth enable
  Login:   python forgelens.py auth login
  Bypass:  auth is OFF by default — enable it explicitly.
"""

import sys
from pathlib import Path

# Add backend/ to path
sys.path.insert(0, str(Path(__file__).parent / "backend"))

from cli.main import app
from core.auth.gate import gate

# ── Auth gate ─────────────────────────────────────────────────────────────────
# Skip auth for these top-level commands so users can always reach them
# regardless of session state.
_AUTH_EXEMPT = {
    "auth",           # all auth subcommands (login, logout, etc.)
    "setup",          # dependency setup (needed before first use)
    "--help", "-h",   # help flags
    "--version",
    "version",
}

def _should_skip_auth() -> bool:
    """Return True if the current invocation should bypass the auth gate."""
    args = sys.argv[1:]
    if not args:
        return True   # no command → show help, no auth needed
    first = args[0].lstrip("-")
    return args[0] in _AUTH_EXEMPT or first in _AUTH_EXEMPT


if __name__ == "__main__":
    if not _should_skip_auth():
        try:
            session = gate.require()
            # Inject the active username into the process environment
            # so commands can reference it without re-reading the session file.
            import os
            os.environ["FORGELENS_USER"] = session.username
            os.environ["FORGELENS_ROLE"] = session.role
        except SystemExit:
            # gate.require() already printed the error and called sys.exit()
            raise
        except KeyboardInterrupt:
            print("\n  Interrupted.")
            sys.exit(1)
    app()
