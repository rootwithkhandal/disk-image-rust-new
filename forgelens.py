#!/usr/bin/env python
"""
ForgeLens CLI launcher.
Run from project root: python forgelens.py <command>
"""

import sys
import os
from pathlib import Path

# Add backend/ to path
sys.path.insert(0, str(Path(__file__).parent / "backend"))

from cli.main import app


if __name__ == "__main__":
    os.environ["FORGELENS_USER"] = "local"
    os.environ["FORGELENS_ROLE"] = "admin"
    app()
