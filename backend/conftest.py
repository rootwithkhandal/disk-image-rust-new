"""
Pytest configuration — adds backend/ to sys.path so that
`from core.xxx import ...` and `from platforms.xxx import ...` work
without installing the package.
"""

import sys
from pathlib import Path

# Insert backend/ directory at the front of sys.path
_backend = str(Path(__file__).parent)
if _backend not in sys.path:
    sys.path.insert(0, _backend)
