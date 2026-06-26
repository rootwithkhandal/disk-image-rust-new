\"\"\"
ForgeLens Desktop GUI Launcher
=============================
Adds backend/ to sys.path and runs the main CTk application window.
\"\"\"

from __future__ import annotations

import sys
from pathlib import Path

# Add backend/ and the project root to sys.path
project_root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(project_root))
sys.path.insert(0, str(project_root / "backend"))

from frontend.app import main

if __name__ == "__main__":
    main()
