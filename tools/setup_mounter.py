"""
Disk Image Mount Tool Setup
=============================
Sets up open-source disk image mounting tools for ForgeLens on Windows.

Tools:
  ImDisk Toolkit (GPL)       — auto-installs via winget or direct download
  Arsenal Image Mounter      — open source (AGPL), manual download instructions

Usage:
    python tools/setup_mounter.py               # install ImDisk
    python tools/setup_mounter.py --tool aim    # AIM instructions
    python tools/setup_mounter.py --tool all    # both
"""

from __future__ import annotations

import argparse
import hashlib
import shutil
import subprocess
import sys
import urllib.request
from pathlib import Path

TOOLS_DIR = Path(__file__).resolve().parent

# ImDisk direct download from SourceForge (GPL, open source)
IMDISK_SF_URL = "https://sourceforge.net/projects/imdisk-toolkit/files/latest/download"
# ImDisk winget package ID
IMDISK_WINGET_ID = "ArsenalRecon.ImDisk"
# ImDisk choco package
IMDISK_CHOCO = "imdisk"


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _check_imdisk_installed() -> bool:
    """Check if imdisk.exe is available on PATH or in System32."""
    return bool(
        shutil.which("imdisk") or
        Path(r"C:\Windows\System32\imdisk.exe").exists() or
        Path(r"C:\Windows\SysWOW64\imdisk.exe").exists() or
        (TOOLS_DIR / "imdisk.exe").exists()
    )


def _try_winget() -> bool:
    """Try to install ImDisk via winget."""
    if not shutil.which("winget"):
        return False
    print("  Trying winget install...")
    result = subprocess.run(
        ["winget", "install", "--id", IMDISK_WINGET_ID, "--silent", "--accept-package-agreements",
         "--accept-source-agreements"],
        capture_output=True, text=True, timeout=120,
    )
    if result.returncode == 0:
        print("  [OK] Installed via winget")
        return True
    print(f"  winget failed: {result.stderr.strip()[:100]}")
    return False


def _try_choco() -> bool:
    """Try to install ImDisk via Chocolatey."""
    if not shutil.which("choco"):
        return False
    print("  Trying chocolatey install...")
    result = subprocess.run(
        ["choco", "install", IMDISK_CHOCO, "-y", "--no-progress"],
        capture_output=True, text=True, timeout=120,
    )
    if result.returncode == 0:
        print("  [OK] Installed via Chocolatey")
        return True
    print(f"  choco failed: {result.stderr.strip()[:100]}")
    return False


def setup_imdisk() -> int:
    """Install ImDisk Toolkit (GPL open-source)."""
    print("── ImDisk Toolkit (GPL, open source) ──────────────────────────────")
    print("Source: https://sourceforge.net/projects/imdisk-toolkit/")
    print()

    # Check if already installed
    if _check_imdisk_installed():
        path = shutil.which("imdisk") or r"C:\Windows\System32\imdisk.exe"
        print(f"[OK] ImDisk already installed: {path}")
        print()
        print("Mount a DD image:")
        print('  python forgelens.py image mount evidence\\image.dd --drive Z --case CASE-001 --examiner "You"')
        return 0

    print("ImDisk not found. Attempting auto-install...\n")

    # Try package managers first
    if _try_winget():
        if _check_imdisk_installed():
            print("\n[OK] ImDisk is ready.")
            _print_usage()
            return 0

    if _try_choco():
        if _check_imdisk_installed():
            print("\n[OK] ImDisk is ready.")
            _print_usage()
            return 0

    # Manual instructions
    print("\n[INFO] Could not auto-install (no winget/choco or requires Administrator).")
    print()
    print("Manual install (2 steps):")
    print("  1. Download the installer:")
    print("     https://sourceforge.net/projects/imdisk-toolkit/files/latest/download")
    print()
    print("  2. Run ImDiskToolkit.exe as Administrator")
    print("     It installs imdisk.exe to C:\\Windows\\System32\\")
    print()
    print("  3. ForgeLens will detect it automatically after install.")
    print()
    print("Then mount:")
    print('  python forgelens.py image mount evidence\\image.dd --drive Z')
    return 1


def setup_aim() -> int:
    """Show Arsenal Image Mounter setup instructions."""
    print("── Arsenal Image Mounter (AGPL, open source) ──────────────────────")
    print("Source: https://github.com/ArsenalRecon/Arsenal-Image-Mounter")
    print("Binary: https://arsenalrecon.com/products/arsenal-image-mounter/downloads")
    print()
    print("AIM is the most capable open-source mounter — supports DD, E01, VHD,")
    print("AFF, split images, BitLocker volumes, and Volume Shadow Copies.")
    print()
    print("Install steps:")
    print("  1. Go to: https://arsenalrecon.com/products/arsenal-image-mounter/downloads")
    print("  2. Download the latest AIM zip")
    print("  3. Extract aim_cli.exe from the zip → place in tools/aim_cli.exe")
    print()

    # Check if already present
    aim = TOOLS_DIR / "aim_cli.exe"
    if aim.exists():
        print(f"[OK] aim_cli.exe already present: {aim}")
        print(f"     SHA256: {_sha256(aim)}")
    else:
        print("[MISSING] tools/aim_cli.exe not found")
        print()
        print("Quick check after placing aim_cli.exe:")
        print("  python forgelens.py setup check")

    print()
    print("Mount with AIM (supports all formats):")
    print('  python forgelens.py image mount evidence\\image.e01 --drive Z')
    return 0 if aim.exists() else 1


def _print_usage() -> None:
    print()
    print("Usage:")
    print('  python forgelens.py image mount evidence\\image.dd --drive Z --case CASE-001 --examiner "You"')
    print('  python forgelens.py image mounts')
    print('  python forgelens.py image unmount <MOUNT_ID>')


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Set up open-source disk image mounting tools for ForgeLens"
    )
    parser.add_argument(
        "--tool",
        choices=["imdisk", "aim", "all"],
        default="imdisk",
        help="Tool to set up (default: imdisk)",
    )
    args = parser.parse_args()

    if args.tool == "imdisk":
        return setup_imdisk()
    elif args.tool == "aim":
        return setup_aim()
    else:  # all
        rc1 = setup_imdisk()
        print()
        rc2 = setup_aim()
        return rc1 if rc1 != 0 else rc2


if __name__ == "__main__":
    sys.exit(main())
