"""
WinPmem Setup Helper
====================
Downloads the latest WinPmem release from GitHub into the tools/ directory.

Usage:
    python tools/setup_winpmem.py
    python tools/setup_winpmem.py --arch x86   # for 32-bit systems
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import urllib.request
from pathlib import Path

TOOLS_DIR = Path(__file__).resolve().parent
GITHUB_API = "https://api.github.com/repos/Velocidex/WinPmem/releases/latest"

# Asset name patterns to look for (in preference order)
_ASSET_PATTERNS = {
    "x64": ["winpmem_mini_x64_rc2.exe", "winpmem_mini_x64.exe", "winpmem_x64.exe"],
    "x86": ["winpmem_mini_x86.exe", "winpmem_x86.exe"],
}


def _get_latest_release() -> dict:
    """Fetch the latest release metadata from GitHub API."""
    print("Fetching latest WinPmem release info from GitHub...")
    req = urllib.request.Request(
        GITHUB_API,
        headers={"Accept": "application/vnd.github+json", "User-Agent": "ForgeLens/0.1"},
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _find_asset(assets: list[dict], arch: str) -> dict | None:
    """Find the best matching asset for the given architecture."""
    patterns = _ASSET_PATTERNS.get(arch, _ASSET_PATTERNS["x64"])
    for pattern in patterns:
        for asset in assets:
            if asset["name"].lower() == pattern.lower():
                return asset
    # Fallback: any exe containing 'winpmem'
    for asset in assets:
        name = asset["name"].lower()
        if "winpmem" in name and name.endswith(".exe"):
            return asset
    return None


def _download_file(url: str, dest: Path) -> None:
    """Download a file with a simple progress indicator."""
    print(f"Downloading {dest.name}...")
    req = urllib.request.Request(url, headers={"User-Agent": "ForgeLens/0.1"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        total = int(resp.headers.get("Content-Length", 0))
        downloaded = 0
        chunk_size = 65536
        with open(dest, "wb") as f:
            while True:
                chunk = resp.read(chunk_size)
                if not chunk:
                    break
                f.write(chunk)
                downloaded += len(chunk)
                if total:
                    pct = downloaded / total * 100
                    print(f"\r  {pct:.1f}%  ({downloaded // 1024} KB / {total // 1024} KB)", end="")
    print()


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def main(arch: str = "x64") -> int:
    try:
        release = _get_latest_release()
    except Exception as exc:
        print(f"[ERROR] Could not fetch release info: {exc}")
        print("  Manual download: https://github.com/Velocidex/WinPmem/releases")
        return 1

    tag = release.get("tag_name", "unknown")
    assets = release.get("assets", [])
    print(f"  Latest release: {tag}")

    asset = _find_asset(assets, arch)
    if not asset:
        print(f"[ERROR] No suitable WinPmem binary found for arch={arch}")
        print("  Available assets:")
        for a in assets:
            print(f"    - {a['name']}")
        return 1

    dest = TOOLS_DIR / asset["name"]

    # Skip if already downloaded
    if dest.exists():
        print(f"[OK] Already present: {dest}")
        print(f"     SHA256: {_sha256(dest)}")
        return 0

    try:
        _download_file(asset["browser_download_url"], dest)
    except Exception as exc:
        print(f"[ERROR] Download failed: {exc}")
        return 1

    sha = _sha256(dest)
    size_kb = dest.stat().st_size // 1024
    print(f"\n[OK] Downloaded: {dest}")
    print(f"     Size  : {size_kb} KB")
    print(f"     SHA256: {sha}")
    print()
    print("Next step — acquire RAM (run as Administrator):")
    print(f'  python forgelens.py memory acquire --output evidence\\memory.raw --case CASE-001 --examiner "Your Name"')
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Download WinPmem into tools/")
    parser.add_argument("--arch", choices=["x64", "x86"], default="x64", help="CPU architecture")
    args = parser.parse_args()
    sys.exit(main(arch=args.arch))
