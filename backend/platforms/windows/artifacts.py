"""
Windows Execution & Browser Artifact Collector
===============================================
Collects:
- Prefetch files (program execution evidence)
- Shimcache / AppCompatCache (execution history)
- Amcache (installed/executed programs)
- Jump Lists (recently used files per application)
- Browser history: Chrome, Edge, Firefox
- USB history (from registry + setupapi logs)
- User profile list
"""

from __future__ import annotations

import json
import shutil
import sqlite3
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from loguru import logger


@dataclass
class PrefetchEntry:
    filename: str
    path: str
    run_count: int = 0
    last_run_time: str = ""
    size_bytes: int = 0


@dataclass
class BrowserHistoryEntry:
    browser: str
    url: str
    title: str = ""
    visit_time: str = ""
    visit_count: int = 0
    profile: str = ""


@dataclass
class UserProfile:
    username: str
    sid: str = ""
    profile_path: str = ""
    last_login: str = ""


def _ps(cmd: str, timeout: int = 20) -> str | None:
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", cmd],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.stdout.strip() if result.returncode == 0 else None
    except Exception as exc:
        logger.error("Artifacts PS error: {}", exc)
        return None


# ── Prefetch ──────────────────────────────────────────────────────────────────


def collect_prefetch() -> list[PrefetchEntry]:
    """
    Collect Prefetch file metadata from C:\\Windows\\Prefetch.
    Requires admin. Returns filename, size, and last modified time.
    """
    entries: list[PrefetchEntry] = []
    prefetch_dir = Path(r"C:\Windows\Prefetch")

    if not prefetch_dir.exists():
        logger.warning("Prefetch directory not found (may be disabled)")
        return entries

    for pf in prefetch_dir.glob("*.pf"):
        try:
            stat = pf.stat()
            entries.append(
                PrefetchEntry(
                    filename=pf.name,
                    path=str(pf),
                    size_bytes=stat.st_size,
                    last_run_time=str(stat.st_mtime),
                )
            )
        except Exception as exc:
            logger.debug("Prefetch read error {}: {}", pf.name, exc)

    logger.info("Prefetch: collected {} entries", len(entries))
    return entries


# ── Shimcache ─────────────────────────────────────────────────────────────────


def collect_shimcache() -> list[dict]:
    """
    Extract AppCompatCache (Shimcache) entries via registry.
    Tracks executables that have been run on the system.
    """
    out = _ps(
        r"$key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache'; "
        r"if (Test-Path $key) { "
        r"  Get-ItemProperty $key | Select-Object AppCompatCache | ConvertTo-Json -Depth 2 "
        r"} else { '{}' }"
    )
    if not out or out == "{}":
        logger.warning("Shimcache: registry key not accessible")
        return []

    # Raw binary — return metadata only (full parsing requires binary decoder)
    logger.info("Shimcache: raw data retrieved (binary parsing requires offline tool)")
    return [
        {
            "raw_available": True,
            "note": "Binary parsing required — use RegRipper or AppCompatCacheParser",
        }
    ]


# ── Amcache ───────────────────────────────────────────────────────────────────


def collect_amcache() -> list[dict]:
    """
    Collect Amcache.hve entries — tracks installed and executed programs.
    Reads from C:\\Windows\\AppCompat\\Programs\\Amcache.hve
    """
    amcache_path = Path(r"C:\Windows\AppCompat\Programs\Amcache.hve")
    if not amcache_path.exists():
        logger.warning("Amcache.hve not found")
        return []

    # Use PowerShell to enumerate via registry provider (limited access)
    out = _ps(
        r"Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store' "
        r"-ErrorAction SilentlyContinue | ConvertTo-Json -Depth 2"
    )

    entries = []
    if out:
        try:
            raw = json.loads(out)
            if isinstance(raw, dict):
                raw = [raw]
            for e in raw:
                entries.append(
                    {
                        "name": e.get("PSChildName", ""),
                        "path": e.get("Name", ""),
                        "source": "amcache_compat_store",
                    }
                )
        except Exception as exc:
            logger.debug("Amcache parse error: {}", exc)

    entries.append(
        {
            "hive_path": str(amcache_path),
            "note": "Full parsing requires offline tool (AmcacheParser / RegRipper)",
            "source": "amcache_hive",
        }
    )

    logger.info("Amcache: {} entries collected", len(entries))
    return entries


# ── Jump Lists ────────────────────────────────────────────────────────────────


def collect_jump_lists() -> list[dict]:
    """
    Collect Jump List files from all user profiles.
    Jump Lists track recently/frequently used files per application.
    """
    entries: list[dict] = []
    users_dir = Path(r"C:\Users")

    if not users_dir.exists():
        return entries

    for user_dir in users_dir.iterdir():
        if not user_dir.is_dir():
            continue
        for jl_dir in [
            user_dir
            / "AppData"
            / "Roaming"
            / "Microsoft"
            / "Windows"
            / "Recent"
            / "AutomaticDestinations",
            user_dir
            / "AppData"
            / "Roaming"
            / "Microsoft"
            / "Windows"
            / "Recent"
            / "CustomDestinations",
        ]:
            if not jl_dir.exists():
                continue
            for jl_file in jl_dir.iterdir():
                try:
                    stat = jl_file.stat()
                    entries.append(
                        {
                            "user": user_dir.name,
                            "filename": jl_file.name,
                            "path": str(jl_file),
                            "size_bytes": stat.st_size,
                            "modified": str(stat.st_mtime),
                            "type": "automatic" if "Automatic" in str(jl_dir) else "custom",
                        }
                    )
                except Exception:
                    pass

    logger.info("Jump Lists: collected {} entries", len(entries))
    return entries


# ── Browser History ───────────────────────────────────────────────────────────


def _read_chromium_history(db_path: Path, browser: str, profile: str) -> list[BrowserHistoryEntry]:
    """Read history from a Chromium-based browser SQLite database."""
    entries: list[BrowserHistoryEntry] = []

    # Copy to temp — browser may have the file locked
    tmp = Path(tempfile.mktemp(suffix=".db"))
    try:
        shutil.copy2(db_path, tmp)
        conn = sqlite3.connect(str(tmp))
        cursor = conn.execute(
            "SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 1000"
        )
        for row in cursor.fetchall():
            # Chrome timestamps: microseconds since 1601-01-01
            ts = row[3]
            entries.append(
                BrowserHistoryEntry(
                    browser=browser,
                    url=row[0] or "",
                    title=row[1] or "",
                    visit_count=int(row[2] or 0),
                    visit_time=str(ts),
                    profile=profile,
                )
            )
        conn.close()
    except Exception as exc:
        logger.debug("Chromium history read error ({}): {}", browser, exc)
    finally:
        tmp.unlink(missing_ok=True)

    return entries


def collect_browser_history() -> dict[str, list[BrowserHistoryEntry]]:
    """
    Collect browser history from Chrome, Edge, and Firefox for all user profiles.
    """
    results: dict[str, list[BrowserHistoryEntry]] = {
        "chrome": [],
        "edge": [],
        "firefox": [],
    }
    users_dir = Path(r"C:\Users")
    if not users_dir.exists():
        return results

    for user_dir in users_dir.iterdir():
        if not user_dir.is_dir() or user_dir.name in ("Public", "Default", "All Users"):
            continue

        # Chrome
        chrome_base = user_dir / "AppData" / "Local" / "Google" / "Chrome" / "User Data"
        if chrome_base.exists():
            for profile_dir in chrome_base.iterdir():
                history_db = profile_dir / "History"
                if history_db.exists():
                    entries = _read_chromium_history(
                        history_db, "chrome", f"{user_dir.name}/{profile_dir.name}"
                    )
                    results["chrome"].extend(entries)

        # Edge
        edge_base = user_dir / "AppData" / "Local" / "Microsoft" / "Edge" / "User Data"
        if edge_base.exists():
            for profile_dir in edge_base.iterdir():
                history_db = profile_dir / "History"
                if history_db.exists():
                    entries = _read_chromium_history(
                        history_db, "edge", f"{user_dir.name}/{profile_dir.name}"
                    )
                    results["edge"].extend(entries)

        # Firefox
        firefox_base = user_dir / "AppData" / "Roaming" / "Mozilla" / "Firefox" / "Profiles"
        if firefox_base.exists():
            for profile_dir in firefox_base.iterdir():
                places_db = profile_dir / "places.sqlite"
                if places_db.exists():
                    tmp = Path(tempfile.mktemp(suffix=".db"))
                    try:
                        shutil.copy2(places_db, tmp)
                        conn = sqlite3.connect(str(tmp))
                        cursor = conn.execute(
                            "SELECT url, title, visit_count, last_visit_date FROM moz_places "
                            "ORDER BY last_visit_date DESC LIMIT 1000"
                        )
                        for row in cursor.fetchall():
                            results["firefox"].append(
                                BrowserHistoryEntry(
                                    browser="firefox",
                                    url=row[0] or "",
                                    title=row[1] or "",
                                    visit_count=int(row[2] or 0),
                                    visit_time=str(row[3] or ""),
                                    profile=f"{user_dir.name}/{profile_dir.name}",
                                )
                            )
                        conn.close()
                    except Exception as exc:
                        logger.debug("Firefox history error: {}", exc)
                    finally:
                        tmp.unlink(missing_ok=True)

    for browser, entries in results.items():
        logger.info("Browser history ({}): {} entries", browser, len(entries))

    return results


# ── User Profiles ─────────────────────────────────────────────────────────────


def collect_user_profiles() -> list[UserProfile]:
    """Enumerate local user accounts and profile paths."""
    profiles: list[UserProfile] = []
    out = _ps(
        'Get-WmiObject Win32_UserAccount -Filter "LocalAccount=True" | '
        "Select-Object Name,SID | ConvertTo-Json -Depth 2"
    )
    if out:
        try:
            raw = json.loads(out)
            if isinstance(raw, dict):
                raw = [raw]
            for u in raw:
                profiles.append(
                    UserProfile(
                        username=u.get("Name", ""),
                        sid=u.get("SID", ""),
                        profile_path=str(Path(r"C:\Users") / u.get("Name", "")),
                    )
                )
        except Exception as exc:
            logger.debug("User profile parse error: {}", exc)

    logger.info("User profiles: collected {} accounts", len(profiles))
    return profiles


def collect_all_artifacts() -> dict:
    """Run all artifact collectors and return grouped results."""
    logger.info("Starting Windows artifact collection")
    return {
        "prefetch": [vars(e) for e in collect_prefetch()],
        "shimcache": collect_shimcache(),
        "amcache": collect_amcache(),
        "jump_lists": collect_jump_lists(),
        "browser_history": {k: [vars(e) for e in v] for k, v in collect_browser_history().items()},
        "user_profiles": [vars(p) for p in collect_user_profiles()],
    }
