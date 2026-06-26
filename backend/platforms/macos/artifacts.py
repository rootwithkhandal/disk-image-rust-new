"""
macOS Artifact Collector
=========================
Collects forensic artifacts from a live macOS system:
- Unified logs (log show)
- Safari history
- Keychain metadata (no secrets)
- LaunchAgents / LaunchDaemons (persistence)
- Recent items
- APFS snapshots
- Time Machine metadata
"""

from __future__ import annotations

import json
import plistlib
import shutil
import sqlite3
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from loguru import logger


@dataclass
class UnifiedLogEntry:
    timestamp: str
    process: str
    message: str
    category: str = ""
    subsystem: str = ""
    level: str = ""


@dataclass
class SafariHistoryEntry:
    url: str
    title: str = ""
    visit_time: str = ""
    visit_count: int = 0
    profile: str = ""


@dataclass
class LaunchEntry:
    label: str
    program: str
    entry_type: str = ""  # LaunchAgent | LaunchDaemon
    run_at_load: bool = False
    source_path: str = ""
    user: str = ""


@dataclass
class KeychainMetadata:
    keychain_path: str
    size_bytes: int = 0
    modified: str = ""
    note: str = "Keychain content requires user authentication — metadata only"


def _run_text(cmd: list[str], timeout: int = 15) -> str | None:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.stdout if result.returncode == 0 else None
    except FileNotFoundError:
        logger.debug("Command not found: {}", cmd[0])
        return None
    except Exception as exc:
        logger.error("macOS artifact command error: {}", exc)
        return None


def _get_users() -> list[tuple[str, Path]]:
    """Return (username, home_dir) for real users."""
    users = []
    try:
        out = _run_text(["dscl", ".", "-list", "/Users", "NFSHomeDirectory"])
        if not out:
            return users
        for line in out.splitlines():
            parts = line.split()
            if len(parts) < 2:
                continue
            username, home = parts[0], Path(parts[1])
            if (
                home.exists()
                and not username.startswith("_")
                and username not in ("daemon", "nobody", "root")
            ):
                users.append((username, home))
    except Exception as exc:
        logger.debug("User enumeration error: {}", exc)
    return users


# ── Unified logs ──────────────────────────────────────────────────────────────


def collect_unified_logs(
    predicate: str = "",
    last_minutes: int = 60,
    max_entries: int = 500,
) -> list[UnifiedLogEntry]:
    """
    Collect macOS Unified Log entries via `log show`.
    Requires macOS 10.12+.
    """
    entries: list[UnifiedLogEntry] = []
    cmd = [
        "log",
        "show",
        "--style",
        "json",
        "--last",
        f"{last_minutes}m",
    ]
    if predicate:
        cmd += ["--predicate", predicate]

    out = _run_text(cmd, timeout=30)
    if not out:
        return entries

    try:
        # log show --style json outputs a JSON array
        data = json.loads(out)
        if not isinstance(data, list):
            data = [data]
        for entry in data[:max_entries]:
            entries.append(
                UnifiedLogEntry(
                    timestamp=entry.get("timestamp", ""),
                    process=entry.get("processImagePath", entry.get("process", "")),
                    message=entry.get("eventMessage", "")[:500],
                    category=entry.get("category", ""),
                    subsystem=entry.get("subsystem", ""),
                    level=entry.get("messageType", ""),
                )
            )
    except json.JSONDecodeError:
        # Fallback: plain text lines
        for line in out.splitlines()[:max_entries]:
            if line.strip():
                entries.append(
                    UnifiedLogEntry(
                        timestamp="",
                        process="",
                        message=line.strip()[:500],
                    )
                )

    logger.info("Unified logs: collected {} entries", len(entries))
    return entries


# ── Safari history ────────────────────────────────────────────────────────────


def collect_safari_history() -> list[SafariHistoryEntry]:
    """Collect Safari browsing history from all user profiles."""
    entries: list[SafariHistoryEntry] = []

    for username, home in _get_users():
        history_db = home / "Library" / "Safari" / "History.db"
        if not history_db.exists():
            continue
        tmp = Path(tempfile.mktemp(suffix=".db"))
        try:
            shutil.copy2(history_db, tmp)
            conn = sqlite3.connect(str(tmp))
            cursor = conn.execute(
                """
                SELECT hi.url, hv.title, hv.visit_time, hi.visit_count
                FROM history_visits hv
                JOIN history_items hi ON hv.history_item = hi.id
                ORDER BY hv.visit_time DESC
                LIMIT 1000
                """
            )
            for row in cursor.fetchall():
                entries.append(
                    SafariHistoryEntry(
                        url=row[0] or "",
                        title=row[1] or "",
                        visit_time=str(row[2] or ""),
                        visit_count=int(row[3] or 0),
                        profile=username,
                    )
                )
            conn.close()
        except Exception as exc:
            logger.debug("Safari history error ({}): {}", username, exc)
        finally:
            tmp.unlink(missing_ok=True)

    logger.info("Safari history: collected {} entries", len(entries))
    return entries


# ── Keychain metadata ─────────────────────────────────────────────────────────


def collect_keychain_metadata() -> list[KeychainMetadata]:
    """
    Collect keychain file metadata (paths, sizes) — NOT secrets.
    Actual keychain content requires user authentication.
    """
    keychains: list[KeychainMetadata] = []
    keychain_paths = [
        Path("/Library/Keychains"),
        Path("/System/Library/Keychains"),
    ]
    for _username, home in _get_users():
        keychain_paths.append(home / "Library" / "Keychains")

    for kc_dir in keychain_paths:
        if not kc_dir.exists():
            continue
        for kc_file in kc_dir.rglob("*.keychain*"):
            try:
                stat = kc_file.stat()
                keychains.append(
                    KeychainMetadata(
                        keychain_path=str(kc_file),
                        size_bytes=stat.st_size,
                        modified=str(stat.st_mtime),
                    )
                )
            except Exception:
                pass

    logger.info("Keychain metadata: {} file(s) found", len(keychains))
    return keychains


# ── LaunchAgents / LaunchDaemons ──────────────────────────────────────────────


def collect_launch_entries() -> list[LaunchEntry]:
    """
    Collect LaunchAgent and LaunchDaemon plist entries.
    These are the primary persistence mechanisms on macOS.
    """
    entries: list[LaunchEntry] = []

    # System-level
    system_dirs = [
        (Path("/Library/LaunchAgents"), "LaunchAgent", "system"),
        (Path("/Library/LaunchDaemons"), "LaunchDaemon", "system"),
        (Path("/System/Library/LaunchAgents"), "LaunchAgent", "system"),
        (Path("/System/Library/LaunchDaemons"), "LaunchDaemon", "system"),
    ]

    # User-level
    for username, home in _get_users():
        system_dirs.append((home / "Library" / "LaunchAgents", "LaunchAgent", username))

    for launch_dir, entry_type, user in system_dirs:
        if not launch_dir.exists():
            continue
        for plist_file in launch_dir.glob("*.plist"):
            try:
                with open(plist_file, "rb") as f:
                    plist = plistlib.load(f)
                program = plist.get("Program") or (plist.get("ProgramArguments") or [""])[0]
                entries.append(
                    LaunchEntry(
                        label=plist.get("Label", plist_file.stem),
                        program=program,
                        entry_type=entry_type,
                        run_at_load=bool(plist.get("RunAtLoad", False)),
                        source_path=str(plist_file),
                        user=user,
                    )
                )
            except Exception as exc:
                logger.debug("LaunchEntry parse error {}: {}", plist_file, exc)

    logger.info("Launch entries: collected {} item(s)", len(entries))
    return entries


# ── APFS snapshots ────────────────────────────────────────────────────────────


def collect_apfs_snapshots() -> list[dict]:
    """List APFS snapshots for all mounted volumes."""
    snapshots: list[dict] = []
    try:
        raw = subprocess.run(
            ["diskutil", "apfs", "listSnapshots", "-plist", "/"],
            capture_output=True,
            timeout=10,
        )
        if raw.returncode == 0:
            plist = plistlib.loads(raw.stdout)
            for snap in plist.get("Snapshots", []):
                snapshots.append(
                    {
                        "name": snap.get("SnapshotName", ""),
                        "uuid": snap.get("SnapshotUUID", ""),
                        "created": snap.get("SnapshotDate", ""),
                        "xid": snap.get("SnapshotXID", ""),
                    }
                )
    except Exception as exc:
        logger.debug("APFS snapshot error: {}", exc)
    logger.info("APFS snapshots: {} found", len(snapshots))
    return snapshots


# ── Time Machine ──────────────────────────────────────────────────────────────


def collect_time_machine_info() -> dict:
    """Collect Time Machine backup metadata."""
    info: dict = {}
    out = _run_text(["tmutil", "status"])
    if out:
        info["status"] = out
    dest_out = _run_text(["tmutil", "destinationinfo"])
    if dest_out:
        info["destinations"] = dest_out
    latest_out = _run_text(["tmutil", "latestbackup"])
    if latest_out:
        info["latest_backup"] = latest_out
    return info


def collect_all_artifacts() -> dict:
    """Run all macOS artifact collectors and return grouped results."""
    logger.info("Starting macOS artifact collection")
    return {
        "unified_logs": [vars(e) for e in collect_unified_logs()],
        "safari_history": [vars(e) for e in collect_safari_history()],
        "keychain_metadata": [vars(e) for e in collect_keychain_metadata()],
        "launch_entries": [vars(e) for e in collect_launch_entries()],
        "apfs_snapshots": collect_apfs_snapshots(),
        "time_machine": collect_time_machine_info(),
    }
