"""
Windows Acquisition Platform
==============================
Full Windows forensic acquisition suite.

Modules:
    enumeration   — drives, partitions, BitLocker, shadow copies, OS version
    registry      — run keys, USB history, UserAssist, RecentDocs
    event_logs    — login activity, PowerShell, process creation, services, RDP
    artifacts     — prefetch, shimcache, amcache, jump lists, browser history
    live_response — processes, network connections, ARP, DNS, scheduled tasks
    memory        — WinPMEM RAM acquisition

Quick usage:
    from platform.windows import WindowsAcquisition
    result = WindowsAcquisition.collect_all(output_dir="/evidence/CASE-001/EV-001")
"""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional  # noqa: F401 — re-exported for callers

from loguru import logger

from platforms.windows.artifacts import collect_all_artifacts
from platforms.windows.enumeration import (
    enumerate_mounted_partitions,
    enumerate_physical_drives,
    enumerate_shadow_copies,
    get_bitlocker_status,
    get_windows_version,
)
from platforms.windows.event_logs import collect_all_event_logs
from platforms.windows.live_response import collect_all_live_response
from platforms.windows.memory import acquire_ram
from platforms.windows.memory import get_ram_info as get_ram_info
from platforms.windows.registry import collect_all_registry_artifacts


class WindowsAcquisition:
    """
    Orchestrates all Windows artifact collection into a single output directory.
    """

    @staticmethod
    def collect_all(
        output_dir: str | Path,
        include_live_response: bool = True,
        include_registry: bool = True,
        include_event_logs: bool = True,
        include_artifacts: bool = True,
        include_ram: bool = False,
        ram_output_path: str | Path | None = None,
    ) -> dict:
        """
        Run all Windows collectors and write JSON output files.

        Args:
            output_dir:           Directory to write artifact JSON files.
            include_live_response: Capture volatile state (processes, network, etc.)
            include_registry:     Collect registry artifacts.
            include_event_logs:   Parse event logs.
            include_artifacts:    Collect execution + browser artifacts.
            include_ram:          Acquire RAM dump via WinPMEM.
            ram_output_path:      Path for RAM dump file.

        Returns:
            Summary dict with counts and output file paths.
        """
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)

        summary = {
            "platform": "windows",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "output_dir": str(out),
            "files": {},
            "counts": {},
        }

        # ── System info ───────────────────────────────────────────────────────
        logger.info("Collecting Windows system info")
        sys_info = get_windows_version()
        drives = enumerate_physical_drives()
        partitions = enumerate_mounted_partitions()
        bitlocker = get_bitlocker_status()
        shadows = enumerate_shadow_copies()

        system_data = {
            "system_info": asdict(sys_info),
            "physical_drives": [asdict(d) for d in drives],
            "mounted_partitions": partitions,
            "bitlocker_status": [asdict(b) for b in bitlocker],
            "shadow_copies": [asdict(s) for s in shadows],
        }
        _write(out / "system_info.json", system_data)
        summary["files"]["system_info"] = str(out / "system_info.json")
        summary["counts"]["drives"] = len(drives)
        summary["counts"]["shadow_copies"] = len(shadows)

        # ── Registry ──────────────────────────────────────────────────────────
        if include_registry:
            logger.info("Collecting registry artifacts")
            reg_data = collect_all_registry_artifacts()
            reg_serialized = {k: [asdict(a) for a in v] for k, v in reg_data.items()}
            _write(out / "registry_artifacts.json", reg_serialized)
            summary["files"]["registry"] = str(out / "registry_artifacts.json")
            summary["counts"]["registry_entries"] = sum(len(v) for v in reg_data.values())

        # ── Event logs ────────────────────────────────────────────────────────
        if include_event_logs:
            logger.info("Collecting event logs")
            evtx_data = collect_all_event_logs()
            evtx_serialized = {k: [asdict(e) for e in v] for k, v in evtx_data.items()}
            _write(out / "event_logs.json", evtx_serialized)
            summary["files"]["event_logs"] = str(out / "event_logs.json")
            summary["counts"]["event_log_entries"] = sum(len(v) for v in evtx_data.values())

        # ── Execution + browser artifacts ─────────────────────────────────────
        if include_artifacts:
            logger.info("Collecting execution and browser artifacts")
            artifact_data = collect_all_artifacts()
            _write(out / "artifacts.json", artifact_data)
            summary["files"]["artifacts"] = str(out / "artifacts.json")
            summary["counts"]["prefetch"] = len(artifact_data.get("prefetch", []))
            summary["counts"]["browser_history"] = sum(
                len(v) for v in artifact_data.get("browser_history", {}).values()
            )

        # ── Live response ─────────────────────────────────────────────────────
        if include_live_response:
            logger.info("Collecting live response data")
            live_data = collect_all_live_response()
            _write(out / "live_response.json", live_data)
            summary["files"]["live_response"] = str(out / "live_response.json")
            summary["counts"]["processes"] = len(live_data.get("processes", []))
            summary["counts"]["network_connections"] = len(live_data.get("network_connections", []))

        # ── RAM acquisition ───────────────────────────────────────────────────
        if include_ram:
            logger.info("Starting RAM acquisition")
            ram_path = ram_output_path or (out / "memory.raw")
            ram_result = acquire_ram(ram_path)
            summary["ram_acquisition"] = asdict(ram_result)
            summary["files"]["ram_dump"] = str(ram_path) if ram_result.success else None

        _write(out / "collection_summary.json", summary)
        logger.info(
            "Windows collection complete | {} artifact categories | output={}",
            len(summary["files"]),
            out,
        )
        return summary


def _write(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
