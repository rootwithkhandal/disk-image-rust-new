"""
macOS Acquisition Platform
===========================
Full macOS forensic acquisition suite.

Modules:
    enumeration — APFS containers, FileVault, SIP, T2/Apple Silicon, disks
    artifacts   — unified logs, Safari history, keychain metadata,
                  LaunchAgents/Daemons, APFS snapshots, Time Machine

Quick usage:
    from platforms.macos import MacOSAcquisition
    result = MacOSAcquisition.collect_all(output_dir="/evidence/CASE-001/EV-001")
"""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from loguru import logger

from platforms.macos.artifacts import collect_all_artifacts
from platforms.macos.enumeration import (
    detect_apfs_containers,
    enumerate_disks,
    get_filevault_status,
    get_macos_system_info,
    get_sip_status,
)


class MacOSAcquisition:
    """Orchestrates all macOS artifact collection into a single output directory."""

    @staticmethod
    def collect_all(
        output_dir: str | Path,
        include_artifacts: bool = True,
    ) -> dict:
        """
        Run all macOS collectors and write JSON output files.

        Args:
            output_dir:        Directory to write artifact JSON files.
            include_artifacts: Collect logs, Safari, keychains, launch entries.

        Returns:
            Summary dict with counts and output file paths.
        """
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)

        summary = {
            "platform": "macos",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "output_dir": str(out),
            "files": {},
            "counts": {},
        }

        # ── System info ───────────────────────────────────────────────────────
        logger.info("Collecting macOS system info")
        sys_info = get_macos_system_info()
        disks = enumerate_disks()
        apfs = detect_apfs_containers()

        system_data = {
            "system_info": asdict(sys_info),
            "disks": [asdict(d) for d in disks],
            "apfs_containers": [asdict(c) for c in apfs],
            "filevault_status": get_filevault_status(),
            "sip_status": get_sip_status(),
        }
        _write(out / "system_info.json", system_data)
        summary["files"]["system_info"] = str(out / "system_info.json")
        summary["counts"]["disks"] = len(disks)
        summary["counts"]["apfs_containers"] = len(apfs)

        # ── Artifacts ─────────────────────────────────────────────────────────
        if include_artifacts:
            logger.info("Collecting macOS artifacts")
            artifact_data = collect_all_artifacts()
            _write(out / "artifacts.json", artifact_data)
            summary["files"]["artifacts"] = str(out / "artifacts.json")
            summary["counts"]["unified_logs"] = len(artifact_data.get("unified_logs", []))
            summary["counts"]["safari_history"] = len(artifact_data.get("safari_history", []))
            summary["counts"]["launch_entries"] = len(artifact_data.get("launch_entries", []))
            summary["counts"]["apfs_snapshots"] = len(artifact_data.get("apfs_snapshots", []))

        _write(out / "collection_summary.json", summary)
        logger.info("macOS collection complete | output={}", out)
        return summary


def _write(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
