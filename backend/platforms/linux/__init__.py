"""
Linux Acquisition Platform
===========================
Full Linux forensic acquisition suite.

Modules:
    enumeration — block devices, LVM, RAID, encrypted partitions, filesystems
    artifacts   — bash history, SSH keys, crontabs, syslog, auth.log, journalctl, Docker
    memory      — AVML / LiME RAM acquisition

Quick usage:
    from platforms.linux import LinuxAcquisition
    result = LinuxAcquisition.collect_all(output_dir="/evidence/CASE-001/EV-001")
"""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional  # noqa: F401 — re-exported for callers

from loguru import logger

from platforms.linux.artifacts import collect_all_artifacts
from platforms.linux.enumeration import (
    detect_block_devices,
    detect_encrypted_partitions,
    detect_filesystem_types,
    detect_lvm_volumes,
    detect_raid_arrays,
)
from platforms.linux.memory import acquire_ram
from platforms.linux.memory import get_ram_info as get_ram_info


class LinuxAcquisition:
    """Orchestrates all Linux artifact collection into a single output directory."""

    @staticmethod
    def collect_all(
        output_dir: str | Path,
        include_artifacts: bool = True,
        include_ram: bool = False,
        ram_output_path: str | Path | None = None,
    ) -> dict:
        """
        Run all Linux collectors and write JSON output files.

        Args:
            output_dir:       Directory to write artifact JSON files.
            include_artifacts: Collect shell history, SSH, crontabs, logs.
            include_ram:      Acquire RAM dump.
            ram_output_path:  Path for RAM dump file.

        Returns:
            Summary dict with counts and output file paths.
        """
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)

        summary = {
            "platform": "linux",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "output_dir": str(out),
            "files": {},
            "counts": {},
        }

        # ── System / disk enumeration ─────────────────────────────────────────
        logger.info("Collecting Linux system info")
        block_devices = detect_block_devices()
        lvm_volumes = detect_lvm_volumes()
        raid_arrays = detect_raid_arrays()
        encrypted = detect_encrypted_partitions()
        fs_types = detect_filesystem_types()

        system_data = {
            "block_devices": [asdict(d) for d in block_devices],
            "lvm_volumes": [asdict(v) for v in lvm_volumes],
            "raid_arrays": [asdict(r) for r in raid_arrays],
            "encrypted_partitions": [asdict(e) for e in encrypted],
            "filesystem_types": fs_types,
        }
        _write(out / "system_info.json", system_data)
        summary["files"]["system_info"] = str(out / "system_info.json")
        summary["counts"]["block_devices"] = len(block_devices)
        summary["counts"]["lvm_volumes"] = len(lvm_volumes)
        summary["counts"]["raid_arrays"] = len(raid_arrays)
        summary["counts"]["encrypted_partitions"] = len(encrypted)

        # ── Artifacts ─────────────────────────────────────────────────────────
        if include_artifacts:
            logger.info("Collecting Linux artifacts")
            artifact_data = collect_all_artifacts()
            _write(out / "artifacts.json", artifact_data)
            summary["files"]["artifacts"] = str(out / "artifacts.json")
            summary["counts"]["bash_history"] = len(artifact_data.get("bash_history", []))
            summary["counts"]["ssh_artifacts"] = len(artifact_data.get("ssh_artifacts", []))
            summary["counts"]["crontabs"] = len(artifact_data.get("crontabs", []))

        # ── RAM acquisition ───────────────────────────────────────────────────
        if include_ram:
            logger.info("Starting Linux RAM acquisition")
            ram_path = ram_output_path or (out / "memory.lime")
            ram_result = acquire_ram(ram_path)
            summary["ram_acquisition"] = asdict(ram_result)
            summary["files"]["ram_dump"] = str(ram_path) if ram_result.success else None

        _write(out / "collection_summary.json", summary)
        logger.info("Linux collection complete | output={}", out)
        return summary


def _write(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
