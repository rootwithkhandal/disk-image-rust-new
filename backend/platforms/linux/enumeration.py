"""
Linux Enumeration
=================
Detects block devices, LVM volumes, RAID arrays,
encrypted partitions, and filesystem types.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from loguru import logger


@dataclass
class BlockDevice:
    name: str
    path: str
    device_type: str = ""
    size_bytes: int = 0
    filesystem: str = ""
    mount_point: str = ""
    is_removable: bool = False
    is_readonly: bool = False
    is_encrypted: bool = False
    encryption_type: str = ""
    uuid: str = ""
    label: str = ""
    children: list[BlockDevice] = field(default_factory=list)

    @property
    def size_gb(self) -> float:
        return round(self.size_bytes / (1024**3), 2)


@dataclass
class LVMInfo:
    vg_name: str
    lv_name: str
    lv_path: str
    size_bytes: int = 0
    lv_attr: str = ""
    mount_point: str = ""


@dataclass
class RAIDInfo:
    device: str
    level: str = ""
    state: str = ""
    members: list[str] = field(default_factory=list)
    size_bytes: int = 0


def _run(cmd: list[str], timeout: int = 10) -> str | None:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.stdout.strip() if result.returncode == 0 else None
    except FileNotFoundError:
        logger.debug("Command not found: {}", cmd[0])
        return None
    except Exception as exc:
        logger.error("Command error {}: {}", cmd, exc)
        return None


def detect_block_devices() -> list[BlockDevice]:
    """Enumerate all block devices via lsblk."""
    devices: list[BlockDevice] = []
    out = _run(
        [
            "lsblk",
            "-J",
            "-b",
            "-o",
            "NAME,TYPE,SIZE,FSTYPE,MOUNTPOINT,UUID,LABEL,RM,RO,TRAN",
        ]
    )
    if not out:
        return devices
    try:
        data = json.loads(out)
        for blk in data.get("blockdevices", []):
            devices.append(_parse_block(blk))
    except Exception as exc:
        logger.error("lsblk parse error: {}", exc)
    logger.info("Linux: detected {} block device(s)", len(devices))
    return devices


def _parse_block(blk: dict) -> BlockDevice:
    name = blk.get("name", "")
    fstype = blk.get("fstype") or ""
    is_encrypted = fstype in ("crypto_LUKS", "BitLocker")
    dev = BlockDevice(
        name=name,
        path=f"/dev/{name}",
        device_type=blk.get("type", ""),
        size_bytes=int(blk.get("size") or 0),
        filesystem=fstype,
        mount_point=blk.get("mountpoint") or "",
        is_removable=str(blk.get("rm", "0")) == "1",
        is_readonly=str(blk.get("ro", "0")) == "1",
        is_encrypted=is_encrypted,
        encryption_type="LUKS" if is_encrypted else "",
        uuid=blk.get("uuid") or "",
        label=blk.get("label") or "",
    )
    for child in blk.get("children", []):
        dev.children.append(_parse_block(child))
    return dev


def detect_lvm_volumes() -> list[LVMInfo]:
    """Enumerate LVM logical volumes via lvs."""
    volumes: list[LVMInfo] = []
    out = _run(["lvs", "--reportformat", "json", "--units", "b", "--nosuffix"])
    if not out:
        return volumes
    try:
        data = json.loads(out)
        for report in data.get("report", []):
            for lv in report.get("lv", []):
                volumes.append(
                    LVMInfo(
                        vg_name=lv.get("vg_name", ""),
                        lv_name=lv.get("lv_name", ""),
                        lv_path=lv.get("lv_path", ""),
                        size_bytes=int(lv.get("lv_size", 0) or 0),
                        lv_attr=lv.get("lv_attr", ""),
                    )
                )
    except Exception as exc:
        logger.debug("LVM parse error: {}", exc)
    logger.info("LVM: detected {} logical volume(s)", len(volumes))
    return volumes


def detect_raid_arrays() -> list[RAIDInfo]:
    """Detect software RAID arrays via /proc/mdstat."""
    arrays: list[RAIDInfo] = []
    try:
        mdstat = Path("/proc/mdstat").read_text()
        current: RAIDInfo | None = None
        for line in mdstat.splitlines():
            line = line.strip()
            if line.startswith("md"):
                parts = line.split()
                dev = f"/dev/{parts[0]}"
                level = parts[3] if len(parts) > 3 else ""
                state = parts[2] if len(parts) > 2 else ""
                members = [p.split("[")[0] for p in parts[4:] if not p.startswith("(")]
                current = RAIDInfo(device=dev, level=level, state=state, members=members)
                arrays.append(current)
    except FileNotFoundError:
        logger.debug("/proc/mdstat not found — no RAID or not Linux")
    except Exception as exc:
        logger.debug("RAID detection error: {}", exc)
    logger.info("RAID: detected {} array(s)", len(arrays))
    return arrays


def detect_encrypted_partitions() -> list[BlockDevice]:
    """Return only encrypted (LUKS) block devices."""
    return [d for d in detect_block_devices() if d.is_encrypted]


def detect_filesystem_types() -> dict[str, str]:
    """Return a map of device path -> filesystem type for all mounted devices."""
    out = _run(["lsblk", "-J", "-o", "NAME,FSTYPE,MOUNTPOINT"])
    result: dict[str, str] = {}
    if not out:
        return result
    try:
        data = json.loads(out)

        def _walk(blk: dict) -> None:
            name = blk.get("name", "")
            fstype = blk.get("fstype") or ""
            if fstype:
                result[f"/dev/{name}"] = fstype
            for child in blk.get("children", []):
                _walk(child)

        for blk in data.get("blockdevices", []):
            _walk(blk)
    except Exception as exc:
        logger.debug("Filesystem type detection error: {}", exc)
    return result
