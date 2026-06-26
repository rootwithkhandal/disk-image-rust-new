"""
Disk Enumeration Module
=======================
Enumerates partitions, filesystems, and volume details from detected
devices. Builds a structured DiskMap used by the imaging engine.

Usage:
    from core.acquisition.disk_enumerator import DiskEnumerator
    from core.acquisition.device_detector import DeviceDetector

    devices = DeviceDetector.detect()
    disk_map = DiskEnumerator.enumerate(devices[0])
    print(disk_map)
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass, field

from loguru import logger

import platform
from core.acquisition.device_detector import Device, DeviceType


@dataclass
class PartitionInfo:
    """Detailed partition metadata."""

    index: int
    device_path: str  # e.g. /dev/sda1, \\.\PhysicalDrive0
    start_sector: int = 0
    end_sector: int = 0
    size_bytes: int = 0
    filesystem: str = ""
    label: str = ""
    mount_point: str = ""
    is_encrypted: bool = False
    encryption_type: str = ""  # BitLocker, LUKS, FileVault
    is_active: bool = False
    raw: dict = field(default_factory=dict)

    @property
    def size_gb(self) -> float:
        return round(self.size_bytes / (1024**3), 2)

    def __str__(self) -> str:
        enc = f" [{self.encryption_type}]" if self.is_encrypted else ""
        return (
            f"  Partition {self.index}: {self.device_path} | "
            f"{self.filesystem or 'unknown'}{enc} | "
            f"{self.size_gb} GB | mount={self.mount_point or 'none'}"
        )


@dataclass
class DiskMap:
    """Full disk layout including all partitions."""

    device: Device
    sector_size: int = 512
    total_sectors: int = 0
    partitions: list[PartitionInfo] = field(default_factory=list)
    has_encrypted_partitions: bool = False
    partition_table: str = ""  # MBR, GPT, APM

    def __str__(self) -> str:
        lines = [
            f"DiskMap: {self.device.device_id} | {self.partition_table} | "
            f"{len(self.partitions)} partition(s)"
        ]
        for p in self.partitions:
            lines.append(str(p))
        return "\n".join(lines)


class DiskEnumerator:
    """
    Enumerates partition layout and filesystem details for a given device.
    """

    @staticmethod
    def enumerate(device: Device) -> DiskMap:
        """Build a full DiskMap for the given device."""
        os_name = platform.system()
        logger.info("Enumerating disk: {} on {}", device.device_id, os_name)

        disk_map = DiskMap(device=device)

        try:
            if os_name == "Windows":
                _enumerate_windows(device, disk_map)
            elif os_name == "Linux":
                _enumerate_linux(device, disk_map)
            elif os_name == "Darwin":
                _enumerate_macos(device, disk_map)
            else:
                logger.warning("Unsupported platform for disk enumeration: {}", os_name)
        except Exception as exc:
            logger.error("Disk enumeration failed for {}: {}", device.device_id, exc)

        disk_map.has_encrypted_partitions = any(p.is_encrypted for p in disk_map.partitions)

        logger.info(
            "Enumerated {} partition(s) on {} | encrypted={}",
            len(disk_map.partitions),
            device.device_id,
            disk_map.has_encrypted_partitions,
        )
        return disk_map

    @staticmethod
    def enumerate_all(devices: list[Device]) -> list[DiskMap]:
        """Enumerate all provided devices."""
        return [
            DiskEnumerator.enumerate(d)
            for d in devices
            if d.device_type not in (DeviceType.ANDROID,)
        ]


# ── Windows ───────────────────────────────────────────────────────────────────


def _enumerate_windows(device: Device, disk_map: DiskMap) -> None:
    """Use PowerShell to get partition info."""
    import json

    # Extract disk number from DeviceID e.g. \\.\PHYSICALDRIVE0 -> 0
    disk_num = "".join(filter(str.isdigit, device.device_id))
    if not disk_num:
        logger.warning("Cannot parse disk number from: {}", device.device_id)
        return

    ps_cmd = (
        f"Get-Partition -DiskNumber {disk_num} | "
        "Select-Object PartitionNumber, Offset, Size, Type, IsActive, "
        "DriveLetter, GptType | ConvertTo-Json"
    )

    result = subprocess.run(
        ["powershell", "-NoProfile", "-Command", ps_cmd],
        capture_output=True,
        text=True,
        timeout=15,
    )

    if result.returncode != 0 or not result.stdout.strip():
        logger.warning("No partition data for disk {}", disk_num)
        return

    raw = json.loads(result.stdout)
    if isinstance(raw, dict):
        raw = [raw]

    for i, part in enumerate(raw):
        size = int(part.get("Size") or 0)
        drive_letter = part.get("DriveLetter") or ""
        mount = f"{drive_letter}:\\" if drive_letter else ""

        # Check BitLocker status
        is_encrypted, enc_type = _check_bitlocker_windows(drive_letter)

        partition = PartitionInfo(
            index=i,
            device_path=f"\\\\.\\{drive_letter}:" if drive_letter else device.device_id,
            size_bytes=size,
            start_sector=int(part.get("Offset") or 0) // 512,
            label=part.get("Type") or "",
            mount_point=mount,
            is_active=bool(part.get("IsActive")),
            is_encrypted=is_encrypted,
            encryption_type=enc_type,
            raw=part,
        )
        disk_map.partitions.append(partition)

    # Detect partition table type
    pt_cmd = f"Get-Disk -Number {disk_num} | Select-Object PartitionStyle | ConvertTo-Json"
    pt_result = subprocess.run(
        ["powershell", "-NoProfile", "-Command", pt_cmd],
        capture_output=True,
        text=True,
        timeout=10,
    )
    if pt_result.returncode == 0 and pt_result.stdout.strip():
        pt_data = json.loads(pt_result.stdout)
        disk_map.partition_table = pt_data.get("PartitionStyle", "")


def _check_bitlocker_windows(drive_letter: str) -> tuple[bool, str]:
    """Check if a drive letter is BitLocker-encrypted."""
    if not drive_letter:
        return False, ""
    try:
        result = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                f"(Get-BitLockerVolume -MountPoint '{drive_letter}:' "
                f"-ErrorAction SilentlyContinue).ProtectionStatus",
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
        status = result.stdout.strip()
        if status == "On":
            return True, "BitLocker"
    except Exception:
        pass
    return False, ""


# ── Linux ─────────────────────────────────────────────────────────────────────


def _enumerate_linux(device: Device, disk_map: DiskMap) -> None:
    """Use lsblk + blkid for detailed partition info."""
    import json

    result = subprocess.run(
        [
            "lsblk",
            "-J",
            "-b",
            "-o",
            "NAME,TYPE,SIZE,FSTYPE,LABEL,MOUNTPOINT,UUID,RO",
            device.device_id,
        ],
        capture_output=True,
        text=True,
        timeout=10,
    )

    if result.returncode != 0:
        logger.warning("lsblk failed for {}: {}", device.device_id, result.stderr.strip())
        return

    data = json.loads(result.stdout)
    top = data.get("blockdevices", [{}])[0]

    for i, child in enumerate(top.get("children", [])):
        name = child.get("name", "")
        path = f"/dev/{name}"
        size = int(child.get("size") or 0)
        fstype = child.get("fstype") or ""
        mount = child.get("mountpoint") or ""

        is_encrypted = fstype in ("crypto_LUKS", "BitLocker")
        enc_type = (
            "LUKS" if fstype == "crypto_LUKS" else ("BitLocker" if fstype == "BitLocker" else "")
        )

        partition = PartitionInfo(
            index=i,
            device_path=path,
            size_bytes=size,
            filesystem=fstype,
            label=child.get("label") or "",
            mount_point=mount,
            is_encrypted=is_encrypted,
            encryption_type=enc_type,
            raw=child,
        )
        disk_map.partitions.append(partition)

    # Detect partition table
    fdisk_result = subprocess.run(
        ["fdisk", "-l", device.device_id],
        capture_output=True,
        text=True,
        timeout=10,
    )
    for line in fdisk_result.stdout.splitlines():
        if "Disklabel type:" in line:
            disk_map.partition_table = line.split(":")[-1].strip().upper()
            break


# ── macOS ─────────────────────────────────────────────────────────────────────


def _enumerate_macos(device: Device, disk_map: DiskMap) -> None:
    """Use diskutil info for partition details."""
    import plistlib

    # Strip /dev/ prefix
    disk_id = device.device_id.replace("/dev/", "")

    result = subprocess.run(
        ["diskutil", "list", "-plist", disk_id],
        capture_output=True,
        timeout=10,
    )

    if result.returncode != 0:
        logger.warning("diskutil list failed for {}", disk_id)
        return

    plist = plistlib.loads(result.stdout)
    all_disks = plist.get("AllDisksAndPartitions", [])

    for disk_entry in all_disks:
        if disk_entry.get("DeviceIdentifier") != disk_id:
            continue

        disk_map.partition_table = "GPT"  # APFS default

        for i, part in enumerate(disk_entry.get("Partitions", [])):
            part_id = part.get("DeviceIdentifier", "")
            size = int(part.get("Size") or 0)
            fstype = part.get("Content") or ""

            is_encrypted = "FileVault" in fstype or "EncryptedRoot" in fstype
            enc_type = "FileVault" if is_encrypted else ""

            partition = PartitionInfo(
                index=i,
                device_path=f"/dev/{part_id}",
                size_bytes=size,
                filesystem=fstype,
                label=part.get("VolumeName") or "",
                is_encrypted=is_encrypted,
                encryption_type=enc_type,
                raw=part,
            )
            disk_map.partitions.append(partition)
        break
