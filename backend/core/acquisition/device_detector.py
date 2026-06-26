"""
Device Detection Module
=======================
Detects physical disks, partitions, removable media, and connected
mobile devices across Windows, Linux, and macOS.

Usage:
    from core.acquisition.device_detector import DeviceDetector
    devices = DeviceDetector.detect()
    for d in devices:
        print(d)
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass, field
from enum import Enum

from loguru import logger

import platform


class DeviceType(str, Enum):
    DISK = "disk"
    PARTITION = "partition"
    REMOVABLE = "removable"
    OPTICAL = "optical"
    ANDROID = "android"
    UNKNOWN = "unknown"


class OSPlatform(str, Enum):
    WINDOWS = "Windows"
    LINUX = "Linux"
    MACOS = "Darwin"


@dataclass
class Device:
    """Represents a detected storage or mobile device."""

    device_id: str  # e.g. "\\\\.\\PhysicalDrive0", "/dev/sda"
    label: str  # Human-readable name
    device_type: DeviceType
    size_bytes: int = 0
    model: str = ""
    serial: str = ""
    interface: str = ""  # USB, SATA, NVMe, etc.
    is_removable: bool = False
    is_readonly: bool = False
    filesystem: str = ""
    mount_point: str = ""
    partitions: list[Device] = field(default_factory=list)
    raw: dict = field(default_factory=dict)  # Original OS data

    @property
    def size_gb(self) -> float:
        return round(self.size_bytes / (1024**3), 2)

    def __str__(self) -> str:
        return (
            f"[{self.device_type.value.upper()}] {self.device_id} | "
            f"{self.label} | {self.size_gb} GB | "
            f"{'Removable' if self.is_removable else 'Fixed'}"
        )


class DeviceDetector:
    """
    Cross-platform device detector.
    Dispatches to the correct OS-specific implementation.
    """

    @staticmethod
    def detect() -> list[Device]:
        """Detect all storage devices on the current system."""
        os_name = platform.system()
        logger.info("Detecting devices on platform: {}", os_name)

        try:
            if os_name == OSPlatform.WINDOWS:
                return _detect_windows()
            elif os_name == OSPlatform.LINUX:
                return _detect_linux()
            elif os_name == OSPlatform.MACOS:
                return _detect_macos()
            else:
                logger.warning("Unsupported platform: {}", os_name)
                return []
        except Exception as exc:
            logger.error("Device detection failed: {}", exc)
            return []

    @staticmethod
    def detect_android() -> list[Device]:
        """Detect connected Android devices via ADB."""
        return _detect_android()


# ── Windows ───────────────────────────────────────────────────────────────────


def _detect_windows() -> list[Device]:
    """Enumerate physical drives via WMI (no external deps)."""
    import json
    import subprocess

    devices: list[Device] = []

    try:
        # Use PowerShell to get disk info as JSON
        ps_cmd = (
            "Get-WmiObject Win32_DiskDrive | "
            "Select-Object DeviceID, Model, SerialNumber, Size, "
            "InterfaceType, MediaType | "
            "ConvertTo-Json"
        )
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_cmd],
            capture_output=True,
            text=True,
            timeout=15,
        )

        if result.returncode != 0:
            logger.warning("WMI query failed: {}", result.stderr.strip())
            return devices

        raw = json.loads(result.stdout or "[]")
        if isinstance(raw, dict):
            raw = [raw]  # Single disk returns object, not array

        for disk in raw:
            size = int(disk.get("Size") or 0)
            media = (disk.get("MediaType") or "").lower()
            is_removable = "removable" in media or "external" in media

            dev = Device(
                device_id=disk.get("DeviceID", ""),
                label=disk.get("Model", "Unknown"),
                device_type=DeviceType.REMOVABLE if is_removable else DeviceType.DISK,
                size_bytes=size,
                model=disk.get("Model", ""),
                serial=(disk.get("SerialNumber") or "").strip(),
                interface=disk.get("InterfaceType", ""),
                is_removable=is_removable,
                raw=disk,
            )
            logger.debug("Found disk: {}", dev)
            devices.append(dev)

    except FileNotFoundError:
        logger.warning("PowerShell not available — skipping Windows disk detection")
    except json.JSONDecodeError as exc:
        logger.error("Failed to parse WMI output: {}", exc)
    except Exception as exc:
        logger.error("Windows device detection error: {}", exc)

    logger.info("Windows: detected {} disk(s)", len(devices))
    return devices


# ── Linux ─────────────────────────────────────────────────────────────────────


def _detect_linux() -> list[Device]:
    """Enumerate block devices via lsblk."""
    import json

    devices: list[Device] = []

    try:
        result = subprocess.run(
            [
                "lsblk",
                "-J",
                "-b",
                "-o",
                "NAME,TYPE,SIZE,MODEL,SERIAL,TRAN,RM,RO,FSTYPE,MOUNTPOINT",
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )

        if result.returncode != 0:
            logger.warning("lsblk failed: {}", result.stderr.strip())
            return devices

        data = json.loads(result.stdout)

        for blk in data.get("blockdevices", []):
            dev = _parse_lsblk_device(blk)
            devices.append(dev)

    except FileNotFoundError:
        logger.warning("lsblk not found — is this a Linux system?")
    except Exception as exc:
        logger.error("Linux device detection error: {}", exc)

    logger.info("Linux: detected {} block device(s)", len(devices))
    return devices


def _parse_lsblk_device(blk: dict, parent_path: str = "") -> Device:
    name = blk.get("name", "")
    path = f"/dev/{name}"
    blk_type = blk.get("type", "disk")
    size = int(blk.get("size") or 0)
    is_removable = str(blk.get("rm", "0")) == "1"
    is_readonly = str(blk.get("ro", "0")) == "1"

    dev = Device(
        device_id=path,
        label=blk.get("model") or name,
        device_type=DeviceType.REMOVABLE
        if is_removable
        else DeviceType(blk_type if blk_type in DeviceType._value2member_map_ else "disk"),
        size_bytes=size,
        model=blk.get("model") or "",
        serial=blk.get("serial") or "",
        interface=blk.get("tran") or "",
        is_removable=is_removable,
        is_readonly=is_readonly,
        filesystem=blk.get("fstype") or "",
        mount_point=blk.get("mountpoint") or "",
        raw=blk,
    )

    for child in blk.get("children", []):
        dev.partitions.append(_parse_lsblk_device(child, path))

    return dev


# ── macOS ─────────────────────────────────────────────────────────────────────


def _detect_macos() -> list[Device]:
    """Enumerate disks via diskutil list -plist."""
    import plistlib

    devices: list[Device] = []

    try:
        result = subprocess.run(
            ["diskutil", "list", "-plist"],
            capture_output=True,
            timeout=10,
        )

        if result.returncode != 0:
            logger.warning("diskutil failed")
            return devices

        plist = plistlib.loads(result.stdout)

        for disk_id in plist.get("WholeDisks", []):
            info_result = subprocess.run(
                ["diskutil", "info", "-plist", disk_id],
                capture_output=True,
                timeout=10,
            )
            if info_result.returncode != 0:
                continue

            info = plistlib.loads(info_result.stdout)
            size = int(info.get("TotalSize", 0))
            is_removable = info.get("Ejectable", False) or info.get("RemovableMedia", False)

            dev = Device(
                device_id=f"/dev/{disk_id}",
                label=info.get("MediaName") or disk_id,
                device_type=DeviceType.REMOVABLE if is_removable else DeviceType.DISK,
                size_bytes=size,
                model=info.get("MediaName") or "",
                serial=info.get("DiskUUID") or "",
                interface=info.get("BusProtocol") or "",
                is_removable=is_removable,
                filesystem=info.get("FilesystemType") or "",
                mount_point=info.get("MountPoint") or "",
                raw=info,
            )
            logger.debug("Found disk: {}", dev)
            devices.append(dev)

    except FileNotFoundError:
        logger.warning("diskutil not found — is this macOS?")
    except Exception as exc:
        logger.error("macOS device detection error: {}", exc)

    logger.info("macOS: detected {} disk(s)", len(devices))
    return devices


# ── Android (ADB) ─────────────────────────────────────────────────────────────


def _detect_android() -> list[Device]:
    """Detect connected Android devices via ADB."""
    devices: list[Device] = []

    try:
        result = subprocess.run(
            ["adb", "devices", "-l"],
            capture_output=True,
            text=True,
            timeout=10,
        )

        lines = result.stdout.strip().splitlines()
        for line in lines[1:]:  # Skip header
            line = line.strip()
            if not line or "offline" in line:
                continue

            parts = line.split()
            serial = parts[0]
            state = parts[1] if len(parts) > 1 else "unknown"

            if state != "device":
                logger.warning("ADB device {} is in state: {}", serial, state)
                continue

            # Get device model
            model_result = subprocess.run(
                ["adb", "-s", serial, "shell", "getprop", "ro.product.model"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            model = model_result.stdout.strip() or "Android Device"

            dev = Device(
                device_id=serial,
                label=model,
                device_type=DeviceType.ANDROID,
                model=model,
                serial=serial,
                interface="USB",
                is_removable=True,
            )
            logger.debug("Found Android device: {}", dev)
            devices.append(dev)

    except FileNotFoundError:
        logger.warning("ADB not found — Android detection skipped")
    except Exception as exc:
        logger.error("Android detection error: {}", exc)

    logger.info("ADB: detected {} Android device(s)", len(devices))
    return devices
