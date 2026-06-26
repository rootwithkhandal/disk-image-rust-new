"""
Windows Enumeration
===================
Detects physical drives, mounted partitions, BitLocker status,
shadow copies, and Windows version info.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, field

from loguru import logger


@dataclass
class WindowsDriveInfo:
    device_id: str
    model: str = ""
    serial: str = ""
    size_bytes: int = 0
    interface: str = ""
    media_type: str = ""
    partitions: list[dict] = field(default_factory=list)

    @property
    def size_gb(self) -> float:
        return round(self.size_bytes / (1024**3), 2)


@dataclass
class BitLockerStatus:
    drive_letter: str
    protection_status: str  # "On" | "Off" | "Unknown"
    lock_status: str  # "Locked" | "Unlocked" | "Unknown"
    encryption_method: str = ""
    is_encrypted: bool = False


@dataclass
class ShadowCopy:
    id: str
    volume: str
    creation_time: str
    provider_name: str = ""
    state: str = ""


@dataclass
class WindowsSystemInfo:
    hostname: str = ""
    os_name: str = ""
    os_version: str = ""
    os_build: str = ""
    architecture: str = ""
    install_date: str = ""
    last_boot: str = ""
    registered_user: str = ""
    domain: str = ""


def _ps(cmd: str, timeout: int = 15) -> str | None:
    """Run a PowerShell command and return stdout, or None on failure."""
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", cmd],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if result.returncode != 0:
            logger.debug("PS command failed: {}", result.stderr.strip()[:200])
            return None
        return result.stdout.strip()
    except Exception as exc:
        logger.error("PowerShell error: {}", exc)
        return None


def enumerate_physical_drives() -> list[WindowsDriveInfo]:
    """Enumerate all physical drives via WMI."""
    drives: list[WindowsDriveInfo] = []
    out = _ps(
        "Get-WmiObject Win32_DiskDrive | "
        "Select-Object DeviceID,Model,SerialNumber,Size,InterfaceType,MediaType | "
        "ConvertTo-Json -Depth 2"
    )
    if not out:
        return drives
    try:
        raw = json.loads(out)
        if isinstance(raw, dict):
            raw = [raw]
        for d in raw:
            drives.append(
                WindowsDriveInfo(
                    device_id=d.get("DeviceID", ""),
                    model=d.get("Model", ""),
                    serial=(d.get("SerialNumber") or "").strip(),
                    size_bytes=int(d.get("Size") or 0),
                    interface=d.get("InterfaceType", ""),
                    media_type=d.get("MediaType", ""),
                )
            )
    except Exception as exc:
        logger.error("Failed to parse drive info: {}", exc)
    logger.info("Enumerated {} physical drive(s)", len(drives))
    return drives


def enumerate_mounted_partitions() -> list[dict]:
    """Enumerate all mounted volumes with drive letters."""
    out = _ps(
        "Get-WmiObject Win32_LogicalDisk | "
        "Select-Object DeviceID,DriveType,FileSystem,Size,FreeSpace,VolumeName | "
        "ConvertTo-Json -Depth 2"
    )
    if not out:
        return []
    try:
        raw = json.loads(out)
        if isinstance(raw, dict):
            raw = [raw]
        logger.info("Enumerated {} mounted partition(s)", len(raw))
        return raw
    except Exception as exc:
        logger.error("Failed to parse partition info: {}", exc)
        return []


def get_bitlocker_status(drive_letter: str | None = None) -> list[BitLockerStatus]:
    """
    Get BitLocker status for one or all drives.
    Requires admin privileges.
    """
    results: list[BitLockerStatus] = []
    target = f"-MountPoint '{drive_letter}:'" if drive_letter else ""
    out = _ps(
        f"Get-BitLockerVolume {target} -ErrorAction SilentlyContinue | "
        "Select-Object MountPoint,ProtectionStatus,LockStatus,EncryptionMethod | "
        "ConvertTo-Json -Depth 2"
    )
    if not out:
        return results
    try:
        raw = json.loads(out)
        if isinstance(raw, dict):
            raw = [raw]
        for v in raw:
            status = BitLockerStatus(
                drive_letter=(v.get("MountPoint") or "").replace(":\\", ""),
                protection_status=str(v.get("ProtectionStatus", "Unknown")),
                lock_status=str(v.get("LockStatus", "Unknown")),
                encryption_method=v.get("EncryptionMethod") or "",
                is_encrypted=str(v.get("ProtectionStatus")) == "1",
            )
            results.append(status)
    except Exception as exc:
        logger.error("Failed to parse BitLocker status: {}", exc)
    return results


def enumerate_shadow_copies() -> list[ShadowCopy]:
    """Enumerate Volume Shadow Copies (VSS)."""
    copies: list[ShadowCopy] = []
    out = _ps(
        "Get-WmiObject Win32_ShadowCopy | "
        "Select-Object ID,VolumeName,InstallDate,ProviderName,State | "
        "ConvertTo-Json -Depth 2"
    )
    if not out:
        return copies
    try:
        raw = json.loads(out)
        if isinstance(raw, dict):
            raw = [raw]
        for s in raw:
            copies.append(
                ShadowCopy(
                    id=s.get("ID", ""),
                    volume=s.get("VolumeName", ""),
                    creation_time=s.get("InstallDate", ""),
                    provider_name=s.get("ProviderName", ""),
                    state=str(s.get("State", "")),
                )
            )
    except Exception as exc:
        logger.error("Failed to parse shadow copies: {}", exc)
    logger.info("Found {} shadow copy/copies", len(copies))
    return copies


def get_windows_version() -> WindowsSystemInfo:
    """Collect Windows OS version and system info."""
    out = _ps(
        "Get-WmiObject Win32_OperatingSystem | "
        "Select-Object CSName,Caption,Version,BuildNumber,OSArchitecture,"
        "InstallDate,LastBootUpTime,RegisteredUser | "
        "ConvertTo-Json -Depth 2"
    )
    info = WindowsSystemInfo()
    if not out:
        return info
    try:
        d = json.loads(out)
        if isinstance(d, list):
            d = d[0]
        info.hostname = d.get("CSName", "")
        info.os_name = d.get("Caption", "")
        info.os_version = d.get("Version", "")
        info.os_build = d.get("BuildNumber", "")
        info.architecture = d.get("OSArchitecture", "")
        info.install_date = d.get("InstallDate", "")
        info.last_boot = d.get("LastBootUpTime", "")
        info.registered_user = d.get("RegisteredUser", "")
    except Exception as exc:
        logger.error("Failed to parse Windows version: {}", exc)
    return info
