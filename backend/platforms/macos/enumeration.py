"""
macOS Enumeration
=================
Detects APFS containers, FileVault status, SIP status,
T2/Apple Silicon chip, and disk layout via diskutil.
"""

from __future__ import annotations

import plistlib
import subprocess
from dataclasses import dataclass, field

from loguru import logger


@dataclass
class APFSContainer:
    container_ref: str
    capacity_bytes: int = 0
    free_bytes: int = 0
    volumes: list[dict] = field(default_factory=list)
    fusion_drive: bool = False


@dataclass
class MacDiskInfo:
    device_id: str
    media_name: str = ""
    size_bytes: int = 0
    bus_protocol: str = ""
    is_removable: bool = False
    is_ejectable: bool = False
    filesystem: str = ""
    mount_point: str = ""
    uuid: str = ""
    partitions: list[dict] = field(default_factory=list)

    @property
    def size_gb(self) -> float:
        return round(self.size_bytes / (1024**3), 2)


@dataclass
class MacSystemInfo:
    hostname: str = ""
    os_version: str = ""
    os_build: str = ""
    hardware_model: str = ""
    chip: str = ""  # Intel / Apple M1 / Apple M2 etc.
    serial_number: str = ""
    sip_status: str = ""
    filevault_status: str = ""
    t2_chip: bool = False
    apple_silicon: bool = False


def _run(cmd: list[str], timeout: int = 10) -> bytes | None:
    try:
        result = subprocess.run(cmd, capture_output=True, timeout=timeout)
        return result.stdout if result.returncode == 0 else None
    except FileNotFoundError:
        logger.debug("Command not found: {}", cmd[0])
        return None
    except Exception as exc:
        logger.error("macOS command error {}: {}", cmd, exc)
        return None


def _run_text(cmd: list[str], timeout: int = 10) -> str | None:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.stdout.strip() if result.returncode == 0 else None
    except Exception as exc:
        logger.error("macOS text command error: {}", exc)
        return None


def detect_apfs_containers() -> list[APFSContainer]:
    """Enumerate APFS containers and their volumes via diskutil."""
    containers: list[APFSContainer] = []
    raw = _run(["diskutil", "apfs", "list", "-plist"])
    if not raw:
        return containers
    try:
        plist = plistlib.loads(raw)
        for c in plist.get("Containers", []):
            container = APFSContainer(
                container_ref=c.get("ContainerReference", ""),
                capacity_bytes=int(c.get("CapacityCeiling", 0)),
                free_bytes=int(c.get("CapacityFree", 0)),
                fusion_drive=bool(c.get("FusionDrive", False)),
                volumes=[
                    {
                        "name": v.get("Name", ""),
                        "device": v.get("DeviceIdentifier", ""),
                        "role": v.get("Roles", []),
                        "size": v.get("CapacityQuota", 0),
                        "encrypted": v.get("Encryption", False),
                        "filevault": v.get("FileVault", False),
                    }
                    for v in c.get("Volumes", [])
                ],
            )
            containers.append(container)
    except Exception as exc:
        logger.error("APFS container parse error: {}", exc)
    logger.info("macOS: detected {} APFS container(s)", len(containers))
    return containers


def get_filevault_status() -> str:
    """Check FileVault encryption status."""
    out = _run_text(["fdesetup", "status"])
    if out:
        return out
    # Fallback via diskutil
    out2 = _run_text(["diskutil", "apfs", "list"])
    if out2 and "FileVault" in out2:
        return "FileVault detected (check diskutil apfs list for details)"
    return "Unknown"


def get_sip_status() -> str:
    """Check System Integrity Protection (SIP) status."""
    out = _run_text(["csrutil", "status"])
    return out or "Unknown (csrutil not available)"


def detect_t2_apple_silicon() -> tuple[bool, bool, str]:
    """
    Detect T2 chip and Apple Silicon.
    Returns (is_t2, is_apple_silicon, chip_description).
    """
    out = _run_text(["sysctl", "-n", "machdep.cpu.brand_string"])
    chip = out or ""
    is_apple_silicon = "Apple" in chip
    is_t2 = False

    # Check for T2 via system_profiler
    sp_out = _run_text(["system_profiler", "SPiBridgeDataType"])
    if sp_out and "T2" in sp_out:
        is_t2 = True

    return is_t2, is_apple_silicon, chip


def get_macos_system_info() -> MacSystemInfo:
    """Collect comprehensive macOS system information."""
    info = MacSystemInfo()

    # Hostname
    info.hostname = _run_text(["hostname"]) or ""

    # OS version
    sw_out = _run(["sw_vers", "-plist"])
    if sw_out:
        try:
            plist = plistlib.loads(sw_out)
            info.os_version = plist.get("ProductVersion", "")
            info.os_build = plist.get("ProductBuildVersion", "")
        except Exception:
            pass

    # Hardware model + serial
    sp_raw = _run(["system_profiler", "SPHardwareDataType", "-xml"])
    if sp_raw:
        try:
            plist = plistlib.loads(sp_raw)
            hw = plist[0].get("_items", [{}])[0]
            info.hardware_model = hw.get("machine_model", "")
            info.serial_number = hw.get("serial_number", "")
            info.chip = hw.get("chip_type", hw.get("cpu_type", ""))
        except Exception:
            pass

    info.sip_status = get_sip_status()
    info.filevault_status = get_filevault_status()
    info.t2_chip, info.apple_silicon, chip_str = detect_t2_apple_silicon()
    if not info.chip:
        info.chip = chip_str

    return info


def enumerate_disks() -> list[MacDiskInfo]:
    """Enumerate all physical disks via diskutil list."""
    disks: list[MacDiskInfo] = []
    raw = _run(["diskutil", "list", "-plist"])
    if not raw:
        return disks
    try:
        plist = plistlib.loads(raw)
        for disk_id in plist.get("WholeDisks", []):
            info_raw = _run(["diskutil", "info", "-plist", disk_id])
            if not info_raw:
                continue
            info = plistlib.loads(info_raw)
            disk = MacDiskInfo(
                device_id=f"/dev/{disk_id}",
                media_name=info.get("MediaName", ""),
                size_bytes=int(info.get("TotalSize", 0)),
                bus_protocol=info.get("BusProtocol", ""),
                is_removable=bool(info.get("RemovableMedia", False)),
                is_ejectable=bool(info.get("Ejectable", False)),
                filesystem=info.get("FilesystemType", ""),
                mount_point=info.get("MountPoint", ""),
                uuid=info.get("DiskUUID", ""),
            )
            disks.append(disk)
    except Exception as exc:
        logger.error("Disk enumeration error: {}", exc)
    logger.info("macOS: enumerated {} disk(s)", len(disks))
    return disks
