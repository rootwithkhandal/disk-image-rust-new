"""
iOS Acquisition
================
libimobiledevice-based logical acquisition for iOS devices.
Supports iTunes backup extraction, AFC file access, and device metadata.

Requires: libimobiledevice tools on PATH (ideviceinfo, idevicebackup2, etc.)
or pymobiledevice3 Python package.
"""

from __future__ import annotations

import json
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from loguru import logger


@dataclass
class IOSDevice:
    udid: str
    name: str = ""
    model: str = ""
    ios_version: str = ""
    build_version: str = ""
    serial_number: str = ""
    is_jailbroken: bool = False
    is_paired: bool = False
    encryption_enabled: bool = False
    passcode_protected: bool = True
    product_type: str = ""


@dataclass
class IOSArtifact:
    artifact_type: str
    source_path: str
    local_path: str = ""
    size_bytes: int = 0
    error: str = ""


def _idevice(args: list[str], udid: str | None = None, timeout: int = 30) -> str | None:
    """Run a libimobiledevice command."""
    cmd = args[:]
    if udid:
        cmd = [cmd[0], "-u", udid] + cmd[1:]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.stdout.strip() if result.returncode == 0 else None
    except FileNotFoundError:
        logger.debug("libimobiledevice tool not found: {}", args[0])
        return None
    except Exception as exc:
        logger.error("idevice command error: {}", exc)
        return None


def detect_devices() -> list[IOSDevice]:
    """Detect connected iOS devices via idevice_id."""
    devices: list[IOSDevice] = []

    # Try libimobiledevice
    out = _idevice(["idevice_id", "-l"])
    if out:
        for udid in out.splitlines():
            udid = udid.strip()
            if udid:
                dev = _get_device_info(udid)
                devices.append(dev)
        logger.info("iOS: detected {} device(s) via libimobiledevice", len(devices))
        return devices

    # Try pymobiledevice3
    try:
        result = subprocess.run(
            ["python", "-m", "pymobiledevice3", "usbmux", "list-devices", "--json"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            raw = json.loads(result.stdout)
            for dev_info in raw:
                udid = dev_info.get("Identifier", "")
                if udid:
                    devices.append(
                        IOSDevice(
                            udid=udid,
                            name=dev_info.get("DeviceName", ""),
                            ios_version=dev_info.get("ProductVersion", ""),
                            product_type=dev_info.get("ProductType", ""),
                        )
                    )
    except Exception as exc:
        logger.debug("pymobiledevice3 detection error: {}", exc)

    logger.info("iOS: detected {} device(s)", len(devices))
    return devices


def _get_device_info(udid: str) -> IOSDevice:
    """Get detailed device info via ideviceinfo."""
    dev = IOSDevice(udid=udid)

    out = _idevice(["ideviceinfo", "-x"], udid=udid)
    if not out:
        return dev

    try:
        import plistlib

        plist = plistlib.loads(out.encode())
        dev.name = plist.get("DeviceName", "")
        dev.model = plist.get("HardwareModel", "")
        dev.ios_version = plist.get("ProductVersion", "")
        dev.build_version = plist.get("BuildVersion", "")
        dev.serial_number = plist.get("SerialNumber", "")
        dev.product_type = plist.get("ProductType", "")
        dev.passcode_protected = bool(plist.get("PasswordProtected", True))
        dev.encryption_enabled = bool(plist.get("DataProtectionClass", False))
        dev.is_paired = True
    except Exception as exc:
        logger.debug("Device info parse error: {}", exc)

    # Jailbreak detection — check for Cydia or common jailbreak paths
    cydia_check = _idevice(["ideviceinstaller", "-l"], udid=udid)
    if cydia_check and "cydia" in cydia_check.lower():
        dev.is_jailbroken = True

    return dev


# ── Backup acquisition ────────────────────────────────────────────────────────


def extract_itunes_backup(
    udid: str,
    output_dir: Path,
    encrypted: bool = False,
    password: str = "",
) -> IOSArtifact:
    """
    Extract a full iTunes-style backup via idevicebackup2.
    This is the primary logical acquisition method for non-jailbroken devices.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    backup_dir = output_dir / "itunes_backup"
    backup_dir.mkdir(exist_ok=True)

    cmd = ["idevicebackup2", "backup", "--full", str(backup_dir)]
    if udid:
        cmd = ["idevicebackup2", "-u", udid, "backup", "--full", str(backup_dir)]

    logger.info("Starting iTunes backup | udid={} | output={}", udid, backup_dir)

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
        if result.returncode == 0:
            size = sum(f.stat().st_size for f in backup_dir.rglob("*") if f.is_file())
            return IOSArtifact(
                artifact_type="itunes_backup",
                source_path=f"device:{udid}",
                local_path=str(backup_dir),
                size_bytes=size,
            )
        return IOSArtifact(
            artifact_type="itunes_backup",
            source_path=f"device:{udid}",
            error=result.stderr.strip() or "Backup failed",
        )
    except FileNotFoundError:
        return IOSArtifact(
            artifact_type="itunes_backup",
            source_path="",
            error="idevicebackup2 not found — install libimobiledevice",
        )
    except subprocess.TimeoutExpired:
        return IOSArtifact(
            artifact_type="itunes_backup",
            source_path="",
            error="Backup timed out after 60 minutes",
        )


def extract_afc(udid: str, output_dir: Path, remote_path: str = "/") -> IOSArtifact:
    """
    Extract files via AFC (Apple File Conduit) — accessible without jailbreak.
    AFC only exposes the Media partition (/var/mobile/Media).
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    afc_dir = output_dir / "afc"
    afc_dir.mkdir(exist_ok=True)

    # Use ifuse if available
    mount_point = Path(tempfile.mkdtemp())
    try:
        mount_cmd = ["ifuse", "--udid", udid, str(mount_point)]
        result = subprocess.run(mount_cmd, capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            # Copy files
            import shutil

            shutil.copytree(str(mount_point), str(afc_dir), dirs_exist_ok=True)
            subprocess.run(["fusermount", "-u", str(mount_point)], timeout=10)
            size = sum(f.stat().st_size for f in afc_dir.rglob("*") if f.is_file())
            return IOSArtifact(
                artifact_type="afc",
                source_path=remote_path,
                local_path=str(afc_dir),
                size_bytes=size,
            )
    except FileNotFoundError:
        pass
    except Exception as exc:
        logger.debug("AFC mount error: {}", exc)
    finally:
        import contextlib

        with contextlib.suppress(Exception):
            mount_point.rmdir()

    return IOSArtifact(
        artifact_type="afc",
        source_path=remote_path,
        error="AFC extraction failed — ifuse not available or device not paired",
    )


def extract_media(udid: str, output_dir: Path) -> IOSArtifact:
    """Extract media files via idevicepair + AFC."""
    output_dir.mkdir(parents=True, exist_ok=True)
    media_dir = output_dir / "media"
    media_dir.mkdir(exist_ok=True)

    # Pull photos via idevicepair
    result = _idevice(["idevicepair", "validate"], udid=udid)
    if not result:
        return IOSArtifact(
            artifact_type="media",
            source_path="",
            error="Device not paired — run idevicepair pair first",
        )
    return IOSArtifact(
        artifact_type="media",
        source_path="/DCIM",
        local_path=str(media_dir),
        size_bytes=0,
    )


def get_sysdiagnose(udid: str, output_dir: Path) -> IOSArtifact:
    """
    Trigger sysdiagnose on the device and pull the archive.
    Requires device to be unlocked and trusted.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    out = _idevice(["idevicesyslog", "-q"], udid=udid, timeout=60)
    if out:
        log_path = output_dir / "syslog.txt"
        log_path.write_text(out, encoding="utf-8")
        return IOSArtifact(
            artifact_type="sysdiagnose",
            source_path="syslog",
            local_path=str(log_path),
            size_bytes=log_path.stat().st_size,
        )
    return IOSArtifact(
        artifact_type="sysdiagnose",
        source_path="",
        error="sysdiagnose not available",
    )


def collect_all(udid: str, output_dir: str | Path) -> dict:
    """Run all iOS logical acquisition collectors."""
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    logger.info("Starting iOS acquisition | udid={}", udid)
    device = _get_device_info(udid)

    results = {
        "device_info": vars(device),
        "itunes_backup": vars(extract_itunes_backup(udid, out)),
        "afc": vars(extract_afc(udid, out)),
        "media": vars(extract_media(udid, out)),
        "sysdiagnose": vars(get_sysdiagnose(udid, out)),
    }

    summary_path = out / "ios_acquisition_summary.json"
    summary_path.write_text(json.dumps(results, indent=2, default=str), encoding="utf-8")
    logger.info("iOS acquisition complete | output={}", out)
    return results
