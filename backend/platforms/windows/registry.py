"""
Windows Registry Artifact Collector
=====================================
Extracts forensic artifacts from registry hives:
- UserAssist (program execution history)
- Run keys (persistence / autorun)
- USB device history
- Recently accessed files (RecentDocs)
- Timezone and system info
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass

from loguru import logger


@dataclass
class RegistryArtifact:
    """A single registry artifact entry."""

    key_path: str
    value_name: str
    value_data: str
    value_type: str = ""
    last_write_time: str = ""
    source: str = ""


def _ps(cmd: str, timeout: int = 20) -> str | None:
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", cmd],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.stdout.strip() if result.returncode == 0 else None
    except Exception as exc:
        logger.error("Registry PS error: {}", exc)
        return None


def _read_reg_key(hive: str, key: str) -> list[RegistryArtifact]:
    """Read all values under a registry key via PowerShell."""
    artifacts: list[RegistryArtifact] = []
    out = _ps(
        f"Get-ItemProperty -Path '{hive}:\\{key}' -ErrorAction SilentlyContinue | "
        "ConvertTo-Json -Depth 3"
    )
    if not out:
        return artifacts
    try:
        data = json.loads(out)
        if isinstance(data, list):
            data = data[0] if data else {}
        for k, v in data.items():
            if k.startswith("PS"):
                continue
            artifacts.append(
                RegistryArtifact(
                    key_path=f"{hive}:\\{key}",
                    value_name=k,
                    value_data=str(v),
                    source="registry",
                )
            )
    except Exception as exc:
        logger.debug("Failed to parse registry key {}: {}", key, exc)
    return artifacts


def collect_run_keys() -> list[RegistryArtifact]:
    """
    Collect autorun / persistence entries from Run and RunOnce keys.
    These are prime persistence indicators.
    """
    artifacts: list[RegistryArtifact] = []
    run_keys = [
        ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
        ("HKCU", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        ("HKCU", r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
        ("HKLM", r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
    ]
    for hive, key in run_keys:
        found = _read_reg_key(hive, key)
        for a in found:
            a.source = "run_keys"
        artifacts.extend(found)
    logger.info("Run keys: collected {} entries", len(artifacts))
    return artifacts


def collect_usb_history() -> list[RegistryArtifact]:
    """
    Collect USB device connection history from USBSTOR.
    Returns device class, friendly name, and serial numbers.
    """
    artifacts: list[RegistryArtifact] = []
    out = _ps(
        r"Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR' "
        r"-Recurse -ErrorAction SilentlyContinue | "
        "Select-Object Name,PSChildName | ConvertTo-Json -Depth 3"
    )
    if out:
        try:
            raw = json.loads(out)
            if isinstance(raw, dict):
                raw = [raw]
            for entry in raw:
                artifacts.append(
                    RegistryArtifact(
                        key_path=r"HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR",
                        value_name=entry.get("PSChildName", ""),
                        value_data=entry.get("Name", ""),
                        source="usb_history",
                    )
                )
        except Exception as exc:
            logger.debug("USB history parse error: {}", exc)

    # Also grab FriendlyName values
    out2 = _ps(
        r"Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR' "
        r"-Recurse -ErrorAction SilentlyContinue | "
        r"ForEach-Object { Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue } | "
        "Select-Object FriendlyName,DeviceDesc,Mfg | ConvertTo-Json -Depth 2"
    )
    if out2:
        try:
            raw2 = json.loads(out2)
            if isinstance(raw2, dict):
                raw2 = [raw2]
            for entry in raw2:
                name = entry.get("FriendlyName") or entry.get("DeviceDesc") or ""
                if name:
                    artifacts.append(
                        RegistryArtifact(
                            key_path=r"HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR",
                            value_name="FriendlyName",
                            value_data=name,
                            source="usb_history",
                        )
                    )
        except Exception as exc:
            logger.debug("USB friendly name parse error: {}", exc)

    logger.info("USB history: collected {} entries", len(artifacts))
    return artifacts


def collect_userassist() -> list[RegistryArtifact]:
    """
    Collect UserAssist entries — tracks GUI program execution counts and timestamps.
    Values are ROT13-encoded program paths.
    """
    import codecs

    artifacts: list[RegistryArtifact] = []

    out = _ps(
        r"Get-ChildItem 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist' "
        r"-Recurse -ErrorAction SilentlyContinue | "
        r"ForEach-Object { Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue } | "
        "ConvertTo-Json -Depth 3"
    )
    if not out:
        return artifacts
    try:
        raw = json.loads(out)
        if isinstance(raw, dict):
            raw = [raw]
        for entry in raw:
            for k, v in entry.items():
                if k.startswith("PS"):
                    continue
                # Decode ROT13
                decoded = codecs.decode(k, "rot_13")
                artifacts.append(
                    RegistryArtifact(
                        key_path=r"HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist",
                        value_name=decoded,
                        value_data=str(v),
                        source="userassist",
                    )
                )
    except Exception as exc:
        logger.debug("UserAssist parse error: {}", exc)

    logger.info("UserAssist: collected {} entries", len(artifacts))
    return artifacts


def collect_recent_docs() -> list[RegistryArtifact]:
    """Collect recently accessed file extensions from RecentDocs."""
    artifacts: list[RegistryArtifact] = []
    out = _ps(
        r"Get-ChildItem 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs' "
        r"-ErrorAction SilentlyContinue | "
        "Select-Object Name,PSChildName | ConvertTo-Json -Depth 2"
    )
    if out:
        try:
            raw = json.loads(out)
            if isinstance(raw, dict):
                raw = [raw]
            for entry in raw:
                artifacts.append(
                    RegistryArtifact(
                        key_path=r"HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs",
                        value_name=entry.get("PSChildName", ""),
                        value_data=entry.get("Name", ""),
                        source="recent_docs",
                    )
                )
        except Exception as exc:
            logger.debug("RecentDocs parse error: {}", exc)
    logger.info("RecentDocs: collected {} entries", len(artifacts))
    return artifacts


def collect_all_registry_artifacts() -> dict[str, list[RegistryArtifact]]:
    """Run all registry collectors and return grouped results."""
    logger.info("Starting registry artifact collection")
    return {
        "run_keys": collect_run_keys(),
        "usb_history": collect_usb_history(),
        "userassist": collect_userassist(),
        "recent_docs": collect_recent_docs(),
    }
