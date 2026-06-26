"""
Registry Artifact Parser Framework
=====================================
Parses Windows registry hives for forensic artifacts.
Supports offline hive parsing via python-registry (regipy).

Key artifacts:
- Run/RunOnce persistence keys
- USB device history (USBSTOR)
- UserAssist (program execution)
- MRU lists (recently used files)
- Network connections history
- Installed software
- System information

Usage:
    from core.artifacts.registry_parser import RegistryParser

    parser = RegistryParser()
    results = parser.parse_hive("/evidence/NTUSER.DAT", hive_type="ntuser")
"""

from __future__ import annotations

import codecs
import json
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from loguru import logger


@dataclass
class RegistryEntry:
    hive: str
    key_path: str
    value_name: str
    value_data: str
    value_type: str = ""
    last_write_time: str = ""
    artifact_type: str = ""
    is_suspicious: bool = False
    suspicious_reason: str = ""


@dataclass
class RegistryParseResult:
    hive_path: str
    hive_type: str
    entries: list[RegistryEntry] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def suspicious_entries(self) -> list[RegistryEntry]:
        return [e for e in self.entries if e.is_suspicious]


# Known suspicious run key patterns
_SUSPICIOUS_RUN_PATTERNS = [
    "powershell",
    "cmd.exe",
    "wscript",
    "cscript",
    "mshta",
    "regsvr32",
    "rundll32",
    "certutil",
    "bitsadmin",
    "\\temp\\",
    "\\tmp\\",
    "\\appdata\\local\\temp\\",
    "\\users\\public\\",
    "%temp%",
    "%appdata%",
]


def _is_suspicious_run_value(value: str) -> tuple[bool, str]:
    """Check if a run key value looks suspicious."""
    v_lower = value.lower()
    for pattern in _SUSPICIOUS_RUN_PATTERNS:
        if pattern in v_lower:
            return True, f"Suspicious pattern in run key: {pattern}"
    return False, ""


class RegistryParser:
    """
    Parses Windows registry hives for forensic artifacts.
    Uses PowerShell for live registry and python-registry for offline hives.
    """

    def __init__(self) -> None:
        self._regipy_available = self._check_regipy()

    def _check_regipy(self) -> bool:
        try:
            import regipy  # noqa: F401

            return True
        except ImportError:
            logger.debug("regipy not installed — offline hive parsing unavailable")
            return False

    # ── Live registry (PowerShell) ────────────────────────────────────────────

    def parse_live_run_keys(self) -> RegistryParseResult:
        """Parse Run/RunOnce keys from the live registry."""
        result = RegistryParseResult(hive_path="LIVE", hive_type="live")
        run_keys = [
            ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
            ("HKCU", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            ("HKCU", r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
            ("HKLM", r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
        ]
        for hive, key in run_keys:
            entries = self._read_live_key(hive, key, "run_key")
            result.entries.extend(entries)
        logger.info("Live run keys: {} entries", len(result.entries))
        return result

    def parse_live_usb_history(self) -> RegistryParseResult:
        """Parse USB device history from live registry."""
        result = RegistryParseResult(hive_path="LIVE", hive_type="live")
        entries = self._read_live_key_children(
            "HKLM", r"SYSTEM\CurrentControlSet\Enum\USBSTOR", "usb_history"
        )
        result.entries.extend(entries)
        logger.info("USB history: {} entries", len(result.entries))
        return result

    def parse_live_userassist(self) -> RegistryParseResult:
        """Parse UserAssist (ROT13-encoded program execution history)."""
        result = RegistryParseResult(hive_path="LIVE", hive_type="live")
        try:
            out = self._ps(
                r"Get-ChildItem 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist' "
                r"-Recurse -ErrorAction SilentlyContinue | "
                r"ForEach-Object { Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue } | "
                "ConvertTo-Json -Depth 3"
            )
            if out:
                data = json.loads(out)
                if isinstance(data, dict):
                    data = [data]
                for item in data:
                    for k, v in item.items():
                        if k.startswith("PS"):
                            continue
                        decoded = codecs.decode(k, "rot_13")
                        is_sus, reason = _is_suspicious_run_value(decoded)
                        result.entries.append(
                            RegistryEntry(
                                hive="HKCU",
                                key_path=r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist",
                                value_name=decoded,
                                value_data=str(v),
                                artifact_type="userassist",
                                is_suspicious=is_sus,
                                suspicious_reason=reason,
                            )
                        )
        except Exception as exc:
            result.errors.append(str(exc))
        logger.info("UserAssist: {} entries", len(result.entries))
        return result

    def parse_live_installed_software(self) -> RegistryParseResult:
        """Parse installed software from Uninstall keys."""
        result = RegistryParseResult(hive_path="LIVE", hive_type="live")
        for hive, key in [
            ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
            ("HKLM", r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
            ("HKCU", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        ]:
            entries = self._read_live_key_children(hive, key, "installed_software")
            result.entries.extend(entries)
        logger.info("Installed software: {} entries", len(result.entries))
        return result

    # ── Offline hive parsing (regipy) ─────────────────────────────────────────

    def parse_hive(self, hive_path: str | Path, hive_type: str = "ntuser") -> RegistryParseResult:
        """
        Parse an offline registry hive file.
        Requires: pip install regipy

        Args:
            hive_path: Path to the hive file (NTUSER.DAT, SYSTEM, SOFTWARE, etc.)
            hive_type: ntuser | system | software | sam | security
        """
        result = RegistryParseResult(hive_path=str(hive_path), hive_type=hive_type)

        if not self._regipy_available:
            result.errors.append("regipy not installed. Run: pip install regipy")
            return result

        try:
            from regipy.registry import RegistryHive

            hive = RegistryHive(str(hive_path))

            # Walk all keys
            for entry in hive.recurse_subkeys(hive.root):
                try:
                    for value in entry.values:
                        data_str = str(value.value)[:500]
                        is_sus, reason = _is_suspicious_run_value(data_str)
                        result.entries.append(
                            RegistryEntry(
                                hive=hive_type,
                                key_path=entry.path,
                                value_name=value.name,
                                value_data=data_str,
                                value_type=str(value.value_type),
                                last_write_time=str(entry.header.last_modified),
                                artifact_type="hive_entry",
                                is_suspicious=is_sus,
                                suspicious_reason=reason,
                            )
                        )
                except Exception:
                    pass

        except Exception as exc:
            result.errors.append(str(exc))
            logger.error("Hive parse error {}: {}", hive_path, exc)

        logger.info(
            "Hive {}: {} entries ({} suspicious)",
            hive_path,
            len(result.entries),
            len(result.suspicious_entries),
        )
        return result

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _ps(self, cmd: str, timeout: int = 15) -> str | None:
        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", cmd],
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            return result.stdout.strip() if result.returncode == 0 else None
        except Exception:
            return None

    def _read_live_key(self, hive: str, key: str, artifact_type: str) -> list[RegistryEntry]:
        entries: list[RegistryEntry] = []
        out = self._ps(
            f"Get-ItemProperty -Path '{hive}:\\{key}' -ErrorAction SilentlyContinue | "
            "ConvertTo-Json -Depth 2"
        )
        if not out:
            return entries
        try:
            data = json.loads(out)
            if isinstance(data, list):
                data = data[0] if data else {}
            for k, v in data.items():
                if k.startswith("PS"):
                    continue
                v_str = str(v)
                is_sus, reason = _is_suspicious_run_value(v_str)
                entries.append(
                    RegistryEntry(
                        hive=hive,
                        key_path=key,
                        value_name=k,
                        value_data=v_str[:500],
                        artifact_type=artifact_type,
                        is_suspicious=is_sus,
                        suspicious_reason=reason,
                    )
                )
        except Exception as exc:
            logger.debug("Registry key parse error {}: {}", key, exc)
        return entries

    def _read_live_key_children(
        self, hive: str, key: str, artifact_type: str
    ) -> list[RegistryEntry]:
        entries: list[RegistryEntry] = []
        out = self._ps(
            f"Get-ChildItem '{hive}:\\{key}' -ErrorAction SilentlyContinue | "
            "Select-Object Name, PSChildName | ConvertTo-Json -Depth 2"
        )
        if not out:
            return entries
        try:
            data = json.loads(out)
            if isinstance(data, dict):
                data = [data]
            for item in data:
                entries.append(
                    RegistryEntry(
                        hive=hive,
                        key_path=key,
                        value_name=item.get("PSChildName", ""),
                        value_data=item.get("Name", ""),
                        artifact_type=artifact_type,
                    )
                )
        except Exception as exc:
            logger.debug("Registry children parse error {}: {}", key, exc)
        return entries
