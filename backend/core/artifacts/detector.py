"""
Artifact Intelligence Detection Engine
=========================================
YARA scanning, IOC matching, suspicious persistence detection,
and malware artifact detection.

Usage:
    from core.artifacts.detector import ArtifactDetector

    detector = ArtifactDetector()
    results = detector.scan_file("/evidence/suspicious.exe")
    ioc_hits = detector.match_iocs("/evidence/", ioc_list=["evil.com", "10.0.0.99"])
    persistence = detector.detect_persistence()
"""

from __future__ import annotations

import hashlib
import math
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from loguru import logger


@dataclass
class YARAMatch:
    rule_name: str
    file_path: str
    tags: list[str] = field(default_factory=list)
    meta: dict = field(default_factory=dict)
    strings: list[str] = field(default_factory=list)
    namespace: str = ""


@dataclass
class IOCMatch:
    ioc_type: str  # domain | ip | hash | url | email | filename
    ioc_value: str
    matched_in: str  # file path or artifact name
    context: str = ""  # surrounding text
    confidence: str = "high"


@dataclass
class PersistenceEntry:
    mechanism: str  # run_key | scheduled_task | service | startup_folder | etc.
    name: str
    command: str
    location: str
    is_suspicious: bool = False
    reason: str = ""


@dataclass
class EntropyResult:
    file_path: str
    entropy: float
    is_packed: bool = False
    is_encrypted: bool = False
    note: str = ""


@dataclass
class DetectionResult:
    file_path: str
    yara_matches: list[YARAMatch] = field(default_factory=list)
    ioc_matches: list[IOCMatch] = field(default_factory=list)
    entropy: EntropyResult | None = None
    sha256: str = ""
    is_malicious: bool = False
    confidence: str = "unknown"
    reasons: list[str] = field(default_factory=list)


# ── IOC patterns ──────────────────────────────────────────────────────────────

_IOC_PATTERNS = {
    "ipv4": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "domain": re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"),
    "url": re.compile(r"https?://[^\s\"'<>]+"),
    "email": re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Z|a-z]{2,}\b"),
    "md5": re.compile(r"\b[0-9a-fA-F]{32}\b"),
    "sha256": re.compile(r"\b[0-9a-fA-F]{64}\b"),
}

# Known malicious indicators (demo set)
_KNOWN_MALICIOUS_HASHES = {
    "44d88612fea8a8f36de82e1278abb02f",  # EICAR test
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
}

_KNOWN_C2_DOMAINS = {
    "evil.com",
    "malware.cc",
    "c2server.net",
    "badactor.ru",
}

_KNOWN_C2_IPS = {
    "10.0.0.99",
    "192.168.100.200",
    "185.220.101.1",
}


class ArtifactDetector:
    """
    Multi-method artifact detection engine.
    """

    def __init__(self, yara_rules_dir: Path | None = None) -> None:
        self._yara_available = self._check_yara()
        self._yara_rules_dir = yara_rules_dir or (
            Path(__file__).resolve().parents[4] / "plugins" / "yara_rules"
        )

    def _check_yara(self) -> bool:
        try:
            import yara  # noqa: F401

            return True
        except ImportError:
            logger.debug("yara-python not installed. Run: pip install yara-python")
            return False

    # ── YARA scanning ─────────────────────────────────────────────────────────

    def scan_file_yara(self, file_path: str | Path) -> list[YARAMatch]:
        """Scan a file against all YARA rules in the rules directory."""
        if not self._yara_available:
            logger.warning("YARA not available — install yara-python")
            return []

        import yara

        matches: list[YARAMatch] = []
        path = Path(file_path)

        if not path.exists():
            return matches

        # Compile all .yar / .yara files
        rule_files = list(self._yara_rules_dir.glob("**/*.yar")) + list(
            self._yara_rules_dir.glob("**/*.yara")
        )

        if not rule_files:
            logger.debug("No YARA rules found in {}", self._yara_rules_dir)
            return matches

        for rule_file in rule_files:
            try:
                rules = yara.compile(str(rule_file))
                for match in rules.match(str(path)):
                    matches.append(
                        YARAMatch(
                            rule_name=match.rule,
                            file_path=str(path),
                            tags=list(match.tags),
                            meta=dict(match.meta),
                            strings=[str(s) for s in match.strings],
                            namespace=match.namespace,
                        )
                    )
            except Exception as exc:
                logger.debug("YARA rule error {}: {}", rule_file, exc)

        if matches:
            logger.warning("YARA: {} match(es) in {}", len(matches), path.name)
        return matches

    # ── IOC matching ──────────────────────────────────────────────────────────

    def match_iocs_in_file(
        self,
        file_path: str | Path,
        custom_iocs: list[str] | None = None,
    ) -> list[IOCMatch]:
        """
        Extract and match IOCs (IPs, domains, URLs, hashes) from a file.
        Checks against known malicious indicators and custom IOC list.
        """
        path = Path(file_path)
        matches: list[IOCMatch] = []

        if not path.exists():
            return matches

        try:
            content = path.read_text(errors="replace")
        except Exception:
            try:
                content = path.read_bytes().decode("latin-1", errors="replace")
            except Exception:
                return matches

        # Extract all IOCs
        for ioc_type, pattern in _IOC_PATTERNS.items():
            for match in pattern.finditer(content):
                value = match.group()
                is_known_bad = (
                    value.lower() in _KNOWN_MALICIOUS_HASHES
                    or value.lower() in _KNOWN_C2_DOMAINS
                    or value in _KNOWN_C2_IPS
                    or (custom_iocs and value.lower() in [i.lower() for i in custom_iocs])
                )
                if is_known_bad:
                    start = max(0, match.start() - 50)
                    end = min(len(content), match.end() + 50)
                    matches.append(
                        IOCMatch(
                            ioc_type=ioc_type,
                            ioc_value=value,
                            matched_in=str(path),
                            context=content[start:end].strip(),
                            confidence="high",
                        )
                    )

        if matches:
            logger.warning("IOC: {} match(es) in {}", len(matches), path.name)
        return matches

    def match_iocs_in_directory(
        self,
        directory: str | Path,
        custom_iocs: list[str] | None = None,
        extensions: list[str] | None = None,
    ) -> list[IOCMatch]:
        """Scan all files in a directory for IOC matches."""
        if extensions is None:
            extensions = [".txt", ".log", ".json", ".xml", ".csv", ".html", ".js", ".py"]

        all_matches: list[IOCMatch] = []
        for path in Path(directory).rglob("*"):
            if path.is_file() and path.suffix.lower() in extensions:
                all_matches.extend(self.match_iocs_in_file(path, custom_iocs))

        logger.info("IOC scan: {} match(es) in {}", len(all_matches), directory)
        return all_matches

    # ── Entropy analysis ──────────────────────────────────────────────────────

    def calculate_entropy(self, file_path: str | Path, block_size: int = 65536) -> EntropyResult:
        """
        Calculate Shannon entropy of a file.
        High entropy (>7.0) suggests encryption or packing.
        """
        path = Path(file_path)
        result = EntropyResult(file_path=str(path), entropy=0.0)

        if not path.exists():
            return result

        try:
            data = path.read_bytes()
            if not data:
                return result

            # Shannon entropy
            freq = [0] * 256
            for byte in data:
                freq[byte] += 1

            entropy = 0.0
            length = len(data)
            for count in freq:
                if count > 0:
                    p = count / length
                    entropy -= p * math.log2(p)

            result.entropy = round(entropy, 4)
            result.is_packed = entropy > 7.0
            result.is_encrypted = entropy > 7.5

            if result.is_encrypted:
                result.note = f"Very high entropy ({entropy:.2f}) — likely encrypted or compressed"
            elif result.is_packed:
                result.note = f"High entropy ({entropy:.2f}) — possibly packed/obfuscated"
            else:
                result.note = f"Normal entropy ({entropy:.2f})"

        except Exception as exc:
            logger.debug("Entropy calculation error {}: {}", path, exc)

        return result

    # ── Persistence detection ─────────────────────────────────────────────────

    def detect_persistence(self) -> list[PersistenceEntry]:
        """
        Detect persistence mechanisms on the current Windows system.
        Checks run keys, scheduled tasks, services, and startup folders.
        """
        entries: list[PersistenceEntry] = []

        # Run keys via PowerShell
        entries.extend(self._check_run_keys())

        # Scheduled tasks
        entries.extend(self._check_scheduled_tasks())

        # Startup folder
        entries.extend(self._check_startup_folders())

        sus_count = sum(1 for e in entries if e.is_suspicious)
        logger.info("Persistence: {} entries, {} suspicious", len(entries), sus_count)
        return entries

    def _check_run_keys(self) -> list[PersistenceEntry]:
        entries: list[PersistenceEntry] = []
        run_keys = [
            r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            r"HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        ]
        for key in run_keys:
            try:
                result = subprocess.run(
                    [
                        "powershell",
                        "-NoProfile",
                        "-Command",
                        f"Get-ItemProperty '{key}' -ErrorAction SilentlyContinue | ConvertTo-Json",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                if result.returncode == 0 and result.stdout.strip():
                    import json

                    data = json.loads(result.stdout)
                    for k, v in data.items():
                        if k.startswith("PS"):
                            continue
                        v_str = str(v)
                        is_sus = any(
                            p in v_str.lower()
                            for p in [
                                "\\temp\\",
                                "\\tmp\\",
                                "powershell",
                                "cmd.exe /c",
                                "wscript",
                                "mshta",
                                "regsvr32",
                                "%appdata%",
                            ]
                        )
                        entries.append(
                            PersistenceEntry(
                                mechanism="run_key",
                                name=k,
                                command=v_str,
                                location=key,
                                is_suspicious=is_sus,
                                reason="Suspicious command pattern" if is_sus else "",
                            )
                        )
            except Exception:
                pass
        return entries

    def _check_scheduled_tasks(self) -> list[PersistenceEntry]:
        entries: list[PersistenceEntry] = []
        try:
            result = subprocess.run(
                [
                    "powershell",
                    "-NoProfile",
                    "-Command",
                    "Get-ScheduledTask -ErrorAction SilentlyContinue | "
                    "Select-Object TaskName,TaskPath,State | ConvertTo-Json -Depth 2",
                ],
                capture_output=True,
                text=True,
                timeout=15,
            )
            if result.returncode == 0 and result.stdout.strip():
                import json

                data = json.loads(result.stdout)
                if isinstance(data, dict):
                    data = [data]
                for task in data:
                    name = task.get("TaskName", "")
                    path = task.get("TaskPath", "")
                    # Flag tasks in unusual locations
                    is_sus = path not in ("\\", "\\Microsoft\\", "\\Microsoft\\Windows\\")
                    entries.append(
                        PersistenceEntry(
                            mechanism="scheduled_task",
                            name=name,
                            command="",
                            location=path,
                            is_suspicious=is_sus,
                            reason="Non-standard task path" if is_sus else "",
                        )
                    )
        except Exception:
            pass
        return entries

    def _check_startup_folders(self) -> list[PersistenceEntry]:
        entries: list[PersistenceEntry] = []
        startup_dirs = [
            Path(r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"),
            Path.home()
            / "AppData"
            / "Roaming"
            / "Microsoft"
            / "Windows"
            / "Start Menu"
            / "Programs"
            / "Startup",
        ]
        for startup_dir in startup_dirs:
            if not startup_dir.exists():
                continue
            for item in startup_dir.iterdir():
                if item.is_file():
                    entries.append(
                        PersistenceEntry(
                            mechanism="startup_folder",
                            name=item.name,
                            command=str(item),
                            location=str(startup_dir),
                            is_suspicious=True,
                            reason="File in startup folder",
                        )
                    )
        return entries

    # ── Full scan ─────────────────────────────────────────────────────────────

    def scan_file(self, file_path: str | Path) -> DetectionResult:
        """
        Run full detection on a single file:
        YARA + IOC matching + entropy analysis + hash lookup.
        """
        path = Path(file_path)
        result = DetectionResult(file_path=str(path))

        if not path.exists():
            return result

        # Hash
        try:
            result.sha256 = hashlib.sha256(path.read_bytes()).hexdigest()
            if result.sha256 in _KNOWN_MALICIOUS_HASHES:
                result.is_malicious = True
                result.reasons.append(f"Known malicious hash: {result.sha256}")
        except Exception:
            pass

        # YARA
        result.yara_matches = self.scan_file_yara(path)
        if result.yara_matches:
            result.is_malicious = True
            result.reasons.extend([f"YARA: {m.rule_name}" for m in result.yara_matches])

        # IOC
        result.ioc_matches = self.match_iocs_in_file(path)
        if result.ioc_matches:
            result.reasons.extend([f"IOC: {m.ioc_value}" for m in result.ioc_matches])

        # Entropy
        result.entropy = self.calculate_entropy(path)
        if result.entropy.is_packed:
            result.reasons.append(result.entropy.note)

        # Confidence
        if result.is_malicious:
            result.confidence = "high"
        elif result.reasons:
            result.confidence = "medium"
        else:
            result.confidence = "clean"

        return result
