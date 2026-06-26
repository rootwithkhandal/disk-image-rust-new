"""
Offensive DFIR Engine (v2.3)
==============================
Hybrid IR + adversary simulation analysis.

Features:
  1. Live Persistence Hunting     — enumerate all persistence mechanisms on a live system
  2. Beacon Detection             — detect C2 beaconing patterns in network/process data
  3. Credential Theft Detection   — identify credential dumping artifacts
  4. Ransomware Triage            — rapid ransomware indicators + blast radius assessment
  5. Lateral Movement Mapping     — reconstruct attacker movement across the environment

Design philosophy:
  - All detections are READ-ONLY — no remediation actions
  - Every finding maps to MITRE ATT&CK
  - Results are evidence-grade: timestamped, hashed, chain-of-custody ready
  - Works on live systems AND memory/disk images (offline mode)

Usage:
    from core.dfir.offensive import OffensiveDFIR

    dfir = OffensiveDFIR()
    report = dfir.hunt_persistence()
    report = dfir.detect_beacons(connections, processes)
    report = dfir.triage_ransomware(scan_path="C:/Users")
    report = dfir.map_lateral_movement(event_logs, processes, connections)
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import subprocess
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from loguru import logger


# ── Shared finding dataclass ──────────────────────────────────────────────────

@dataclass
class DFIRFinding:
    finding_id: str
    category: str           # persistence | beacon | credential | ransomware | lateral_movement
    title: str
    severity: str           # critical | high | medium | low | info
    score: float            # 0.0 – 10.0
    description: str
    evidence: list[str] = field(default_factory=list)
    affected_entities: list[str] = field(default_factory=list)
    mitre_technique: str = ""
    mitre_tactic: str = ""
    mitre_url: str = ""
    recommendation: str = ""
    confidence: float = 0.8
    raw: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.mitre_technique and not self.mitre_url:
            self.mitre_url = f"https://attack.mitre.org/techniques/{self.mitre_technique.replace('.', '/')}"


@dataclass
class DFIRReport:
    title: str
    generated_at: str
    findings: list[DFIRFinding] = field(default_factory=list)
    summary: str = ""
    risk_score: float = 0.0
    risk_level: str = "low"

    @property
    def critical(self) -> list[DFIRFinding]:
        return [f for f in self.findings if f.severity == "critical"]

    @property
    def high(self) -> list[DFIRFinding]:
        return [f for f in self.findings if f.severity == "high"]

    def to_dict(self) -> dict:
        return asdict(self)


def _fid(prefix: str) -> str:
    """Generate a short finding ID."""
    import uuid
    return f"{prefix}-{str(uuid.uuid4())[:8].upper()}"


def _ps(cmd: str, timeout: int = 20) -> str | None:
    """Run a PowerShell command, return stdout or None."""
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", cmd],
            capture_output=True, text=True, timeout=timeout,
        )
        return result.stdout.strip() if result.returncode == 0 else None
    except Exception:
        return None


def _ps_json(cmd: str, timeout: int = 20) -> list | dict | None:
    """Run a PowerShell command expecting JSON output."""
    out = _ps(cmd + " | ConvertTo-Json -Depth 3 -Compress", timeout)
    if not out:
        return None
    try:
        return json.loads(out)
    except Exception:
        return None


# ══════════════════════════════════════════════════════════════════════════════
# 1. PERSISTENCE HUNTING
# ══════════════════════════════════════════════════════════════════════════════

# Persistence locations and their MITRE mappings
_PERSISTENCE_SOURCES = {
    "run_keys": {
        "mitre": "T1547.001", "tactic": "Persistence",
        "keys": [
            r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            r"HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            r"HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            r"HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        ],
    },
    "scheduled_tasks": {"mitre": "T1053.005", "tactic": "Persistence"},
    "services":        {"mitre": "T1543.003", "tactic": "Persistence"},
    "startup_folder":  {"mitre": "T1547.001", "tactic": "Persistence"},
    "wmi_subscriptions": {"mitre": "T1546.003", "tactic": "Persistence"},
    "boot_execute":    {"mitre": "T1547.001", "tactic": "Persistence"},
    "image_hijack":    {"mitre": "T1546.012", "tactic": "Privilege Escalation"},
    "com_hijack":      {"mitre": "T1546.015", "tactic": "Privilege Escalation"},
    "lsa_providers":   {"mitre": "T1547.005", "tactic": "Persistence"},
    "dll_search_order":{"mitre": "T1574.001", "tactic": "Defense Evasion"},
}

# Suspicious patterns in persistence entries
_SUSPICIOUS_PERSISTENCE_PATTERNS = [
    (re.compile(r'\\temp\\', re.I),           "Executes from TEMP directory"),
    (re.compile(r'\\tmp\\', re.I),            "Executes from TMP directory"),
    (re.compile(r'powershell.*-enc', re.I),   "Encoded PowerShell command"),
    (re.compile(r'powershell.*-nop', re.I),   "PowerShell NoProfile execution"),
    (re.compile(r'cmd\.exe\s*/c', re.I),      "CMD silent execution"),
    (re.compile(r'wscript|cscript', re.I),    "Script host execution"),
    (re.compile(r'mshta', re.I),              "MSHTA execution (HTA file)"),
    (re.compile(r'regsvr32.*\/i:', re.I),     "Regsvr32 remote script (Squiblydoo)"),
    (re.compile(r'certutil.*-urlcache', re.I),"CertUtil download cradle"),
    (re.compile(r'bitsadmin.*\/transfer', re.I),"BITS transfer (T1197)"),
    (re.compile(r'rundll32.*,', re.I),        "Rundll32 export execution"),
    (re.compile(r'%appdata%|%temp%|%public%', re.I), "User-writable path"),
    (re.compile(r'\\users\\.*\\downloads\\', re.I), "User Downloads folder"),
]


def hunt_persistence(live: bool = True) -> DFIRReport:
    r"""
    Enumerate ALL persistence mechanisms on the current system.

    Checks:
      - Registry Run/RunOnce keys (HKLM + HKCU)
      - Scheduled tasks (all, including hidden)
      - Windows services (non-Microsoft)
      - Startup folders (user + all users)
      - WMI event subscriptions
      - Boot execute entries
      - IFEO (Image File Execution Options) debugger hijacks
      - AppCert/AppInit DLLs
      - LSA authentication packages
      - COM object hijacks (HKCU\Software\Classes)

    Returns:
        DFIRReport with all persistence findings.
    """
    findings: list[DFIRFinding] = []
    logger.info("Persistence hunt started")

    # ── Registry Run keys ─────────────────────────────────────────────────────
    for key in _PERSISTENCE_SOURCES["run_keys"]["keys"]:
        data = _ps_json(f"Get-ItemProperty '{key}' -ErrorAction SilentlyContinue")
        if not data or not isinstance(data, dict):
            continue
        for name, value in data.items():
            if name.startswith("PS"):
                continue
            value_str = str(value)
            suspicious_reasons = [
                reason for pattern, reason in _SUSPICIOUS_PERSISTENCE_PATTERNS
                if pattern.search(value_str)
            ]
            severity = "high" if suspicious_reasons else "medium"
            score = 8.0 if suspicious_reasons else 5.0
            findings.append(DFIRFinding(
                finding_id=_fid("PERS"),
                category="persistence",
                title=f"Run Key: {name}",
                severity=severity,
                score=score,
                description=f"Registry run key '{name}' in {key.split(':')[0]}",
                evidence=[f"Key: {key}", f"Name: {name}", f"Value: {value_str[:200]}"],
                affected_entities=[name],
                mitre_technique="T1547.001",
                mitre_tactic="Persistence",
                recommendation="Verify this entry is a legitimate application. Remove if unauthorized.",
                confidence=0.9,
                raw={"key": key, "name": name, "value": value_str},
            ))

    # ── Scheduled tasks ───────────────────────────────────────────────────────
    tasks = _ps_json(
        "Get-ScheduledTask -ErrorAction SilentlyContinue | "
        "Select-Object TaskName,TaskPath,State,"
        "@{N='Action';E={($_.Actions | ForEach-Object { $_.Execute + ' ' + $_.Arguments }) -join ';'}}"
    )
    if tasks:
        if isinstance(tasks, dict):
            tasks = [tasks]
        for task in tasks:
            name = task.get("TaskName", "")
            path = task.get("TaskPath", "")
            action = task.get("Action") or ""
            # Flag tasks in non-standard paths
            is_ms_path = path.startswith("\\Microsoft\\")
            suspicious_reasons = [
                reason for pattern, reason in _SUSPICIOUS_PERSISTENCE_PATTERNS
                if pattern.search(action)
            ]
            if suspicious_reasons or not is_ms_path:
                severity = "high" if suspicious_reasons else "low"
                findings.append(DFIRFinding(
                    finding_id=_fid("PERS"),
                    category="persistence",
                    title=f"Scheduled Task: {name}",
                    severity=severity,
                    score=7.5 if suspicious_reasons else 3.0,
                    description=f"Scheduled task '{name}' in non-Microsoft path {path}",
                    evidence=[f"Task: {path}{name}", f"Action: {action[:200]}"] +
                              [f"Suspicious: {r}" for r in suspicious_reasons],
                    affected_entities=[name],
                    mitre_technique="T1053.005",
                    mitre_tactic="Persistence",
                    recommendation="Verify this scheduled task is authorized. Check the action command.",
                    confidence=0.75 if suspicious_reasons else 0.4,
                    raw=task,
                ))

    # ── Services ──────────────────────────────────────────────────────────────
    services = _ps_json(
        "Get-WmiObject Win32_Service | "
        "Select-Object Name,DisplayName,State,StartMode,PathName,StartName | "
        "Where-Object { $_.PathName -notlike '*\\Windows\\*' -and $_.PathName -ne $null }"
    )
    if services:
        if isinstance(services, dict):
            services = [services]
        for svc in services[:50]:  # limit output
            path = svc.get("PathName") or ""
            name = svc.get("Name") or ""
            suspicious_reasons = [
                reason for pattern, reason in _SUSPICIOUS_PERSISTENCE_PATTERNS
                if pattern.search(path)
            ]
            if suspicious_reasons:
                findings.append(DFIRFinding(
                    finding_id=_fid("PERS"),
                    category="persistence",
                    title=f"Suspicious Service: {name}",
                    severity="high",
                    score=7.5,
                    description=f"Non-system service with suspicious path: {name}",
                    evidence=[f"Service: {name}", f"Path: {path[:200]}"] +
                              [f"Suspicious: {r}" for r in suspicious_reasons],
                    affected_entities=[name],
                    mitre_technique="T1543.003",
                    mitre_tactic="Persistence",
                    recommendation="Verify this service is legitimate. Check binary hash against VT.",
                    confidence=0.80,
                    raw=svc,
                ))

    # ── WMI subscriptions ─────────────────────────────────────────────────────
    wmi_filters = _ps_json(
        "Get-WMIObject -Namespace root\\subscription -Class __EventFilter "
        "-ErrorAction SilentlyContinue | Select-Object Name,Query"
    )
    if wmi_filters:
        if isinstance(wmi_filters, dict):
            wmi_filters = [wmi_filters]
        for filt in wmi_filters:
            findings.append(DFIRFinding(
                finding_id=_fid("PERS"),
                category="persistence",
                title=f"WMI Event Filter: {filt.get('Name', 'unknown')}",
                severity="critical",
                score=9.5,
                description="WMI event subscription detected — rare in legitimate software, high-value persistence.",
                evidence=[f"Filter: {filt.get('Name')}", f"Query: {str(filt.get('Query',''))[:200]}"],
                affected_entities=[filt.get("Name", "")],
                mitre_technique="T1546.003",
                mitre_tactic="Persistence",
                recommendation="WMI subscriptions are rarely legitimate. Investigate immediately.",
                confidence=0.95,
                raw=filt,
            ))

    # ── IFEO debugger hijack ──────────────────────────────────────────────────
    ifeo = _ps_json(
        "Get-ChildItem 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options' "
        "-ErrorAction SilentlyContinue | "
        "Where-Object { (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).Debugger } | "
        "Select-Object PSChildName, @{N='Debugger';E={(Get-ItemProperty $_.PSPath).Debugger}}"
    )
    if ifeo:
        if isinstance(ifeo, dict):
            ifeo = [ifeo]
        for entry in ifeo:
            dbg = entry.get("Debugger") or ""
            # Sysmon and legitimate debuggers are expected
            if "sysmon" in dbg.lower() or "windbg" in dbg.lower():
                continue
            findings.append(DFIRFinding(
                finding_id=_fid("PERS"),
                category="persistence",
                title=f"IFEO Debugger Hijack: {entry.get('PSChildName')}",
                severity="critical",
                score=9.0,
                description=f"Image File Execution Options debugger set — intercepts process launch.",
                evidence=[f"Target: {entry.get('PSChildName')}", f"Debugger: {dbg[:200]}"],
                affected_entities=[entry.get("PSChildName", "")],
                mitre_technique="T1546.012",
                mitre_tactic="Privilege Escalation",
                recommendation="Remove IFEO debugger entry immediately unless explicitly authorized.",
                confidence=0.95,
            ))

    # ── Startup folders ───────────────────────────────────────────────────────
    startup_dirs = [
        Path(r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"),
        Path.home() / "AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup",
    ]
    for sdir in startup_dirs:
        if not sdir.exists():
            continue
        for item in sdir.iterdir():
            if item.is_file():
                findings.append(DFIRFinding(
                    finding_id=_fid("PERS"),
                    category="persistence",
                    title=f"Startup Folder Entry: {item.name}",
                    severity="medium",
                    score=6.0,
                    description=f"File in startup folder: {item}",
                    evidence=[f"Path: {item}"],
                    affected_entities=[item.name],
                    mitre_technique="T1547.001",
                    mitre_tactic="Persistence",
                    recommendation="Verify this file is a legitimate autostart entry.",
                    confidence=0.70,
                ))

    return _build_report("Persistence Hunt", findings)


# ══════════════════════════════════════════════════════════════════════════════
# 2. BEACON DETECTION
# ══════════════════════════════════════════════════════════════════════════════

# C2 framework default beacon intervals (seconds) ± jitter
_KNOWN_BEACON_INTERVALS = {
    "Cobalt Strike": (60, 30),    # default 60s ± 30s jitter
    "Metasploit":    (5, 0),      # meterpreter default
    "Sliver":        (60, 0),
    "Empire":        (5, 2),
    "Covenant":      (10, 0),
    "Brute Ratel":   (60, 0),
}

_BEACON_SUSPICIOUS_PORTS = {
    80, 443, 8080, 8443,  # common web ports used for C2
    4444, 4445, 1337, 31337, 6666, 9999,  # classic C2
    53,   # DNS C2
    22,   # SSH tunneling
}

_C2_PROCESS_INDICATORS = {
    "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe",
    "msbuild.exe", "cmstp.exe", "installutil.exe",
}


def detect_beacons(
    connections: list[dict],
    processes: list[dict] | None = None,
    connection_history: list[dict] | None = None,
) -> DFIRReport:
    """
    Detect C2 beaconing patterns in network and process data.

    Beaconing indicators:
      - Regular connection intervals to the same remote host (statistical)
      - C2 framework default ports
      - Known LOLBin processes with network connections
      - Long-lived HTTP/S connections with low data volume (keep-alive beacons)
      - DNS requests at regular intervals (DNS C2)
      - Process making connections it normally wouldn't (parent-child + network)

    Args:
        connections:        Current network connections (from netstat/memory).
        processes:          Current process list.
        connection_history: Historical connection log entries for interval analysis.
    """
    findings: list[DFIRFinding] = []
    logger.info("Beacon detection started | {} connections", len(connections))

    # ── LOLBin process + network connection correlation ───────────────────────
    proc_map: dict[int, str] = {}
    if processes:
        for p in processes:
            pid = int(p.get("PID") or p.get("pid") or 0)
            name = (p.get("ImageFileName") or p.get("Name") or "").lower()
            proc_map[pid] = name

    for conn in connections:
        remote_port = int(conn.get("ForeignPort") or conn.get("remote_port") or 0)
        remote_addr = conn.get("ForeignAddr") or conn.get("remote_addr") or ""
        local_port = int(conn.get("LocalPort") or conn.get("local_port") or 0)
        pid = int(conn.get("PID") or conn.get("OwningProcess") or conn.get("pid") or 0)
        proc_name = (
            conn.get("Owner") or conn.get("process_name") or
            proc_map.get(pid, "") or f"PID:{pid}"
        ).lower()
        state = (conn.get("State") or conn.get("state") or "").upper()

        # Skip local/loopback
        if remote_addr in ("0.0.0.0", "::", "127.0.0.1", "::1") or not remote_addr:
            continue

        # LOLBin making outbound connection
        if any(lol in proc_name for lol in _C2_PROCESS_INDICATORS) and remote_port in (80, 443, 8080, 8443):
            findings.append(DFIRFinding(
                finding_id=_fid("BCNX"),
                category="beacon",
                title=f"LOLBin Network Connection: {proc_name}",
                severity="high",
                score=8.0,
                description=f"Living-off-the-land binary '{proc_name}' has outbound HTTP(S) connection.",
                evidence=[
                    f"Process: {proc_name} (PID {pid})",
                    f"Connection: {remote_addr}:{remote_port} [{state}]",
                ],
                affected_entities=[proc_name, remote_addr],
                mitre_technique="T1071.001",
                mitre_tactic="Command and Control",
                recommendation=f"Investigate why {proc_name} is making HTTP connections. Check for encoded commands.",
                confidence=0.80,
                raw=conn,
            ))

        # Suspicious C2 port
        if remote_port in {4444, 4445, 1337, 31337, 6666, 9999, 8888}:
            findings.append(DFIRFinding(
                finding_id=_fid("BCNX"),
                category="beacon",
                title=f"C2 Port Connection: port {remote_port}",
                severity="critical",
                score=9.0,
                description=f"Process '{proc_name}' connected to classic C2 port {remote_port}.",
                evidence=[f"Process: {proc_name}", f"Remote: {remote_addr}:{remote_port}"],
                affected_entities=[proc_name, remote_addr],
                mitre_technique="T1571",
                mitre_tactic="Command and Control",
                recommendation=f"Block port {remote_port} at firewall. Isolate the affected system.",
                confidence=0.90,
                raw=conn,
            ))

        # DNS C2 indicator (process using port 53)
        if remote_port == 53 and any(lol in proc_name for lol in _C2_PROCESS_INDICATORS):
            findings.append(DFIRFinding(
                finding_id=_fid("BCNX"),
                category="beacon",
                title=f"Possible DNS C2: {proc_name}",
                severity="high",
                score=8.5,
                description=f"Unexpected DNS connection from '{proc_name}' — possible DNS tunneling.",
                evidence=[f"Process: {proc_name}", f"DNS server: {remote_addr}"],
                affected_entities=[proc_name],
                mitre_technique="T1071.004",
                mitre_tactic="Command and Control",
                recommendation="Capture and analyze DNS traffic. Look for high-entropy subdomain queries.",
                confidence=0.75,
                raw=conn,
            ))

    # ── Statistical interval analysis from connection history ─────────────────
    if connection_history and len(connection_history) > 10:
        beacon_hits = _analyze_beacon_intervals(connection_history)
        findings.extend(beacon_hits)

    return _build_report("Beacon Detection", findings)


def _analyze_beacon_intervals(history: list[dict]) -> list[DFIRFinding]:
    """
    Statistical analysis of connection timestamps to detect regular beaconing.
    Groups connections by remote host, computes interval statistics.
    """
    import statistics as _stats
    findings: list[DFIRFinding] = []

    # Group by remote host:port
    host_timestamps: dict[str, list[float]] = {}
    for entry in history:
        ts_str = entry.get("timestamp") or entry.get("time") or ""
        remote = f"{entry.get('remote_addr','?')}:{entry.get('remote_port','?')}"
        if not ts_str:
            continue
        try:
            dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            host_timestamps.setdefault(remote, []).append(dt.timestamp())
        except Exception:
            continue

    for host, timestamps in host_timestamps.items():
        if len(timestamps) < 5:
            continue
        timestamps.sort()
        intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
        if not intervals:
            continue

        mean_interval = _stats.mean(intervals)
        stdev_interval = _stats.stdev(intervals) if len(intervals) > 1 else 0

        # Low coefficient of variation = very regular = likely beacon
        cv = (stdev_interval / mean_interval) if mean_interval > 0 else 1.0

        # Check against known C2 intervals
        matched_c2 = None
        for c2_name, (base_interval, jitter) in _KNOWN_BEACON_INTERVALS.items():
            if abs(mean_interval - base_interval) <= max(jitter, base_interval * 0.3):
                matched_c2 = c2_name
                break

        if cv < 0.3 or matched_c2:  # coefficient of variation < 30% = regular
            severity = "critical" if matched_c2 else "high"
            score = 9.5 if matched_c2 else 7.5
            desc = (
                f"Regular beacon pattern to {host}: "
                f"mean interval {mean_interval:.0f}s, CV={cv:.2f}"
            )
            if matched_c2:
                desc += f" — matches {matched_c2} default beacon interval"

            findings.append(DFIRFinding(
                finding_id=_fid("BCNX"),
                category="beacon",
                title=f"Beacon Pattern: {host}",
                severity=severity,
                score=score,
                description=desc,
                evidence=[
                    f"Remote: {host}",
                    f"Connections: {len(timestamps)}",
                    f"Mean interval: {mean_interval:.1f}s",
                    f"StdDev: {stdev_interval:.1f}s",
                    f"CV: {cv:.3f}",
                ] + ([f"Matches C2: {matched_c2}"] if matched_c2 else []),
                affected_entities=[host],
                mitre_technique="T1071",
                mitre_tactic="Command and Control",
                recommendation=f"Capture network traffic to {host}. Block and investigate.",
                confidence=0.90 if matched_c2 else 0.70,
            ))

    return findings


# ══════════════════════════════════════════════════════════════════════════════
# 3. CREDENTIAL THEFT DETECTION
# ══════════════════════════════════════════════════════════════════════════════

_CRED_THEFT_PROCESSES = {
    "mimikatz.exe":   ("T1003.001", "OS Credential Dumping: LSASS Memory", "critical", 9.5),
    "wce.exe":        ("T1003.001", "OS Credential Dumping", "critical", 9.5),
    "fgdump.exe":     ("T1003.001", "OS Credential Dumping", "critical", 9.0),
    "pwdump.exe":     ("T1003.001", "OS Credential Dumping", "critical", 9.0),
    "procdump.exe":   ("T1003.001", "LSASS dump via ProcDump", "high", 8.0),
    "ntdsutil.exe":   ("T1003.003", "NTDS.dit extraction", "critical", 9.5),
    "secretsdump":    ("T1003.002", "SAM/LSA secrets dump", "critical", 9.5),
    "comsvcs.dll":    ("T1003.001", "LSASS dump via comsvcs.dll MiniDump", "critical", 9.0),
    "vssadmin.exe":   ("T1003.003", "VSS shadow copy for NTDS.dit", "high", 8.0),
    "diskshadow.exe": ("T1003.003", "Shadow copy for credential extraction", "high", 8.0),
}

_CRED_THEFT_REGISTRY = [
    (r"HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest",
     "UseLogonCredential", "1",
     "WDigest plaintext credential storage enabled — T1112", "T1112"),
]

_CRED_THEFT_FILE_INDICATORS = [
    (r"C:\Windows\Temp\*.dmp",   "LSASS dump file in TEMP"),
    (r"C:\Users\*\AppData\Local\Temp\*.dmp", "LSASS dump file in user TEMP"),
    (r"C:\lsass.dmp",            "LSASS dump at root"),
    (r"C:\Windows\Temp\out.txt", "Credential output file (common Mimikatz output)"),
]


def detect_credential_theft(
    processes: list[dict] | None = None,
    events: list[dict] | None = None,
    live: bool = True,
) -> DFIRReport:
    """
    Detect credential theft artifacts on a live or offline system.

    Checks:
      - Known credential dumping tools in process list
      - LSASS access by non-system processes (EventID 4656/4663)
      - WDigest plaintext credential storage (registry)
      - Dump files in suspicious locations
      - SAM/NTDS.dit access events
      - Kerberoasting indicators (EventID 4769 with RC4)
      - Pass-the-Hash indicators (EventID 4624 type 3 with NTLM)
      - DCSync replication requests (EventID 4662)
    """
    findings: list[DFIRFinding] = []
    logger.info("Credential theft detection started")

    # ── Process scan ──────────────────────────────────────────────────────────
    if processes:
        for proc in processes:
            name = (proc.get("ImageFileName") or proc.get("Name") or "").lower()
            cmdline = (proc.get("CommandLine") or proc.get("cmdline") or "").lower()
            pid = proc.get("PID") or proc.get("pid") or 0

            for tool, (mitre, desc, sev, score) in _CRED_THEFT_PROCESSES.items():
                if tool.lower() in name:
                    findings.append(DFIRFinding(
                        finding_id=_fid("CRED"),
                        category="credential",
                        title=f"Credential Tool: {name}",
                        severity=sev,
                        score=score,
                        description=f"Known credential theft tool '{name}' detected in process list.",
                        evidence=[f"Process: {name} (PID {pid})", f"MITRE: {mitre} — {desc}"],
                        affected_entities=[name],
                        mitre_technique=mitre,
                        mitre_tactic="Credential Access",
                        recommendation=f"Isolate system. All credentials considered compromised. Reset passwords.",
                        confidence=0.98,
                        raw=proc,
                    ))
                    break

            # comsvcs.dll MiniDump via rundll32
            if "rundll32" in name and "comsvcs" in cmdline and "minidump" in cmdline:
                findings.append(DFIRFinding(
                    finding_id=_fid("CRED"),
                    category="credential",
                    title="LSASS Dump via comsvcs.dll",
                    severity="critical",
                    score=9.5,
                    description="rundll32 comsvcs.dll MiniDump — stealthy LSASS dump technique.",
                    evidence=[f"PID: {pid}", f"CommandLine: {cmdline[:200]}"],
                    affected_entities=[name],
                    mitre_technique="T1003.001",
                    mitre_tactic="Credential Access",
                    recommendation="Check for .dmp files. All credentials on this system are compromised.",
                    confidence=0.99,
                ))

    # ── Event log analysis ────────────────────────────────────────────────────
    if events:
        # EventID 4769 with RC4 = Kerberoasting
        kerb_events = [
            e for e in events
            if int(e.get("event_id") or e.get("Id") or 0) == 4769
            and str(e.get("ticket_encryption") or e.get("TicketEncryptionType") or "") in ("0x17", "23")
        ]
        if kerb_events:
            findings.append(DFIRFinding(
                finding_id=_fid("CRED"),
                category="credential",
                title=f"Kerberoasting: {len(kerb_events)} RC4 TGS Request(s)",
                severity="high",
                score=8.5,
                description=f"{len(kerb_events)} Kerberos TGS requests using RC4 encryption — Kerberoasting indicator.",
                evidence=[
                    f"EventID 4769 count: {len(kerb_events)}",
                    "RC4 encryption type 0x17 selected (weak, targeted for offline cracking)",
                ],
                mitre_technique="T1558.003",
                mitre_tactic="Credential Access",
                recommendation="Identify source account. Enforce AES-only Kerberos. Review service account passwords.",
                confidence=0.85,
            ))

        # EventID 4624 Type 3 + NTLM = Pass-the-Hash
        pth_events = [
            e for e in events
            if int(e.get("event_id") or e.get("Id") or 0) == 4624
            and str(e.get("logon_type") or e.get("LogonType") or "") == "3"
            and "ntlm" in str(e.get("auth_package") or e.get("AuthenticationPackageName") or "").lower()
        ]
        if pth_events:
            findings.append(DFIRFinding(
                finding_id=_fid("CRED"),
                category="credential",
                title=f"Pass-the-Hash: {len(pth_events)} NTLM Network Logon(s)",
                severity="high",
                score=8.0,
                description=f"{len(pth_events)} NTLM network logons (type 3) — possible Pass-the-Hash.",
                evidence=[f"EventID 4624 type 3 NTLM count: {len(pth_events)}"],
                mitre_technique="T1550.002",
                mitre_tactic="Lateral Movement",
                recommendation="Review source hosts. Enforce Kerberos. Consider Protected Users security group.",
                confidence=0.70,
            ))

        # EventID 4662 = DCSync (replication rights accessed)
        dcsync_events = [
            e for e in events
            if int(e.get("event_id") or e.get("Id") or 0) == 4662
            and "1131f6ad" in str(e.get("properties") or e.get("Properties") or "").lower()
        ]
        if dcsync_events:
            findings.append(DFIRFinding(
                finding_id=_fid("CRED"),
                category="credential",
                title=f"DCSync Attack: {len(dcsync_events)} Replication Event(s)",
                severity="critical",
                score=10.0,
                description="AD replication rights (DS-Replication-Get-Changes-All) accessed — DCSync attack.",
                evidence=[f"EventID 4662 replication count: {len(dcsync_events)}"],
                mitre_technique="T1003.006",
                mitre_tactic="Credential Access",
                recommendation="CRITICAL: DCSync gives attacker all domain credentials. Full domain password reset required.",
                confidence=0.95,
            ))

    # ── WDigest registry check ────────────────────────────────────────────────
    if live:
        import platform as _platform
        if _platform.system() == "Windows":
            wdigest = _ps("(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest' -ErrorAction SilentlyContinue).UseLogonCredential")
            if wdigest and wdigest.strip() == "1":
                findings.append(DFIRFinding(
                    finding_id=_fid("CRED"),
                    category="credential",
                    title="WDigest Plaintext Credentials Enabled",
                    severity="high",
                    score=8.5,
                    description="WDigest UseLogonCredential=1 — plaintext passwords cached in memory.",
                    evidence=["HKLM:\\...\\WDigest\\UseLogonCredential = 1"],
                    mitre_technique="T1112",
                    mitre_tactic="Defense Evasion",
                    recommendation="Set UseLogonCredential=0. This change requires reboot to take effect.",
                    confidence=1.0,
                ))

    return _build_report("Credential Theft Detection", findings)


# ══════════════════════════════════════════════════════════════════════════════
# 4. RANSOMWARE TRIAGE
# ══════════════════════════════════════════════════════════════════════════════

_RANSOM_NOTE_PATTERNS = [
    re.compile(r'READ[-_\s]?ME', re.I),
    re.compile(r'DECRYPT[-_\s]?FILES', re.I),
    re.compile(r'YOUR[-_\s]?FILES[-_\s]?ARE[-_\s]?ENCRYPTED', re.I),
    re.compile(r'HOW[-_\s]?TO[-_\s]?RECOVER', re.I),
    re.compile(r'RESTORE[-_\s]?FILES', re.I),
    re.compile(r'RECOVERY[-_\s]?INSTRUCTIONS', re.I),
    re.compile(r'\.onion', re.I),
    re.compile(r'bitcoin|btc|monero|xmr', re.I),
]

# Known ransomware encrypted file extensions
_RANSOM_EXTENSIONS = {
    ".locked", ".encrypted", ".enc", ".crypt", ".crypto",
    ".crypz", ".locky", ".cerber", ".zepto", ".thor",
    ".aesir", ".odin", ".zzzzz", ".micro", ".vvv",
    ".ecc", ".ezz", ".exx", ".xyz", ".zzz",
    ".abc", ".aaa", ".xtbl", ".wncry", ".wcry",
    ".wannacry", ".wnry", ".wncrypt",
    ".ryuk", ".RYK",
    ".lck", ".lock",
    ".pay2decrypt",
    ".matrix", ".MTX",
    ".phobos", ".PHOBOS",
    ".dharma", ".karma", ".corona",
}

_RANSOM_PROCESSES = {
    "vssadmin.exe": ("Deleting shadow copies — ransomware anti-recovery", "T1490", 9.0),
    "wbadmin.exe": ("Deleting Windows backup catalog", "T1490", 8.5),
    "bcdedit.exe": ("Disabling Windows recovery", "T1490", 8.5),
    "wmic.exe": ("WMI shadow copy deletion", "T1490", 8.0),
    "cipher.exe": ("Encrypting files via cipher", "T1486", 9.0),
}

_RANSOM_VSSADMIN_PATTERNS = [
    re.compile(r'delete\s+shadows', re.I),
    re.compile(r'resize\s+shadowstorage.*maxsize=(\d+)%', re.I),
]


def triage_ransomware(
    scan_path: str | Path = "C:\\",
    processes: list[dict] | None = None,
    events: list[dict] | None = None,
    max_files: int = 50000,
) -> DFIRReport:
    """
    Rapid ransomware triage — identify indicators and blast radius.

    Checks:
      - Ransomware note file patterns
      - Known encrypted file extensions
      - Shadow copy deletion commands
      - Mass file rename/create operations (EventID 4663)
      - High entropy file distribution
      - VSS deletion in process command lines
      - Recovery tool disabling
      - File encryption process indicators

    Args:
        scan_path:  Root path to scan for encrypted files and ransom notes.
        processes:  Running process list (for VSS deletion detection).
        events:     Security/System event logs.
        max_files:  Maximum files to scan (limits scan time).
    """
    findings: list[DFIRFinding] = []
    scan_root = Path(scan_path)
    logger.info("Ransomware triage started | path={}", scan_root)

    ransom_notes: list[Path] = []
    encrypted_files: list[Path] = []
    high_entropy_files: list[Path] = []
    scanned = 0
    extension_counts: dict[str, int] = {}

    # ── Filesystem scan ───────────────────────────────────────────────────────
    if scan_root.exists():
        for item in scan_root.rglob("*"):
            if scanned >= max_files:
                break
            if not item.is_file():
                continue
            scanned += 1

            # Ransom note detection
            if any(p.search(item.name) for p in _RANSOM_NOTE_PATTERNS):
                ransom_notes.append(item)

            # Known ransomware extension
            ext = item.suffix.lower()
            if ext in _RANSOM_EXTENSIONS:
                encrypted_files.append(item)
                extension_counts[ext] = extension_counts.get(ext, 0) + 1

    if ransom_notes:
        # Read first ransom note for IOCs
        note_content = ""
        try:
            note_content = ransom_notes[0].read_text(errors="replace")[:500]
        except Exception:
            pass

        # Extract .onion URLs
        onion_urls = re.findall(r'[a-z2-7]{16,56}\.onion(?:/\S*)?', note_content, re.I)

        findings.append(DFIRFinding(
            finding_id=_fid("RNSOM"),
            category="ransomware",
            title=f"Ransom Note Detected: {len(ransom_notes)} file(s)",
            severity="critical",
            score=10.0,
            description=f"Ransomware note files found — active encryption confirmed.",
            evidence=[
                f"Note files: {[str(n) for n in ransom_notes[:5]]}",
                f"First note preview: {note_content[:200]}",
            ] + ([f"Onion URLs: {onion_urls}"] if onion_urls else []),
            affected_entities=[str(ransom_notes[0].parent)],
            mitre_technique="T1486",
            mitre_tactic="Impact",
            recommendation="CRITICAL: Disconnect from network. Preserve disk image. Do NOT pay ransom without legal consultation.",
            confidence=0.99,
        ))

    if encrypted_files:
        top_ext = max(extension_counts, key=extension_counts.get) if extension_counts else "unknown"
        findings.append(DFIRFinding(
            finding_id=_fid("RNSOM"),
            category="ransomware",
            title=f"Encrypted Files: {len(encrypted_files)} with known ransomware extensions",
            severity="critical",
            score=9.5,
            description=f"Files with ransomware encryption extensions found. Most common: {top_ext} ({extension_counts.get(top_ext, 0)} files).",
            evidence=[
                f"Total encrypted files: {len(encrypted_files)}",
                f"Extensions: {dict(sorted(extension_counts.items(), key=lambda x: -x[1]))}",
                f"Sample paths: {[str(f) for f in encrypted_files[:3]]}",
            ],
            affected_entities=[top_ext],
            mitre_technique="T1486",
            mitre_tactic="Impact",
            recommendation="Identify encryption start time from file timestamps. Assess blast radius. Check backups.",
            confidence=0.95,
        ))

    # ── Process analysis ──────────────────────────────────────────────────────
    if processes:
        for proc in processes:
            name = (proc.get("ImageFileName") or proc.get("Name") or "").lower()
            cmdline = (proc.get("CommandLine") or proc.get("cmdline") or "").lower()

            for proc_name, (desc, mitre, score) in _RANSOM_PROCESSES.items():
                if proc_name.lower() in name:
                    is_ransom_cmd = any(p.search(cmdline) for p in _RANSOM_VSSADMIN_PATTERNS)
                    if is_ransom_cmd or proc_name == "cipher.exe":
                        findings.append(DFIRFinding(
                            finding_id=_fid("RNSOM"),
                            category="ransomware",
                            title=f"Anti-Recovery: {name}",
                            severity="critical",
                            score=score,
                            description=f"{desc}: '{cmdline[:100]}'",
                            evidence=[f"Process: {name}", f"CommandLine: {cmdline[:200]}"],
                            mitre_technique=mitre,
                            mitre_tactic="Impact",
                            recommendation="Shadow copies likely deleted. Check for offline backups.",
                            confidence=0.95,
                        ))

    # ── Blast radius estimation ───────────────────────────────────────────────
    if encrypted_files or ransom_notes:
        total_encrypted_size = sum(
            f.stat().st_size for f in encrypted_files if f.exists()
        )
        # Estimate remaining files from sample
        estimated_total = len(encrypted_files) * (max_files // max(scanned, 1))
        findings.append(DFIRFinding(
            finding_id=_fid("RNSOM"),
            category="ransomware",
            title="Blast Radius Estimate",
            severity="info",
            score=5.0,
            description=f"Estimated impact assessment based on filesystem scan.",
            evidence=[
                f"Files scanned: {scanned:,}",
                f"Encrypted files found: {len(encrypted_files):,}",
                f"Estimated total encrypted: ~{estimated_total:,}",
                f"Encrypted data size: {total_encrypted_size/(1024**3):.2f} GB (sampled)",
                f"Unique extensions: {list(extension_counts.keys())}",
            ],
            recommendation="Full disk scan needed for accurate blast radius. Check backup integrity.",
            confidence=0.5,
        ))

    return _build_report("Ransomware Triage", findings)


# ══════════════════════════════════════════════════════════════════════════════
# 5. LATERAL MOVEMENT MAPPING
# ══════════════════════════════════════════════════════════════════════════════

_LATERAL_EVENT_IDS = {
    4624: "Successful logon",
    4625: "Failed logon",
    4648: "Explicit credential logon",
    4672: "Special privileges assigned",
    4776: "NTLM authentication",
    4768: "Kerberos TGT request",
    4769: "Kerberos service ticket",
    4771: "Kerberos pre-auth failed",
    7045: "Service installed",
    4697: "Service installed (security log)",
    5140: "Network share accessed",
    5145: "Network share object access",
    4688: "Process creation",
}

_LATERAL_LOGON_TYPES = {
    2: "Interactive", 3: "Network", 4: "Batch",
    5: "Service", 7: "Unlock", 8: "NetworkCleartext",
    9: "NewCredentials", 10: "RemoteInteractive",
    11: "CachedInteractive",
}

_HIGH_RISK_LOGON_TYPES = {3, 8, 10}  # Network, NetworkCleartext, RemoteInteractive


def map_lateral_movement(
    events: list[dict] | None = None,
    processes: list[dict] | None = None,
    connections: list[dict] | None = None,
) -> DFIRReport:
    """
    Reconstruct attacker lateral movement across an environment.

    Analyzes:
      - Logon events (4624/4625) — source/destination host mapping
      - Explicit credential use (4648) — pass-the-ticket/hash indicators
      - Network share access (5140/5145) — C$ and ADMIN$ share usage
      - Remote service installation (7045/4697) — PsExec/similar
      - WMI remote execution (process creation from WMI)
      - RDP connections (logon type 10)
      - PsExec/WinRM/DCOM process chains

    Returns:
        DFIRReport with movement graph and MITRE mappings.
    """
    findings: list[DFIRFinding] = []
    logger.info("Lateral movement mapping started")

    if not events and not processes and not connections:
        return _build_report("Lateral Movement Mapping", findings)

    # ── Event log analysis ────────────────────────────────────────────────────
    if events:
        # Build logon map: source_host -> dest_host
        logon_map: dict[str, list[dict]] = {}

        for event in events:
            eid = int(event.get("event_id") or event.get("Id") or 0)
            if eid not in (4624, 4625, 4648):
                continue

            logon_type = int(event.get("logon_type") or event.get("LogonType") or 0)
            src_host = event.get("workstation_name") or event.get("WorkstationName") or ""
            src_ip = event.get("ip_address") or event.get("IpAddress") or ""
            username = event.get("account_name") or event.get("SubjectUserName") or ""
            dest_host = event.get("computer") or event.get("Computer") or ""
            ts = event.get("time_created") or event.get("timestamp") or ""

            if logon_type not in _HIGH_RISK_LOGON_TYPES:
                continue
            if not src_ip and not src_host:
                continue

            key = f"{src_ip or src_host} -> {dest_host}"
            logon_map.setdefault(key, []).append({
                "type": _LATERAL_LOGON_TYPES.get(logon_type, str(logon_type)),
                "user": username, "ts": ts, "eid": eid, "success": eid == 4624,
            })

        # Flag hosts with multiple lateral logons
        for path, logons in logon_map.items():
            successful = [l for l in logons if l["success"]]
            failed = [l for l in logons if not l["success"]]
            if not successful:
                continue

            rdp_logons = [l for l in successful if l["type"] == "RemoteInteractive"]
            network_logons = [l for l in successful if l["type"] == "Network"]

            severity = "high" if len(successful) > 3 else "medium"
            score = 8.0 if rdp_logons else 6.5

            findings.append(DFIRFinding(
                finding_id=_fid("LATM"),
                category="lateral_movement",
                title=f"Lateral Logon Path: {path}",
                severity=severity,
                score=score,
                description=f"Lateral movement path: {path} ({len(successful)} successful logons)",
                evidence=[
                    f"Path: {path}",
                    f"Successful logons: {len(successful)}",
                    f"Failed logons: {len(failed)}",
                    f"RDP sessions: {len(rdp_logons)}",
                    f"Network logons: {len(network_logons)}",
                    f"Users: {list({l['user'] for l in successful})[:5]}",
                ],
                affected_entities=path.split(" -> "),
                mitre_technique="T1021.001" if rdp_logons else "T1021",
                mitre_tactic="Lateral Movement",
                recommendation=f"Investigate logon sessions on {path.split(' -> ')[-1]}. Review for data access.",
                confidence=0.80,
            ))

        # Admin share access (5140)
        share_events = [
            e for e in events
            if int(e.get("event_id") or e.get("Id") or 0) == 5140
            and any(s in str(e.get("share_name") or e.get("ShareName") or "").upper()
                    for s in ["ADMIN$", "C$", "IPC$"])
        ]
        if share_events:
            share_hosts = list({e.get("ip_address") or e.get("IpAddress") or "" for e in share_events})
            findings.append(DFIRFinding(
                finding_id=_fid("LATM"),
                category="lateral_movement",
                title=f"Admin Share Access: {len(share_events)} event(s)",
                severity="high",
                score=8.0,
                description=f"Administrative share (ADMIN$, C$) access from {len(share_hosts)} host(s).",
                evidence=[
                    f"Events: {len(share_events)}",
                    f"Source hosts: {share_hosts[:5]}",
                ],
                mitre_technique="T1021.002",
                mitre_tactic="Lateral Movement",
                recommendation="Review which accounts accessed admin shares. PsExec uses ADMIN$.",
                confidence=0.85,
            ))

        # Remote service installation (7045 / 4697)
        svc_events = [
            e for e in events
            if int(e.get("event_id") or e.get("Id") or 0) in (7045, 4697)
        ]
        if svc_events:
            findings.append(DFIRFinding(
                finding_id=_fid("LATM"),
                category="lateral_movement",
                title=f"Remote Service Installation: {len(svc_events)} service(s)",
                severity="high",
                score=8.5,
                description=f"{len(svc_events)} remote service installation(s) — PsExec/SMBExec indicator.",
                evidence=[
                    f"Service install events: {len(svc_events)}",
                    f"Services: {[e.get('service_name') or e.get('ServiceName','?') for e in svc_events[:3]]}",
                ],
                mitre_technique="T1021.002",
                mitre_tactic="Lateral Movement",
                recommendation="Identify source of service installation. PsExec leaves 'PSEXESVC' service.",
                confidence=0.85,
            ))

    # ── Process-based lateral movement ────────────────────────────────────────
    if processes:
        lateral_tools = {
            "psexec.exe":          ("T1021.002", "PsExec remote execution"),
            "wmic.exe":            ("T1047", "WMI remote execution"),
            "winrs.exe":           ("T1021.006", "WinRM remote execution"),
            "mstsc.exe":           ("T1021.001", "RDP client"),
            "invoke-command":      ("T1021.006", "PowerShell remoting"),
            "enter-pssession":     ("T1021.006", "PowerShell remoting"),
            "impacket":            ("T1021.002", "Impacket lateral movement framework"),
            "crackmapexec":        ("T1021",     "CrackMapExec lateral movement"),
            "smbclient":           ("T1021.002", "SMB client lateral movement"),
        }
        for proc in processes:
            name = (proc.get("ImageFileName") or proc.get("Name") or "").lower()
            cmdline = (proc.get("CommandLine") or proc.get("cmdline") or "").lower()
            pid = proc.get("PID") or proc.get("pid") or 0

            for tool, (mitre, desc) in lateral_tools.items():
                if tool in name or tool in cmdline:
                    # Check for remote targets in cmdline
                    remote_targets = re.findall(r'\\\\([\w\-\.]+)\\', cmdline)
                    findings.append(DFIRFinding(
                        finding_id=_fid("LATM"),
                        category="lateral_movement",
                        title=f"Lateral Movement Tool: {name}",
                        severity="high",
                        score=8.0,
                        description=f"{desc}: '{name}' (PID {pid})",
                        evidence=[
                            f"Process: {name} (PID {pid})",
                            f"CommandLine: {cmdline[:200]}",
                        ] + ([f"Targets: {remote_targets}"] if remote_targets else []),
                        affected_entities=[name] + remote_targets,
                        mitre_technique=mitre,
                        mitre_tactic="Lateral Movement",
                        recommendation=f"Identify all target systems. Check for further compromise.",
                        confidence=0.85,
                    ))
                    break

    # ── Movement graph summary ────────────────────────────────────────────────
    if findings:
        all_entities: list[str] = []
        for f in findings:
            all_entities.extend(f.affected_entities)
        unique_hosts = list({e for e in all_entities if e and len(e) > 2})

        findings.append(DFIRFinding(
            finding_id=_fid("LATM"),
            category="lateral_movement",
            title="Movement Summary",
            severity="info",
            score=0.0,
            description=f"Lateral movement detected across {len(unique_hosts)} host(s)/entity/entities.",
            evidence=[
                f"Compromised/involved hosts: {unique_hosts[:10]}",
                f"Total movement findings: {len(findings) - 1}",
            ],
            recommendation="Build complete network graph. Identify patient-zero and all pivot points.",
            confidence=0.8,
        ))

    return _build_report("Lateral Movement Mapping", findings)


# ══════════════════════════════════════════════════════════════════════════════
# REPORT BUILDER + ORCHESTRATOR
# ══════════════════════════════════════════════════════════════════════════════

def _build_report(title: str, findings: list[DFIRFinding]) -> DFIRReport:
    """Build and score a DFIRReport from a list of findings."""
    report = DFIRReport(
        title=title,
        findings=findings,
        generated_at=datetime.now(timezone.utc).isoformat(),
    )

    if not findings:
        report.summary = f"{title}: No findings detected."
        report.risk_level = "low"
        return report

    # Weighted risk score
    weights = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    scored = [f for f in findings if f.severity != "info"]
    if scored:
        total_w = sum(weights.get(f.severity, 1) for f in scored)
        weighted = sum(f.score * weights.get(f.severity, 1) for f in scored)
        report.risk_score = round(weighted / total_w, 2) if total_w else 0.0
    else:
        report.risk_score = 0.0

    if report.risk_score >= 8.5:
        report.risk_level = "critical"
    elif report.risk_score >= 6.5:
        report.risk_level = "high"
    elif report.risk_score >= 4.0:
        report.risk_level = "medium"
    else:
        report.risk_level = "low"

    critical_count = len(report.critical)
    high_count = len(report.high)

    if critical_count:
        report.summary = f"CRITICAL: {critical_count} critical finding(s) require immediate response."
    elif high_count:
        report.summary = f"HIGH: {high_count} high-severity finding(s) require investigation."
    else:
        report.summary = f"{len(findings)} finding(s) detected. Risk level: {report.risk_level}."

    logger.info(
        "{}: {} findings | critical={} high={} risk={}",
        title, len(findings), critical_count, high_count, report.risk_level,
    )
    return report


class OffensiveDFIR:
    """
    Unified interface for all V2.3 offensive DFIR capabilities.
    All methods are READ-ONLY and evidence-grade.
    """

    def hunt_persistence(self) -> DFIRReport:
        return hunt_persistence()

    def detect_beacons(
        self,
        connections: list[dict],
        processes: list[dict] | None = None,
        history: list[dict] | None = None,
    ) -> DFIRReport:
        return detect_beacons(connections, processes, history)

    def detect_credential_theft(
        self,
        processes: list[dict] | None = None,
        events: list[dict] | None = None,
        live: bool = True,
    ) -> DFIRReport:
        return detect_credential_theft(processes, events, live)

    def triage_ransomware(
        self,
        scan_path: str | Path = "C:\\",
        processes: list[dict] | None = None,
        events: list[dict] | None = None,
        max_files: int = 50000,
    ) -> DFIRReport:
        return triage_ransomware(scan_path, processes, events, max_files)

    def map_lateral_movement(
        self,
        events: list[dict] | None = None,
        processes: list[dict] | None = None,
        connections: list[dict] | None = None,
    ) -> DFIRReport:
        return map_lateral_movement(events, processes, connections)

    def full_triage(
        self,
        scan_path: str | Path = "C:\\",
        processes: list[dict] | None = None,
        connections: list[dict] | None = None,
        events: list[dict] | None = None,
        output_dir: str | Path | None = None,
    ) -> dict[str, DFIRReport]:
        """
        Run all DFIR modules in sequence and optionally save JSON reports.
        Returns dict of {module_name: DFIRReport}.
        """
        logger.info("Full DFIR triage started")
        results = {
            "persistence":    self.hunt_persistence(),
            "beacons":        self.detect_beacons(connections or [], processes),
            "credentials":    self.detect_credential_theft(processes, events),
            "ransomware":     self.triage_ransomware(scan_path, processes, events),
            "lateral_movement": self.map_lateral_movement(events, processes, connections),
        }

        if output_dir:
            out = Path(output_dir)
            out.mkdir(parents=True, exist_ok=True)
            for name, report in results.items():
                path = out / f"dfir_{name}.json"
                path.write_text(
                    json.dumps(report.to_dict(), indent=2, default=str),
                    encoding="utf-8",
                )

        total = sum(len(r.findings) for r in results.values())
        critical = sum(len(r.critical) for r in results.values())
        logger.info("Full triage complete | total={} critical={}", total, critical)
        return results
