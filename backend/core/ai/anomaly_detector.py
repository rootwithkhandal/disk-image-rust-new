"""
Behavioral Anomaly Detector
==============================
Detects behavioral anomalies in forensic data using statistical
baselines and rule-based heuristics.

Detects:
- Unusual process execution patterns
- Off-hours activity
- Abnormal network connection volumes
- Lateral movement indicators
- Data staging / exfiltration patterns
- Privilege escalation indicators

Usage:
    from core.ai.anomaly_detector import AnomalyDetector

    detector = AnomalyDetector()
    anomalies = detector.analyze(processes, connections, events)
"""

from __future__ import annotations

import statistics
from dataclasses import dataclass, field
from datetime import datetime, timezone

from loguru import logger


@dataclass
class Anomaly:
    anomaly_type: str  # process | network | temporal | privilege | lateral_movement | staging
    description: str
    severity: str  # low | medium | high | critical
    score: float  # 0.0 - 10.0
    evidence: list[str] = field(default_factory=list)
    affected_entities: list[str] = field(default_factory=list)
    mitre_technique: str = ""
    mitre_tactic: str = ""
    recommendation: str = ""
    confidence: float = 0.75

    def __str__(self) -> str:
        return f"[{self.severity.upper()}] {self.anomaly_type}: {self.description}"


@dataclass
class AnomalyReport:
    total_anomalies: int
    critical: list[Anomaly] = field(default_factory=list)
    high: list[Anomaly] = field(default_factory=list)
    medium: list[Anomaly] = field(default_factory=list)
    low: list[Anomaly] = field(default_factory=list)
    risk_score: float = 0.0
    risk_level: str = "low"
    summary: str = ""
    generated_at: str = ""

    @property
    def all_anomalies(self) -> list[Anomaly]:
        return self.critical + self.high + self.medium + self.low


# ── Baseline knowledge ────────────────────────────────────────────────────────

# Processes that should never spawn certain children
_SUSPICIOUS_PARENT_CHILD = {
    "winword.exe": ["cmd.exe", "powershell.exe", "wscript.exe", "mshta.exe"],
    "excel.exe": ["cmd.exe", "powershell.exe", "wscript.exe"],
    "outlook.exe": ["cmd.exe", "powershell.exe", "wscript.exe", "mshta.exe"],
    "iexplore.exe": ["cmd.exe", "powershell.exe", "wscript.exe"],
    "chrome.exe": ["cmd.exe", "powershell.exe"],
    "firefox.exe": ["cmd.exe", "powershell.exe"],
    "svchost.exe": ["cmd.exe", "powershell.exe", "wscript.exe"],
    "explorer.exe": ["mimikatz.exe", "wce.exe", "fgdump.exe"],
}

# Processes that indicate privilege escalation
_PRIV_ESC_INDICATORS = [
    "whoami.exe",
    "net.exe",
    "net1.exe",
    "nltest.exe",
    "dsquery.exe",
    "adfind.exe",
    "bloodhound.exe",
]

# Lateral movement tools
_LATERAL_MOVEMENT_TOOLS = [
    "psexec.exe",
    "wmic.exe",
    "mstsc.exe",
    "winrs.exe",
    "invoke-command",
    "enter-pssession",
]

# Data staging indicators
_STAGING_INDICATORS = [
    "rar.exe",
    "7z.exe",
    "winzip.exe",
    "robocopy.exe",
    "xcopy.exe",
    "compress-archive",
]

# Business hours (9 AM - 6 PM)
_BUSINESS_HOURS_START = 9
_BUSINESS_HOURS_END = 18


class AnomalyDetector:
    """
    Behavioral anomaly detection using rule-based heuristics and statistics.
    """

    def analyze(
        self,
        processes: list[dict] | None = None,
        connections: list[dict] | None = None,
        events: list[dict] | None = None,
        login_events: list[dict] | None = None,
    ) -> AnomalyReport:
        """
        Run full behavioral anomaly analysis.

        Args:
            processes:     List of process dicts from memory/live response.
            connections:   List of network connection dicts.
            events:        List of event log entries.
            login_events:  List of login/logoff events.

        Returns:
            AnomalyReport with all detected anomalies.
        """
        anomalies: list[Anomaly] = []

        if processes:
            anomalies.extend(self._analyze_processes(processes))

        if connections:
            anomalies.extend(self._analyze_connections(connections))

        if events:
            anomalies.extend(self._analyze_events(events))

        if login_events:
            anomalies.extend(self._analyze_logins(login_events))

        # Cross-correlate
        if processes and connections:
            anomalies.extend(self._correlate_process_network(processes, connections))

        return self._build_report(anomalies)

    # ── Process analysis ──────────────────────────────────────────────────────

    def _analyze_processes(self, processes: list[dict]) -> list[Anomaly]:
        anomalies: list[Anomaly] = []

        # Build PID -> name map
        pid_map: dict[int, str] = {}
        for p in processes:
            pid = int(p.get("PID") or p.get("pid") or 0)
            name = (p.get("ImageFileName") or p.get("Name") or p.get("name") or "").lower()
            pid_map[pid] = name

        for proc in processes:
            name = (proc.get("ImageFileName") or proc.get("Name") or proc.get("name") or "").lower()
            ppid = int(proc.get("PPID") or proc.get("ppid") or 0)
            pid = int(proc.get("PID") or proc.get("pid") or 0)
            parent_name = pid_map.get(ppid, "").lower()

            # Suspicious parent-child
            if parent_name in _SUSPICIOUS_PARENT_CHILD:
                bad_children = _SUSPICIOUS_PARENT_CHILD[parent_name]
                if any(child in name for child in bad_children):
                    anomalies.append(
                        Anomaly(
                            anomaly_type="process",
                            description=f"Suspicious parent-child: {parent_name} spawned {name}",
                            severity="high",
                            score=8.0,
                            evidence=[
                                f"Parent: {parent_name} (PID {ppid})",
                                f"Child: {name} (PID {pid})",
                            ],
                            affected_entities=[name, parent_name],
                            mitre_technique="T1059",
                            mitre_tactic="Execution",
                            recommendation=f"Investigate why {parent_name} spawned {name}. Check for macro execution or exploit.",
                            confidence=0.85,
                        )
                    )

            # Privilege escalation indicators
            if any(ind in name for ind in _PRIV_ESC_INDICATORS):
                anomalies.append(
                    Anomaly(
                        anomaly_type="privilege",
                        description=f"Privilege escalation indicator: {name}",
                        severity="medium",
                        score=6.5,
                        evidence=[f"Process: {name} (PID {pid})"],
                        affected_entities=[name],
                        mitre_technique="T1069",
                        mitre_tactic="Discovery",
                        recommendation="Review what account ran this tool and what information was gathered.",
                        confidence=0.70,
                    )
                )

            # Lateral movement tools
            if any(tool in name for tool in _LATERAL_MOVEMENT_TOOLS):
                anomalies.append(
                    Anomaly(
                        anomaly_type="lateral_movement",
                        description=f"Lateral movement tool detected: {name}",
                        severity="high",
                        score=7.5,
                        evidence=[f"Process: {name} (PID {pid})"],
                        affected_entities=[name],
                        mitre_technique="T1021",
                        mitre_tactic="Lateral Movement",
                        recommendation="Identify source and destination of lateral movement. Check for unauthorized access.",
                        confidence=0.80,
                    )
                )

            # Data staging
            if any(tool in name for tool in _STAGING_INDICATORS):
                anomalies.append(
                    Anomaly(
                        anomaly_type="staging",
                        description=f"Data staging/compression tool: {name}",
                        severity="medium",
                        score=6.0,
                        evidence=[f"Process: {name} (PID {pid})"],
                        affected_entities=[name],
                        mitre_technique="T1560",
                        mitre_tactic="Collection",
                        recommendation="Check what data is being compressed. Look for exfiltration indicators.",
                        confidence=0.65,
                    )
                )

        return anomalies

    # ── Network analysis ──────────────────────────────────────────────────────

    def _analyze_connections(self, connections: list[dict]) -> list[Anomaly]:
        anomalies: list[Anomaly] = []

        # Count connections per process
        proc_conn_count: dict[str, int] = {}
        for conn in connections:
            proc = (
                conn.get("Owner") or conn.get("process_name") or conn.get("process") or "unknown"
            ).lower()
            proc_conn_count[proc] = proc_conn_count.get(proc, 0) + 1

        # Flag processes with unusually high connection counts
        if len(proc_conn_count) > 1:
            counts = list(proc_conn_count.values())
            mean = statistics.mean(counts)
            stdev = statistics.stdev(counts) if len(counts) > 1 else 0

            for proc, count in proc_conn_count.items():
                if stdev > 0 and count > mean + 2 * stdev and count > 5:
                    anomalies.append(
                        Anomaly(
                            anomaly_type="network",
                            description=f"Abnormal connection volume: {proc} has {count} connections",
                            severity="medium",
                            score=6.0,
                            evidence=[
                                f"{proc}: {count} connections (mean={mean:.1f}, stdev={stdev:.1f})"
                            ],
                            affected_entities=[proc],
                            mitre_technique="T1071",
                            mitre_tactic="Command and Control",
                            recommendation=f"Investigate why {proc} has {count} active connections.",
                            confidence=0.70,
                        )
                    )

        # Check for connections to non-standard ports
        suspicious_ports = {4444, 4445, 1337, 31337, 8888, 9999, 6666}
        for conn in connections:
            remote_port = int(conn.get("ForeignPort") or conn.get("remote_port") or 0)
            proc = conn.get("Owner") or conn.get("process_name") or "unknown"
            if remote_port in suspicious_ports:
                anomalies.append(
                    Anomaly(
                        anomaly_type="network",
                        description=f"Connection to suspicious port {remote_port} by {proc}",
                        severity="high",
                        score=8.0,
                        evidence=[f"{proc} -> port {remote_port}"],
                        affected_entities=[proc],
                        mitre_technique="T1571",
                        mitre_tactic="Command and Control",
                        recommendation=f"Investigate connection to port {remote_port}. Common C2/reverse shell port.",
                        confidence=0.85,
                    )
                )

        return anomalies

    # ── Event log analysis ────────────────────────────────────────────────────

    def _analyze_events(self, events: list[dict]) -> list[Anomaly]:
        anomalies: list[Anomaly] = []

        # Count failed logins (EventID 4625)
        failed_logins = [e for e in events if int(e.get("event_id") or e.get("Id") or 0) == 4625]
        if len(failed_logins) > 10:
            anomalies.append(
                Anomaly(
                    anomaly_type="temporal",
                    description=f"Brute force indicator: {len(failed_logins)} failed login attempts",
                    severity="high" if len(failed_logins) > 50 else "medium",
                    score=7.0 if len(failed_logins) > 50 else 5.5,
                    evidence=[f"{len(failed_logins)} EventID 4625 (failed logon) events"],
                    mitre_technique="T1110",
                    mitre_tactic="Credential Access",
                    recommendation="Review source IPs of failed logins. Check for account lockouts.",
                    confidence=0.90,
                )
            )

        # Service installs (EventID 7045)
        service_installs = [e for e in events if int(e.get("event_id") or e.get("Id") or 0) == 7045]
        if service_installs:
            anomalies.append(
                Anomaly(
                    anomaly_type="process",
                    description=f"{len(service_installs)} new service(s) installed",
                    severity="medium",
                    score=6.0,
                    evidence=[
                        f"EventID 7045: {e.get('message', '')[:80]}" for e in service_installs[:3]
                    ],
                    mitre_technique="T1543.003",
                    mitre_tactic="Persistence",
                    recommendation="Review newly installed services. Verify they are legitimate.",
                    confidence=0.80,
                )
            )

        return anomalies

    # ── Login analysis ────────────────────────────────────────────────────────

    def _analyze_logins(self, login_events: list[dict]) -> list[Anomaly]:
        anomalies: list[Anomaly] = []

        # Off-hours logins
        off_hours: list[dict] = []
        for event in login_events:
            ts = event.get("time_created") or event.get("timestamp") or ""
            try:
                # Parse hour from timestamp
                if "T" in ts:
                    hour = int(ts.split("T")[1][:2])
                elif " " in ts:
                    hour = int(ts.split(" ")[1][:2])
                else:
                    continue
                if hour < _BUSINESS_HOURS_START or hour >= _BUSINESS_HOURS_END:
                    off_hours.append(event)
            except Exception:
                pass

        if off_hours:
            anomalies.append(
                Anomaly(
                    anomaly_type="temporal",
                    description=f"{len(off_hours)} login(s) outside business hours",
                    severity="medium",
                    score=5.5,
                    evidence=[
                        f"Off-hours login at {e.get('time_created', '')[:19]}"
                        for e in off_hours[:3]
                    ],
                    mitre_technique="T1078",
                    mitre_tactic="Defense Evasion",
                    recommendation="Verify off-hours logins are authorized. Check for compromised credentials.",
                    confidence=0.65,
                )
            )

        return anomalies

    # ── Cross-correlation ─────────────────────────────────────────────────────

    def _correlate_process_network(
        self, processes: list[dict], connections: list[dict]
    ) -> list[Anomaly]:
        """Correlate processes with their network connections."""
        anomalies: list[Anomaly] = []

        # Find processes with both suspicious flags AND network connections
        sus_procs = {
            str(p.get("PID") or p.get("pid") or 0)
            for p in processes
            if p.get("_suspicious") or p.get("is_suspicious")
        }

        for conn in connections:
            pid = str(conn.get("PID") or conn.get("OwningProcess") or conn.get("pid") or "")
            if pid in sus_procs:
                proc = conn.get("Owner") or conn.get("process_name") or f"PID {pid}"
                remote = f"{conn.get('ForeignAddr', '')}:{conn.get('ForeignPort', '')}"
                anomalies.append(
                    Anomaly(
                        anomaly_type="network",
                        description=f"Suspicious process {proc} has active network connection to {remote}",
                        severity="critical",
                        score=9.0,
                        evidence=[f"Process: {proc} (PID {pid})", f"Connection: -> {remote}"],
                        affected_entities=[proc],
                        mitre_technique="T1071",
                        mitre_tactic="Command and Control",
                        recommendation="Isolate system. Block connection. Capture network traffic for analysis.",
                        confidence=0.90,
                    )
                )

        return anomalies

    # ── Report builder ────────────────────────────────────────────────────────

    def _build_report(self, anomalies: list[Anomaly]) -> AnomalyReport:
        report = AnomalyReport(
            total_anomalies=len(anomalies),
            generated_at=datetime.now(timezone.utc).isoformat(),
        )

        for anomaly in anomalies:
            if anomaly.severity == "critical":
                report.critical.append(anomaly)
            elif anomaly.severity == "high":
                report.high.append(anomaly)
            elif anomaly.severity == "medium":
                report.medium.append(anomaly)
            else:
                report.low.append(anomaly)

        # Risk score = weighted average
        if anomalies:
            weights = {"critical": 4, "high": 3, "medium": 2, "low": 1}
            total_weight = sum(weights.get(a.severity, 1) for a in anomalies)
            weighted_score = sum(a.score * weights.get(a.severity, 1) for a in anomalies)
            report.risk_score = round(weighted_score / total_weight, 2)
        else:
            report.risk_score = 0.0

        if report.risk_score >= 8.0:
            report.risk_level = "critical"
        elif report.risk_score >= 6.0:
            report.risk_level = "high"
        elif report.risk_score >= 4.0:
            report.risk_level = "medium"
        else:
            report.risk_level = "low"

        # Summary
        if report.critical:
            report.summary = (
                f"CRITICAL: {len(report.critical)} critical anomaly/anomalies detected. "
                f"Immediate incident response required."
            )
        elif report.high:
            report.summary = (
                f"HIGH: {len(report.high)} high-severity anomaly/anomalies. "
                f"Analyst investigation required."
            )
        elif report.medium:
            report.summary = f"MEDIUM: {len(report.medium)} anomaly/anomalies for review."
        else:
            report.summary = "No significant behavioral anomalies detected."

        logger.info(
            "Anomaly report: critical={} high={} medium={} low={} risk={}",
            len(report.critical),
            len(report.high),
            len(report.medium),
            len(report.low),
            report.risk_level,
        )
        return report
