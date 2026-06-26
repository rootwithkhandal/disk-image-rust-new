"""
Suspicious Activity Explainer
================================
Explains suspicious artifacts and activities in plain English.
Provides analyst-friendly context for IOC hits, malware indicators,
persistence mechanisms, and anomalous behavior.

Usage:
    from core.ai.explainer import ActivityExplainer

    explainer = ActivityExplainer()
    explanation = explainer.explain_process(process_data)
    explanation = explainer.explain_ioc("evil.com", "domain")
    explanation = explainer.explain_persistence(entry)
"""

from __future__ import annotations

from dataclasses import dataclass, field

from loguru import logger


@dataclass
class Explanation:
    subject: str
    severity: str  # info | low | medium | high | critical
    what_it_is: str  # Plain English description
    why_suspicious: str  # Why this is flagged
    analyst_action: str  # Recommended next step
    mitre_technique: str = ""  # MITRE ATT&CK technique ID
    mitre_tactic: str = ""  # MITRE ATT&CK tactic
    references: list[str] = field(default_factory=list)
    confidence: float = 0.8

    def __str__(self) -> str:
        return (
            f"[{self.severity.upper()}] {self.subject}\n"
            f"What: {self.what_it_is}\n"
            f"Why: {self.why_suspicious}\n"
            f"Action: {self.analyst_action}"
        )


# ── Knowledge base ────────────────────────────────────────────────────────────

_PROCESS_KB: dict[str, dict] = {
    "mimikatz.exe": {
        "severity": "critical",
        "what": "Mimikatz is a credential dumping tool used to extract passwords, hashes, and Kerberos tickets from Windows memory.",
        "why": "Its presence indicates an active or recent credential theft attack.",
        "action": "Isolate the system immediately. Check for lateral movement. Review all accounts for unauthorized access.",
        "mitre": "T1003.001",
        "tactic": "Credential Access",
    },
    "psexec.exe": {
        "severity": "high",
        "what": "PsExec is a legitimate Sysinternals tool for remote execution, frequently abused by attackers for lateral movement.",
        "why": "Unexpected PsExec usage often indicates an attacker moving laterally through the network.",
        "action": "Review source and destination of PsExec connections. Check for unauthorized remote sessions.",
        "mitre": "T1021.002",
        "tactic": "Lateral Movement",
    },
    "nc.exe": {
        "severity": "high",
        "what": "Netcat (nc.exe) is a network utility that can create reverse shells and backdoors.",
        "why": "Netcat in unexpected locations is a strong indicator of attacker tooling.",
        "action": "Check for active network connections from this process. Identify C2 infrastructure.",
        "mitre": "T1059",
        "tactic": "Execution",
    },
    "mshta.exe": {
        "severity": "high",
        "what": "MSHTA executes HTML Applications (.hta files) and is commonly used for malware execution.",
        "why": "Attackers use MSHTA to execute malicious scripts while bypassing application whitelisting.",
        "action": "Examine the HTA file being executed. Check parent process and command line arguments.",
        "mitre": "T1218.005",
        "tactic": "Defense Evasion",
    },
    "wscript.exe": {
        "severity": "medium",
        "what": "Windows Script Host executes VBScript and JScript files.",
        "why": "Malware frequently uses WScript to execute malicious scripts dropped on disk.",
        "action": "Identify the script being executed. Check for persistence mechanisms.",
        "mitre": "T1059.005",
        "tactic": "Execution",
    },
    "regsvr32.exe": {
        "severity": "high",
        "what": "RegSvr32 registers COM objects and can execute arbitrary DLLs or remote scripts.",
        "why": "Squiblydoo attack: regsvr32 /s /n /u /i:<url> scrobj.dll bypasses AppLocker.",
        "action": "Check command line for remote URLs or unusual DLL paths.",
        "mitre": "T1218.010",
        "tactic": "Defense Evasion",
    },
    "certutil.exe": {
        "severity": "high",
        "what": "CertUtil is a Windows certificate utility that can download files and decode base64.",
        "why": "Attackers abuse CertUtil to download malware payloads while evading detection.",
        "action": "Check command line for -urlcache or -decode flags. Identify downloaded files.",
        "mitre": "T1105",
        "tactic": "Command and Control",
    },
}

_IOC_KB: dict[str, dict] = {
    "domain": {
        "what": "A domain name associated with malicious infrastructure.",
        "why": "This domain appears in threat intelligence feeds as a known C2 server, phishing domain, or malware distribution point.",
        "action": "Block the domain at the firewall/DNS level. Search for all systems that communicated with it.",
        "mitre": "T1071.001",
        "tactic": "Command and Control",
    },
    "ip": {
        "what": "An IP address associated with malicious activity.",
        "why": "This IP appears in threat intelligence as a known C2 server, scanner, or attacker infrastructure.",
        "action": "Block at firewall. Review all connections to/from this IP. Check for data exfiltration.",
        "mitre": "T1071",
        "tactic": "Command and Control",
    },
    "hash": {
        "what": "A file hash matching a known malicious sample.",
        "why": "This hash matches a known malware sample in threat intelligence databases.",
        "action": "Quarantine the file immediately. Search for the same hash across all systems.",
        "mitre": "T1204",
        "tactic": "Execution",
    },
    "url": {
        "what": "A URL associated with malicious content.",
        "why": "This URL has been flagged as a phishing page, malware download, or C2 endpoint.",
        "action": "Block the URL. Identify all users who accessed it. Check for credential theft.",
        "mitre": "T1566.002",
        "tactic": "Initial Access",
    },
}

_PERSISTENCE_KB: dict[str, dict] = {
    "run_key": {
        "what": "A Windows Registry Run key that executes a program at user login.",
        "why": "Malware commonly uses Run keys to maintain persistence across reboots.",
        "action": "Examine the command being executed. Verify it is a legitimate application.",
        "mitre": "T1547.001",
        "tactic": "Persistence",
    },
    "scheduled_task": {
        "what": "A Windows Scheduled Task that runs a program at a specified time or event.",
        "why": "Attackers create scheduled tasks to maintain persistence and execute payloads.",
        "action": "Review the task action, trigger, and run-as user. Verify legitimacy.",
        "mitre": "T1053.005",
        "tactic": "Persistence",
    },
    "startup_folder": {
        "what": "A file placed in the Windows Startup folder that executes at login.",
        "why": "The Startup folder is a simple but effective persistence mechanism.",
        "action": "Identify the file and verify it is a legitimate application.",
        "mitre": "T1547.001",
        "tactic": "Persistence",
    },
    "service": {
        "what": "A Windows service that runs in the background.",
        "why": "Malware installs services to run with elevated privileges and survive reboots.",
        "action": "Check the service binary path. Verify the service is legitimate.",
        "mitre": "T1543.003",
        "tactic": "Persistence",
    },
}


class ActivityExplainer:
    """
    Explains suspicious artifacts in plain English with MITRE ATT&CK context.
    """

    def explain_process(self, process: dict) -> Explanation:
        """Explain a suspicious process."""
        name = (
            process.get("ImageFileName") or process.get("Name") or process.get("name") or "unknown"
        ).lower()
        pid = process.get("PID") or process.get("pid") or 0
        reasons = process.get("_suspicious_reasons") or process.get("suspicious_reasons") or []

        kb = _PROCESS_KB.get(name)
        if kb:
            return Explanation(
                subject=f"{name} (PID {pid})",
                severity=kb["severity"],
                what_it_is=kb["what"],
                why_suspicious=kb["why"],
                analyst_action=kb["action"],
                mitre_technique=kb.get("mitre", ""),
                mitre_tactic=kb.get("tactic", ""),
                confidence=0.95,
            )

        # Generic explanation for unknown suspicious processes
        reason_str = "; ".join(reasons) if reasons else "Flagged by heuristic analysis"
        return Explanation(
            subject=f"{name} (PID {pid})",
            severity="medium",
            what_it_is=f"Process '{name}' was flagged as potentially suspicious.",
            why_suspicious=reason_str,
            analyst_action="Investigate the process path, parent process, and command line arguments.",
            mitre_technique="T1059",
            mitre_tactic="Execution",
            confidence=0.6,
        )

    def explain_ioc(self, ioc_value: str, ioc_type: str) -> Explanation:
        """Explain an IOC match."""
        kb = _IOC_KB.get(ioc_type.lower(), _IOC_KB["domain"])
        return Explanation(
            subject=f"{ioc_type.upper()}: {ioc_value}",
            severity="high",
            what_it_is=kb["what"],
            why_suspicious=f"{ioc_value} — {kb['why']}",
            analyst_action=kb["action"],
            mitre_technique=kb.get("mitre", ""),
            mitre_tactic=kb.get("tactic", ""),
            confidence=0.85,
        )

    def explain_persistence(self, entry: dict) -> Explanation:
        """Explain a persistence mechanism."""
        mechanism = entry.get("mechanism", "run_key")
        name = entry.get("name", "unknown")
        command = entry.get("command", "")
        reason = entry.get("reason", "")

        kb = _PERSISTENCE_KB.get(mechanism, _PERSISTENCE_KB["run_key"])
        why = f"Entry '{name}' executes: {command[:100]}"
        if reason:
            why += f" — {reason}"

        return Explanation(
            subject=f"Persistence: {name} ({mechanism})",
            severity="high" if entry.get("is_suspicious") else "medium",
            what_it_is=kb["what"],
            why_suspicious=why,
            analyst_action=kb["action"],
            mitre_technique=kb.get("mitre", ""),
            mitre_tactic=kb.get("tactic", ""),
            confidence=0.80,
        )

    def explain_malfind(self, malfind_entry: dict) -> Explanation:
        """Explain a malfind (injected code) result."""
        process = malfind_entry.get("Process") or malfind_entry.get("process", "unknown")
        pid = malfind_entry.get("PID") or malfind_entry.get("pid", 0)
        protection = malfind_entry.get("Protection") or malfind_entry.get("protection", "")

        return Explanation(
            subject=f"Injected Code: {process} (PID {pid})",
            severity="critical",
            what_it_is=(
                "Memory region with executable permissions in an unexpected location, "
                "indicating possible code injection or process hollowing."
            ),
            why_suspicious=(
                f"Memory protection '{protection}' (PAGE_EXECUTE_READWRITE) in process "
                f"'{process}' suggests shellcode or injected PE. "
                "Legitimate code is rarely marked as both writable and executable."
            ),
            analyst_action=(
                "Dump the memory region for analysis. "
                "Check if the process is hollowed. "
                "Submit the memory dump to a sandbox."
            ),
            mitre_technique="T1055",
            mitre_tactic="Defense Evasion",
            confidence=0.90,
        )

    def explain_high_entropy(self, file_path: str, entropy: float) -> Explanation:
        """Explain a high-entropy file."""
        return Explanation(
            subject=f"High Entropy File: {file_path}",
            severity="medium" if entropy < 7.5 else "high",
            what_it_is=(
                "A file with unusually high Shannon entropy, suggesting it may be "
                "encrypted, compressed, or packed."
            ),
            why_suspicious=(
                f"Entropy of {entropy:.2f}/8.0 exceeds normal thresholds. "
                "Malware packers and encrypted payloads exhibit high entropy to evade signature detection."
            ),
            analyst_action=(
                "Submit to a sandbox for dynamic analysis. "
                "Check if the file is a known packer format (UPX, MPRESS). "
                "Compare against known-good file hashes."
            ),
            mitre_technique="T1027",
            mitre_tactic="Defense Evasion",
            confidence=0.70,
        )

    def batch_explain(self, items: list[dict], item_type: str) -> list[Explanation]:
        """Explain a list of suspicious items."""
        explanations: list[Explanation] = []
        for item in items:
            try:
                if item_type == "process":
                    explanations.append(self.explain_process(item))
                elif item_type == "ioc":
                    explanations.append(
                        self.explain_ioc(item.get("ioc_value", ""), item.get("ioc_type", "domain"))
                    )
                elif item_type == "persistence":
                    explanations.append(self.explain_persistence(item))
                elif item_type == "malfind":
                    explanations.append(self.explain_malfind(item))
            except Exception as exc:
                logger.debug("Explain error for {}: {}", item_type, exc)
        return explanations
