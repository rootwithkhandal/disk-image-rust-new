"""
Timeline Narrator
==================
Converts raw forensic timeline events into a coherent narrative
that tells the story of what happened on a system.

Identifies attack phases, reconstructs attacker activity,
and produces a readable incident timeline.

Usage:
    from core.ai.timeline_narrator import TimelineNarrator

    narrator = TimelineNarrator()
    story = narrator.narrate(timeline_events)
    print(story.narrative)
    print(story.attack_phases)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass
class AttackPhase:
    """A detected phase of an attack in the timeline."""

    phase_name: str  # reconnaissance | initial_access | execution | persistence | etc.
    start_time: str
    end_time: str
    events: list[dict] = field(default_factory=list)
    description: str = ""
    mitre_tactic: str = ""
    confidence: float = 0.7


@dataclass
class TimelineStory:
    """The narrated story of a forensic timeline."""

    title: str
    narrative: str
    attack_phases: list[AttackPhase] = field(default_factory=list)
    key_events: list[dict] = field(default_factory=list)
    timeline_start: str = ""
    timeline_end: str = ""
    total_events: int = 0
    suspicious_events: int = 0
    risk_level: str = "low"
    generated_at: str = ""

    def __str__(self) -> str:
        phases = "\n".join(f"  [{p.phase_name}] {p.description}" for p in self.attack_phases)
        return f"{self.title}\n\n{self.narrative}\n\nAttack Phases:\n{phases}"


# MITRE ATT&CK tactic ordering (kill chain)
_TACTIC_ORDER = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]

# Process names mapped to attack phases
_PHASE_INDICATORS = {
    "initial_access": ["powershell.exe", "wscript.exe", "mshta.exe", "cmd.exe"],
    "execution": ["powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "regsvr32.exe"],
    "persistence": ["schtasks.exe", "reg.exe", "sc.exe", "wmic.exe"],
    "credential_access": ["mimikatz.exe", "lsass.exe", "wce.exe", "fgdump.exe"],
    "lateral_movement": ["psexec.exe", "wmic.exe", "net.exe", "mstsc.exe"],
    "c2": ["nc.exe", "ncat.exe", "certutil.exe"],
}


class TimelineNarrator:
    """
    Converts forensic timeline events into a human-readable narrative.
    """

    def narrate(self, events: list[dict]) -> TimelineStory:
        """
        Generate a narrative from a list of timeline events.

        Args:
            events: List of TimelineEvent dicts (from MemoryTimeline or unified timeline)

        Returns:
            TimelineStory with narrative and detected attack phases.
        """
        if not events:
            return TimelineStory(
                title="Empty Timeline",
                narrative="No timeline events to analyze.",
                generated_at=datetime.now(timezone.utc).isoformat(),
            )

        # Sort by timestamp
        sorted_events = sorted(events, key=lambda e: e.get("timestamp", ""))
        suspicious = [e for e in sorted_events if e.get("is_suspicious") or e.get("suspicious")]

        start = sorted_events[0].get("timestamp", "")[:19]
        end = sorted_events[-1].get("timestamp", "")[:19]

        # Detect attack phases
        phases = self._detect_phases(sorted_events)

        # Build narrative
        narrative = self._build_narrative(sorted_events, suspicious, phases, start, end)

        risk = "low"
        if len(suspicious) > 5:
            risk = "critical"
        elif len(suspicious) > 2:
            risk = "high"
        elif len(suspicious) > 0:
            risk = "medium"

        return TimelineStory(
            title=f"Timeline Analysis — {start} to {end}",
            narrative=narrative,
            attack_phases=phases,
            key_events=suspicious[:10],
            timeline_start=start,
            timeline_end=end,
            total_events=len(sorted_events),
            suspicious_events=len(suspicious),
            risk_level=risk,
            generated_at=datetime.now(timezone.utc).isoformat(),
        )

    def _detect_phases(self, events: list[dict]) -> list[AttackPhase]:
        """Detect MITRE ATT&CK phases from timeline events."""
        phases: list[AttackPhase] = []
        phase_events: dict[str, list[dict]] = {p: [] for p in _PHASE_INDICATORS}

        for event in events:
            process = (event.get("process_name") or event.get("process") or "").lower()
            for phase, indicators in _PHASE_INDICATORS.items():
                if any(ind in process for ind in indicators):
                    phase_events[phase].append(event)

        for phase_name, evs in phase_events.items():
            if not evs:
                continue
            start = evs[0].get("timestamp", "")[:19]
            end = evs[-1].get("timestamp", "")[:19]
            phases.append(
                AttackPhase(
                    phase_name=phase_name,
                    start_time=start,
                    end_time=end,
                    events=evs,
                    description=self._describe_phase(phase_name, evs),
                    mitre_tactic=phase_name.replace("_", " ").title(),
                    confidence=0.75,
                )
            )

        return phases

    def _describe_phase(self, phase: str, events: list[dict]) -> str:
        """Generate a one-line description of an attack phase."""
        processes = list({e.get("process_name") or e.get("process") or "unknown" for e in events})[
            :3
        ]
        proc_str = ", ".join(processes)

        descriptions = {
            "initial_access": f"Initial access via {proc_str}",
            "execution": f"Code execution through {proc_str}",
            "persistence": f"Persistence established using {proc_str}",
            "credential_access": f"Credential theft attempted via {proc_str}",
            "lateral_movement": f"Lateral movement using {proc_str}",
            "c2": f"Command and control communication via {proc_str}",
        }
        return descriptions.get(phase, f"{phase}: {proc_str}")

    def _build_narrative(
        self,
        events: list[dict],
        suspicious: list[dict],
        phases: list[AttackPhase],
        start: str,
        end: str,
    ) -> str:
        """Build the full narrative text."""
        lines: list[str] = []

        # Opening
        lines.append(
            f"Timeline spans from {start} to {end}, containing {len(events)} events total."
        )

        if not suspicious:
            lines.append("No suspicious activity was detected in this timeline.")
            return " ".join(lines)

        lines.append(
            f"{len(suspicious)} suspicious event(s) were identified, "
            f"suggesting {'a multi-stage attack' if len(phases) > 2 else 'malicious activity'}."
        )

        # Phase narrative
        if phases:
            phase_names = [p.phase_name.replace("_", " ") for p in phases]
            lines.append(f"Detected attack phases: {', '.join(phase_names)}.")

        # Key events
        if suspicious:
            first_sus = suspicious[0]
            ts = first_sus.get("timestamp", "")[:19]
            proc = first_sus.get("process_name") or first_sus.get("process") or "unknown process"
            lines.append(f"The first suspicious activity occurred at {ts} involving {proc}.")

        # Credential access
        cred_events = [
            e
            for e in suspicious
            if "mimikatz" in (e.get("process_name") or e.get("process") or "").lower()
        ]
        if cred_events:
            lines.append(
                "CRITICAL: Credential dumping tool (mimikatz) was detected. "
                "All credentials on this system and connected systems should be considered compromised."
            )

        # C2 connections
        c2_events = [
            e
            for e in events
            if e.get("event_type") == "network" and (e.get("is_suspicious") or e.get("suspicious"))
        ]
        if c2_events:
            lines.append(
                f"{len(c2_events)} suspicious network connection(s) detected, "
                "suggesting active C2 communication."
            )

        lines.append(
            "Analyst recommendation: Isolate affected systems, "
            "preserve memory dumps, and initiate incident response procedures."
        )

        return " ".join(lines)

    def narrate_process_tree(self, processes: list[dict]) -> str:
        """
        Narrate a process tree, highlighting suspicious parent-child relationships.
        """
        if not processes:
            return "No process data available."

        suspicious = [p for p in processes if p.get("_suspicious") or p.get("is_suspicious")]
        total = len(processes)

        if not suspicious:
            return f"Process tree contains {total} processes. No suspicious activity detected."

        lines = [f"Process tree analysis: {total} processes, {len(suspicious)} suspicious."]

        for proc in suspicious[:5]:
            name = proc.get("ImageFileName") or proc.get("Name") or "unknown"
            pid = proc.get("PID") or proc.get("pid") or 0
            ppid = proc.get("PPID") or proc.get("ppid") or 0
            reasons = proc.get("_suspicious_reasons") or []
            reason_str = reasons[0] if reasons else "heuristic flag"
            lines.append(f"  • {name} (PID {pid}, parent {ppid}): {reason_str}")

        return "\n".join(lines)
