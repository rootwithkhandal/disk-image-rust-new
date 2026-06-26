"""
IOC Prioritization Engine
===========================
Scores and ranks IOCs by severity, confidence, and context.
Deduplicates, enriches with threat intel context, and produces
a prioritized action list for analysts.

Usage:
    from core.ai.ioc_prioritizer import IOCPrioritizer

    prioritizer = IOCPrioritizer()
    ranked = prioritizer.prioritize(ioc_matches)
    report = prioritizer.generate_report(ranked)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone

from loguru import logger


@dataclass
class PrioritizedIOC:
    ioc_type: str
    ioc_value: str
    score: float  # 0.0 - 10.0
    priority: str  # P1 | P2 | P3 | P4
    severity: str  # critical | high | medium | low | info
    occurrences: int = 1
    sources: list[str] = field(default_factory=list)
    context: list[str] = field(default_factory=list)
    mitre_technique: str = ""
    recommended_action: str = ""
    is_known_bad: bool = False
    confidence: float = 0.8

    def __str__(self) -> str:
        return f"[{self.priority}] {self.ioc_type}:{self.ioc_value} (score={self.score:.1f})"


@dataclass
class IOCReport:
    total_iocs: int
    p1_critical: list[PrioritizedIOC] = field(default_factory=list)
    p2_high: list[PrioritizedIOC] = field(default_factory=list)
    p3_medium: list[PrioritizedIOC] = field(default_factory=list)
    p4_low: list[PrioritizedIOC] = field(default_factory=list)
    generated_at: str = ""
    summary: str = ""

    @property
    def all_iocs(self) -> list[PrioritizedIOC]:
        return self.p1_critical + self.p2_high + self.p3_medium + self.p4_low

    @property
    def action_required_count(self) -> int:
        return len(self.p1_critical) + len(self.p2_high)


# ── Scoring weights ───────────────────────────────────────────────────────────

_TYPE_BASE_SCORES = {
    "hash": 9.0,  # Known malicious hash = highest confidence
    "ip": 7.5,
    "domain": 7.0,
    "url": 6.5,
    "email": 5.0,
    "md5": 8.5,
    "sha256": 9.0,
    "ipv4": 7.5,
}

_KNOWN_BAD_BONUS = 3.0
_MULTIPLE_OCCURRENCE_BONUS = 0.5  # per additional occurrence
_CONTEXT_BONUS = 0.3  # per context hit

# Known malicious indicators (demo set — production uses threat intel feeds)
_KNOWN_BAD_DOMAINS = {"evil.com", "malware.cc", "c2server.net", "badactor.ru"}
_KNOWN_BAD_IPS = {"10.0.0.99", "192.168.100.200", "185.220.101.1"}
_KNOWN_BAD_HASHES = {
    "44d88612fea8a8f36de82e1278abb02f",
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
}

# Private/internal IP ranges (lower priority)
_PRIVATE_IP_PATTERNS = [
    re.compile(r"^10\."),
    re.compile(r"^192\.168\."),
    re.compile(r"^172\.(1[6-9]|2[0-9]|3[01])\."),
    re.compile(r"^127\."),
]


def _is_private_ip(ip: str) -> bool:
    return any(p.match(ip) for p in _PRIVATE_IP_PATTERNS)


def _is_known_bad(ioc_type: str, value: str) -> bool:
    v = value.lower()
    if ioc_type in ("domain",):
        return v in _KNOWN_BAD_DOMAINS
    if ioc_type in ("ip", "ipv4"):
        return v in _KNOWN_BAD_IPS
    if ioc_type in ("hash", "md5", "sha256"):
        return v in _KNOWN_BAD_HASHES
    return False


class IOCPrioritizer:
    """
    Scores, deduplicates, and prioritizes IOCs for analyst action.
    """

    def prioritize(self, ioc_matches: list[dict]) -> list[PrioritizedIOC]:
        """
        Score and rank a list of IOC matches.

        Args:
            ioc_matches: List of IOCMatch dicts with ioc_type, ioc_value, matched_in, context

        Returns:
            Sorted list of PrioritizedIOC (highest score first).
        """
        # Deduplicate and aggregate
        aggregated: dict[str, PrioritizedIOC] = {}

        for match in ioc_matches:
            ioc_type = match.get("ioc_type", "unknown")
            ioc_value = match.get("ioc_value", "")
            source = match.get("matched_in", "")
            context = match.get("context", "")

            key = f"{ioc_type}:{ioc_value.lower()}"

            if key in aggregated:
                existing = aggregated[key]
                existing.occurrences += 1
                if source and source not in existing.sources:
                    existing.sources.append(source)
                if context and context not in existing.context:
                    existing.context.append(context[:100])
            else:
                aggregated[key] = PrioritizedIOC(
                    ioc_type=ioc_type,
                    ioc_value=ioc_value,
                    score=0.0,
                    priority="P4",
                    severity="info",
                    sources=[source] if source else [],
                    context=[context[:100]] if context else [],
                    is_known_bad=_is_known_bad(ioc_type, ioc_value),
                )

        # Score each IOC
        for ioc in aggregated.values():
            ioc.score = self._score(ioc)
            ioc.priority, ioc.severity = self._classify(ioc.score)
            ioc.recommended_action = self._recommend_action(ioc)
            ioc.mitre_technique = self._map_mitre(ioc.ioc_type)

        ranked = sorted(aggregated.values(), key=lambda x: x.score, reverse=True)
        logger.info("IOC prioritization: {} unique IOCs ranked", len(ranked))
        return ranked

    def _score(self, ioc: PrioritizedIOC) -> float:
        """Calculate a 0-10 priority score."""
        base = _TYPE_BASE_SCORES.get(ioc.ioc_type.lower(), 5.0)

        # Known bad bonus
        if ioc.is_known_bad:
            base += _KNOWN_BAD_BONUS

        # Multiple occurrences
        if ioc.occurrences > 1:
            base += min(_MULTIPLE_OCCURRENCE_BONUS * (ioc.occurrences - 1), 1.5)

        # Context hits
        base += min(_CONTEXT_BONUS * len(ioc.context), 1.0)

        # Reduce score for private IPs (likely internal)
        if ioc.ioc_type in ("ip", "ipv4") and _is_private_ip(ioc.ioc_value):
            base -= 2.0

        return round(min(max(base, 0.0), 10.0), 2)

    def _classify(self, score: float) -> tuple[str, str]:
        """Map score to priority and severity."""
        if score >= 9.0:
            return "P1", "critical"
        elif score >= 7.0:
            return "P2", "high"
        elif score >= 5.0:
            return "P3", "medium"
        else:
            return "P4", "low"

    def _recommend_action(self, ioc: PrioritizedIOC) -> str:
        """Generate a recommended action for the IOC."""
        actions = {
            "hash": "Quarantine file. Search all systems for this hash. Submit to sandbox.",
            "md5": "Quarantine file. Search all systems for this hash. Submit to sandbox.",
            "sha256": "Quarantine file. Search all systems for this hash. Submit to sandbox.",
            "domain": "Block at DNS/firewall. Search logs for all systems that resolved this domain.",
            "ip": "Block at firewall. Review all connections to/from this IP.",
            "ipv4": "Block at firewall. Review all connections to/from this IP.",
            "url": "Block URL. Identify all users who accessed it. Check for credential theft.",
            "email": "Review email logs. Check for phishing campaign indicators.",
        }
        base = actions.get(ioc.ioc_type.lower(), "Investigate and block as appropriate.")
        if ioc.is_known_bad:
            base = "IMMEDIATE ACTION REQUIRED. " + base
        return base

    def _map_mitre(self, ioc_type: str) -> str:
        """Map IOC type to MITRE ATT&CK technique."""
        mapping = {
            "domain": "T1071.001",
            "ip": "T1071",
            "ipv4": "T1071",
            "url": "T1566.002",
            "hash": "T1204",
            "md5": "T1204",
            "sha256": "T1204",
            "email": "T1566.001",
        }
        return mapping.get(ioc_type.lower(), "")

    def generate_report(self, ranked_iocs: list[PrioritizedIOC]) -> IOCReport:
        """Generate a structured IOC report from ranked IOCs."""
        report = IOCReport(
            total_iocs=len(ranked_iocs),
            generated_at=datetime.now(timezone.utc).isoformat(),
        )

        for ioc in ranked_iocs:
            if ioc.priority == "P1":
                report.p1_critical.append(ioc)
            elif ioc.priority == "P2":
                report.p2_high.append(ioc)
            elif ioc.priority == "P3":
                report.p3_medium.append(ioc)
            else:
                report.p4_low.append(ioc)

        # Summary
        if report.p1_critical:
            report.summary = (
                f"CRITICAL: {len(report.p1_critical)} P1 IOC(s) require immediate action. "
                f"{len(report.p2_high)} P2 IOC(s) require investigation."
            )
        elif report.p2_high:
            report.summary = (
                f"HIGH: {len(report.p2_high)} P2 IOC(s) require investigation. "
                f"No P1 critical IOCs detected."
            )
        elif report.p3_medium:
            report.summary = f"MEDIUM: {len(report.p3_medium)} IOC(s) for analyst review."
        else:
            report.summary = f"LOW: {len(report.p4_low)} low-priority IOC(s) detected."

        logger.info(
            "IOC report: P1={} P2={} P3={} P4={}",
            len(report.p1_critical),
            len(report.p2_high),
            len(report.p3_medium),
            len(report.p4_low),
        )
        return report
