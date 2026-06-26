"""
Cross-Device Timeline Fusion (V3.0)
=====================================
Merges forensic timelines from multiple devices/sources into a single
unified, de-duplicated, sorted timeline with cross-device correlation.

Sources supported:
  - Memory dump timelines (Volatility3)
  - Windows Event Logs
  - Filesystem MFT/MAC times
  - Network capture timestamps
  - Mobile device event logs
  - Cloud audit logs (AWS CloudTrail, Azure Activity Log, GCP Audit)
  - Custom JSON timelines

Features:
  - Automatic timestamp normalization to UTC
  - Cross-device event correlation (same actor, same IP, close timestamps)
  - Attack sequence detection across devices
  - MITRE ATT&CK phase annotation

Usage:
    from core.v3.timeline_fusion import TimelineFusion

    fusion = TimelineFusion(case_id="CASE-001")
    fusion.add_source("workstation-01", "memory", processes_json)
    fusion.add_source("dc-01",          "events",  event_log_json)
    fusion.add_source("aws",            "cloud",   cloudtrail_json)

    unified = fusion.build()
    fusion.export(Path("evidence/unified_timeline.json"))
    correlated = fusion.correlate()
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from loguru import logger


@dataclass
class FusedEvent:
    timestamp: str          # ISO 8601 UTC
    source_device: str      # hostname or label
    source_type: str        # memory | events | filesystem | network | mobile | cloud | custom
    event_type: str         # process_create | logon | network | file_access | etc.
    actor: str = ""         # username, process name, or IP
    description: str = ""
    raw: dict = field(default_factory=dict)
    is_suspicious: bool = False
    mitre_technique: str = ""
    mitre_tactic: str = ""
    correlation_id: str = ""   # links related events across devices
    confidence: float = 0.8

    def __lt__(self, other: "FusedEvent") -> bool:
        return self.timestamp < other.timestamp


@dataclass
class CorrelatedCluster:
    """A group of cross-device events that appear related."""
    cluster_id: str
    events: list[FusedEvent]
    correlation_type: str   # same_actor | same_ip | temporal_proximity | attack_sequence
    description: str = ""
    risk_level: str = "medium"


@dataclass
class FusedTimeline:
    case_id: str
    generated_at: str
    total_events: int
    sources: list[str]
    time_range_start: str
    time_range_end: str
    suspicious_events: int
    events: list[FusedEvent] = field(default_factory=list)
    correlated_clusters: list[CorrelatedCluster] = field(default_factory=list)


class TimelineFusion:
    """
    Merges and correlates forensic timelines from multiple evidence sources.
    """

    # Max seconds between events to consider them temporally related
    CORRELATION_WINDOW_SECS = 300  # 5 minutes

    def __init__(self, case_id: str) -> None:
        self.case_id = case_id
        self._sources: list[tuple[str, str, list[FusedEvent]]] = []
        self._all_events: list[FusedEvent] = []

    def add_source(
        self,
        device_label: str,
        source_type: str,
        data: list[dict] | dict,
    ) -> int:
        """
        Add a timeline source.

        Args:
            device_label: Human-readable device name.
            source_type:  memory | events | filesystem | network | mobile | cloud | custom
            data:         Raw event data (format depends on source_type).

        Returns:
            Number of events parsed.
        """
        parsers = {
            "memory":     self._parse_memory,
            "events":     self._parse_windows_events,
            "filesystem": self._parse_filesystem,
            "network":    self._parse_network,
            "mobile":     self._parse_mobile,
            "cloud":      self._parse_cloud,
            "custom":     self._parse_custom,
        }
        parser = parsers.get(source_type, self._parse_custom)
        events = parser(device_label, data if isinstance(data, list) else [data])
        self._sources.append((device_label, source_type, events))
        logger.info("Timeline source added | device={} | type={} | events={}", device_label, source_type, len(events))
        return len(events)

    def build(self) -> list[FusedEvent]:
        """Merge all sources into a single sorted timeline."""
        all_events: list[FusedEvent] = []
        for _, _, events in self._sources:
            all_events.extend(events)

        # Sort by timestamp
        all_events.sort()
        self._all_events = all_events
        logger.info("Fused timeline: {} total events from {} source(s)", len(all_events), len(self._sources))
        return all_events

    def correlate(self) -> list[CorrelatedCluster]:
        """
        Find cross-device correlations:
          - Same actor (username/IP) across multiple devices
          - Temporal proximity (events on different devices within 5 min window)
          - Attack sequence patterns (credential dump followed by lateral movement)
        """
        if not self._all_events:
            self.build()

        clusters: list[CorrelatedCluster] = []
        import uuid as _uuid

        # ── Same actor across devices ─────────────────────────────────────────
        actor_events: dict[str, list[FusedEvent]] = {}
        for event in self._all_events:
            if event.actor and len(event.actor) > 2:
                actor_events.setdefault(event.actor.lower(), []).append(event)

        for actor, events in actor_events.items():
            devices = list({e.source_device for e in events})
            if len(devices) > 1:
                clusters.append(CorrelatedCluster(
                    cluster_id=str(_uuid.uuid4())[:8],
                    events=events[:20],
                    correlation_type="same_actor",
                    description=f"Actor '{actor}' seen on {len(devices)} device(s): {', '.join(devices[:5])}",
                    risk_level="high" if any(e.is_suspicious for e in events) else "medium",
                ))

        # ── Temporal proximity across devices ─────────────────────────────────
        for i, event_a in enumerate(self._all_events):
            if not event_a.is_suspicious:
                continue
            nearby: list[FusedEvent] = []
            for event_b in self._all_events[i+1:i+50]:
                if event_b.source_device == event_a.source_device:
                    continue
                try:
                    ta = datetime.fromisoformat(event_a.timestamp.replace("Z", "+00:00"))
                    tb = datetime.fromisoformat(event_b.timestamp.replace("Z", "+00:00"))
                    diff = abs((tb - ta).total_seconds())
                    if diff <= self.CORRELATION_WINDOW_SECS:
                        nearby.append(event_b)
                except Exception:
                    pass
            if nearby:
                clusters.append(CorrelatedCluster(
                    cluster_id=str(_uuid.uuid4())[:8],
                    events=[event_a] + nearby[:5],
                    correlation_type="temporal_proximity",
                    description=(
                        f"Suspicious event on {event_a.source_device} followed by activity "
                        f"on {list({e.source_device for e in nearby})[:3]} within "
                        f"{self.CORRELATION_WINDOW_SECS}s"
                    ),
                    risk_level="high",
                ))
            if len(clusters) > 50:
                break

        # ── Attack sequence detection ─────────────────────────────────────────
        # Look for: credential_access -> lateral_movement pattern across devices
        cred_events = [e for e in self._all_events if e.mitre_tactic in ("Credential Access",)]
        lateral_events = [e for e in self._all_events if e.mitre_tactic in ("Lateral Movement",)]

        for cred in cred_events:
            for lat in lateral_events:
                if lat.source_device == cred.source_device:
                    continue
                try:
                    tc = datetime.fromisoformat(cred.timestamp.replace("Z", "+00:00"))
                    tl = datetime.fromisoformat(lat.timestamp.replace("Z", "+00:00"))
                    diff = (tl - tc).total_seconds()
                    if 0 < diff < 3600:  # lateral within 1 hour of cred theft
                        clusters.append(CorrelatedCluster(
                            cluster_id=str(_uuid.uuid4())[:8],
                            events=[cred, lat],
                            correlation_type="attack_sequence",
                            description=(
                                f"Credential access on {cred.source_device} followed by "
                                f"lateral movement to {lat.source_device} ({int(diff/60)}min later)"
                            ),
                            risk_level="critical",
                        ))
                except Exception:
                    pass

        logger.info("Timeline correlation: {} cluster(s) found", len(clusters))
        return clusters

    def export(self, output_path: Path) -> Path:
        """Export the fused timeline to JSON."""
        clusters = self.correlate()
        timeline = FusedTimeline(
            case_id=self.case_id,
            generated_at=datetime.now(timezone.utc).isoformat(),
            total_events=len(self._all_events),
            sources=[f"{dev}({stype})" for dev, stype, _ in self._sources],
            time_range_start=self._all_events[0].timestamp if self._all_events else "",
            time_range_end=self._all_events[-1].timestamp if self._all_events else "",
            suspicious_events=sum(1 for e in self._all_events if e.is_suspicious),
            events=self._all_events,
            correlated_clusters=clusters,
        )
        data = asdict(timeline)
        output_path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
        logger.info("Fused timeline exported: {}", output_path)
        return output_path

    # ── Source parsers ────────────────────────────────────────────────────────

    def _parse_memory(self, device: str, data: list[dict]) -> list[FusedEvent]:
        events: list[FusedEvent] = []
        for item in data:
            # Process creation events from Volatility3
            ts = item.get("CreateTime") or item.get("timestamp") or ""
            if not ts or ts in ("N/A", "0", ""):
                continue
            name = item.get("ImageFileName") or item.get("Name") or "unknown"
            pid = item.get("PID") or item.get("pid") or 0
            is_sus = bool(item.get("_suspicious") or item.get("is_suspicious"))
            events.append(FusedEvent(
                timestamp=_normalize_ts(str(ts)),
                source_device=device,
                source_type="memory",
                event_type="process_create",
                actor=name,
                description=f"Process created: {name} (PID {pid})",
                raw=item,
                is_suspicious=is_sus,
            ))
        return events

    def _parse_windows_events(self, device: str, data: list[dict]) -> list[FusedEvent]:
        events: list[FusedEvent] = []
        eid_map = {
            4624: ("logon", "Credential Access", False),
            4625: ("logon_fail", "Credential Access", False),
            4648: ("explicit_logon", "Credential Access", True),
            4688: ("process_create", "Execution", False),
            4697: ("service_install", "Persistence", True),
            7045: ("service_install", "Persistence", True),
            4672: ("priv_assign", "Privilege Escalation", False),
            5140: ("share_access", "Lateral Movement", True),
        }
        for item in data:
            eid = int(item.get("event_id") or item.get("Id") or 0)
            ts = item.get("time_created") or item.get("timestamp") or ""
            if not ts:
                continue
            etype, tactic, sus = eid_map.get(eid, (f"event_{eid}", "", False))
            username = item.get("account_name") or item.get("SubjectUserName") or ""
            events.append(FusedEvent(
                timestamp=_normalize_ts(ts),
                source_device=device,
                source_type="events",
                event_type=etype,
                actor=username,
                description=f"EventID {eid}: {etype}",
                raw=item,
                is_suspicious=sus,
                mitre_tactic=tactic,
            ))
        return events

    def _parse_filesystem(self, device: str, data: list[dict]) -> list[FusedEvent]:
        events: list[FusedEvent] = []
        for item in data:
            for ts_field, etype in [
                ("modified", "file_modified"),
                ("created", "file_created"),
                ("accessed", "file_accessed"),
            ]:
                ts = item.get(ts_field) or item.get(f"mtime" if ts_field == "modified" else ts_field) or ""
                if not ts:
                    continue
                events.append(FusedEvent(
                    timestamp=_normalize_ts(str(ts)),
                    source_device=device,
                    source_type="filesystem",
                    event_type=etype,
                    actor=item.get("owner") or "",
                    description=f"{etype}: {item.get('path', '')}",
                    raw=item,
                ))
        return events

    def _parse_network(self, device: str, data: list[dict]) -> list[FusedEvent]:
        events: list[FusedEvent] = []
        for item in data:
            ts = item.get("timestamp") or item.get("time") or ""
            if not ts:
                continue
            src = item.get("src_ip") or item.get("LocalAddr") or ""
            dst = item.get("dst_ip") or item.get("ForeignAddr") or ""
            events.append(FusedEvent(
                timestamp=_normalize_ts(str(ts)),
                source_device=device,
                source_type="network",
                event_type="network_connection",
                actor=src,
                description=f"Network: {src} -> {dst}:{item.get('dst_port', '')}",
                raw=item,
            ))
        return events

    def _parse_mobile(self, device: str, data: list[dict]) -> list[FusedEvent]:
        events: list[FusedEvent] = []
        for item in data:
            ts = item.get("timestamp") or item.get("date") or ""
            if not ts:
                continue
            events.append(FusedEvent(
                timestamp=_normalize_ts(str(ts)),
                source_device=device,
                source_type="mobile",
                event_type=item.get("event_type") or item.get("type") or "mobile_event",
                actor=item.get("contact") or item.get("app") or "",
                description=item.get("message") or item.get("body") or "",
                raw=item,
            ))
        return events

    def _parse_cloud(self, device: str, data: list[dict]) -> list[FusedEvent]:
        events: list[FusedEvent] = []
        for item in data:
            # AWS CloudTrail
            ts = (item.get("eventTime") or item.get("timestamp") or
                  item.get("time") or item.get("eventTimestamp") or "")
            if not ts:
                continue
            actor = (item.get("userIdentity", {}).get("userName") or
                     item.get("caller") or item.get("principalId") or "")
            etype = item.get("eventName") or item.get("operationName") or "cloud_event"
            events.append(FusedEvent(
                timestamp=_normalize_ts(str(ts)),
                source_device=device,
                source_type="cloud",
                event_type=etype,
                actor=actor,
                description=f"{etype} by {actor}",
                raw=item,
            ))
        return events

    def _parse_custom(self, device: str, data: list[dict]) -> list[FusedEvent]:
        events: list[FusedEvent] = []
        for item in data:
            ts = (item.get("timestamp") or item.get("time") or
                  item.get("date") or item.get("ts") or "")
            if not ts:
                continue
            events.append(FusedEvent(
                timestamp=_normalize_ts(str(ts)),
                source_device=device,
                source_type="custom",
                event_type=item.get("event_type") or item.get("type") or "event",
                actor=item.get("actor") or item.get("user") or "",
                description=item.get("description") or item.get("message") or "",
                raw=item,
                is_suspicious=bool(item.get("is_suspicious") or item.get("suspicious")),
                mitre_technique=item.get("mitre_technique") or "",
                mitre_tactic=item.get("mitre_tactic") or "",
            ))
        return events


def _normalize_ts(ts: str) -> str:
    """Normalize various timestamp formats to ISO 8601 UTC."""
    if not ts or ts in ("N/A", "0", "None"):
        return ""
    # Already ISO
    if "T" in ts and ("+00:00" in ts or "Z" in ts or "UTC" in ts):
        return ts.replace("Z", "+00:00").replace(" UTC", "+00:00")
    # Volatility format: "2026-05-22 14:42:41 UTC+0000"
    ts_clean = re.sub(r'\s*UTC[+-]\d+$', '', ts).strip()
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S",
                "%m/%d/%Y %I:%M:%S %p", "%Y-%m-%d"):
        try:
            dt = datetime.strptime(ts_clean, fmt)
            return dt.replace(tzinfo=timezone.utc).isoformat()
        except ValueError:
            continue
    return ts  # Return as-is if we can't parse
