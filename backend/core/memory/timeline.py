"""
Memory Timeline Reconstruction
================================
Builds forensic timelines from memory artifacts:
- Process creation / exit events
- Network connection timestamps
- DLL load times
- User activity reconstruction

Usage:
    from core.memory.timeline import MemoryTimeline

    tl = MemoryTimeline(dump_path="/evidence/memory.raw")
    events = tl.build()
    tl.export_json("/evidence/memory_timeline.json")
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from loguru import logger

from core.memory.volatility_engine import VolatilityEngine


@dataclass
class TimelineEvent:
    """A single timestamped event in the memory timeline."""

    timestamp: str
    event_type: str  # process_create | process_exit | dll_load | network | credential
    source: str  # volatility plugin that produced this
    pid: int = 0
    process_name: str = ""
    description: str = ""
    is_suspicious: bool = False
    raw: dict = field(default_factory=dict)

    def __lt__(self, other: TimelineEvent) -> bool:
        return self.timestamp < other.timestamp


class MemoryTimeline:
    """
    Reconstructs a forensic timeline from memory dump analysis.
    """

    def __init__(self, dump_path: str | Path) -> None:
        self.dump_path = Path(dump_path)
        self.engine = VolatilityEngine(dump_path)
        self._events: list[TimelineEvent] = []

    def build(self) -> list[TimelineEvent]:
        """
        Run all timeline-relevant plugins and merge into a sorted event list.
        Returns events sorted by timestamp (oldest first).
        """
        logger.info("Building memory timeline from {}", self.dump_path.name)
        self._events = []

        self._collect_process_events()
        self._collect_network_events()

        self._events.sort()
        logger.info("Memory timeline: {} event(s)", len(self._events))
        return self._events

    def _collect_process_events(self) -> None:
        """Extract process creation/exit events."""
        result = self.engine.list_processes()
        if not result.success:
            logger.debug("Process list unavailable: {}", result.error)
            return

        for row in result.data:
            pid = int(row.get("PID") or row.get("pid") or 0)
            name = row.get("ImageFileName") or row.get("Name") or "unknown"
            create_time = str(row.get("CreateTime") or row.get("create_time") or "")
            exit_time = str(row.get("ExitTime") or row.get("exit_time") or "")
            is_sus = bool(row.get("_suspicious", False))

            if create_time and create_time not in ("N/A", "0", ""):
                self._events.append(
                    TimelineEvent(
                        timestamp=_normalize_ts(create_time),
                        event_type="process_create",
                        source="windows.pslist",
                        pid=pid,
                        process_name=name,
                        description=f"Process created: {name} (PID {pid})",
                        is_suspicious=is_sus,
                        raw=row,
                    )
                )

            if exit_time and exit_time not in ("N/A", "0", ""):
                self._events.append(
                    TimelineEvent(
                        timestamp=_normalize_ts(exit_time),
                        event_type="process_exit",
                        source="windows.pslist",
                        pid=pid,
                        process_name=name,
                        description=f"Process exited: {name} (PID {pid})",
                        is_suspicious=is_sus,
                        raw=row,
                    )
                )

    def _collect_network_events(self) -> None:
        """Extract network connection events."""
        result = self.engine.list_connections()
        if not result.success:
            logger.debug("Network connections unavailable: {}", result.error)
            return

        for row in result.data:
            pid = int(row.get("PID") or row.get("pid") or 0)
            name = row.get("Owner") or row.get("process_name") or "unknown"
            create_time = str(row.get("CreateTime") or row.get("create_time") or "")
            local = f"{row.get('LocalAddr', '')}:{row.get('LocalPort', '')}"
            remote = f"{row.get('ForeignAddr', '')}:{row.get('ForeignPort', '')}"
            state = row.get("State") or row.get("state") or ""

            if create_time and create_time not in ("N/A", "0", ""):
                self._events.append(
                    TimelineEvent(
                        timestamp=_normalize_ts(create_time),
                        event_type="network",
                        source="windows.netstat",
                        pid=pid,
                        process_name=name,
                        description=f"Network: {name} {local} -> {remote} [{state}]",
                        raw=row,
                    )
                )

    def get_suspicious_events(self) -> list[TimelineEvent]:
        """Return only events flagged as suspicious."""
        return [e for e in self._events if e.is_suspicious]

    def get_process_timeline(self) -> list[TimelineEvent]:
        """Return only process creation/exit events."""
        return [e for e in self._events if e.event_type in ("process_create", "process_exit")]

    def get_network_timeline(self) -> list[TimelineEvent]:
        """Return only network events."""
        return [e for e in self._events if e.event_type == "network"]

    def export_json(self, output_path: str | Path) -> Path:
        """Export the full timeline to a JSON file."""
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "dump_path": str(self.dump_path),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "total_events": len(self._events),
            "suspicious_events": len(self.get_suspicious_events()),
            "events": [asdict(e) for e in self._events],
        }
        path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
        logger.info("Memory timeline exported: {} ({} events)", path, len(self._events))
        return path

    def summary(self) -> dict:
        """Return a summary of the timeline."""
        return {
            "total_events": len(self._events),
            "process_events": len(self.get_process_timeline()),
            "network_events": len(self.get_network_timeline()),
            "suspicious_events": len(self.get_suspicious_events()),
            "time_range": {
                "start": self._events[0].timestamp if self._events else "",
                "end": self._events[-1].timestamp if self._events else "",
            },
        }


def _normalize_ts(ts: str) -> str:
    """Normalize various timestamp formats to ISO 8601."""
    if not ts or ts in ("N/A", "0"):
        return ""
    # Already ISO
    if "T" in ts or "Z" in ts:
        return ts
    # Volatility format: "2026-05-22 14:42:41 UTC+0000"
    try:
        ts_clean = ts.replace(" UTC+0000", "").replace(" UTC", "").strip()
        dt = datetime.strptime(ts_clean, "%Y-%m-%d %H:%M:%S")
        return dt.replace(tzinfo=timezone.utc).isoformat()
    except Exception:
        return ts
