"""
Windows Event Log Collector
============================
Parses EVTX event logs for:
- Login / logoff activity (Security 4624, 4625, 4634)
- PowerShell execution (4103, 4104)
- Process creation (4688)
- Service installs (7045)
- RDP sessions (4778, 4779)
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, field

from loguru import logger


@dataclass
class EventLogEntry:
    """A single parsed Windows event log entry."""

    event_id: int
    time_created: str
    level: str
    provider: str
    message: str
    channel: str = ""
    computer: str = ""
    user: str = ""
    extra: dict = field(default_factory=dict)

    def __str__(self) -> str:
        return f"[{self.time_created}] EventID={self.event_id} | {self.provider} | {self.message[:120]}"


def _ps(cmd: str, timeout: int = 30) -> str | None:
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", cmd],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.stdout.strip() if result.returncode == 0 else None
    except Exception as exc:
        logger.error("Event log PS error: {}", exc)
        return None


def _query_event_log(
    log_name: str,
    event_ids: list[int],
    max_events: int = 500,
) -> list[EventLogEntry]:
    """Query a Windows event log channel for specific event IDs."""
    entries: list[EventLogEntry] = []

    id_filter = " -or ".join(f"$_.Id -eq {eid}" for eid in event_ids)
    cmd = (
        f"Get-WinEvent -LogName '{log_name}' -MaxEvents {max_events} "
        f"-ErrorAction SilentlyContinue | "
        f"Where-Object {{ {id_filter} }} | "
        "Select-Object Id,TimeCreated,LevelDisplayName,ProviderName,Message,MachineName | "
        "ConvertTo-Json -Depth 2"
    )
    out = _ps(cmd, timeout=30)
    if not out:
        return entries

    try:
        raw = json.loads(out)
        if isinstance(raw, dict):
            raw = [raw]
        for e in raw:
            entries.append(
                EventLogEntry(
                    event_id=int(e.get("Id", 0)),
                    time_created=str(e.get("TimeCreated", "")),
                    level=e.get("LevelDisplayName", ""),
                    provider=e.get("ProviderName", ""),
                    message=(e.get("Message") or "")[:500],
                    channel=log_name,
                    computer=e.get("MachineName", ""),
                )
            )
    except Exception as exc:
        logger.debug("Event log parse error ({}): {}", log_name, exc)

    return entries


def collect_login_activity(max_events: int = 500) -> list[EventLogEntry]:
    """
    Collect login/logoff events from Security log.
    EventIDs: 4624 (logon), 4625 (failed logon), 4634 (logoff), 4648 (explicit creds)
    """
    entries = _query_event_log(
        "Security",
        [4624, 4625, 4634, 4648, 4672],
        max_events,
    )
    logger.info("Login activity: collected {} events", len(entries))
    return entries


def collect_powershell_activity(max_events: int = 300) -> list[EventLogEntry]:
    """
    Collect PowerShell script block and module logging events.
    EventIDs: 4103 (module logging), 4104 (script block)
    """
    entries = _query_event_log(
        "Microsoft-Windows-PowerShell/Operational",
        [4103, 4104, 4105, 4106],
        max_events,
    )
    logger.info("PowerShell activity: collected {} events", len(entries))
    return entries


def collect_process_creation(max_events: int = 500) -> list[EventLogEntry]:
    """
    Collect process creation events (requires audit policy enabled).
    EventID: 4688
    """
    entries = _query_event_log("Security", [4688, 4689], max_events)
    logger.info("Process creation: collected {} events", len(entries))
    return entries


def collect_service_installs(max_events: int = 200) -> list[EventLogEntry]:
    """
    Collect service installation events — common malware persistence vector.
    EventID: 7045 (new service installed)
    """
    entries = _query_event_log("System", [7045, 7034, 7036], max_events)
    logger.info("Service installs: collected {} events", len(entries))
    return entries


def collect_rdp_activity(max_events: int = 200) -> list[EventLogEntry]:
    """
    Collect RDP session events.
    EventIDs: 4778 (session reconnected), 4779 (session disconnected)
    """
    entries = _query_event_log("Security", [4778, 4779], max_events)
    logger.info("RDP activity: collected {} events", len(entries))
    return entries


def collect_all_event_logs(max_events: int = 500) -> dict[str, list[EventLogEntry]]:
    """Run all event log collectors and return grouped results."""
    logger.info("Starting event log collection")
    return {
        "login_activity": collect_login_activity(max_events),
        "powershell_activity": collect_powershell_activity(max_events),
        "process_creation": collect_process_creation(max_events),
        "service_installs": collect_service_installs(max_events),
        "rdp_activity": collect_rdp_activity(max_events),
    }
