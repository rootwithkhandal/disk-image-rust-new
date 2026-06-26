"""
Windows Live Response
======================
Captures volatile system state from a live Windows system:
- Running processes
- Network sockets and connections
- ARP table
- DNS cache
- Scheduled tasks
- Loaded drivers
- Logged-on users
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass

from loguru import logger


@dataclass
class ProcessEntry:
    pid: int
    name: str
    path: str = ""
    command_line: str = ""
    parent_pid: int = 0
    user: str = ""
    cpu_percent: float = 0.0
    memory_mb: float = 0.0
    start_time: str = ""
    hash_sha256: str = ""


@dataclass
class NetworkConnection:
    protocol: str
    local_address: str
    local_port: int
    remote_address: str
    remote_port: int
    state: str = ""
    pid: int = 0
    process_name: str = ""


@dataclass
class ScheduledTask:
    name: str
    path: str
    state: str = ""
    last_run: str = ""
    next_run: str = ""
    run_as: str = ""
    actions: str = ""


def _ps(cmd: str, timeout: int = 20) -> str | None:
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", cmd],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.stdout.strip() if result.returncode == 0 else None
    except Exception as exc:
        logger.error("Live response PS error: {}", exc)
        return None


def enumerate_processes() -> list[ProcessEntry]:
    """Enumerate all running processes with path, user, and memory."""
    processes: list[ProcessEntry] = []
    out = _ps(
        "Get-WmiObject Win32_Process | "
        "Select-Object ProcessId,Name,ExecutablePath,CommandLine,ParentProcessId,"
        "WorkingSetSize,CreationDate | "
        "ConvertTo-Json -Depth 2"
    )
    if not out:
        # Fallback to Get-Process
        out = _ps(
            "Get-Process | Select-Object Id,Name,Path,CPU,WorkingSet,StartTime | "
            "ConvertTo-Json -Depth 2"
        )

    if not out:
        return processes

    try:
        raw = json.loads(out)
        if isinstance(raw, dict):
            raw = [raw]
        for p in raw:
            pid = int(p.get("ProcessId") or p.get("Id") or 0)
            mem_bytes = int(p.get("WorkingSetSize") or p.get("WorkingSet") or 0)
            processes.append(
                ProcessEntry(
                    pid=pid,
                    name=p.get("Name", ""),
                    path=p.get("ExecutablePath") or p.get("Path") or "",
                    command_line=p.get("CommandLine") or "",
                    parent_pid=int(p.get("ParentProcessId") or 0),
                    memory_mb=round(mem_bytes / (1024**2), 2),
                    start_time=str(p.get("CreationDate") or p.get("StartTime") or ""),
                )
            )
    except Exception as exc:
        logger.error("Process enumeration parse error: {}", exc)

    logger.info("Live response: {} running process(es)", len(processes))
    return processes


def capture_network_connections() -> list[NetworkConnection]:
    """Capture active TCP/UDP connections with owning process."""
    connections: list[NetworkConnection] = []
    out = _ps(
        "Get-NetTCPConnection -ErrorAction SilentlyContinue | "
        "Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess | "
        "ConvertTo-Json -Depth 2"
    )
    if out:
        try:
            raw = json.loads(out)
            if isinstance(raw, dict):
                raw = [raw]
            for c in raw:
                connections.append(
                    NetworkConnection(
                        protocol="TCP",
                        local_address=c.get("LocalAddress", ""),
                        local_port=int(c.get("LocalPort") or 0),
                        remote_address=c.get("RemoteAddress", ""),
                        remote_port=int(c.get("RemotePort") or 0),
                        state=c.get("State", ""),
                        pid=int(c.get("OwningProcess") or 0),
                    )
                )
        except Exception as exc:
            logger.debug("TCP connection parse error: {}", exc)

    # UDP
    out_udp = _ps(
        "Get-NetUDPEndpoint -ErrorAction SilentlyContinue | "
        "Select-Object LocalAddress,LocalPort,OwningProcess | "
        "ConvertTo-Json -Depth 2"
    )
    if out_udp:
        try:
            raw = json.loads(out_udp)
            if isinstance(raw, dict):
                raw = [raw]
            for c in raw:
                connections.append(
                    NetworkConnection(
                        protocol="UDP",
                        local_address=c.get("LocalAddress", ""),
                        local_port=int(c.get("LocalPort") or 0),
                        remote_address="",
                        remote_port=0,
                        pid=int(c.get("OwningProcess") or 0),
                    )
                )
        except Exception as exc:
            logger.debug("UDP endpoint parse error: {}", exc)

    logger.info("Network connections: {} captured", len(connections))
    return connections


def capture_arp_table() -> list[dict]:
    """Capture the ARP cache (IP-to-MAC mappings)."""
    out = _ps(
        "Get-NetNeighbor -ErrorAction SilentlyContinue | "
        "Select-Object IPAddress,LinkLayerAddress,State,InterfaceAlias | "
        "ConvertTo-Json -Depth 2"
    )
    if not out:
        return []
    try:
        raw = json.loads(out)
        if isinstance(raw, dict):
            raw = [raw]
        logger.info("ARP table: {} entries", len(raw))
        return raw
    except Exception as exc:
        logger.debug("ARP parse error: {}", exc)
        return []


def capture_dns_cache() -> list[dict]:
    """Capture the DNS client cache."""
    out = _ps(
        "Get-DnsClientCache -ErrorAction SilentlyContinue | "
        "Select-Object Entry,RecordName,RecordType,Status,DataLength,Data | "
        "ConvertTo-Json -Depth 2"
    )
    if not out:
        return []
    try:
        raw = json.loads(out)
        if isinstance(raw, dict):
            raw = [raw]
        logger.info("DNS cache: {} entries", len(raw))
        return raw
    except Exception as exc:
        logger.debug("DNS cache parse error: {}", exc)
        return []


def collect_scheduled_tasks() -> list[ScheduledTask]:
    """Enumerate scheduled tasks — common persistence mechanism."""
    tasks: list[ScheduledTask] = []
    out = _ps(
        "Get-ScheduledTask -ErrorAction SilentlyContinue | "
        "Select-Object TaskName,TaskPath,State | "
        "ConvertTo-Json -Depth 2"
    )
    if not out:
        return tasks
    try:
        raw = json.loads(out)
        if isinstance(raw, dict):
            raw = [raw]
        for t in raw:
            tasks.append(
                ScheduledTask(
                    name=t.get("TaskName", ""),
                    path=t.get("TaskPath", ""),
                    state=str(t.get("State", "")),
                )
            )
    except Exception as exc:
        logger.debug("Scheduled task parse error: {}", exc)

    logger.info("Scheduled tasks: {} found", len(tasks))
    return tasks


def collect_all_live_response() -> dict:
    """Run all live response collectors and return grouped results."""
    logger.info("Starting Windows live response collection")
    return {
        "processes": [vars(p) for p in enumerate_processes()],
        "network_connections": [vars(c) for c in capture_network_connections()],
        "arp_table": capture_arp_table(),
        "dns_cache": capture_dns_cache(),
        "scheduled_tasks": [vars(t) for t in collect_scheduled_tasks()],
    }
