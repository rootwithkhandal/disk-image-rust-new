# automation/auto_win.py
import csv
import io
import os
import subprocess
from pathlib import Path

from loguru import logger


class WindowsAutomation:
    """Collect forensic artifacts from a live Windows system."""

    # ------------------------------------------------------------------
    # Event logs
    # ------------------------------------------------------------------

    def collect_event_logs(self, log_name: str = "System", count: int = 100) -> str | None:
        """
        Collect Windows Event Log entries via wevtutil.

        Args:
            log_name: Event log channel (System, Application, Security, etc.).
            count:    Maximum number of events to retrieve.

        Returns:
            Raw text output, or None on error.
        """
        try:
            result = subprocess.run(
                [
                    "wevtutil", "qe", log_name,
                    f"/c:{count}", "/rd:true", "/f:text",
                ],
                capture_output=True, text=True, check=True,
            )
            logger.info(f"Collected {log_name} event log ({count} entries).")
            return result.stdout
        except Exception as e:
            logger.error(f"Failed to collect event logs: {e}")
            return None

    # ------------------------------------------------------------------
    # Network
    # ------------------------------------------------------------------

    def list_network_connections(self) -> str | None:
        """
        Return active network connections via netstat.

        Returns:
            Raw netstat output, or None on error.
        """
        try:
            result = subprocess.run(
                ["netstat", "-ano"],
                capture_output=True, text=True, check=True,
            )
            logger.info("Collected network connections.")
            return result.stdout
        except Exception as e:
            logger.error(f"Failed to list network connections: {e}")
            return None

    # ------------------------------------------------------------------
    # Processes
    # ------------------------------------------------------------------

    def list_running_processes(self) -> list[dict]:
        """
        Return running processes via `tasklist /fo csv`.

        Returns:
            List of dicts with keys: image_name, pid, session_name,
            session_num, mem_usage.
        """
        try:
            result = subprocess.run(
                ["tasklist", "/fo", "csv"],
                capture_output=True, text=True, check=True,
            )
            reader = csv.DictReader(io.StringIO(result.stdout))
            processes = [
                {
                    "image_name":   row.get("Image Name", ""),
                    "pid":          row.get("PID", ""),
                    "session_name": row.get("Session Name", ""),
                    "session_num":  row.get("Session#", ""),
                    "mem_usage":    row.get("Mem Usage", ""),
                }
                for row in reader
            ]
            logger.info(f"Collected {len(processes)} running processes.")
            return processes
        except Exception as e:
            logger.error(f"Failed to list running processes: {e}")
            return []

    # ------------------------------------------------------------------
    # Persistence / startup
    # ------------------------------------------------------------------

    def list_startup_items(self) -> str | None:
        """
        List startup items via `wmic startup list full`.

        Returns:
            Raw wmic output, or None on error.
        """
        try:
            result = subprocess.run(
                ["wmic", "startup", "list", "full"],
                capture_output=True, text=True, check=True,
            )
            logger.info("Collected startup items.")
            return result.stdout
        except Exception as e:
            logger.error(f"Failed to list startup items: {e}")
            return None

    def collect_prefetch_list(self) -> list[dict]:
        """
        List files in the Windows Prefetch directory.

        Returns:
            List of dicts with keys: name, size, last_modified.
        """
        prefetch_dir = Path(r"C:\Windows\Prefetch")
        results: list[dict] = []

        if not prefetch_dir.exists():
            logger.warning("Prefetch directory not found or not accessible.")
            return results

        try:
            for entry in prefetch_dir.iterdir():
                if entry.is_file() and entry.suffix.lower() == ".pf":
                    stat = entry.stat()
                    results.append({
                        "name":          entry.name,
                        "size":          stat.st_size,
                        "last_modified": stat.st_mtime,
                    })

            logger.info(f"Collected {len(results)} prefetch entries.")
        except PermissionError:
            logger.error("Permission denied reading Prefetch directory.")
        except Exception as e:
            logger.error(f"Failed to collect prefetch list: {e}")

        return results
