# automation/auto_linux.py
import csv
import io
import subprocess
from pathlib import Path

from loguru import logger


class LinuxAutomation:
    """Collect forensic artifacts from a live Linux system."""

    # ------------------------------------------------------------------
    # Logs
    # ------------------------------------------------------------------

    def collect_logs(self, log_path: str = "/var/log/syslog") -> str | None:
        """
        Read a system log file.

        Args:
            log_path: Path to the log file (default: /var/log/syslog).

        Returns:
            Log content as a string, or None on error.
        """
        try:
            content = Path(log_path).read_text(errors="replace")
            logger.info(f"Collected logs from '{log_path}' ({len(content)} bytes)")
            return content
        except Exception as e:
            logger.error(f"Failed to read logs from '{log_path}': {e}")
            return None

    # ------------------------------------------------------------------
    # Processes
    # ------------------------------------------------------------------

    def list_running_processes(self) -> list[dict]:
        """
        Return a list of running processes via `ps aux`.

        Returns:
            List of dicts with keys: user, pid, cpu, mem, command.
        """
        try:
            result = subprocess.run(
                ["ps", "aux"],
                capture_output=True, text=True, check=True,
            )
            lines = result.stdout.strip().splitlines()
            if len(lines) < 2:
                return []

            processes: list[dict] = []
            for line in lines[1:]:
                parts = line.split(None, 10)
                if len(parts) >= 11:
                    processes.append({
                        "user":    parts[0],
                        "pid":     parts[1],
                        "cpu":     parts[2],
                        "mem":     parts[3],
                        "command": parts[10],
                    })

            logger.info(f"Collected {len(processes)} running processes.")
            return processes

        except Exception as e:
            logger.error(f"Failed to list running processes: {e}")
            return []

    # ------------------------------------------------------------------
    # Network
    # ------------------------------------------------------------------

    def scan_network_connections(self) -> str | None:
        """
        Return active network connections via `ss -tuna`.

        Returns:
            Raw output string, or None on error.
        """
        try:
            result = subprocess.run(
                ["ss", "-tuna"],
                capture_output=True, text=True, check=True,
            )
            logger.info("Collected network connections.")
            return result.stdout
        except Exception as e:
            logger.error(f"Failed to scan network connections: {e}")
            return None

    # ------------------------------------------------------------------
    # Persistence / scheduled tasks
    # ------------------------------------------------------------------

    def collect_cron_jobs(self) -> dict:
        """
        Collect cron job entries from /etc/crontab and /var/spool/cron/.

        Returns:
            Dict with keys 'system_crontab' (str) and 'user_crontabs' (dict).
        """
        output: dict = {"system_crontab": None, "user_crontabs": {}}

        # System crontab
        try:
            output["system_crontab"] = Path("/etc/crontab").read_text(errors="replace")
            logger.info("Collected /etc/crontab")
        except Exception as e:
            logger.warning(f"Could not read /etc/crontab: {e}")

        # Per-user crontabs
        spool = Path("/var/spool/cron/crontabs")
        if spool.exists():
            for entry in spool.iterdir():
                if entry.is_file():
                    try:
                        output["user_crontabs"][entry.name] = entry.read_text(errors="replace")
                        logger.info(f"Collected crontab for user '{entry.name}'")
                    except Exception as e:
                        logger.warning(f"Could not read crontab for '{entry.name}': {e}")

        return output

    def collect_bash_history(self, user_home: str) -> str | None:
        """
        Read the .bash_history file for a given user home directory.

        Args:
            user_home: Path to the user's home directory.

        Returns:
            History content as a string, or None on error.
        """
        history_path = Path(user_home) / ".bash_history"
        try:
            content = history_path.read_text(errors="replace")
            logger.info(f"Collected bash history from '{history_path}'")
            return content
        except Exception as e:
            logger.error(f"Failed to read bash history from '{history_path}': {e}")
            return None
