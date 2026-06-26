"""
Linux Artifact Collector
=========================
Collects forensic artifacts from a live Linux system:
- Bash / shell history
- SSH keys and known_hosts
- Crontabs (user + system)
- Syslog / auth.log
- Journalctl logs
- Docker artifacts
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path

from loguru import logger


@dataclass
class ShellHistoryEntry:
    user: str
    shell: str
    command: str
    line_number: int = 0
    source_file: str = ""


@dataclass
class SSHArtifact:
    user: str
    artifact_type: str  # private_key | public_key | known_hosts | authorized_keys
    path: str
    content_preview: str = ""
    permissions: str = ""


@dataclass
class CrontabEntry:
    user: str
    schedule: str
    command: str
    source: str = ""


@dataclass
class LogEntry:
    source: str
    line: str
    timestamp: str = ""


def _run(cmd: list[str], timeout: int = 15) -> str | None:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.stdout if result.returncode == 0 else None
    except FileNotFoundError:
        logger.debug("Command not found: {}", cmd[0])
        return None
    except Exception as exc:
        logger.error("Command error: {}", exc)
        return None


def _get_users() -> list[tuple[str, Path]]:
    """Return list of (username, home_dir) for real users."""
    users = []
    try:
        passwd = Path("/etc/passwd").read_text()
        for line in passwd.splitlines():
            parts = line.split(":")
            if len(parts) < 7:
                continue
            username = parts[0]
            uid = int(parts[2])
            home = Path(parts[5])
            shell = parts[6]
            # Only real users (uid >= 1000 or root) with valid home
            if (uid >= 1000 or uid == 0) and home.exists() and "nologin" not in shell:
                users.append((username, home))
    except Exception as exc:
        logger.debug("Could not read /etc/passwd: {}", exc)
    return users


# ── Shell history ─────────────────────────────────────────────────────────────


def collect_bash_history() -> list[ShellHistoryEntry]:
    """Collect bash/zsh/fish history from all user home directories."""
    entries: list[ShellHistoryEntry] = []
    history_files = [
        (".bash_history", "bash"),
        (".zsh_history", "zsh"),
        (".sh_history", "sh"),
        (".local/share/fish/fish_history", "fish"),
    ]
    for username, home in _get_users():
        for filename, shell in history_files:
            hist_path = home / filename
            if not hist_path.exists():
                continue
            try:
                lines = hist_path.read_text(errors="replace").splitlines()
                for i, line in enumerate(lines):
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    # zsh history format: ": timestamp:0;command"
                    if shell == "zsh" and line.startswith(":"):
                        parts = line.split(";", 1)
                        line = parts[1] if len(parts) > 1 else line
                    entries.append(
                        ShellHistoryEntry(
                            user=username,
                            shell=shell,
                            command=line[:500],
                            line_number=i + 1,
                            source_file=str(hist_path),
                        )
                    )
            except Exception as exc:
                logger.debug("History read error {}: {}", hist_path, exc)

    logger.info("Shell history: collected {} command(s)", len(entries))
    return entries


# ── SSH artifacts ─────────────────────────────────────────────────────────────


def collect_ssh_artifacts() -> list[SSHArtifact]:
    """Collect SSH keys, known_hosts, and authorized_keys from all users."""
    artifacts: list[SSHArtifact] = []
    key_patterns = [
        ("id_rsa", "private_key"),
        ("id_ed25519", "private_key"),
        ("id_ecdsa", "private_key"),
        ("id_dsa", "private_key"),
        ("id_rsa.pub", "public_key"),
        ("id_ed25519.pub", "public_key"),
        ("id_ecdsa.pub", "public_key"),
        ("known_hosts", "known_hosts"),
        ("authorized_keys", "authorized_keys"),
    ]
    for username, home in _get_users():
        ssh_dir = home / ".ssh"
        if not ssh_dir.exists():
            continue
        for filename, artifact_type in key_patterns:
            key_path = ssh_dir / filename
            if not key_path.exists():
                continue
            try:
                stat = key_path.stat()
                perms = oct(stat.st_mode)[-3:]
                content = key_path.read_text(errors="replace")
                preview = content[:200].replace("\n", " ")
                artifacts.append(
                    SSHArtifact(
                        user=username,
                        artifact_type=artifact_type,
                        path=str(key_path),
                        content_preview=preview,
                        permissions=perms,
                    )
                )
            except Exception as exc:
                logger.debug("SSH artifact read error {}: {}", key_path, exc)

    logger.info("SSH artifacts: collected {} item(s)", len(artifacts))
    return artifacts


# ── Crontabs ──────────────────────────────────────────────────────────────────


def collect_crontabs() -> list[CrontabEntry]:
    """Collect crontab entries from users and system cron directories."""
    entries: list[CrontabEntry] = []

    # User crontabs via crontab -l
    for username, _ in _get_users():
        out = _run(["crontab", "-l", "-u", username])
        if not out:
            continue
        for line in out.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(None, 5)
            if len(parts) >= 6:
                entries.append(
                    CrontabEntry(
                        user=username,
                        schedule=" ".join(parts[:5]),
                        command=parts[5],
                        source=f"crontab -l -u {username}",
                    )
                )

    # System cron directories
    cron_dirs = [
        Path("/etc/cron.d"),
        Path("/etc/cron.daily"),
        Path("/etc/cron.hourly"),
        Path("/etc/cron.weekly"),
        Path("/etc/cron.monthly"),
    ]
    for cron_dir in cron_dirs:
        if not cron_dir.exists():
            continue
        for cron_file in cron_dir.iterdir():
            if not cron_file.is_file():
                continue
            try:
                for line in cron_file.read_text(errors="replace").splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split(None, 6)
                    if len(parts) >= 7:
                        entries.append(
                            CrontabEntry(
                                user=parts[5],
                                schedule=" ".join(parts[:5]),
                                command=parts[6],
                                source=str(cron_file),
                            )
                        )
            except Exception as exc:
                logger.debug("Cron file read error {}: {}", cron_file, exc)

    # /etc/crontab
    etc_crontab = Path("/etc/crontab")
    if etc_crontab.exists():
        try:
            for line in etc_crontab.read_text(errors="replace").splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(None, 6)
                if len(parts) >= 7:
                    entries.append(
                        CrontabEntry(
                            user=parts[5],
                            schedule=" ".join(parts[:5]),
                            command=parts[6],
                            source="/etc/crontab",
                        )
                    )
        except Exception as exc:
            logger.debug("crontab read error: {}", exc)

    logger.info("Crontabs: collected {} entry/entries", len(entries))
    return entries


# ── System logs ───────────────────────────────────────────────────────────────


def collect_syslog(max_lines: int = 1000) -> list[LogEntry]:
    """Collect recent syslog entries."""
    entries: list[LogEntry] = []
    log_paths = [Path("/var/log/syslog"), Path("/var/log/messages")]
    for log_path in log_paths:
        if not log_path.exists():
            continue
        try:
            lines = log_path.read_text(errors="replace").splitlines()
            for line in lines[-max_lines:]:
                if line.strip():
                    entries.append(LogEntry(source=str(log_path), line=line.strip()))
        except PermissionError:
            logger.warning("Permission denied reading {}", log_path)
        except Exception as exc:
            logger.debug("Syslog read error: {}", exc)
        break  # Use first found
    logger.info("Syslog: collected {} line(s)", len(entries))
    return entries


def collect_auth_log(max_lines: int = 1000) -> list[LogEntry]:
    """Collect authentication log entries (login attempts, sudo, etc.)."""
    entries: list[LogEntry] = []
    log_paths = [Path("/var/log/auth.log"), Path("/var/log/secure")]
    for log_path in log_paths:
        if not log_path.exists():
            continue
        try:
            lines = log_path.read_text(errors="replace").splitlines()
            for line in lines[-max_lines:]:
                if line.strip():
                    entries.append(LogEntry(source=str(log_path), line=line.strip()))
        except PermissionError:
            logger.warning("Permission denied reading {}", log_path)
        except Exception as exc:
            logger.debug("Auth log read error: {}", exc)
        break
    logger.info("Auth log: collected {} line(s)", len(entries))
    return entries


def collect_journalctl(max_lines: int = 1000, unit: str | None = None) -> list[LogEntry]:
    """Collect systemd journal entries via journalctl."""
    entries: list[LogEntry] = []
    cmd = ["journalctl", "-n", str(max_lines), "--no-pager", "-o", "short-iso"]
    if unit:
        cmd += ["-u", unit]
    out = _run(cmd, timeout=20)
    if not out:
        return entries
    for line in out.splitlines():
        if line.strip():
            entries.append(LogEntry(source="journalctl", line=line.strip()))
    logger.info("Journalctl: collected {} line(s)", len(entries))
    return entries


# ── Docker artifacts ──────────────────────────────────────────────────────────


def collect_docker_artifacts() -> dict:
    """Collect Docker container, image, and volume metadata."""
    result: dict = {"containers": [], "images": [], "volumes": [], "networks": []}

    for key, cmd in [
        ("containers", ["docker", "ps", "-a", "--format", "{{json .}}"]),
        ("images", ["docker", "images", "--format", "{{json .}}"]),
        ("volumes", ["docker", "volume", "ls", "--format", "{{json .}}"]),
        ("networks", ["docker", "network", "ls", "--format", "{{json .}}"]),
    ]:
        out = _run(cmd)
        if not out:
            continue
        import json

        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                result[key].append(json.loads(line))
            except Exception:
                result[key].append({"raw": line})

    logger.info(
        "Docker: {} containers, {} images, {} volumes",
        len(result["containers"]),
        len(result["images"]),
        len(result["volumes"]),
    )
    return result


def collect_all_artifacts() -> dict:
    """Run all Linux artifact collectors and return grouped results."""
    logger.info("Starting Linux artifact collection")
    return {
        "bash_history": [vars(e) for e in collect_bash_history()],
        "ssh_artifacts": [vars(e) for e in collect_ssh_artifacts()],
        "crontabs": [vars(e) for e in collect_crontabs()],
        "syslog": [vars(e) for e in collect_syslog()],
        "auth_log": [vars(e) for e in collect_auth_log()],
        "journalctl": [vars(e) for e in collect_journalctl()],
        "docker": collect_docker_artifacts(),
    }
