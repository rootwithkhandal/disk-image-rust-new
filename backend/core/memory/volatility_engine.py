"""
Volatility3 Integration Engine
================================
Wraps Volatility3 for memory forensics analysis.
Supports process analysis, DLL/module extraction,
network connections, credential artifacts, and malware detection.

Usage:
    from core.memory.volatility_engine import VolatilityEngine

    engine = VolatilityEngine(dump_path="/evidence/memory.raw")
    processes = engine.list_processes()
    connections = engine.list_connections()
    creds = engine.find_credentials()
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from loguru import logger


@dataclass
class MemoryProcess:
    pid: int
    ppid: int
    name: str
    offset: str = ""
    create_time: str = ""
    exit_time: str = ""
    threads: int = 0
    handles: int = 0
    session_id: int = 0
    wow64: bool = False
    cmdline: str = ""
    path: str = ""
    is_suspicious: bool = False
    suspicious_reasons: list[str] = field(default_factory=list)


@dataclass
class MemoryDLL:
    pid: int
    process_name: str
    base: str = ""
    size: int = 0
    name: str = ""
    path: str = ""
    load_time: str = ""


@dataclass
class MemoryConnection:
    pid: int
    process_name: str = ""
    protocol: str = ""
    local_addr: str = ""
    local_port: int = 0
    remote_addr: str = ""
    remote_port: int = 0
    state: str = ""
    create_time: str = ""


@dataclass
class CredentialArtifact:
    artifact_type: str  # lsass_hash | cached_cred | dpapi_blob | vault_entry
    username: str = ""
    domain: str = ""
    lm_hash: str = ""
    nt_hash: str = ""
    plaintext: str = ""
    source: str = ""


@dataclass
class VolatilityResult:
    success: bool
    plugin: str
    dump_path: str
    data: list[dict] = field(default_factory=list)
    error: str = ""
    row_count: int = 0


class VolatilityEngine:
    """
    Wraps Volatility3 CLI for memory forensics analysis.
    Uses plain-text renderer for maximum compatibility — the JSON renderer
    aborts on partial symbol errors (e.g. _MM_SESSION_SPACE on Win11 24H2),
    whereas the text renderer emits all available rows before the warning.
    """

    def __init__(self, dump_path: str | Path) -> None:
        self.dump_path = Path(dump_path)
        self._vol_cmd = self._find_volatility()

    def _find_volatility(self) -> list[str] | None:
        """Locate Volatility3 executable."""
        for candidate in ["vol3", "vol", "volatility3"]:
            if shutil.which(candidate):
                return [candidate]
        # Try the venv's vol.exe directly
        import sys
        from pathlib import Path as _P
        venv_vol = _P(sys.executable).parent / "vol.exe"
        if venv_vol.exists():
            return [str(venv_vol)]
        logger.warning(
            "Volatility3 not found. Install with: pip install volatility3"
        )
        return None

    def _run_plugin(self, plugin: str, extra_args: list[str] | None = None) -> VolatilityResult:
        """
        Run a Volatility3 plugin using the plain-text renderer.
        Parses the tab-separated table output into a list of dicts.
        """
        if not self._vol_cmd:
            return VolatilityResult(
                success=False, plugin=plugin, dump_path=str(self.dump_path),
                error="Volatility3 not installed",
            )

        if not self.dump_path.exists():
            return VolatilityResult(
                success=False, plugin=plugin, dump_path=str(self.dump_path),
                error=f"Memory dump not found: {self.dump_path}",
            )

        # Use plain text renderer + -q (quiet: suppress progress bars).
        # --renderer json aborts on _MM_SESSION_SPACE symbol errors before writing output.
        # Plain text renderer writes all available rows first, then the warning.
        cmd = self._vol_cmd + ["-f", str(self.dump_path), "-q", plugin] + (extra_args or [])

        logger.info("Running Volatility3 plugin: {} on {}", plugin, self.dump_path.name)

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=1800,  # 30 min for large dumps
            )

            stdout = result.stdout.strip()

            if not stdout:
                error = result.stderr.strip()[:500] or "No output from Volatility3"
                logger.error("Volatility3 plugin {} failed: {}", plugin, error)
                return VolatilityResult(
                    success=False, plugin=plugin, dump_path=str(self.dump_path),
                    error=error,
                )

            rows = _parse_vol_text(stdout)
            logger.info("Plugin {} returned {} row(s)", plugin, len(rows))
            return VolatilityResult(
                success=True, plugin=plugin, dump_path=str(self.dump_path),
                data=rows, row_count=len(rows),
            )

        except subprocess.TimeoutExpired:
            return VolatilityResult(
                success=False, plugin=plugin, dump_path=str(self.dump_path),
                error="Plugin timed out after 30 minutes",
            )
        except Exception as exc:
            logger.error("Volatility3 error: {}", exc)
            return VolatilityResult(
                success=False, plugin=plugin, dump_path=str(self.dump_path),
                error=str(exc),
            )

    # ── Process analysis ──────────────────────────────────────────────────────

    def list_processes(self) -> VolatilityResult:
        """List all processes from memory. Detects suspicious processes."""
        for plugin in ["windows.pslist.PsList", "linux.pslist.PsList"]:
            result = self._run_plugin(plugin)
            if result.success:
                result.data = [_enrich_process(row) for row in result.data]
                return result
        return result

    def process_tree(self) -> VolatilityResult:
        """Build process parent-child tree."""
        for plugin in ["windows.pstree.PsTree", "linux.pstree.PsTree"]:
            result = self._run_plugin(plugin)
            if result.success:
                return result
        return result

    def dump_process(self, pid: int, output_dir: str | Path) -> VolatilityResult:
        """Dump a specific process memory to disk."""
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        return self._run_plugin(
            "windows.dumpfiles.DumpFiles",
            ["--pid", str(pid), "--output-dir", str(out)],
        )

    # ── DLL / module analysis ─────────────────────────────────────────────────

    def list_dlls(self, pid: int | None = None) -> VolatilityResult:
        """List loaded DLLs for all processes or a specific PID."""
        args = ["--pid", str(pid)] if pid else []
        for plugin in ["windows.dlllist.DllList", "linux.lsmod.Lsmod"]:
            result = self._run_plugin(plugin, args)
            if result.success:
                return result
        return result

    def find_injected_code(self) -> VolatilityResult:
        """Detect injected code / hollowed processes."""
        return self._run_plugin("windows.malfind.Malfind")

    # ── Network connections ───────────────────────────────────────────────────

    def list_connections(self) -> VolatilityResult:
        """List active and closed network connections from memory."""
        for plugin in ["windows.netstat.NetStat", "windows.netscan.NetScan", "linux.netstat.NetStat"]:
            result = self._run_plugin(plugin)
            if result.success:
                return result
        return result

    # ── Credential artifacts ──────────────────────────────────────────────────

    def find_credentials(self) -> VolatilityResult:
        """Extract credential artifacts from LSASS memory."""
        return self._run_plugin("windows.lsadump.Lsadump")

    def find_hashes(self) -> VolatilityResult:
        """Extract NTLM hashes from memory."""
        return self._run_plugin("windows.hashdump.Hashdump")

    # ── Malware detection ─────────────────────────────────────────────────────

    def detect_malware(self) -> VolatilityResult:
        """Detect injected shellcode, PE headers in unexpected regions."""
        return self._run_plugin("windows.malfind.Malfind")

    def check_ssdt(self) -> VolatilityResult:
        """Check SSDT for hooks (rootkit detection)."""
        return self._run_plugin("windows.ssdt.SSDT")

    # ── Timeline ──────────────────────────────────────────────────────────────

    def memory_timeline(self) -> VolatilityResult:
        """Generate a memory-based timeline of process creation events."""
        return self._run_plugin("timeliner.Timeliner")

    # ── Full analysis ─────────────────────────────────────────────────────────

    def full_analysis(self) -> dict[str, VolatilityResult]:
        """Run a comprehensive memory analysis suite."""
        logger.info("Starting full memory analysis on {}", self.dump_path.name)
        return {
            "processes": self.list_processes(),
            "process_tree": self.process_tree(),
            "dlls": self.list_dlls(),
            "connections": self.list_connections(),
            "malfind": self.detect_malware(),
            "hashes": self.find_hashes(),
        }


# ── Text output parser ────────────────────────────────────────────────────────

def _parse_vol_text(stdout: str) -> list[dict]:
    """
    Parse Volatility3 plain-text tabular output into a list of dicts.

    Volatility3 text format:
        Volatility 3 Framework 2.7.0
        PID\tPPID\tImageFileName\t...   <- header line
        4\t0\tSystem\t...               <- data lines
        ...
        Volatility experienced...       <- optional trailing warning
    """
    rows: list[dict] = []
    header: list[str] = []

    for line in stdout.splitlines():
        line = line.rstrip()

        # Skip framework version line and blank lines
        if not line or line.startswith("Volatility 3") or line.startswith("Progress:"):
            continue

        # Skip warning/error lines that appear after the data
        if line.startswith("Volatility experienced") or line.startswith("symbol_table") \
                or line.startswith("*") or line.startswith("Unable to validate") \
                or line.startswith("No further"):
            break  # data is done

        parts = line.split("\t")

        if not header:
            # First content line is the header
            header = [p.strip() for p in parts]
            continue

        if len(parts) < len(header):
            # Pad short rows
            parts += [""] * (len(header) - len(parts))

        row = {header[i]: parts[i].strip() for i in range(len(header))}
        rows.append(row)

    return rows


# ── Process enrichment ────────────────────────────────────────────────────────

_SUSPICIOUS_NAMES = {
    "mimikatz.exe", "meterpreter.exe", "nc.exe", "ncat.exe",
    "psexec.exe", "wce.exe", "fgdump.exe", "pwdump.exe", "procdump.exe",
}

_SUSPICIOUS_PATHS = [
    "\\temp\\", "\\tmp\\", "\\appdata\\local\\temp\\",
    "\\users\\public\\", "\\programdata\\",
]


def _enrich_process(row: dict) -> dict:
    """Add _suspicious flag and reasons to a process row."""
    name = (row.get("ImageFileName") or row.get("Name") or "").lower()
    path = (row.get("Path") or "").lower()
    reasons: list[str] = []

    if name in _SUSPICIOUS_NAMES:
        reasons.append(f"Known suspicious process: {name}")
    for sus_path in _SUSPICIOUS_PATHS:
        if sus_path in path:
            reasons.append(f"Suspicious path: {path}")
            break

    row["_suspicious"] = len(reasons) > 0
    row["_suspicious_reasons"] = reasons
    return row
