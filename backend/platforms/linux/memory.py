"""
Linux Memory Acquisition
=========================
Integrates LiME (Linux Memory Extractor) and AVML
for live RAM acquisition on Linux systems.

LiME: https://github.com/504ensicsLabs/LiME
AVML: https://github.com/microsoft/avml
"""

from __future__ import annotations

import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from loguru import logger


@dataclass
class LinuxMemoryResult:
    success: bool
    dump_path: str = ""
    size_bytes: int = 0
    duration_seconds: float = 0.0
    hash_sha256: str = ""
    hash_md5: str = ""
    verified: bool = False
    tool_used: str = ""
    error: str = ""

    @property
    def size_gb(self) -> float:
        return round(self.size_bytes / (1024**3), 2)


def _find_tool(names: list[str]) -> Path | None:
    """Find a tool on PATH or in tools/ directory."""
    tools_dir = Path(__file__).resolve().parents[3] / "tools"
    for name in names:
        candidate = tools_dir / name
        if candidate.exists():
            return candidate
        found = shutil.which(name)
        if found:
            return Path(found)
    return None


def acquire_ram_avml(output_path: str | Path) -> LinuxMemoryResult:
    """
    Acquire RAM using AVML (no kernel module required).
    Preferred method — works without loading a kernel module.
    """
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)

    avml = _find_tool(["avml", "avml-memory"])
    if not avml:
        return LinuxMemoryResult(
            success=False,
            error="AVML not found. Download from https://github.com/microsoft/avml/releases",
        )

    logger.info("Starting RAM acquisition via AVML | output={}", output)
    start = time.perf_counter()

    try:
        result = subprocess.run(
            [str(avml), str(output)],
            capture_output=True,
            text=True,
            timeout=600,
        )
        duration = round(time.perf_counter() - start, 2)

        if result.returncode != 0:
            error = result.stderr.strip() or result.stdout.strip()
            return LinuxMemoryResult(
                success=False,
                error=f"AVML failed: {error}",
                tool_used="avml",
            )

        return _finalize_dump(output, duration, "avml")

    except subprocess.TimeoutExpired:
        return LinuxMemoryResult(success=False, error="AVML timed out", tool_used="avml")
    except PermissionError:
        return LinuxMemoryResult(
            success=False,
            error="Permission denied — run as root",
            tool_used="avml",
        )
    except Exception as exc:
        return LinuxMemoryResult(success=False, error=str(exc), tool_used="avml")


def acquire_ram_lime(
    output_path: str | Path,
    lime_module_path: str | None = None,
    format: str = "lime",
) -> LinuxMemoryResult:
    """
    Acquire RAM using LiME kernel module.
    Requires the LiME .ko module compiled for the running kernel.

    Args:
        output_path:       Path to write the memory dump.
        lime_module_path:  Path to lime.ko (auto-detected if None).
        format:            lime | padded | raw
    """
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)

    lime_ko = Path(lime_module_path) if lime_module_path else _find_tool(["lime.ko", "lime-*.ko"])

    if not lime_ko or not lime_ko.exists():
        return LinuxMemoryResult(
            success=False,
            error=(
                "LiME kernel module not found. "
                "Compile for your kernel: https://github.com/504ensicsLabs/LiME"
            ),
            tool_used="lime",
        )

    logger.info("Starting RAM acquisition via LiME | output={}", output)
    start = time.perf_counter()

    try:
        # Load LiME module with output path and format
        result = subprocess.run(
            [
                "insmod",
                str(lime_ko),
                f"path={output}",
                f"format={format}",
            ],
            capture_output=True,
            text=True,
            timeout=600,
        )
        duration = round(time.perf_counter() - start, 2)

        if result.returncode != 0:
            error = result.stderr.strip()
            return LinuxMemoryResult(
                success=False,
                error=f"LiME insmod failed: {error}",
                tool_used="lime",
            )

        # Unload module
        subprocess.run(["rmmod", "lime"], capture_output=True, timeout=10)

        return _finalize_dump(output, duration, "lime")

    except subprocess.TimeoutExpired:
        return LinuxMemoryResult(success=False, error="LiME timed out", tool_used="lime")
    except PermissionError:
        return LinuxMemoryResult(
            success=False,
            error="Permission denied — run as root",
            tool_used="lime",
        )
    except Exception as exc:
        return LinuxMemoryResult(success=False, error=str(exc), tool_used="lime")


def acquire_ram(output_path: str | Path) -> LinuxMemoryResult:
    """
    Auto-select best available RAM acquisition tool.
    Tries AVML first (no kernel module), then LiME.
    """
    # Try AVML first
    if _find_tool(["avml", "avml-memory"]):
        return acquire_ram_avml(output_path)
    # Fall back to LiME
    if _find_tool(["lime.ko"]):
        return acquire_ram_lime(output_path)
    return LinuxMemoryResult(
        success=False,
        error=(
            "No memory acquisition tool found. "
            "Install AVML (https://github.com/microsoft/avml) "
            "or LiME (https://github.com/504ensicsLabs/LiME)"
        ),
    )


def _finalize_dump(output: Path, duration: float, tool: str) -> LinuxMemoryResult:
    """Hash and verify a completed memory dump."""
    if not output.exists():
        return LinuxMemoryResult(
            success=False,
            error="Dump file not found after acquisition",
            tool_used=tool,
        )

    size = output.stat().st_size
    logger.info("RAM dump complete | size={:.2f} GB | duration={}s", size / (1024**3), duration)

    from core.hashing.hasher import HashAlgorithm, Hasher

    multi = Hasher.hash_file_multi(output, [HashAlgorithm.SHA256, HashAlgorithm.MD5])
    sha256 = multi.hashes.get(HashAlgorithm.SHA256, "")
    md5 = multi.hashes.get(HashAlgorithm.MD5, "")

    # Write hash sidecar
    hash_file = output.with_suffix(output.suffix + ".hashes")
    hash_file.write_text(f"SHA256: {sha256}\nMD5:    {md5}\n", encoding="utf-8")

    verified = Hasher.verify_file(output, HashAlgorithm.SHA256, sha256)

    return LinuxMemoryResult(
        success=True,
        dump_path=str(output),
        size_bytes=size,
        duration_seconds=duration,
        hash_sha256=sha256,
        hash_md5=md5,
        verified=verified,
        tool_used=tool,
    )


def get_ram_info() -> dict:
    """Return RAM info from /proc/meminfo."""
    info: dict = {}
    try:
        meminfo = Path("/proc/meminfo").read_text()
        for line in meminfo.splitlines():
            if ":" in line:
                key, val = line.split(":", 1)
                info[key.strip()] = val.strip()
        total_kb = int(info.get("MemTotal", "0 kB").split()[0])
        avail_kb = int(info.get("MemAvailable", "0 kB").split()[0])
        return {
            "total_gb": round(total_kb / (1024**2), 2),
            "available_gb": round(avail_kb / (1024**2), 2),
            "used_gb": round((total_kb - avail_kb) / (1024**2), 2),
        }
    except Exception as exc:
        logger.debug("RAM info error: {}", exc)
        return {}
