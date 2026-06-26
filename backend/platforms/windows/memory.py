"""
Windows Memory Acquisition
===========================
Integrates WinPmem for live RAM acquisition with full chain of custody,
evidence vault integration, and post-acquisition hash verification.

WinPmem is auto-detected from:
  1. tools/ directory (relative to project root)
  2. System PATH

Download WinPmem:
  python tools/setup_winpmem.py
  — or manually from https://github.com/Velocidex/WinPmem/releases

Usage:
    from platforms.windows.memory import acquire_ram, get_ram_info, find_winpmem

    result = acquire_ram(
        output_path="evidence/memory.raw",
        case_id="CASE-001",
        examiner="Analyst",
        verify=True,
    )
    print(result)
"""

from __future__ import annotations

import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from loguru import logger

# WinPmem executable names to search for (in preference order)
WINPMEM_NAMES = [
    "winpmem_mini_x64_rc2.exe",
    "winpmem_mini_x64.exe",
    "winpmem_mini_x86.exe",
    "winpmem.exe",
    "DumpIt.exe",
]

# DumpIt uses a different CLI — flag it so we can adjust the command
_DUMPIT_NAMES = {"DumpIt.exe", "dumpit.exe"}


@dataclass
class MemoryAcquisitionResult:
    success: bool
    dump_path: str = ""
    evidence_id: str = ""
    case_id: str = ""
    size_bytes: int = 0
    duration_seconds: float = 0.0
    hash_sha256: str = ""
    hash_md5: str = ""
    verified: bool = False
    error: str = ""
    tool_used: str = ""

    @property
    def size_gb(self) -> float:
        return round(self.size_bytes / (1024**3), 2)

    def __str__(self) -> str:
        status = "SUCCESS" if self.success else f"FAILED: {self.error}"
        return (
            f"[{status}] {self.evidence_id} | "
            f"{self.size_gb} GB | {self.duration_seconds}s | "
            f"verified={self.verified} | tool={self.tool_used}"
        )


def find_winpmem() -> Path | None:
    """
    Locate a WinPmem (or DumpIt) executable.

    Search order:
      1. tools/ directory relative to project root
      2. System PATH
    """
    tools_dir = Path(__file__).resolve().parents[3] / "tools"

    for name in WINPMEM_NAMES:
        # tools/ first
        candidate = tools_dir / name
        if candidate.exists():
            logger.debug("Found memory tool in tools/: {}", candidate)
            return candidate
        # then PATH
        found = shutil.which(name)
        if found:
            logger.debug("Found memory tool on PATH: {}", found)
            return Path(found)

    return None


def get_ram_info() -> dict:
    """Return total, available, and used RAM from the live system."""
    try:
        import psutil

        mem = psutil.virtual_memory()
        return {
            "total_gb": round(mem.total / (1024**3), 2),
            "available_gb": round(mem.available / (1024**3), 2),
            "used_gb": round(mem.used / (1024**3), 2),
            "percent_used": mem.percent,
        }
    except Exception as exc:
        logger.error("RAM info error: {}", exc)
        return {}


def acquire_ram(
    output_path: str | Path,
    case_id: str = "CASE-UNKNOWN",
    examiner: str = "unknown",
    notes: str = "",
    geo_location: str = "",
    verify: bool = True,
) -> MemoryAcquisitionResult:
    """
    Acquire a full RAM dump using WinPmem (or DumpIt as fallback).

    Integrates with the ForgeLens evidence vault:
      - Creates a chain of custody entry
      - Writes metadata.json and hash manifest
      - Records acquisition and verification events

    Args:
        output_path:  Path to write the memory dump (.raw).
        case_id:      Case identifier for the evidence vault.
        examiner:     Name of the examiner performing the acquisition.
        notes:        Free-text acquisition notes.
        geo_location: Lab or location name.
        verify:       Re-hash the dump after acquisition to verify integrity.

    Returns:
        MemoryAcquisitionResult with path, size, hashes, and CoC evidence_id.
    """
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)

    # ── Locate tool ───────────────────────────────────────────────────────────
    tool = find_winpmem()
    if not tool:
        msg = (
            "No memory acquisition tool found.\n"
            "Run:  python tools/setup_winpmem.py\n"
            "Or download manually from https://github.com/Velocidex/WinPmem/releases\n"
            "and place in the tools/ directory."
        )
        logger.error(msg)
        return MemoryAcquisitionResult(success=False, error=msg)

    tool_name = tool.name
    is_dumpit = tool_name in _DUMPIT_NAMES

    # ── Chain of custody — open session ──────────────────────────────────────
    from core.acquisition.metadata_collector import AcquisitionMetadata, MetadataCollector, DeviceMetadata
    from core.chain_of_custody.evidence_manager import EvidenceManager
    from core.hashing.hasher import HashAlgorithm, Hasher

    ram_info = get_ram_info()
    device_meta = DeviceMetadata(
        device_id="RAM",
        model="Physical Memory",
        size_bytes=int(ram_info.get("total_gb", 0) * (1024**3)),
        interface="internal",
    )

    meta = MetadataCollector.new_session(
        case_id=case_id,
        examiner=examiner,
        device_id="RAM",
        acquisition_method="memory",
        notes=notes or f"Live RAM acquisition via {tool_name}",
        geo_location=geo_location,
        device_meta=device_meta,
    )

    mgr = EvidenceManager()
    ev_dir = mgr.create_evidence_entry(meta)

    # Write dump into the evidence directory
    dump_filename = f"{meta.evidence_id}.raw"
    dump_path = ev_dir / dump_filename

    logger.info(
        "RAM acquisition started | tool={} | output={} | evidence_id={}",
        tool_name,
        dump_path,
        meta.evidence_id,
    )

    # ── Run WinPmem / DumpIt ──────────────────────────────────────────────────
    start = time.perf_counter()

    try:
        if is_dumpit:
            # DumpIt: DumpIt.exe /OUTPUT <path> /QUIET
            cmd = [str(tool), f"/OUTPUT:{dump_path}", "/QUIET"]
        else:
            # WinPmem: winpmem.exe <output>
            cmd = [str(tool), str(dump_path)]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600,  # 10 min max
        )

        duration = round(time.perf_counter() - start, 2)

        # WinPmem often exits with code 1 even on success — check the file first.
        # Only treat as failure if the dump file is missing or empty.
        dump_exists = dump_path.exists() and dump_path.stat().st_size > 0
        if result.returncode != 0 and not dump_exists:
            error = (result.stderr.strip() or result.stdout.strip())[:500]
            logger.error("Memory tool failed (rc={}): {}", result.returncode, error)
            mgr.record_custody_event(
                meta.evidence_id, case_id,
                event_type="failed",
                actor="system",
                notes=f"{tool_name} exit code {result.returncode}: {error}",
            )
            return MemoryAcquisitionResult(
                success=False,
                evidence_id=meta.evidence_id,
                case_id=case_id,
                error=f"{tool_name} exit code {result.returncode}: {error}",
                tool_used=tool_name,
            )

        if result.returncode != 0 and dump_exists:
            logger.warning(
                "WinPmem exited {} but dump file exists ({:.2f} GB) — treating as success",
                result.returncode, dump_path.stat().st_size / (1024**3),
            )

        if not dump_path.exists():
            # Some WinPmem versions write to cwd — check there too
            fallback = output.parent / dump_filename
            if fallback.exists() and fallback != dump_path:
                fallback.rename(dump_path)
            else:
                err = "Acquisition completed but dump file not found"
                mgr.record_custody_event(
                    meta.evidence_id, case_id,
                    event_type="failed", actor="system", notes=err,
                )
                return MemoryAcquisitionResult(
                    success=False,
                    evidence_id=meta.evidence_id,
                    case_id=case_id,
                    error=err,
                    tool_used=tool_name,
                )

        size = dump_path.stat().st_size
        logger.info(
            "RAM dump written | size={:.2f} GB | duration={}s",
            size / (1024**3),
            duration,
        )

        # ── Hash ──────────────────────────────────────────────────────────────
        logger.info("Hashing dump (SHA256 + MD5)...")
        multi = Hasher.hash_file_multi(
            dump_path,
            algorithms=[HashAlgorithm.SHA256, HashAlgorithm.MD5, HashAlgorithm.SHA1],
        )
        sha256 = multi.hashes.get(HashAlgorithm.SHA256, "")
        md5    = multi.hashes.get(HashAlgorithm.MD5, "")
        sha1   = multi.hashes.get(HashAlgorithm.SHA1, "")

        # ── Write hash manifest ───────────────────────────────────────────────
        mgr.write_hash_file(
            case_id=case_id,
            evidence_id=meta.evidence_id,
            filename=dump_filename,
            sha256=sha256,
            md5=md5,
            sha1=sha1,
        )

        # ── Post-acquisition verification ─────────────────────────────────────
        verified = False
        if verify:
            logger.info("Verifying dump integrity...")
            verified = mgr.verify_evidence_integrity(
                case_id=case_id,
                evidence_id=meta.evidence_id,
                image_filename=dump_filename,
            )
            logger.info("Verification: {}", "PASS" if verified else "FAIL")

        # ── Finalize metadata ─────────────────────────────────────────────────
        meta = MetadataCollector.finalize(
            meta,
            hash_sha256=sha256,
            hash_md5=md5,
            hash_sha1=sha1,
            bytes_acquired=size,
            output_path=str(dump_path),
            verified=verified,
        )
        mgr.write_metadata(meta)

        # ── Generate acquisition report ───────────────────────────────────────
        try:
            from core.reporting.report_generator import ReportFormat, ReportGenerator
            gen = ReportGenerator(output_dir=ev_dir)
            gen.generate(meta, formats=[ReportFormat.JSON, ReportFormat.HTML, ReportFormat.TEXT])
        except Exception as exc:
            logger.debug("Report generation skipped: {}", exc)

        return MemoryAcquisitionResult(
            success=True,
            dump_path=str(dump_path),
            evidence_id=meta.evidence_id,
            case_id=case_id,
            size_bytes=size,
            duration_seconds=duration,
            hash_sha256=sha256,
            hash_md5=md5,
            verified=verified,
            tool_used=tool_name,
        )

    except subprocess.TimeoutExpired:
        err = f"{tool_name} timed out after 10 minutes"
        mgr.record_custody_event(
            meta.evidence_id, case_id,
            event_type="failed", actor="system", notes=err,
        )
        return MemoryAcquisitionResult(
            success=False,
            evidence_id=meta.evidence_id,
            case_id=case_id,
            error=err,
            tool_used=tool_name,
        )
    except PermissionError:
        err = "Permission denied — run as Administrator"
        mgr.record_custody_event(
            meta.evidence_id, case_id,
            event_type="failed", actor="system", notes=err,
        )
        return MemoryAcquisitionResult(
            success=False,
            evidence_id=meta.evidence_id,
            case_id=case_id,
            error=err,
            tool_used=tool_name,
        )
    except Exception as exc:
        logger.error("RAM acquisition error: {}", exc)
        mgr.record_custody_event(
            meta.evidence_id, case_id,
            event_type="failed", actor="system", notes=str(exc),
        )
        return MemoryAcquisitionResult(
            success=False,
            evidence_id=meta.evidence_id,
            case_id=case_id,
            error=str(exc),
            tool_used=tool_name,
        )
