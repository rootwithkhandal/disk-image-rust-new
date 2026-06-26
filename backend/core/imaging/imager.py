"""
Disk Imaging Engine
===================
Sector-by-sector forensic imaging with:
- RAW/DD and E01 format support
- Chunked read/write with configurable block size
- Real-time dual-algorithm hashing (SHA256 + MD5)
- Pause / resume / cancel support
- Read-only enforcement on source device
- Throughput and progress tracking
- Per-session acquisition logging

Usage:
    from core.imaging.imager import DiskImager, ImageFormat

    imager = DiskImager()
    result = imager.acquire(
        source="/dev/sda",
        output_dir="/evidence/CASE-001",
        case_id="CASE-001",
        examiner="Analyst",
    )
    print(result)
"""

from __future__ import annotations

import hashlib
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from loguru import logger

import platform
from core.acquisition.metadata_collector import (
    AcquisitionMetadata,
    DeviceMetadata,
    MetadataCollector,
)
from core.chain_of_custody.evidence_manager import EvidenceManager
from core.reporting.report_generator import ReportFormat, ReportGenerator


class ImageFormat(str, Enum):
    DD = "dd"
    E01 = "e01"


class AcquisitionState(str, Enum):
    IDLE = "idle"
    RUNNING = "running"
    PAUSED = "paused"
    CANCELLED = "cancelled"
    COMPLETE = "complete"
    FAILED = "failed"


@dataclass
class AcquisitionProgress:
    """Live progress snapshot during acquisition."""

    bytes_read: int = 0
    total_bytes: int = 0
    elapsed_seconds: float = 0.0
    state: AcquisitionState = AcquisitionState.IDLE
    current_hash_sha256: str = ""
    current_hash_md5: str = ""

    @property
    def percent(self) -> float:
        if self.total_bytes == 0:
            return 0.0
        return round((self.bytes_read / self.total_bytes) * 100, 2)

    @property
    def throughput_mbps(self) -> float:
        if self.elapsed_seconds == 0:
            return 0.0
        return round((self.bytes_read / (1024**2)) / self.elapsed_seconds, 2)

    @property
    def eta_seconds(self) -> float:
        if self.throughput_mbps == 0 or self.total_bytes == 0:
            return 0.0
        remaining_mb = (self.total_bytes - self.bytes_read) / (1024**2)
        return round(remaining_mb / self.throughput_mbps, 1)

    def __str__(self) -> str:
        return (
            f"{self.percent:.1f}% | "
            f"{self.bytes_read / (1024**2):.1f} / {self.total_bytes / (1024**2):.1f} MB | "
            f"{self.throughput_mbps} MB/s | ETA {self.eta_seconds}s | {self.state.value}"
        )


@dataclass
class AcquisitionResult:
    """Final result of a completed acquisition."""

    success: bool
    evidence_id: str = ""
    case_id: str = ""
    image_path: str = ""
    write_protect_status: str = "UNKNOWN"  # CONFIRMED_RO | CONFIRMED_RW | UNKNOWN
    # Post-acquisition image hashes (hash of the captured image file)
    hash_sha256: str = ""
    hash_md5: str = ""
    hash_sha1: str = ""
    bytes_acquired: int = 0
    duration_seconds: float = 0.0
    verified: bool = False
    error: str = ""
    report_paths: dict = field(default_factory=dict)

    def __str__(self) -> str:
        status = "SUCCESS" if self.success else f"FAILED: {self.error}"
        return (
            f"[{status}] {self.evidence_id} | "
            f"{self.bytes_acquired / (1024**2):.1f} MB | "
            f"{self.duration_seconds}s | verified={self.verified}"
        )


class DiskImager:
    """
    Forensic disk imager.

    Thread-safe with pause/resume/cancel support via threading events.
    """

    def __init__(self, evidence_manager: EvidenceManager | None = None) -> None:
        self._mgr = evidence_manager or EvidenceManager()
        self._pause_event = threading.Event()
        self._cancel_event = threading.Event()
        self._pause_event.set()  # Not paused by default
        self._state = AcquisitionState.IDLE
        self._progress = AcquisitionProgress()

    # ── Public controls ───────────────────────────────────────────────────────

    def pause(self) -> None:
        """Pause an in-progress acquisition."""
        if self._state == AcquisitionState.RUNNING:
            self._pause_event.clear()
            self._state = AcquisitionState.PAUSED
            logger.info("Acquisition paused")

    def resume(self) -> None:
        """Resume a paused acquisition."""
        if self._state == AcquisitionState.PAUSED:
            self._pause_event.set()
            self._state = AcquisitionState.RUNNING
            logger.info("Acquisition resumed")

    def cancel(self) -> None:
        """Cancel an in-progress acquisition."""
        self._cancel_event.set()
        self._pause_event.set()  # Unblock if paused
        self._state = AcquisitionState.CANCELLED
        logger.warning("Acquisition cancelled by user")

    @property
    def progress(self) -> AcquisitionProgress:
        return self._progress

    # ── Main acquire method ───────────────────────────────────────────────────

    def acquire(
        self,
        source: str,
        output_dir: str | Path,
        case_id: str,
        examiner: str,
        image_format: ImageFormat = ImageFormat.DD,
        block_size: int = 65536,
        notes: str = "",
        geo_location: str = "",
        post_verify: bool = True,
        progress_callback: Callable[[AcquisitionProgress], None] | None = None,
    ) -> AcquisitionResult:
        """
        Acquire a forensic image from a source device.

        Args:
            source:            Source device path or file.
            output_dir:        Directory to write the image into.
            case_id:           Case identifier.
            examiner:          Examiner name.
            image_format:      DD or E01.
            block_size:        Read/write block size in bytes.
            notes:             Free-text acquisition notes.
            geo_location:      Lab or location name.
            post_verify:       Re-hash image after acquisition to verify.
            progress_callback: Called with AcquisitionProgress on each block.

        Returns:
            AcquisitionResult with all metadata and hash values.
        """
        if platform.system() == "Windows":
            import re
            if re.match(r"(?i)^PhysicalDrive\d+$", source):
                source = r"\\.\\" + source

        self._cancel_event.clear()
        self._pause_event.set()
        self._state = AcquisitionState.RUNNING

        # ── Build metadata ────────────────────────────────────────────────────
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        device_meta = _build_device_meta(source)
        meta = MetadataCollector.new_session(
            case_id=case_id,
            examiner=examiner,
            device_id=source,
            acquisition_method="physical",
            notes=notes,
            geo_location=geo_location,
            device_meta=device_meta,
        )

        # ── Create evidence directory ─────────────────────────────────────────
        ev_dir = self._mgr.create_evidence_entry(meta)
        image_filename = f"{meta.evidence_id}.{image_format.value}"
        image_path = ev_dir / image_filename

        acq_logger = logger.bind(acquisition=True, session_id=meta.session_id)
        acq_logger.info(
            "Acquisition started | source={} | output={} | format={} | block_size={}",
            source,
            image_path,
            image_format.value,
            block_size,
        )

        # ── Validate source ───────────────────────────────────────────────────
        try:
            total_bytes = _get_source_size(source)
        except Exception as exc:
            return self._fail(meta, f"Cannot open source device: {exc}")

        self._progress = AcquisitionProgress(
            total_bytes=total_bytes,
            state=AcquisitionState.RUNNING,
        )

        # ── Read-only check ───────────────────────────────────────────────────
        ro_status = _check_write_protect(source)
        if ro_status == "CONFIRMED_RO":
            acq_logger.info(
                "Write-protect CONFIRMED \u2014 source is read-only: {}", source
            )
        elif ro_status == "CONFIRMED_RW":
            acq_logger.warning(
                "Write-protect NOT SET \u2014 source is writable! "
                "Ensure a hardware write-blocker is in use: {}", source
            )
        else:
            acq_logger.warning(
                "Write-protect status INCONCLUSIVE \u2014 could not verify: {}", source
            )

        # ── Acquire ───────────────────────────────────────────────────────────
        start_time = time.perf_counter()
        sha256 = hashlib.sha256()
        md5 = hashlib.md5()
        sha1 = hashlib.sha1()
        bytes_read = 0

        try:
            src_file = _open_source(source)
            with src_file, open(image_path, "wb") as dst:
                while True:
                    # Pause support
                    self._pause_event.wait()

                    # Cancel support
                    if self._cancel_event.is_set():
                        self._state = AcquisitionState.CANCELLED
                        acq_logger.warning("Acquisition cancelled at {} bytes", bytes_read)
                        image_path.unlink(missing_ok=True)
                        return AcquisitionResult(
                            success=False,
                            evidence_id=meta.evidence_id,
                            case_id=case_id,
                            error="Cancelled by user",
                        )

                    chunk = src_file.read(block_size)
                    if not chunk:
                        break

                    dst.write(chunk)
                    sha256.update(chunk)
                    md5.update(chunk)
                    sha1.update(chunk)
                    bytes_read += len(chunk)

                    # Update progress
                    elapsed = time.perf_counter() - start_time
                    self._progress = AcquisitionProgress(
                        bytes_read=bytes_read,
                        total_bytes=total_bytes,
                        elapsed_seconds=round(elapsed, 2),
                        state=AcquisitionState.RUNNING,
                    )

                    if progress_callback:
                        progress_callback(self._progress)

                    # Log every 512 MB
                    if bytes_read % (512 * 1024 * 1024) < block_size:
                        acq_logger.debug("Progress: {}", self._progress)

        except PermissionError as exc:
            return self._fail(meta, f"Permission denied — run as administrator: {exc}")
        except OSError as exc:
            return self._fail(meta, f"I/O error during acquisition: {exc}")
        except Exception as exc:
            return self._fail(meta, f"Unexpected error: {exc}")

        duration = round(time.perf_counter() - start_time, 2)
        hash_sha256 = sha256.hexdigest()
        hash_md5 = md5.hexdigest()
        hash_sha1 = sha1.hexdigest()

        acq_logger.info(
            "Acquisition complete | bytes={} | duration={}s | sha256={}",
            bytes_read,
            duration,
            hash_sha256,
        )

        # ── Write hash manifest ───────────────────────────────────────────────
        self._mgr.write_hash_file(
            case_id=case_id,
            evidence_id=meta.evidence_id,
            filename=image_filename,
            sha256=hash_sha256,
            md5=hash_md5,
            sha1=hash_sha1,
        )

        # ── Post-acquisition verification ─────────────────────────────────────
        verified = False
        if post_verify:
            acq_logger.info("Starting post-acquisition verification...")
            verified = self._mgr.verify_evidence_integrity(
                case_id=case_id,
                evidence_id=meta.evidence_id,
                image_filename=image_filename,
            )
            acq_logger.info("Verification result: {}", "PASS" if verified else "FAIL")

        # ── Finalize metadata ─────────────────────────────────────────────────
        meta = MetadataCollector.finalize(
            meta,
            hash_sha256=hash_sha256,
            hash_md5=hash_md5,
            hash_sha1=hash_sha1,
            bytes_acquired=bytes_read,
            output_path=str(image_path),
            verified=verified,
        )
        self._mgr.write_metadata(meta)

        # ── Generate reports ──────────────────────────────────────────────────
        gen = ReportGenerator(output_dir=ev_dir)
        report_paths = gen.generate(
            meta, formats=[ReportFormat.JSON, ReportFormat.HTML, ReportFormat.TEXT]
        )

        self._state = AcquisitionState.COMPLETE

        return AcquisitionResult(
            success=True,
            evidence_id=meta.evidence_id,
            case_id=case_id,
            image_path=str(image_path),
            write_protect_status=ro_status,
            hash_sha256=hash_sha256,
            hash_md5=hash_md5,
            hash_sha1=hash_sha1,
            bytes_acquired=bytes_read,
            duration_seconds=duration,
            verified=verified,
            report_paths={k.value: str(v) for k, v in report_paths.items()},
        )

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _fail(self, meta: AcquisitionMetadata, error: str) -> AcquisitionResult:
        self._state = AcquisitionState.FAILED
        logger.error("Acquisition failed | evidence_id={} | error={}", meta.evidence_id, error)
        self._mgr.record_custody_event(
            meta.evidence_id,
            meta.case_id,
            event_type="failed",
            actor="system",
            notes=error,
        )
        return AcquisitionResult(
            success=False,
            evidence_id=meta.evidence_id,
            case_id=meta.case_id,
            error=error,
        )


# ── Helpers ───────────────────────────────────────────────────────────────────


def _get_source_size(source: str) -> int:
    """Get the byte size of a source device or file."""
    path = Path(source)

    # Regular file
    if path.is_file():
        return path.stat().st_size

    # Block device (Linux/macOS)
    if platform.system() in ("Linux", "Darwin"):
        try:
            import fcntl
            import struct

            with open(source, "rb") as f:
                # BLKGETSIZE64 ioctl — Linux only
                buf = b" " * 8
                BLKGETSIZE64 = 0x80081272
                result = fcntl.ioctl(f.fileno(), BLKGETSIZE64, buf)
                return struct.unpack("Q", result)[0]
        except Exception:
            pass

    # Windows physical drive — use seek to end
    try:
        with open(source, "rb") as f:
            f.seek(0, 2)
            return f.tell()
    except Exception:
        pass

    # Fallback — unknown size (stream until EOF)
    return 0


def _get_source_size(source: str) -> int:
    """Get the byte size of a source device or file."""
    path = Path(source)
    if path.is_file():
        return path.stat().st_size
    # For block devices, try seek-to-end
    try:
        with open(source, "rb") as f:
            f.seek(0, 2)
            size = f.tell()
            return size if size > 0 else 0
    except Exception:
        return 0


# Write-protect status outcomes
_WP_CONFIRMED_RO  = "CONFIRMED_RO"   # device is confirmed read-only
_WP_CONFIRMED_RW  = "CONFIRMED_RW"   # device is confirmed writable (no write-block)
_WP_UNKNOWN       = "UNKNOWN"         # could not determine status


def _check_write_protect(source: str) -> str:
    """
    Determine whether a source device has write-protection active.

    Returns one of:
        "CONFIRMED_RO"  - kernel confirmed the device is write-protected
        "CONFIRMED_RW"  - kernel confirmed the device is writable (no block)
        "UNKNOWN"       - status could not be determined

    On Windows, issues IOCTL_DISK_IS_WRITABLE via DeviceIoControl.
    If the ioctl fails with ERROR_WRITE_PROTECT (19) the device is
    write-protected; if it succeeds the device is writable.

    On Linux, reads /sys/block/<dev>/ro (1 = read-only).
    """
    if platform.system() == "Linux":
        dev_name = Path(source).name
        ro_path = Path(f"/sys/block/{dev_name}/ro")
        if ro_path.exists():
            flag = ro_path.read_text().strip()
            return _WP_CONFIRMED_RO if flag == "1" else _WP_CONFIRMED_RW
        return _WP_UNKNOWN

    if platform.system() == "Windows":
        try:
            import ctypes

            GENERIC_READ          = 0x80000000
            FILE_SHARE_READ       = 0x00000001
            FILE_SHARE_WRITE      = 0x00000002
            OPEN_EXISTING         = 3
            IOCTL_DISK_IS_WRITABLE = 0x00070024   # CTL_CODE(IOCTL_DISK_BASE,0x09,METHOD_BUFFERED,FILE_ANY_ACCESS)
            ERROR_WRITE_PROTECT   = 19

            kernel32 = ctypes.windll.kernel32
            handle = kernel32.CreateFileW(
                source,
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                0,
                None,
            )
            if handle == -1:
                return _WP_UNKNOWN

            try:
                bytes_returned = ctypes.c_ulong(0)
                ok = kernel32.DeviceIoControl(
                    handle,
                    IOCTL_DISK_IS_WRITABLE,
                    None, 0,
                    None, 0,
                    ctypes.byref(bytes_returned),
                    None,
                )
                if ok:
                    return _WP_CONFIRMED_RW   # ioctl succeeded — disk is writable
                err = kernel32.GetLastError()
                if err == ERROR_WRITE_PROTECT:
                    return _WP_CONFIRMED_RO   # ERROR_WRITE_PROTECT — disk is write-blocked
                return _WP_UNKNOWN            # some other error — inconclusive
            finally:
                kernel32.CloseHandle(handle)
        except Exception:
            return _WP_UNKNOWN

    return _WP_UNKNOWN  # Darwin / other — inconclusive


def _build_device_meta(source: str) -> DeviceMetadata:
    """Build a basic DeviceMetadata from a source path."""
    path = Path(source)
    size = 0
    try:
        if path.is_file():
            size = path.stat().st_size
        else:
            with open(source, "rb") as f:
                f.seek(0, 2)
                size = f.tell()
    except Exception:
        pass

    return DeviceMetadata(
        device_id=source,
        size_bytes=size,
    )


def _open_source(source: str):
    """
    Open a source device for reading.

    On Windows, physical drives (\\\\.\\ prefix) must be opened via the
    Win32 CreateFile API with FILE_SHARE_READ | FILE_SHARE_WRITE to avoid
    the PermissionError that plain open() raises against raw drives.
    All other paths fall back to a normal binary open().
    """
    if platform.system() == "Windows" and source.startswith("\\\\.\\"):
        import ctypes
        import msvcrt
        import os

        GENERIC_READ       = 0x80000000
        FILE_SHARE_READ    = 0x00000001
        FILE_SHARE_WRITE   = 0x00000002
        OPEN_EXISTING      = 3
        FILE_ATTRIBUTE_NORMAL = 0x80

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.CreateFileW(
            source,
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
        if handle == -1:  # INVALID_HANDLE_VALUE
            raise PermissionError(
                f"CreateFile failed for {source} — run as Administrator "
                f"(error {ctypes.windll.kernel32.GetLastError()})"
            )
        fd = msvcrt.open_osfhandle(handle, os.O_RDONLY)
        return os.fdopen(fd, "rb")

    return open(source, "rb")
