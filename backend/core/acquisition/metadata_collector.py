"""
Metadata Collector
==================
Collects system, device, and acquisition metadata at the start of
every forensic session. This data feeds the chain of custody record
and the final evidence manifest.

Usage:
    from core.acquisition.metadata_collector import MetadataCollector

    meta = MetadataCollector.collect(device_id="\\\\.\\PhysicalDrive0")
    print(meta.to_dict())
"""

from __future__ import annotations

import socket
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

import psutil
from loguru import logger

import platform


@dataclass
class SystemMetadata:
    """Metadata about the examiner's workstation."""

    hostname: str
    os_name: str
    os_version: str
    os_arch: str
    cpu_model: str
    cpu_cores: int
    ram_total_gb: float
    python_version: str
    tool_version: str = "ForgeLens 0.1.0"


@dataclass
class DeviceMetadata:
    """Metadata about the source device being acquired."""

    device_id: str
    model: str = ""
    serial: str = ""
    interface: str = ""
    size_bytes: int = 0
    filesystem: str = ""
    is_removable: bool = False
    is_encrypted: bool = False
    encryption_type: str = ""
    extra: dict = field(default_factory=dict)

    @property
    def size_gb(self) -> float:
        return round(self.size_bytes / (1024**3), 2)


@dataclass
class AcquisitionMetadata:
    """
    Full metadata record for a single acquisition session.
    This is the root object written to metadata.json in the evidence folder.
    """

    evidence_id: str
    case_id: str
    session_id: str
    examiner: str
    timestamp_utc: str  # ISO 8601
    acquisition_method: str  # physical, logical, live, remote
    tool_version: str = "ForgeLens 0.1.0"
    notes: str = ""
    geo_location: str = ""
    system: SystemMetadata | None = None
    device: DeviceMetadata | None = None
    hash_sha256: str = ""
    hash_md5: str = ""
    hash_sha1: str = ""
    hash_blake3: str = ""
    acquisition_start: str = ""
    acquisition_end: str = ""
    duration_seconds: float = 0.0
    bytes_acquired: int = 0
    output_path: str = ""
    verified: bool = False
    signature: str = ""

    def to_dict(self) -> dict:
        return asdict(self)

    def __str__(self) -> str:
        return (
            f"Evidence: {self.evidence_id} | Case: {self.case_id} | "
            f"Examiner: {self.examiner} | {self.timestamp_utc}"
        )


class MetadataCollector:
    """
    Collects and assembles acquisition metadata.
    """

    @staticmethod
    def collect_system() -> SystemMetadata:
        """Collect metadata about the current workstation."""
        try:
            cpu = platform.processor() or "Unknown CPU"
            ram = round(psutil.virtual_memory().total / (1024**3), 2)
            cores = psutil.cpu_count(logical=False) or 1

            meta = SystemMetadata(
                hostname=socket.gethostname(),
                os_name=platform.system(),
                os_version=platform.version(),
                os_arch=platform.machine(),
                cpu_model=cpu,
                cpu_cores=cores,
                ram_total_gb=ram,
                python_version=platform.python_version(),
            )
            logger.debug("System metadata collected: {}", meta.hostname)
            return meta

        except Exception as exc:
            logger.error("Failed to collect system metadata: {}", exc)
            return SystemMetadata(
                hostname="unknown",
                os_name=platform.system(),
                os_version="",
                os_arch="",
                cpu_model="",
                cpu_cores=0,
                ram_total_gb=0.0,
                python_version=platform.python_version(),
            )

    @staticmethod
    def new_session(
        case_id: str,
        examiner: str,
        device_id: str,
        acquisition_method: str = "physical",
        notes: str = "",
        geo_location: str = "",
        device_meta: DeviceMetadata | None = None,
    ) -> AcquisitionMetadata:
        """
        Create a new AcquisitionMetadata record for a session.

        Args:
            case_id:            Case identifier (e.g. CASE-2026-001).
            examiner:           Name of the examiner.
            device_id:          Source device path or serial.
            acquisition_method: physical | logical | live | remote.
            notes:              Free-text notes.
            geo_location:       Lab or location name.
            device_meta:        Optional pre-built DeviceMetadata.

        Returns:
            AcquisitionMetadata ready to be written to disk.
        """
        session_id = str(uuid.uuid4())
        evidence_id = f"EV-{session_id[:8].upper()}"
        now = datetime.now(timezone.utc).isoformat()

        system_meta = MetadataCollector.collect_system()

        if device_meta is None:
            device_meta = DeviceMetadata(device_id=device_id)

        meta = AcquisitionMetadata(
            evidence_id=evidence_id,
            case_id=case_id,
            session_id=session_id,
            examiner=examiner,
            timestamp_utc=now,
            acquisition_method=acquisition_method,
            notes=notes,
            geo_location=geo_location,
            system=system_meta,
            device=device_meta,
            acquisition_start=now,
        )

        logger.info(
            "New acquisition session | evidence_id={} | case={} | examiner={}",
            evidence_id,
            case_id,
            examiner,
        )
        return meta

    @staticmethod
    def finalize(
        meta: AcquisitionMetadata,
        hash_sha256: str = "",
        hash_md5: str = "",
        hash_sha1: str = "",
        hash_blake3: str = "",
        bytes_acquired: int = 0,
        output_path: str = "",
        verified: bool = False,
    ) -> AcquisitionMetadata:
        """
        Finalize metadata after acquisition completes.
        Fills in hashes, timing, and output path.
        """
        now = datetime.now(timezone.utc).isoformat()

        meta.acquisition_end = now
        meta.hash_sha256 = hash_sha256
        meta.hash_md5 = hash_md5
        meta.hash_sha1 = hash_sha1
        meta.hash_blake3 = hash_blake3
        meta.bytes_acquired = bytes_acquired
        meta.output_path = output_path
        meta.verified = verified

        # Calculate duration
        try:
            start = datetime.fromisoformat(meta.acquisition_start)
            end = datetime.fromisoformat(now)
            meta.duration_seconds = round((end - start).total_seconds(), 2)
        except Exception:
            meta.duration_seconds = 0.0

        logger.info(
            "Acquisition finalized | evidence_id={} | verified={} | duration={}s",
            meta.evidence_id,
            verified,
            meta.duration_seconds,
        )
        return meta
