"""
Evidence Synchronization
=========================
Synchronizes evidence between remote agents and the central evidence vault.
Handles chunked transfer, integrity verification, and conflict resolution.

Usage:
    from core.remote.sync import EvidenceSync

    sync = EvidenceSync(vault_base="/evidence")
    sync.pull_from_agent(client, case_id="CASE-001", evidence_id="EV-ABC")
    sync.push_to_vault(local_path, case_id, evidence_id)
"""

from __future__ import annotations

import json
import shutil
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from loguru import logger

from core.config import settings
from core.hashing.hasher import HashAlgorithm, Hasher


@dataclass
class SyncResult:
    success: bool
    source: str
    destination: str
    bytes_transferred: int = 0
    sha256: str = ""
    verified: bool = False
    error: str = ""
    duration_seconds: float = 0.0

    def __str__(self) -> str:
        status = "OK" if self.success else f"FAILED: {self.error}"
        return f"[{status}] {self.source} -> {self.destination} | {self.bytes_transferred:,} bytes"


@dataclass
class SyncManifest:
    """Tracks what has been synced for a case."""

    case_id: str
    synced_items: list[dict] = field(default_factory=list)
    last_sync: str = ""
    total_bytes: int = 0

    def add_item(self, evidence_id: str, sha256: str, size: int, source: str) -> None:
        self.synced_items.append(
            {
                "evidence_id": evidence_id,
                "sha256": sha256,
                "size_bytes": size,
                "source": source,
                "synced_at": datetime.now(timezone.utc).isoformat(),
            }
        )
        self.total_bytes += size
        self.last_sync = datetime.now(timezone.utc).isoformat()


class EvidenceSync:
    """
    Manages evidence synchronization between agents and the central vault.
    """

    def __init__(self, vault_base: Path | None = None) -> None:
        self.vault_base = Path(vault_base or settings.evidence.base_path)
        self.vault_base.mkdir(parents=True, exist_ok=True)

    # ── Push (local -> vault) ─────────────────────────────────────────────────

    def push_to_vault(
        self,
        source_path: Path,
        case_id: str,
        evidence_id: str,
        verify: bool = True,
    ) -> SyncResult:
        """
        Copy a local file into the evidence vault with integrity verification.

        Args:
            source_path:  Local file to push.
            case_id:      Target case ID.
            evidence_id:  Target evidence ID.
            verify:       Re-hash after copy to verify integrity.
        """
        import time

        start = time.perf_counter()

        dest_dir = self.vault_base / "cases" / case_id / evidence_id
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest_path = dest_dir / source_path.name

        result = SyncResult(
            source=str(source_path),
            destination=str(dest_path),
            success=False,
        )

        if not source_path.exists():
            result.error = f"Source not found: {source_path}"
            return result

        try:
            # Hash source before copy
            src_hash = Hasher.hash_file(source_path, HashAlgorithm.SHA256)
            result.sha256 = src_hash.hex_digest
            result.bytes_transferred = src_hash.size_bytes

            # Copy
            shutil.copy2(source_path, dest_path)

            # Verify after copy
            if verify:
                ok = Hasher.verify_file(dest_path, HashAlgorithm.SHA256, src_hash.hex_digest)
                result.verified = ok
                if not ok:
                    result.error = "Integrity check failed after copy"
                    dest_path.unlink(missing_ok=True)
                    return result

            result.success = True
            result.duration_seconds = round(time.perf_counter() - start, 2)

            # Write hash sidecar
            hash_path = dest_dir / f"{source_path.name}.sha256"
            hash_path.write_text(src_hash.hex_digest, encoding="utf-8")

            logger.info(
                "Pushed to vault: {} -> {} | {} bytes | verified={}",
                source_path.name,
                dest_path,
                result.bytes_transferred,
                result.verified,
            )

        except Exception as exc:
            result.error = str(exc)
            logger.error("Push to vault failed: {}", exc)

        return result

    # ── Pull (agent -> local) ─────────────────────────────────────────────────

    def pull_from_agent(
        self,
        agent_client,
        case_id: str,
        output_dir: Path | None = None,
    ) -> SyncResult:
        """
        Pull live response data from a remote agent into the vault.

        Args:
            agent_client: Connected AgentClient instance.
            case_id:      Case to associate the data with.
            output_dir:   Override output directory.
        """
        import time

        start = time.perf_counter()

        out = output_dir or (self.vault_base / "cases" / case_id / "remote_collection")
        out.mkdir(parents=True, exist_ok=True)

        result = SyncResult(
            source=agent_client.base_url,
            destination=str(out),
            success=False,
        )

        try:
            task_result = agent_client.run_live_response()

            if not task_result.success:
                result.error = task_result.error
                return result

            # Write collected data
            output_file = out / f"live_response_{int(time.time())}.json"
            output_file.write_text(
                json.dumps(task_result.data, indent=2, default=str),
                encoding="utf-8",
            )

            result.bytes_transferred = output_file.stat().st_size
            result.sha256 = Hasher.hash_file(output_file, HashAlgorithm.SHA256).hex_digest
            result.success = True
            result.duration_seconds = round(time.perf_counter() - start, 2)

            logger.info(
                "Pulled from agent: {} | {} bytes", agent_client.base_url, result.bytes_transferred
            )

        except Exception as exc:
            result.error = str(exc)
            logger.error("Pull from agent failed: {}", exc)

        return result

    # ── Manifest ──────────────────────────────────────────────────────────────

    def load_manifest(self, case_id: str) -> SyncManifest:
        """Load or create a sync manifest for a case."""
        manifest_path = self.vault_base / "cases" / case_id / "sync_manifest.json"
        if manifest_path.exists():
            try:
                data = json.loads(manifest_path.read_text(encoding="utf-8"))
                return SyncManifest(
                    **{k: v for k, v in data.items() if k in SyncManifest.__dataclass_fields__}
                )
            except Exception:
                pass
        return SyncManifest(case_id=case_id)

    def save_manifest(self, manifest: SyncManifest) -> None:
        """Save a sync manifest."""
        manifest_path = self.vault_base / "cases" / manifest.case_id / "sync_manifest.json"
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        manifest_path.write_text(
            json.dumps(
                {
                    "case_id": manifest.case_id,
                    "synced_items": manifest.synced_items,
                    "last_sync": manifest.last_sync,
                    "total_bytes": manifest.total_bytes,
                },
                indent=2,
            ),
            encoding="utf-8",
        )

    # ── Integrity audit ───────────────────────────────────────────────────────

    def audit_vault(self, case_id: str) -> dict:
        """
        Re-verify all evidence files in a case against stored hashes.
        Returns a report of pass/fail for each file.
        """
        case_dir = self.vault_base / "cases" / case_id
        if not case_dir.exists():
            return {"error": f"Case not found: {case_id}"}

        report = {
            "case_id": case_id,
            "audited_at": datetime.now(timezone.utc).isoformat(),
            "results": [],
            "passed": 0,
            "failed": 0,
        }

        for ev_dir in case_dir.iterdir():
            if not ev_dir.is_dir():
                continue
            for hash_file in ev_dir.glob("*.sha256"):
                image_file = hash_file.with_suffix("")
                if not image_file.exists():
                    continue
                expected = hash_file.read_text().strip()
                ok = Hasher.verify_file(image_file, HashAlgorithm.SHA256, expected)
                entry = {
                    "evidence_id": ev_dir.name,
                    "file": image_file.name,
                    "verified": ok,
                }
                report["results"].append(entry)
                if ok:
                    report["passed"] += 1
                else:
                    report["failed"] += 1

        logger.info(
            "Vault audit | case={} | passed={} | failed={}",
            case_id,
            report["passed"],
            report["failed"],
        )
        return report
