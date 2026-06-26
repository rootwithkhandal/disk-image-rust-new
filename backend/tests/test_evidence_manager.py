"""Tests for the evidence manager."""

import tempfile
from pathlib import Path

from core.acquisition.metadata_collector import MetadataCollector
from core.chain_of_custody.evidence_manager import EvidenceManager


def _temp_manager() -> tuple[EvidenceManager, Path]:
    tmp = tempfile.mkdtemp()
    return EvidenceManager(base_path=tmp), Path(tmp)


class TestEvidenceManager:
    def test_create_evidence_entry(self):
        mgr, base = _temp_manager()
        meta = MetadataCollector.new_session("CASE-001", "Analyst", "/dev/sda")
        ev_dir = mgr.create_evidence_entry(meta)

        assert ev_dir.exists()
        assert (ev_dir / "chain_of_custody.json").exists()
        assert (ev_dir / "acquisition.log").exists()

    def test_write_and_read_metadata(self):
        mgr, _ = _temp_manager()
        meta = MetadataCollector.new_session("CASE-002", "Analyst", "/dev/sdb")
        mgr.create_evidence_entry(meta)
        mgr.write_metadata(meta)

        data = mgr.read_metadata(meta.case_id, meta.evidence_id)
        assert data["evidence_id"] == meta.evidence_id
        assert data["case_id"] == meta.case_id

    def test_custody_chain(self):
        mgr, _ = _temp_manager()
        meta = MetadataCollector.new_session("CASE-003", "Analyst", "/dev/sdc")
        mgr.create_evidence_entry(meta)

        mgr.record_custody_event(
            meta.evidence_id,
            meta.case_id,
            event_type="transferred",
            actor="Analyst B",
            notes="Transferred to lab",
        )

        events = mgr.get_custody_chain(meta.case_id, meta.evidence_id)
        # created event + transferred event
        assert len(events) >= 2
        types = [e["event_type"] for e in events]
        assert "created" in types
        assert "transferred" in types

    def test_list_cases_and_evidence(self):
        mgr, _ = _temp_manager()
        meta1 = MetadataCollector.new_session("CASE-004", "Analyst", "/dev/sda")
        meta2 = MetadataCollector.new_session("CASE-004", "Analyst", "/dev/sdb")
        mgr.create_evidence_entry(meta1)
        mgr.create_evidence_entry(meta2)

        cases = mgr.list_cases()
        assert "CASE-004" in cases

        evidence = mgr.list_evidence("CASE-004")
        assert meta1.evidence_id in evidence
        assert meta2.evidence_id in evidence

    def test_write_hash_file(self):
        mgr, _ = _temp_manager()
        meta = MetadataCollector.new_session("CASE-005", "Analyst", "/dev/sda")
        mgr.create_evidence_entry(meta)

        hash_path = mgr.write_hash_file(
            meta.case_id,
            meta.evidence_id,
            filename="image.dd",
            sha256="abc123",
            md5="def456",
        )
        assert hash_path.exists()
        content = hash_path.read_text()
        assert "SHA256: abc123" in content
        assert "MD5:    def456" in content
