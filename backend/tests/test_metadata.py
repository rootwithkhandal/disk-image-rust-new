"""Tests for the metadata collector."""

from core.acquisition.metadata_collector import MetadataCollector


class TestMetadataCollector:
    def test_collect_system(self):
        meta = MetadataCollector.collect_system()
        assert meta.hostname != ""
        assert meta.os_name != ""
        assert meta.python_version != ""
        assert meta.ram_total_gb > 0

    def test_new_session(self):
        meta = MetadataCollector.new_session(
            case_id="CASE-TEST-001",
            examiner="Test Examiner",
            device_id="/dev/sda",
            acquisition_method="physical",
            notes="Unit test session",
        )
        assert meta.case_id == "CASE-TEST-001"
        assert meta.examiner == "Test Examiner"
        assert meta.evidence_id.startswith("EV-")
        assert meta.session_id != ""
        assert meta.timestamp_utc != ""
        assert meta.system is not None
        assert meta.device is not None

    def test_finalize(self):
        meta = MetadataCollector.new_session(
            case_id="CASE-TEST-002",
            examiner="Analyst",
            device_id="/dev/sdb",
        )
        meta = MetadataCollector.finalize(
            meta,
            hash_sha256="abc123",
            hash_md5="def456",
            bytes_acquired=1024,
            output_path="/evidence/image.dd",
            verified=True,
        )
        assert meta.hash_sha256 == "abc123"
        assert meta.hash_md5 == "def456"
        assert meta.bytes_acquired == 1024
        assert meta.verified is True
        assert meta.acquisition_end != ""
        assert meta.duration_seconds >= 0

    def test_to_dict(self):
        meta = MetadataCollector.new_session(
            case_id="CASE-TEST-003",
            examiner="Analyst",
            device_id="test",
        )
        d = meta.to_dict()
        assert isinstance(d, dict)
        assert "evidence_id" in d
        assert "case_id" in d
