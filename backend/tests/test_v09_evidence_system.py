"""
Tests for V0.9 — Evidence Management System
Covers: CaseManager, EvidenceIndex, VaultCrypto, updated EvidenceManager
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from core.acquisition.metadata_collector import MetadataCollector

# ── Helpers ───────────────────────────────────────────────────────────────────


def _tmp_base() -> Path:
    return Path(tempfile.mkdtemp())


def _make_meta(case_id: str = "CASE-TEST", examiner: str = "Analyst"):
    return MetadataCollector.new_session(
        case_id=case_id,
        examiner=examiner,
        device_id="/dev/sda",
        acquisition_method="physical",
    )


# ── CaseManager ───────────────────────────────────────────────────────────────


class TestCaseManager:
    def test_create_case(self):
        from core.chain_of_custody.case_manager import CaseManager

        mgr = CaseManager(base_path=_tmp_base())
        case = mgr.create_case(
            "CASE-001",
            examiner="Alice",
            title="Ransomware IR",
            tags=["ransomware", "windows"],
        )
        assert case.case_id == "CASE-001"
        assert case.examiner == "Alice"
        assert "ransomware" in case.tags

    def test_create_duplicate_returns_existing(self):
        from core.chain_of_custody.case_manager import CaseManager

        base = _tmp_base()
        mgr = CaseManager(base_path=base)
        mgr.create_case("CASE-DUP", examiner="Alice")
        case2 = mgr.create_case("CASE-DUP", examiner="Bob")
        assert case2.examiner == "Alice"  # Original preserved

    def test_get_case(self):
        from core.chain_of_custody.case_manager import CaseManager

        base = _tmp_base()
        mgr = CaseManager(base_path=base)
        mgr.create_case("CASE-002", examiner="Bob", description="Phishing")
        case = mgr.get_case("CASE-002")
        assert case is not None
        assert case.description == "Phishing"

    def test_update_case_status(self):
        from core.chain_of_custody.case_manager import CaseManager, CaseStatus

        base = _tmp_base()
        mgr = CaseManager(base_path=base)
        mgr.create_case("CASE-003", examiner="Carol")
        updated = mgr.update_case("CASE-003", status=CaseStatus.CLOSED)
        assert updated.status == CaseStatus.CLOSED
        assert updated.closed_at != ""

    def test_list_cases(self):
        from core.chain_of_custody.case_manager import CaseManager

        base = _tmp_base()
        mgr = CaseManager(base_path=base)
        mgr.create_case("CASE-A", examiner="Alice")
        mgr.create_case("CASE-B", examiner="Bob")
        cases = mgr.list_cases()
        ids = [c.case_id for c in cases]
        assert "CASE-A" in ids
        assert "CASE-B" in ids

    def test_search_cases(self):
        from core.chain_of_custody.case_manager import CaseManager

        base = _tmp_base()
        mgr = CaseManager(base_path=base)
        mgr.create_case("CASE-RANSOM", examiner="Alice", description="Ransomware attack")
        mgr.create_case("CASE-PHISH", examiner="Bob", description="Phishing campaign")
        results = mgr.search_cases("ransomware")
        assert len(results) == 1
        assert results[0].case_id == "CASE-RANSOM"

    def test_search_by_tag(self):
        from core.chain_of_custody.case_manager import CaseManager

        base = _tmp_base()
        mgr = CaseManager(base_path=base)
        mgr.create_case("CASE-T1", examiner="Alice", tags=["malware", "windows"])
        mgr.create_case("CASE-T2", examiner="Bob", tags=["phishing"])
        results = mgr.search_cases("malware")
        assert any(c.case_id == "CASE-T1" for c in results)

    def test_add_evidence_to_case(self):
        from core.chain_of_custody.case_manager import CaseManager

        base = _tmp_base()
        mgr = CaseManager(base_path=base)
        mgr.create_case("CASE-EV", examiner="Alice")
        mgr.add_evidence_to_case("CASE-EV", "EV-001")
        case = mgr.get_case("CASE-EV")
        assert "EV-001" in case.evidence_ids

    def test_registry_persists(self):
        from core.chain_of_custody.case_manager import CaseManager

        base = _tmp_base()
        mgr1 = CaseManager(base_path=base)
        mgr1.create_case("CASE-PERSIST", examiner="Alice")
        # New instance reads from disk
        mgr2 = CaseManager(base_path=base)
        case = mgr2.get_case("CASE-PERSIST")
        assert case is not None


# ── EvidenceIndex ─────────────────────────────────────────────────────────────


class TestEvidenceIndex:
    def test_index_evidence(self):
        from core.chain_of_custody.evidence_index import EvidenceIndex

        base = _tmp_base()
        idx = EvidenceIndex(base_path=base)
        entry = idx.index_evidence(
            "CASE-001",
            "EV-001",
            tags=["ransomware", "windows"],
            metadata={"examiner": "Alice", "hash_sha256": "abc123"},
        )
        assert entry.evidence_id == "EV-001"
        assert "ransomware" in entry.tags

    def test_search(self):
        from core.chain_of_custody.evidence_index import EvidenceIndex

        base = _tmp_base()
        idx = EvidenceIndex(base_path=base)
        idx.index_evidence(
            "CASE-001", "EV-001", tags=["ransomware"], metadata={"examiner": "Alice"}
        )
        idx.index_evidence("CASE-001", "EV-002", tags=["phishing"], metadata={"examiner": "Bob"})
        results = idx.search("alice")
        assert len(results) == 1
        assert results[0].evidence_id == "EV-001"

    def test_get_by_tag(self):
        from core.chain_of_custody.evidence_index import EvidenceIndex

        base = _tmp_base()
        idx = EvidenceIndex(base_path=base)
        idx.index_evidence("CASE-001", "EV-001", tags=["malware"])
        idx.index_evidence("CASE-001", "EV-002", tags=["phishing"])
        results = idx.get_by_tag("malware")
        assert len(results) == 1
        assert results[0].evidence_id == "EV-001"

    def test_get_by_case(self):
        from core.chain_of_custody.evidence_index import EvidenceIndex

        base = _tmp_base()
        idx = EvidenceIndex(base_path=base)
        idx.index_evidence("CASE-A", "EV-001", metadata={})
        idx.index_evidence("CASE-A", "EV-002", metadata={})
        idx.index_evidence("CASE-B", "EV-003", metadata={})
        results = idx.get_by_case("CASE-A")
        assert len(results) == 2

    def test_update_tags(self):
        from core.chain_of_custody.evidence_index import EvidenceIndex

        base = _tmp_base()
        idx = EvidenceIndex(base_path=base)
        idx.index_evidence("CASE-001", "EV-001", tags=["old"])
        idx.update_tags("EV-001", ["new", "updated"])
        entry = idx.get_entry("EV-001")
        assert "new" in entry.tags
        assert "old" not in entry.tags

    def test_get_unverified(self):
        from core.chain_of_custody.evidence_index import EvidenceIndex

        base = _tmp_base()
        idx = EvidenceIndex(base_path=base)
        idx.index_evidence("CASE-001", "EV-001", metadata={"verified": False})
        idx.index_evidence("CASE-001", "EV-002", metadata={"verified": True})
        unverified = idx.get_unverified()
        ids = [e.evidence_id for e in unverified]
        assert "EV-001" in ids
        assert "EV-002" not in ids

    def test_all_tags(self):
        from core.chain_of_custody.evidence_index import EvidenceIndex

        base = _tmp_base()
        idx = EvidenceIndex(base_path=base)
        idx.index_evidence("CASE-001", "EV-001", tags=["alpha", "beta"])
        idx.index_evidence("CASE-001", "EV-002", tags=["beta", "gamma"])
        tags = idx.all_tags()
        assert tags == ["alpha", "beta", "gamma"]

    def test_rebuild(self):
        from core.chain_of_custody.evidence_index import EvidenceIndex
        from core.chain_of_custody.evidence_manager import EvidenceManager

        base = _tmp_base()
        mgr = EvidenceManager(base_path=base)
        meta1 = _make_meta("CASE-RB")
        meta2 = _make_meta("CASE-RB")
        mgr.create_evidence_entry(meta1)
        mgr.write_metadata(meta1)
        mgr.create_evidence_entry(meta2)
        mgr.write_metadata(meta2)
        idx = EvidenceIndex(base_path=base)
        count = idx.rebuild()
        assert count == 2


# ── VaultCrypto ───────────────────────────────────────────────────────────────


class TestVaultCrypto:
    def test_generate_key(self):
        from core.chain_of_custody.vault_crypto import VaultCrypto

        key = VaultCrypto.generate_key()
        assert len(key) == 32

    def test_key_b64_roundtrip(self):
        from core.chain_of_custody.vault_crypto import VaultCrypto

        key = VaultCrypto.generate_key()
        b64 = VaultCrypto.key_to_b64(key)
        restored = VaultCrypto.key_from_b64(b64)
        assert key == restored

    def test_encrypt_decrypt_file(self):
        from core.chain_of_custody.vault_crypto import CRYPTO_AVAILABLE, VaultCrypto

        if not CRYPTO_AVAILABLE:
            pytest.skip("cryptography not installed")

        tmp = Path(tempfile.mkdtemp())
        src = tmp / "test.dd"
        enc = tmp / "test.dd.enc"
        dec = tmp / "test.dd.restored"

        data = b"ForgeLens test data " * 1000
        src.write_bytes(data)

        key = VaultCrypto.generate_key()
        assert VaultCrypto.encrypt_file(src, enc, key) is True
        assert enc.exists()
        assert enc.stat().st_size > 0

        assert VaultCrypto.decrypt_file(enc, dec, key) is True
        assert dec.read_bytes() == data

    def test_decrypt_wrong_key_fails(self):
        from core.chain_of_custody.vault_crypto import CRYPTO_AVAILABLE, VaultCrypto

        if not CRYPTO_AVAILABLE:
            pytest.skip("cryptography not installed")

        tmp = Path(tempfile.mkdtemp())
        src = tmp / "test.dd"
        enc = tmp / "test.dd.enc"
        dec = tmp / "test.dd.bad"

        src.write_bytes(b"secret data")
        key = VaultCrypto.generate_key()
        VaultCrypto.encrypt_file(src, enc, key)

        wrong_key = VaultCrypto.generate_key()
        result = VaultCrypto.decrypt_file(enc, dec, wrong_key)
        assert result is False

    def test_sign_and_verify_metadata(self):
        from core.chain_of_custody.vault_crypto import VaultCrypto

        key = VaultCrypto.generate_key()
        metadata = {"evidence_id": "EV-001", "hash_sha256": "abc123", "verified": True}
        sig = VaultCrypto.sign_metadata(metadata, key)
        assert VaultCrypto.verify_signature(metadata, sig, key) is True

    def test_tampered_metadata_fails_verification(self):
        from core.chain_of_custody.vault_crypto import VaultCrypto

        key = VaultCrypto.generate_key()
        metadata = {"evidence_id": "EV-001", "hash_sha256": "abc123"}
        sig = VaultCrypto.sign_metadata(metadata, key)
        # Tamper with metadata
        metadata["hash_sha256"] = "tampered"
        assert VaultCrypto.verify_signature(metadata, sig, key) is False

    def test_write_and_read_signed_metadata(self):
        from core.chain_of_custody.vault_crypto import VaultCrypto

        tmp = Path(tempfile.mkdtemp())
        key = VaultCrypto.generate_key()
        metadata = {"evidence_id": "EV-001", "examiner": "Alice", "verified": True}

        path = VaultCrypto.write_signed_metadata(metadata, tmp / "meta.signed.json", key)
        assert path.exists()

        loaded, is_valid = VaultCrypto.read_and_verify_metadata(path, key)
        assert is_valid is True
        assert loaded["evidence_id"] == "EV-001"

    def test_derive_key_from_password(self):
        from core.chain_of_custody.vault_crypto import VaultCrypto

        key1, salt = VaultCrypto.derive_key_from_password("test-password")
        key2, _ = VaultCrypto.derive_key_from_password("test-password", salt=salt)
        assert key1 == key2
        assert len(key1) == 32


# ── Updated EvidenceManager ───────────────────────────────────────────────────


class TestEvidenceManagerV09:
    def test_tagging(self):
        from core.chain_of_custody.evidence_manager import EvidenceManager

        base = _tmp_base()
        mgr = EvidenceManager(base_path=base)
        meta = _make_meta()
        mgr.create_evidence_entry(meta)
        mgr.tag_evidence(meta.case_id, meta.evidence_id, ["ransomware", "windows"])
        tags = mgr.get_tags(meta.case_id, meta.evidence_id)
        assert "ransomware" in tags
        assert "windows" in tags

    def test_tags_merge_dedup(self):
        from core.chain_of_custody.evidence_manager import EvidenceManager

        base = _tmp_base()
        mgr = EvidenceManager(base_path=base)
        meta = _make_meta()
        mgr.create_evidence_entry(meta)
        mgr.tag_evidence(meta.case_id, meta.evidence_id, ["alpha", "beta"])
        mgr.tag_evidence(meta.case_id, meta.evidence_id, ["beta", "gamma"])
        tags = mgr.get_tags(meta.case_id, meta.evidence_id)
        assert tags == ["alpha", "beta", "gamma"]

    def test_custody_event_has_seq(self):
        from core.chain_of_custody.evidence_manager import EvidenceManager

        base = _tmp_base()
        mgr = EvidenceManager(base_path=base)
        meta = _make_meta()
        mgr.create_evidence_entry(meta)
        mgr.record_custody_event(meta.evidence_id, meta.case_id, "analyzed", "Alice")
        events = mgr.get_custody_chain(meta.case_id, meta.evidence_id)
        seqs = [e["seq"] for e in events]
        assert seqs == list(range(1, len(seqs) + 1))

    def test_audit_trail_across_evidence(self):
        from core.chain_of_custody.evidence_manager import EvidenceManager

        base = _tmp_base()
        mgr = EvidenceManager(base_path=base)
        meta1 = _make_meta("CASE-AUDIT")
        meta2 = _make_meta("CASE-AUDIT")
        mgr.create_evidence_entry(meta1)
        mgr.create_evidence_entry(meta2)
        trail = mgr.get_audit_trail("CASE-AUDIT")
        assert len(trail) >= 2
        # Should be time-sorted
        timestamps = [e["timestamp"] for e in trail]
        assert timestamps == sorted(timestamps)

    def test_write_and_verify_signed_metadata(self):
        from core.chain_of_custody.evidence_manager import EvidenceManager
        from core.chain_of_custody.vault_crypto import CRYPTO_AVAILABLE, VaultCrypto

        if not CRYPTO_AVAILABLE:
            pytest.skip("cryptography not installed")

        base = _tmp_base()
        mgr = EvidenceManager(base_path=base)
        meta = _make_meta()
        mgr.create_evidence_entry(meta)
        mgr.write_metadata(meta)

        key = VaultCrypto.generate_key()
        mgr.write_signed_metadata(meta, key)

        loaded, is_valid = mgr.verify_signed_metadata(meta.case_id, meta.evidence_id, key)
        assert is_valid is True
        assert loaded["evidence_id"] == meta.evidence_id

    def test_auto_index_on_create(self):
        from core.chain_of_custody.evidence_index import EvidenceIndex
        from core.chain_of_custody.evidence_manager import EvidenceManager

        base = _tmp_base()
        mgr = EvidenceManager(base_path=base)
        meta = _make_meta("CASE-IDX")
        mgr.create_evidence_entry(meta)
        mgr.write_metadata(meta)

        idx = EvidenceIndex(base_path=base)
        entry = idx.get_entry(meta.evidence_id)
        assert entry is not None
        assert entry.case_id == "CASE-IDX"
