"""
Tests for V2.0 — Enterprise DFIR Platform
Covers: CaseOrchestrator, SIEMConnector, ThreatIntelManager, CloudAcquisition
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from core.enterprise.case_orchestrator import CaseDashboard, CaseOrchestrator
from core.enterprise.cloud_acquisition import CloudAcquisition, CloudAcquisitionResult
from core.enterprise.siem_integration import SIEMConnector, SIEMEvent, SIEMPlatform
from core.enterprise.threat_intel import LookupResult, ThreatIntelManager

# ── CaseOrchestrator ──────────────────────────────────────────────────────────


class TestCaseOrchestrator:
    def _orch(self) -> CaseOrchestrator:
        return CaseOrchestrator(base_path=Path(tempfile.mkdtemp()))

    def test_assign_examiner(self):
        orch = self._orch()
        orch._case_mgr.create_case("CASE-001", examiner="Alice")
        assignment = orch.assign_examiner("CASE-001", "Bob", role="analyst")
        assert assignment.examiner == "Bob"
        assert assignment.case_id == "CASE-001"

    def test_get_assignments(self):
        orch = self._orch()
        orch._case_mgr.create_case("CASE-002", examiner="Alice")
        orch.assign_examiner("CASE-002", "Alice")
        orch.assign_examiner("CASE-002", "Bob")
        assignments = orch.get_assignments("CASE-002")
        assert len(assignments) == 2

    def test_escalate_case(self):
        orch = self._orch()
        orch._case_mgr.create_case("CASE-003", examiner="Alice", priority="medium")
        result = orch.escalate_case("CASE-003", reason="Ransomware confirmed")
        assert result is True
        case = orch._case_mgr.get_case("CASE-003")
        assert case.priority == "critical"

    def test_close_case(self):
        from core.chain_of_custody.case_manager import CaseStatus

        orch = self._orch()
        orch._case_mgr.create_case("CASE-004", examiner="Alice")
        result = orch.close_case("CASE-004", examiner="Alice", notes="Investigation complete")
        assert result is True
        case = orch._case_mgr.get_case("CASE-004")
        assert case.status == CaseStatus.CLOSED

    def test_get_dashboard(self):
        orch = self._orch()
        orch._case_mgr.create_case("CASE-A", examiner="Alice", priority="critical")
        orch._case_mgr.create_case("CASE-B", examiner="Bob", priority="high")
        dashboard = orch.get_dashboard()
        assert isinstance(dashboard, CaseDashboard)
        assert dashboard.total_cases == 2
        assert "CASE-A" in dashboard.critical_cases
        assert "CASE-B" in dashboard.high_cases

    def test_unassigned_cases_in_dashboard(self):
        orch = self._orch()
        orch._case_mgr.create_case("CASE-UNASSIGNED", examiner="Alice")
        dashboard = orch.get_dashboard()
        assert "CASE-UNASSIGNED" in dashboard.unassigned_cases

    def test_get_workload(self):
        orch = self._orch()
        orch._case_mgr.create_case("CASE-W1", examiner="Alice")
        orch._case_mgr.create_case("CASE-W2", examiner="Alice")
        orch.assign_examiner("CASE-W1", "Alice")
        orch.assign_examiner("CASE-W2", "Alice")
        workload = orch.get_workload("Alice")
        assert "CASE-W1" in workload
        assert "CASE-W2" in workload

    def test_assignments_persist(self):
        base = Path(tempfile.mkdtemp())
        orch1 = CaseOrchestrator(base_path=base)
        orch1._case_mgr.create_case("CASE-P", examiner="Alice")
        orch1.assign_examiner("CASE-P", "Alice")
        orch2 = CaseOrchestrator(base_path=base)
        assignments = orch2.get_assignments("CASE-P")
        assert len(assignments) == 1


# ── SIEMConnector ─────────────────────────────────────────────────────────────


class TestSIEMConnector:
    def test_send_event_no_endpoint(self):
        """Without endpoint, events are logged but not sent — should succeed."""
        conn = SIEMConnector(platform=SIEMPlatform.GENERIC)
        result = conn.send_event({"event_type": "test", "data": "value"})
        assert result.success is True
        assert result.events_sent == 1

    def test_send_acquisition_event(self):
        conn = SIEMConnector()
        metadata = {
            "evidence_id": "EV-001",
            "case_id": "CASE-001",
            "examiner": "Alice",
            "hash_sha256": "abc123",
            "verified": True,
            "bytes_acquired": 1024,
        }
        result = conn.send_acquisition_event(metadata)
        assert result.success is True

    def test_send_ioc_alert_empty_report(self):
        from core.ai.ioc_prioritizer import IOCReport

        conn = SIEMConnector()
        report = IOCReport(total_iocs=0)
        result = conn.send_ioc_alert(report)
        assert result.success is True
        assert result.events_sent == 0

    def test_send_ioc_alert_with_p1(self):
        from core.ai.ioc_prioritizer import IOCReport, PrioritizedIOC

        conn = SIEMConnector()
        report = IOCReport(total_iocs=1)
        report.p1_critical.append(
            PrioritizedIOC(
                ioc_type="domain",
                ioc_value="evil.com",
                score=9.5,
                priority="P1",
                severity="critical",
                recommended_action="Block immediately",
            )
        )
        result = conn.send_ioc_alert(report)
        assert result.success is True
        assert result.events_sent == 1

    def test_send_anomaly_alert(self):
        from core.ai.anomaly_detector import Anomaly, AnomalyReport

        conn = SIEMConnector()
        report = AnomalyReport(total_anomalies=1)
        report.critical.append(
            Anomaly(
                anomaly_type="process",
                description="Mimikatz detected",
                severity="critical",
                score=9.5,
            )
        )
        result = conn.send_anomaly_alert(report)
        assert result.success is True

    def test_test_connection_no_endpoint(self):
        conn = SIEMConnector()
        assert conn.test_connection() is False

    def test_sev_to_cef(self):
        assert SIEMConnector._sev_to_cef("critical") == 10
        assert SIEMConnector._sev_to_cef("high") == 7
        assert SIEMConnector._sev_to_cef("low") == 3

    def test_siem_event_defaults(self):
        ev = SIEMEvent(event_type="test", severity="info")
        assert ev.source == "forgelens"
        assert ev.timestamp != ""
        assert ev.data == {}


# ── ThreatIntelManager ────────────────────────────────────────────────────────


class TestThreatIntelManager:
    def _mgr(self) -> ThreatIntelManager:
        return ThreatIntelManager(base_path=Path(tempfile.mkdtemp()))

    def test_builtin_indicators_seeded(self):
        mgr = self._mgr()
        assert mgr.cache_size > 0

    def test_lookup_known_bad_domain(self):
        mgr = self._mgr()
        result = mgr.lookup("evil.com")
        assert result.found is True
        assert result.verdict == "malicious"
        assert result.risk_score >= 80

    def test_lookup_known_bad_ip(self):
        mgr = self._mgr()
        result = mgr.lookup("10.0.0.99")
        assert result.found is True
        assert result.verdict in ("malicious", "suspicious")

    def test_lookup_known_bad_hash(self):
        mgr = self._mgr()
        result = mgr.lookup("44d88612fea8a8f36de82e1278abb02f")
        assert result.found is True
        assert result.verdict == "malicious"

    def test_lookup_unknown_returns_not_found(self):
        mgr = self._mgr()
        result = mgr.lookup("totally-clean-domain.com")
        assert result.found is False
        assert result.verdict == "unknown"

    def test_lookup_case_insensitive(self):
        mgr = self._mgr()
        result = mgr.lookup("EVIL.COM")
        assert result.found is True

    def test_bulk_lookup(self):
        mgr = self._mgr()
        results = mgr.bulk_lookup(["evil.com", "google.com", "10.0.0.99"])
        assert len(results) == 3
        assert results["evil.com"].found is True
        assert results["google.com"].found is False

    def test_add_feed(self):
        mgr = self._mgr()
        feed = mgr.add_feed("test_feed", "https://example.com/iocs", feed_type="generic")
        assert feed.name == "test_feed"
        feeds = mgr.list_feeds()
        assert any(f.name == "test_feed" for f in feeds)

    def test_enrich_ioc_report(self):
        from core.ai.ioc_prioritizer import IOCPrioritizer

        mgr = self._mgr()
        prioritizer = IOCPrioritizer()
        iocs = [
            {"ioc_type": "domain", "ioc_value": "evil.com"},
            {"ioc_type": "domain", "ioc_value": "google.com"},
        ]
        report = prioritizer.generate_report(prioritizer.prioritize(iocs))
        enriched = mgr.enrich_ioc_report(report)
        assert isinstance(enriched, dict)

    def test_lookup_result_dataclass(self):
        result = LookupResult(value="test.com", found=False, verdict="unknown")
        assert result.found is False
        assert result.risk_score == 0

    def test_cache_persists(self):
        base = Path(tempfile.mkdtemp())
        mgr1 = ThreatIntelManager(base_path=base)
        mgr1._cache["custom-ioc.com"] = {"ioc_type": "domain", "severity": "high", "confidence": 90}
        mgr1._save_cache()
        mgr2 = ThreatIntelManager(base_path=base)
        result = mgr2.lookup("custom-ioc.com")
        assert result.found is True


# ── CloudAcquisition ──────────────────────────────────────────────────────────


class TestCloudAcquisition:
    def test_acquire_aws_snapshot_no_cli(self):
        """Without AWS CLI, should fail gracefully."""
        acq = CloudAcquisition()
        tmp = Path(tempfile.mkdtemp())
        result = acq.acquire_aws_snapshot("vol-fake123", tmp)
        # Either succeeds (if aws cli present) or fails gracefully
        assert isinstance(result, CloudAcquisitionResult)
        assert result.provider == "aws"

    def test_collect_aws_iam_no_cli(self):
        acq = CloudAcquisition()
        tmp = Path(tempfile.mkdtemp())
        result = acq.collect_aws_iam_artifacts(tmp)
        assert isinstance(result, CloudAcquisitionResult)
        assert result.provider == "aws"

    def test_acquire_docker_container_no_docker(self):
        acq = CloudAcquisition()
        tmp = Path(tempfile.mkdtemp())
        result = acq.acquire_docker_container("fake_container_id", tmp)
        assert isinstance(result, CloudAcquisitionResult)
        assert result.provider == "docker"

    def test_collect_docker_artifacts_no_docker(self):
        acq = CloudAcquisition()
        tmp = Path(tempfile.mkdtemp())
        result = acq.collect_docker_artifacts(tmp)
        assert isinstance(result, CloudAcquisitionResult)
        assert result.provider == "docker"

    def test_collect_kubernetes_no_kubectl(self):
        acq = CloudAcquisition()
        tmp = Path(tempfile.mkdtemp())
        result = acq.collect_kubernetes_artifacts(namespace="default", output_dir=tmp)
        assert isinstance(result, CloudAcquisitionResult)
        assert result.provider == "kubernetes"

    def test_cloud_result_dataclass(self):
        result = CloudAcquisitionResult(
            success=True,
            provider="aws",
            resource_id="snap-123",
            output_path="/evidence/snap.json",
            size_bytes=1024,
        )
        assert result.success is True
        assert result.provider == "aws"
