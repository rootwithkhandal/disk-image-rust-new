"""
Tests for V1.4 — AI-Assisted Analysis
Covers: EvidenceSummarizer, ActivityExplainer, TimelineNarrator,
        IOCPrioritizer, AnomalyDetector
"""

from __future__ import annotations

from core.ai.anomaly_detector import Anomaly, AnomalyDetector, AnomalyReport
from core.ai.explainer import ActivityExplainer, Explanation
from core.ai.ioc_prioritizer import IOCPrioritizer, IOCReport, PrioritizedIOC
from core.ai.summarizer import EvidenceSummarizer, Summary
from core.ai.timeline_narrator import TimelineNarrator, TimelineStory

# ── EvidenceSummarizer ────────────────────────────────────────────────────────


class TestEvidenceSummarizer:
    def _meta(self, verified=True) -> dict:
        return {
            "evidence_id": "EV-TEST001",
            "case_id": "CASE-2026-001",
            "examiner": "Alice",
            "acquisition_method": "physical",
            "verified": verified,
            "hash_sha256": "abc123def456" * 4,
            "bytes_acquired": 1073741824,  # 1 GB
            "duration_seconds": 10.5,
            "timestamp_utc": "2026-05-22T14:42:41+00:00",
            "device": {"device_id": "/dev/sda", "model": "Samsung SSD"},
        }

    def test_summarize_acquisition_verified(self):
        s = EvidenceSummarizer()
        summary = s.summarize_acquisition(self._meta(verified=True))
        assert isinstance(summary, Summary)
        assert summary.risk_level == "low"
        assert "verified" in summary.narrative.lower() or "integrity" in summary.narrative.lower()
        assert len(summary.key_findings) > 0

    def test_summarize_acquisition_unverified(self):
        s = EvidenceSummarizer()
        summary = s.summarize_acquisition(self._meta(verified=False))
        assert summary.risk_level in ("medium", "high")
        assert any("NOT" in f or "not" in f.lower() for f in summary.key_findings)

    def test_summarize_acquisition_fields(self):
        s = EvidenceSummarizer()
        summary = s.summarize_acquisition(self._meta())
        assert "EV-TEST001" in summary.title
        assert summary.confidence > 0
        assert summary.generated_at != ""
        assert summary.source_type == "acquisition"

    def test_summarize_artifacts_clean(self):
        s = EvidenceSummarizer()
        summary = s.summarize_artifacts({}, platform="windows")
        assert isinstance(summary, Summary)
        assert summary.risk_level == "low"

    def test_summarize_artifacts_suspicious(self):
        s = EvidenceSummarizer()
        data = {
            "run_keys": [{"value_name": "evil", "value_data": "cmd.exe", "is_suspicious": True}],
            "processes": [{"name": "mimikatz.exe", "_suspicious": True}],
        }
        summary = s.summarize_artifacts(data, platform="windows")
        assert summary.risk_level in ("high", "critical")
        assert any("suspicious" in f.lower() or "⚠" in f for f in summary.key_findings)

    def test_summarize_case(self):
        s = EvidenceSummarizer()
        case = {
            "case_id": "CASE-001",
            "examiner": "Bob",
            "status": "active",
            "tags": ["ransomware"],
        }
        evidence = [
            {"verified": True, "bytes_acquired": 1024**3},
            {"verified": False, "bytes_acquired": 512**3},
        ]
        summary = s.summarize_case(case, evidence)
        assert "CASE-001" in summary.title
        assert summary.risk_level in ("low", "medium")
        assert any("ransomware" in f.lower() for f in summary.key_findings)

    def test_summary_str(self):
        summary = Summary(
            title="Test",
            narrative="Test narrative",
            key_findings=["Finding 1"],
            risk_level="high",
        )
        s = str(summary)
        assert "HIGH" in s
        assert "Test" in s


# ── ActivityExplainer ─────────────────────────────────────────────────────────


class TestActivityExplainer:
    def test_explain_known_process(self):
        e = ActivityExplainer()
        proc = {"ImageFileName": "mimikatz.exe", "PID": 4096, "PPID": 2048}
        explanation = e.explain_process(proc)
        assert explanation.severity == "critical"
        assert "credential" in explanation.what_it_is.lower()
        assert explanation.mitre_technique == "T1003.001"
        assert explanation.confidence > 0.9

    def test_explain_unknown_process(self):
        e = ActivityExplainer()
        proc = {
            "ImageFileName": "unknown_tool.exe",
            "PID": 9999,
            "_suspicious_reasons": ["Suspicious path"],
        }
        explanation = e.explain_process(proc)
        assert isinstance(explanation, Explanation)
        assert explanation.severity in ("low", "medium", "high", "critical")

    def test_explain_ioc_domain(self):
        e = ActivityExplainer()
        explanation = e.explain_ioc("evil.com", "domain")
        assert explanation.severity == "high"
        assert "evil.com" in explanation.subject
        assert explanation.mitre_technique != ""

    def test_explain_ioc_ip(self):
        e = ActivityExplainer()
        explanation = e.explain_ioc("10.0.0.99", "ip")
        assert isinstance(explanation, Explanation)
        assert "10.0.0.99" in explanation.subject

    def test_explain_persistence_run_key(self):
        e = ActivityExplainer()
        entry = {
            "mechanism": "run_key",
            "name": "Updater",
            "command": "C:\\temp\\update.exe",
            "is_suspicious": True,
            "reason": "Suspicious path",
        }
        explanation = e.explain_persistence(entry)
        assert explanation.severity == "high"
        assert explanation.mitre_technique == "T1547.001"

    def test_explain_malfind(self):
        e = ActivityExplainer()
        entry = {"Process": "cmd.exe", "PID": 4200, "Protection": "PAGE_EXECUTE_READWRITE"}
        explanation = e.explain_malfind(entry)
        assert explanation.severity == "critical"
        assert explanation.mitre_technique == "T1055"

    def test_explain_high_entropy(self):
        e = ActivityExplainer()
        explanation = e.explain_high_entropy("/evidence/payload.bin", 7.8)
        assert explanation.severity == "high"
        assert "7.8" in explanation.why_suspicious

    def test_batch_explain(self):
        e = ActivityExplainer()
        items = [
            {"ImageFileName": "mimikatz.exe", "PID": 1},
            {"ImageFileName": "psexec.exe", "PID": 2},
        ]
        explanations = e.batch_explain(items, "process")
        assert len(explanations) == 2
        assert all(isinstance(ex, Explanation) for ex in explanations)

    def test_explanation_str(self):
        ex = Explanation(
            subject="mimikatz.exe",
            severity="critical",
            what_it_is="Credential dumper",
            why_suspicious="Known malware",
            analyst_action="Isolate system",
        )
        s = str(ex)
        assert "CRITICAL" in s
        assert "mimikatz.exe" in s


# ── TimelineNarrator ──────────────────────────────────────────────────────────


class TestTimelineNarrator:
    def _events(self) -> list[dict]:
        return [
            {
                "timestamp": "2026-05-22T08:00:00Z",
                "event_type": "process_create",
                "process_name": "System",
                "pid": 4,
                "is_suspicious": False,
            },
            {
                "timestamp": "2026-05-22T14:30:11Z",
                "event_type": "process_create",
                "process_name": "mimikatz.exe",
                "pid": 4096,
                "is_suspicious": True,
            },
            {
                "timestamp": "2026-05-22T14:30:12Z",
                "event_type": "network",
                "process_name": "mimikatz.exe",
                "pid": 4096,
                "is_suspicious": True,
            },
            {
                "timestamp": "2026-05-22T14:30:13Z",
                "event_type": "process_create",
                "process_name": "cmd.exe",
                "pid": 4200,
                "is_suspicious": True,
            },
        ]

    def test_narrate_basic(self):
        n = TimelineNarrator()
        story = n.narrate(self._events())
        assert isinstance(story, TimelineStory)
        assert story.total_events == 4
        assert story.suspicious_events == 3
        assert story.risk_level in ("medium", "high", "critical")

    def test_narrate_empty(self):
        n = TimelineNarrator()
        story = n.narrate([])
        assert story.total_events == 0
        assert "No timeline" in story.narrative

    def test_narrate_detects_phases(self):
        n = TimelineNarrator()
        story = n.narrate(self._events())
        # mimikatz.exe should trigger credential_access phase
        phase_names = [p.phase_name for p in story.attack_phases]
        assert "credential_access" in phase_names

    def test_narrate_narrative_mentions_mimikatz(self):
        n = TimelineNarrator()
        story = n.narrate(self._events())
        assert "mimikatz" in story.narrative.lower() or "credential" in story.narrative.lower()

    def test_narrate_timeline_bounds(self):
        n = TimelineNarrator()
        story = n.narrate(self._events())
        assert "2026-05-22" in story.timeline_start
        assert "2026-05-22" in story.timeline_end

    def test_narrate_process_tree(self):
        n = TimelineNarrator()
        processes = [
            {
                "ImageFileName": "mimikatz.exe",
                "PID": 4096,
                "_suspicious": True,
                "_suspicious_reasons": ["Known credential dumper"],
            },
            {"ImageFileName": "System", "PID": 4, "_suspicious": False},
        ]
        narrative = n.narrate_process_tree(processes)
        assert "mimikatz" in narrative.lower()
        assert "suspicious" in narrative.lower()

    def test_story_str(self):
        n = TimelineNarrator()
        story = n.narrate(self._events())
        s = str(story)
        assert story.title in s


# ── IOCPrioritizer ────────────────────────────────────────────────────────────


class TestIOCPrioritizer:
    def _iocs(self) -> list[dict]:
        return [
            {
                "ioc_type": "domain",
                "ioc_value": "evil.com",
                "matched_in": "log.txt",
                "context": "C2",
            },
            {
                "ioc_type": "ip",
                "ioc_value": "10.0.0.99",
                "matched_in": "netlog.txt",
                "context": "beacon",
            },
            {
                "ioc_type": "domain",
                "ioc_value": "evil.com",
                "matched_in": "memory.txt",
                "context": "DNS",
            },
            {
                "ioc_type": "domain",
                "ioc_value": "google.com",
                "matched_in": "browser.txt",
                "context": "",
            },
            {
                "ioc_type": "hash",
                "ioc_value": "44d88612fea8a8f36de82e1278abb02f",
                "matched_in": "file.exe",
            },
        ]

    def test_prioritize_returns_list(self):
        p = IOCPrioritizer()
        ranked = p.prioritize(self._iocs())
        assert isinstance(ranked, list)
        assert len(ranked) > 0

    def test_deduplication(self):
        p = IOCPrioritizer()
        ranked = p.prioritize(self._iocs())
        # evil.com appears twice but should be deduplicated
        evil_entries = [r for r in ranked if r.ioc_value == "evil.com"]
        assert len(evil_entries) == 1
        assert evil_entries[0].occurrences == 2

    def test_known_bad_gets_high_score(self):
        p = IOCPrioritizer()
        ranked = p.prioritize(self._iocs())
        evil = next((r for r in ranked if r.ioc_value == "evil.com"), None)
        assert evil is not None
        assert evil.is_known_bad is True
        assert evil.score >= 9.0

    def test_known_bad_hash_critical(self):
        p = IOCPrioritizer()
        ranked = p.prioritize(self._iocs())
        h = next((r for r in ranked if r.ioc_type == "hash"), None)
        assert h is not None
        assert h.priority in ("P1", "P2")

    def test_sorted_by_score(self):
        p = IOCPrioritizer()
        ranked = p.prioritize(self._iocs())
        scores = [r.score for r in ranked]
        assert scores == sorted(scores, reverse=True)

    def test_generate_report(self):
        p = IOCPrioritizer()
        ranked = p.prioritize(self._iocs())
        report = p.generate_report(ranked)
        assert isinstance(report, IOCReport)
        assert report.total_iocs == len(ranked)
        assert report.summary != ""
        assert report.generated_at != ""

    def test_report_action_required_count(self):
        p = IOCPrioritizer()
        ranked = p.prioritize(self._iocs())
        report = p.generate_report(ranked)
        assert report.action_required_count == len(report.p1_critical) + len(report.p2_high)

    def test_empty_iocs(self):
        p = IOCPrioritizer()
        ranked = p.prioritize([])
        assert ranked == []
        report = p.generate_report(ranked)
        assert report.total_iocs == 0

    def test_prioritized_ioc_str(self):
        ioc = PrioritizedIOC(
            ioc_type="domain",
            ioc_value="evil.com",
            score=9.5,
            priority="P1",
            severity="critical",
        )
        s = str(ioc)
        assert "P1" in s
        assert "evil.com" in s


# ── AnomalyDetector ───────────────────────────────────────────────────────────


class TestAnomalyDetector:
    def _processes(self) -> list[dict]:
        return [
            {"ImageFileName": "winword.exe", "PID": 1000, "PPID": 500},
            {"ImageFileName": "cmd.exe", "PID": 1001, "PPID": 1000},  # word -> cmd = suspicious
            {"ImageFileName": "mimikatz.exe", "PID": 1002, "PPID": 1001, "_suspicious": True},
            {"ImageFileName": "psexec.exe", "PID": 1003, "PPID": 1001},
            {"ImageFileName": "explorer.exe", "PID": 500, "PPID": 0},
        ]

    def _connections(self) -> list[dict]:
        return [
            {"Owner": "mimikatz.exe", "PID": 1002, "ForeignAddr": "10.0.0.99", "ForeignPort": 4444},
            {
                "Owner": "chrome.exe",
                "PID": 2000,
                "ForeignAddr": "142.250.80.46",
                "ForeignPort": 443,
            },
        ]

    def test_analyze_processes(self):
        d = AnomalyDetector()
        report = d.analyze(processes=self._processes())
        assert isinstance(report, AnomalyReport)
        assert report.total_anomalies > 0

    def test_detects_suspicious_parent_child(self):
        d = AnomalyDetector()
        report = d.analyze(processes=self._processes())
        all_a = report.all_anomalies
        parent_child = [
            a
            for a in all_a
            if "parent-child" in a.description.lower() or "spawned" in a.description.lower()
        ]
        assert len(parent_child) > 0

    def test_detects_lateral_movement(self):
        d = AnomalyDetector()
        report = d.analyze(processes=self._processes())
        lateral = [a for a in report.all_anomalies if a.anomaly_type == "lateral_movement"]
        assert len(lateral) > 0

    def test_detects_suspicious_port(self):
        d = AnomalyDetector()
        report = d.analyze(connections=self._connections())
        port_anomalies = [a for a in report.all_anomalies if "4444" in a.description]
        assert len(port_anomalies) > 0

    def test_correlates_process_and_network(self):
        d = AnomalyDetector()
        report = d.analyze(processes=self._processes(), connections=self._connections())
        critical = report.critical
        # mimikatz with C2 connection should be critical
        assert len(critical) > 0

    def test_detects_failed_logins(self):
        d = AnomalyDetector()
        events = [{"event_id": 4625, "message": "Failed login"} for _ in range(15)]
        report = d.analyze(events=events)
        brute = [
            a
            for a in report.all_anomalies
            if "brute" in a.description.lower() or "failed" in a.description.lower()
        ]
        assert len(brute) > 0

    def test_detects_off_hours_login(self):
        d = AnomalyDetector()
        logins = [
            {"event_id": 4624, "time_created": "2026-05-22T02:30:00Z"},  # 2 AM
            {"event_id": 4624, "time_created": "2026-05-22T03:15:00Z"},  # 3 AM
        ]
        report = d.analyze(login_events=logins)
        off_hours = [
            a
            for a in report.all_anomalies
            if "off-hours" in a.description.lower() or "outside" in a.description.lower()
        ]
        assert len(off_hours) > 0

    def test_empty_input_returns_clean_report(self):
        d = AnomalyDetector()
        report = d.analyze()
        assert report.total_anomalies == 0
        assert report.risk_level == "low"
        assert "No significant" in report.summary

    def test_risk_score_calculation(self):
        d = AnomalyDetector()
        report = d.analyze(processes=self._processes(), connections=self._connections())
        assert 0.0 <= report.risk_score <= 10.0

    def test_anomaly_str(self):
        a = Anomaly(
            anomaly_type="process",
            description="Suspicious process detected",
            severity="high",
            score=8.0,
        )
        s = str(a)
        assert "HIGH" in s
        assert "process" in s

    def test_report_all_anomalies(self):
        d = AnomalyDetector()
        report = d.analyze(processes=self._processes(), connections=self._connections())
        total = len(report.all_anomalies)
        assert total == report.total_anomalies
