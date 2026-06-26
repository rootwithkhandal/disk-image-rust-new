"""
Tests for V1.1 — Memory Forensics
Covers: VolatilityEngine, MemoryTimeline
All tests run gracefully without Volatility3 installed.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from core.memory.timeline import MemoryTimeline, TimelineEvent, _normalize_ts
from core.memory.volatility_engine import VolatilityEngine, VolatilityResult, _enrich_process

# ── VolatilityEngine ──────────────────────────────────────────────────────────


class TestVolatilityEngine:
    def test_init_with_nonexistent_dump(self):
        engine = VolatilityEngine("/nonexistent/memory.raw")
        assert engine.dump_path == Path("/nonexistent/memory.raw")

    def test_run_plugin_missing_dump_returns_failure(self):
        engine = VolatilityEngine("/nonexistent/memory.raw")
        result = engine._run_plugin("windows.pslist.PsList")
        assert result.success is False
        assert result.error != ""

    def test_run_plugin_no_volatility_returns_failure(self):
        """Without Volatility3, all plugins should fail gracefully."""
        tmp = Path(tempfile.mktemp(suffix=".raw"))
        tmp.write_bytes(b"\x00" * 1024)
        engine = VolatilityEngine(tmp)
        # Force no volatility
        engine._vol_cmd = None
        result = engine._run_plugin("windows.pslist.PsList")
        assert result.success is False
        assert "not installed" in result.error.lower()
        tmp.unlink()

    def test_list_processes_no_vol_fails_gracefully(self):
        tmp = Path(tempfile.mktemp(suffix=".raw"))
        tmp.write_bytes(b"\x00" * 1024)
        engine = VolatilityEngine(tmp)
        engine._vol_cmd = None
        result = engine.list_processes()
        assert isinstance(result, VolatilityResult)
        assert result.success is False
        tmp.unlink()

    def test_full_analysis_returns_dict(self):
        tmp = Path(tempfile.mktemp(suffix=".raw"))
        tmp.write_bytes(b"\x00" * 1024)
        engine = VolatilityEngine(tmp)
        engine._vol_cmd = None
        results = engine.full_analysis()
        assert isinstance(results, dict)
        assert "processes" in results
        assert "connections" in results
        assert "malfind" in results
        tmp.unlink()

    def test_volatility_result_dataclass(self):
        result = VolatilityResult(
            success=True,
            plugin="windows.pslist",
            dump_path="/evidence/memory.raw",
            data=[{"PID": 4, "Name": "System"}],
            row_count=1,
        )
        assert result.success is True
        assert result.row_count == 1
        assert len(result.data) == 1


class TestEnrichProcess:
    def test_clean_process_not_flagged(self):
        row = {"ImageFileName": "explorer.exe", "PID": 2048, "Wow64": ""}
        enriched = _enrich_process(row)
        assert enriched["_suspicious"] is False
        assert enriched["_suspicious_reasons"] == []

    def test_mimikatz_flagged(self):
        row = {"ImageFileName": "mimikatz.exe", "PID": 4096, "Wow64": ""}
        enriched = _enrich_process(row)
        assert enriched["_suspicious"] is True
        assert len(enriched["_suspicious_reasons"]) > 0

    def test_suspicious_path_flagged(self):
        row = {"ImageFileName": "evil.exe", "PID": 9999, "Wow64": "C:\\Users\\Public\\evil.exe"}
        enriched = _enrich_process(row)
        assert enriched["_suspicious"] is True

    def test_lsass_flagged(self):
        row = {"ImageFileName": "lsass.exe", "PID": 908, "Wow64": ""}
        enriched = _enrich_process(row)
        assert enriched["_suspicious"] is True


# ── MemoryTimeline ────────────────────────────────────────────────────────────


class TestMemoryTimeline:
    def test_init(self):
        tl = MemoryTimeline("/nonexistent/memory.raw")
        assert tl.dump_path == Path("/nonexistent/memory.raw")

    def test_build_no_volatility_returns_empty(self):
        tmp = Path(tempfile.mktemp(suffix=".raw"))
        tmp.write_bytes(b"\x00" * 1024)
        tl = MemoryTimeline(tmp)
        tl.engine._vol_cmd = None
        events = tl.build()
        assert isinstance(events, list)
        tmp.unlink()

    def test_summary_empty(self):
        tl = MemoryTimeline("/nonexistent/memory.raw")
        summary = tl.summary()
        assert summary["total_events"] == 0
        assert summary["process_events"] == 0
        assert summary["network_events"] == 0

    def test_export_json_empty(self):
        tmp_dir = Path(tempfile.mkdtemp())
        tl = MemoryTimeline("/nonexistent/memory.raw")
        tl._events = []
        out = tl.export_json(tmp_dir / "timeline.json")
        assert out.exists()
        data = json.loads(out.read_text())
        assert data["total_events"] == 0
        assert "events" in data

    def test_export_json_with_events(self):
        tmp_dir = Path(tempfile.mkdtemp())
        tl = MemoryTimeline("/evidence/memory.raw")
        tl._events = [
            TimelineEvent(
                timestamp="2026-05-22T14:30:11+00:00",
                event_type="process_create",
                source="windows.pslist",
                pid=4096,
                process_name="mimikatz.exe",
                description="Known credential dumper",
                is_suspicious=True,
            ),
            TimelineEvent(
                timestamp="2026-05-22T14:30:12+00:00",
                event_type="network",
                source="windows.netstat",
                pid=4096,
                process_name="mimikatz.exe",
                description="C2 connection: 10.0.0.99:4444",
                is_suspicious=True,
            ),
        ]
        out = tl.export_json(tmp_dir / "timeline.json")
        data = json.loads(out.read_text())
        assert data["total_events"] == 2
        assert data["suspicious_events"] == 2

    def test_get_suspicious_events(self):
        tl = MemoryTimeline("/evidence/memory.raw")
        tl._events = [
            TimelineEvent(
                "2026-05-22T08:00:00Z",
                "process_create",
                "pslist",
                4,
                "System",
                "System started",
                False,
            ),
            TimelineEvent(
                "2026-05-22T14:30:11Z",
                "process_create",
                "pslist",
                4096,
                "mimikatz.exe",
                "Malware",
                True,
            ),
        ]
        sus = tl.get_suspicious_events()
        assert len(sus) == 1
        assert sus[0].process_name == "mimikatz.exe"

    def test_get_process_timeline(self):
        tl = MemoryTimeline("/evidence/memory.raw")
        tl._events = [
            TimelineEvent(
                "2026-05-22T08:00:00Z", "process_create", "pslist", 4, "System", "", False
            ),
            TimelineEvent(
                "2026-05-22T09:00:00Z", "network", "netstat", 100, "chrome.exe", "", False
            ),
            TimelineEvent("2026-05-22T10:00:00Z", "process_exit", "pslist", 4, "System", "", False),
        ]
        proc = tl.get_process_timeline()
        assert len(proc) == 2
        assert all(e.event_type in ("process_create", "process_exit") for e in proc)

    def test_timeline_sorted(self):
        tl = MemoryTimeline("/evidence/memory.raw")
        tl._events = [
            TimelineEvent(
                "2026-05-22T14:00:00Z", "process_create", "pslist", 200, "late.exe", "", False
            ),
            TimelineEvent(
                "2026-05-22T08:00:00Z", "process_create", "pslist", 100, "early.exe", "", False
            ),
        ]
        tl._events.sort()
        assert tl._events[0].process_name == "early.exe"
        assert tl._events[1].process_name == "late.exe"


class TestNormalizeTimestamp:
    def test_already_iso(self):
        ts = "2026-05-22T14:30:11+00:00"
        assert _normalize_ts(ts) == ts

    def test_volatility_format(self):
        ts = "2026-05-22 14:30:11 UTC+0000"
        result = _normalize_ts(ts)
        assert "2026-05-22" in result
        assert "14:30:11" in result

    def test_empty_returns_empty(self):
        assert _normalize_ts("") == ""
        assert _normalize_ts("N/A") == ""
        assert _normalize_ts("0") == ""

    def test_unknown_format_returns_as_is(self):
        ts = "some-weird-format"
        result = _normalize_ts(ts)
        assert result == ts
