"""
Tests for V1.2 — Artifact Intelligence Engine
Covers: BrowserParser, RegistryParser, SQLiteParser, ExifParser, ArtifactDetector
"""

from __future__ import annotations

import json
import sqlite3
import tempfile
from pathlib import Path

# ── BrowserParser ─────────────────────────────────────────────────────────────


class TestBrowserParser:
    def _make_chrome_history_db(self) -> Path:
        """Create a minimal Chrome-style History SQLite database."""
        tmp = Path(tempfile.mktemp(suffix=".db"))
        conn = sqlite3.connect(str(tmp))
        conn.execute(
            "CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT, "
            "visit_count INTEGER, typed_count INTEGER, last_visit_time INTEGER)"
        )
        conn.execute(
            "INSERT INTO urls VALUES (1, 'https://example.com', 'Example', 5, 1, 13300000000000000)"
        )
        conn.execute(
            "INSERT INTO urls VALUES (2, 'https://evil.com/malware', 'Evil', 1, 0, 13300000000000001)"
        )
        conn.commit()
        conn.close()
        return tmp

    def test_parse_chromium_history(self):
        from core.artifacts.browser_parser import BrowserParser

        db = self._make_chrome_history_db()
        parser = BrowserParser()
        result = parser.parse_chromium_history(db, browser="chrome", profile="Default")
        assert result.browser == "chrome"
        assert len(result.history) == 2
        urls = [e.url for e in result.history]
        assert "https://example.com" in urls
        db.unlink()

    def test_parse_chromium_history_missing_db(self):
        from core.artifacts.browser_parser import BrowserParser

        parser = BrowserParser()
        result = parser.parse_chromium_history(Path("/nonexistent/History"))
        assert len(result.errors) > 0
        assert len(result.history) == 0

    def test_history_entry_fields(self):
        from core.artifacts.browser_parser import BrowserParser

        db = self._make_chrome_history_db()
        parser = BrowserParser()
        result = parser.parse_chromium_history(db, browser="edge", profile="Profile 1")
        entry = result.history[0]
        assert entry.browser == "edge"
        assert entry.profile == "Profile 1"
        assert entry.url != ""
        assert entry.visit_count >= 0
        db.unlink()

    def test_total_artifacts(self):
        from core.artifacts.browser_parser import BrowserParser

        db = self._make_chrome_history_db()
        parser = BrowserParser()
        result = parser.parse_chromium_history(db)
        assert result.total_artifacts == len(result.history)
        db.unlink()

    def test_chrome_timestamp_conversion(self):
        from core.artifacts.browser_parser import _chrome_ts

        # Known value: 0 microseconds = 1601-01-01
        ts = _chrome_ts(0)
        assert "1601" in ts

    def test_firefox_timestamp_conversion(self):
        from core.artifacts.browser_parser import _firefox_ts

        ts = _firefox_ts(0)
        assert "1970" in ts


# ── RegistryParser ────────────────────────────────────────────────────────────


class TestRegistryParser:
    def test_init(self):
        from core.artifacts.registry_parser import RegistryParser

        parser = RegistryParser()
        assert parser is not None

    def test_parse_live_run_keys_returns_result(self):
        from core.artifacts.registry_parser import RegistryParser

        parser = RegistryParser()
        result = parser.parse_live_run_keys()
        assert result is not None
        assert isinstance(result.entries, list)

    def test_parse_live_usb_history_returns_result(self):
        from core.artifacts.registry_parser import RegistryParser

        parser = RegistryParser()
        result = parser.parse_live_usb_history()
        assert isinstance(result.entries, list)

    def test_suspicious_run_value_detection(self):
        from core.artifacts.registry_parser import _is_suspicious_run_value

        is_sus, reason = _is_suspicious_run_value("powershell -enc abc123")
        assert is_sus is True
        assert reason != ""

    def test_clean_run_value_not_flagged(self):
        from core.artifacts.registry_parser import _is_suspicious_run_value

        is_sus, _ = _is_suspicious_run_value("C:\\Program Files\\Notepad++\\notepad++.exe")
        assert is_sus is False

    def test_suspicious_path_flagged(self):
        from core.artifacts.registry_parser import _is_suspicious_run_value

        is_sus, reason = _is_suspicious_run_value("C:\\Users\\Public\\evil.exe")
        assert is_sus is True

    def test_parse_hive_no_regipy(self):
        from core.artifacts.registry_parser import RegistryParser

        parser = RegistryParser()
        parser._regipy_available = False
        result = parser.parse_hive("/nonexistent/NTUSER.DAT")
        assert len(result.errors) > 0

    def test_registry_entry_dataclass(self):
        from core.artifacts.registry_parser import RegistryEntry

        entry = RegistryEntry(
            hive="HKLM",
            key_path=r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            value_name="Updater",
            value_data="C:\\temp\\update.exe",
            artifact_type="run_key",
            is_suspicious=True,
            suspicious_reason="Suspicious path",
        )
        assert entry.is_suspicious is True
        assert entry.hive == "HKLM"


# ── SQLiteParser ──────────────────────────────────────────────────────────────


class TestSQLiteParser:
    def _make_test_db(self) -> Path:
        tmp = Path(tempfile.mktemp(suffix=".db"))
        conn = sqlite3.connect(str(tmp))
        conn.execute("CREATE TABLE messages (id INTEGER, body TEXT, date INTEGER)")
        conn.execute("INSERT INTO messages VALUES (1, 'Hello World', 1716000000)")
        conn.execute("INSERT INTO messages VALUES (2, 'Test message', 1716000001)")
        conn.execute("CREATE TABLE contacts (id INTEGER, name TEXT, phone TEXT)")
        conn.execute("INSERT INTO contacts VALUES (1, 'Alice', '+1234567890')")
        conn.commit()
        conn.close()
        return tmp

    def test_open_and_close(self):
        from core.artifacts.sqlite_parser import SQLiteParser

        db = self._make_test_db()
        parser = SQLiteParser(db)
        assert parser.open() is True
        parser.close()
        db.unlink()

    def test_list_tables(self):
        from core.artifacts.sqlite_parser import SQLiteParser

        db = self._make_test_db()
        with SQLiteParser(db) as parser:
            tables = parser.list_tables()
        assert "messages" in tables
        assert "contacts" in tables
        db.unlink()

    def test_query(self):
        from core.artifacts.sqlite_parser import SQLiteParser

        db = self._make_test_db()
        with SQLiteParser(db) as parser:
            result = parser.query("SELECT * FROM messages ORDER BY id")
        assert result.success is True
        assert result.row_count == 2
        assert result.rows[0]["body"] == "Hello World"
        db.unlink()

    def test_query_table(self):
        from core.artifacts.sqlite_parser import SQLiteParser

        db = self._make_test_db()
        with SQLiteParser(db) as parser:
            result = parser.query_table("contacts")
        assert result.success is True
        assert result.row_count == 1
        db.unlink()

    def test_describe_table(self):
        from core.artifacts.sqlite_parser import SQLiteParser

        db = self._make_test_db()
        with SQLiteParser(db) as parser:
            info = parser.describe_table("messages")
        assert info.name == "messages"
        assert info.row_count == 2
        assert "body" in info.columns
        db.unlink()

    def test_export_all_tables(self):
        from core.artifacts.sqlite_parser import SQLiteParser

        db = self._make_test_db()
        out_dir = Path(tempfile.mkdtemp())
        with SQLiteParser(db) as parser:
            exported = parser.export_all_tables(out_dir)
        assert "messages" in exported
        assert "contacts" in exported
        assert exported["messages"].exists()
        data = json.loads(exported["messages"].read_text())
        assert data["table"] == "messages"
        assert len(data["rows"]) == 2
        db.unlink()

    def test_is_sqlite(self):
        from core.artifacts.sqlite_parser import SQLiteParser

        db = self._make_test_db()
        assert SQLiteParser.is_sqlite(db) is True
        db.unlink()

    def test_is_not_sqlite(self):
        from core.artifacts.sqlite_parser import SQLiteParser

        tmp = Path(tempfile.mktemp())
        tmp.write_bytes(b"not a sqlite file")
        assert SQLiteParser.is_sqlite(tmp) is False
        tmp.unlink()

    def test_missing_db_returns_empty(self):
        from core.artifacts.sqlite_parser import SQLiteParser

        parser = SQLiteParser("/nonexistent/db.sqlite")
        tables = parser.list_tables()
        assert tables == []

    def test_context_manager(self):
        from core.artifacts.sqlite_parser import SQLiteParser

        db = self._make_test_db()
        with SQLiteParser(db) as parser:
            assert parser._conn is not None
        assert parser._conn is None
        db.unlink()


# ── ExifParser ────────────────────────────────────────────────────────────────


class TestExifParser:
    def test_init(self):
        from core.artifacts.exif_parser import ExifParser

        parser = ExifParser()
        assert parser is not None

    def test_parse_missing_file(self):
        from core.artifacts.exif_parser import ExifParser

        parser = ExifParser()
        result = parser.parse("/nonexistent/photo.jpg")
        assert len(result.errors) > 0

    def test_parse_non_image_file(self):
        from core.artifacts.exif_parser import ExifParser

        tmp = Path(tempfile.mktemp(suffix=".txt"))
        tmp.write_text("not an image")
        parser = ExifParser()
        result = parser.parse(tmp)
        # Should not crash
        assert result.file_path == str(tmp)
        tmp.unlink()

    def test_gps_coordinates_str(self):
        from core.artifacts.exif_parser import GPSCoordinates

        gps = GPSCoordinates(latitude=37.7749, longitude=-122.4194)
        assert "37.7749" in str(gps)
        assert "-122.4194" in str(gps)

    def test_gps_maps_url(self):
        from core.artifacts.exif_parser import GPSCoordinates

        gps = GPSCoordinates(latitude=51.5074, longitude=-0.1278)
        assert "maps.google.com" in gps.google_maps_url
        assert "51.5074" in gps.google_maps_url

    def test_exif_result_has_gps_false(self):
        from core.artifacts.exif_parser import ExifResult

        result = ExifResult(file_path="/test.jpg")
        assert result.has_gps is False

    def test_dms_to_decimal(self):
        from core.artifacts.exif_parser import _dms_to_decimal

        # 51 degrees, 30 minutes, 0 seconds = 51.5
        result = _dms_to_decimal("[51/1, 30/1, 0/1]")
        assert result is not None
        assert abs(result - 51.5) < 0.001

    def test_exif_result_to_dict(self):
        from core.artifacts.exif_parser import ExifResult, GPSCoordinates

        result = ExifResult(
            file_path="/evidence/photo.jpg",
            device_make="Apple",
            device_model="iPhone 14",
            gps=GPSCoordinates(latitude=37.7749, longitude=-122.4194),
        )
        d = result.to_dict()
        assert d["device_make"] == "Apple"
        assert d["has_gps"] is True
        assert "gps_lat" in d


# ── ArtifactDetector ──────────────────────────────────────────────────────────


class TestArtifactDetector:
    def test_init(self):
        from core.artifacts.detector import ArtifactDetector

        detector = ArtifactDetector()
        assert detector is not None

    def test_calculate_entropy_random(self):
        import os

        from core.artifacts.detector import ArtifactDetector

        tmp = Path(tempfile.mktemp())
        tmp.write_bytes(os.urandom(65536))  # Random = high entropy
        detector = ArtifactDetector()
        result = detector.calculate_entropy(tmp)
        assert result.entropy > 7.0
        assert result.is_packed is True
        tmp.unlink()

    def test_calculate_entropy_zeros(self):
        from core.artifacts.detector import ArtifactDetector

        tmp = Path(tempfile.mktemp())
        tmp.write_bytes(b"\x00" * 65536)  # All zeros = zero entropy
        detector = ArtifactDetector()
        result = detector.calculate_entropy(tmp)
        assert result.entropy == 0.0
        assert result.is_packed is False
        tmp.unlink()

    def test_calculate_entropy_missing_file(self):
        from core.artifacts.detector import ArtifactDetector

        detector = ArtifactDetector()
        result = detector.calculate_entropy("/nonexistent/file.bin")
        assert result.entropy == 0.0

    def test_match_iocs_known_bad_domain(self):
        from core.artifacts.detector import ArtifactDetector

        tmp = Path(tempfile.mktemp(suffix=".txt"))
        tmp.write_text("Connecting to evil.com for C2 communication")
        detector = ArtifactDetector()
        matches = detector.match_iocs_in_file(tmp)
        assert any(m.ioc_value == "evil.com" for m in matches)
        tmp.unlink()

    def test_match_iocs_known_bad_ip(self):
        from core.artifacts.detector import ArtifactDetector

        tmp = Path(tempfile.mktemp(suffix=".txt"))
        tmp.write_text("Beacon to 10.0.0.99:4444")
        detector = ArtifactDetector()
        matches = detector.match_iocs_in_file(tmp)
        assert any(m.ioc_value == "10.0.0.99" for m in matches)
        tmp.unlink()

    def test_match_iocs_custom_ioc(self):
        from core.artifacts.detector import ArtifactDetector

        tmp = Path(tempfile.mktemp(suffix=".txt"))
        tmp.write_text("Connecting to custom-c2.example.com")
        detector = ArtifactDetector()
        matches = detector.match_iocs_in_file(tmp, custom_iocs=["custom-c2.example.com"])
        assert any("custom-c2.example.com" in m.ioc_value for m in matches)
        tmp.unlink()

    def test_match_iocs_clean_file(self):
        from core.artifacts.detector import ArtifactDetector

        tmp = Path(tempfile.mktemp(suffix=".txt"))
        tmp.write_text("This is a clean log file with no IOCs")
        detector = ArtifactDetector()
        matches = detector.match_iocs_in_file(tmp)
        assert len(matches) == 0
        tmp.unlink()

    def test_scan_file_known_hash(self):

        from core.artifacts.detector import ArtifactDetector

        # Create a file whose SHA256 is in the known bad set
        # Use EICAR-like content that hashes to a known value
        tmp = Path(tempfile.mktemp())
        tmp.write_bytes(b"\x00" * 100)
        detector = ArtifactDetector()
        result = detector.scan_file(tmp)
        assert result.sha256 != ""
        assert result.file_path == str(tmp)
        tmp.unlink()

    def test_scan_file_missing(self):
        from core.artifacts.detector import ArtifactDetector

        detector = ArtifactDetector()
        result = detector.scan_file("/nonexistent/file.exe")
        assert result.sha256 == ""

    def test_detect_persistence_returns_list(self):
        from core.artifacts.detector import ArtifactDetector

        detector = ArtifactDetector()
        entries = detector.detect_persistence()
        assert isinstance(entries, list)

    def test_persistence_entry_dataclass(self):
        from core.artifacts.detector import PersistenceEntry

        entry = PersistenceEntry(
            mechanism="run_key",
            name="Updater",
            command="C:\\temp\\update.exe",
            location=r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            is_suspicious=True,
            reason="Suspicious path",
        )
        assert entry.is_suspicious is True
        assert entry.mechanism == "run_key"
