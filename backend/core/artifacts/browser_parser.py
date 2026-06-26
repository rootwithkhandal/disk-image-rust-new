"""
Browser Artifact Parser Framework
===================================
Parses browser history, cookies, downloads, and sessions from
Chrome, Edge, Firefox, and Safari SQLite databases.

Usage:
    from core.artifacts.browser_parser import BrowserParser

    parser = BrowserParser()
    results = parser.parse_all(profile_dir="/Users/alice/AppData/Local/Google/Chrome/User Data")
    for entry in results.history:
        print(entry.url, entry.visit_time)
"""

from __future__ import annotations

import shutil
import sqlite3
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

from loguru import logger

# Chrome/Edge epoch: microseconds since 1601-01-01
_CHROME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def _chrome_ts(micros: int) -> str:
    """Convert Chrome timestamp (microseconds since 1601-01-01) to ISO 8601."""
    try:
        return (_CHROME_EPOCH + timedelta(microseconds=micros)).isoformat()
    except Exception:
        return str(micros)


def _firefox_ts(micros: int) -> str:
    """Convert Firefox timestamp (microseconds since Unix epoch) to ISO 8601."""
    try:
        return datetime.fromtimestamp(micros / 1_000_000, tz=timezone.utc).isoformat()
    except Exception:
        return str(micros)


@dataclass
class HistoryEntry:
    browser: str
    url: str
    title: str = ""
    visit_time: str = ""
    visit_count: int = 0
    profile: str = ""
    typed_count: int = 0


@dataclass
class DownloadEntry:
    browser: str
    url: str
    target_path: str = ""
    start_time: str = ""
    end_time: str = ""
    total_bytes: int = 0
    state: str = ""
    profile: str = ""


@dataclass
class CookieEntry:
    browser: str
    host: str
    name: str
    path: str = ""
    creation_time: str = ""
    expires_time: str = ""
    is_secure: bool = False
    is_httponly: bool = False
    profile: str = ""


@dataclass
class BrowserParseResult:
    browser: str
    profile: str
    history: list[HistoryEntry] = field(default_factory=list)
    downloads: list[DownloadEntry] = field(default_factory=list)
    cookies: list[CookieEntry] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def total_artifacts(self) -> int:
        return len(self.history) + len(self.downloads) + len(self.cookies)


def _safe_connect(db_path: Path) -> sqlite3.Connection | None:
    """Copy DB to temp file (may be locked) and open connection."""
    tmp = Path(tempfile.mktemp(suffix=".db"))
    try:
        shutil.copy2(db_path, tmp)
        return sqlite3.connect(str(tmp))
    except Exception as exc:
        logger.debug("DB copy/connect error {}: {}", db_path, exc)
        tmp.unlink(missing_ok=True)
        return None


class BrowserParser:
    """
    Parses browser artifacts from Chromium-based browsers and Firefox.
    """

    # ── Chrome / Edge ─────────────────────────────────────────────────────────

    def parse_chromium_history(
        self, history_db: Path, browser: str = "chrome", profile: str = ""
    ) -> BrowserParseResult:
        """Parse Chrome/Edge History SQLite database."""
        result = BrowserParseResult(browser=browser, profile=profile)

        conn = _safe_connect(history_db)
        if not conn:
            result.errors.append(f"Cannot open {history_db}")
            return result

        try:
            # History
            cursor = conn.execute(
                "SELECT url, title, visit_count, typed_count, last_visit_time "
                "FROM urls ORDER BY last_visit_time DESC LIMIT 5000"
            )
            for row in cursor.fetchall():
                result.history.append(
                    HistoryEntry(
                        browser=browser,
                        url=row[0] or "",
                        title=row[1] or "",
                        visit_count=int(row[2] or 0),
                        typed_count=int(row[3] or 0),
                        visit_time=_chrome_ts(int(row[4] or 0)),
                        profile=profile,
                    )
                )

            # Downloads
            try:
                cursor = conn.execute(
                    "SELECT current_path, tab_url, start_time, end_time, "
                    "received_bytes, state FROM downloads ORDER BY start_time DESC LIMIT 1000"
                )
                for row in cursor.fetchall():
                    result.downloads.append(
                        DownloadEntry(
                            browser=browser,
                            url=row[1] or "",
                            target_path=row[0] or "",
                            start_time=_chrome_ts(int(row[2] or 0)),
                            end_time=_chrome_ts(int(row[3] or 0)),
                            total_bytes=int(row[4] or 0),
                            state=str(row[5] or ""),
                            profile=profile,
                        )
                    )
            except sqlite3.OperationalError:
                pass  # Downloads table may not exist in all versions

        except Exception as exc:
            result.errors.append(str(exc))
            logger.debug("Chromium history parse error: {}", exc)
        finally:
            conn.close()

        logger.info(
            "{} history: {} URLs, {} downloads | profile={}",
            browser,
            len(result.history),
            len(result.downloads),
            profile,
        )
        return result

    def parse_chromium_cookies(
        self, cookies_db: Path, browser: str = "chrome", profile: str = ""
    ) -> list[CookieEntry]:
        """Parse Chrome/Edge Cookies SQLite database."""
        cookies: list[CookieEntry] = []
        conn = _safe_connect(cookies_db)
        if not conn:
            return cookies
        try:
            cursor = conn.execute(
                "SELECT host_key, name, path, creation_utc, expires_utc, "
                "is_secure, is_httponly FROM cookies ORDER BY creation_utc DESC LIMIT 10000"
            )
            for row in cursor.fetchall():
                cookies.append(
                    CookieEntry(
                        browser=browser,
                        host=row[0] or "",
                        name=row[1] or "",
                        path=row[2] or "",
                        creation_time=_chrome_ts(int(row[3] or 0)),
                        expires_time=_chrome_ts(int(row[4] or 0)),
                        is_secure=bool(row[5]),
                        is_httponly=bool(row[6]),
                        profile=profile,
                    )
                )
        except Exception as exc:
            logger.debug("Chromium cookies parse error: {}", exc)
        finally:
            conn.close()
        return cookies

    # ── Firefox ───────────────────────────────────────────────────────────────

    def parse_firefox_history(self, places_db: Path, profile: str = "") -> BrowserParseResult:
        """Parse Firefox places.sqlite database."""
        result = BrowserParseResult(browser="firefox", profile=profile)
        conn = _safe_connect(places_db)
        if not conn:
            result.errors.append(f"Cannot open {places_db}")
            return result

        try:
            cursor = conn.execute(
                "SELECT url, title, visit_count, last_visit_date "
                "FROM moz_places ORDER BY last_visit_date DESC LIMIT 5000"
            )
            for row in cursor.fetchall():
                result.history.append(
                    HistoryEntry(
                        browser="firefox",
                        url=row[0] or "",
                        title=row[1] or "",
                        visit_count=int(row[2] or 0),
                        visit_time=_firefox_ts(int(row[3] or 0)),
                        profile=profile,
                    )
                )

            # Downloads from moz_annos
            try:
                cursor = conn.execute(
                    "SELECT p.url, a.content, a.dateAdded "
                    "FROM moz_annos a JOIN moz_places p ON a.place_id = p.id "
                    "WHERE a.anno_attribute_id IN "
                    "(SELECT id FROM moz_anno_attributes WHERE name='downloads/destinationFileURI') "
                    "ORDER BY a.dateAdded DESC LIMIT 1000"
                )
                for row in cursor.fetchall():
                    result.downloads.append(
                        DownloadEntry(
                            browser="firefox",
                            url=row[0] or "",
                            target_path=row[1] or "",
                            start_time=_firefox_ts(int(row[2] or 0)),
                            profile=profile,
                        )
                    )
            except sqlite3.OperationalError:
                pass

        except Exception as exc:
            result.errors.append(str(exc))
            logger.debug("Firefox history parse error: {}", exc)
        finally:
            conn.close()

        logger.info("Firefox history: {} URLs | profile={}", len(result.history), profile)
        return result

    # ── Auto-detect and parse all ─────────────────────────────────────────────

    def parse_directory(self, base_dir: Path) -> list[BrowserParseResult]:
        """
        Auto-detect and parse all browser databases under a directory.
        Searches for Chrome, Edge, and Firefox profile structures.
        """
        results: list[BrowserParseResult] = []
        base = Path(base_dir)

        # Chrome
        chrome_base = base / "Google" / "Chrome" / "User Data"
        if chrome_base.exists():
            for profile_dir in chrome_base.iterdir():
                history_db = profile_dir / "History"
                if history_db.exists():
                    r = self.parse_chromium_history(history_db, "chrome", profile_dir.name)
                    cookies_db = profile_dir / "Cookies"
                    if cookies_db.exists():
                        r.cookies = self.parse_chromium_cookies(
                            cookies_db, "chrome", profile_dir.name
                        )
                    results.append(r)

        # Edge
        edge_base = base / "Microsoft" / "Edge" / "User Data"
        if edge_base.exists():
            for profile_dir in edge_base.iterdir():
                history_db = profile_dir / "History"
                if history_db.exists():
                    results.append(
                        self.parse_chromium_history(history_db, "edge", profile_dir.name)
                    )

        # Firefox
        firefox_base = base / "Mozilla" / "Firefox" / "Profiles"
        if firefox_base.exists():
            for profile_dir in firefox_base.iterdir():
                places_db = profile_dir / "places.sqlite"
                if places_db.exists():
                    results.append(self.parse_firefox_history(places_db, profile_dir.name))

        logger.info("Browser parser: {} profile(s) parsed", len(results))
        return results
