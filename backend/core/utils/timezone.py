"""
ForgeLens Timezone Utilities
==============================
All timestamps in ForgeLens use this module to ensure consistent
timezone-aware formatting across the platform.

Default: IST (India Standard Time, UTC+5:30)
Override in settings.yaml:  app.timezone: "Asia/Kolkata"
Override via env var:        APP__TIMEZONE=UTC

Usage:
    from core.utils.timezone import now_iso, local_tz, format_ts

    ts = now_iso()          # "2026-06-08T19:30:00.123456+05:30"
    ts = now_iso(fmt="display")  # "08 Jun 2026, 07:30:05 PM IST"
"""

from __future__ import annotations

from datetime import datetime, timezone, timedelta

# ── Timezone registry ─────────────────────────────────────────────────────────
# Common IANA names -> fixed UTC offsets
# (avoids requiring the 'pytz' or 'zoneinfo' dependency on all platforms)

_TIMEZONE_OFFSETS: dict[str, timedelta] = {
    # India
    "Asia/Kolkata":     timedelta(hours=5,  minutes=30),
    "IST":              timedelta(hours=5,  minutes=30),
    # UTC
    "UTC":              timedelta(0),
    "Etc/UTC":          timedelta(0),
    # US
    "America/New_York": timedelta(hours=-5),
    "America/Chicago":  timedelta(hours=-6),
    "America/Denver":   timedelta(hours=-7),
    "America/Los_Angeles": timedelta(hours=-8),
    # Europe
    "Europe/London":    timedelta(hours=0),
    "Europe/Berlin":    timedelta(hours=1),
    "Europe/Paris":     timedelta(hours=1),
    "Europe/Moscow":    timedelta(hours=3),
    # Asia-Pacific
    "Asia/Dubai":       timedelta(hours=4),
    "Asia/Singapore":   timedelta(hours=8),
    "Asia/Tokyo":       timedelta(hours=9),
    "Australia/Sydney": timedelta(hours=10),
}

_TIMEZONE_ABBR: dict[str, str] = {
    "Asia/Kolkata":        "IST",
    "IST":                 "IST",
    "UTC":                 "UTC",
    "America/New_York":    "EST",
    "America/Los_Angeles": "PST",
    "Europe/London":       "GMT",
    "Asia/Singapore":      "SGT",
    "Asia/Tokyo":          "JST",
}


def _resolve_tz(tz_name: str) -> timezone:
    """Resolve a timezone name to a datetime.timezone object."""
    offset = _TIMEZONE_OFFSETS.get(tz_name)
    if offset is not None:
        abbr = _TIMEZONE_ABBR.get(tz_name, tz_name)
        return timezone(offset, name=abbr)

    # Try zoneinfo (Python 3.9+, optional)
    try:
        from zoneinfo import ZoneInfo  # type: ignore
        zi = ZoneInfo(tz_name)
        # Get current offset from zoneinfo
        now_utc = datetime.now(timezone.utc)
        now_local = now_utc.astimezone(zi)
        return now_local.tzinfo  # type: ignore
    except Exception:
        pass

    # Fallback to UTC with a warning
    from loguru import logger
    logger.warning("Unknown timezone '{}' — falling back to UTC", tz_name)
    return timezone.utc


def local_tz() -> timezone:
    """Return the configured local timezone."""
    try:
        from core.config import settings
        tz_name = getattr(settings.app, "timezone", "Asia/Kolkata")
    except Exception:
        tz_name = "Asia/Kolkata"
    return _resolve_tz(tz_name)


def now_ist() -> datetime:
    """Return current datetime in the configured local timezone."""
    return datetime.now(local_tz())


def now_iso(fmt: str = "iso") -> str:
    """
    Return current timestamp as a string.

    fmt options:
      "iso"      — ISO 8601 with offset  e.g. 2026-06-08T19:30:00.123456+05:30
      "display"  — Human readable        e.g. 08 Jun 2026, 07:30:05 PM IST
      "date"     — Date only             e.g. 2026-06-08
      "log"      — Log-style             e.g. 2026-06-08 19:30:05 IST
    """
    now = now_ist()
    if fmt == "iso":
        return now.isoformat()
    elif fmt == "display":
        abbr = now.tzname() or "IST"
        return now.strftime(f"%d %b %Y, %I:%M:%S %p {abbr}")
    elif fmt == "date":
        return now.strftime("%Y-%m-%d")
    elif fmt == "log":
        abbr = now.tzname() or "IST"
        return now.strftime(f"%Y-%m-%d %H:%M:%S {abbr}")
    return now.isoformat()


def format_ts(ts_iso: str, fmt: str = "display") -> str:
    """
    Convert a stored ISO 8601 UTC timestamp to the local timezone for display.

    Args:
        ts_iso: ISO 8601 string (e.g. "2026-06-08T14:20:52+00:00")
        fmt:    Output format — same options as now_iso()
    """
    if not ts_iso:
        return ""
    try:
        # Parse the stored UTC timestamp
        if ts_iso.endswith("Z"):
            ts_iso = ts_iso[:-1] + "+00:00"
        dt_utc = datetime.fromisoformat(ts_iso)
        if dt_utc.tzinfo is None:
            dt_utc = dt_utc.replace(tzinfo=timezone.utc)
        # Convert to local timezone
        dt_local = dt_utc.astimezone(local_tz())
        if fmt == "iso":
            return dt_local.isoformat()
        elif fmt == "display":
            abbr = dt_local.tzname() or "IST"
            return dt_local.strftime(f"%d %b %Y, %I:%M:%S %p {abbr}")
        elif fmt == "date":
            return dt_local.strftime("%Y-%m-%d")
        elif fmt == "log":
            abbr = dt_local.tzname() or "IST"
            return dt_local.strftime(f"%Y-%m-%d %H:%M:%S {abbr}")
        return dt_local.isoformat()
    except Exception:
        return ts_iso
