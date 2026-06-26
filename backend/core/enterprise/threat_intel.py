"""
Threat Intelligence Feed Integration
=======================================
Syncs IOC feeds from MISP, OTX, and custom sources.
Enriches artifacts with threat context.

Usage:
    from core.enterprise.threat_intel import ThreatIntelManager

    mgr = ThreatIntelManager()
    mgr.add_feed("misp", "https://misp.example.com", api_key="KEY")
    result = mgr.lookup("evil.com")
    mgr.sync_feeds()
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from loguru import logger

from core.config import settings


@dataclass
class ThreatIndicator:
    value: str
    ioc_type: str
    threat_type: str = ""
    confidence: int = 0  # 0-100
    severity: str = "unknown"
    source: str = ""
    tags: list[str] = field(default_factory=list)
    first_seen: str = ""
    last_seen: str = ""
    description: str = ""
    mitre_techniques: list[str] = field(default_factory=list)


@dataclass
class FeedConfig:
    name: str
    url: str
    feed_type: str = "generic"  # misp | otx | taxii | generic
    api_key: str = ""
    enabled: bool = True
    last_sync: str = ""
    indicator_count: int = 0


@dataclass
class LookupResult:
    value: str
    found: bool
    indicators: list[ThreatIndicator] = field(default_factory=list)
    risk_score: int = 0
    verdict: str = "unknown"  # clean | suspicious | malicious | unknown


class ThreatIntelManager:
    """
    Manages threat intelligence feeds and IOC lookups.
    Maintains a local cache for offline operation.
    """

    CACHE_FILE = "threat_intel_cache.json"
    FEEDS_FILE = "threat_feeds.json"

    def __init__(self, base_path: Path | None = None) -> None:
        self.base_path = Path(base_path or settings.evidence.base_path)
        self.base_path.mkdir(parents=True, exist_ok=True)
        self._cache_path = self.base_path / self.CACHE_FILE
        self._feeds_path = self.base_path / self.FEEDS_FILE
        self._cache: dict[str, dict] = self._load_cache()
        self._feeds: dict[str, dict] = self._load_feeds()
        self._seed_builtin_indicators()

    def _load_cache(self) -> dict:
        if self._cache_path.exists():
            try:
                return json.loads(self._cache_path.read_text(encoding="utf-8"))
            except Exception:
                pass
        return {}

    def _save_cache(self) -> None:
        self._cache_path.write_text(
            json.dumps(self._cache, indent=2, default=str), encoding="utf-8"
        )

    def _load_feeds(self) -> dict:
        if self._feeds_path.exists():
            try:
                return json.loads(self._feeds_path.read_text(encoding="utf-8"))
            except Exception:
                pass
        return {}

    def _save_feeds(self) -> None:
        self._feeds_path.write_text(
            json.dumps(self._feeds, indent=2, default=str), encoding="utf-8"
        )

    def _seed_builtin_indicators(self) -> None:
        """Seed with a small built-in IOC set for offline operation."""
        builtin = {
            "evil.com": {
                "ioc_type": "domain",
                "severity": "critical",
                "threat_type": "c2",
                "confidence": 95,
                "source": "builtin",
            },
            "malware.cc": {
                "ioc_type": "domain",
                "severity": "critical",
                "threat_type": "malware",
                "confidence": 90,
                "source": "builtin",
            },
            "10.0.0.99": {
                "ioc_type": "ip",
                "severity": "high",
                "threat_type": "c2",
                "confidence": 85,
                "source": "builtin",
            },
            "44d88612fea8a8f36de82e1278abb02f": {
                "ioc_type": "hash",
                "severity": "critical",
                "threat_type": "malware",
                "confidence": 100,
                "source": "builtin",
                "description": "EICAR test file",
            },
        }
        for value, data in builtin.items():
            if value not in self._cache:
                self._cache[value] = data
        self._save_cache()

    # ── Feed management ───────────────────────────────────────────────────────

    def add_feed(
        self,
        name: str,
        url: str,
        feed_type: str = "generic",
        api_key: str = "",
    ) -> FeedConfig:
        """Register a new threat intelligence feed."""
        feed = FeedConfig(name=name, url=url, feed_type=feed_type, api_key=api_key)
        self._feeds[name] = {
            "name": name,
            "url": url,
            "feed_type": feed_type,
            "api_key": api_key,
            "enabled": True,
            "last_sync": "",
            "indicator_count": 0,
        }
        self._save_feeds()
        logger.info("Threat feed added: {} ({})", name, feed_type)
        return feed

    def list_feeds(self) -> list[FeedConfig]:
        return [FeedConfig(**f) for f in self._feeds.values()]

    def sync_feeds(self) -> dict[str, int]:
        """Sync all enabled feeds. Returns {feed_name: indicators_added}."""
        results: dict[str, int] = {}
        for name, feed_data in self._feeds.items():
            if not feed_data.get("enabled"):
                continue
            feed = FeedConfig(**feed_data)
            count = self._sync_feed(feed)
            results[name] = count
            self._feeds[name]["last_sync"] = datetime.now(timezone.utc).isoformat()
            self._feeds[name]["indicator_count"] = count
        self._save_feeds()
        return results

    def _sync_feed(self, feed: FeedConfig) -> int:
        """Sync a single feed. Returns number of indicators added."""
        try:
            req = urllib.request.Request(feed.url)
            if feed.api_key:
                req.add_header("Authorization", f"Bearer {feed.api_key}")
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode("utf-8"))

            indicators = self._parse_feed_response(data, feed.feed_type)
            for ind in indicators:
                self._cache[ind.value.lower()] = {
                    "ioc_type": ind.ioc_type,
                    "severity": ind.severity,
                    "threat_type": ind.threat_type,
                    "confidence": ind.confidence,
                    "source": feed.name,
                    "tags": ind.tags,
                    "description": ind.description,
                }
            self._save_cache()
            logger.info("Feed synced: {} | {} indicators", feed.name, len(indicators))
            return len(indicators)

        except Exception as exc:
            logger.warning("Feed sync failed ({}): {}", feed.name, exc)
            return 0

    def _parse_feed_response(self, data: dict | list, feed_type: str) -> list[ThreatIndicator]:
        """Parse feed response into ThreatIndicator objects."""
        indicators: list[ThreatIndicator] = []

        if feed_type == "otx":
            # OTX AlienVault format
            for pulse in data.get("results", []):
                for ind in pulse.get("indicators", []):
                    indicators.append(
                        ThreatIndicator(
                            value=ind.get("indicator", ""),
                            ioc_type=ind.get("type", "").lower(),
                            threat_type=pulse.get("name", ""),
                            confidence=70,
                            source="otx",
                            tags=pulse.get("tags", []),
                        )
                    )

        elif feed_type == "misp":
            # MISP format
            for attr in data.get("Attribute", []):
                indicators.append(
                    ThreatIndicator(
                        value=attr.get("value", ""),
                        ioc_type=attr.get("type", "").lower(),
                        confidence=int(attr.get("confidence", 50) or 50),
                        source="misp",
                        description=attr.get("comment", ""),
                    )
                )

        else:
            # Generic: list of {value, type, severity}
            items = data if isinstance(data, list) else data.get("indicators", [])
            for item in items:
                if isinstance(item, str):
                    indicators.append(ThreatIndicator(value=item, ioc_type="unknown"))
                elif isinstance(item, dict):
                    indicators.append(
                        ThreatIndicator(
                            value=item.get("value", item.get("ioc", "")),
                            ioc_type=item.get("type", "unknown"),
                            severity=item.get("severity", "medium"),
                            confidence=int(item.get("confidence", 50) or 50),
                            source="generic",
                        )
                    )

        return [i for i in indicators if i.value]

    # ── Lookup ────────────────────────────────────────────────────────────────

    def lookup(self, value: str) -> LookupResult:
        """Look up an IOC in the local cache."""
        key = value.lower().strip()
        data = self._cache.get(key)

        if not data:
            return LookupResult(value=value, found=False, verdict="unknown")

        indicator = ThreatIndicator(
            value=value,
            ioc_type=data.get("ioc_type", "unknown"),
            threat_type=data.get("threat_type", ""),
            confidence=int(data.get("confidence", 50) or 50),
            severity=data.get("severity", "unknown"),
            source=data.get("source", ""),
            tags=data.get("tags", []),
            description=data.get("description", ""),
        )

        risk_score = min(indicator.confidence, 100)
        verdict = (
            "malicious" if risk_score >= 80 else "suspicious" if risk_score >= 50 else "unknown"
        )

        return LookupResult(
            value=value,
            found=True,
            indicators=[indicator],
            risk_score=risk_score,
            verdict=verdict,
        )

    def bulk_lookup(self, values: list[str]) -> dict[str, LookupResult]:
        """Look up multiple IOCs at once."""
        return {v: self.lookup(v) for v in values}

    def enrich_ioc_report(self, ioc_report) -> dict[str, LookupResult]:
        """Enrich all IOCs in an IOCReport with threat intel context."""
        all_values = [ioc.ioc_value for ioc in ioc_report.all_iocs]
        return self.bulk_lookup(all_values)

    @property
    def cache_size(self) -> int:
        return len(self._cache)
