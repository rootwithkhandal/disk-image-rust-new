"""
SIEM Integration
=================
Sends forensic events and IOC alerts to SIEM platforms.
Supports Splunk HEC, Elastic/OpenSearch, and generic syslog/CEF.

Usage:
    from core.enterprise.siem_integration import SIEMConnector, SIEMPlatform

    connector = SIEMConnector(
        platform=SIEMPlatform.SPLUNK,
        endpoint="https://splunk:8088",
        token="HEC-TOKEN",
    )
    connector.send_event({"event": "acquisition_complete", "evidence_id": "EV-001"})
    connector.send_ioc_alert(ioc_report)
"""

from __future__ import annotations

import json
import socket
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum

from loguru import logger


class SIEMPlatform(str, Enum):
    SPLUNK = "splunk"
    ELASTIC = "elastic"
    OPENSEARCH = "opensearch"
    SYSLOG = "syslog"
    GENERIC = "generic"


@dataclass
class SIEMEvent:
    event_type: str
    severity: str
    source: str = "forgelens"
    data: dict = None
    timestamp: str = ""

    def __post_init__(self):
        if self.data is None:
            self.data = {}
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()


@dataclass
class SIEMResult:
    success: bool
    platform: str
    events_sent: int = 0
    error: str = ""


class SIEMConnector:
    """
    Sends forensic events to SIEM platforms.
    """

    def __init__(
        self,
        platform: SIEMPlatform = SIEMPlatform.GENERIC,
        endpoint: str = "",
        token: str = "",
        index: str = "forgelens",
        timeout: int = 10,
    ) -> None:
        self.platform = platform
        self.endpoint = endpoint.rstrip("/")
        self.token = token
        self.index = index
        self.timeout = timeout

    def send_event(self, event_data: dict, severity: str = "info") -> SIEMResult:
        """Send a single event to the SIEM."""
        event = SIEMEvent(
            event_type=event_data.get("event_type", "forgelens_event"),
            severity=severity,
            data=event_data,
        )
        return self._dispatch([event])

    def send_acquisition_event(self, metadata: dict) -> SIEMResult:
        """Send an acquisition completion event."""
        event = SIEMEvent(
            event_type="acquisition_complete",
            severity="info",
            data={
                "evidence_id": metadata.get("evidence_id"),
                "case_id": metadata.get("case_id"),
                "examiner": metadata.get("examiner"),
                "sha256": metadata.get("hash_sha256"),
                "verified": metadata.get("verified"),
                "bytes_acquired": metadata.get("bytes_acquired"),
                "source": "forgelens",
            },
        )
        return self._dispatch([event])

    def send_ioc_alert(self, ioc_report) -> SIEMResult:
        """Send IOC alerts from an IOCReport to the SIEM."""
        events: list[SIEMEvent] = []

        # Send P1 and P2 IOCs as alerts
        for ioc in ioc_report.p1_critical + ioc_report.p2_high:
            events.append(
                SIEMEvent(
                    event_type="ioc_alert",
                    severity="critical" if ioc.priority == "P1" else "high",
                    data={
                        "ioc_type": ioc.ioc_type,
                        "ioc_value": ioc.ioc_value,
                        "score": ioc.score,
                        "priority": ioc.priority,
                        "occurrences": ioc.occurrences,
                        "mitre_technique": ioc.mitre_technique,
                        "recommended_action": ioc.recommended_action,
                        "source": "forgelens",
                    },
                )
            )

        if not events:
            return SIEMResult(success=True, platform=self.platform.value, events_sent=0)

        return self._dispatch(events)

    def send_anomaly_alert(self, anomaly_report) -> SIEMResult:
        """Send anomaly alerts from an AnomalyReport to the SIEM."""
        events: list[SIEMEvent] = []

        for anomaly in anomaly_report.critical + anomaly_report.high:
            events.append(
                SIEMEvent(
                    event_type="anomaly_alert",
                    severity=anomaly.severity,
                    data={
                        "anomaly_type": anomaly.anomaly_type,
                        "description": anomaly.description,
                        "score": anomaly.score,
                        "mitre_technique": anomaly.mitre_technique,
                        "mitre_tactic": anomaly.mitre_tactic,
                        "recommendation": anomaly.recommendation,
                        "source": "forgelens",
                    },
                )
            )

        return self._dispatch(events)

    def test_connection(self) -> bool:
        """Test connectivity to the SIEM endpoint."""
        if not self.endpoint:
            return False
        try:
            req = urllib.request.Request(self.endpoint)
            if self.token:
                req.add_header("Authorization", f"Bearer {self.token}")
            urllib.request.urlopen(req, timeout=self.timeout)
            return True
        except Exception:
            return False

    # ── Dispatch ──────────────────────────────────────────────────────────────

    def _dispatch(self, events: list[SIEMEvent]) -> SIEMResult:
        """Route events to the correct SIEM platform."""
        if not self.endpoint:
            logger.debug("SIEM: no endpoint configured — events logged only")
            for ev in events:
                logger.info("SIEM event [{}]: {}", ev.severity, ev.event_type)
            return SIEMResult(success=True, platform="none", events_sent=len(events))

        try:
            if self.platform == SIEMPlatform.SPLUNK:
                return self._send_splunk(events)
            elif self.platform in (SIEMPlatform.ELASTIC, SIEMPlatform.OPENSEARCH):
                return self._send_elastic(events)
            elif self.platform == SIEMPlatform.SYSLOG:
                return self._send_syslog(events)
            else:
                return self._send_generic(events)
        except Exception as exc:
            logger.error("SIEM dispatch error: {}", exc)
            return SIEMResult(success=False, platform=self.platform.value, error=str(exc))

    def _send_splunk(self, events: list[SIEMEvent]) -> SIEMResult:
        """Send events to Splunk HEC."""
        url = f"{self.endpoint}/services/collector/event"
        sent = 0
        for ev in events:
            payload = json.dumps(
                {
                    "time": datetime.now(timezone.utc).timestamp(),
                    "source": "forgelens",
                    "sourcetype": f"forgelens:{ev.event_type}",
                    "index": self.index,
                    "event": {**ev.data, "severity": ev.severity, "event_type": ev.event_type},
                }
            ).encode("utf-8")
            req = urllib.request.Request(
                url,
                data=payload,
                headers={
                    "Authorization": f"Splunk {self.token}",
                    "Content-Type": "application/json",
                },
            )
            try:
                urllib.request.urlopen(req, timeout=self.timeout)
                sent += 1
            except Exception as exc:
                logger.warning("Splunk HEC error: {}", exc)

        logger.info("Splunk: sent {}/{} events", sent, len(events))
        return SIEMResult(success=sent > 0, platform="splunk", events_sent=sent)

    def _send_elastic(self, events: list[SIEMEvent]) -> SIEMResult:
        """Send events to Elasticsearch/OpenSearch."""
        url = f"{self.endpoint}/{self.index}/_doc"
        sent = 0
        for ev in events:
            payload = json.dumps(
                {
                    "@timestamp": ev.timestamp,
                    "event_type": ev.event_type,
                    "severity": ev.severity,
                    **ev.data,
                }
            ).encode("utf-8")
            req = urllib.request.Request(
                url,
                data=payload,
                headers={
                    "Content-Type": "application/json",
                    **({"Authorization": f"ApiKey {self.token}"} if self.token else {}),
                },
            )
            try:
                urllib.request.urlopen(req, timeout=self.timeout)
                sent += 1
            except Exception as exc:
                logger.warning("Elastic error: {}", exc)

        return SIEMResult(success=sent > 0, platform=self.platform.value, events_sent=sent)

    def _send_syslog(self, events: list[SIEMEvent]) -> SIEMResult:
        """Send events via UDP syslog (CEF format)."""
        host, port_str = (self.endpoint.split(":") + ["514"])[:2]
        port = int(port_str)
        sent = 0
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            for ev in events:
                cef = (
                    f"CEF:0|ForgeLens|DFIR|0.1|{ev.event_type}|"
                    f"{ev.event_type}|{self._sev_to_cef(ev.severity)}|"
                    f"msg={json.dumps(ev.data)}"
                )
                try:
                    sock.sendto(cef.encode("utf-8"), (host, port))
                    sent += 1
                except Exception as exc:
                    logger.warning("Syslog error: {}", exc)

        return SIEMResult(success=sent > 0, platform="syslog", events_sent=sent)

    def _send_generic(self, events: list[SIEMEvent]) -> SIEMResult:
        """Send events as JSON POST to a generic HTTP endpoint."""
        payload = json.dumps(
            [
                {
                    "timestamp": ev.timestamp,
                    "event_type": ev.event_type,
                    "severity": ev.severity,
                    **ev.data,
                }
                for ev in events
            ]
        ).encode("utf-8")
        req = urllib.request.Request(
            self.endpoint,
            data=payload,
            headers={
                "Content-Type": "application/json",
                **({"Authorization": f"Bearer {self.token}"} if self.token else {}),
            },
        )
        try:
            urllib.request.urlopen(req, timeout=self.timeout)
            return SIEMResult(success=True, platform="generic", events_sent=len(events))
        except Exception as exc:
            return SIEMResult(success=False, platform="generic", error=str(exc))

    @staticmethod
    def _sev_to_cef(severity: str) -> int:
        return {"critical": 10, "high": 7, "medium": 5, "low": 3, "info": 1}.get(severity, 5)
