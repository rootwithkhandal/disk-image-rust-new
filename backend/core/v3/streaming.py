"""
Real-Time Evidence Streaming (V3.0)
=====================================
Streams forensic acquisition progress, analysis results, and alerts
to connected clients via Server-Sent Events (SSE).

Architecture:
  AcquisitionEngine  ->  StreamBroker  ->  SSE clients (browser/Tauri)
  AnalysisEngine     ->  StreamBroker  ->  SSE clients
  RemoteAgent        ->  StreamBroker  ->  SSE clients

StreamBroker is a pub/sub in-memory bus. FastAPI SSE endpoints subscribe
to channels and push events to clients as text/event-stream.

Usage (FastAPI route):
    from core.v3.streaming import broker

    @app.get("/api/stream/{case_id}")
    async def stream(case_id: str, request: Request):
        return StreamingResponse(
            broker.subscribe(f"case:{case_id}"),
            media_type="text/event-stream",
        )

Usage (publisher):
    from core.v3.streaming import broker
    broker.publish("case:CASE-001", "acquisition_progress", {"percent": 42.0})
    broker.publish("case:CASE-001", "alert", {"severity": "critical", "msg": "Mimikatz detected"})
"""

from __future__ import annotations

import asyncio
import json
import threading
import time
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import AsyncGenerator

from loguru import logger


@dataclass
class StreamEvent:
    event_type: str        # acquisition_progress | alert | analysis_complete | agent_status | etc.
    channel: str           # case:CASE-001 | global | agent:<id>
    data: dict = field(default_factory=dict)
    timestamp: str = ""
    event_id: str = ""

    def __post_init__(self) -> None:
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()
        if not self.event_id:
            import uuid
            self.event_id = str(uuid.uuid4())[:8]

    def to_sse(self) -> str:
        """Format as Server-Sent Event string."""
        payload = json.dumps({
            "type": self.event_type,
            "channel": self.channel,
            "data": self.data,
            "timestamp": self.timestamp,
        }, default=str)
        return f"id: {self.event_id}\nevent: {self.event_type}\ndata: {payload}\n\n"


class StreamBroker:
    """
    In-memory pub/sub broker for forensic event streaming.
    Thread-safe for sync publishers, async-compatible for FastAPI SSE consumers.
    """

    def __init__(self, max_history: int = 100) -> None:
        # channel -> list of asyncio.Queue for each subscriber
        self._subscribers: dict[str, list[asyncio.Queue]] = defaultdict(list)
        # channel -> last N events (for replay on reconnect)
        self._history: dict[str, list[StreamEvent]] = defaultdict(list)
        self._max_history = max_history
        self._lock = threading.Lock()
        self._loop: asyncio.AbstractEventLoop | None = None

    def set_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        """Register the running event loop (call from FastAPI startup)."""
        self._loop = loop

    def publish(
        self,
        channel: str,
        event_type: str,
        data: dict | None = None,
    ) -> StreamEvent:
        """
        Publish an event to a channel (thread-safe).
        Can be called from sync acquisition/analysis code.
        """
        event = StreamEvent(
            event_type=event_type,
            channel=channel,
            data=data or {},
        )

        # Store in history
        with self._lock:
            hist = self._history[channel]
            hist.append(event)
            if len(hist) > self._max_history:
                self._history[channel] = hist[-self._max_history:]

        # Push to all async subscribers on this channel + "global"
        for ch in (channel, "global"):
            subs = self._subscribers.get(ch, [])
            if subs and self._loop and self._loop.is_running():
                for q in list(subs):
                    try:
                        self._loop.call_soon_threadsafe(q.put_nowait, event)
                    except Exception:
                        pass

        logger.debug("Stream event | channel={} | type={}", channel, event_type)
        return event

    def publish_alert(
        self,
        case_id: str,
        severity: str,
        title: str,
        description: str,
        mitre_technique: str = "",
    ) -> StreamEvent:
        """Convenience method to publish a security alert."""
        return self.publish(
            f"case:{case_id}",
            "alert",
            {
                "severity": severity,
                "title": title,
                "description": description,
                "mitre_technique": mitre_technique,
            },
        )

    def publish_progress(
        self,
        case_id: str,
        evidence_id: str,
        operation: str,
        percent: float,
        bytes_done: int = 0,
        total_bytes: int = 0,
        throughput_mbps: float = 0.0,
    ) -> StreamEvent:
        """Convenience method to publish acquisition progress."""
        return self.publish(
            f"case:{case_id}",
            "acquisition_progress",
            {
                "evidence_id": evidence_id,
                "operation": operation,
                "percent": round(percent, 1),
                "bytes_done": bytes_done,
                "total_bytes": total_bytes,
                "throughput_mbps": throughput_mbps,
            },
        )

    async def subscribe(
        self,
        channel: str,
        replay_history: bool = True,
    ) -> AsyncGenerator[str, None]:
        """
        Async generator that yields SSE-formatted strings.
        Intended for use with FastAPI StreamingResponse.

        Args:
            channel:        Channel to subscribe to (e.g. "case:CASE-001").
            replay_history: Send last N events on connect for catch-up.
        """
        q: asyncio.Queue = asyncio.Queue(maxsize=200)

        with self._lock:
            self._subscribers[channel].append(q)

        try:
            # Replay history on connect
            if replay_history:
                for event in self._history.get(channel, []):
                    yield event.to_sse()

            # Keep-alive ping every 15s + real events
            while True:
                try:
                    event = await asyncio.wait_for(q.get(), timeout=15.0)
                    yield event.to_sse()
                except asyncio.TimeoutError:
                    # Send keep-alive comment
                    yield f": keep-alive {datetime.now(timezone.utc).isoformat()}\n\n"
        finally:
            with self._lock:
                try:
                    self._subscribers[channel].remove(q)
                except ValueError:
                    pass

    def get_history(self, channel: str, last_n: int | None = None) -> list[StreamEvent]:
        """Return event history for a channel."""
        hist = self._history.get(channel, [])
        return hist[-last_n:] if last_n else hist

    def subscriber_count(self, channel: str) -> int:
        return len(self._subscribers.get(channel, []))

    def channels(self) -> list[str]:
        return list(self._history.keys())


# ── Module-level singleton ────────────────────────────────────────────────────
broker = StreamBroker()


# ── Progress callback adapters ────────────────────────────────────────────────

def make_acquisition_callback(case_id: str, evidence_id: str):
    """
    Returns a progress_callback compatible with DiskImager.acquire().
    Publishes acquisition_progress events to the stream broker.
    """
    def callback(bytes_read: int, total_bytes: int) -> None:
        percent = (bytes_read / total_bytes * 100) if total_bytes else 0.0
        broker.publish_progress(
            case_id=case_id,
            evidence_id=evidence_id,
            operation="imaging",
            percent=percent,
            bytes_done=bytes_read,
            total_bytes=total_bytes,
        )
    return callback
