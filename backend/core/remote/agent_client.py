"""
Remote Agent Client
====================
Connects to a remote ForgeLens agent and dispatches tasks.
All communication is HMAC-signed. TLS is handled by the transport layer.

Usage:
    from core.remote.agent_client import AgentClient

    client = AgentClient("http://192.168.1.100:8765", token="secret")
    status = client.get_status()
    result = client.run_live_response()
    result = client.run_imaging(source="/dev/sda", case_id="CASE-001", examiner="Alice")
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass

from loguru import logger

from core.remote.agent import AgentStatus, AgentTask, AgentTaskResult


@dataclass
class ConnectionInfo:
    host: str
    port: int
    agent_id: str = ""
    os_name: str = ""
    hostname: str = ""
    last_seen: str = ""
    latency_ms: float = 0.0
    reachable: bool = False


class AgentClient:
    """
    Client for communicating with a remote ForgeLens agent.
    Signs all requests with HMAC-SHA256.
    """

    def __init__(
        self,
        base_url: str,
        token: str,
        timeout: int = 30,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self._token = token.encode("utf-8")
        self.timeout = timeout

    # ── Authentication ────────────────────────────────────────────────────────

    def _sign(self, payload: bytes) -> str:
        return hmac.new(self._token, payload, hashlib.sha256).hexdigest()

    # ── HTTP helpers ──────────────────────────────────────────────────────────

    def _get(self, path: str) -> dict:
        url = f"{self.base_url}{path}"
        try:
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.URLError as exc:
            raise ConnectionError(f"Cannot reach agent at {url}: {exc}") from exc
        except Exception as exc:
            raise RuntimeError(f"GET {url} failed: {exc}") from exc

    def _post(self, path: str, data: dict) -> dict:
        url = f"{self.base_url}{path}"
        body = json.dumps(data, default=str).encode("utf-8")
        signature = self._sign(body)

        req = urllib.request.Request(
            url,
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "X-ForgeLens-Signature": signature,
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            body_err = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"Agent returned {exc.code}: {body_err}") from exc
        except urllib.error.URLError as exc:
            raise ConnectionError(f"Cannot reach agent at {url}: {exc}") from exc

    # ── Status ────────────────────────────────────────────────────────────────

    def get_status(self) -> AgentStatus:
        """Get agent status and system info."""
        data = self._get("/status")
        return AgentStatus(
            **{k: v for k, v in data.items() if k in AgentStatus.__dataclass_fields__}
        )

    def ping(self) -> ConnectionInfo:
        """Ping the agent and return connection info with latency."""
        info = ConnectionInfo(
            host=self.base_url.split("://")[-1].split(":")[0],
            port=int(self.base_url.split(":")[-1]) if ":" in self.base_url else 8765,
        )
        start = time.perf_counter()
        try:
            status = self.get_status()
            info.latency_ms = round((time.perf_counter() - start) * 1000, 1)
            info.agent_id = status.agent_id
            info.os_name = status.os_name
            info.hostname = status.hostname
            info.last_seen = status.last_seen
            info.reachable = True
            logger.info("Agent ping OK | {} | {}ms", self.base_url, info.latency_ms)
        except Exception as exc:
            info.reachable = False
            logger.warning("Agent unreachable: {} — {}", self.base_url, exc)
        return info

    # ── Task dispatch ─────────────────────────────────────────────────────────

    def _run_task(self, task_type: str, params: dict | None = None) -> AgentTaskResult:
        """Submit a task to the agent and return the result."""
        task = AgentTask(
            task_id=str(uuid.uuid4()),
            task_type=task_type,
            params=params or {},
            submitted_at=__import__("datetime")
            .datetime.now(__import__("datetime").timezone.utc)
            .isoformat(),
        )
        logger.info("Submitting task {} to {}", task_type, self.base_url)
        data = self._post(
            "/task",
            {
                "task_id": task.task_id,
                "task_type": task.task_type,
                "params": task.params,
                "submitted_at": task.submitted_at,
                "submitted_by": task.submitted_by,
            },
        )
        return AgentTaskResult(
            **{k: v for k, v in data.items() if k in AgentTaskResult.__dataclass_fields__}
        )

    def run_live_response(self) -> AgentTaskResult:
        """Collect live response data from the remote target."""
        return self._run_task("live_response")

    def run_imaging(
        self,
        source: str,
        case_id: str,
        examiner: str,
        verify: bool = True,
    ) -> AgentTaskResult:
        """Perform remote disk imaging."""
        return self._run_task(
            "imaging",
            {
                "source": source,
                "case_id": case_id,
                "examiner": examiner,
                "verify": verify,
            },
        )

    def run_artifact_collect(self, artifact_type: str = "all") -> AgentTaskResult:
        """Collect artifacts from the remote target."""
        return self._run_task("artifact_collect", {"type": artifact_type})

    def run_memory_acquisition(self) -> AgentTaskResult:
        """Acquire RAM from the remote target."""
        return self._run_task("memory")

    def get_agent_status_task(self) -> AgentTaskResult:
        """Get detailed agent status via task interface."""
        return self._run_task("status")
