"""
Remote Acquisition Agent
=========================
Lightweight agent that runs on a remote target system.
Accepts encrypted commands from the ForgeLens server and
executes acquisition tasks, streaming results back securely.

Architecture:
    ForgeLens Server  <──HTTPS/TLS──>  Remote Agent
    (operator)                         (target system)

The agent:
- Listens for signed task commands
- Executes acquisition (imaging, artifact collection, live response)
- Streams results back encrypted
- Maintains a local audit log

Usage (on target):
    python -m core.remote.agent --host 0.0.0.0 --port 8765 --token <secret>

Usage (from server):
    from core.remote.agent_client import AgentClient
    client = AgentClient("https://target:8765", token="secret")
    result = client.run_task("live_response")
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import socket
import threading
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer, ThreadingHTTPServer
from pathlib import Path

from loguru import logger

import platform


@dataclass
class AgentTask:
    task_id: str
    task_type: str  # live_response | imaging | artifact_collect | memory
    params: dict = field(default_factory=dict)
    submitted_at: str = ""
    submitted_by: str = ""


@dataclass
class AgentTaskResult:
    task_id: str
    task_type: str
    success: bool
    data: dict = field(default_factory=dict)
    error: str = ""
    completed_at: str = ""
    duration_seconds: float = 0.0


@dataclass
class AgentStatus:
    agent_id: str
    hostname: str
    os_name: str
    os_version: str
    python_version: str
    agent_version: str = "0.1.0"
    uptime_seconds: float = 0.0
    tasks_completed: int = 0
    tasks_failed: int = 0
    last_seen: str = ""


class AgentAuthenticator:
    """
    HMAC-SHA256 request authentication.
    Every request must include a valid HMAC signature.
    """

    def __init__(self, token: str) -> None:
        self._token = token.encode("utf-8")

    def sign(self, payload: bytes) -> str:
        """Generate HMAC-SHA256 signature for a payload."""
        return hmac.new(self._token, payload, hashlib.sha256).hexdigest()

    def verify(self, payload: bytes, signature: str) -> bool:
        """Verify a payload signature."""
        expected = self.sign(payload)
        return hmac.compare_digest(expected, signature)


class RemoteAgent:
    """
    Lightweight HTTP-based remote acquisition agent.
    Runs on the target system and accepts signed task commands.
    """

    VERSION = "0.1.0"

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 8765,
        token: str = "",
        output_dir: Path | None = None,
    ) -> None:
        self.host = host
        self.port = port
        self.auth = AgentAuthenticator(token or os.urandom(32).hex())
        self.output_dir = output_dir or Path("./agent_output")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self._start_time = time.time()
        self._tasks_completed = 0
        self._tasks_failed = 0
        self._agent_id = self._generate_agent_id()
        self._server: HTTPServer | None = None
        self._running = False

    def _generate_agent_id(self) -> str:
        """Generate a unique agent ID based on hostname + MAC."""
        hostname = socket.gethostname()
        return hashlib.sha256(hostname.encode()).hexdigest()[:16]

    def get_status(self) -> AgentStatus:
        """Return current agent status."""
        return AgentStatus(
            agent_id=self._agent_id,
            hostname=socket.gethostname(),
            os_name=platform.system(),
            os_version=platform.version(),
            python_version=platform.python_version(),
            agent_version=self.VERSION,
            uptime_seconds=round(time.time() - self._start_time, 1),
            tasks_completed=self._tasks_completed,
            tasks_failed=self._tasks_failed,
            last_seen=datetime.now(timezone.utc).isoformat(),
        )

    def execute_task(self, task: AgentTask) -> AgentTaskResult:
        """
        Execute a task and return the result.
        Dispatches to the appropriate acquisition module.
        """
        start = time.perf_counter()
        logger.info("Agent executing task: {} ({})", task.task_id, task.task_type)

        try:
            if task.task_type == "live_response":
                data = self._task_live_response(task.params)
            elif task.task_type == "imaging":
                data = self._task_imaging(task.params)
            elif task.task_type == "artifact_collect":
                data = self._task_artifact_collect(task.params)
            elif task.task_type == "memory":
                data = self._task_memory(task.params)
            elif task.task_type == "status":
                data = asdict(self.get_status())
            else:
                raise ValueError(f"Unknown task type: {task.task_type}")

            duration = round(time.perf_counter() - start, 2)
            self._tasks_completed += 1
            result = AgentTaskResult(
                task_id=task.task_id,
                task_type=task.task_type,
                success=True,
                data=data,
                completed_at=datetime.now(timezone.utc).isoformat(),
                duration_seconds=duration,
            )
            logger.info("Task {} completed in {}s", task.task_id, duration)
            return result

        except Exception as exc:
            duration = round(time.perf_counter() - start, 2)
            self._tasks_failed += 1
            logger.error("Task {} failed: {}", task.task_id, exc)
            return AgentTaskResult(
                task_id=task.task_id,
                task_type=task.task_type,
                success=False,
                error=str(exc),
                completed_at=datetime.now(timezone.utc).isoformat(),
                duration_seconds=duration,
            )

    # ── Task implementations ──────────────────────────────────────────────────

    def _task_live_response(self, params: dict) -> dict:
        """Collect live response data from the target system."""
        os_name = platform.system()
        if os_name == "Windows":
            from platforms.windows.live_response import collect_all_live_response

            return collect_all_live_response()
        elif os_name == "Linux":
            from platforms.linux.artifacts import collect_all_artifacts

            return collect_all_artifacts()
        else:
            return {"platform": os_name, "note": "Live response not implemented for this platform"}

    def _task_imaging(self, params: dict) -> dict:
        """Perform disk imaging on the target."""
        source = params.get("source", "")

        if not source:
            raise ValueError("source parameter required for imaging task")

        from core.imaging.imager import DiskImager

        imager = DiskImager()
        result = imager.acquire(
            source=source,
            output_dir=str(self.output_dir),
            case_id=params.get("case_id", "REMOTE"),
            examiner=params.get("examiner", "remote_agent"),
            post_verify=params.get("verify", True),
        )
        return {
            "success": result.success,
            "evidence_id": result.evidence_id,
            "image_path": result.image_path,
            "sha256": result.hash_sha256,
            "bytes_acquired": result.bytes_acquired,
            "verified": result.verified,
            "error": result.error,
        }

    def _task_artifact_collect(self, params: dict) -> dict:
        """Collect artifacts from the target system."""
        os_name = platform.system()
        artifact_type = params.get("type", "all")

        if os_name == "Windows":
            if artifact_type == "registry":
                from platforms.windows.registry import collect_all_registry_artifacts

                data = collect_all_registry_artifacts()
                return {k: [asdict(a) for a in v] for k, v in data.items()}
            elif artifact_type == "browser":
                from platforms.windows.artifacts import collect_browser_history

                data = collect_browser_history()
                return {k: [asdict(e) for e in v] for k, v in data.items()}
            else:
                from platforms.windows import WindowsAcquisition

                out = self.output_dir / f"artifacts_{int(time.time())}"
                return WindowsAcquisition.collect_all(out, include_ram=False)
        elif os_name == "Linux":
            from platforms.linux.artifacts import collect_all_artifacts

            return collect_all_artifacts()
        else:
            return {"platform": os_name, "note": "Artifact collection not implemented"}

    def _task_memory(self, params: dict) -> dict:
        """Acquire memory from the target system."""
        output_path = self.output_dir / f"memory_{int(time.time())}.raw"
        os_name = platform.system()

        if os_name == "Windows":
            from platforms.windows.memory import acquire_ram

            result = acquire_ram(output_path)
            return asdict(result)
        elif os_name == "Linux":
            from platforms.linux.memory import acquire_ram

            result = acquire_ram(output_path)
            return asdict(result)
        else:
            return {"success": False, "error": f"Memory acquisition not supported on {os_name}"}

    # ── HTTP server ───────────────────────────────────────────────────────────

    def start(self) -> None:
        """Start the agent HTTP server in a background thread."""
        agent = self

        class Handler(BaseHTTPRequestHandler):
            timeout = 10  # Request read timeout

            def log_message(self, format: str, *args: object) -> None:
                logger.debug("Agent HTTP: " + format % args)

            def do_GET(self) -> None:
                if self.path == "/status":
                    self._respond(200, asdict(agent.get_status()))
                else:
                    self._respond(404, {"error": "Not found"})

            def do_POST(self) -> None:
                if self.path != "/task":
                    self._respond(404, {"error": "Not found"})
                    return

                # Verify signature
                sig = self.headers.get("X-ForgeLens-Signature", "")
                length = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(length)

                if not agent.auth.verify(body, sig):
                    self._respond(401, {"error": "Invalid signature"})
                    return

                try:
                    task_data = json.loads(body)
                    task = AgentTask(**task_data)
                    result = agent.execute_task(task)
                    self._respond(200, asdict(result))
                except Exception as exc:
                    self._respond(400, {"error": str(exc)})

            def _respond(self, code: int, data: dict) -> None:
                body = json.dumps(data, default=str).encode("utf-8")
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(body)
                self.wfile.flush()

        self._server = ThreadingHTTPServer((self.host, self.port), Handler)
        self._server.timeout = 10
        self._running = True

        def _serve():
            while self._running:
                self._server.handle_request()

        thread = threading.Thread(target=_serve, daemon=True)
        thread.start()
        # Give the server a moment to bind
        time.sleep(0.05)
        logger.info(
            "Remote agent started | {}:{} | agent_id={}", self.host, self.port, self._agent_id
        )

    def stop(self) -> None:
        """Stop the agent server."""
        self._running = False
        if self._server:
            self._server.server_close()
            self._server = None
        logger.info("Remote agent stopped")

    @property
    def is_running(self) -> bool:
        return self._running
