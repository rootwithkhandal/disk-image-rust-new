"""
Distributed Acquisition Coordinator (V3.0)
============================================
Orchestrates simultaneous forensic acquisition across multiple remote agents.
Manages task queues, parallel execution, progress aggregation, and fault tolerance.

Usage:
    from core.v3.distributed import DistributedAcquisition

    coord = DistributedAcquisition()
    coord.add_agent("192.168.1.10:8765", token="secret1", label="WORKSTATION-01")
    coord.add_agent("192.168.1.11:8765", token="secret2", label="SERVER-02")

    job = coord.acquire_all(case_id="CASE-001", examiner="Alice")
    coord.wait(job.job_id)
    print(coord.get_job_report(job.job_id))
"""

from __future__ import annotations

import json
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path

from loguru import logger

from core.config import settings


class AgentState(str, Enum):
    ONLINE   = "online"
    OFFLINE  = "offline"
    BUSY     = "busy"
    ERROR    = "error"


class JobState(str, Enum):
    PENDING  = "pending"
    RUNNING  = "running"
    COMPLETE = "complete"
    FAILED   = "failed"
    PARTIAL  = "partial"   # some agents failed, some succeeded


@dataclass
class AgentNode:
    agent_id: str
    url: str
    token: str
    label: str = ""
    state: AgentState = AgentState.OFFLINE
    last_seen: str = ""
    latency_ms: float = 0.0
    os_name: str = ""
    hostname: str = ""
    tasks_completed: int = 0
    current_task: str = ""


@dataclass
class AgentJobResult:
    agent_id: str
    label: str
    task_type: str
    success: bool
    duration_seconds: float = 0.0
    output: dict = field(default_factory=dict)
    error: str = ""
    started_at: str = ""
    completed_at: str = ""


@dataclass
class DistributedJob:
    job_id: str
    case_id: str
    examiner: str
    task_type: str
    state: JobState = JobState.PENDING
    agent_results: list[AgentJobResult] = field(default_factory=list)
    created_at: str = ""
    completed_at: str = ""
    total_agents: int = 0
    successful_agents: int = 0
    failed_agents: int = 0

    @property
    def progress_pct(self) -> float:
        if self.total_agents == 0:
            return 0.0
        done = self.successful_agents + self.failed_agents
        return round(done / self.total_agents * 100, 1)


class DistributedAcquisition:
    """
    Coordinates parallel forensic acquisition across multiple remote agents.
    Each agent runs independently; results are aggregated and stored in the vault.
    """

    STATE_FILE = "distributed_jobs.json"

    def __init__(self, base_path: Path | None = None) -> None:
        self._base = Path(base_path or settings.evidence.base_path)
        self._base.mkdir(parents=True, exist_ok=True)
        self._agents: dict[str, AgentNode] = {}
        self._jobs: dict[str, DistributedJob] = {}
        self._lock = threading.Lock()
        self._load_state()

    # ── Agent registry ────────────────────────────────────────────────────────

    def add_agent(self, url: str, token: str, label: str = "") -> AgentNode:
        """Register a remote agent."""
        agent_id = str(uuid.uuid4())[:8].upper()
        node = AgentNode(
            agent_id=agent_id,
            url=url.rstrip("/"),
            token=token,
            label=label or url,
        )
        with self._lock:
            self._agents[agent_id] = node
        self._save_state()
        logger.info("Agent registered | id={} | url={} | label={}", agent_id, url, label)
        return node

    def remove_agent(self, agent_id: str) -> bool:
        with self._lock:
            if agent_id in self._agents:
                del self._agents[agent_id]
                self._save_state()
                return True
        return False

    def list_agents(self) -> list[AgentNode]:
        return list(self._agents.values())

    def ping_all(self) -> dict[str, bool]:
        """Ping all registered agents and update their state. Returns {agent_id: reachable}."""
        results: dict[str, bool] = {}
        threads: list[threading.Thread] = []

        def _ping(node: AgentNode) -> None:
            try:
                from core.remote.agent_client import AgentClient
                client = AgentClient(node.url, node.token, timeout=5)
                info = client.ping()
                with self._lock:
                    node.state = AgentState.ONLINE if info.reachable else AgentState.OFFLINE
                    node.last_seen = datetime.now(timezone.utc).isoformat()
                    node.latency_ms = info.latency_ms
                    node.os_name = info.os_name
                    node.hostname = info.hostname
                results[node.agent_id] = info.reachable
            except Exception as exc:
                with self._lock:
                    node.state = AgentState.ERROR
                results[node.agent_id] = False
                logger.debug("Ping failed for {}: {}", node.url, exc)

        for node in self._agents.values():
            t = threading.Thread(target=_ping, args=(node,), daemon=True)
            threads.append(t)
            t.start()

        for t in threads:
            t.join(timeout=10)

        self._save_state()
        return results

    # ── Distributed job dispatch ──────────────────────────────────────────────

    def acquire_all(
        self,
        case_id: str,
        examiner: str,
        task_type: str = "live_response",
        params: dict | None = None,
        agent_ids: list[str] | None = None,
        async_run: bool = True,
    ) -> DistributedJob:
        """
        Dispatch an acquisition task to all (or selected) online agents simultaneously.

        Args:
            case_id:    Case ID for chain of custody.
            examiner:   Examiner name.
            task_type:  live_response | imaging | artifact_collect | memory
            params:     Task-specific parameters.
            agent_ids:  Limit to specific agent IDs (all online agents if None).
            async_run:  Run in background threads (True) or block until complete (False).

        Returns:
            DistributedJob tracking the overall progress.
        """
        job_id = str(uuid.uuid4())[:12].upper()
        targets = [
            n for n in self._agents.values()
            if n.state in (AgentState.ONLINE, AgentState.BUSY)
            and (agent_ids is None or n.agent_id in agent_ids)
        ]

        if not targets:
            raise RuntimeError("No online agents available. Run ping_all() first.")

        job = DistributedJob(
            job_id=job_id,
            case_id=case_id,
            examiner=examiner,
            task_type=task_type,
            state=JobState.RUNNING,
            created_at=datetime.now(timezone.utc).isoformat(),
            total_agents=len(targets),
        )
        with self._lock:
            self._jobs[job_id] = job

        logger.info("Distributed job {} | type={} | agents={}", job_id, task_type, len(targets))

        def _run_agent(node: AgentNode) -> None:
            result = self._dispatch_to_agent(node, job, params or {})
            with self._lock:
                job.agent_results.append(result)
                if result.success:
                    job.successful_agents += 1
                else:
                    job.failed_agents += 1
                # Update job state
                done = job.successful_agents + job.failed_agents
                if done == job.total_agents:
                    if job.failed_agents == 0:
                        job.state = JobState.COMPLETE
                    elif job.successful_agents == 0:
                        job.state = JobState.FAILED
                    else:
                        job.state = JobState.PARTIAL
                    job.completed_at = datetime.now(timezone.utc).isoformat()
                    self._save_state()
                    logger.info(
                        "Job {} complete | success={} failed={}",
                        job_id, job.successful_agents, job.failed_agents,
                    )

        threads = []
        for node in targets:
            t = threading.Thread(target=_run_agent, args=(node,), daemon=True)
            threads.append(t)
            t.start()

        if not async_run:
            for t in threads:
                t.join()

        return job

    def _dispatch_to_agent(
        self,
        node: AgentNode,
        job: DistributedJob,
        params: dict,
    ) -> AgentJobResult:
        """Execute a task on a single agent and sync results to vault."""
        from core.remote.agent_client import AgentClient
        from core.remote.sync import EvidenceSync

        result = AgentJobResult(
            agent_id=node.agent_id,
            label=node.label,
            task_type=job.task_type,
            success=False,
            started_at=datetime.now(timezone.utc).isoformat(),
        )
        start = time.perf_counter()

        with self._lock:
            node.state = AgentState.BUSY
            node.current_task = job.job_id

        try:
            client = AgentClient(node.url, node.token, timeout=600)
            dispatch = {
                "live_response":   client.run_live_response,
                "artifact_collect":client.run_artifact_collect,
                "memory":          client.run_memory_acquisition,
            }
            fn = dispatch.get(job.task_type)
            if fn is None:
                raise ValueError(f"Unsupported task type: {job.task_type}")

            task_result = fn()
            result.success = task_result.success
            result.output = task_result.data if isinstance(task_result.data, dict) else {}
            result.error = task_result.error

            # Sync collected data to vault
            if task_result.success and task_result.data:
                sync = EvidenceSync(self._base)
                evidence_id = f"EV-{node.agent_id}-{job.job_id[:6]}"
                out_dir = self._base / "cases" / job.case_id / evidence_id
                out_dir.mkdir(parents=True, exist_ok=True)
                data_path = out_dir / f"{job.task_type}_{node.agent_id}.json"
                data_path.write_text(
                    json.dumps(task_result.data, indent=2, default=str),
                    encoding="utf-8",
                )
                # Record in chain of custody
                try:
                    from core.chain_of_custody.evidence_manager import EvidenceManager
                    from core.acquisition.metadata_collector import MetadataCollector, DeviceMetadata
                    meta = MetadataCollector.new_session(
                        case_id=job.case_id,
                        examiner=job.examiner,
                        device_id=node.hostname or node.url,
                        acquisition_method=f"remote_{job.task_type}",
                        notes=f"Distributed acquisition via agent {node.label}",
                        device_meta=DeviceMetadata(
                            device_id=node.hostname or node.agent_id,
                            model=node.os_name,
                            interface="network",
                        ),
                    )
                    mgr = EvidenceManager()
                    mgr.create_evidence_entry(meta)
                    meta = MetadataCollector.finalize(meta, output_path=str(data_path))
                    mgr.write_metadata(meta)
                except Exception as exc:
                    logger.debug("CoC entry for distributed job failed: {}", exc)

        except Exception as exc:
            result.error = str(exc)
            logger.error("Agent {} task failed: {}", node.label, exc)

        finally:
            with self._lock:
                node.state = AgentState.ONLINE
                node.current_task = ""
                node.tasks_completed += 1

        result.duration_seconds = round(time.perf_counter() - start, 2)
        result.completed_at = datetime.now(timezone.utc).isoformat()
        return result

    def wait(self, job_id: str, timeout: int = 3600) -> DistributedJob:
        """Block until a job completes or timeout (seconds)."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            job = self._jobs.get(job_id)
            if job and job.state in (JobState.COMPLETE, JobState.FAILED, JobState.PARTIAL):
                return job
            time.sleep(2)
        raise TimeoutError(f"Job {job_id} did not complete within {timeout}s")

    def get_job(self, job_id: str) -> DistributedJob | None:
        return self._jobs.get(job_id)

    def get_job_report(self, job_id: str) -> dict:
        job = self._jobs.get(job_id)
        if not job:
            return {"error": f"Job {job_id} not found"}
        return {
            "job_id": job.job_id,
            "case_id": job.case_id,
            "task_type": job.task_type,
            "state": job.state.value,
            "progress": f"{job.progress_pct}%",
            "total_agents": job.total_agents,
            "successful": job.successful_agents,
            "failed": job.failed_agents,
            "created_at": job.created_at,
            "completed_at": job.completed_at,
            "results": [
                {
                    "agent": r.label,
                    "success": r.success,
                    "duration": r.duration_seconds,
                    "error": r.error,
                }
                for r in job.agent_results
            ],
        }

    # ── State persistence ─────────────────────────────────────────────────────

    def _save_state(self) -> None:
        state = {
            "agents": {aid: vars(n) for aid, n in self._agents.items()},
            "jobs": {
                jid: {
                    k: (v.value if hasattr(v, "value") else v)
                    for k, v in vars(j).items()
                    if k != "agent_results"
                }
                for jid, j in self._jobs.items()
            },
        }
        path = self._base / self.STATE_FILE
        try:
            path.write_text(json.dumps(state, indent=2, default=str), encoding="utf-8")
        except Exception as exc:
            logger.debug("State save error: {}", exc)

    def _load_state(self) -> None:
        path = self._base / self.STATE_FILE
        if not path.exists():
            return
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            for aid, nd in data.get("agents", {}).items():
                nd["state"] = AgentState(nd.get("state", "offline"))
                self._agents[aid] = AgentNode(**{
                    k: v for k, v in nd.items() if k in AgentNode.__dataclass_fields__
                })
        except Exception as exc:
            logger.debug("State load error: {}", exc)
