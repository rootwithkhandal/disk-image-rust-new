"""
ForgeLens V3.0 API Routes
===========================
Full REST + SSE API for the Battlefield Edition.

Endpoints:
  GET  /api/stream/{case_id}           — SSE event stream for a case
  GET  /api/stream/global              — SSE global event stream

  GET  /api/cases                      — list all cases
  POST /api/cases                      — create case
  GET  /api/cases/{case_id}            — get case detail
  PATCH /api/cases/{case_id}           — update case

  GET  /api/cases/{case_id}/evidence   — list evidence for a case
  GET  /api/cases/{case_id}/ledger     — get immutable ledger
  POST /api/cases/{case_id}/ledger/verify — verify ledger chain integrity

  GET  /api/cases/{case_id}/graph      — threat graph JSON
  GET  /api/cases/{case_id}/graph.dot  — threat graph DOT (Graphviz)
  GET  /api/cases/{case_id}/graph.stix — STIX 2.1 bundle

  GET  /api/cases/{case_id}/timeline   — fused cross-device timeline
  GET  /api/cases/{case_id}/collab     — collaboration dashboard
  POST /api/cases/{case_id}/collab/notes      — add note
  GET  /api/cases/{case_id}/collab/notes      — get notes
  POST /api/cases/{case_id}/collab/tasks      — assign task
  GET  /api/cases/{case_id}/collab/tasks      — get tasks
  PATCH /api/cases/{case_id}/collab/tasks/{task_id} — update task status
  POST /api/cases/{case_id}/collab/annotate   — annotate evidence
  POST /api/cases/{case_id}/collab/handoff    — initiate case handoff

  GET  /api/agents                     — list distributed agents
  POST /api/agents                     — register agent
  POST /api/agents/ping                — ping all agents
  POST /api/agents/acquire             — dispatch distributed acquisition
  GET  /api/agents/jobs/{job_id}       — get job status/report
"""

from __future__ import annotations

import json
from pathlib import Path

from fastapi import APIRouter, Body, HTTPException, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from core.v3.streaming import broker

router = APIRouter(prefix="/api/v3", tags=["v3"])


# ── SSE Streaming ─────────────────────────────────────────────────────────────

@router.get("/stream/{case_id}")
async def stream_case(case_id: str, request: Request):
    """SSE stream for a specific case — progress, alerts, analysis events."""
    async def event_gen():
        async for chunk in broker.subscribe(f"case:{case_id}"):
            if await request.is_disconnected():
                break
            yield chunk
    return StreamingResponse(event_gen(), media_type="text/event-stream",
                              headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@router.get("/stream/global")
async def stream_global(request: Request):
    """SSE global stream — all events across all cases."""
    async def event_gen():
        async for chunk in broker.subscribe("global"):
            if await request.is_disconnected():
                break
            yield chunk
    return StreamingResponse(event_gen(), media_type="text/event-stream",
                              headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@router.get("/stream/history/{case_id}")
def stream_history(case_id: str, last_n: int = 50):
    """Return recent event history for a case channel (for reconnect catch-up)."""
    events = broker.get_history(f"case:{case_id}", last_n=last_n)
    return {"channel": f"case:{case_id}", "events": [
        {"type": e.event_type, "data": e.data, "timestamp": e.timestamp}
        for e in events
    ]}


# ── Cases ─────────────────────────────────────────────────────────────────────

class CreateCaseRequest(BaseModel):
    case_id: str
    examiner: str
    title: str = ""
    description: str = ""
    tags: list[str] = []
    priority: str = "medium"


class UpdateCaseRequest(BaseModel):
    status: str | None = None
    notes: str | None = None
    tags: list[str] | None = None
    priority: str | None = None


@router.get("/cases")
def list_cases(status: str | None = None):
    """List all cases in the evidence vault."""
    from core.chain_of_custody.case_manager import CaseManager, CaseStatus
    mgr = CaseManager()
    filt = CaseStatus(status) if status else None
    cases = mgr.list_cases(status=filt)
    return {"cases": [c.to_dict() for c in cases], "total": len(cases)}


@router.post("/cases", status_code=201)
def create_case(req: CreateCaseRequest):
    """Create a new case."""
    from core.chain_of_custody.case_manager import CaseManager
    mgr = CaseManager()
    case = mgr.create_case(
        case_id=req.case_id, examiner=req.examiner,
        title=req.title, description=req.description,
        tags=req.tags, priority=req.priority,
    )
    broker.publish(f"case:{req.case_id}", "case_created", {"case_id": req.case_id, "examiner": req.examiner})
    return case.to_dict()


@router.get("/cases/{case_id}")
def get_case(case_id: str):
    """Get case detail with evidence list and collaboration summary."""
    from core.chain_of_custody.case_manager import CaseManager
    from core.chain_of_custody.evidence_manager import EvidenceManager
    from core.enterprise.case_orchestrator import CaseOrchestrator

    case = CaseManager().get_case(case_id)
    if not case:
        raise HTTPException(404, f"Case {case_id} not found")

    mgr = EvidenceManager()
    evidence_ids = mgr.list_evidence(case_id)
    orch = CaseOrchestrator()
    assignments = orch.get_assignments(case_id)

    return {
        **case.to_dict(),
        "evidence_count": len(evidence_ids),
        "evidence_ids": evidence_ids,
        "assignments": [{"examiner": a.examiner, "role": a.role} for a in assignments],
    }


@router.patch("/cases/{case_id}")
def update_case(case_id: str, req: UpdateCaseRequest):
    """Update case status, notes, tags, or priority."""
    from core.chain_of_custody.case_manager import CaseManager, CaseStatus
    mgr = CaseManager()
    case = mgr.update_case(
        case_id,
        status=CaseStatus(req.status) if req.status else None,
        notes=req.notes,
        tags=req.tags,
        priority=req.priority,
    )
    if not case:
        raise HTTPException(404, f"Case {case_id} not found")
    broker.publish(f"case:{case_id}", "case_updated", {"case_id": case_id, "status": case.status.value})
    return case.to_dict()


# ── Evidence ──────────────────────────────────────────────────────────────────

@router.get("/cases/{case_id}/evidence")
def list_evidence(case_id: str):
    """List all evidence items for a case with metadata."""
    from core.chain_of_custody.evidence_index import EvidenceIndex
    idx = EvidenceIndex()
    entries = idx.get_by_case(case_id)
    return {
        "case_id": case_id,
        "evidence": [
            {
                "evidence_id": e.evidence_id,
                "device": e.device_model or e.device_id,
                "method": e.acquisition_method,
                "examiner": e.examiner,
                "size_gb": e.size_gb,
                "verified": e.verified,
                "tags": e.tags,
                "timestamp": e.timestamp_utc,
                "sha256": e.hash_sha256[:16] + "..." if e.hash_sha256 else "",
            }
            for e in entries
        ],
        "total": len(entries),
    }


@router.get("/cases/{case_id}/evidence/{evidence_id}/custody")
def get_custody_chain(case_id: str, evidence_id: str):
    """Get the chain of custody for an evidence item."""
    from core.chain_of_custody.evidence_manager import EvidenceManager
    mgr = EvidenceManager()
    events = mgr.get_custody_chain(case_id, evidence_id)
    if not events:
        raise HTTPException(404, f"No custody events for {evidence_id}")
    return {"evidence_id": evidence_id, "case_id": case_id, "events": events}


# ── Immutable Ledger ──────────────────────────────────────────────────────────

@router.get("/cases/{case_id}/ledger")
def get_ledger(case_id: str, evidence_id: str | None = None):
    """Get ledger entries for a case, optionally filtered by evidence."""
    from core.v3.ledger import EvidenceLedger
    ledger = EvidenceLedger(case_id)
    entries = ledger.get_entries(evidence_id=evidence_id)
    return {
        "case_id": case_id,
        "total_entries": len(entries),
        "entries": [
            {
                "seq": e.seq,
                "evidence_id": e.evidence_id,
                "event_type": e.event_type,
                "actor": e.actor,
                "timestamp": e.timestamp,
                "notes": e.notes,
                "entry_hash": e.entry_hash[:16] + "...",
            }
            for e in entries
        ],
    }


@router.post("/cases/{case_id}/ledger/verify")
def verify_ledger(case_id: str):
    """Verify the hash-chain integrity of the case ledger."""
    from core.v3.ledger import EvidenceLedger
    from dataclasses import asdict
    ledger = EvidenceLedger(case_id)
    valid, report = ledger.verify_chain()
    return {
        "valid": valid,
        "report": asdict(report),
    }


@router.post("/cases/{case_id}/ledger/migrate")
def migrate_ledger(case_id: str):
    """Migrate existing chain_of_custody.json events into the immutable ledger."""
    from core.v3.ledger import EvidenceLedger
    ledger = EvidenceLedger.migrate_from_coc(case_id)
    entries = ledger.get_entries()
    return {"case_id": case_id, "migrated_entries": len(entries)}


# ── Threat Graph ──────────────────────────────────────────────────────────────

@router.get("/cases/{case_id}/graph")
def get_threat_graph(case_id: str):
    """Build and return the threat graph for a case (JSON)."""
    from core.v3.threat_graph import ThreatGraph
    from core.chain_of_custody.evidence_manager import EvidenceManager
    from core.chain_of_custody.evidence_index import EvidenceIndex
    import json as _json

    graph = ThreatGraph(case_id)

    # Load processes and connections from all evidence items
    mgr = EvidenceManager()
    idx = EvidenceIndex()
    for entry in idx.get_by_case(case_id):
        ev_dir = mgr.evidence_dir(case_id, entry.evidence_id)
        # Load process export JSON if exists
        for proc_file in ev_dir.glob("*.processes.json"):
            try:
                data = _json.loads(proc_file.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    graph.ingest_processes(data.get("processes", []))
                    graph.ingest_connections(data.get("connections", []))
            except Exception:
                pass

    summary = graph.analyze()
    from dataclasses import asdict
    return {
        "case_id": case_id,
        "summary": asdict(summary),
        "nodes": [asdict(n) for n in graph._nodes.values()],
        "edges": [asdict(e) for e in graph._edges.values()],
    }


@router.get("/cases/{case_id}/graph.dot", response_class=None)
def get_threat_graph_dot(case_id: str):
    """Return Graphviz DOT format for the threat graph."""
    import tempfile, os
    from core.v3.threat_graph import ThreatGraph
    graph = ThreatGraph(case_id)
    with tempfile.NamedTemporaryFile(mode="w", suffix=".dot", delete=False) as f:
        tmp = Path(f.name)
    try:
        graph.export_dot(tmp)
        content = tmp.read_text(encoding="utf-8")
    finally:
        tmp.unlink(missing_ok=True)
    from fastapi.responses import PlainTextResponse
    return PlainTextResponse(content, media_type="text/vnd.graphviz")


@router.get("/cases/{case_id}/graph.stix")
def get_threat_graph_stix(case_id: str):
    """Return STIX 2.1 bundle for the threat graph IOCs."""
    import tempfile
    from core.v3.threat_graph import ThreatGraph
    graph = ThreatGraph(case_id)
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        tmp = Path(f.name)
    try:
        graph.export_stix(tmp)
        data = json.loads(tmp.read_text(encoding="utf-8"))
    finally:
        tmp.unlink(missing_ok=True)
    return data


# ── Timeline Fusion ───────────────────────────────────────────────────────────

@router.get("/cases/{case_id}/timeline")
def get_fused_timeline(case_id: str, suspicious_only: bool = False):
    """Return the cross-device fused timeline for a case."""
    from core.v3.timeline_fusion import TimelineFusion
    from core.chain_of_custody.evidence_manager import EvidenceManager
    import json as _json

    fusion = TimelineFusion(case_id)
    mgr = EvidenceManager()

    for ev_id in mgr.list_evidence(case_id):
        ev_dir = mgr.evidence_dir(case_id, ev_id)
        for proc_file in ev_dir.glob("*.processes.json"):
            try:
                data = _json.loads(proc_file.read_text(encoding="utf-8"))
                procs = data.get("processes", []) if isinstance(data, dict) else data
                if procs:
                    fusion.add_source(ev_id, "memory", procs)
            except Exception:
                pass

    events = fusion.build()
    if suspicious_only:
        events = [e for e in events if e.is_suspicious]

    from dataclasses import asdict
    return {
        "case_id": case_id,
        "total_events": len(events),
        "sources": [f"{dev}({st})" for dev, st, _ in fusion._sources],
        "events": [asdict(e) for e in events[:500]],  # cap at 500 for API
    }


# ── Collaboration ─────────────────────────────────────────────────────────────

class NoteRequest(BaseModel):
    author: str
    text: str
    evidence_id: str = ""
    tags: list[str] = []


class TaskRequest(BaseModel):
    assigned_by: str
    assigned_to: str
    title: str
    description: str = ""
    evidence_id: str = ""
    priority: str = "medium"
    due_date: str = ""


class TaskUpdateRequest(BaseModel):
    actor: str
    status: str
    notes: str = ""


class AnnotateRequest(BaseModel):
    evidence_id: str
    author: str
    annotation_type: str
    text: str = ""
    mitre_technique: str = ""


class HandoffRequest(BaseModel):
    from_examiner: str
    to_examiner: str
    summary: str
    open_items: list[str] = []


@router.get("/cases/{case_id}/collab")
def get_collab_dashboard(case_id: str):
    """Collaboration dashboard for a case."""
    from core.v3.collaboration import CollaborationManager
    collab = CollaborationManager(case_id)
    return collab.get_dashboard()


@router.post("/cases/{case_id}/collab/notes", status_code=201)
def add_note(case_id: str, req: NoteRequest):
    """Add an investigator note."""
    from core.v3.collaboration import CollaborationManager
    from dataclasses import asdict
    collab = CollaborationManager(case_id)
    note = collab.add_note(req.author, req.text, req.evidence_id, req.tags)
    broker.publish(f"case:{case_id}", "note_added", {"author": req.author, "note_id": note.note_id})
    return asdict(note)


@router.get("/cases/{case_id}/collab/notes")
def get_notes(case_id: str, evidence_id: str | None = None, author: str | None = None):
    """Get notes for a case."""
    from core.v3.collaboration import CollaborationManager
    from dataclasses import asdict
    collab = CollaborationManager(case_id)
    notes = collab.get_notes(evidence_id=evidence_id, author=author)
    return {"notes": [asdict(n) for n in notes], "total": len(notes)}


@router.post("/cases/{case_id}/collab/tasks", status_code=201)
def assign_task(case_id: str, req: TaskRequest):
    """Assign a task to an investigator."""
    from core.v3.collaboration import CollaborationManager
    from dataclasses import asdict
    collab = CollaborationManager(case_id)
    task = collab.assign_task(
        req.assigned_by, req.assigned_to, req.title,
        req.description, req.evidence_id, req.priority, req.due_date,
    )
    broker.publish(f"case:{case_id}", "task_assigned",
                   {"task_id": task.task_id, "assigned_to": req.assigned_to})
    return asdict(task)


@router.get("/cases/{case_id}/collab/tasks")
def get_tasks(case_id: str, assigned_to: str | None = None, status: str | None = None):
    """Get tasks for a case."""
    from core.v3.collaboration import CollaborationManager, TaskStatus
    from dataclasses import asdict
    collab = CollaborationManager(case_id)
    tasks = collab.get_tasks(
        assigned_to=assigned_to,
        status=TaskStatus(status) if status else None,
    )
    return {"tasks": [asdict(t) for t in tasks], "total": len(tasks)}


@router.patch("/cases/{case_id}/collab/tasks/{task_id}")
def update_task(case_id: str, task_id: str, req: TaskUpdateRequest):
    """Update a task status."""
    from core.v3.collaboration import CollaborationManager, TaskStatus
    collab = CollaborationManager(case_id)
    ok = collab.update_task_status(task_id, req.actor, TaskStatus(req.status), req.notes)
    if not ok:
        raise HTTPException(404, f"Task {task_id} not found")
    broker.publish(f"case:{case_id}", "task_updated",
                   {"task_id": task_id, "status": req.status, "actor": req.actor})
    return {"task_id": task_id, "status": req.status, "updated": True}


@router.post("/cases/{case_id}/collab/annotate", status_code=201)
def annotate_evidence(case_id: str, req: AnnotateRequest):
    """Annotate an evidence item."""
    from core.v3.collaboration import CollaborationManager, AnnotationType
    from dataclasses import asdict
    collab = CollaborationManager(case_id)
    ann = collab.annotate(
        req.evidence_id, req.author,
        AnnotationType(req.annotation_type), req.text,
        mitre_technique=req.mitre_technique,
    )
    broker.publish(f"case:{case_id}", "annotation_added",
                   {"evidence_id": req.evidence_id, "type": req.annotation_type})
    return asdict(ann)


@router.post("/cases/{case_id}/collab/handoff")
def initiate_handoff(case_id: str, req: HandoffRequest):
    """Initiate a formal case handoff between examiners."""
    from core.v3.collaboration import CollaborationManager
    collab = CollaborationManager(case_id)
    handoff = collab.initiate_handoff(
        req.from_examiner, req.to_examiner, req.summary, req.open_items,
    )
    broker.publish(f"case:{case_id}", "case_handoff",
                   {"from": req.from_examiner, "to": req.to_examiner})
    return handoff


# ── Distributed Agents ────────────────────────────────────────────────────────

class AddAgentRequest(BaseModel):
    url: str
    token: str
    label: str = ""


class AcquireRequest(BaseModel):
    case_id: str
    examiner: str
    task_type: str = "live_response"
    params: dict = {}
    agent_ids: list[str] = []


@router.get("/agents")
def list_agents():
    """List all registered distributed agents."""
    from core.v3.distributed import DistributedAcquisition
    from dataclasses import asdict
    coord = DistributedAcquisition()
    return {"agents": [asdict(a) for a in coord.list_agents()], "total": len(coord.list_agents())}


@router.post("/agents", status_code=201)
def add_agent(req: AddAgentRequest):
    """Register a remote acquisition agent."""
    from core.v3.distributed import DistributedAcquisition
    from dataclasses import asdict
    coord = DistributedAcquisition()
    node = coord.add_agent(req.url, req.token, req.label)
    return asdict(node)


@router.post("/agents/ping")
def ping_agents():
    """Ping all registered agents and update their status."""
    from core.v3.distributed import DistributedAcquisition
    coord = DistributedAcquisition()
    results = coord.ping_all()
    online = sum(1 for v in results.values() if v)
    return {"results": results, "online": online, "offline": len(results) - online}


@router.post("/agents/acquire")
def distributed_acquire(req: AcquireRequest):
    """Dispatch an acquisition task to all online agents."""
    from core.v3.distributed import DistributedAcquisition
    coord = DistributedAcquisition()
    try:
        job = coord.acquire_all(
            case_id=req.case_id,
            examiner=req.examiner,
            task_type=req.task_type,
            params=req.params,
            agent_ids=req.agent_ids or None,
            async_run=True,
        )
        broker.publish(f"case:{req.case_id}", "distributed_job_started",
                       {"job_id": job.job_id, "task_type": req.task_type, "agents": job.total_agents})
        return {"job_id": job.job_id, "total_agents": job.total_agents, "state": job.state.value}
    except RuntimeError as exc:
        raise HTTPException(400, str(exc))


@router.get("/agents/jobs/{job_id}")
def get_job(job_id: str):
    """Get the status and report for a distributed acquisition job."""
    from core.v3.distributed import DistributedAcquisition
    coord = DistributedAcquisition()
    report = coord.get_job_report(job_id)
    if "error" in report:
        raise HTTPException(404, report["error"])
    return report
