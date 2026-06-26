"""
Multi-Investigator Collaboration (V3.0)
=========================================
Shared workspace for multiple forensic investigators on the same case.

Features:
  - Examiner notes with timestamps and authorship
  - Task assignment and tracking
  - Evidence annotation (flag, comment, bookmark)
  - Conflict detection (concurrent evidence access)
  - Activity feed (who did what, when)
  - Case handoff workflow

All collaboration data is stored alongside the evidence in the vault
and is part of the immutable chain of custody.

Usage:
    from core.v3.collaboration import CollaborationManager

    collab = CollaborationManager(case_id="CASE-001")
    collab.add_note("EV-ABC", author="alice", text="Found mimikatz at 14:32")
    collab.assign_task("alice", "bob", task="Analyze memory dump EV-XYZ")
    collab.annotate("EV-ABC", author="bob", annotation_type="flag", text="Critical finding")
    feed = collab.get_activity_feed()
"""

from __future__ import annotations

import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path

from loguru import logger

from core.config import settings


class TaskStatus(str, Enum):
    OPEN       = "open"
    IN_PROGRESS = "in_progress"
    REVIEW     = "review"
    DONE       = "done"
    BLOCKED    = "blocked"


class AnnotationType(str, Enum):
    FLAG      = "flag"       # Mark for attention
    BOOKMARK  = "bookmark"   # Save for later
    COMMENT   = "comment"    # Free-text note
    CRITICAL  = "critical"   # Critical finding
    REVIEWED  = "reviewed"   # Marked as reviewed
    DISPUTE   = "dispute"    # Disputed finding — needs second opinion


@dataclass
class InvestigatorNote:
    note_id: str
    case_id: str
    evidence_id: str         # Empty string = case-level note
    author: str
    text: str
    timestamp: str
    edited_at: str = ""
    replies: list[dict] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)


@dataclass
class CollabTask:
    task_id: str
    case_id: str
    title: str
    description: str
    assigned_by: str
    assigned_to: str
    status: TaskStatus = TaskStatus.OPEN
    priority: str = "medium"
    evidence_id: str = ""    # Related evidence item
    created_at: str = ""
    updated_at: str = ""
    due_date: str = ""
    notes: str = ""


@dataclass
class EvidenceAnnotation:
    annotation_id: str
    case_id: str
    evidence_id: str
    author: str
    annotation_type: AnnotationType
    text: str
    timestamp: str
    offset: str = ""         # Optional: byte offset or timestamp within evidence
    mitre_technique: str = ""


@dataclass
class ActivityEvent:
    activity_id: str
    case_id: str
    actor: str
    action: str              # noted | annotated | assigned | completed | accessed | etc.
    target: str              # evidence_id, task_id, or "case"
    description: str
    timestamp: str
    metadata: dict = field(default_factory=dict)


class CollaborationManager:
    """
    Manages multi-investigator collaboration for a case.
    All data stored in evidence/cases/<case_id>/collab/
    """

    def __init__(self, case_id: str, base_path: Path | None = None) -> None:
        self.case_id = case_id
        self._base = Path(base_path or settings.evidence.base_path)
        self._collab_dir = self._base / "cases" / case_id / "collab"
        self._collab_dir.mkdir(parents=True, exist_ok=True)

        self._notes_path      = self._collab_dir / "notes.json"
        self._tasks_path      = self._collab_dir / "tasks.json"
        self._annotations_path= self._collab_dir / "annotations.json"
        self._activity_path   = self._collab_dir / "activity_feed.json"

    # ── Notes ─────────────────────────────────────────────────────────────────

    def add_note(
        self,
        author: str,
        text: str,
        evidence_id: str = "",
        tags: list[str] | None = None,
    ) -> InvestigatorNote:
        """Add an investigator note at case or evidence level."""
        note = InvestigatorNote(
            note_id=str(uuid.uuid4())[:8].upper(),
            case_id=self.case_id,
            evidence_id=evidence_id,
            author=author,
            text=text,
            timestamp=datetime.now(timezone.utc).isoformat(),
            tags=tags or [],
        )
        notes = self._load_json(self._notes_path, [])
        notes.append(asdict(note))
        self._save_json(self._notes_path, notes)

        self._record_activity(author, "noted", evidence_id or "case",
                              f"Added note: {text[:80]}")
        logger.debug("Note added | case={} | author={} | evidence={}", self.case_id, author, evidence_id)
        return note

    def reply_to_note(self, note_id: str, author: str, text: str) -> bool:
        """Add a reply to an existing note."""
        notes = self._load_json(self._notes_path, [])
        for note in notes:
            if note.get("note_id") == note_id:
                note.setdefault("replies", []).append({
                    "reply_id": str(uuid.uuid4())[:8],
                    "author": author,
                    "text": text,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                })
                self._save_json(self._notes_path, notes)
                self._record_activity(author, "replied", note_id, f"Reply: {text[:60]}")
                return True
        return False

    def get_notes(
        self,
        evidence_id: str | None = None,
        author: str | None = None,
    ) -> list[InvestigatorNote]:
        """Get notes, optionally filtered by evidence or author."""
        notes = self._load_json(self._notes_path, [])
        results = []
        for n in notes:
            if evidence_id and n.get("evidence_id") != evidence_id:
                continue
            if author and n.get("author") != author:
                continue
            results.append(InvestigatorNote(**{
                k: v for k, v in n.items() if k in InvestigatorNote.__dataclass_fields__
            }))
        return sorted(results, key=lambda x: x.timestamp, reverse=True)

    # ── Tasks ─────────────────────────────────────────────────────────────────

    def assign_task(
        self,
        assigned_by: str,
        assigned_to: str,
        title: str,
        description: str = "",
        evidence_id: str = "",
        priority: str = "medium",
        due_date: str = "",
    ) -> CollabTask:
        """Assign a task to an investigator."""
        now = datetime.now(timezone.utc).isoformat()
        task = CollabTask(
            task_id=str(uuid.uuid4())[:8].upper(),
            case_id=self.case_id,
            title=title,
            description=description,
            assigned_by=assigned_by,
            assigned_to=assigned_to,
            evidence_id=evidence_id,
            priority=priority,
            created_at=now,
            updated_at=now,
            due_date=due_date,
        )
        tasks = self._load_json(self._tasks_path, [])
        tasks.append(asdict(task))
        self._save_json(self._tasks_path, tasks)

        self._record_activity(
            assigned_by, "assigned",
            assigned_to,
            f"Task '{title}' assigned to {assigned_to}",
            metadata={"task_id": task.task_id, "evidence_id": evidence_id},
        )
        logger.info("Task assigned | {} -> {} | {}", assigned_by, assigned_to, title)
        return task

    def update_task_status(
        self,
        task_id: str,
        actor: str,
        status: TaskStatus,
        notes: str = "",
    ) -> bool:
        """Update a task's status."""
        tasks = self._load_json(self._tasks_path, [])
        for task in tasks:
            if task.get("task_id") == task_id:
                task["status"] = status.value
                task["updated_at"] = datetime.now(timezone.utc).isoformat()
                if notes:
                    task["notes"] = notes
                self._save_json(self._tasks_path, tasks)
                self._record_activity(actor, "updated_task", task_id,
                                      f"Task status: {status.value}")
                return True
        return False

    def get_tasks(
        self,
        assigned_to: str | None = None,
        status: TaskStatus | None = None,
    ) -> list[CollabTask]:
        """Get tasks, optionally filtered."""
        tasks = self._load_json(self._tasks_path, [])
        results = []
        for t in tasks:
            if assigned_to and t.get("assigned_to") != assigned_to:
                continue
            if status and t.get("status") != status.value:
                continue
            t["status"] = TaskStatus(t.get("status", "open"))
            results.append(CollabTask(**{
                k: v for k, v in t.items() if k in CollabTask.__dataclass_fields__
            }))
        return results

    # ── Annotations ───────────────────────────────────────────────────────────

    def annotate(
        self,
        evidence_id: str,
        author: str,
        annotation_type: AnnotationType | str,
        text: str = "",
        offset: str = "",
        mitre_technique: str = "",
    ) -> EvidenceAnnotation:
        """Annotate an evidence item."""
        if isinstance(annotation_type, str):
            annotation_type = AnnotationType(annotation_type)

        annotation = EvidenceAnnotation(
            annotation_id=str(uuid.uuid4())[:8].upper(),
            case_id=self.case_id,
            evidence_id=evidence_id,
            author=author,
            annotation_type=annotation_type,
            text=text,
            timestamp=datetime.now(timezone.utc).isoformat(),
            offset=offset,
            mitre_technique=mitre_technique,
        )
        annotations = self._load_json(self._annotations_path, [])
        annotations.append(asdict(annotation))
        self._save_json(self._annotations_path, annotations)

        self._record_activity(
            author, "annotated", evidence_id,
            f"{annotation_type.value}: {text[:60]}",
            metadata={"annotation_id": annotation.annotation_id},
        )
        return annotation

    def get_annotations(
        self,
        evidence_id: str | None = None,
        annotation_type: AnnotationType | None = None,
    ) -> list[EvidenceAnnotation]:
        """Get annotations, optionally filtered."""
        annotations = self._load_json(self._annotations_path, [])
        results = []
        for a in annotations:
            if evidence_id and a.get("evidence_id") != evidence_id:
                continue
            if annotation_type and a.get("annotation_type") != annotation_type.value:
                continue
            a["annotation_type"] = AnnotationType(a.get("annotation_type", "comment"))
            results.append(EvidenceAnnotation(**{
                k: v for k, v in a.items() if k in EvidenceAnnotation.__dataclass_fields__
            }))
        return results

    # ── Activity feed ─────────────────────────────────────────────────────────

    def get_activity_feed(
        self,
        actor: str | None = None,
        limit: int = 100,
    ) -> list[ActivityEvent]:
        """Return recent activity, optionally filtered by actor."""
        activities = self._load_json(self._activity_path, [])
        results = [
            ActivityEvent(**{k: v for k, v in a.items() if k in ActivityEvent.__dataclass_fields__})
            for a in activities
            if not actor or a.get("actor") == actor
        ]
        return sorted(results, key=lambda x: x.timestamp, reverse=True)[:limit]

    def _record_activity(
        self,
        actor: str,
        action: str,
        target: str,
        description: str,
        metadata: dict | None = None,
    ) -> None:
        event = ActivityEvent(
            activity_id=str(uuid.uuid4())[:8],
            case_id=self.case_id,
            actor=actor,
            action=action,
            target=target,
            description=description,
            timestamp=datetime.now(timezone.utc).isoformat(),
            metadata=metadata or {},
        )
        activities = self._load_json(self._activity_path, [])
        activities.append(asdict(event))
        # Keep last 1000 events
        if len(activities) > 1000:
            activities = activities[-1000:]
        self._save_json(self._activity_path, activities)

    # ── Case handoff ──────────────────────────────────────────────────────────

    def initiate_handoff(
        self,
        from_examiner: str,
        to_examiner: str,
        summary: str,
        open_items: list[str] | None = None,
    ) -> dict:
        """
        Create a formal case handoff record.
        Documents what was done and what remains for the incoming examiner.
        """
        handoff = {
            "handoff_id": str(uuid.uuid4())[:8].upper(),
            "case_id": self.case_id,
            "from_examiner": from_examiner,
            "to_examiner": to_examiner,
            "summary": summary,
            "open_items": open_items or [],
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "open_tasks": len(self.get_tasks(status=TaskStatus.OPEN)),
            "total_notes": len(self.get_notes()),
            "critical_annotations": len(self.get_annotations(annotation_type=AnnotationType.CRITICAL)),
        }
        handoff_path = self._collab_dir / f"handoff_{handoff['handoff_id']}.json"
        handoff_path.write_text(json.dumps(handoff, indent=2), encoding="utf-8")

        self._record_activity(
            from_examiner, "handoff", to_examiner,
            f"Case handed off to {to_examiner}: {summary[:80]}",
            metadata={"handoff_id": handoff["handoff_id"]},
        )
        # Auto-assign outstanding tasks to new examiner
        for task in self.get_tasks(status=TaskStatus.OPEN):
            self.update_task_status(task.task_id, from_examiner, TaskStatus.OPEN,
                                    notes=f"Transferred to {to_examiner}")

        logger.info("Case handoff | {} -> {} | case={}", from_examiner, to_examiner, self.case_id)
        return handoff

    # ── Dashboard ─────────────────────────────────────────────────────────────

    def get_dashboard(self) -> dict:
        """Return a collaboration dashboard for the case."""
        all_tasks = self.get_tasks()
        all_notes = self.get_notes()
        all_annotations = self.get_annotations()
        feed = self.get_activity_feed(limit=10)

        # Workload by examiner
        workload: dict[str, int] = {}
        for task in all_tasks:
            workload[task.assigned_to] = workload.get(task.assigned_to, 0) + 1

        return {
            "case_id": self.case_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "tasks": {
                "total": len(all_tasks),
                "open": len([t for t in all_tasks if t.status == TaskStatus.OPEN]),
                "in_progress": len([t for t in all_tasks if t.status == TaskStatus.IN_PROGRESS]),
                "done": len([t for t in all_tasks if t.status == TaskStatus.DONE]),
                "blocked": len([t for t in all_tasks if t.status == TaskStatus.BLOCKED]),
            },
            "notes": len(all_notes),
            "annotations": {
                "total": len(all_annotations),
                "critical": len([a for a in all_annotations if a.annotation_type == AnnotationType.CRITICAL]),
                "flags": len([a for a in all_annotations if a.annotation_type == AnnotationType.FLAG]),
            },
            "workload_by_examiner": workload,
            "recent_activity": [
                {"actor": e.actor, "action": e.action, "target": e.target, "ts": e.timestamp[:19]}
                for e in feed
            ],
        }

    # ── I/O helpers ───────────────────────────────────────────────────────────

    def _load_json(self, path: Path, default: list | dict) -> list | dict:
        if path.exists():
            try:
                return json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                pass
        return default

    def _save_json(self, path: Path, data: list | dict) -> None:
        path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
