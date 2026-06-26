"""
Case Management System
=======================
Manages cases as first-class objects with metadata, status,
examiner assignment, and evidence inventory.

Usage:
    from core.chain_of_custody.case_manager import CaseManager

    mgr = CaseManager()
    case = mgr.create_case("CASE-2026-001", examiner="Alice", description="Ransomware IR")
    mgr.add_evidence_to_case(case.case_id, "EV-ABC123")
    cases = mgr.search_cases("ransomware")
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path

from loguru import logger

from core.config import settings


class CaseStatus(str, Enum):
    OPEN = "open"
    ACTIVE = "active"
    CLOSED = "closed"
    ARCHIVED = "archived"


@dataclass
class Case:
    case_id: str
    title: str
    examiner: str
    status: CaseStatus = CaseStatus.OPEN
    description: str = ""
    created_at: str = ""
    updated_at: str = ""
    closed_at: str = ""
    tags: list[str] = field(default_factory=list)
    evidence_ids: list[str] = field(default_factory=list)
    notes: str = ""
    priority: str = "medium"  # low | medium | high | critical

    def to_dict(self) -> dict:
        return asdict(self)


class CaseManager:
    """
    Manages the case registry — a flat JSON index of all cases.
    Each case maps to a directory under evidence/cases/<case_id>/
    """

    REGISTRY_FILE = "case_registry.json"

    def __init__(self, base_path: Path | None = None) -> None:
        self.base_path = Path(base_path or settings.evidence.base_path)
        self.cases_dir = self.base_path / "cases"
        self.cases_dir.mkdir(parents=True, exist_ok=True)
        self._registry_path = self.base_path / self.REGISTRY_FILE
        self._registry: dict[str, dict] = self._load_registry()

    # ── Registry I/O ──────────────────────────────────────────────────────────

    def _load_registry(self) -> dict[str, dict]:
        if self._registry_path.exists():
            try:
                return json.loads(self._registry_path.read_text(encoding="utf-8"))
            except Exception as exc:
                logger.error("Failed to load case registry: {}", exc)
        return {}

    def _save_registry(self) -> None:
        self._registry_path.write_text(
            json.dumps(self._registry, indent=2, default=str),
            encoding="utf-8",
        )

    # ── Case CRUD ─────────────────────────────────────────────────────────────

    def create_case(
        self,
        case_id: str,
        examiner: str,
        title: str = "",
        description: str = "",
        tags: list[str] | None = None,
        priority: str = "medium",
    ) -> Case:
        """
        Create a new case and register it.

        Args:
            case_id:     Unique case identifier (e.g. CASE-2026-001).
            examiner:    Lead examiner name.
            title:       Short case title.
            description: Free-text description.
            tags:        List of tags for categorization.
            priority:    low | medium | high | critical.

        Returns:
            Case object.
        """
        if case_id in self._registry:
            logger.warning("Case {} already exists — returning existing", case_id)
            return self.get_case(case_id)

        now = datetime.now(timezone.utc).isoformat()
        case = Case(
            case_id=case_id,
            title=title or case_id,
            examiner=examiner,
            description=description,
            created_at=now,
            updated_at=now,
            tags=tags or [],
            priority=priority,
        )

        # Create case directory
        case_dir = self.cases_dir / case_id
        case_dir.mkdir(parents=True, exist_ok=True)

        # Write case metadata
        case_meta_path = case_dir / "case.json"
        case_meta_path.write_text(
            json.dumps(case.to_dict(), indent=2, default=str),
            encoding="utf-8",
        )

        self._registry[case_id] = case.to_dict()
        self._save_registry()

        logger.info("Case created | case_id={} | examiner={}", case_id, examiner)
        return case

    def get_case(self, case_id: str) -> Case | None:
        """Retrieve a case by ID."""
        data = self._registry.get(case_id)
        if not data:
            # Try loading from disk
            case_meta = self.cases_dir / case_id / "case.json"
            if case_meta.exists():
                data = json.loads(case_meta.read_text(encoding="utf-8"))
                self._registry[case_id] = data
        if not data:
            return None
        data["status"] = CaseStatus(data.get("status", "open"))
        return Case(**{k: v for k, v in data.items() if k in Case.__dataclass_fields__})

    def update_case(
        self,
        case_id: str,
        status: CaseStatus | None = None,
        notes: str | None = None,
        tags: list[str] | None = None,
        priority: str | None = None,
    ) -> Case | None:
        """Update case fields."""
        case = self.get_case(case_id)
        if not case:
            logger.error("Case not found: {}", case_id)
            return None

        if status:
            case.status = status
            if status == CaseStatus.CLOSED:
                case.closed_at = datetime.now(timezone.utc).isoformat()
        if notes is not None:
            case.notes = notes
        if tags is not None:
            case.tags = tags
        if priority is not None:
            case.priority = priority

        case.updated_at = datetime.now(timezone.utc).isoformat()

        # Persist
        case_meta = self.cases_dir / case_id / "case.json"
        case_meta.write_text(
            json.dumps(case.to_dict(), indent=2, default=str),
            encoding="utf-8",
        )
        self._registry[case_id] = case.to_dict()
        self._save_registry()

        logger.info("Case updated | case_id={} | status={}", case_id, case.status)
        return case

    def add_evidence_to_case(self, case_id: str, evidence_id: str) -> None:
        """Link an evidence ID to a case."""
        case = self.get_case(case_id)
        if not case:
            logger.error("Case not found: {}", case_id)
            return
        if evidence_id not in case.evidence_ids:
            case.evidence_ids.append(evidence_id)
            self.update_case(case_id)
            self._registry[case_id]["evidence_ids"] = case.evidence_ids
            self._save_registry()
            logger.info("Evidence {} linked to case {}", evidence_id, case_id)

    def list_cases(self, status: CaseStatus | None = None) -> list[Case]:
        """List all cases, optionally filtered by status."""
        cases = []
        for case_id in self._registry:
            case = self.get_case(case_id)
            if case and (status is None or case.status == status):
                cases.append(case)
        return sorted(cases, key=lambda c: c.created_at, reverse=True)

    def search_cases(self, query: str) -> list[Case]:
        """
        Full-text search across case ID, title, description, examiner, and tags.
        Case-insensitive substring match.
        """
        q = query.lower()
        results = []
        for case in self.list_cases():
            searchable = " ".join(
                [
                    case.case_id,
                    case.title,
                    case.description,
                    case.examiner,
                    case.notes,
                    " ".join(case.tags),
                ]
            ).lower()
            if q in searchable:
                results.append(case)
        logger.info("Case search '{}': {} result(s)", query, len(results))
        return results

    def delete_case(self, case_id: str, confirm: bool = False) -> bool:
        """
        Remove a case from the registry (does NOT delete files).
        Requires confirm=True as a safety gate.
        """
        if not confirm:
            logger.warning("delete_case requires confirm=True")
            return False
        if case_id in self._registry:
            del self._registry[case_id]
            self._save_registry()
            logger.info("Case {} removed from registry", case_id)
            return True
        return False
