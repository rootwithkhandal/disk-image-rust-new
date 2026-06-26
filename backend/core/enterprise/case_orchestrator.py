"""
Multi-Case Orchestrator
========================
Manages multiple concurrent cases, coordinates examiner assignments,
tracks case priorities, and provides a unified case dashboard.

Usage:
    from core.enterprise.case_orchestrator import CaseOrchestrator

    orch = CaseOrchestrator()
    orch.assign_examiner("CASE-001", "alice")
    orch.escalate_case("CASE-001", reason="Ransomware confirmed")
    dashboard = orch.get_dashboard()
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from loguru import logger

from core.chain_of_custody.case_manager import CaseManager, CaseStatus
from core.config import settings


@dataclass
class CaseAssignment:
    case_id: str
    examiner: str
    role: str = "examiner"
    assigned_at: str = ""
    notes: str = ""


@dataclass
class CaseDashboard:
    total_cases: int = 0
    open_cases: int = 0
    active_cases: int = 0
    closed_cases: int = 0
    critical_cases: list[str] = field(default_factory=list)
    high_cases: list[str] = field(default_factory=list)
    unassigned_cases: list[str] = field(default_factory=list)
    recent_activity: list[dict] = field(default_factory=list)
    generated_at: str = ""


class CaseOrchestrator:
    """
    Enterprise multi-case orchestration layer.
    Sits on top of CaseManager to add assignment, escalation, and dashboarding.
    """

    ASSIGNMENTS_FILE = "case_assignments.json"

    def __init__(self, base_path: Path | None = None) -> None:
        self.base_path = Path(base_path or settings.evidence.base_path)
        self.base_path.mkdir(parents=True, exist_ok=True)
        self._case_mgr = CaseManager(base_path=self.base_path)
        self._assignments_path = self.base_path / self.ASSIGNMENTS_FILE
        self._assignments: dict[str, list[dict]] = self._load_assignments()

    def _load_assignments(self) -> dict[str, list[dict]]:
        if self._assignments_path.exists():
            try:
                return json.loads(self._assignments_path.read_text(encoding="utf-8"))
            except Exception:
                pass
        return {}

    def _save_assignments(self) -> None:
        self._assignments_path.write_text(
            json.dumps(self._assignments, indent=2, default=str),
            encoding="utf-8",
        )

    def assign_examiner(
        self,
        case_id: str,
        examiner: str,
        role: str = "examiner",
        notes: str = "",
    ) -> CaseAssignment:
        """Assign an examiner to a case."""
        assignment = CaseAssignment(
            case_id=case_id,
            examiner=examiner,
            role=role,
            assigned_at=datetime.now(timezone.utc).isoformat(),
            notes=notes,
        )
        if case_id not in self._assignments:
            self._assignments[case_id] = []
        self._assignments[case_id].append(asdict(assignment))
        self._save_assignments()
        logger.info("Examiner assigned | case={} | examiner={}", case_id, examiner)
        return assignment

    def get_assignments(self, case_id: str) -> list[CaseAssignment]:
        """Get all examiner assignments for a case."""
        return [CaseAssignment(**a) for a in self._assignments.get(case_id, [])]

    def escalate_case(self, case_id: str, reason: str = "") -> bool:
        """Escalate a case to critical priority."""
        case = self._case_mgr.update_case(case_id, priority="critical")
        if case:
            logger.warning("Case escalated to CRITICAL | case={} | reason={}", case_id, reason)
            return True
        return False

    def close_case(self, case_id: str, examiner: str, notes: str = "") -> bool:
        """Close a case with final notes."""
        case = self._case_mgr.update_case(case_id, status=CaseStatus.CLOSED, notes=notes)
        if case:
            logger.info("Case closed | case={} | examiner={}", case_id, examiner)
            return True
        return False

    def get_dashboard(self) -> CaseDashboard:
        """Generate a real-time case dashboard."""
        all_cases = self._case_mgr.list_cases()
        dashboard = CaseDashboard(
            total_cases=len(all_cases),
            generated_at=datetime.now(timezone.utc).isoformat(),
        )

        for case in all_cases:
            if case.status == CaseStatus.OPEN:
                dashboard.open_cases += 1
            elif case.status == CaseStatus.ACTIVE:
                dashboard.active_cases += 1
            elif case.status == CaseStatus.CLOSED:
                dashboard.closed_cases += 1

            if case.priority == "critical":
                dashboard.critical_cases.append(case.case_id)
            elif case.priority == "high":
                dashboard.high_cases.append(case.case_id)

            if not self._assignments.get(case.case_id):
                dashboard.unassigned_cases.append(case.case_id)

        return dashboard

    def get_workload(self, examiner: str) -> list[str]:
        """Return all case IDs assigned to an examiner."""
        assigned: list[str] = []
        for case_id, assignments in self._assignments.items():
            if any(a.get("examiner") == examiner for a in assignments):
                assigned.append(case_id)
        return assigned
