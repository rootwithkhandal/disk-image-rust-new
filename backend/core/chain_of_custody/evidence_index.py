"""
Evidence Index & Search
========================
Builds and maintains a searchable index of all evidence items
across all cases. Supports tagging, full-text search, and filtering.

Usage:
    from core.chain_of_custody.evidence_index import EvidenceIndex

    idx = EvidenceIndex()
    idx.index_evidence("CASE-001", "EV-ABC123", tags=["ransomware", "windows"])
    results = idx.search("ransomware")
    tagged = idx.get_by_tag("windows")
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from loguru import logger

from core.config import settings


@dataclass
class EvidenceIndexEntry:
    evidence_id: str
    case_id: str
    device_id: str = ""
    device_model: str = ""
    examiner: str = ""
    acquisition_method: str = ""
    timestamp_utc: str = ""
    hash_sha256: str = ""
    size_bytes: int = 0
    verified: bool = False
    tags: list[str] = field(default_factory=list)
    notes: str = ""
    output_path: str = ""
    indexed_at: str = ""

    @property
    def size_gb(self) -> float:
        return round(self.size_bytes / (1024**3), 2)

    def matches(self, query: str) -> bool:
        """Case-insensitive substring match across all text fields."""
        q = query.lower()
        searchable = " ".join(
            [
                self.evidence_id,
                self.case_id,
                self.device_id,
                self.device_model,
                self.examiner,
                self.acquisition_method,
                self.hash_sha256,
                self.notes,
                " ".join(self.tags),
            ]
        ).lower()
        return q in searchable


class EvidenceIndex:
    """
    Flat JSON index of all evidence items for fast search and filtering.
    Stored at evidence/evidence_index.json
    """

    INDEX_FILE = "evidence_index.json"

    def __init__(self, base_path: Path | None = None) -> None:
        self.base_path = Path(base_path or settings.evidence.base_path)
        self.base_path.mkdir(parents=True, exist_ok=True)
        self._index_path = self.base_path / self.INDEX_FILE
        self._index: dict[str, dict] = self._load()

    def _load(self) -> dict[str, dict]:
        if self._index_path.exists():
            try:
                return json.loads(self._index_path.read_text(encoding="utf-8"))
            except Exception as exc:
                logger.error("Failed to load evidence index: {}", exc)
        return {}

    def _save(self) -> None:
        self._index_path.write_text(
            json.dumps(self._index, indent=2, default=str),
            encoding="utf-8",
        )

    # ΓöÇΓöÇ Indexing ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ

    def index_evidence(
        self,
        case_id: str,
        evidence_id: str,
        tags: list[str] | None = None,
        notes: str = "",
        metadata: dict | None = None,
    ) -> EvidenceIndexEntry:
        """
        Add or update an evidence item in the index.
        Reads metadata.json from the evidence directory if not provided.
        """
        if metadata is None:
            meta_path = self.base_path / "cases" / case_id / evidence_id / "metadata.json"
            if meta_path.exists():
                metadata = json.loads(meta_path.read_text(encoding="utf-8"))
            else:
                metadata = {}

        dev = metadata.get("device") or {}
        if isinstance(dev, dict):
            device_id = dev.get("device_id", "")
            device_model = dev.get("model", "")
        else:
            device_id = getattr(dev, "device_id", "")
            device_model = getattr(dev, "model", "")

        entry = EvidenceIndexEntry(
            evidence_id=evidence_id,
            case_id=case_id,
            device_id=device_id,
            device_model=device_model,
            examiner=metadata.get("examiner", ""),
            acquisition_method=metadata.get("acquisition_method", ""),
            timestamp_utc=metadata.get("timestamp_utc", ""),
            hash_sha256=metadata.get("hash_sha256", ""),
            size_bytes=int(metadata.get("bytes_acquired", 0) or 0),
            verified=bool(metadata.get("verified", False)),
            tags=tags or [],
            notes=notes,
            output_path=metadata.get("output_path", ""),
            indexed_at=datetime.now(timezone.utc).isoformat(),
        )

        self._index[evidence_id] = asdict(entry)
        self._save()
        logger.info("Evidence indexed | evidence_id={} | tags={}", evidence_id, tags)
        return entry

    def update_tags(self, evidence_id: str, tags: list[str]) -> bool:
        """Update tags for an indexed evidence item."""
        if evidence_id not in self._index:
            logger.warning("Evidence {} not in index", evidence_id)
            return False
        self._index[evidence_id]["tags"] = tags
        self._save()
        logger.info("Tags updated | evidence_id={} | tags={}", evidence_id, tags)
        return True

    def remove(self, evidence_id: str) -> bool:
        """Remove an evidence item from the index."""
        if evidence_id in self._index:
            del self._index[evidence_id]
            self._save()
            return True
        return False

    # ΓöÇΓöÇ Search & filter ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ

    def search(self, query: str) -> list[EvidenceIndexEntry]:
        """Full-text search across all indexed evidence."""
        results = []
        for data in self._index.values():
            entry = EvidenceIndexEntry(
                **{k: v for k, v in data.items() if k in EvidenceIndexEntry.__dataclass_fields__}
            )
            if entry.matches(query):
                results.append(entry)
        logger.info("Evidence search '{}': {} result(s)", query, len(results))
        return results

    def get_by_tag(self, tag: str) -> list[EvidenceIndexEntry]:
        """Return all evidence items with a specific tag."""
        tag_lower = tag.lower()
        results = []
        for data in self._index.values():
            tags = [t.lower() for t in data.get("tags", [])]
            if tag_lower in tags:
                entry = EvidenceIndexEntry(
                    **{
                        k: v
                        for k, v in data.items()
                        if k in EvidenceIndexEntry.__dataclass_fields__
                    }
                )
                results.append(entry)
        return results

    def get_by_case(self, case_id: str) -> list[EvidenceIndexEntry]:
        """Return all evidence items for a specific case."""
        results = []
        for data in self._index.values():
            if data.get("case_id") == case_id:
                entry = EvidenceIndexEntry(
                    **{
                        k: v
                        for k, v in data.items()
                        if k in EvidenceIndexEntry.__dataclass_fields__
                    }
                )
                results.append(entry)
        return sorted(results, key=lambda e: e.timestamp_utc, reverse=True)

    def get_unverified(self) -> list[EvidenceIndexEntry]:
        """Return all evidence items that have not been verified."""
        return [
            EvidenceIndexEntry(
                **{k: v for k, v in data.items() if k in EvidenceIndexEntry.__dataclass_fields__}
            )
            for data in self._index.values()
            if not data.get("verified", False)
        ]

    def get_entry(self, evidence_id: str) -> EvidenceIndexEntry | None:
        """Get a single index entry by evidence ID."""
        data = self._index.get(evidence_id)
        if not data:
            return None
        return EvidenceIndexEntry(
            **{k: v for k, v in data.items() if k in EvidenceIndexEntry.__dataclass_fields__}
        )

    def all_entries(self) -> list[EvidenceIndexEntry]:
        """Return all indexed evidence entries."""
        return [
            EvidenceIndexEntry(
                **{k: v for k, v in data.items() if k in EvidenceIndexEntry.__dataclass_fields__}
            )
            for data in self._index.values()
        ]

    def all_tags(self) -> list[str]:
        """Return a sorted list of all unique tags in the index."""
        tags: set[str] = set()
        for data in self._index.values():
            tags.update(data.get("tags", []))
        return sorted(tags)

    def rebuild(self) -> int:
        """
        Rebuild the index by scanning all evidence directories.
        Returns the number of items indexed.
        """
        self._index = {}
        cases_dir = self.base_path / "cases"
        if not cases_dir.exists():
            return 0

        count = 0
        for case_dir in cases_dir.iterdir():
            if not case_dir.is_dir():
                continue
            for ev_dir in case_dir.iterdir():
                if not ev_dir.is_dir():
                    continue
                meta_path = ev_dir / "metadata.json"
                if meta_path.exists():
                    self.index_evidence(case_dir.name, ev_dir.name)
                    count += 1

        logger.info("Index rebuilt | {} evidence item(s) indexed", count)
        return count
