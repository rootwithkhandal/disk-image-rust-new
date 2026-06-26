"""
Immutable Evidence Ledger (V3.0)
==================================
Cryptographically tamper-evident, append-only ledger for evidence events.

Uses a hash-chain (like a blockchain without PoW) where each entry contains
the SHA256 of the previous entry, making retroactive tampering detectable.

Every evidence event (create, access, transfer, verify, modify) is recorded
as a signed ledger entry. The chain can be audited offline.

Usage:
    from core.v3.ledger import EvidenceLedger

    ledger = EvidenceLedger(case_id="CASE-001")
    ledger.append("EV-ABC", "created", actor="alice", notes="Physical acquisition")
    ledger.append("EV-ABC", "accessed", actor="bob",  notes="Memory analysis")

    ok, report = ledger.verify_chain()
    print(report)
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from loguru import logger

from core.config import settings


@dataclass
class LedgerEntry:
    seq: int                  # Monotonic sequence number
    case_id: str
    evidence_id: str
    event_type: str           # created|accessed|transferred|verified|modified|exported|deleted
    actor: str                # Username or system
    timestamp: str            # ISO 8601 UTC
    notes: str = ""
    metadata: dict = field(default_factory=dict)
    prev_hash: str = ""       # SHA256 of previous entry's content hash
    entry_hash: str = ""      # SHA256(seq+case+evidence+event+actor+ts+notes+prev_hash)
    hmac_sig: str = ""        # HMAC-SHA256 of entry_hash (optional, requires key)

    def compute_hash(self) -> str:
        """Compute the canonical hash of this entry (excluding entry_hash and hmac_sig)."""
        canonical = json.dumps({
            "seq":         self.seq,
            "case_id":     self.case_id,
            "evidence_id": self.evidence_id,
            "event_type":  self.event_type,
            "actor":       self.actor,
            "timestamp":   self.timestamp,
            "notes":       self.notes,
            "metadata":    self.metadata,
            "prev_hash":   self.prev_hash,
        }, sort_keys=True, default=str)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def sign(self, key: bytes) -> str:
        """Compute HMAC-SHA256 signature of this entry's hash."""
        return hmac.new(key, self.entry_hash.encode("utf-8"), hashlib.sha256).hexdigest()


@dataclass
class LedgerAuditReport:
    case_id: str
    total_entries: int
    chain_valid: bool
    tampered_entries: list[int] = field(default_factory=list)
    first_entry_time: str = ""
    last_entry_time: str = ""
    actors: list[str] = field(default_factory=list)
    event_counts: dict = field(default_factory=dict)
    integrity_note: str = ""
    generated_at: str = ""


class EvidenceLedger:
    """
    Append-only, hash-chained evidence event ledger.
    One ledger file per case, stored at evidence/cases/<case_id>/ledger.jsonl
    Each line is a JSON-encoded LedgerEntry.
    """

    LEDGER_FILENAME = "ledger.jsonl"
    GENESIS_HASH = "0" * 64  # First entry's prev_hash

    def __init__(
        self,
        case_id: str,
        base_path: Path | None = None,
        signing_key: bytes | None = None,
    ) -> None:
        self.case_id = case_id
        self._base = Path(base_path or settings.evidence.base_path)
        self._signing_key = signing_key
        self._ledger_path = self._base / "cases" / case_id / self.LEDGER_FILENAME
        self._ledger_path.parent.mkdir(parents=True, exist_ok=True)

    # ── Append ────────────────────────────────────────────────────────────────

    def append(
        self,
        evidence_id: str,
        event_type: str,
        actor: str,
        notes: str = "",
        metadata: dict | None = None,
    ) -> LedgerEntry:
        """
        Append an immutable event to the ledger.

        Args:
            evidence_id: Evidence item this event relates to.
            event_type:  created|accessed|transferred|verified|modified|exported|deleted
            actor:       Username or system identifier.
            notes:       Free-text description.
            metadata:    Additional structured data (e.g. hash values, file sizes).

        Returns:
            The committed LedgerEntry.
        """
        # Get current chain tip
        entries = self._read_all()
        prev_hash = entries[-1].entry_hash if entries else self.GENESIS_HASH
        seq = len(entries) + 1

        entry = LedgerEntry(
            seq=seq,
            case_id=self.case_id,
            evidence_id=evidence_id,
            event_type=event_type,
            actor=actor,
            timestamp=datetime.now(timezone.utc).isoformat(),
            notes=notes,
            metadata=metadata or {},
            prev_hash=prev_hash,
        )
        entry.entry_hash = entry.compute_hash()

        if self._signing_key:
            entry.hmac_sig = entry.sign(self._signing_key)

        # Append atomically
        line = json.dumps(asdict(entry), default=str) + "\n"
        with open(self._ledger_path, "a", encoding="utf-8") as f:
            f.write(line)

        logger.debug(
            "Ledger entry | case={} | evidence={} | event={} | seq={}",
            self.case_id, evidence_id, event_type, seq,
        )
        return entry

    # ── Read ──────────────────────────────────────────────────────────────────

    def _read_all(self) -> list[LedgerEntry]:
        """Read all entries from the ledger file."""
        if not self._ledger_path.exists():
            return []
        entries: list[LedgerEntry] = []
        with open(self._ledger_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    entry = LedgerEntry(**{
                        k: v for k, v in data.items()
                        if k in LedgerEntry.__dataclass_fields__
                    })
                    entries.append(entry)
                except Exception as exc:
                    logger.warning("Corrupt ledger entry: {}", exc)
        return entries

    def get_entries(
        self,
        evidence_id: str | None = None,
        event_type: str | None = None,
        actor: str | None = None,
    ) -> list[LedgerEntry]:
        """Filter ledger entries."""
        entries = self._read_all()
        if evidence_id:
            entries = [e for e in entries if e.evidence_id == evidence_id]
        if event_type:
            entries = [e for e in entries if e.event_type == event_type]
        if actor:
            entries = [e for e in entries if e.actor == actor]
        return entries

    # ── Verification ──────────────────────────────────────────────────────────

    def verify_chain(self) -> tuple[bool, LedgerAuditReport]:
        """
        Verify the integrity of the entire hash chain.

        For each entry:
          1. Recompute its hash and compare against stored entry_hash
          2. Verify its prev_hash matches the previous entry's entry_hash
          3. If signing key provided, verify HMAC signatures

        Returns:
            (chain_valid, LedgerAuditReport)
        """
        entries = self._read_all()
        tampered: list[int] = []
        actors: set[str] = set()
        event_counts: dict[str, int] = {}

        if not entries:
            report = LedgerAuditReport(
                case_id=self.case_id,
                total_entries=0,
                chain_valid=True,
                integrity_note="Empty ledger — no entries to verify.",
                generated_at=datetime.now(timezone.utc).isoformat(),
            )
            return True, report

        prev_hash = self.GENESIS_HASH

        for entry in entries:
            actors.add(entry.actor)
            event_counts[entry.event_type] = event_counts.get(entry.event_type, 0) + 1

            # 1. Verify entry hash
            expected_hash = entry.compute_hash()
            if entry.entry_hash != expected_hash:
                tampered.append(entry.seq)
                logger.error(
                    "Ledger tampered! Entry seq={} hash mismatch | stored={} expected={}",
                    entry.seq, entry.entry_hash[:16], expected_hash[:16],
                )
                continue

            # 2. Verify chain linkage
            if entry.prev_hash != prev_hash:
                tampered.append(entry.seq)
                logger.error(
                    "Ledger chain break at seq={} | stored_prev={} expected_prev={}",
                    entry.seq, entry.prev_hash[:16], prev_hash[:16],
                )

            # 3. HMAC verification (if key provided)
            if self._signing_key and entry.hmac_sig:
                expected_sig = entry.sign(self._signing_key)
                if not hmac.compare_digest(entry.hmac_sig, expected_sig):
                    if entry.seq not in tampered:
                        tampered.append(entry.seq)
                    logger.error("HMAC verification failed at seq={}", entry.seq)

            prev_hash = entry.entry_hash

        chain_valid = len(tampered) == 0
        note = (
            "Chain integrity VERIFIED — all entries are authentic and unmodified."
            if chain_valid else
            f"TAMPERING DETECTED at {len(tampered)} entry/entries: seq={tampered}"
        )

        report = LedgerAuditReport(
            case_id=self.case_id,
            total_entries=len(entries),
            chain_valid=chain_valid,
            tampered_entries=tampered,
            first_entry_time=entries[0].timestamp if entries else "",
            last_entry_time=entries[-1].timestamp if entries else "",
            actors=sorted(actors),
            event_counts=event_counts,
            integrity_note=note,
            generated_at=datetime.now(timezone.utc).isoformat(),
        )
        logger.info("Ledger audit | case={} | entries={} | valid={}", self.case_id, len(entries), chain_valid)
        return chain_valid, report

    def export_json(self, output_path: Path) -> Path:
        """Export the full ledger as a pretty-printed JSON file."""
        entries = self._read_all()
        data = {
            "case_id": self.case_id,
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "total_entries": len(entries),
            "entries": [asdict(e) for e in entries],
        }
        output_path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
        return output_path

    @classmethod
    def migrate_from_coc(
        cls,
        case_id: str,
        base_path: Path | None = None,
    ) -> "EvidenceLedger":
        """
        Migrate existing chain_of_custody.json events into the ledger.
        Non-destructive — original CoC files are untouched.
        """
        base = Path(base_path or settings.evidence.base_path)
        ledger = cls(case_id, base_path=base)
        case_dir = base / "cases" / case_id

        if not case_dir.exists():
            return ledger

        migrated = 0
        for ev_dir in case_dir.iterdir():
            if not ev_dir.is_dir():
                continue
            coc_path = ev_dir / "chain_of_custody.json"
            if not coc_path.exists():
                continue
            try:
                coc = json.loads(coc_path.read_text(encoding="utf-8"))
                for event in coc.get("events", []):
                    ledger.append(
                        evidence_id=ev_dir.name,
                        event_type=event.get("event_type", "legacy"),
                        actor=event.get("actor", "migrated"),
                        notes=event.get("notes", ""),
                        metadata={"migrated_from": "chain_of_custody.json", "seq": event.get("seq")},
                    )
                    migrated += 1
            except Exception as exc:
                logger.debug("Migration error for {}: {}", ev_dir.name, exc)

        logger.info("Ledger migration: {} events migrated for case {}", migrated, case_id)
        return ledger
