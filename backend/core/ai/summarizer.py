"""
Evidence Summarizer
====================
Automated evidence summarization using rule-based NLP and
optional LLM integration (OpenAI / local Ollama).

Produces human-readable summaries of:
- Acquisition metadata
- Artifact collections
- Chain of custody events
- Memory analysis results

Usage:
    from core.ai.summarizer import EvidenceSummarizer

    summarizer = EvidenceSummarizer()
    summary = summarizer.summarize_acquisition(metadata_dict)
    print(summary.narrative)
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone

from loguru import logger


@dataclass
class Summary:
    title: str
    narrative: str
    key_findings: list[str] = field(default_factory=list)
    risk_level: str = "unknown"  # low | medium | high | critical
    confidence: float = 0.0  # 0.0 - 1.0
    generated_at: str = ""
    source_type: str = ""

    def __str__(self) -> str:
        findings = "\n".join(f"  • {f}" for f in self.key_findings)
        return (
            f"[{self.risk_level.upper()}] {self.title}\n{self.narrative}\nKey Findings:\n{findings}"
        )


class EvidenceSummarizer:
    """
    Rule-based evidence summarizer with optional LLM augmentation.
    Works fully offline — LLM is optional enhancement.
    """

    def __init__(self, use_llm: bool = False, llm_endpoint: str = "") -> None:
        self.use_llm = use_llm
        self.llm_endpoint = llm_endpoint
        self._llm_available = self._check_llm() if use_llm else False

    def _check_llm(self) -> bool:
        """Check if an LLM endpoint is reachable."""
        if not self.llm_endpoint:
            return False
        try:
            import urllib.request

            urllib.request.urlopen(self.llm_endpoint, timeout=2)
            return True
        except Exception:
            return False

    # ── Acquisition summary ───────────────────────────────────────────────────

    def summarize_acquisition(self, metadata: dict) -> Summary:
        """
        Generate a human-readable summary of an acquisition.

        Args:
            metadata: AcquisitionMetadata dict (from metadata.json)

        Returns:
            Summary with narrative and key findings.
        """
        evidence_id = metadata.get("evidence_id", "Unknown")
        case_id = metadata.get("case_id", "Unknown")
        examiner = metadata.get("examiner", "Unknown")
        method = metadata.get("acquisition_method", "unknown")
        verified = metadata.get("verified", False)
        sha256 = metadata.get("hash_sha256", "")
        bytes_acq = int(metadata.get("bytes_acquired", 0) or 0)
        duration = float(metadata.get("duration_seconds", 0) or 0)
        timestamp = metadata.get("timestamp_utc", "")

        dev = metadata.get("device") or {}
        device_id = (
            dev.get("device_id", "") if isinstance(dev, dict) else getattr(dev, "device_id", "")
        )
        device_model = dev.get("model", "") if isinstance(dev, dict) else getattr(dev, "model", "")

        size_gb = round(bytes_acq / (1024**3), 3)
        findings: list[str] = []
        risk = "low"

        # Build narrative
        ts_str = timestamp[:10] if timestamp else "unknown date"
        narrative = (
            f"On {ts_str}, examiner {examiner} performed a {method} acquisition "
            f"of {device_model or device_id or 'unknown device'} "
            f"({size_gb} GB) for case {case_id}. "
        )

        if verified:
            narrative += "The acquisition was successfully verified with SHA256 integrity check. "
            findings.append(f"✔ Integrity verified — SHA256: {sha256[:16]}...")
        else:
            narrative += "WARNING: The acquisition has NOT been verified. "
            findings.append("⚠ Integrity NOT verified — manual verification required")
            risk = "medium"

        if duration > 0:
            throughput = round((bytes_acq / (1024**2)) / duration, 1) if duration > 0 else 0
            findings.append(f"Acquisition speed: {throughput} MB/s over {duration}s")

        findings.append(f"Evidence ID: {evidence_id}")
        findings.append(f"Case: {case_id} | Examiner: {examiner}")

        return Summary(
            title=f"Acquisition Summary — {evidence_id}",
            narrative=narrative.strip(),
            key_findings=findings,
            risk_level=risk,
            confidence=0.95,
            generated_at=datetime.now(timezone.utc).isoformat(),
            source_type="acquisition",
        )

    # ── Artifact summary ──────────────────────────────────────────────────────

    def summarize_artifacts(self, artifact_data: dict, platform: str = "windows") -> Summary:
        """
        Summarize collected artifacts and highlight suspicious findings.
        """
        findings: list[str] = []
        risk = "low"
        suspicious_count = 0

        # Registry run keys
        run_keys = artifact_data.get("run_keys", [])
        sus_run = [e for e in run_keys if e.get("is_suspicious") or e.get("_suspicious")]
        if sus_run:
            suspicious_count += len(sus_run)
            findings.append(f"⚠ {len(sus_run)} suspicious run key(s) detected")
            risk = "high"
        elif run_keys:
            findings.append(f"{len(run_keys)} run key(s) — no suspicious entries")

        # Browser history
        browser = artifact_data.get("browser_history", {})
        total_urls = sum(len(v) for v in browser.values()) if isinstance(browser, dict) else 0
        if total_urls > 0:
            findings.append(f"{total_urls} browser history URL(s) collected")

        # Prefetch
        prefetch = artifact_data.get("prefetch", [])
        if prefetch:
            findings.append(f"{len(prefetch)} prefetch file(s) — execution history available")

        # Processes (from live response)
        processes = artifact_data.get("processes", [])
        sus_procs = [p for p in processes if p.get("_suspicious") or p.get("is_suspicious")]
        if sus_procs:
            suspicious_count += len(sus_procs)
            findings.append(f"⚠ {len(sus_procs)} suspicious process(es) running")
            risk = "critical" if len(sus_procs) > 2 else "high"

        # Network connections
        connections = artifact_data.get("network_connections", [])
        if connections:
            findings.append(f"{len(connections)} active network connection(s)")

        narrative = (
            f"Artifact collection from {platform} system yielded "
            f"{len(findings)} artifact categories. "
        )
        if suspicious_count > 0:
            narrative += (
                f"ALERT: {suspicious_count} suspicious indicator(s) detected "
                f"requiring immediate analyst review. "
            )
        else:
            narrative += "No immediately suspicious artifacts identified. "

        return Summary(
            title=f"Artifact Summary — {platform.upper()}",
            narrative=narrative.strip(),
            key_findings=findings,
            risk_level=risk,
            confidence=0.85,
            generated_at=datetime.now(timezone.utc).isoformat(),
            source_type="artifacts",
        )

    # ── Case summary ──────────────────────────────────────────────────────────

    def summarize_case(self, case_data: dict, evidence_list: list[dict]) -> Summary:
        """
        Generate a high-level case summary from case metadata and evidence.
        """
        case_id = case_data.get("case_id", "Unknown")
        examiner = case_data.get("examiner", "Unknown")
        status = case_data.get("status", "unknown")
        tags = case_data.get("tags", [])
        ev_count = len(evidence_list)
        verified_count = sum(1 for e in evidence_list if e.get("verified"))

        findings = [
            f"Case status: {status.upper()}",
            f"Examiner: {examiner}",
            f"{ev_count} evidence item(s) | {verified_count} verified",
        ]
        if tags:
            findings.append(f"Tags: {', '.join(tags)}")

        total_bytes = sum(int(e.get("bytes_acquired", 0) or 0) for e in evidence_list)
        if total_bytes > 0:
            findings.append(f"Total data acquired: {round(total_bytes / (1024**3), 2)} GB")

        unverified = ev_count - verified_count
        risk = "low"
        if unverified > 0:
            findings.append(f"⚠ {unverified} evidence item(s) not verified")
            risk = "medium"

        narrative = (
            f"Case {case_id} managed by {examiner} contains {ev_count} evidence item(s). "
            f"{'All evidence has been integrity-verified.' if unverified == 0 else f'{unverified} item(s) require verification.'} "
            f"Case is currently {status}."
        )

        return Summary(
            title=f"Case Summary — {case_id}",
            narrative=narrative.strip(),
            key_findings=findings,
            risk_level=risk,
            confidence=0.90,
            generated_at=datetime.now(timezone.utc).isoformat(),
            source_type="case",
        )

    # ── LLM augmentation ──────────────────────────────────────────────────────

    def augment_with_llm(self, summary: Summary, context: str = "") -> Summary:
        """
        Optionally augment a rule-based summary with LLM narrative.
        Falls back to rule-based summary if LLM is unavailable.
        """
        if not self._llm_available:
            logger.debug("LLM not available — using rule-based summary")
            return summary

        try:
            import urllib.request

            prompt = (
                f"You are a DFIR analyst. Summarize this forensic finding concisely:\n\n"
                f"Title: {summary.title}\n"
                f"Findings: {chr(10).join(summary.key_findings)}\n"
                f"Context: {context}\n\n"
                f"Provide a 2-3 sentence analyst narrative."
            )
            payload = json.dumps({"prompt": prompt, "stream": False}).encode()
            req = urllib.request.Request(
                f"{self.llm_endpoint}/api/generate",
                data=payload,
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read())
                llm_narrative = data.get("response", "").strip()
                if llm_narrative:
                    summary.narrative = llm_narrative
                    summary.confidence = min(summary.confidence + 0.05, 1.0)
        except Exception as exc:
            logger.debug("LLM augmentation failed: {}", exc)

        return summary
