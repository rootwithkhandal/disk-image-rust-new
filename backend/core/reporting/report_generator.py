"""
Report Generator
================
Generates acquisition reports in JSON, HTML, and plain-text formats
from AcquisitionMetadata. PDF support is added when reportlab is installed.

Usage:
    from core.reporting.report_generator import ReportGenerator, ReportFormat

    gen = ReportGenerator(output_dir="/path/to/evidence/EV-001")
    gen.generate(meta, formats=[ReportFormat.JSON, ReportFormat.HTML])
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path

from loguru import logger

from core.acquisition.metadata_collector import AcquisitionMetadata

# PDF is optional
try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False


class ReportFormat(str, Enum):
    JSON = "json"
    HTML = "html"
    TEXT = "text"
    PDF = "pdf"


class ReportGenerator:
    """
    Generates forensic acquisition reports from AcquisitionMetadata.
    """

    def __init__(self, output_dir: str | Path) -> None:
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate(
        self,
        meta: AcquisitionMetadata,
        formats: list[ReportFormat] | None = None,
    ) -> dict[ReportFormat, Path]:
        """
        Generate reports in the requested formats.

        Args:
            meta:    Acquisition metadata to report on.
            formats: List of formats. Defaults to [JSON, HTML, TEXT].

        Returns:
            Dict mapping each format to the output file path.
        """
        if formats is None:
            formats = [ReportFormat.JSON, ReportFormat.HTML, ReportFormat.TEXT]

        outputs: dict[ReportFormat, Path] = {}

        for fmt in formats:
            try:
                if fmt == ReportFormat.JSON:
                    outputs[fmt] = self._write_json(meta)
                elif fmt == ReportFormat.HTML:
                    outputs[fmt] = self._write_html(meta)
                elif fmt == ReportFormat.TEXT:
                    outputs[fmt] = self._write_text(meta)
                elif fmt == ReportFormat.PDF:
                    outputs[fmt] = self._write_pdf(meta)
            except Exception as exc:
                logger.error("Failed to generate {} report: {}", fmt.value, exc)

        logger.info(
            "Reports generated for {} | formats={}",
            meta.evidence_id,
            [f.value for f in outputs],
        )
        return outputs

    # ── JSON ──────────────────────────────────────────────────────────────────

    def _write_json(self, meta: AcquisitionMetadata) -> Path:
        path = self.output_dir / f"report_{meta.evidence_id}.json"
        path.write_text(
            json.dumps(meta.to_dict(), indent=2, default=str),
            encoding="utf-8",
        )
        logger.debug("JSON report written: {}", path)
        return path

    # ── Plain text ────────────────────────────────────────────────────────────

    def _write_text(self, meta: AcquisitionMetadata) -> Path:
        path = self.output_dir / f"report_{meta.evidence_id}.txt"
        path.write_text(_render_text(meta), encoding="utf-8")
        logger.debug("Text report written: {}", path)
        return path

    # ── HTML ──────────────────────────────────────────────────────────────────

    def _write_html(self, meta: AcquisitionMetadata) -> Path:
        path = self.output_dir / f"report_{meta.evidence_id}.html"
        path.write_text(_render_html(meta), encoding="utf-8")
        logger.debug("HTML report written: {}", path)
        return path

    # ── PDF ───────────────────────────────────────────────────────────────────

    def _write_pdf(self, meta: AcquisitionMetadata) -> Path:
        if not PDF_AVAILABLE:
            raise RuntimeError("reportlab is not installed. Run: pip install reportlab")

        path = self.output_dir / f"report_{meta.evidence_id}.pdf"
        doc = SimpleDocTemplate(str(path), pagesize=A4)
        styles = getSampleStyleSheet()
        story = []

        # Title
        story.append(Paragraph("ForgeLens — Acquisition Report", styles["Title"]))
        story.append(Spacer(1, 12))

        # Summary table
        data = [
            ["Field", "Value"],
            ["Evidence ID", meta.evidence_id],
            ["Case ID", meta.case_id],
            ["Examiner", meta.examiner],
            ["Timestamp (UTC)", meta.timestamp_utc],
            ["Method", meta.acquisition_method],
            ["Device", meta.device.device_id if meta.device else ""],
            ["SHA256", meta.hash_sha256 or "—"],
            ["MD5", meta.hash_md5 or "—"],
            ["Verified", "YES" if meta.verified else "NO"],
            ["Duration", f"{meta.duration_seconds}s"],
            ["Bytes Acquired", str(meta.bytes_acquired)],
            ["Notes", meta.notes or "—"],
        ]

        table = Table(data, colWidths=[150, 350])
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1a1a2e")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    (
                        "ROWBACKGROUNDS",
                        (0, 1),
                        (-1, -1),
                        [colors.white, colors.HexColor("#f0f0f0")],
                    ),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                    ("FONTSIZE", (0, 0), (-1, -1), 9),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]
            )
        )
        story.append(table)

        doc.build(story)
        logger.debug("PDF report written: {}", path)
        return path


# ── Renderers ─────────────────────────────────────────────────────────────────


def _get(obj, key: str, default: str = "") -> str:
    """Get a value from either a dataclass/object or a plain dict."""
    if obj is None:
        return default
    if isinstance(obj, dict):
        return str(obj.get(key) or default)
    return str(getattr(obj, key, default) or default)


def _render_text(meta: AcquisitionMetadata) -> str:
    dev = meta.device
    sys = meta.system
    sep = "=" * 60

    lines = [
        sep,
        "  FORGELENS — ACQUISITION REPORT",
        sep,
        f"  Evidence ID   : {meta.evidence_id}",
        f"  Case ID       : {meta.case_id}",
        f"  Examiner      : {meta.examiner}",
        f"  Timestamp UTC : {meta.timestamp_utc}",
        f"  Method        : {meta.acquisition_method}",
        f"  Tool          : {meta.tool_version}",
        f"  Notes         : {meta.notes or '—'}",
        f"  Location      : {meta.geo_location or '—'}",
        "",
        "  DEVICE",
        "-" * 40,
        f"  Device ID     : {_get(dev, 'device_id') or '—'}",
        f"  Model         : {_get(dev, 'model') or '—'}",
        f"  Serial        : {_get(dev, 'serial') or '—'}",
        f"  Interface     : {_get(dev, 'interface') or '—'}",
        f"  Size          : {_get(dev, 'size_gb') or '—'} GB",
        f"  Encrypted     : {'YES — ' + _get(dev, 'encryption_type') if _get(dev, 'is_encrypted') == 'True' else 'NO'}",
        "",
        "  INTEGRITY",
        "-" * 40,
        f"  SHA256        : {meta.hash_sha256 or '—'}",
        f"  MD5           : {meta.hash_md5 or '—'}",
        f"  SHA1          : {meta.hash_sha1 or '—'}",
        f"  BLAKE3        : {meta.hash_blake3 or '—'}",
        f"  Verified      : {'PASS' if meta.verified else 'NOT VERIFIED'}",
        "",
        "  ACQUISITION",
        "-" * 40,
        f"  Start         : {meta.acquisition_start}",
        f"  End           : {meta.acquisition_end}",
        f"  Duration      : {meta.duration_seconds}s",
        f"  Bytes         : {meta.bytes_acquired:,}",
        f"  Output        : {meta.output_path or '—'}",
        "",
        "  EXAMINER SYSTEM",
        "-" * 40,
        f"  Hostname      : {_get(sys, 'hostname') or '—'}",
        f"  OS            : {(_get(sys, 'os_name') + ' ' + _get(sys, 'os_version')).strip() or '—'}",
        f"  Python        : {_get(sys, 'python_version') or '—'}",
        sep,
        f"  Generated by ForgeLens at {datetime.now(timezone.utc).isoformat()}",
        sep,
    ]
    return "\n".join(lines)


def _render_html(meta: AcquisitionMetadata) -> str:
    dev = meta.device
    sys_meta = meta.system

    def row(label: str, value: str) -> str:
        return f"<tr><td><strong>{label}</strong></td><td>{value or '—'}</td></tr>"

    verified_badge = (
        '<span style="color:green;font-weight:bold">✔ VERIFIED</span>'
        if meta.verified
        else '<span style="color:orange;font-weight:bold">⚠ NOT VERIFIED</span>'
    )

    is_enc = _get(dev, "is_encrypted") == "True"
    enc_type = _get(dev, "encryption_type")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>ForgeLens Report — {meta.evidence_id}</title>
  <style>
    body {{ font-family: 'Courier New', monospace; background: #0d0d1a; color: #e0e0e0; padding: 2rem; }}
    h1 {{ color: #00d4ff; border-bottom: 1px solid #333; padding-bottom: 0.5rem; }}
    h2 {{ color: #7ecfff; margin-top: 2rem; }}
    table {{ border-collapse: collapse; width: 100%; max-width: 800px; }}
    td {{ padding: 6px 12px; border: 1px solid #333; }}
    tr:nth-child(even) {{ background: #1a1a2e; }}
    .hash {{ font-size: 0.8rem; word-break: break-all; color: #aaffaa; }}
    .footer {{ margin-top: 2rem; font-size: 0.75rem; color: #666; }}
  </style>
</head>
<body>
  <h1>🔍 ForgeLens — Acquisition Report</h1>

  <h2>Case Summary</h2>
  <table>
    {row("Evidence ID", meta.evidence_id)}
    {row("Case ID", meta.case_id)}
    {row("Examiner", meta.examiner)}
    {row("Timestamp (UTC)", meta.timestamp_utc)}
    {row("Method", meta.acquisition_method)}
    {row("Tool", meta.tool_version)}
    {row("Location", meta.geo_location)}
    {row("Notes", meta.notes)}
  </table>

  <h2>Device</h2>
  <table>
    {row("Device ID", _get(dev, "device_id"))}
    {row("Model", _get(dev, "model"))}
    {row("Serial", _get(dev, "serial"))}
    {row("Interface", _get(dev, "interface"))}
    {row("Size", _get(dev, "size_gb") + " GB")}
    {row("Encrypted", ("YES — " + enc_type) if is_enc else "NO")}
  </table>

  <h2>Integrity</h2>
  <table>
    <tr><td><strong>Verified</strong></td><td>{verified_badge}</td></tr>
    <tr><td><strong>SHA256</strong></td><td class="hash">{meta.hash_sha256 or "—"}</td></tr>
    <tr><td><strong>MD5</strong></td><td class="hash">{meta.hash_md5 or "—"}</td></tr>
    <tr><td><strong>SHA1</strong></td><td class="hash">{meta.hash_sha1 or "—"}</td></tr>
    <tr><td><strong>BLAKE3</strong></td><td class="hash">{meta.hash_blake3 or "—"}</td></tr>
  </table>

  <h2>Acquisition Timeline</h2>
  <table>
    {row("Start", meta.acquisition_start)}
    {row("End", meta.acquisition_end)}
    {row("Duration", f"{meta.duration_seconds}s")}
    {row("Bytes Acquired", f"{meta.bytes_acquired:,}")}
    {row("Output Path", meta.output_path)}
  </table>

  <h2>Examiner System</h2>
  <table>
    {row("Hostname", _get(sys_meta, "hostname"))}
    {row("OS", (_get(sys_meta, "os_name") + " " + _get(sys_meta, "os_version")).strip())}
    {row("Python", _get(sys_meta, "python_version"))}
  </table>

  <div class="footer">
    Generated by ForgeLens at {datetime.now(timezone.utc).isoformat()}
  </div>
</body>
</html>"""
