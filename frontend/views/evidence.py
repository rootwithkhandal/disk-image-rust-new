"""
ForgeLens Evidence View
=======================
Evidence browser — search, filter, view metadata and chain of custody.
"""

from __future__ import annotations

from typing import Any

import customtkinter as ctk

from frontend.theme import Colors, Fonts, Icons, Layout
from frontend.utils import DataTable, SectionHeader, run_in_thread


class EvidenceView(ctk.CTkFrame):
    """Evidence browser view."""

    def __init__(self, master: Any, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)

        content = ctk.CTkFrame(self, fg_color="transparent")
        content.pack(fill="both", expand=True, padx=Layout.PAD_LG, pady=Layout.PAD_LG)

        # ── Header ────────────────────────────────────────────────────────────
        header = ctk.CTkFrame(content, fg_color="transparent")
        header.pack(fill="x", pady=(0, Layout.PAD_LG))

        ctk.CTkLabel(
            header, text="Evidence Vault", font=Fonts.TITLE,
            text_color=Colors.TEXT_PRIMARY,
        ).pack(side="left")

        ctk.CTkButton(
            header, text=f"{Icons.REFRESH}  Rebuild Index", font=Fonts.SMALL_BOLD,
            width=140, height=36,
            fg_color=Colors.BG_SURFACE, hover_color=Colors.BG_HOVER,
            text_color=Colors.TEXT_SECONDARY,
            command=self._rebuild_index,
        ).pack(side="right")

        # ── Filters ──────────────────────────────────────────────────────────
        filters = ctk.CTkFrame(content, fg_color="transparent")
        filters.pack(fill="x", pady=(0, Layout.PAD_MD))

        self._search_var = ctk.StringVar()
        search_entry = ctk.CTkEntry(
            filters, placeholder_text="Search evidence...", font=Fonts.SMALL,
            width=300, height=34,
            fg_color=Colors.BG_SURFACE, border_color=Colors.BORDER,
            text_color=Colors.TEXT_PRIMARY,
            textvariable=self._search_var,
        )
        search_entry.pack(side="left", padx=(0, 8))
        search_entry.bind("<Return>", lambda e: self._search())

        ctk.CTkButton(
            filters, text=Icons.SEARCH, width=34, height=34,
            fg_color=Colors.BG_SURFACE, hover_color=Colors.BG_HOVER,
            text_color=Colors.TEXT_SECONDARY,
            command=self._search,
        ).pack(side="left", padx=(0, 16))

        # Tag filter
        ctk.CTkLabel(
            filters, text="Tag:", font=Fonts.SMALL,
            text_color=Colors.TEXT_SECONDARY,
        ).pack(side="left", padx=(0, 6))

        self._tag_var = ctk.StringVar()
        self._tag_entry = ctk.CTkEntry(
            filters, placeholder_text="Filter by tag", font=Fonts.SMALL,
            width=150, height=34,
            fg_color=Colors.BG_SURFACE, border_color=Colors.BORDER,
            text_color=Colors.TEXT_PRIMARY,
            textvariable=self._tag_var,
        )
        self._tag_entry.pack(side="left", padx=(0, 8))
        self._tag_entry.bind("<Return>", lambda e: self._filter_by_tag())

        # Case filter
        ctk.CTkLabel(
            filters, text="Case:", font=Fonts.SMALL,
            text_color=Colors.TEXT_SECONDARY,
        ).pack(side="left", padx=(8, 6))

        self._case_var = ctk.StringVar()
        self._case_entry = ctk.CTkEntry(
            filters, placeholder_text="Filter by case ID", font=Fonts.SMALL,
            width=160, height=34,
            fg_color=Colors.BG_SURFACE, border_color=Colors.BORDER,
            text_color=Colors.TEXT_PRIMARY,
            textvariable=self._case_var,
        )
        self._case_entry.pack(side="left")
        self._case_entry.bind("<Return>", lambda e: self._filter_by_case())

        # ── Status ────────────────────────────────────────────────────────────
        self._status = ctk.CTkLabel(
            content, text="Loading evidence...", font=Fonts.SMALL,
            text_color=Colors.TEXT_SECONDARY,
        )
        self._status.pack(anchor="w", pady=(0, Layout.PAD_SM))

        # ── Evidence Table ────────────────────────────────────────────────────
        columns = [
            ("Evidence ID", 130),
            ("Case ID", 140),
            ("Device", 160),
            ("Method", 100),
            ("Examiner", 100),
            ("Size (GB)", 80),
            ("Verified", 70),
            ("Tags", 140),
            ("Timestamp", 140),
        ]

        self._table = DataTable(content, columns=columns, on_row_click=self._on_evidence_click)
        self._table.pack(fill="both", expand=True)

        # ── Detail Panel ──────────────────────────────────────────────────────
        self._detail = ctk.CTkFrame(
            content, fg_color=Colors.BG_PANEL, corner_radius=Layout.RADIUS_LG,
            border_width=1, border_color=Colors.BORDER, height=140,
        )
        self._detail.pack(fill="x", pady=(Layout.PAD_MD, 0))
        self._detail.pack_propagate(False)

        self._detail_content = ctk.CTkLabel(
            self._detail, text="  Select an evidence item to view details",
            font=Fonts.SMALL, text_color=Colors.TEXT_SECONDARY,
        )
        self._detail_content.pack(padx=Layout.CARD_PAD, pady=Layout.PAD_XL)

        # ── Load ──────────────────────────────────────────────────────────────
        self.after(200, self._load_all)

    # ── Data ──────────────────────────────────────────────────────────────────

    def _load_all(self):
        def _fetch():
            from core.chain_of_custody.evidence_index import EvidenceIndex
            idx = EvidenceIndex()
            return idx.search("")

        self._handle_results(_fetch, "evidence item(s)")

    def _search(self):
        query = self._search_var.get().strip()
        if not query:
            self._load_all()
            return

        def _fetch():
            from core.chain_of_custody.evidence_index import EvidenceIndex
            return EvidenceIndex().search(query)

        self._handle_results(_fetch, f"result(s) for '{query}'")

    def _filter_by_tag(self):
        tag = self._tag_var.get().strip()
        if not tag:
            self._load_all()
            return

        def _fetch():
            from core.chain_of_custody.evidence_index import EvidenceIndex
            return EvidenceIndex().get_by_tag(tag)

        self._handle_results(_fetch, f"result(s) with tag '{tag}'")

    def _filter_by_case(self):
        case_id = self._case_var.get().strip()
        if not case_id:
            self._load_all()
            return

        def _fetch():
            from core.chain_of_custody.evidence_index import EvidenceIndex
            return EvidenceIndex().get_by_case(case_id)

        self._handle_results(_fetch, f"item(s) in case '{case_id}'")

    def _handle_results(self, fetch_fn, suffix: str):
        def _on_done(entries):
            rows = []
            for e in entries:
                rows.append({
                    "Evidence ID": e.evidence_id,
                    "Case ID": e.case_id,
                    "Device": e.device_model or e.device_id or "—",
                    "Method": e.acquisition_method or "—",
                    "Examiner": e.examiner or "—",
                    "Size (GB)": str(e.size_gb) if e.size_gb else "—",
                    "Verified": "✔" if e.verified else "—",
                    "Tags": ", ".join(e.tags) if e.tags else "—",
                    "Timestamp": e.timestamp_utc[:19] if e.timestamp_utc else "—",
                })
            self._table.set_data(rows)
            self._status.configure(
                text=f"{len(entries)} {suffix}",
                text_color=Colors.TEXT_SECONDARY,
            )

        def _on_error(exc):
            self._status.configure(text=f"Error: {exc}", text_color=Colors.ERROR)

        run_in_thread(self, fetch_fn, on_success=_on_done, on_error=_on_error)

    def _rebuild_index(self):
        self._status.configure(text="Rebuilding index...", text_color=Colors.INFO)

        def _rebuild():
            from core.chain_of_custody.evidence_index import EvidenceIndex
            return EvidenceIndex().rebuild()

        def _done(count):
            self._status.configure(
                text=f"Index rebuilt — {count} item(s) indexed",
                text_color=Colors.SUCCESS,
            )
            self._load_all()

        run_in_thread(self, _rebuild, on_success=_done)

    def _on_evidence_click(self, idx: int, row: dict):
        for w in self._detail.winfo_children():
            w.destroy()

        detail = ctk.CTkFrame(self._detail, fg_color="transparent")
        detail.pack(fill="both", expand=True, padx=Layout.CARD_PAD, pady=Layout.PAD_MD)

        ev_id = row.get("Evidence ID", "")
        ctk.CTkLabel(
            detail, text=f"Evidence: {ev_id}",
            font=Fonts.SUBHEADING, text_color=Colors.ACCENT,
        ).pack(anchor="w")

        info = ctk.CTkFrame(detail, fg_color="transparent")
        info.pack(fill="x", pady=(6, 0))

        for label, key in [("Case", "Case ID"), ("Device", "Device"), ("Method", "Method"),
                           ("Examiner", "Examiner"), ("Size", "Size (GB)"), ("Verified", "Verified")]:
            ctk.CTkLabel(
                info, text=f"{label}: ", font=Fonts.SMALL_BOLD,
                text_color=Colors.TEXT_SECONDARY,
            ).pack(side="left")
            val = row.get(key, "—")
            color = Colors.SUCCESS if key == "Verified" and val == "✔" else Colors.TEXT_PRIMARY
            ctk.CTkLabel(
                info, text=val, font=Fonts.SMALL,
                text_color=color,
            ).pack(side="left", padx=(0, 14))
