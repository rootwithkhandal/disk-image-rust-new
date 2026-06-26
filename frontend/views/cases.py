"""
ForgeLens Cases View
====================
Case management — list, create, update, search cases.
"""

from __future__ import annotations

from typing import Any

import customtkinter as ctk

from frontend.theme import Colors, Fonts, Icons, Layout
from frontend.utils import DataTable, SectionHeader, run_in_thread, show_error, show_success


class CasesView(ctk.CTkFrame):
    """Case management view."""

    def __init__(self, master: Any, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)

        content = ctk.CTkFrame(self, fg_color="transparent")
        content.pack(fill="both", expand=True, padx=Layout.PAD_LG, pady=Layout.PAD_LG)

        # ── Header ────────────────────────────────────────────────────────────
        header = ctk.CTkFrame(content, fg_color="transparent")
        header.pack(fill="x", pady=(0, Layout.PAD_LG))

        ctk.CTkLabel(
            header, text="Cases", font=Fonts.TITLE,
            text_color=Colors.TEXT_PRIMARY,
        ).pack(side="left")

        ctk.CTkButton(
            header, text=f"{Icons.ADD}  New Case", font=Fonts.BODY_BOLD,
            width=140, height=36,
            fg_color=Colors.SUCCESS, hover_color="#3edd85",
            command=self._show_create_dialog,
        ).pack(side="right")

        self._refresh_btn = ctk.CTkButton(
            header, text=f"{Icons.REFRESH}  Refresh", font=Fonts.SMALL_BOLD,
            width=100, height=36,
            fg_color=Colors.BG_SURFACE, hover_color=Colors.BG_HOVER,
            text_color=Colors.TEXT_SECONDARY,
            command=self._load_cases,
        )
        self._refresh_btn.pack(side="right", padx=(0, 8))

        # ── Filters Row ──────────────────────────────────────────────────────
        filters = ctk.CTkFrame(content, fg_color="transparent")
        filters.pack(fill="x", pady=(0, Layout.PAD_MD))

        # Search
        self._search_var = ctk.StringVar()
        search_entry = ctk.CTkEntry(
            filters, placeholder_text="Search cases...", font=Fonts.SMALL,
            width=300, height=34,
            fg_color=Colors.BG_SURFACE, border_color=Colors.BORDER,
            text_color=Colors.TEXT_PRIMARY,
            textvariable=self._search_var,
        )
        search_entry.pack(side="left", padx=(0, 12))
        search_entry.bind("<Return>", lambda e: self._search())

        ctk.CTkButton(
            filters, text=Icons.SEARCH, width=34, height=34,
            fg_color=Colors.BG_SURFACE, hover_color=Colors.BG_HOVER,
            text_color=Colors.TEXT_SECONDARY,
            command=self._search,
        ).pack(side="left", padx=(0, 16))

        # Status filter
        ctk.CTkLabel(
            filters, text="Status:", font=Fonts.SMALL,
            text_color=Colors.TEXT_SECONDARY,
        ).pack(side="left", padx=(0, 6))

        self._status_var = ctk.StringVar(value="All")
        ctk.CTkOptionMenu(
            filters, variable=self._status_var,
            values=["All", "open", "active", "closed", "archived"],
            width=120, height=34, font=Fonts.SMALL,
            fg_color=Colors.BG_SURFACE, button_color=Colors.BG_HOVER,
            button_hover_color=Colors.ACCENT_DIM,
            text_color=Colors.TEXT_PRIMARY,
            dropdown_fg_color=Colors.BG_PANEL,
            dropdown_text_color=Colors.TEXT_PRIMARY,
            dropdown_hover_color=Colors.BG_HOVER,
            command=lambda _: self._load_cases(),
        ).pack(side="left")

        # ── Status label ──────────────────────────────────────────────────────
        self._status = ctk.CTkLabel(
            content, text="Loading cases...", font=Fonts.SMALL,
            text_color=Colors.TEXT_SECONDARY,
        )
        self._status.pack(anchor="w", pady=(0, Layout.PAD_SM))

        # ── Cases Table ───────────────────────────────────────────────────────
        columns = [
            ("Case ID", 160),
            ("Title", 200),
            ("Examiner", 120),
            ("Status", 90),
            ("Priority", 80),
            ("Evidence", 70),
            ("Tags", 150),
            ("Created", 100),
        ]

        self._table = DataTable(content, columns=columns, on_row_click=self._on_case_click)
        self._table.pack(fill="both", expand=True)

        # ── Load initial data ─────────────────────────────────────────────────
        self.after(200, self._load_cases)

    # ── Data Loading ──────────────────────────────────────────────────────────

    def _load_cases(self):
        status_filter = self._status_var.get()

        def _fetch():
            from core.chain_of_custody.case_manager import CaseManager, CaseStatus
            mgr = CaseManager()
            filt = CaseStatus(status_filter) if status_filter != "All" else None
            return mgr.list_cases(status=filt)

        def _on_done(cases):
            rows = []
            for c in cases:
                rows.append({
                    "Case ID": c.case_id,
                    "Title": c.title or "—",
                    "Examiner": c.examiner,
                    "Status": c.status.value,
                    "Priority": c.priority,
                    "Evidence": str(len(c.evidence_ids)),
                    "Tags": ", ".join(c.tags) if c.tags else "—",
                    "Created": c.created_at[:10] if c.created_at else "—",
                })
            self._table.set_data(rows)
            self._status.configure(
                text=f"{len(cases)} case(s) found",
                text_color=Colors.TEXT_SECONDARY,
            )

        def _on_error(exc):
            self._status.configure(text=f"Error: {exc}", text_color=Colors.ERROR)

        run_in_thread(self, _fetch, on_success=_on_done, on_error=_on_error)

    def _search(self):
        query = self._search_var.get().strip()
        if not query:
            self._load_cases()
            return

        def _fetch():
            from core.chain_of_custody.case_manager import CaseManager
            return CaseManager().search_cases(query)

        def _on_done(cases):
            rows = []
            for c in cases:
                rows.append({
                    "Case ID": c.case_id,
                    "Title": c.title or "—",
                    "Examiner": c.examiner,
                    "Status": c.status.value,
                    "Priority": c.priority,
                    "Evidence": str(len(c.evidence_ids)),
                    "Tags": ", ".join(c.tags) if c.tags else "—",
                    "Created": c.created_at[:10] if c.created_at else "—",
                })
            self._table.set_data(rows)
            self._status.configure(
                text=f"{len(cases)} result(s) for '{query}'",
                text_color=Colors.TEXT_SECONDARY,
            )

        run_in_thread(self, _fetch, on_success=_on_done)

    def _on_case_click(self, idx: int, row: dict):
        """Show case detail (future: open case detail panel)."""
        pass  # Placeholder for case detail navigation

    # ── Create Case Dialog ────────────────────────────────────────────────────

    def _show_create_dialog(self):
        dialog = ctk.CTkToplevel(self)
        dialog.title("Create New Case")
        dialog.geometry("500x480")
        dialog.resizable(False, False)
        dialog.transient(self.winfo_toplevel())
        dialog.grab_set()
        dialog.configure(fg_color=Colors.BG_DARKEST)

        # Center
        dialog.after(10, lambda: self._center(dialog))

        ctk.CTkLabel(
            dialog, text="Create New Case", font=Fonts.HEADING,
            text_color=Colors.TEXT_PRIMARY,
        ).pack(pady=(24, 16))

        form = ctk.CTkFrame(dialog, fg_color="transparent")
        form.pack(fill="x", padx=32)

        fields = {}

        def _add_field(label: str, placeholder: str = "", default: str = "") -> ctk.CTkEntry:
            ctk.CTkLabel(
                form, text=label, font=Fonts.SMALL_BOLD,
                text_color=Colors.TEXT_SECONDARY,
            ).pack(anchor="w", pady=(8, 2))
            entry = ctk.CTkEntry(
                form, placeholder_text=placeholder, font=Fonts.BODY,
                height=36, fg_color=Colors.BG_SURFACE,
                border_color=Colors.BORDER, text_color=Colors.TEXT_PRIMARY,
            )
            if default:
                entry.insert(0, default)
            entry.pack(fill="x", pady=(0, 4))
            return entry

        fields["case_id"] = _add_field("Case ID *", "e.g. CASE-2026-001")
        fields["examiner"] = _add_field("Examiner *", "Your name")
        fields["title"] = _add_field("Title", "Short case title")
        fields["description"] = _add_field("Description", "Case description")
        fields["tags"] = _add_field("Tags", "Comma-separated tags")

        # Priority
        ctk.CTkLabel(
            form, text="Priority", font=Fonts.SMALL_BOLD,
            text_color=Colors.TEXT_SECONDARY,
        ).pack(anchor="w", pady=(8, 2))

        priority_var = ctk.StringVar(value="medium")
        ctk.CTkOptionMenu(
            form, variable=priority_var,
            values=["low", "medium", "high", "critical"],
            width=200, height=36, font=Fonts.BODY,
            fg_color=Colors.BG_SURFACE, button_color=Colors.BG_HOVER,
            text_color=Colors.TEXT_PRIMARY,
            dropdown_fg_color=Colors.BG_PANEL,
            dropdown_text_color=Colors.TEXT_PRIMARY,
        ).pack(anchor="w")

        # Buttons
        btn_frame = ctk.CTkFrame(dialog, fg_color="transparent")
        btn_frame.pack(pady=20)

        def _create():
            case_id = fields["case_id"].get().strip()
            examiner = fields["examiner"].get().strip()
            if not case_id or not examiner:
                show_error(dialog, "Validation", "Case ID and Examiner are required.")
                return

            try:
                from core.chain_of_custody.case_manager import CaseManager
                mgr = CaseManager()
                tag_list = [t.strip() for t in fields["tags"].get().split(",") if t.strip()]
                mgr.create_case(
                    case_id=case_id, examiner=examiner,
                    title=fields["title"].get().strip() or case_id,
                    description=fields["description"].get().strip(),
                    tags=tag_list, priority=priority_var.get(),
                )
                dialog.destroy()
                show_success(self, "Case Created", f"Case {case_id} created successfully.")
                self._load_cases()
            except Exception as exc:
                show_error(dialog, "Error", str(exc))

        ctk.CTkButton(
            btn_frame, text="Create Case", width=140, height=36,
            font=Fonts.BODY_BOLD,
            fg_color=Colors.SUCCESS, hover_color="#3edd85",
            command=_create,
        ).pack(side="left", padx=8)

        ctk.CTkButton(
            btn_frame, text="Cancel", width=100, height=36,
            font=Fonts.BODY,
            fg_color=Colors.BG_SURFACE, hover_color=Colors.BG_HOVER,
            text_color=Colors.TEXT_SECONDARY,
            command=dialog.destroy,
        ).pack(side="left", padx=8)

    def _center(self, dialog):
        dialog.update_idletasks()
        parent = self.winfo_toplevel()
        pw, ph = parent.winfo_width(), parent.winfo_height()
        px, py = parent.winfo_rootx(), parent.winfo_rooty()
        dw, dh = dialog.winfo_width(), dialog.winfo_height()
        dialog.geometry(f"+{px + (pw - dw) // 2}+{py + (ph - dh) // 2}")
