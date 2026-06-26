"""
ForgeLens DFIR View
===================
Offensive DFIR modules — persistence, beacons, credentials, ransomware, lateral.
"""

from __future__ import annotations

from typing import Any

import customtkinter as ctk

from frontend.theme import Colors, Fonts, Icons, Layout
from frontend.utils import SectionHeader, run_in_thread, show_error


class DFIRView(ctk.CTkFrame):
    """Offensive DFIR analysis view."""

    MODULES = {
        "persist": ("Persistence Hunting", "Hunt registry run keys, scheduled tasks, services, WMI, startup"),
        "beacons": ("Beacon Detection", "Detect C2 beaconing, LOLBin connections, suspicious DNS"),
        "creds": ("Credential Theft", "Mimikatz, Kerberoasting, DCSync, Pass-the-Hash, WDigest"),
        "ransomware": ("Ransomware Triage", "Ransom notes, encrypted extensions, VSS deletion, blast radius"),
        "lateral": ("Lateral Movement", "Logon paths, admin shares, remote services, PsExec/WMI/RDP"),
        "full-triage": ("Full Triage", "Run ALL five DFIR modules and produce combined report"),
    }

    def __init__(self, master: Any, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)

        content = ctk.CTkFrame(self, fg_color="transparent")
        content.pack(fill="both", expand=True, padx=Layout.PAD_LG, pady=Layout.PAD_LG)

        # ── Header ────────────────────────────────────────────────────────────
        ctk.CTkLabel(
            content, text="DFIR Analysis", font=Fonts.TITLE,
            text_color=Colors.TEXT_PRIMARY,
        ).pack(anchor="w")

        ctk.CTkLabel(
            content, text="Offensive DFIR modules with MITRE ATT&CK mapping",
            font=Fonts.SMALL, text_color=Colors.TEXT_SECONDARY,
        ).pack(anchor="w", pady=(4, Layout.PAD_LG))

        # ── Module Selector ───────────────────────────────────────────────────
        modules_frame = ctk.CTkFrame(
            content, fg_color=Colors.BG_PANEL, corner_radius=Layout.RADIUS_LG,
            border_width=1, border_color=Colors.BORDER,
        )
        modules_frame.pack(fill="x", pady=(0, Layout.PAD_LG))

        modules_inner = ctk.CTkFrame(modules_frame, fg_color="transparent")
        modules_inner.pack(fill="x", padx=Layout.PAD_XL, pady=Layout.PAD_XL)

        ctk.CTkLabel(
            modules_inner, text="SELECT MODULE", font=Fonts.SMALL_BOLD,
            text_color=Colors.TEXT_MUTED,
        ).pack(anchor="w", pady=(0, Layout.PAD_MD))

        self._selected_module = ctk.StringVar(value="persist")
        self._module_btns: dict[str, ctk.CTkButton] = {}

        # Module cards in a 2x3 grid
        grid = ctk.CTkFrame(modules_inner, fg_color="transparent")
        grid.pack(fill="x")
        grid.columnconfigure((0, 1, 2), weight=1)

        for i, (key, (title, desc)) in enumerate(self.MODULES.items()):
            row = i // 3
            col = i % 3

            btn_frame = ctk.CTkFrame(
                grid, fg_color=Colors.BG_SURFACE, corner_radius=Layout.RADIUS_MD,
                border_width=1, border_color=Colors.BORDER,
            )
            btn_frame.grid(row=row, column=col, padx=4, pady=4, sticky="nsew")

            # Make the whole card clickable
            inner = ctk.CTkFrame(btn_frame, fg_color="transparent")
            inner.pack(fill="both", padx=12, pady=10)

            title_lbl = ctk.CTkLabel(
                inner, text=title, font=Fonts.SMALL_BOLD,
                text_color=Colors.TEXT_PRIMARY,
            )
            title_lbl.pack(anchor="w")

            desc_lbl = ctk.CTkLabel(
                inner, text=desc, font=Fonts.TINY,
                text_color=Colors.TEXT_MUTED, wraplength=200, anchor="w", justify="left",
            )
            desc_lbl.pack(anchor="w", pady=(2, 0))

            # Bind click
            for widget in (btn_frame, inner, title_lbl, desc_lbl):
                widget.bind("<Button-1>", lambda e, k=key: self._select_module(k))
                widget.bind("<Enter>", lambda e, f=btn_frame: f.configure(fg_color=Colors.BG_HOVER))
                widget.bind("<Leave>", lambda e, f=btn_frame, k=key: f.configure(
                    fg_color=Colors.ACCENT_DIM if self._selected_module.get() == k else Colors.BG_SURFACE
                ))

            self._module_btns[key] = btn_frame

        self._update_module_selection()

        # ── Run Button ────────────────────────────────────────────────────────
        self._run_btn = ctk.CTkButton(
            content, text=f"{Icons.PLAY}  Run Analysis", font=Fonts.BODY_BOLD,
            width=180, height=44,
            fg_color=Colors.ACCENT, hover_color=Colors.ACCENT_HOVER,
            command=self._run_analysis,
        )
        self._run_btn.pack(anchor="w", pady=(0, Layout.PAD_LG))

        # ── Status ────────────────────────────────────────────────────────────
        self._status = ctk.CTkLabel(
            content, text="Select a module and click Run Analysis",
            font=Fonts.SMALL, text_color=Colors.TEXT_SECONDARY,
        )
        self._status.pack(anchor="w", pady=(0, Layout.PAD_SM))

        # ── Results ───────────────────────────────────────────────────────────
        SectionHeader(content, title="Findings").pack(fill="x", pady=(0, Layout.PAD_MD))

        self._results_scroll = ctk.CTkScrollableFrame(
            content, fg_color=Colors.BG_PANEL, corner_radius=Layout.RADIUS_LG,
            border_width=1, border_color=Colors.BORDER,
        )
        self._results_scroll.pack(fill="both", expand=True)

        self._results_placeholder = ctk.CTkLabel(
            self._results_scroll, text="  No findings yet — run an analysis module",
            font=Fonts.SMALL, text_color=Colors.TEXT_SECONDARY,
        )
        self._results_placeholder.pack(padx=Layout.CARD_PAD, pady=Layout.PAD_XL)

    # ── Module Selection ──────────────────────────────────────────────────────

    def _select_module(self, key: str):
        self._selected_module.set(key)
        self._update_module_selection()

    def _update_module_selection(self):
        for k, frame in self._module_btns.items():
            if k == self._selected_module.get():
                frame.configure(fg_color=Colors.ACCENT_DIM, border_color=Colors.ACCENT)
            else:
                frame.configure(fg_color=Colors.BG_SURFACE, border_color=Colors.BORDER)

    # ── Analysis ──────────────────────────────────────────────────────────────

    def _run_analysis(self):
        module = self._selected_module.get()
        title = self.MODULES[module][0]

        self._run_btn.configure(state="disabled", text="Running...")
        self._status.configure(text=f"Running {title}...", text_color=Colors.INFO)

        def _run():
            from core.dfir.dfir_engine import DFIREngine
            engine = DFIREngine()

            module_map = {
                "persist": engine.hunt_persistence,
                "beacons": engine.detect_beacons,
                "creds": engine.detect_credential_theft,
                "ransomware": engine.triage_ransomware,
                "lateral": engine.map_lateral_movement,
                "full-triage": engine.full_triage,
            }

            fn = module_map.get(module)
            if fn:
                return fn()
            return None

        def _on_done(report):
            self._run_btn.configure(state="normal", text=f"{Icons.PLAY}  Run Analysis")
            if report is None:
                self._status.configure(text="Module returned no data", text_color=Colors.WARNING)
                return

            findings = []
            if hasattr(report, "findings"):
                findings = report.findings
            elif isinstance(report, dict):
                findings = report.get("findings", [])
            elif isinstance(report, list):
                findings = report

            self._status.configure(
                text=f"{title}: {len(findings)} finding(s)",
                text_color=Colors.SUCCESS if not findings else Colors.WARNING,
            )
            self._display_findings(findings)

        def _on_error(exc):
            self._run_btn.configure(state="normal", text=f"{Icons.PLAY}  Run Analysis")
            self._status.configure(text=f"Error: {exc}", text_color=Colors.ERROR)

        run_in_thread(self, _run, on_success=_on_done, on_error=_on_error)

    def _display_findings(self, findings: list):
        for w in self._results_scroll.winfo_children():
            w.destroy()

        if not findings:
            ctk.CTkLabel(
                self._results_scroll, text="  ✔  No findings — system appears clean",
                font=Fonts.BODY, text_color=Colors.SUCCESS,
            ).pack(padx=Layout.CARD_PAD, pady=Layout.PAD_XL)
            return

        for i, finding in enumerate(findings):
            # Each finding as a card
            severity = "medium"
            mitre = ""
            description = ""
            title = ""

            if isinstance(finding, dict):
                title = finding.get("title", finding.get("name", f"Finding #{i+1}"))
                description = finding.get("description", finding.get("detail", str(finding)))
                severity = finding.get("severity", finding.get("risk", "medium"))
                mitre = finding.get("mitre_technique", finding.get("technique", ""))
            elif hasattr(finding, "title"):
                title = getattr(finding, "title", f"Finding #{i+1}")
                description = getattr(finding, "description", str(finding))
                severity = getattr(finding, "severity", "medium")
                mitre = getattr(finding, "mitre_technique", "")
            else:
                title = f"Finding #{i+1}"
                description = str(finding)

            # Severity color
            sev_colors = {
                "critical": Colors.ERROR, "high": Colors.ACCENT,
                "medium": Colors.WARNING, "low": Colors.TEXT_SECONDARY,
            }
            sev_color = sev_colors.get(str(severity).lower(), Colors.TEXT_PRIMARY)

            card = ctk.CTkFrame(
                self._results_scroll, fg_color=Colors.BG_SURFACE,
                corner_radius=Layout.RADIUS_MD, border_width=1,
                border_color=sev_color,
            )
            card.pack(fill="x", padx=4, pady=4)

            card_inner = ctk.CTkFrame(card, fg_color="transparent")
            card_inner.pack(fill="x", padx=Layout.CARD_PAD, pady=Layout.PAD_MD)

            # Title row
            title_row = ctk.CTkFrame(card_inner, fg_color="transparent")
            title_row.pack(fill="x")

            ctk.CTkLabel(
                title_row, text=f"● {str(severity).upper()}", font=Fonts.TINY,
                text_color=sev_color,
            ).pack(side="left")

            if mitre:
                ctk.CTkLabel(
                    title_row, text=f"  {mitre}", font=Fonts.TINY,
                    text_color=Colors.INFO,
                ).pack(side="left", padx=(8, 0))

            ctk.CTkLabel(
                card_inner, text=title, font=Fonts.BODY_BOLD,
                text_color=Colors.TEXT_PRIMARY,
            ).pack(anchor="w", pady=(4, 2))

            ctk.CTkLabel(
                card_inner, text=description, font=Fonts.SMALL,
                text_color=Colors.TEXT_SECONDARY, wraplength=800,
                anchor="w", justify="left",
            ).pack(anchor="w")
