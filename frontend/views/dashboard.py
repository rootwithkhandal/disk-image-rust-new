"""
ForgeLens Dashboard View
========================
System overview with stat cards, recent activity, system info, and quick actions.
"""

from __future__ import annotations

import platform
from typing import Any

import customtkinter as ctk

from frontend.theme import Colors, Fonts, Icons, Layout
from frontend.utils import StatCard, SectionHeader, run_in_thread


class DashboardView(ctk.CTkFrame):
    """Main dashboard view."""

    def __init__(self, master: Any, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)

        # Scrollable content
        scroll = ctk.CTkScrollableFrame(self, fg_color="transparent")
        scroll.pack(fill="both", expand=True, padx=Layout.PAD_LG, pady=Layout.PAD_LG)

        # ── Header ────────────────────────────────────────────────────────────
        header = ctk.CTkFrame(scroll, fg_color="transparent")
        header.pack(fill="x", pady=(0, Layout.PAD_LG))

        ctk.CTkLabel(
            header, text="Dashboard", font=Fonts.TITLE,
            text_color=Colors.TEXT_PRIMARY,
        ).pack(side="left")

        ctk.CTkLabel(
            header, text="System Overview & Quick Actions", font=Fonts.SMALL,
            text_color=Colors.TEXT_SECONDARY,
        ).pack(side="left", padx=(16, 0), pady=(6, 0))

        # ── Stat Cards ────────────────────────────────────────────────────────
        cards_frame = ctk.CTkFrame(scroll, fg_color="transparent")
        cards_frame.pack(fill="x", pady=(0, Layout.PAD_XL))
        cards_frame.columnconfigure((0, 1, 2, 3), weight=1)

        self._card_cases = StatCard(
            cards_frame, title="Cases", value="—",
            accent=Colors.STATUS_OPEN, icon=Icons.CASES,
        )
        self._card_cases.grid(row=0, column=0, padx=(0, 8), sticky="nsew")

        self._card_evidence = StatCard(
            cards_frame, title="Evidence Items", value="—",
            accent=Colors.SUCCESS, icon=Icons.EVIDENCE,
        )
        self._card_evidence.grid(row=0, column=1, padx=8, sticky="nsew")

        self._card_devices = StatCard(
            cards_frame, title="Devices", value="—",
            accent=Colors.WARNING, icon=Icons.DEVICES,
        )
        self._card_devices.grid(row=0, column=2, padx=8, sticky="nsew")

        self._card_hashes = StatCard(
            cards_frame, title="Platform", value=platform.system(),
            accent=Colors.INFO, icon=Icons.SHIELD,
        )
        self._card_hashes.grid(row=0, column=3, padx=(8, 0), sticky="nsew")

        # ── Two-column layout ─────────────────────────────────────────────────
        body = ctk.CTkFrame(scroll, fg_color="transparent")
        body.pack(fill="both", expand=True)
        body.columnconfigure(0, weight=3)
        body.columnconfigure(1, weight=2)

        # Left column — Quick Actions
        left = ctk.CTkFrame(body, fg_color="transparent")
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 8))

        SectionHeader(left, title="Quick Actions").pack(fill="x", pady=(0, Layout.PAD_MD))

        actions_panel = ctk.CTkFrame(
            left, fg_color=Colors.BG_PANEL, corner_radius=Layout.RADIUS_LG,
            border_width=1, border_color=Colors.BORDER,
        )
        actions_panel.pack(fill="x", pady=(0, Layout.PAD_LG))

        actions = [
            (Icons.DEVICES + "  Scan Devices", Colors.INFO, "devices"),
            (Icons.ADD + "  New Case", Colors.SUCCESS, "cases"),
            (Icons.ACQUISITION + "  Start Acquisition", Colors.ACCENT, "acquisition"),
            (Icons.HASHING + "  Hash File", Colors.WARNING, "hashing"),
        ]

        try:
            from core.config import settings
            disabled_features = settings.features.disabled
        except Exception:
            disabled_features = []

        visible_actions = [a for a in actions if a[2] not in disabled_features]

        for i, (text, color, tab_key) in enumerate(visible_actions):
            btn = ctk.CTkButton(
                actions_panel, text=text, font=Fonts.BODY_BOLD,
                height=44, anchor="w",
                fg_color=Colors.BG_SURFACE, hover_color=Colors.BG_HOVER,
                text_color=Colors.TEXT_PRIMARY,
                corner_radius=Layout.RADIUS_SM,
                command=lambda k=tab_key: self._navigate(k),
            )
            btn.pack(fill="x", padx=Layout.CARD_PAD, pady=(Layout.CARD_PAD if i == 0 else 4, 4 if i < len(visible_actions) - 1 else Layout.CARD_PAD))

        # Recent activity
        SectionHeader(left, title="Recent Activity").pack(fill="x", pady=(Layout.PAD_MD, Layout.PAD_MD))

        self._activity_frame = ctk.CTkFrame(
            left, fg_color=Colors.BG_PANEL, corner_radius=Layout.RADIUS_LG,
            border_width=1, border_color=Colors.BORDER,
        )
        self._activity_frame.pack(fill="x")

        self._activity_label = ctk.CTkLabel(
            self._activity_frame, text="  Loading activity...",
            font=Fonts.SMALL, text_color=Colors.TEXT_SECONDARY,
        )
        self._activity_label.pack(padx=Layout.CARD_PAD, pady=Layout.PAD_XL)

        # Right column — System Info
        right = ctk.CTkFrame(body, fg_color="transparent")
        right.grid(row=0, column=1, sticky="nsew", padx=(8, 0))

        SectionHeader(right, title="System Info").pack(fill="x", pady=(0, Layout.PAD_MD))

        sys_panel = ctk.CTkFrame(
            right, fg_color=Colors.BG_PANEL, corner_radius=Layout.RADIUS_LG,
            border_width=1, border_color=Colors.BORDER,
        )
        sys_panel.pack(fill="x")

        sys_info = self._get_system_info()
        for i, (label, value) in enumerate(sys_info):
            row = ctk.CTkFrame(
                sys_panel,
                fg_color=Colors.BG_SURFACE if i % 2 == 0 else "transparent",
                corner_radius=0,
            )
            row.pack(fill="x", padx=2, pady=1)

            ctk.CTkLabel(
                row, text=label, font=Fonts.SMALL_BOLD,
                text_color=Colors.TEXT_SECONDARY, width=120, anchor="w",
            ).pack(side="left", padx=(Layout.CARD_PAD, 8), pady=8)

            ctk.CTkLabel(
                row, text=value, font=Fonts.SMALL,
                text_color=Colors.TEXT_PRIMARY, anchor="w",
            ).pack(side="left", padx=(0, Layout.CARD_PAD), pady=8)

        # ── Capability matrix ─────────────────────────────────────────────────
        SectionHeader(right, title="Capabilities").pack(fill="x", pady=(Layout.PAD_LG, Layout.PAD_MD))

        caps_panel = ctk.CTkFrame(
            right, fg_color=Colors.BG_PANEL, corner_radius=Layout.RADIUS_LG,
            border_width=1, border_color=Colors.BORDER,
        )
        caps_panel.pack(fill="x")

        try:
            from core.config import settings
            disabled_features = settings.features.disabled
        except Exception:
            disabled_features = []

        capabilities = [
            ("Disk Imaging", "devices" not in disabled_features),
            ("Memory Forensics", "memory" not in disabled_features),
            ("Mobile Forensics", "mobile" not in disabled_features),
            ("Cloud Acquisition", "cloud" not in disabled_features),
            ("YARA Scanning", "yara" not in disabled_features),
            ("DFIR Modules", "dfir" not in disabled_features),
            ("AI Analysis", "v3" not in disabled_features),
            ("Distributed Agents", "v3" not in disabled_features),
        ]

        for i, (cap, available) in enumerate(capabilities):
            row = ctk.CTkFrame(caps_panel, fg_color="transparent", height=28)
            row.pack(fill="x", padx=Layout.CARD_PAD, pady=2)
            row.pack_propagate(False)

            status_icon = Icons.CHECK if available else Icons.CROSS
            status_color = Colors.SUCCESS if available else Colors.TEXT_MUTED

            ctk.CTkLabel(
                row, text=status_icon, font=Fonts.SMALL,
                text_color=status_color, width=20,
            ).pack(side="left")

            ctk.CTkLabel(
                row, text=cap, font=Fonts.SMALL,
                text_color=Colors.TEXT_PRIMARY,
            ).pack(side="left", padx=(6, 0))

        # ── Load data ─────────────────────────────────────────────────────────
        self.after(200, self._load_stats)

    # ── Navigation callback (set by App) ──────────────────────────────────────

    _navigate_callback = None

    def set_navigate(self, callback):
        self._navigate_callback = callback

    def _navigate(self, tab_key: str):
        if self._navigate_callback:
            self._navigate_callback(tab_key)

    # ── Data loading ──────────────────────────────────────────────────────────

    def _load_stats(self):
        def _fetch():
            try:
                from core.chain_of_custody.case_manager import CaseManager
                cases = CaseManager().list_cases()
                case_count = len(cases)
            except Exception:
                case_count = 0

            try:
                from core.chain_of_custody.evidence_index import EvidenceIndex
                idx = EvidenceIndex()
                ev_count = len(idx.search(""))
            except Exception:
                ev_count = 0

            return case_count, ev_count

        def _on_done(result):
            case_count, ev_count = result
            self._card_cases.set_value(str(case_count))
            self._card_evidence.set_value(str(ev_count))
            self._card_devices.set_value("—")
            self._activity_label.configure(
                text="  No recent acquisitions" if ev_count == 0 else f"  {ev_count} evidence item(s) in vault"
            )

        run_in_thread(self, _fetch, on_success=_on_done)

    @staticmethod
    def _get_system_info() -> list[tuple[str, str]]:
        import psutil
        mem = psutil.virtual_memory()
        return [
            ("OS", f"{platform.system()} {platform.release()}"),
            ("Architecture", platform.machine()),
            ("Processor", platform.processor()[:40] or "Unknown"),
            ("CPU Cores", str(psutil.cpu_count(logical=True))),
            ("RAM Total", f"{mem.total / (1024**3):.1f} GB"),
            ("RAM Available", f"{mem.available / (1024**3):.1f} GB"),
            ("Python", platform.python_version()),
        ]
