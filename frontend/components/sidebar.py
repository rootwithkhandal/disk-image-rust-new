"""
ForgeLens Sidebar
=================
Left navigation panel with tab buttons, branding, and version info.
"""

from __future__ import annotations

from typing import Any, Callable

import customtkinter as ctk

from frontend.theme import Colors, Fonts, Icons, Layout


class Sidebar(ctk.CTkFrame):
    """Collapsible sidebar with navigation buttons."""

    # Tab definitions: (key, icon, label)
    TABS = [
        ("dashboard",   Icons.DASHBOARD,   "Dashboard"),
        ("devices",     Icons.DEVICES,     "Devices"),
        ("cases",       Icons.CASES,       "Cases"),
        ("evidence",    Icons.EVIDENCE,    "Evidence"),
        ("acquisition", Icons.ACQUISITION, "Acquisition"),
        ("hashing",     Icons.HASHING,     "Hashing"),
        ("memory",      Icons.MEMORY,      "Memory"),
        ("dfir",        Icons.DFIR,        "DFIR"),
    ]

    def __init__(
        self,
        master: Any,
        on_tab_change: Callable[[str], None],
        **kwargs,
    ):
        super().__init__(
            master,
            width=Layout.SIDEBAR_WIDTH,
            fg_color=Colors.BG_DARK,
            corner_radius=0,
            **kwargs,
        )
        self.pack_propagate(False)

        self._on_tab_change = on_tab_change
        self._active_tab = "dashboard"
        self._buttons: dict[str, ctk.CTkButton] = {}

        # ── Branding ──────────────────────────────────────────────────────────
        brand_frame = ctk.CTkFrame(self, fg_color="transparent")
        brand_frame.pack(fill="x", padx=Layout.PAD_LG, pady=(Layout.PAD_XL, Layout.PAD_SM))

        # Logo accent bar
        accent = ctk.CTkFrame(brand_frame, width=4, height=36, fg_color=Colors.ACCENT, corner_radius=2)
        accent.pack(side="left", padx=(0, 10))

        title_block = ctk.CTkFrame(brand_frame, fg_color="transparent")
        title_block.pack(side="left", fill="x")

        ctk.CTkLabel(
            title_block, text="FORGELENS", font=("Segoe UI", 18, "bold"),
            text_color=Colors.TEXT_PRIMARY,
        ).pack(anchor="w")

        ctk.CTkLabel(
            title_block, text="DFIR Platform", font=Fonts.TINY,
            text_color=Colors.TEXT_MUTED,
        ).pack(anchor="w")

        # Divider
        ctk.CTkFrame(self, height=1, fg_color=Colors.BORDER).pack(
            fill="x", padx=Layout.PAD_LG, pady=(Layout.PAD_SM, Layout.PAD_MD),
        )

        # ── Navigation Label ──────────────────────────────────────────────────
        ctk.CTkLabel(
            self, text="NAVIGATION", font=Fonts.TINY,
            text_color=Colors.TEXT_MUTED,
        ).pack(anchor="w", padx=Layout.PAD_XL, pady=(0, Layout.PAD_SM))

        # ── Tab Buttons ───────────────────────────────────────────────────────
        try:
            from core.config import settings
            disabled_features = settings.features.disabled
        except Exception:
            disabled_features = []

        visible_tabs = [t for t in self.TABS if t[0] not in disabled_features]

        for key, icon, label in visible_tabs:
            btn = ctk.CTkButton(
                self,
                text=f"  {icon}   {label}",
                font=Fonts.BODY,
                anchor="w",
                height=40,
                corner_radius=Layout.RADIUS_SM,
                fg_color="transparent",
                hover_color=Colors.BG_HOVER,
                text_color=Colors.TEXT_SECONDARY,
                command=lambda k=key: self._select(k),
            )
            btn.pack(fill="x", padx=Layout.PAD_MD, pady=2)
            self._buttons[key] = btn

        # Set initial active state
        self._update_active_styles()

        # ── Bottom ────────────────────────────────────────────────────────────
        spacer = ctk.CTkFrame(self, fg_color="transparent")
        spacer.pack(fill="both", expand=True)

        # Divider
        ctk.CTkFrame(self, height=1, fg_color=Colors.BORDER).pack(
            fill="x", padx=Layout.PAD_LG, pady=(Layout.PAD_SM, Layout.PAD_SM),
        )

        # Version
        ctk.CTkLabel(
            self, text="v3.0.0 — Battlefield Edition", font=Fonts.TINY,
            text_color=Colors.TEXT_MUTED,
        ).pack(padx=Layout.PAD_LG, pady=(0, Layout.PAD_MD))

    # ── Internal ──────────────────────────────────────────────────────────────

    def _select(self, key: str) -> None:
        if key == self._active_tab:
            return
        self._active_tab = key
        self._update_active_styles()
        self._on_tab_change(key)

    def _update_active_styles(self) -> None:
        for key, btn in self._buttons.items():
            if key == self._active_tab:
                btn.configure(
                    fg_color=Colors.ACCENT_DIM,
                    text_color=Colors.ACCENT,
                    hover_color=Colors.ACCENT_DIM,
                )
            else:
                btn.configure(
                    fg_color="transparent",
                    text_color=Colors.TEXT_SECONDARY,
                    hover_color=Colors.BG_HOVER,
                )
