"""
ForgeLens Desktop Application
==============================
Main application window with sidebar navigation and tabbed content area.

Usage:
    python -m frontend.launch
    python forgelens.py gui
"""

from __future__ import annotations

import customtkinter as ctk

from frontend.theme import Colors, Layout
from frontend.components.sidebar import Sidebar
from frontend.views.dashboard import DashboardView
from frontend.views.devices import DevicesView
from frontend.views.cases import CasesView
from frontend.views.evidence import EvidenceView
from frontend.views.acquisition import AcquisitionView
from frontend.views.hashing import HashingView
from frontend.views.memory import MemoryView
from frontend.views.dfir import DFIRView


class App(ctk.CTk):
    """ForgeLens main application window."""

    APP_TITLE = "ForgeLens — DFIR Platform"

    def __init__(self):
        super().__init__()

        # ── Window Setup ──────────────────────────────────────────────────────
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self.title(self.APP_TITLE)
        self.geometry(f"{Layout.WINDOW_MIN_WIDTH}x{Layout.WINDOW_MIN_HEIGHT}")
        self.minsize(Layout.WINDOW_MIN_WIDTH, Layout.WINDOW_MIN_HEIGHT)
        self.configure(fg_color=Colors.BG_DARKEST)

        # ── Layout ────────────────────────────────────────────────────────────
        # Sidebar (left)
        self._sidebar = Sidebar(self, on_tab_change=self._switch_tab)
        self._sidebar.pack(side="left", fill="y")

        # Content area (right)
        self._content = ctk.CTkFrame(self, fg_color=Colors.BG_DARKEST, corner_radius=0)
        self._content.pack(side="right", fill="both", expand=True)

        # ── Create Views ──────────────────────────────────────────────────────
        self._views: dict[str, ctk.CTkFrame] = {}
        self._current_view: str = ""

        self._create_views()

        # ── Show Default View ─────────────────────────────────────────────────
        self._switch_tab("dashboard")

    # ── View Management ───────────────────────────────────────────────────────

    def _create_views(self):
        """Lazily instantiate all views."""
        view_classes = {
            "dashboard":   DashboardView,
            "devices":     DevicesView,
            "cases":       CasesView,
            "evidence":    EvidenceView,
            "acquisition": AcquisitionView,
            "hashing":     HashingView,
            "memory":      MemoryView,
            "dfir":        DFIRView,
        }

        try:
            from core.config import settings
            disabled_features = settings.features.disabled
        except Exception:
            disabled_features = []

        for key, cls in view_classes.items():
            if key in disabled_features:
                continue
            view = cls(self._content)
            self._views[key] = view

            # Wire up navigation callback for dashboard quick actions
            if hasattr(view, "set_navigate"):
                view.set_navigate(self._navigate_to)

    def _switch_tab(self, tab_key: str):
        """Switch the visible content view."""
        if tab_key == self._current_view:
            return

        # Hide current
        if self._current_view and self._current_view in self._views:
            self._views[self._current_view].pack_forget()

        # Show new
        if tab_key in self._views:
            self._views[tab_key].pack(fill="both", expand=True)
            self._current_view = tab_key

    def _navigate_to(self, tab_key: str):
        """Navigate to a tab (used by dashboard quick actions)."""
        self._sidebar._select(tab_key)


def main():
    """Launch the ForgeLens desktop application."""
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()
