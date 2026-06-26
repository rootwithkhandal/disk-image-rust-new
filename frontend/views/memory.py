"""
ForgeLens Memory View
=====================
Volatility3 memory forensics — process listing, DLLs, connections, malfind.
"""

from __future__ import annotations

from tkinter import filedialog
from typing import Any

import customtkinter as ctk

from frontend.theme import Colors, Fonts, Icons, Layout
from frontend.utils import DataTable, SectionHeader, run_in_thread, show_error


class MemoryView(ctk.CTkFrame):
    """Memory forensics view."""

    PLUGINS = {
        "processes": "Process List",
        "pstree": "Process Tree",
        "dlls": "DLL List",
        "connections": "Network Connections",
        "malfind": "Injected Code (Malfind)",
        "hashes": "NTLM Hashes",
        "timeline": "Memory Timeline",
    }

    def __init__(self, master: Any, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)

        content = ctk.CTkFrame(self, fg_color="transparent")
        content.pack(fill="both", expand=True, padx=Layout.PAD_LG, pady=Layout.PAD_LG)

        # ── Header ────────────────────────────────────────────────────────────
        ctk.CTkLabel(
            content, text="Memory Forensics", font=Fonts.TITLE,
            text_color=Colors.TEXT_PRIMARY,
        ).pack(anchor="w", pady=(0, Layout.PAD_LG))

        # ── Config Panel ─────────────────────────────────────────────────────
        config_panel = ctk.CTkFrame(
            content, fg_color=Colors.BG_PANEL, corner_radius=Layout.RADIUS_LG,
            border_width=1, border_color=Colors.BORDER,
        )
        config_panel.pack(fill="x", pady=(0, Layout.PAD_LG))

        config_inner = ctk.CTkFrame(config_panel, fg_color="transparent")
        config_inner.pack(fill="x", padx=Layout.PAD_XL, pady=Layout.PAD_XL)

        # Dump file
        file_row = ctk.CTkFrame(config_inner, fg_color="transparent")
        file_row.pack(fill="x", pady=(0, Layout.PAD_MD))

        ctk.CTkLabel(
            file_row, text="Memory Dump:", font=Fonts.BODY_BOLD,
            text_color=Colors.TEXT_SECONDARY,
        ).pack(side="left", padx=(0, 8))

        self._dump_var = ctk.StringVar()
        ctk.CTkEntry(
            file_row, textvariable=self._dump_var,
            placeholder_text="Path to memory dump (.raw, .vmem, .dmp)",
            font=Fonts.SMALL, height=36,
            fg_color=Colors.BG_SURFACE, border_color=Colors.BORDER,
            text_color=Colors.TEXT_PRIMARY,
        ).pack(side="left", fill="x", expand=True, padx=(0, 8))

        ctk.CTkButton(
            file_row, text=f"{Icons.FOLDER}  Browse", width=100, height=36,
            font=Fonts.SMALL_BOLD,
            fg_color=Colors.BG_SURFACE, hover_color=Colors.BG_HOVER,
            text_color=Colors.TEXT_SECONDARY,
            command=self._browse_dump,
        ).pack(side="right")

        # Plugin + Analyze
        opts_row = ctk.CTkFrame(config_inner, fg_color="transparent")
        opts_row.pack(fill="x")

        ctk.CTkLabel(
            opts_row, text="Plugin:", font=Fonts.BODY_BOLD,
            text_color=Colors.TEXT_SECONDARY,
        ).pack(side="left", padx=(0, 8))

        self._plugin_var = ctk.StringVar(value="processes")
        ctk.CTkOptionMenu(
            opts_row, variable=self._plugin_var,
            values=list(self.PLUGINS.keys()),
            width=180, height=36, font=Fonts.SMALL,
            fg_color=Colors.BG_SURFACE, button_color=Colors.BG_HOVER,
            text_color=Colors.TEXT_PRIMARY,
            dropdown_fg_color=Colors.BG_PANEL,
            dropdown_text_color=Colors.TEXT_PRIMARY,
        ).pack(side="left", padx=(0, 16))

        self._analyze_btn = ctk.CTkButton(
            opts_row, text=f"{Icons.PLAY}  Analyze", font=Fonts.BODY_BOLD,
            width=140, height=40,
            fg_color=Colors.ACCENT, hover_color=Colors.ACCENT_HOVER,
            command=self._analyze,
        )
        self._analyze_btn.pack(side="left")

        # ── Status ────────────────────────────────────────────────────────────
        self._status = ctk.CTkLabel(
            content, text="Select a memory dump and plugin, then click Analyze",
            font=Fonts.SMALL, text_color=Colors.TEXT_SECONDARY,
        )
        self._status.pack(anchor="w", pady=(0, Layout.PAD_SM))

        # ── Results ───────────────────────────────────────────────────────────
        SectionHeader(content, title="Results").pack(fill="x", pady=(0, Layout.PAD_MD))

        self._results_frame = ctk.CTkScrollableFrame(
            content, fg_color=Colors.BG_PANEL, corner_radius=Layout.RADIUS_LG,
            border_width=1, border_color=Colors.BORDER,
        )
        self._results_frame.pack(fill="both", expand=True)

        self._results_placeholder = ctk.CTkLabel(
            self._results_frame, text="  No results yet — run an analysis",
            font=Fonts.SMALL, text_color=Colors.TEXT_SECONDARY,
        )
        self._results_placeholder.pack(padx=Layout.CARD_PAD, pady=Layout.PAD_XL)

    # ── Actions ───────────────────────────────────────────────────────────────

    def _browse_dump(self):
        path = filedialog.askopenfilename(
            title="Select Memory Dump",
            filetypes=[("Memory dumps", "*.raw *.vmem *.dmp *.mem"), ("All files", "*.*")],
        )
        if path:
            self._dump_var.set(path)

    def _analyze(self):
        dump_path = self._dump_var.get().strip()
        plugin = self._plugin_var.get()

        if not dump_path:
            show_error(self, "Validation", "Please select a memory dump file.")
            return

        self._analyze_btn.configure(state="disabled", text="Analyzing...")
        self._status.configure(
            text=f"Running {self.PLUGINS[plugin]}... (this may take a few minutes)",
            text_color=Colors.INFO,
        )

        def _run():
            from core.memory.volatility_engine import VolatilityEngine
            engine = VolatilityEngine()

            plugin_map = {
                "processes": engine.list_processes,
                "pstree": engine.list_processes,   # Uses same underlying plugin
                "dlls": engine.list_dlls,
                "connections": engine.list_connections,
                "malfind": engine.detect_malfind,
                "hashes": engine.extract_hashes,
                "timeline": engine.build_timeline,
            }

            fn = plugin_map.get(plugin, engine.list_processes)
            return fn(dump_path)

        def _on_done(results):
            self._analyze_btn.configure(state="normal", text=f"{Icons.PLAY}  Analyze")
            self._status.configure(
                text=f"{self.PLUGINS[plugin]}: {len(results)} result(s)",
                text_color=Colors.SUCCESS,
            )
            self._display_results(results, plugin)

        def _on_error(exc):
            self._analyze_btn.configure(state="normal", text=f"{Icons.PLAY}  Analyze")
            self._status.configure(text=f"Error: {exc}", text_color=Colors.ERROR)

        run_in_thread(self, _run, on_success=_on_done, on_error=_on_error)

    def _display_results(self, results: list, plugin: str):
        # Clear
        for w in self._results_frame.winfo_children():
            w.destroy()

        if not results:
            ctk.CTkLabel(
                self._results_frame, text="  No results returned",
                font=Fonts.SMALL, text_color=Colors.TEXT_SECONDARY,
            ).pack(padx=Layout.CARD_PAD, pady=Layout.PAD_XL)
            return

        # Display as rows
        for i, item in enumerate(results):
            if isinstance(item, dict):
                is_suspicious = item.get("_suspicious", False)
                bg = Colors.ACCENT_DIM if is_suspicious else (
                    Colors.BG_SURFACE if i % 2 == 0 else Colors.BG_PANEL
                )

                row = ctk.CTkFrame(self._results_frame, fg_color=bg, corner_radius=0)
                row.pack(fill="x", padx=2, pady=1)

                text_parts = []
                for key, val in item.items():
                    if not key.startswith("_"):
                        text_parts.append(f"{key}: {val}")

                text = "  |  ".join(text_parts[:6])

                label_color = Colors.ACCENT if is_suspicious else Colors.TEXT_PRIMARY
                ctk.CTkLabel(
                    row, text=text, font=Fonts.MONO_SMALL,
                    text_color=label_color, anchor="w",
                ).pack(fill="x", padx=Layout.PAD_SM, pady=4)

                if is_suspicious:
                    reasons = item.get("_suspicious_reasons", [])
                    if reasons:
                        ctk.CTkLabel(
                            row, text=f"  ⚠ {', '.join(reasons)}",
                            font=Fonts.TINY, text_color=Colors.WARNING, anchor="w",
                        ).pack(fill="x", padx=Layout.PAD_SM, pady=(0, 4))
            else:
                row = ctk.CTkFrame(
                    self._results_frame,
                    fg_color=Colors.BG_SURFACE if i % 2 == 0 else Colors.BG_PANEL,
                    corner_radius=0,
                )
                row.pack(fill="x", padx=2, pady=1)
                ctk.CTkLabel(
                    row, text=str(item), font=Fonts.MONO_SMALL,
                    text_color=Colors.TEXT_PRIMARY, anchor="w",
                ).pack(fill="x", padx=Layout.PAD_SM, pady=4)
