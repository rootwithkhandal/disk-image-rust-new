"""
ForgeLens Devices View
======================
Scan and display connected storage and mobile devices.
"""

from __future__ import annotations

from typing import Any

import customtkinter as ctk

from frontend.theme import Colors, Fonts, Icons, Layout
from frontend.utils import DataTable, SectionHeader, run_in_thread, show_error


class DevicesView(ctk.CTkFrame):
    """Device scanner view."""

    def __init__(self, master: Any, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)

        content = ctk.CTkFrame(self, fg_color="transparent")
        content.pack(fill="both", expand=True, padx=Layout.PAD_LG, pady=Layout.PAD_LG)

        # ── Header ────────────────────────────────────────────────────────────
        header = ctk.CTkFrame(content, fg_color="transparent")
        header.pack(fill="x", pady=(0, Layout.PAD_LG))

        ctk.CTkLabel(
            header, text="Devices", font=Fonts.TITLE,
            text_color=Colors.TEXT_PRIMARY,
        ).pack(side="left")

        # Android toggle
        self._android_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(
            header, text="Include Android (ADB)", font=Fonts.SMALL,
            variable=self._android_var,
            fg_color=Colors.ACCENT, hover_color=Colors.ACCENT_HOVER,
            border_color=Colors.BORDER,
            text_color=Colors.TEXT_SECONDARY,
        ).pack(side="right", padx=(0, 12))

        self._scan_btn = ctk.CTkButton(
            header, text=f"{Icons.REFRESH}  Scan Devices", font=Fonts.BODY_BOLD,
            width=160, height=36,
            fg_color=Colors.ACCENT, hover_color=Colors.ACCENT_HOVER,
            command=self._scan,
        )
        self._scan_btn.pack(side="right")

        # ── Status ────────────────────────────────────────────────────────────
        self._status = ctk.CTkLabel(
            content, text="Click 'Scan Devices' to detect connected devices",
            font=Fonts.SMALL, text_color=Colors.TEXT_SECONDARY,
        )
        self._status.pack(anchor="w", pady=(0, Layout.PAD_SM))

        # ── Device Table ──────────────────────────────────────────────────────
        columns = [
            ("Device ID", 200),
            ("Type", 90),
            ("Model", 200),
            ("Size (GB)", 90),
            ("Interface", 90),
            ("Serial", 140),
            ("Removable", 80),
        ]

        self._table = DataTable(
            content, columns=columns, on_row_click=self._on_device_click,
        )
        self._table.pack(fill="both", expand=True)

        # ── Detail Panel ──────────────────────────────────────────────────────
        self._detail_frame = ctk.CTkFrame(
            content, fg_color=Colors.BG_PANEL, corner_radius=Layout.RADIUS_LG,
            border_width=1, border_color=Colors.BORDER, height=120,
        )
        self._detail_frame.pack(fill="x", pady=(Layout.PAD_MD, 0))
        self._detail_frame.pack_propagate(False)

        self._detail_label = ctk.CTkLabel(
            self._detail_frame,
            text="  Select a device to view details",
            font=Fonts.SMALL, text_color=Colors.TEXT_SECONDARY,
        )
        self._detail_label.pack(padx=Layout.CARD_PAD, pady=Layout.PAD_LG)

    # ── Scanning ──────────────────────────────────────────────────────────────

    def _scan(self):
        self._scan_btn.configure(state="disabled", text="Scanning...")
        self._status.configure(text="Scanning for devices...", text_color=Colors.INFO)

        def _detect():
            from core.acquisition.device_detector import DeviceDetector
            devices = DeviceDetector.detect()
            if self._android_var.get():
                try:
                    devices += DeviceDetector.detect_android()
                except Exception:
                    pass
            return devices

        def _on_done(devices):
            self._scan_btn.configure(state="normal", text=f"{Icons.REFRESH}  Scan Devices")
            rows = []
            for d in devices:
                rows.append({
                    "Device ID": d.device_id,
                    "Type": d.device_type.value.upper(),
                    "Model": d.model or d.label or "—",
                    "Size (GB)": str(d.size_gb),
                    "Interface": d.interface or "—",
                    "Serial": d.serial or "—",
                    "Removable": "Yes" if d.is_removable else "No",
                })
            self._table.set_data(rows)
            count = len(devices)
            self._status.configure(
                text=f"Found {count} device(s)" if count > 0 else "No devices found",
                text_color=Colors.SUCCESS if count > 0 else Colors.WARNING,
            )

        def _on_error(exc):
            self._scan_btn.configure(state="normal", text=f"{Icons.REFRESH}  Scan Devices")
            self._status.configure(text=f"Error: {exc}", text_color=Colors.ERROR)
            show_error(self, "Scan Error", str(exc))

        run_in_thread(self, _detect, on_success=_on_done, on_error=_on_error)

    def _on_device_click(self, idx: int, row: dict):
        # Clear detail panel
        for w in self._detail_frame.winfo_children():
            w.destroy()

        detail_content = ctk.CTkFrame(self._detail_frame, fg_color="transparent")
        detail_content.pack(fill="both", expand=True, padx=Layout.CARD_PAD, pady=Layout.PAD_MD)

        ctk.CTkLabel(
            detail_content, text=f"Device Details — {row.get('Device ID', '')}",
            font=Fonts.SUBHEADING, text_color=Colors.ACCENT,
        ).pack(anchor="w")

        info_row = ctk.CTkFrame(detail_content, fg_color="transparent")
        info_row.pack(fill="x", pady=(8, 0))

        for label, key in [("Type", "Type"), ("Model", "Model"), ("Size", "Size (GB)"),
                           ("Interface", "Interface"), ("Serial", "Serial")]:
            ctk.CTkLabel(
                info_row, text=f"{label}: ", font=Fonts.SMALL_BOLD,
                text_color=Colors.TEXT_SECONDARY,
            ).pack(side="left")
            ctk.CTkLabel(
                info_row, text=row.get(key, "—"), font=Fonts.SMALL,
                text_color=Colors.TEXT_PRIMARY,
            ).pack(side="left", padx=(0, 16))
