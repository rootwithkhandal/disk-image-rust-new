"""
ForgeLens GUI Utilities
=======================
Threading helpers, formatting, and dialog utilities.
"""

from __future__ import annotations

import threading
from typing import Any, Callable

import customtkinter as ctk

from frontend.theme import Colors, Fonts, Layout


# ── Threading ─────────────────────────────────────────────────────────────────


def run_in_thread(
    widget: ctk.CTkBaseClass,
    fn: Callable[[], Any],
    on_success: Callable[[Any], None] | None = None,
    on_error: Callable[[Exception], None] | None = None,
) -> None:
    """
    Run `fn` in a background thread. When finished, schedule `on_success` or
    `on_error` on the main GUI thread via `widget.after()`.

    This keeps the GUI responsive during blocking operations (device scan,
    hashing, imaging, Volatility analysis, etc.).
    """

    def _worker():
        try:
            result = fn()
            if on_success:
                widget.after(0, lambda: on_success(result))
        except Exception as exc:
            if on_error:
                widget.after(0, lambda e=exc: on_error(e))

    thread = threading.Thread(target=_worker, daemon=True)
    thread.start()


# ── Formatting ────────────────────────────────────────────────────────────────


def format_bytes(n: int | float) -> str:
    """Human-readable byte formatting."""
    if n < 0:
        return "0 B"
    for unit in ("B", "KB", "MB", "GB", "TB", "PB"):
        if abs(n) < 1024.0:
            if unit == "B":
                return f"{int(n)} {unit}"
            return f"{n:.2f} {unit}"
        n /= 1024.0
    return f"{n:.2f} EB"


def format_duration(seconds: float) -> str:
    """Human-readable duration formatting."""
    if seconds < 1:
        return f"{seconds * 1000:.0f}ms"
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes = int(seconds // 60)
    secs = int(seconds % 60)
    if minutes < 60:
        return f"{minutes}m {secs}s"
    hours = int(minutes // 60)
    mins = int(minutes % 60)
    return f"{hours}h {mins}m"


def truncate(text: str, max_len: int = 40) -> str:
    """Truncate text with ellipsis."""
    if len(text) <= max_len:
        return text
    return text[: max_len - 3] + "..."


# ── Clipboard ─────────────────────────────────────────────────────────────────


def copy_to_clipboard(widget: ctk.CTkBaseClass, text: str) -> None:
    """Copy text to the system clipboard."""
    widget.clipboard_clear()
    widget.clipboard_append(text)


# ── Dialogs ───────────────────────────────────────────────────────────────────


def show_error(parent: ctk.CTkBaseClass, title: str, message: str) -> None:
    """Show a styled error dialog."""
    dialog = ctk.CTkToplevel(parent)
    dialog.title(title)
    dialog.geometry("420x180")
    dialog.resizable(False, False)
    dialog.transient(parent)
    dialog.grab_set()
    dialog.configure(fg_color=Colors.BG_DARKEST)

    # Center on parent
    dialog.after(10, lambda: _center_dialog(dialog, parent))

    icon_label = ctk.CTkLabel(
        dialog, text="✘", font=("Segoe UI", 36), text_color=Colors.ERROR,
    )
    icon_label.pack(pady=(20, 5))

    msg_label = ctk.CTkLabel(
        dialog, text=message, font=Fonts.BODY,
        text_color=Colors.TEXT_PRIMARY, wraplength=380,
    )
    msg_label.pack(pady=5, padx=20)

    ok_btn = ctk.CTkButton(
        dialog, text="OK", width=100, height=32,
        fg_color=Colors.ERROR, hover_color=Colors.ACCENT_HOVER,
        command=dialog.destroy,
    )
    ok_btn.pack(pady=(10, 15))


def show_success(parent: ctk.CTkBaseClass, title: str, message: str) -> None:
    """Show a styled success dialog."""
    dialog = ctk.CTkToplevel(parent)
    dialog.title(title)
    dialog.geometry("420x180")
    dialog.resizable(False, False)
    dialog.transient(parent)
    dialog.grab_set()
    dialog.configure(fg_color=Colors.BG_DARKEST)

    dialog.after(10, lambda: _center_dialog(dialog, parent))

    icon_label = ctk.CTkLabel(
        dialog, text="✔", font=("Segoe UI", 36), text_color=Colors.SUCCESS,
    )
    icon_label.pack(pady=(20, 5))

    msg_label = ctk.CTkLabel(
        dialog, text=message, font=Fonts.BODY,
        text_color=Colors.TEXT_PRIMARY, wraplength=380,
    )
    msg_label.pack(pady=5, padx=20)

    ok_btn = ctk.CTkButton(
        dialog, text="OK", width=100, height=32,
        fg_color=Colors.SUCCESS, hover_color="#3edd85",
        command=dialog.destroy,
    )
    ok_btn.pack(pady=(10, 15))


def show_confirm(
    parent: ctk.CTkBaseClass, title: str, message: str,
    on_confirm: Callable[[], None] | None = None,
) -> None:
    """Show a styled confirmation dialog with Yes/No buttons."""
    dialog = ctk.CTkToplevel(parent)
    dialog.title(title)
    dialog.geometry("440x190")
    dialog.resizable(False, False)
    dialog.transient(parent)
    dialog.grab_set()
    dialog.configure(fg_color=Colors.BG_DARKEST)

    dialog.after(10, lambda: _center_dialog(dialog, parent))

    icon_label = ctk.CTkLabel(
        dialog, text="⚠", font=("Segoe UI", 32), text_color=Colors.WARNING,
    )
    icon_label.pack(pady=(20, 5))

    msg_label = ctk.CTkLabel(
        dialog, text=message, font=Fonts.BODY,
        text_color=Colors.TEXT_PRIMARY, wraplength=400,
    )
    msg_label.pack(pady=5, padx=20)

    btn_frame = ctk.CTkFrame(dialog, fg_color="transparent")
    btn_frame.pack(pady=(10, 15))

    def _yes():
        dialog.destroy()
        if on_confirm:
            on_confirm()

    ctk.CTkButton(
        btn_frame, text="Yes", width=90, height=32,
        fg_color=Colors.ACCENT, hover_color=Colors.ACCENT_HOVER,
        command=_yes,
    ).pack(side="left", padx=8)

    ctk.CTkButton(
        btn_frame, text="No", width=90, height=32,
        fg_color=Colors.BG_SURFACE, hover_color=Colors.BG_HOVER,
        command=dialog.destroy,
    ).pack(side="left", padx=8)


# ── Reusable Widgets ──────────────────────────────────────────────────────────


class StatCard(ctk.CTkFrame):
    """A dashboard stat card showing a value with a label and accent color."""

    def __init__(
        self,
        master: Any,
        title: str,
        value: str = "0",
        accent: str = Colors.ACCENT,
        icon: str = "",
        **kwargs,
    ):
        super().__init__(
            master,
            fg_color=Colors.BG_PANEL,
            corner_radius=Layout.RADIUS_LG,
            border_width=1,
            border_color=Colors.BORDER,
            **kwargs,
        )

        self._accent = accent

        # Top accent bar
        accent_bar = ctk.CTkFrame(
            self, height=3, fg_color=accent, corner_radius=0,
        )
        accent_bar.pack(fill="x", padx=1, pady=(1, 0))

        # Content
        content = ctk.CTkFrame(self, fg_color="transparent")
        content.pack(fill="both", expand=True, padx=Layout.CARD_PAD, pady=Layout.CARD_PAD)

        # Icon + Title row
        header = ctk.CTkFrame(content, fg_color="transparent")
        header.pack(fill="x")

        if icon:
            ctk.CTkLabel(
                header, text=icon, font=("Segoe UI", 16),
                text_color=accent,
            ).pack(side="left", padx=(0, 6))

        ctk.CTkLabel(
            header, text=title.upper(), font=Fonts.SMALL_BOLD,
            text_color=Colors.TEXT_SECONDARY,
        ).pack(side="left")

        # Value
        self._value_label = ctk.CTkLabel(
            content, text=value, font=("Segoe UI", 28, "bold"),
            text_color=Colors.TEXT_PRIMARY,
        )
        self._value_label.pack(anchor="w", pady=(8, 0))

    def set_value(self, value: str) -> None:
        self._value_label.configure(text=value)


class SectionHeader(ctk.CTkFrame):
    """A styled section header with title and optional action button."""

    def __init__(
        self,
        master: Any,
        title: str,
        action_text: str = "",
        action_command: Callable | None = None,
        **kwargs,
    ):
        super().__init__(master, fg_color="transparent", **kwargs)

        ctk.CTkLabel(
            self, text=title, font=Fonts.HEADING,
            text_color=Colors.TEXT_PRIMARY,
        ).pack(side="left")

        if action_text and action_command:
            ctk.CTkButton(
                self, text=action_text, width=120, height=32,
                font=Fonts.SMALL_BOLD,
                fg_color=Colors.ACCENT, hover_color=Colors.ACCENT_HOVER,
                corner_radius=Layout.RADIUS_SM,
                command=action_command,
            ).pack(side="right")


class DataTable(ctk.CTkScrollableFrame):
    """A styled scrollable data table with header row and clickable data rows."""

    def __init__(
        self,
        master: Any,
        columns: list[tuple[str, int]],
        on_row_click: Callable[[int, dict], None] | None = None,
        **kwargs,
    ):
        super().__init__(
            master,
            fg_color=Colors.BG_PANEL,
            corner_radius=Layout.RADIUS_MD,
            border_width=1,
            border_color=Colors.BORDER,
            **kwargs,
        )

        self._columns = columns
        self._on_row_click = on_row_click
        self._rows: list[dict] = []
        self._row_frames: list[ctk.CTkFrame] = []

        # Header
        header_frame = ctk.CTkFrame(self, fg_color=Colors.BG_SURFACE, height=36, corner_radius=0)
        header_frame.pack(fill="x", padx=1, pady=(1, 0))
        header_frame.pack_propagate(False)

        for i, (col_name, col_width) in enumerate(columns):
            lbl = ctk.CTkLabel(
                header_frame, text=col_name.upper(), font=Fonts.SMALL_BOLD,
                text_color=Colors.TEXT_SECONDARY, width=col_width, anchor="w",
            )
            lbl.pack(side="left", padx=(12 if i == 0 else 6, 6), pady=6)

    def set_data(self, rows: list[dict]) -> None:
        """Replace all data rows."""
        # Clear existing
        for frame in self._row_frames:
            frame.destroy()
        self._row_frames.clear()
        self._rows = rows

        for idx, row in enumerate(rows):
            bg = Colors.BG_PANEL if idx % 2 == 0 else Colors.BG_DARKEST
            row_frame = ctk.CTkFrame(self, fg_color=bg, height=Layout.ROW_HEIGHT, corner_radius=0)
            row_frame.pack(fill="x", padx=1)
            row_frame.pack_propagate(False)

            for i, (col_name, col_width) in enumerate(self._columns):
                value = str(row.get(col_name, "—"))
                text_color = Colors.TEXT_PRIMARY
                # Color code specific columns
                if col_name.lower() in ("status",):
                    text_color = self._status_color(value)
                elif col_name.lower() in ("priority",):
                    text_color = self._priority_color(value)
                elif col_name.lower() in ("verified",):
                    text_color = Colors.SUCCESS if value.lower() in ("true", "yes", "✔") else Colors.WARNING

                lbl = ctk.CTkLabel(
                    row_frame, text=truncate(value, 50), font=Fonts.SMALL,
                    text_color=text_color, width=col_width, anchor="w",
                )
                lbl.pack(side="left", padx=(12 if i == 0 else 6, 6), pady=4)

                # Clickable
                if self._on_row_click:
                    lbl.bind("<Button-1>", lambda e, r=idx: self._on_row_click(r, self._rows[r]))

            if self._on_row_click:
                row_frame.bind("<Enter>", lambda e, f=row_frame: f.configure(fg_color=Colors.BG_HOVER))
                row_frame.bind("<Leave>", lambda e, f=row_frame, b=bg: f.configure(fg_color=b))
                row_frame.bind("<Button-1>", lambda e, r=idx: self._on_row_click(r, self._rows[r]))

            self._row_frames.append(row_frame)

    @staticmethod
    def _status_color(status: str) -> str:
        s = status.lower()
        if s in ("open", "pending"):
            return Colors.STATUS_OPEN
        if s in ("active", "running", "in_progress"):
            return Colors.STATUS_ACTIVE
        if s in ("closed", "complete", "done"):
            return Colors.TEXT_SECONDARY
        if s in ("critical", "failed"):
            return Colors.STATUS_CRITICAL
        return Colors.TEXT_PRIMARY

    @staticmethod
    def _priority_color(priority: str) -> str:
        p = priority.lower()
        if p == "low":
            return Colors.PRIORITY_LOW
        if p == "medium":
            return Colors.PRIORITY_MEDIUM
        if p in ("high",):
            return Colors.PRIORITY_HIGH
        if p == "critical":
            return Colors.PRIORITY_CRITICAL
        return Colors.TEXT_PRIMARY


# ── Internal ──────────────────────────────────────────────────────────────────


def _center_dialog(dialog: ctk.CTkToplevel, parent: ctk.CTkBaseClass) -> None:
    """Center a dialog over its parent."""
    dialog.update_idletasks()
    pw = parent.winfo_width()
    ph = parent.winfo_height()
    px = parent.winfo_rootx()
    py = parent.winfo_rooty()
    dw = dialog.winfo_width()
    dh = dialog.winfo_height()
    x = px + (pw - dw) // 2
    y = py + (ph - dh) // 2
    dialog.geometry(f"+{x}+{y}")
