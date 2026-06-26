"""
ForgeLens Hashing View
======================
Hash and verify files with multiple algorithms.
"""

from __future__ import annotations

from pathlib import Path
from tkinter import filedialog
from typing import Any

import customtkinter as ctk

from frontend.theme import Colors, Fonts, Icons, Layout
from frontend.utils import (
    SectionHeader, copy_to_clipboard, format_bytes, format_duration,
    run_in_thread, show_error, show_success,
)


class HashingView(ctk.CTkFrame):
    """Hash and verify files."""

    def __init__(self, master: Any, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)

        scroll = ctk.CTkScrollableFrame(self, fg_color="transparent")
        scroll.pack(fill="both", expand=True, padx=Layout.PAD_LG, pady=Layout.PAD_LG)

        # ── Header ────────────────────────────────────────────────────────────
        ctk.CTkLabel(
            scroll, text="File Hashing", font=Fonts.TITLE,
            text_color=Colors.TEXT_PRIMARY,
        ).pack(anchor="w", pady=(0, Layout.PAD_LG))

        # ── Hash Panel ────────────────────────────────────────────────────────
        hash_panel = ctk.CTkFrame(
            scroll, fg_color=Colors.BG_PANEL, corner_radius=Layout.RADIUS_LG,
            border_width=1, border_color=Colors.BORDER,
        )
        hash_panel.pack(fill="x", pady=(0, Layout.PAD_LG))

        inner = ctk.CTkFrame(hash_panel, fg_color="transparent")
        inner.pack(fill="x", padx=Layout.PAD_XL, pady=Layout.PAD_XL)

        # File selection
        file_row = ctk.CTkFrame(inner, fg_color="transparent")
        file_row.pack(fill="x", pady=(0, Layout.PAD_MD))

        ctk.CTkLabel(
            file_row, text="File:", font=Fonts.BODY_BOLD,
            text_color=Colors.TEXT_SECONDARY,
        ).pack(side="left", padx=(0, 8))

        self._file_var = ctk.StringVar()
        ctk.CTkEntry(
            file_row, textvariable=self._file_var,
            placeholder_text="Select a file to hash...",
            font=Fonts.SMALL, height=36,
            fg_color=Colors.BG_SURFACE, border_color=Colors.BORDER,
            text_color=Colors.TEXT_PRIMARY,
        ).pack(side="left", fill="x", expand=True, padx=(0, 8))

        ctk.CTkButton(
            file_row, text=f"{Icons.FOLDER}  Browse", width=100, height=36,
            font=Fonts.SMALL_BOLD,
            fg_color=Colors.BG_SURFACE, hover_color=Colors.BG_HOVER,
            text_color=Colors.TEXT_SECONDARY,
            command=self._browse_file,
        ).pack(side="right")

        # Options row
        opts_row = ctk.CTkFrame(inner, fg_color="transparent")
        opts_row.pack(fill="x", pady=(0, Layout.PAD_MD))

        ctk.CTkLabel(
            opts_row, text="Algorithm:", font=Fonts.BODY_BOLD,
            text_color=Colors.TEXT_SECONDARY,
        ).pack(side="left", padx=(0, 8))

        self._algo_var = ctk.StringVar(value="sha256")
        ctk.CTkOptionMenu(
            opts_row, variable=self._algo_var,
            values=["sha256", "md5", "sha1", "blake3"],
            width=120, height=36, font=Fonts.SMALL,
            fg_color=Colors.BG_SURFACE, button_color=Colors.BG_HOVER,
            text_color=Colors.TEXT_PRIMARY,
            dropdown_fg_color=Colors.BG_PANEL,
            dropdown_text_color=Colors.TEXT_PRIMARY,
        ).pack(side="left", padx=(0, 16))

        self._multi_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(
            opts_row, text="Multi-hash (SHA256 + MD5 + SHA1)",
            variable=self._multi_var, font=Fonts.SMALL,
            fg_color=Colors.ACCENT, hover_color=Colors.ACCENT_HOVER,
            border_color=Colors.BORDER, text_color=Colors.TEXT_SECONDARY,
        ).pack(side="left", padx=(0, 16))

        self._chunk_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(
            opts_row, text="Per-chunk hashes",
            variable=self._chunk_var, font=Fonts.SMALL,
            fg_color=Colors.ACCENT, hover_color=Colors.ACCENT_HOVER,
            border_color=Colors.BORDER, text_color=Colors.TEXT_SECONDARY,
        ).pack(side="left")

        # Hash button
        self._hash_btn = ctk.CTkButton(
            inner, text=f"{Icons.HASHING}  Hash File", font=Fonts.BODY_BOLD,
            width=160, height=44,
            fg_color=Colors.ACCENT, hover_color=Colors.ACCENT_HOVER,
            command=self._hash_file,
        )
        self._hash_btn.pack(anchor="w")

        # ── Progress ──────────────────────────────────────────────────────────
        self._progress_bar = ctk.CTkProgressBar(
            scroll, height=12,
            fg_color=Colors.BG_SURFACE, progress_color=Colors.INFO,
            corner_radius=Layout.RADIUS_SM,
        )
        self._progress_bar.pack(fill="x", pady=(0, Layout.PAD_SM))
        self._progress_bar.set(0)

        self._progress_label = ctk.CTkLabel(
            scroll, text="", font=Fonts.SMALL, text_color=Colors.TEXT_SECONDARY,
        )
        self._progress_label.pack(anchor="w", pady=(0, Layout.PAD_LG))

        # ── Hash Result ───────────────────────────────────────────────────────
        SectionHeader(scroll, title="Hash Result").pack(fill="x", pady=(0, Layout.PAD_MD))

        self._result_panel = ctk.CTkFrame(
            scroll, fg_color=Colors.BG_PANEL, corner_radius=Layout.RADIUS_LG,
            border_width=1, border_color=Colors.BORDER,
        )
        self._result_panel.pack(fill="x", pady=(0, Layout.PAD_XL))

        self._result_content = ctk.CTkLabel(
            self._result_panel, text="  No hash result yet",
            font=Fonts.SMALL, text_color=Colors.TEXT_SECONDARY,
        )
        self._result_content.pack(padx=Layout.CARD_PAD, pady=Layout.PAD_XL)

        # ── Verify Section ────────────────────────────────────────────────────
        SectionHeader(scroll, title="Verify Hash").pack(fill="x", pady=(0, Layout.PAD_MD))

        verify_panel = ctk.CTkFrame(
            scroll, fg_color=Colors.BG_PANEL, corner_radius=Layout.RADIUS_LG,
            border_width=1, border_color=Colors.BORDER,
        )
        verify_panel.pack(fill="x")

        verify_inner = ctk.CTkFrame(verify_panel, fg_color="transparent")
        verify_inner.pack(fill="x", padx=Layout.PAD_XL, pady=Layout.PAD_XL)

        ctk.CTkLabel(
            verify_inner, text="Expected Hash:", font=Fonts.BODY_BOLD,
            text_color=Colors.TEXT_SECONDARY,
        ).pack(anchor="w", pady=(0, 4))

        self._expected_var = ctk.StringVar()
        ctk.CTkEntry(
            verify_inner, textvariable=self._expected_var,
            placeholder_text="Paste expected hash digest here...",
            font=Fonts.MONO_SMALL, height=36,
            fg_color=Colors.BG_SURFACE, border_color=Colors.BORDER,
            text_color=Colors.TEXT_PRIMARY,
        ).pack(fill="x", pady=(0, Layout.PAD_MD))

        self._verify_btn = ctk.CTkButton(
            verify_inner, text=f"{Icons.CHECK}  Verify", font=Fonts.BODY_BOLD,
            width=140, height=40,
            fg_color=Colors.INFO, hover_color="#33d9ff",
            command=self._verify_hash,
        )
        self._verify_btn.pack(anchor="w")

        self._verify_label = ctk.CTkLabel(
            verify_inner, text="", font=Fonts.BODY_BOLD, text_color=Colors.TEXT_SECONDARY,
        )
        self._verify_label.pack(anchor="w", pady=(Layout.PAD_SM, 0))

    # ── Actions ───────────────────────────────────────────────────────────────

    def _browse_file(self):
        path = filedialog.askopenfilename(title="Select File to Hash")
        if path:
            self._file_var.set(path)

    def _hash_file(self):
        file_path = self._file_var.get().strip()
        if not file_path:
            show_error(self, "Validation", "Please select a file.")
            return

        if not Path(file_path).exists() and not file_path.startswith("\\\\.\\"):
            show_error(self, "Not Found", f"File not found: {file_path}")
            return

        self._hash_btn.configure(state="disabled", text="Hashing...")
        self._progress_bar.set(0)
        self._progress_label.configure(text="Hashing...", text_color=Colors.INFO)

        multi = self._multi_var.get()
        algo_str = self._algo_var.get()
        chunk_level = self._chunk_var.get()

        def _hash():
            from core.hashing.hasher import HashAlgorithm, Hasher
            if multi:
                return Hasher.hash_file_multi(
                    file_path,
                    algorithms=[HashAlgorithm.SHA256, HashAlgorithm.MD5, HashAlgorithm.SHA1],
                )
            else:
                return Hasher.hash_file(
                    file_path, HashAlgorithm(algo_str), chunk_level=chunk_level,
                )

        def _on_done(result):
            self._hash_btn.configure(state="normal", text=f"{Icons.HASHING}  Hash File")
            self._progress_bar.set(1.0)
            self._progress_label.configure(text="Complete!", text_color=Colors.SUCCESS)
            self._show_hash_result(result, multi)

        def _on_error(exc):
            self._hash_btn.configure(state="normal", text=f"{Icons.HASHING}  Hash File")
            self._progress_label.configure(text=f"Error: {exc}", text_color=Colors.ERROR)
            show_error(self, "Hash Error", str(exc))

        run_in_thread(self, _hash, on_success=_on_done, on_error=_on_error)

    def _show_hash_result(self, result, multi: bool):
        for w in self._result_panel.winfo_children():
            w.destroy()

        inner = ctk.CTkFrame(self._result_panel, fg_color="transparent")
        inner.pack(fill="x", padx=Layout.PAD_XL, pady=Layout.PAD_LG)

        if multi:
            ctk.CTkLabel(
                inner, text=f"File: {result.file_path}", font=Fonts.SMALL,
                text_color=Colors.TEXT_SECONDARY,
            ).pack(anchor="w", pady=(0, 4))
            ctk.CTkLabel(
                inner, text=f"Size: {format_bytes(result.size_bytes)} | Duration: {format_duration(result.duration_seconds)}",
                font=Fonts.SMALL, text_color=Colors.TEXT_SECONDARY,
            ).pack(anchor="w", pady=(0, 8))

            for algo, digest in result.hashes.items():
                row = ctk.CTkFrame(inner, fg_color="transparent")
                row.pack(fill="x", pady=2)

                ctk.CTkLabel(
                    row, text=f"{algo.value.upper()}:", font=Fonts.SMALL_BOLD,
                    text_color=Colors.ACCENT, width=70, anchor="w",
                ).pack(side="left")

                ctk.CTkLabel(
                    row, text=digest, font=Fonts.MONO_SMALL,
                    text_color=Colors.TEXT_PRIMARY,
                ).pack(side="left", padx=(4, 8))

                ctk.CTkButton(
                    row, text=Icons.COPY, width=28, height=24,
                    fg_color="transparent", hover_color=Colors.BG_HOVER,
                    text_color=Colors.TEXT_SECONDARY,
                    command=lambda d=digest: copy_to_clipboard(self, d),
                ).pack(side="left")
        else:
            ctk.CTkLabel(
                inner, text=f"{result.algorithm.value.upper()} Hash", font=Fonts.SUBHEADING,
                text_color=Colors.ACCENT,
            ).pack(anchor="w", pady=(0, 8))

            hash_row = ctk.CTkFrame(inner, fg_color=Colors.BG_SURFACE, corner_radius=Layout.RADIUS_SM)
            hash_row.pack(fill="x", pady=(0, 8))

            ctk.CTkLabel(
                hash_row, text=result.hex_digest, font=Fonts.MONO,
                text_color=Colors.SUCCESS,
            ).pack(side="left", padx=12, pady=10)

            ctk.CTkButton(
                hash_row, text=f"{Icons.COPY}  Copy", width=80, height=28,
                font=Fonts.SMALL, fg_color=Colors.BG_HOVER,
                hover_color=Colors.ACCENT_DIM,
                text_color=Colors.TEXT_PRIMARY,
                command=lambda: copy_to_clipboard(self, result.hex_digest),
            ).pack(side="right", padx=8, pady=6)

            ctk.CTkLabel(
                inner, text=f"Size: {format_bytes(result.size_bytes)} | Duration: {format_duration(result.duration_seconds)} | {result.throughput_mbps} MB/s",
                font=Fonts.SMALL, text_color=Colors.TEXT_SECONDARY,
            ).pack(anchor="w")

            if result.chunk_hashes:
                ctk.CTkLabel(
                    inner, text=f"Chunk hashes: {len(result.chunk_hashes)}",
                    font=Fonts.SMALL, text_color=Colors.TEXT_MUTED,
                ).pack(anchor="w", pady=(4, 0))

    def _verify_hash(self):
        file_path = self._file_var.get().strip()
        expected = self._expected_var.get().strip()

        if not file_path or not expected:
            show_error(self, "Validation", "File and expected hash are required.")
            return

        algo_str = self._algo_var.get()
        self._verify_btn.configure(state="disabled", text="Verifying...")

        def _verify():
            from core.hashing.hasher import HashAlgorithm, Hasher
            return Hasher.verify_file(file_path, HashAlgorithm(algo_str), expected)

        def _on_done(match):
            self._verify_btn.configure(state="normal", text=f"{Icons.CHECK}  Verify")
            if match:
                self._verify_label.configure(
                    text=f"{Icons.CHECK}  VERIFIED — {algo_str.upper()} hash matches!",
                    text_color=Colors.SUCCESS,
                )
            else:
                self._verify_label.configure(
                    text=f"{Icons.CROSS}  MISMATCH — hash does not match!",
                    text_color=Colors.ERROR,
                )

        def _on_error(exc):
            self._verify_btn.configure(state="normal", text=f"{Icons.CHECK}  Verify")
            self._verify_label.configure(text=f"Error: {exc}", text_color=Colors.ERROR)

        run_in_thread(self, _verify, on_success=_on_done, on_error=_on_error)
