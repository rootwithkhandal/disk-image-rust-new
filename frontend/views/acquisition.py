"""
ForgeLens Acquisition View
==========================
Configure and run forensic disk imaging with live progress tracking.
"""

from __future__ import annotations

import threading
from pathlib import Path
from tkinter import filedialog
from typing import Any

import customtkinter as ctk

from frontend.theme import Colors, Fonts, Icons, Layout
from frontend.utils import (
    SectionHeader, format_bytes, format_duration, run_in_thread,
    show_confirm, show_error, show_success,
)


class AcquisitionView(ctk.CTkFrame):
    """Forensic acquisition view with live progress."""

    def __init__(self, master: Any, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)

        self._imager = None
        self._acq_thread: threading.Thread | None = None
        self._polling = False

        scroll = ctk.CTkScrollableFrame(self, fg_color="transparent")
        scroll.pack(fill="both", expand=True, padx=Layout.PAD_LG, pady=Layout.PAD_LG)

        # ── Header ────────────────────────────────────────────────────────────
        ctk.CTkLabel(
            scroll, text="Disk Acquisition", font=Fonts.TITLE,
            text_color=Colors.TEXT_PRIMARY,
        ).pack(anchor="w", pady=(0, Layout.PAD_LG))

        # ── Configuration Panel ───────────────────────────────────────────────
        config_panel = ctk.CTkFrame(
            scroll, fg_color=Colors.BG_PANEL, corner_radius=Layout.RADIUS_LG,
            border_width=1, border_color=Colors.BORDER,
        )
        config_panel.pack(fill="x", pady=(0, Layout.PAD_LG))

        config_inner = ctk.CTkFrame(config_panel, fg_color="transparent")
        config_inner.pack(fill="x", padx=Layout.PAD_XL, pady=Layout.PAD_XL)

        # Row 1: Source + Output
        row1 = ctk.CTkFrame(config_inner, fg_color="transparent")
        row1.pack(fill="x", pady=(0, Layout.PAD_MD))
        row1.columnconfigure(1, weight=1)
        row1.columnconfigure(3, weight=1)

        ctk.CTkLabel(row1, text="Source:", font=Fonts.BODY_BOLD, text_color=Colors.TEXT_SECONDARY).grid(row=0, column=0, sticky="w", padx=(0, 8))
        self._source_var = ctk.StringVar()
        ctk.CTkEntry(
            row1, textvariable=self._source_var, placeholder_text=r"e.g. \\.\PhysicalDrive0 or /dev/sda",
            font=Fonts.MONO_SMALL, height=36,
            fg_color=Colors.BG_SURFACE, border_color=Colors.BORDER, text_color=Colors.TEXT_PRIMARY,
        ).grid(row=0, column=1, sticky="ew", padx=(0, 16))

        ctk.CTkLabel(row1, text="Output:", font=Fonts.BODY_BOLD, text_color=Colors.TEXT_SECONDARY).grid(row=0, column=2, sticky="w", padx=(0, 8))
        self._output_var = ctk.StringVar()
        out_entry = ctk.CTkEntry(
            row1, textvariable=self._output_var, placeholder_text="Output directory",
            font=Fonts.SMALL, height=36,
            fg_color=Colors.BG_SURFACE, border_color=Colors.BORDER, text_color=Colors.TEXT_PRIMARY,
        )
        out_entry.grid(row=0, column=3, sticky="ew", padx=(0, 8))

        ctk.CTkButton(
            row1, text=Icons.FOLDER, width=36, height=36,
            fg_color=Colors.BG_SURFACE, hover_color=Colors.BG_HOVER,
            text_color=Colors.TEXT_SECONDARY,
            command=self._browse_output,
        ).grid(row=0, column=4)

        # Row 2: Case, Examiner, Format
        row2 = ctk.CTkFrame(config_inner, fg_color="transparent")
        row2.pack(fill="x", pady=(0, Layout.PAD_MD))
        row2.columnconfigure((1, 3), weight=1)

        ctk.CTkLabel(row2, text="Case ID:", font=Fonts.BODY_BOLD, text_color=Colors.TEXT_SECONDARY).grid(row=0, column=0, sticky="w", padx=(0, 8))
        self._case_var = ctk.StringVar()
        ctk.CTkEntry(
            row2, textvariable=self._case_var, placeholder_text="CASE-2026-001",
            font=Fonts.SMALL, height=36,
            fg_color=Colors.BG_SURFACE, border_color=Colors.BORDER, text_color=Colors.TEXT_PRIMARY,
        ).grid(row=0, column=1, sticky="ew", padx=(0, 16))

        ctk.CTkLabel(row2, text="Examiner:", font=Fonts.BODY_BOLD, text_color=Colors.TEXT_SECONDARY).grid(row=0, column=2, sticky="w", padx=(0, 8))
        self._examiner_var = ctk.StringVar()
        ctk.CTkEntry(
            row2, textvariable=self._examiner_var, placeholder_text="Your name",
            font=Fonts.SMALL, height=36,
            fg_color=Colors.BG_SURFACE, border_color=Colors.BORDER, text_color=Colors.TEXT_PRIMARY,
        ).grid(row=0, column=3, sticky="ew", padx=(0, 16))

        ctk.CTkLabel(row2, text="Format:", font=Fonts.BODY_BOLD, text_color=Colors.TEXT_SECONDARY).grid(row=0, column=4, sticky="w", padx=(0, 8))
        self._format_var = ctk.StringVar(value="dd")
        ctk.CTkOptionMenu(
            row2, variable=self._format_var, values=["dd", "e01"],
            width=80, height=36, font=Fonts.SMALL,
            fg_color=Colors.BG_SURFACE, button_color=Colors.BG_HOVER,
            text_color=Colors.TEXT_PRIMARY,
            dropdown_fg_color=Colors.BG_PANEL,
            dropdown_text_color=Colors.TEXT_PRIMARY,
        ).grid(row=0, column=5)

        # Row 3: Block size, Verify, Notes
        row3 = ctk.CTkFrame(config_inner, fg_color="transparent")
        row3.pack(fill="x")

        ctk.CTkLabel(row3, text="Block Size:", font=Fonts.BODY_BOLD, text_color=Colors.TEXT_SECONDARY).pack(side="left", padx=(0, 8))
        self._block_var = ctk.StringVar(value="65536")
        ctk.CTkEntry(
            row3, textvariable=self._block_var, width=100, height=36,
            font=Fonts.MONO_SMALL,
            fg_color=Colors.BG_SURFACE, border_color=Colors.BORDER, text_color=Colors.TEXT_PRIMARY,
        ).pack(side="left", padx=(0, 16))

        self._verify_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(
            row3, text="Post-verify", variable=self._verify_var,
            font=Fonts.SMALL, fg_color=Colors.ACCENT,
            hover_color=Colors.ACCENT_HOVER, border_color=Colors.BORDER,
            text_color=Colors.TEXT_SECONDARY,
        ).pack(side="left", padx=(0, 16))

        ctk.CTkLabel(row3, text="Notes:", font=Fonts.BODY_BOLD, text_color=Colors.TEXT_SECONDARY).pack(side="left", padx=(0, 8))
        self._notes_var = ctk.StringVar()
        ctk.CTkEntry(
            row3, textvariable=self._notes_var, placeholder_text="Acquisition notes (optional)",
            font=Fonts.SMALL, height=36,
            fg_color=Colors.BG_SURFACE, border_color=Colors.BORDER, text_color=Colors.TEXT_PRIMARY,
        ).pack(side="left", fill="x", expand=True)

        # ── Action Buttons ────────────────────────────────────────────────────
        btn_frame = ctk.CTkFrame(scroll, fg_color="transparent")
        btn_frame.pack(fill="x", pady=(0, Layout.PAD_LG))

        self._start_btn = ctk.CTkButton(
            btn_frame, text=f"{Icons.PLAY}  Start Acquisition", font=Fonts.BODY_BOLD,
            width=200, height=44,
            fg_color=Colors.ACCENT, hover_color=Colors.ACCENT_HOVER,
            command=self._start_acquisition,
        )
        self._start_btn.pack(side="left")

        self._pause_btn = ctk.CTkButton(
            btn_frame, text=f"{Icons.PAUSE}  Pause", font=Fonts.BODY,
            width=100, height=44,
            fg_color=Colors.WARNING, hover_color="#f5b041",
            command=self._pause, state="disabled",
        )
        self._pause_btn.pack(side="left", padx=(12, 0))

        self._cancel_btn = ctk.CTkButton(
            btn_frame, text=f"{Icons.STOP}  Cancel", font=Fonts.BODY,
            width=100, height=44,
            fg_color=Colors.ERROR, hover_color="#ec7063",
            command=self._cancel, state="disabled",
        )
        self._cancel_btn.pack(side="left", padx=(8, 0))

        # ── Progress Panel ────────────────────────────────────────────────────
        SectionHeader(scroll, title="Progress").pack(fill="x", pady=(0, Layout.PAD_MD))

        progress_panel = ctk.CTkFrame(
            scroll, fg_color=Colors.BG_PANEL, corner_radius=Layout.RADIUS_LG,
            border_width=1, border_color=Colors.BORDER,
        )
        progress_panel.pack(fill="x", pady=(0, Layout.PAD_LG))

        progress_inner = ctk.CTkFrame(progress_panel, fg_color="transparent")
        progress_inner.pack(fill="x", padx=Layout.PAD_XL, pady=Layout.PAD_XL)

        # Progress bar
        self._progress_bar = ctk.CTkProgressBar(
            progress_inner, height=Layout.PROGRESS_HEIGHT,
            fg_color=Colors.BG_SURFACE, progress_color=Colors.ACCENT,
            corner_radius=Layout.RADIUS_SM,
        )
        self._progress_bar.pack(fill="x", pady=(0, Layout.PAD_SM))
        self._progress_bar.set(0)

        # Progress text
        self._progress_label = ctk.CTkLabel(
            progress_inner, text="Idle — ready for acquisition",
            font=Fonts.BODY, text_color=Colors.TEXT_SECONDARY,
        )
        self._progress_label.pack(anchor="w", pady=(0, Layout.PAD_MD))

        # Stats grid
        stats = ctk.CTkFrame(progress_inner, fg_color="transparent")
        stats.pack(fill="x")
        stats.columnconfigure((0, 1, 2, 3), weight=1)

        self._stat_labels = {}
        for col, (key, label) in enumerate([
            ("bytes", "Bytes Read"), ("throughput", "Throughput"),
            ("eta", "ETA"), ("state", "State"),
        ]):
            frame = ctk.CTkFrame(stats, fg_color=Colors.BG_SURFACE, corner_radius=Layout.RADIUS_SM)
            frame.grid(row=0, column=col, padx=4, sticky="ew")

            ctk.CTkLabel(
                frame, text=label.upper(), font=Fonts.TINY,
                text_color=Colors.TEXT_MUTED,
            ).pack(padx=12, pady=(8, 2))

            val_label = ctk.CTkLabel(
                frame, text="—", font=Fonts.BODY_BOLD,
                text_color=Colors.TEXT_PRIMARY,
            )
            val_label.pack(padx=12, pady=(0, 8))
            self._stat_labels[key] = val_label

        # ── Result Panel ──────────────────────────────────────────────────────
        SectionHeader(scroll, title="Result").pack(fill="x", pady=(0, Layout.PAD_MD))

        self._result_panel = ctk.CTkFrame(
            scroll, fg_color=Colors.BG_PANEL, corner_radius=Layout.RADIUS_LG,
            border_width=1, border_color=Colors.BORDER,
        )
        self._result_panel.pack(fill="x")

        self._result_label = ctk.CTkLabel(
            self._result_panel, text="  No acquisition result yet",
            font=Fonts.SMALL, text_color=Colors.TEXT_SECONDARY,
        )
        self._result_label.pack(padx=Layout.CARD_PAD, pady=Layout.PAD_XL)

    # ── Actions ───────────────────────────────────────────────────────────────

    def _browse_output(self):
        path = filedialog.askdirectory(title="Select Output Directory")
        if path:
            self._output_var.set(path)

    def _start_acquisition(self):
        source = self._source_var.get().strip()
        output = self._output_var.get().strip()
        case_id = self._case_var.get().strip()
        examiner = self._examiner_var.get().strip()

        if not all([source, output, case_id, examiner]):
            show_error(self, "Validation", "Source, Output, Case ID, and Examiner are required.")
            return

        try:
            block_size = int(self._block_var.get())
        except ValueError:
            show_error(self, "Validation", "Block size must be a number.")
            return

        def _do_start():
            self._start_btn.configure(state="disabled")
            self._cancel_btn.configure(state="normal")

            # Check if this is an Android device serial
            from core.acquisition.device_detector import DeviceDetector
            is_android = False
            try:
                android_devs = DeviceDetector.detect_android()
                if any(d.serial.lower() == source.lower() or d.device_id.lower() == source.lower() for d in android_devs):
                    is_android = True
            except Exception:
                pass

            if not is_android:
                import os
                import re
                is_disk_path = source.startswith(("\\\\.\\", "/dev/")) or re.match(r"^[a-zA-Z]:\\", source)
                if not is_disk_path and not os.path.exists(source) and re.match(r"^[a-zA-Z0-9_-]+$", source):
                    is_android = True

            if is_android:
                self._pause_btn.configure(state="disabled")
                self._imager = AndroidImagerAdapter()
            else:
                self._pause_btn.configure(state="normal")
                from core.imaging.imager import DiskImager, ImageFormat
                self._imager = DiskImager()
                fmt = ImageFormat(self._format_var.get())

            self._polling = True
            self._poll_progress()

            def _acquire():
                if is_android:
                    return self._imager.acquire(
                        source=source,
                        output_dir=output,
                        case_id=case_id,
                        examiner=examiner,
                        notes=self._notes_var.get().strip(),
                    )
                else:
                    return self._imager.acquire(
                        source=source,
                        output_dir=output,
                        case_id=case_id,
                        examiner=examiner,
                        image_format=fmt,
                        block_size=block_size,
                        notes=self._notes_var.get().strip(),
                        post_verify=self._verify_var.get(),
                    )

            def _on_done(result):
                self._polling = False
                self._start_btn.configure(state="normal")
                self._pause_btn.configure(state="disabled")
                self._cancel_btn.configure(state="disabled")

                if result.success:
                    self._progress_bar.set(1.0)
                    self._progress_label.configure(
                        text="Acquisition complete!", text_color=Colors.SUCCESS,
                    )
                    self._show_result(result)
                else:
                    self._progress_label.configure(
                        text=f"Failed: {result.error}", text_color=Colors.ERROR,
                    )

            def _on_error(exc):
                self._polling = False
                self._start_btn.configure(state="normal")
                self._pause_btn.configure(state="disabled")
                self._cancel_btn.configure(state="disabled")
                self._progress_label.configure(
                    text=f"Error: {exc}", text_color=Colors.ERROR,
                )

            run_in_thread(self, _acquire, on_success=_on_done, on_error=_on_error)

        show_confirm(self, "Start Acquisition",
                     f"Acquire from {source} to {output}?", on_confirm=_do_start)

    def _pause(self):
        if self._imager:
            if self._imager._state.value == "paused":
                self._imager.resume()
                self._pause_btn.configure(text=f"{Icons.PAUSE}  Pause")
            else:
                self._imager.pause()
                self._pause_btn.configure(text=f"{Icons.PLAY}  Resume")

    def _cancel(self):
        if self._imager:
            show_confirm(self, "Cancel", "Cancel the running acquisition?",
                         on_confirm=self._imager.cancel)

    # ── Progress Polling ──────────────────────────────────────────────────────

    def _poll_progress(self):
        if not self._polling or not self._imager:
            return

        prog = self._imager.progress
        pct = prog.percent / 100.0

        self._progress_bar.set(pct)
        status_info = getattr(prog, "status_text", prog.state.value)
        self._progress_label.configure(
            text=f"{prog.percent:.1f}% \u2014 {status_info}",
            text_color=Colors.INFO,
        )

        self._stat_labels["bytes"].configure(
            text=f"{format_bytes(prog.bytes_read)} / {format_bytes(prog.total_bytes)}" if prog.total_bytes > 0 else f"{format_bytes(prog.bytes_read)}",
        )
        self._stat_labels["throughput"].configure(
            text=f"{prog.throughput_mbps} MB/s" if prog.throughput_mbps > 0 else "\u2014",
        )
        self._stat_labels["eta"].configure(
            text=format_duration(prog.eta_seconds) if prog.eta_seconds > 0 else "\u2014",
        )
        self._stat_labels["state"].configure(
            text=prog.state.value.upper(),
            text_color=Colors.SUCCESS if prog.state.value in ("running", "complete") else Colors.WARNING,
        )

        self.after(250, self._poll_progress)

    # ── Result Display ────────────────────────────────────────────────────────

    def _show_result(self, result):
        for w in self._result_panel.winfo_children():
            w.destroy()

        inner = ctk.CTkFrame(self._result_panel, fg_color="transparent")
        inner.pack(fill="x", padx=Layout.PAD_XL, pady=Layout.PAD_LG)

        status_color = Colors.SUCCESS if result.success else Colors.ERROR
        status_text = "\u2714  ACQUISITION COMPLETE" if result.success else "\u2718  ACQUISITION FAILED"

        ctk.CTkLabel(
            inner, text=status_text, font=Fonts.HEADING,
            text_color=status_color,
        ).pack(anchor="w", pady=(0, Layout.PAD_MD))

        details = [
            ("Evidence ID", result.evidence_id),
            ("Case ID", result.case_id),
            ("Image Path", result.image_path),
            ("Size", format_bytes(result.bytes_acquired)),
            ("Duration", format_duration(result.duration_seconds)),
            ("Verified", "PASS" if result.verified else "FAIL"),
        ]

        # ── Write-protect badge ───────────────────────────────────────────────
        wp_raw = getattr(result, "write_protect_status", "UNKNOWN")
        wp_map = {
            "CONFIRMED_RO": ("🛡  Write-Protect CONFIRMED",  Colors.SUCCESS),
            "CONFIRMED_RW": ("⚠  Write-Protect NOT SET",     Colors.ERROR),
            "UNKNOWN":      ("?  Write-Protect INCONCLUSIVE", Colors.TEXT_MUTED),
        }
        wp_text, wp_color = wp_map.get(wp_raw, wp_map["UNKNOWN"])
        wp_badge = ctk.CTkFrame(
            inner, fg_color=Colors.BG_SURFACE, corner_radius=Layout.RADIUS_SM,
        )
        wp_badge.pack(fill="x", pady=(0, Layout.PAD_MD))
        ctk.CTkLabel(
            wp_badge, text=wp_text, font=Fonts.SMALL_BOLD,
            text_color=wp_color,
        ).pack(side="left", padx=12, pady=6)

        for label, value in details:
            row = ctk.CTkFrame(inner, fg_color="transparent")
            row.pack(fill="x", pady=1)

            ctk.CTkLabel(
                row, text=f"{label}:", font=Fonts.SMALL_BOLD,
                text_color=Colors.TEXT_SECONDARY, width=100, anchor="w",
            ).pack(side="left")

            val_color = Colors.TEXT_PRIMARY
            if label == "Verified":
                val_color = Colors.SUCCESS if value == "PASS" else Colors.ERROR

            ctk.CTkLabel(
                row, text=value, font=Fonts.MONO_SMALL if label in ("SHA256", "MD5", "SHA1") else Fonts.SMALL,
                text_color=val_color, anchor="w",
            ).pack(side="left", padx=(8, 0))

        # ── Post-Acquisition Image Hash Section ─────────────────────────────────
        post_sha256 = getattr(result, "hash_sha256", "")
        post_md5    = getattr(result, "hash_md5", "")
        post_sha1   = getattr(result, "hash_sha1", "")

        if post_sha256 or post_md5 or post_sha1:
            post_frame = ctk.CTkFrame(
                inner, fg_color=Colors.BG_SURFACE, corner_radius=Layout.RADIUS_SM,
                border_width=1, border_color=Colors.BORDER,
            )
            post_frame.pack(fill="x", pady=(4, Layout.PAD_SM))

            post_inner = ctk.CTkFrame(post_frame, fg_color="transparent")
            post_inner.pack(fill="x", padx=12, pady=10)

            ctk.CTkLabel(
                post_inner,
                text="\U0001f5bc\ufe0f  POST-ACQUISITION IMAGE HASHES",
                font=Fonts.SMALL_BOLD,
                text_color=Colors.SUCCESS,
            ).pack(anchor="w", pady=(0, 6))

            ctk.CTkLabel(
                post_inner,
                text="Hash of the captured image file \u2014 used for integrity verification",
                font=Fonts.TINY,
                text_color=Colors.TEXT_MUTED,
            ).pack(anchor="w", pady=(0, 8))

            for lbl, val in [("SHA256", post_sha256), ("MD5", post_md5), ("SHA1", post_sha1)]:
                if val:
                    r = ctk.CTkFrame(post_inner, fg_color="transparent")
                    r.pack(fill="x", pady=1)
                    ctk.CTkLabel(
                        r, text=f"{lbl}:", font=Fonts.SMALL_BOLD,
                        text_color=Colors.TEXT_SECONDARY, width=70, anchor="w",
                    ).pack(side="left")
                    ctk.CTkLabel(
                        r, text=val, font=Fonts.MONO_SMALL,
                        text_color=Colors.SUCCESS, anchor="w",
                    ).pack(side="left", padx=(8, 0))


class AndroidImagerAdapter:

    def __init__(self):
        from core.imaging.imager import AcquisitionState
        self._state = AcquisitionState.IDLE
        self.percent = 0.0
        self.status_text = "Starting Android acquisition"
        self.bytes_acquired = 0
        self.cancel_event = threading.Event()

    @property
    def progress(self):
        class MockProgress:
            def __init__(self, parent):
                self.percent = parent.percent
                self.state = parent._state
                self.bytes_read = parent.bytes_acquired
                self.total_bytes = 0
                self.throughput_mbps = 0.0
                self.eta_seconds = 0.0
                self.status_text = parent.status_text
        return MockProgress(self)

    def cancel(self):
        from core.imaging.imager import AcquisitionState
        self._state = AcquisitionState.CANCELLED
        self.cancel_event.set()

    def pause(self):
        pass

    def resume(self):
        pass

    def acquire(
        self,
        source: str,
        output_dir: str | Path,
        case_id: str,
        examiner: str,
        notes: str = "",
        location: str = "",
        **kwargs,
    ):
        import time
        import shutil
        from core.imaging.imager import AcquisitionState, AcquisitionResult
        from core.acquisition.metadata_collector import MetadataCollector, DeviceMetadata
        from core.chain_of_custody.evidence_manager import EvidenceManager
        from platforms.android.acquisition import detect_devices, collect_all

        self._state = AcquisitionState.RUNNING
        start_time = time.perf_counter()

        self.percent = 5.0
        self.status_text = "Detecting Android devices..."
        
        devices = detect_devices()
        device = next((d for d in devices if d.serial == source), None)
        if not device:
            if devices:
                device = devices[0]
            else:
                self._state = AcquisitionState.FAILED
                return AcquisitionResult(
                    success=False,
                    error="No connected Android device found or unauthorized.",
                )

        if self.cancel_event.is_set():
            self._state = AcquisitionState.CANCELLED
            return AcquisitionResult(success=False, error="Cancelled by user")

        meta = MetadataCollector.new_session(
            case_id=case_id,
            examiner=examiner,
            device_id=device.serial,
            acquisition_method="logical",
            notes=notes,
            geo_location=location,
            device_meta=DeviceMetadata(
                device_id=device.serial,
                model=f"{device.manufacturer} {device.model}",
                serial=device.serial,
                interface="USB/ADB",
            ),
        )
        mgr = EvidenceManager()
        ev_dir = mgr.create_evidence_entry(meta)

        def progress_callback(step_name, pct):
            if self.cancel_event.is_set():
                raise RuntimeError("Cancelled by user")
            self.status_text = step_name
            self.percent = pct
            if ev_dir.exists():
                try:
                    self.bytes_acquired = sum(f.stat().st_size for f in ev_dir.rglob("*") if f.is_file())
                except Exception:
                    pass

        try:
            results = collect_all(device.serial, ev_dir, progress_callback=progress_callback)
            if self.cancel_event.is_set():
                raise RuntimeError("Cancelled by user")

            # Hash and verify files
            self.status_text = "Verifying acquired files..."
            from core.hashing.hasher import Hasher, HashAlgorithm
            EXCLUDED_FILES = {
                "metadata.json",
                "metadata.signed.json",
                "logical_manifest.hashes",
                "acquisition.log",
                "chain_of_custody.json",
                "tags.json",
            }
            file_hashes = {}
            for path in ev_dir.rglob("*"):
                if path.is_file() and path.name not in EXCLUDED_FILES:
                    rel_path = path.relative_to(ev_dir).as_posix()
                    res = Hasher.hash_file(path, HashAlgorithm.SHA256)
                    file_hashes[rel_path] = res.hex_digest

            mgr.write_logical_manifest(case_id, meta.evidence_id, file_hashes)
            verified = mgr.verify_logical_integrity(case_id, meta.evidence_id)

            meta = MetadataCollector.finalize(meta, output_path=str(ev_dir), bytes_acquired=self.bytes_acquired, verified=verified)
            mgr.write_metadata(meta)
            self._state = AcquisitionState.COMPLETE
            duration = round(time.perf_counter() - start_time, 2)

            return AcquisitionResult(
                success=True,
                evidence_id=meta.evidence_id,
                case_id=case_id,
                image_path=str(ev_dir),
                bytes_acquired=self.bytes_acquired,
                duration_seconds=duration,
                verified=verified,
            )
        except Exception as exc:
            if self.cancel_event.is_set() or "Cancelled by user" in str(exc):
                self._state = AcquisitionState.CANCELLED
                if ev_dir.exists():
                    try:
                        shutil.rmtree(ev_dir)
                    except Exception:
                        pass
                return AcquisitionResult(
                    success=False,
                    evidence_id=meta.evidence_id,
                    case_id=case_id,
                    error="Cancelled by user",
                )
            
            self._state = AcquisitionState.FAILED
            return AcquisitionResult(
                success=False,
                evidence_id=meta.evidence_id,
                case_id=case_id,
                error=str(exc),
            )
