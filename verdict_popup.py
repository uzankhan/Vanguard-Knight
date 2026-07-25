#!/usr/bin/env python3
"""
Vanguard Knight - Permission Request Popup (Uncertain-Confidence Detections)
================================================================================
Three-tier detection response (this file handles tier 2):

  TIER 1 - CONFIRMED MALICIOUS (auto-block, no permission asked)
    LOLBin patterns, LSASS credential dumping, process injection,
    ransomware entropy fingerprint, honeypot triggers, BadUSB correlation.
    These are near-certain attack signatures -- asking permission here
    would just give real malware a window to finish executing.

  TIER 2 - UNCERTAIN (ask the user -- THIS FILE)
    A downloaded app, a newly-run existing file, or similar that scores in
    the "suspicious but not confirmed" band: e.g. unsigned + unusual
    location, but no explicit attack pattern matched. Real judgment calls
    where a false positive is plausible (a legitimate new tool you just
    downloaded) -- the user decides.

  TIER 3 - SAFE (ignored, no popup)
    Signed, normal location, no suspicious indicators.

This dialog plays a distinct (softer, non-alarming) notification beep --
different from the urgent red CRITICAL alert beep -- since this is a
judgment call, not a confirmed emergency.
"""

import threading
import logging

import customtkinter as ctk

from theme import *

try:
    import winsound
    HAVE_WINSOUND = True
except ImportError:
    HAVE_WINSOUND = False

logger = logging.getLogger("VanguardKnight.PermissionPopup")


def play_notice_beep():
    """A single, calmer beep -- distinct from the urgent 3-tone critical alert."""
    if HAVE_WINSOUND:
        try:
            winsound.Beep(750, 220)
        except Exception:
            winsound.MessageBeep(winsound.MB_ICONASTERISK)


class PermissionRequestPopup(ctk.CTkToplevel):
    """
    Shown for TIER 2 (uncertain) detections. Presents what was found and
    why it's flagged, and asks the user to Allow or Quarantine it.

    `on_decision(allow: bool)` is called exactly once, either when the user
    clicks a button or when the dialog times out (default = Quarantine,
    a fail-safe choice -- staying silent should never grant trust).
    """

    AUTO_DECISION_TIMEOUT_MS = 60_000  # 60 seconds -- then default to Quarantine

    def __init__(self, master, file_name: str, file_path: str, reason: str,
                 source_context: str, on_decision, sha256: str = None,
                 confidence_score: int = None):
        super().__init__(master)
        self.title("Vanguard Knight -- Review Needed")
        self.geometry("500x420")
        self.configure(fg_color=COLOR_BG)
        self.attributes("-topmost", True)
        self.resizable(False, False)
        apply_window_icon(self)

        self.on_decision = on_decision
        self._decided = False

        border = ctk.CTkFrame(self, fg_color=COLOR_WARNING, corner_radius=12)
        border.pack(fill="both", expand=True, padx=3, pady=3)
        inner = ctk.CTkFrame(border, fg_color=COLOR_PANEL, corner_radius=10)
        inner.pack(fill="both", expand=True, padx=3, pady=3)

        ctk.CTkLabel(inner, text="⚠ REVIEW NEEDED", font=FONT_HEADING,
                    text_color=COLOR_WARNING).pack(pady=(18, 4))
        ctk.CTkLabel(inner, text=source_context, font=FONT_SMALL,
                    text_color=COLOR_TEXT_MUTED).pack()

        ctk.CTkLabel(inner, text=file_name, font=(FONT_FAMILY, 15, "bold"),
                    text_color=COLOR_TEXT).pack(pady=(12, 2))
        ctk.CTkLabel(inner, text=file_path, font=FONT_SMALL, text_color=COLOR_TEXT_MUTED,
                    wraplength=420).pack(pady=(0, 10))

        reason_box = ctk.CTkFrame(inner, fg_color=COLOR_BG, corner_radius=8)
        reason_box.pack(fill="x", padx=24, pady=6)
        ctk.CTkLabel(reason_box, text="Why this was flagged:", font=(FONT_FAMILY, 11, "bold"),
                    text_color=COLOR_WARNING).pack(anchor="w", padx=14, pady=(10, 2))
        ctk.CTkLabel(reason_box, text=reason, font=FONT_SMALL, text_color=COLOR_TEXT,
                    wraplength=400, justify="left").pack(anchor="w", padx=14, pady=(0, 10))

        if confidence_score is not None:
            ctk.CTkLabel(inner, text=f"Trust score: {confidence_score}/100 (uncertain range)",
                        font=FONT_SMALL, text_color=COLOR_TEXT_MUTED).pack(pady=(4, 0))
        if sha256:
            ctk.CTkLabel(inner, text=f"SHA-256: {sha256[:24]}...", font=FONT_SMALL,
                        text_color=COLOR_TEXT_MUTED).pack()

        btn_row = ctk.CTkFrame(inner, fg_color="transparent")
        btn_row.pack(pady=20)
        ctk.CTkButton(btn_row, text="✓ Allow", command=self._allow, fg_color=COLOR_PRIMARY,
                     hover_color=COLOR_PRIMARY_HOVER, text_color=COLOR_BG, font=FONT_BUTTON,
                     width=140, height=42).pack(side="left", padx=10)
        ctk.CTkButton(btn_row, text="✕ Quarantine", command=self._quarantine, fg_color=COLOR_DANGER,
                     hover_color="#CC2E2E", font=FONT_BUTTON, width=140, height=42
                     ).pack(side="left", padx=10)

        self.countdown_label = ctk.CTkLabel(inner, text="", font=FONT_SMALL,
                                            text_color=COLOR_TEXT_MUTED)
        self.countdown_label.pack(pady=(0, 10))
        self._remaining_seconds = self.AUTO_DECISION_TIMEOUT_MS // 1000
        self._tick_countdown()

        threading.Thread(target=play_notice_beep, daemon=True).start()
        self.after(self.AUTO_DECISION_TIMEOUT_MS, self._timeout_default)

    def _tick_countdown(self):
        if self._decided:
            return
        self.countdown_label.configure(
            text=f"No response in {self._remaining_seconds}s -> defaults to Quarantine (safe default)")
        self._remaining_seconds -= 1
        if self._remaining_seconds >= 0:
            self.after(1000, self._tick_countdown)

    def _allow(self):
        if self._decided:
            return
        self._decided = True
        self.destroy()
        self.on_decision(True)

    def _quarantine(self):
        if self._decided:
            return
        self._decided = True
        self.destroy()
        self.on_decision(False)

    def _timeout_default(self):
        if self._decided:
            return
        self._decided = True
        logger.info("[PERMISSION_POPUP] No user response within timeout -- defaulting to Quarantine.")
        try:
            self.destroy()
        except Exception:
            pass
        self.on_decision(False)


if __name__ == "__main__":
    root = ctk.CTk()
    root.geometry("300x150")
    root.configure(fg_color=COLOR_BG)

    decisions = []

    def handle_decision(allowed):
        decisions.append(allowed)
        print(f"Decision received: {'ALLOW' if allowed else 'QUARANTINE'}")

    def open_popup():
        PermissionRequestPopup(
            root, file_name="new_toolkit_installer.exe",
            file_path=r"C:\Users\Maham\Downloads\new_toolkit_installer.exe",
            reason="Unsigned executable, downloaded recently, running from Downloads folder. "
                   "No known-malicious pattern matched, but trust score is in the uncertain range.",
            source_context="Newly downloaded application",
            on_decision=handle_decision, sha256="a1b2c3d4e5f67890" * 2,
            confidence_score=38,
        )

    ctk.CTkButton(root, text="Simulate detection", command=open_popup).pack(pady=40)
    root.mainloop()
