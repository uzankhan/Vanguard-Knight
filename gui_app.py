#!/usr/bin/env python3
"""
Vanguard Knight - Main GUI Application
==========================================
Built with CustomTkinter. Structure:

  VanguardApp
    |-- FirstRunWizard (shown only on first install)
    |     |-- WelcomeScreen
    |     |-- HandEnrollScreen   (calls hand_auth.py)
    |     |-- VaultPathScreen
    |
    |-- MainDashboard (the everyday screen)
    |     |-- Animated Activate/Deactivate button (pulsing glow)
    |     |-- Status shield indicator
    |     |-- Live stats (analyzed / blocked / trusted)
    |     |-- Live log panel
    |     |-- 3-dot menu -> Help page, About page
    |
    |-- ThreatAlertPopup (red, pulsing, plays a beep, always-on-top)

Design note on animation: CustomTkinter/Tkinter doesn't support video or
GPU shaders, so "animation" here means smooth, tasteful widget-property
transitions done via `.after()` timers -- color interpolation (glow pulse),
easing on size/position, fade-style alpha on toplevels. This is the
realistic ceiling for this tech stack (as discussed) but done well it
reads as a genuinely polished, alive interface rather than a static form.
"""

import os
import sys
import time
import threading
import queue
import webbrowser
import urllib.parse
from pathlib import Path
from datetime import datetime

import customtkinter as ctk
from tkinter import filedialog, Canvas

try:
    import winsound
    HAVE_WINSOUND = True
except ImportError:
    HAVE_WINSOUND = False  # non-Windows dev/testing fallback

try:
    import pystray
    from PIL import Image as PILImage
    HAVE_TRAY = True
except Exception:
    # On Windows (our actual target), pystray uses its win32 backend which
    # just needs pywin32 (already a hard dependency). This broad except is
    # specifically to tolerate non-Windows dev/test environments where
    # pystray's backend auto-detection can fail in other ways (e.g. no
    # GTK on a bare Linux box) -- the app still runs fine without a tray
    # icon, just falling back to iconify() for minimize.
    HAVE_TRAY = False

from theme import *
from hand_verify_dialog import HandVerifyDialog
from verdict_popup import PermissionRequestPopup
from hacker_fx import (MatrixRainCanvas, GlitchLabel, draw_hud_corners,
                       HUDCutPanel, BlinkingCursor, TypewriterTextbox)

try:
    from core_engine import CoreEngine
    HAVE_ENGINE = True
except ImportError as e:
    HAVE_ENGINE = False
    _ENGINE_IMPORT_ERROR = str(e)

ctk.set_appearance_mode("dark")


def play_alert_beep():
    """Distinct urgent beep pattern for threat alerts."""
    if HAVE_WINSOUND:
        try:
            winsound.Beep(1200, 180)
            winsound.Beep(900, 180)
            winsound.Beep(1200, 220)
        except Exception:
            winsound.MessageBeep(winsound.MB_ICONHAND)
    # else: silently skip on non-Windows dev environments


# =====================================================================
# Reusable animated glow button (used for the big Activate/Deactivate control)
# =====================================================================

class PulsingGlowButton(ctk.CTkFrame):
    """
    A circular-ish glowing button that pulses its border/glow color smoothly.
    Used for the main Activate/Deactivate control -- this is the single
    most 'alive' element on the dashboard, meant to feel like the system
    is breathing/watching, not a static button.
    """

    def __init__(self, parent, text, command, base_color, glow_color,
                 size=220, font=FONT_BUTTON, **kwargs):
        super().__init__(parent, fg_color="transparent", **kwargs)
        self.command = command
        self.base_color = base_color
        self.glow_color = glow_color
        self.size = size
        self._pulse_phase = 0.0
        self._pulsing = True

        self.canvas = Canvas(self, width=size, height=size, bg=COLOR_BG,
                             highlightthickness=0)
        self.canvas.pack()

        self.label_var = text
        self._render()
        self.canvas.bind("<Button-1>", lambda e: self.command())
        self.canvas.configure(cursor="hand2")
        self._animate()

    def _lerp_color(self, c1, c2, t):
        """Linear-interpolate between two hex colors -- the core of the pulse effect."""
        c1 = c1.lstrip('#'); c2 = c2.lstrip('#')
        r1, g1, b1 = int(c1[0:2], 16), int(c1[2:4], 16), int(c1[4:6], 16)
        r2, g2, b2 = int(c2[0:2], 16), int(c2[2:4], 16), int(c2[4:6], 16)
        r = int(r1 + (r2 - r1) * t)
        g = int(g1 + (g2 - g1) * t)
        b = int(b1 + (b2 - b1) * t)
        return f"#{r:02x}{g:02x}{b:02x}"

    def _render(self):
        self.canvas.delete("all")
        t = (1 + __import__('math').sin(self._pulse_phase)) / 2  # 0..1 smooth oscillation
        ring_color = self._lerp_color(self.base_color, self.glow_color, t)
        pad = 10 + int(6 * t)  # glow "breathes" outward slightly

        cx, cy, r = self.size / 2, self.size / 2, (self.size / 2) - 15
        # Outer glow rings (decreasing opacity simulated via decreasing brightness step)
        for i in range(3, 0, -1):
            glow_r = r + (i * (4 + pad // 3))
            self.canvas.create_oval(cx - glow_r, cy - glow_r, cx + glow_r, cy + glow_r,
                                    outline=ring_color, width=1)
        # Main ring
        self.canvas.create_oval(cx - r, cy - r, cx + r, cy + r,
                                outline=ring_color, width=4, fill=COLOR_PANEL)
        # Label
        self.canvas.create_text(cx, cy, text=self.label_var, fill=COLOR_TEXT,
                                font=FONT_BUTTON, justify="center", width=r * 1.6)

    def set_text(self, text):
        self.label_var = text
        self._render()

    def set_colors(self, base_color, glow_color):
        self.base_color = base_color
        self.glow_color = glow_color

    def _animate(self):
        if not self._pulsing:
            return
        self._pulse_phase += 0.12
        self._render()
        self.after(40, self._animate)

    def stop(self):
        self._pulsing = False


# =====================================================================
# Threat Alert Popup (red, pulsing, beeping)
# =====================================================================

class ThreatAlertPopup(ctk.CTkToplevel):
    """Always-on-top red alert that appears the instant a threat is
    detected/blocked. Pulses its border and plays an urgent beep pattern."""

    def __init__(self, master, threat_name: str, reason: str, severity: str = "CRITICAL"):
        super().__init__(master)
        apply_window_icon(self)
        self.title("⚠ THREAT DETECTED")
        self.geometry("460x260")
        self.configure(fg_color=COLOR_BG)
        self.attributes("-topmost", True)
        self.resizable(False, False)

        self._pulse = 0.0
        self._pulsing = True

        border = ctk.CTkFrame(self, fg_color=COLOR_DANGER, corner_radius=12)
        border.pack(fill="both", expand=True, padx=4, pady=4)
        inner = ctk.CTkFrame(border, fg_color=COLOR_PANEL, corner_radius=10)
        inner.pack(fill="both", expand=True, padx=3, pady=3)

        ctk.CTkLabel(inner, text="⚠ THREAT NEUTRALIZED", font=FONT_HEADING,
                    text_color=COLOR_DANGER).pack(pady=(18, 6))
        ctk.CTkLabel(inner, text=threat_name, font=(FONT_FAMILY, 16, "bold"),
                    text_color=COLOR_TEXT).pack(pady=2)
        ctk.CTkLabel(inner, text=reason, font=FONT_BODY, text_color=COLOR_TEXT_MUTED,
                    wraplength=380, justify="center").pack(pady=8, padx=20)
        ctk.CTkLabel(inner, text=f"Severity: {severity}", font=FONT_SMALL,
                    text_color=SEVERITY_COLORS.get(severity, COLOR_DANGER)).pack()
        ctk.CTkLabel(inner, text="✓ Process terminated & quarantined.", font=FONT_SMALL,
                    text_color=COLOR_PRIMARY).pack(pady=(10, 4))

        ctk.CTkButton(inner, text="Dismiss", command=self._close, fg_color=COLOR_DANGER,
                     hover_color="#CC2E2E", font=FONT_BUTTON, width=120).pack(pady=12)

        self._border_widget = border
        self._animate_border()
        threading.Thread(target=play_alert_beep, daemon=True).start()
        self.after(8000, self._close)  # auto-dismiss if ignored

    def _animate_border(self):
        if not self._pulsing:
            return
        import math
        t = (1 + math.sin(self._pulse)) / 2
        r1, g1, b1 = int(COLOR_DANGER[1:3], 16), int(COLOR_DANGER[3:5], 16), int(COLOR_DANGER[5:7], 16)
        r2, g2, b2 = int(COLOR_DANGER_GLOW[1:3], 16), int(COLOR_DANGER_GLOW[3:5], 16), int(COLOR_DANGER_GLOW[5:7], 16)
        r = int(r1 + (r2 - r1) * t); g = int(g1 + (g2 - g1) * t); b = int(b1 + (b2 - b1) * t)
        try:
            self._border_widget.configure(fg_color=f"#{r:02x}{g:02x}{b:02x}")
        except Exception:
            pass
        self._pulse += 0.25
        self.after(60, self._animate_border)

    def _close(self):
        self._pulsing = False
        try:
            self.destroy()
        except Exception:
            pass


# =====================================================================
# Help Page (3-dot menu)
# =====================================================================

class HelpPage(ctk.CTkToplevel):
    def __init__(self, master):
        super().__init__(master)
        apply_window_icon(self)
        self.title("Help & Support")
        self.geometry("560x520")
        self.configure(fg_color=COLOR_BG)
        self.attributes("-topmost", True)

        ctk.CTkLabel(self, text="Help & Support", font=FONT_TITLE,
                    text_color=COLOR_PRIMARY).pack(pady=(20, 4))
        ctk.CTkLabel(self, text=APP_TAGLINE, font=FONT_SUBTITLE,
                    text_color=COLOR_TEXT_MUTED).pack(pady=(0, 20))

        card = ctk.CTkFrame(self, fg_color=COLOR_PANEL, corner_radius=14)
        card.pack(fill="both", expand=True, padx=24, pady=10)

        ctk.CTkLabel(card, text="Found a bug or having an issue?", font=FONT_HEADING,
                    text_color=COLOR_TEXT).pack(pady=(20, 8), padx=20, anchor="w")
        ctk.CTkLabel(card, text="Describe what happened below. This will open your email "
                               "client with the message pre-filled, addressed to the developer.",
                    font=FONT_BODY, text_color=COLOR_TEXT_MUTED, wraplength=460,
                    justify="left").pack(padx=20, anchor="w")

        self.subject_entry = ctk.CTkEntry(card, placeholder_text="Short summary of the issue",
                                          width=460, height=36)
        self.subject_entry.pack(pady=(14, 8), padx=20)

        self.body_textbox = ctk.CTkTextbox(card, width=460, height=140,
                                           fg_color=COLOR_BG, text_color=COLOR_TEXT)
        self.body_textbox.pack(padx=20, pady=(0, 10))
        self.body_textbox.insert("1.0", "Describe the bug or issue here...")

        ctk.CTkButton(card, text="✉  Send Bug Report", command=self._send_email,
                     fg_color=COLOR_PRIMARY, hover_color=COLOR_PRIMARY_HOVER,
                     text_color=COLOR_BG, font=FONT_BUTTON, height=42).pack(pady=10)

        divider = ctk.CTkFrame(card, fg_color=COLOR_BORDER, height=1)
        divider.pack(fill="x", padx=20, pady=14)

        contact_frame = ctk.CTkFrame(card, fg_color="transparent")
        contact_frame.pack(pady=(0, 20))
        ctk.CTkLabel(contact_frame, text="Developer", font=FONT_SMALL,
                    text_color=COLOR_TEXT_MUTED).pack()
        ctk.CTkLabel(contact_frame, text="Uzan Khan", font=(FONT_FAMILY, 14, "bold"),
                    text_color=COLOR_PRIMARY).pack()
        ctk.CTkLabel(contact_frame, text=SUPPORT_EMAIL, font=FONT_BODY,
                    text_color=COLOR_TEXT_MUTED).pack()

    def _send_email(self):
        subject = self.subject_entry.get() or "Vanguard Knight - Bug Report"
        body = self.body_textbox.get("1.0", "end-1c")
        params = urllib.parse.urlencode({'subject': subject, 'body': body})
        mailto = f"mailto:{SUPPORT_EMAIL}?{params}"
        try:
            webbrowser.open(mailto)
        except Exception as e:
            print(f"Could not open email client: {e}")


# =====================================================================
# About Page (3-dot menu)
# =====================================================================

ABOUT_TEXT = """Vanguard Knight watches your computer in real time and looks for
signs of malware, hackers, and other threats -- the same way a security
guard watches a building, except this one never sleeps and reacts in
milliseconds.

HOW IT WORKS (in plain terms):

1. Watching -- Vanguard Knight uses Sysmon, a trusted Microsoft tool, to
   see everything that happens on your computer: every program that
   starts, every file that's created, every network connection made.

2. Judging -- Every time something happens, Vanguard Knight asks a series
   of smart questions: Is this program signed by a trusted company? Is it
   running from a normal location? Is it behaving like known malware
   (for example, rapidly encrypting files like ransomware, or injecting
   itself into other programs)?

3. Acting -- If something looks dangerous enough, Vanguard Knight
   immediately stops it and stores a safe copy in a locked-away
   quarantine folder, in case you ever need to recover it or investigate
   further.

4. Remembering -- Every action Vanguard Knight takes is written into a
   detailed report -- what happened, when, and why -- so you always have
   a clear record, like a security guard's incident log.

5. Trusting your own tools -- Programs you personally approve (like your
   own projects) are remembered and skipped during scanning, so Vanguard
   Knight never gets in your way.

6. Guarding your keyboard -- Vanguard Knight also watches for a sneaky
   attack where a malicious USB device pretends to be a keyboard and
   types commands on its own. It can tell the difference between real
   human typing and an automated device, and reacts instantly.

7. Protecting itself -- Vanguard Knight is built to resist being shut
   down or deleted by anything other than you. Turning it off requires
   your hand to be shown to the camera and verified -- something no
   ordinary program, virus, or remote attacker can fake.

Vanguard Knight was designed and built from the ground up as a personal
project, with the goal of being genuinely useful, genuinely intelligent,
and genuinely respectful of your privacy -- everything it does runs
locally on your machine.
"""


class AboutPage(ctk.CTkToplevel):
    def __init__(self, master):
        super().__init__(master)
        apply_window_icon(self)
        self.title("About Vanguard Knight")
        self.geometry("620x640")
        self.configure(fg_color=COLOR_BG)
        self.attributes("-topmost", True)

        ctk.CTkLabel(self, text=APP_TITLE, font=FONT_TITLE,
                    text_color=COLOR_PRIMARY).pack(pady=(20, 2))
        ctk.CTkLabel(self, text=APP_TAGLINE, font=FONT_SUBTITLE,
                    text_color=COLOR_TEXT_MUTED).pack()
        ctk.CTkLabel(self, text=AUTHOR_CREDIT, font=(FONT_FAMILY, 12, "bold"),
                    text_color=COLOR_ACCENT).pack(pady=(4, 16))

        box = ctk.CTkTextbox(self, width=560, height=460, fg_color=COLOR_PANEL,
                             text_color=COLOR_TEXT, font=FONT_BODY, wrap="word")
        box.pack(padx=20, pady=10, fill="both", expand=True)
        box.insert("1.0", ABOUT_TEXT)
        box.configure(state="disabled")

        ctk.CTkLabel(self, text="© 2026 Vanguard Knight -- Made by Uzan Khan",
                    font=FONT_SMALL, text_color=COLOR_TEXT_MUTED).pack(pady=(0, 16))


# =====================================================================
# Main dashboard window
# =====================================================================

class VanguardMainWindow(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("1000x680")
        self.minsize(900, 600)
        self.configure(fg_color=COLOR_BG)
        apply_window_icon(self)
        self._logo_image = load_logo_ctk_image(size=(40, 40))

        # -----------------------------------------------------------
        # KIOSK-STYLE WINDOW: no native title bar, no native [_][□][X]
        # buttons. This removes the casual "just click X" route to close
        # the app -- the ONLY way to stop protection is the Deactivate
        # button, which requires hand verification. Minimize is still
        # available, but only through our own controlled 3-dot menu.
        #
        # Honest limits (same OS-security-model point as before): this
        # stops CASUAL closing (no X button, Alt+F4 does nothing). It does
        # NOT and CANNOT stop a genuine machine Administrator from force-
        # killing the process via Task Manager -- that's fundamental to how
        # Windows works, not something any user-mode app can override. The
        # watchdog service (self_protection.py / watchdog_main.py) is what
        # handles that case by restarting protection automatically.
        # -----------------------------------------------------------
        self.overrideredirect(True)
        self._center_on_screen(1000, 680)

        # Block Alt+F4 outright -- it does nothing rather than opening any
        # dialog, since closing must always be a deliberate button click,
        # never a keyboard reflex.
        self.bind("<Alt-F4>", lambda e: "break")
        # Safety net: if anything ever does trigger the WM_DELETE_WINDOW
        # protocol (some OS/window-manager paths can still send it even to
        # overrideredirect windows), swallow it instead of closing.
        self.protocol("WM_DELETE_WINDOW", lambda: None)

        self.is_active = False
        self.engine = None

        # -----------------------------------------------------------
        # THREAD-SAFETY BRIDGE
        # -----------------------------------------------------------
        # CoreEngine's detection logic runs on background worker threads.
        # Tkinter widgets may ONLY be touched from the main GUI thread --
        # calling .configure()/.insert() etc. from another thread causes
        # crashes or corrupted state. So instead of updating widgets
        # directly from engine callbacks, those callbacks just push a
        # small message onto this thread-safe queue; the GUI polls it via
        # .after() on the main thread and does the actual widget updates
        # there. This is the standard safe pattern for Tkinter + background
        # threads.
        self._ui_queue: "queue.Queue" = queue.Queue()
        self.after(100, self._process_ui_queue)

        self._build_header()
        self._build_body()

        if not HAVE_ENGINE:
            self._log(f"[!] Core engine unavailable on this system: {_ENGINE_IMPORT_ERROR}")
            self._log("[!] This is expected when running outside Windows (e.g. for GUI "
                      "preview/testing) -- on the real deployment machine, pywin32/psutil "
                      "will be present and the engine will load normally.")

    # -----------------------------------------------------------
    # UI queue processing (runs on main thread only)
    # -----------------------------------------------------------

    def _process_ui_queue(self):
        try:
            while True:
                msg = self._ui_queue.get_nowait()
                kind = msg[0]

                if kind == 'log':
                    self._log(msg[1])

                elif kind == 'alert':
                    _, alert_type, text, severity, extra = msg
                    if alert_type == "threat_blocked":
                        threat_name = text.split(":")[0] if ":" in text else "Unknown threat"
                        reason = text.split(":", 1)[1].strip() if ":" in text else text
                        ThreatAlertPopup(self, threat_name=threat_name, reason=reason, severity=severity)
                    self._log(f"[{severity}] {alert_type}: {text}")

                elif kind == 'permission_request':
                    _, details, on_decision = msg
                    self._show_permission_popup(details, on_decision)

                elif kind == 'stats':
                    self._update_stats_display(msg[1])

        except queue.Empty:
            pass
        self.after(100, self._process_ui_queue)

    def _show_permission_popup(self, details: dict, on_decision):
        """Runs on the main thread (called from the queue processor)."""
        PermissionRequestPopup(
            self,
            file_name=Path(details.get('exe_path', '')).name or details.get('threat_name', 'Unknown'),
            file_path=details.get('exe_path', ''),
            reason=details.get('reason', ''),
            source_context="File flagged for review",
            on_decision=on_decision,
            confidence_score=details.get('score'),
        )

    def _update_stats_display(self, stats: dict):
        self.stats_label.configure(
            text=f"Analyzed: {stats.get('analyzed', 0)}\n"
                 f"Blocked: {stats.get('blocked', 0)}\n"
                 f"Trusted-skipped: {stats.get('trusted_skipped', 0)}"
        )

    # -----------------------------------------------------------
    # Engine-facing callbacks (called from BACKGROUND threads --
    # these must ONLY ever push to the queue, never touch widgets directly)
    # -----------------------------------------------------------

    def _engine_log_callback(self, message: str):
        self._ui_queue.put(('log', message))

    def _engine_alert_callback(self, alert_type: str, text: str, severity: str = "INFO", extra: dict = None):
        self._ui_queue.put(('alert', alert_type, text, severity, extra))

    def _engine_permission_callback(self, details: dict, on_decision):
        self._ui_queue.put(('permission_request', details, on_decision))

    # ---------------- Header ----------------

    def _build_header(self):
        header = ctk.CTkFrame(self, fg_color=COLOR_PANEL, height=84, corner_radius=0)
        header.pack(fill="x")
        header.pack_propagate(False)

        # overrideredirect(True) removes the OS's native window dragging
        # along with the title bar, so we implement our own: clicking and
        # dragging anywhere on the header moves the window. This keeps the
        # window usable/repositionable despite having no OS chrome.
        self._drag_offset_x = 0
        self._drag_offset_y = 0

        def start_drag(event):
            self._drag_offset_x = event.x
            self._drag_offset_y = event.y

        def do_drag(event):
            x = self.winfo_pointerx() - self._drag_offset_x
            y = self.winfo_pointery() - self._drag_offset_y
            self.geometry(f"+{x}+{y}")

        header.bind("<Button-1>", start_drag)
        header.bind("<B1-Motion>", do_drag)
        header.bind("<Double-Button-1>", lambda e: self._toggle_fullscreen())

        left = ctk.CTkFrame(header, fg_color="transparent")
        left.pack(side="left", padx=20)
        left.bind("<Button-1>", start_drag)
        left.bind("<B1-Motion>", do_drag)
        if self._logo_image:
            ctk.CTkLabel(left, image=self._logo_image, text="").pack(side="left", padx=(0, 10))
        else:
            ctk.CTkLabel(left, text="🛡", font=(FONT_FAMILY, 30), text_color=COLOR_PRIMARY).pack(side="left", padx=(0, 10))
        title_box = ctk.CTkFrame(left, fg_color="transparent")
        title_box.pack(side="left")
        title_box.bind("<Button-1>", start_drag)
        title_box.bind("<B1-Motion>", do_drag)
        title_lbl = ctk.CTkLabel(title_box, text=APP_TITLE, font=(FONT_FAMILY, 22, "bold"),
                                 text_color=COLOR_PRIMARY)
        title_lbl.pack(anchor="w")
        title_lbl.bind("<Button-1>", start_drag)
        title_lbl.bind("<B1-Motion>", do_drag)
        tagline_lbl = ctk.CTkLabel(title_box, text=APP_TAGLINE, font=FONT_SMALL,
                                   text_color=COLOR_TEXT_MUTED)
        tagline_lbl.pack(anchor="w")
        tagline_lbl.bind("<Button-1>", start_drag)
        tagline_lbl.bind("<B1-Motion>", do_drag)

        # Subtle occasional glitch-flicker on the title -- purely cosmetic,
        # reads as "terminal/hacker interface" rather than a static app label.
        self._title_glitch = GlitchLabel(title_lbl, APP_TITLE, glitch_chance=0.006)

        right = ctk.CTkFrame(header, fg_color="transparent")
        right.pack(side="right", padx=20)

        self.status_dot = ctk.CTkLabel(right, text="●", font=(FONT_FAMILY, 18),
                                       text_color=COLOR_TEXT_MUTED)
        self.status_dot.pack(side="left", padx=(0, 6))
        self.status_label = ctk.CTkLabel(right, text="INACTIVE", font=(FONT_FAMILY, 12, "bold"),
                                         text_color=COLOR_TEXT_MUTED)
        self.status_label.pack(side="left", padx=(0, 20))

        # Custom minimize -- the only window-chrome-like control we expose.
        # There is deliberately NO close/X button anywhere in this header.
        ctk.CTkButton(right, text="—", width=36, height=36, font=(FONT_FAMILY, 16),
                     fg_color="transparent", hover_color=COLOR_BORDER,
                     text_color=COLOR_TEXT_MUTED, command=self._minimize
                     ).pack(side="left", padx=(0, 4))

        # Fullscreen toggle -- overrideredirect() removes the native
        # maximize button along with everything else, so this replaces it.
        ctk.CTkButton(right, text="⛶", width=36, height=36, font=(FONT_FAMILY, 14),
                     fg_color="transparent", hover_color=COLOR_BORDER,
                     text_color=COLOR_TEXT_MUTED, command=self._toggle_fullscreen
                     ).pack(side="left", padx=(0, 4))

        self.menu_btn = ctk.CTkButton(right, text="⋮", width=40, height=40, font=(FONT_FAMILY, 20),
                                      fg_color="transparent", hover_color=COLOR_BORDER,
                                      text_color=COLOR_TEXT, command=self._show_menu)
        self.menu_btn.pack(side="left")

    def _center_on_screen(self, width: int, height: int):
        screen_w = self.winfo_screenwidth()
        screen_h = self.winfo_screenheight()
        x = (screen_w - width) // 2
        y = (screen_h - height) // 2
        self.geometry(f"{width}x{height}+{x}+{y}")
        self._normal_geometry = f"{width}x{height}+{x}+{y}"
        self._is_fullscreen = False

    def _toggle_fullscreen(self):
        # overrideredirect windows have no native maximize button, so this
        # is our replacement: toggles between the normal windowed size/
        # position and covering the entire screen. We track the previous
        # geometry ourselves since there's no OS-level "restore" to rely on.
        if not self._is_fullscreen:
            self._normal_geometry = self.geometry()
            screen_w = self.winfo_screenwidth()
            screen_h = self.winfo_screenheight()
            self.geometry(f"{screen_w}x{screen_h}+0+0")
            self._is_fullscreen = True
        else:
            self.geometry(self._normal_geometry)
            self._is_fullscreen = False

    def _minimize(self):
        # overrideredirect windows can be lost from the taskbar entirely on
        # some Windows configurations if just iconify()'d -- withdraw()
        # (fully hide) + a system tray icon guarantees the window is always
        # recoverable, which is the important safety property here.
        self.withdraw()
        self._ensure_tray_icon()

    def _ensure_tray_icon(self):
        if not HAVE_TRAY:
            # No pystray available -- fall back to iconify so the window
            # isn't completely unreachable, even without a tray icon.
            try:
                self.deiconify()
                self.iconify()
            except Exception:
                pass
            return
        if getattr(self, '_tray_icon', None) is not None:
            return  # already running

        try:
            if self._logo_image is not None:
                pil_img = PILImage.open(LOGO_PATH).resize((64, 64))
            else:
                pil_img = PILImage.new('RGB', (64, 64), color=COLOR_PRIMARY)
        except Exception:
            pil_img = PILImage.new('RGB', (64, 64), color=COLOR_PRIMARY)

        menu = pystray.Menu(
            pystray.MenuItem("Show Vanguard Knight", self._tray_show, default=True),
            pystray.MenuItem(f"Status: {'ACTIVE' if self.is_active else 'INACTIVE'}", None, enabled=False),
        )
        self._tray_icon = pystray.Icon("VanguardKnight", pil_img, APP_TITLE, menu)
        threading.Thread(target=self._tray_icon.run, daemon=True).start()

    def _tray_show(self, icon=None, item=None):
        # Called from the tray icon's own thread -- must marshal back onto
        # the Tkinter main thread via .after(), same thread-safety rule as
        # the engine callbacks.
        self.after(0, self._restore_from_tray)

    def _restore_from_tray(self):
        if getattr(self, '_tray_icon', None) is not None:
            try:
                self._tray_icon.stop()
            except Exception:
                pass
            self._tray_icon = None
        self.deiconify()
        self.lift()
        self.focus_force()

    def _show_menu(self):
        menu = ctk.CTkToplevel(self)
        menu.title("Menu")
        menu.geometry("220x160")
        menu.configure(fg_color=COLOR_PANEL)
        menu.attributes("-topmost", True)
        # position near the menu button
        x = self.winfo_x() + self.winfo_width() - 240
        y = self.winfo_y() + 90
        menu.geometry(f"+{x}+{y}")

        ctk.CTkButton(menu, text="❓  Help & Support", anchor="w",
                     fg_color="transparent", hover_color=COLOR_BORDER, text_color=COLOR_TEXT,
                     font=FONT_BODY, command=lambda: [menu.destroy(), HelpPage(self)]).pack(fill="x", padx=8, pady=(10, 4))
        ctk.CTkButton(menu, text="ℹ️  About", anchor="w",
                     fg_color="transparent", hover_color=COLOR_BORDER, text_color=COLOR_TEXT,
                     font=FONT_BODY, command=lambda: [menu.destroy(), AboutPage(self)]).pack(fill="x", padx=8, pady=4)
        ctk.CTkButton(menu, text="🗕  Minimize", anchor="w",
                     fg_color="transparent", hover_color=COLOR_BORDER, text_color=COLOR_TEXT,
                     font=FONT_BODY, command=lambda: [menu.destroy(), self._minimize()]).pack(fill="x", padx=8, pady=4)

    # ---------------- Body ----------------

    def _add_hud_corners(self, panel, size=20, color=None):
        """Adds four small L-bracket canvases at the corners of `panel`,
        giving it a HUD/targeting-frame look instead of a plain rounded
        rectangle. Each tiny canvas's background matches the panel's fill
        color so only the bracket lines are visible, blending seamlessly."""
        color = color or COLOR_PRIMARY
        specs = [
            ('nw', 0.0, 0.0, 0, 0, ( (0,0,size,0), (0,0,0,size) )),
            ('ne', 1.0, 0.0, -size, 0, ( (size,0,0,0), (size,0,size,size) )),
            ('sw', 0.0, 1.0, 0, -size, ( (0,size,size,size), (0,0,0,size) )),
            ('se', 1.0, 1.0, -size, -size, ( (0,size,size,size), (size,0,size,size) )),
        ]
        for anchor, relx, rely, xoff, yoff, lines in specs:
            c = Canvas(panel, width=size, height=size, bg=COLOR_PANEL, highlightthickness=0)
            c.place(relx=relx, rely=rely, x=xoff, y=yoff, anchor=anchor)
            for x1, y1, x2, y2 in lines:
                c.create_line(x1, y1, x2, y2, fill=color, width=2)

    def _build_body(self):
        body = ctk.CTkFrame(self, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=20, pady=20)

        # Left: main control -- angled-corner HUD panel with bracketed title
        left_hud = HUDCutPanel(body, width=320, height=600, title="Shield Control",
                               corner_cut=20)
        left_hud.pack(side="left", fill="y", padx=(0, 16))
        left_panel = left_hud.content

        # Ambient matrix-rain texture behind the shield control content --
        # placed first (bottom of z-order among siblings), dimmed so it
        # reads as background atmosphere rather than competing with the
        # actual controls drawn on top of it.
        self._matrix_bg = MatrixRainCanvas(left_panel, width=280, height=560, dim=True,
                                           bg_color=COLOR_PANEL)
        self._matrix_bg.place(x=0, y=0, relwidth=1.0, relheight=1.0)

        self.glow_button = PulsingGlowButton(
            left_panel, text="ACTIVATE", command=self._toggle_shield,
            base_color=COLOR_SECONDARY, glow_color=COLOR_PRIMARY, size=190,
        )
        self.glow_button.pack(pady=(20, 10))

        ctk.CTkLabel(left_panel, text="Deactivating requires hand verification.",
                    font=FONT_SMALL, text_color=COLOR_TEXT_MUTED, wraplength=250,
                    justify="center").pack(pady=(6, 20))

        stats_card = ctk.CTkFrame(left_panel, fg_color=COLOR_BG, corner_radius=0,
                                  border_width=1, border_color=COLOR_BORDER)
        stats_card.pack(fill="x", padx=10, pady=10)
        self.stats_label = ctk.CTkLabel(stats_card,
                                        text="ANALYZED: 0\nBLOCKED: 0\nTRUSTED-SKIPPED: 0",
                                        font=FONT_BODY, text_color=COLOR_PRIMARY, justify="left")
        self.stats_label.pack(padx=16, pady=16, anchor="w")

        # Right: live log -- same HUD-cut styling, bracketed title
        right_hud = HUDCutPanel(body, width=600, height=600, title="Live Activity Log",
                                corner_cut=20)
        right_hud.pack(side="right", fill="both", expand=True)
        right_panel = right_hud.content

        self.log_box = ctk.CTkTextbox(right_panel, fg_color=COLOR_BG, text_color=COLOR_PRIMARY,
                                      font=FONT_MONO_LOG, border_width=0)
        self.log_box.pack(fill="both", expand=True, side="top")

        # Terminal-style prompt line with a blinking cursor underneath the
        # log, purely atmospheric -- reinforces the "live terminal" feel.
        self._prompt_label = ctk.CTkLabel(right_panel, text="", font=FONT_MONO_LOG,
                                          text_color=COLOR_PRIMARY, anchor="w")
        self._prompt_label.pack(fill="x", side="bottom", pady=(4, 0))
        self._prompt_cursor = BlinkingCursor(self._prompt_label, base_text="vanguard@shield:~$")

        # New log lines are revealed with a typewriter effect instead of
        # appearing instantly -- reads as the system actively processing.
        self._log_typewriter = TypewriterTextbox(self.log_box, chars_per_tick=3, tick_ms=8)

        self._log("System idle. Press ACTIVATE to begin protection.")

    # ---------------- Behavior ----------------

    def _log(self, message: str):
        ts = datetime.now().strftime("%H:%M:%S")
        line = f"[{ts}] {message}"
        if hasattr(self, '_log_typewriter'):
            self._log_typewriter.append_line(line)
        else:
            # Fallback for any log call that happens before the typewriter
            # wrapper is set up (shouldn't normally happen, but stays safe).
            self.log_box.insert("end", line + "\n")
            self.log_box.see("end")

    def _toggle_shield(self):
        if not self.is_active:
            self._activate()
        else:
            self._request_deactivate()

    def _activate(self):
        if not HAVE_ENGINE:
            self._log("[!] Cannot activate -- core engine is unavailable on this system.")
            return

        self.engine = CoreEngine(
            alert_callback=self._engine_alert_callback,
            log_callback=self._engine_log_callback,
            permission_callback=self._engine_permission_callback,
        )
        try:
            self.engine.start()
        except Exception as e:
            self._log(f"[!] Failed to start engine: {e}")
            return

        self.is_active = True
        self.glow_button.set_text("ACTIVE")
        self.glow_button.set_colors(COLOR_PRIMARY, COLOR_PRIMARY)
        self.status_dot.configure(text_color=COLOR_PRIMARY)
        self.status_label.configure(text="ACTIVE", text_color=COLOR_PRIMARY)
        self._log("Shield activated. Real-time monitoring started.")
        self._start_stats_polling()

    def _start_stats_polling(self):
        """Periodically pushes engine.stats onto the UI queue (from a
        background thread) so the dashboard's stats panel stays live."""
        def poll_loop():
            while self.is_active and self.engine:
                self._ui_queue.put(('stats', dict(self.engine.stats)))
                time.sleep(2)
        threading.Thread(target=poll_loop, daemon=True).start()

    def _request_deactivate(self):
        """Deactivation requires hand verification (or the recovery-key
        fallback) -- this is enforced here, not just suggested, so the
        shield can't be casually toggled off."""
        # Guard against opening a second verification dialog if one is
        # already open (e.g. the Deactivate button/click gets triggered
        # twice quickly) -- a stray second dialog was a plausible source
        # of confusing "nothing happens" behavior.
        if getattr(self, '_deactivate_dialog_open', False):
            self._log("[!] A verification dialog is already open.")
            return
        self._deactivate_dialog_open = True

        def on_success_wrapper(method):
            self._deactivate_dialog_open = False
            self._on_deactivate_verified(method)

        HandVerifyDialog(self, on_success=on_success_wrapper,
                         purpose_text="Deactivating Vanguard Knight")

    def _on_deactivate_verified(self, method: str):
        # Log immediately, before doing anything else -- if this line never
        # appears in the log, we know the callback itself never fired
        # (a dialog/threading issue). If it DOES appear but the shield
        # doesn't visibly deactivate, we know the bug is below this line.
        self._log(f"[DEACTIVATE] Verification succeeded via: {method}. Stopping shield now...")
        try:
            if self.engine:
                try:
                    self.engine.stop()
                    self._log("[DEACTIVATE] Engine stopped successfully.")
                except Exception as e:
                    self._log(f"[!] Error stopping engine: {e}")
                self.engine = None
            else:
                self._log("[DEACTIVATE] No engine instance was running (already stopped?).")

            self.is_active = False
            self.glow_button.set_text("ACTIVATE")
            self.glow_button.set_colors(COLOR_SECONDARY, COLOR_PRIMARY)
            self.status_dot.configure(text_color=COLOR_TEXT_MUTED)
            self.status_label.configure(text="INACTIVE", text_color=COLOR_TEXT_MUTED)
            self._log("[DEACTIVATE] Shield deactivated -- UI updated to INACTIVE.")
        except Exception as e:
            # If anything above throws, we now see exactly what and where,
            # instead of the UI silently staying in a stuck "ACTIVE" state.
            self._log(f"[!] CRITICAL: Deactivation UI update failed: {e}")
            import traceback
            self._log(traceback.format_exc())

    def simulate_threat_alert(self, name="suspicious_loader.exe",
                              reason="LOLBin pattern + unsigned binary from Temp folder"):
        """Demo hook -- in production, core_engine.py's alert_callback calls this."""
        self._log(f"[ALERT] {name} -- {reason}")
        ThreatAlertPopup(self, threat_name=name, reason=reason, severity="CRITICAL")


if __name__ == "__main__":
    # NOTE: this direct launch is a VISUAL smoke-test only (useful for
    # checking the theme/animations/popup rendering on any machine, even
    # without Windows-only libraries installed). The real production entry
    # point that wires up the first-run wizard + live engine is app_main.py.
    app = VanguardMainWindow()
    app.after(1500, app.simulate_threat_alert)
    app.mainloop()
