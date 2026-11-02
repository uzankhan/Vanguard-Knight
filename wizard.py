#!/usr/bin/env python3
"""
Vanguard Knight - First-Run Setup Wizard
=============================================
Runs exactly once, the very first time the app is launched (checked via
hand_auth.HandAuthManager.is_enrolled() -- if no hand profile exists yet,
this wizard runs before the main dashboard).

Steps:
  1. Welcome            -- intro + what's about to happen
  2. Vault Path          -- where to store the Vault folder (Quarantine,
                            Forensics, logs, etc.)
  3. Hand Enrollment     -- camera-based gesture setup (calls hand_auth.py)
  4. Recovery Key        -- shown ONCE, user must save it (calls recovery_key.py)
  5. Done                -- hands off to the main dashboard
"""

import threading
import time
from pathlib import Path

import customtkinter as ctk
from tkinter import filedialog
from PIL import Image, ImageTk

from theme import *
from hand_auth import HandAuthManager, HAVE_VISION, REQUIRED_CONSECUTIVE_MATCHES
from recovery_key import RecoveryKeyManager

try:
    import cv2
except ImportError:
    cv2 = None


class SetupWizard(ctk.CTk):
    def __init__(self, on_complete=None):
        super().__init__()
        self.title(f"{APP_TITLE} -- First-Time Setup")
        self.geometry("720x600")
        self.minsize(680, 560)
        self.configure(fg_color=COLOR_BG)
        apply_window_icon(self)
        self._logo_image = load_logo_ctk_image(size=(90, 90))
        self.on_complete = on_complete or (lambda vault_path: None)

        self.hand_mgr = HandAuthManager()
        self.recovery_mgr = RecoveryKeyManager()
        self.vault_path_var = ctk.StringVar(value=r"C:\VanguardKnight_Vault")
        self.generated_recovery_key = None
        self._camera_active = False
        self._cap = None

        self.container = ctk.CTkFrame(self, fg_color="transparent")
        self.container.pack(fill="both", expand=True, padx=30, pady=30)

        self.steps = [
            self._build_welcome,
            self._build_vault_path,
            self._build_hand_enroll,
            self._build_recovery_key,
            self._build_done,
        ]
        self.step_index = 0
        self._render_step()

    # ---------------------------------------------------------------
    def _clear(self):
        for w in self.container.winfo_children():
            w.destroy()

    def _render_step(self):
        self._clear()
        self.steps[self.step_index]()

    def _progress_dots(self, parent):
        dots = ctk.CTkFrame(parent, fg_color="transparent")
        dots.pack(pady=(0, 10))
        for i in range(len(self.steps)):
            color = COLOR_PRIMARY if i <= self.step_index else COLOR_BORDER
            ctk.CTkLabel(dots, text="●", font=(FONT_FAMILY, 14), text_color=color).pack(side="left", padx=4)

    def _next_step(self):
        self.step_index += 1
        self._render_step()

    # ---------------------------------------------------------------
    # Step 1: Welcome
    # ---------------------------------------------------------------
    def _build_welcome(self):
        self._progress_dots(self.container)
        if self._logo_image:
            ctk.CTkLabel(self.container, image=self._logo_image, text="").pack(pady=(30, 10))
        else:
            ctk.CTkLabel(self.container, text="🛡", font=(FONT_FAMILY, 56),
                        text_color=COLOR_PRIMARY).pack(pady=(30, 10))
        ctk.CTkLabel(self.container, text=f"Welcome to {APP_TITLE}", font=FONT_TITLE,
                    text_color=COLOR_PRIMARY).pack()
        ctk.CTkLabel(self.container, text=APP_TAGLINE, font=FONT_SUBTITLE,
                    text_color=COLOR_TEXT_MUTED).pack(pady=(4, 30))

        info = ctk.CTkFrame(self.container, fg_color=COLOR_PANEL, corner_radius=14)
        info.pack(fill="x", padx=10, pady=10)
        ctk.CTkLabel(info, text="Before you begin, we'll set up a few things:",
                    font=FONT_BODY, text_color=COLOR_TEXT).pack(anchor="w", padx=24, pady=(20, 10))
        for line in [
            "1.  Choose where Vanguard Knight stores its data (Vault folder)",
            "2.  Set up hand-gesture verification (used only to turn the shield off)",
            "3.  Generate your one-time Recovery Key (save this somewhere safe!)",
        ]:
            ctk.CTkLabel(info, text=line, font=FONT_BODY, text_color=COLOR_TEXT_MUTED,
                        anchor="w").pack(anchor="w", padx=24, pady=4)
        ctk.CTkLabel(info, text="", height=10).pack()

        ctk.CTkButton(self.container, text="Get Started  ->", command=self._next_step,
                     fg_color=COLOR_PRIMARY, hover_color=COLOR_PRIMARY_HOVER,
                     text_color=COLOR_BG, font=FONT_BUTTON, height=46, width=220
                     ).pack(pady=30)
        ctk.CTkLabel(self.container, text=AUTHOR_CREDIT, font=FONT_SMALL,
                    text_color=COLOR_ACCENT).pack(side="bottom", pady=10)

    # ---------------------------------------------------------------
    # Step 2: Vault path
    # ---------------------------------------------------------------
    def _build_vault_path(self):
        self._progress_dots(self.container)
        ctk.CTkLabel(self.container, text="Choose Your Vault Location", font=FONT_HEADING,
                    text_color=COLOR_PRIMARY).pack(pady=(20, 6))
        ctk.CTkLabel(self.container,
                    text="This folder will store quarantined threats, incident reports, "
                         "and logs. Choose a drive with enough free space.",
                    font=FONT_BODY, text_color=COLOR_TEXT_MUTED, wraplength=560,
                    justify="center").pack(pady=(0, 24))

        path_frame = ctk.CTkFrame(self.container, fg_color=COLOR_PANEL, corner_radius=12)
        path_frame.pack(fill="x", padx=10, pady=10)
        entry = ctk.CTkEntry(path_frame, textvariable=self.vault_path_var, width=440, height=40,
                            font=FONT_BODY)
        entry.pack(side="left", padx=16, pady=16)
        ctk.CTkButton(path_frame, text="Browse...", width=100, height=40,
                     fg_color=COLOR_SECONDARY, hover_color=COLOR_PRIMARY,
                     command=self._browse_path).pack(side="left", padx=(0, 16), pady=16)

        nav = ctk.CTkFrame(self.container, fg_color="transparent")
        nav.pack(side="bottom", fill="x", pady=20)
        ctk.CTkButton(nav, text="<- Back", command=self._prev_step, fg_color=COLOR_BORDER,
                     hover_color=COLOR_SECONDARY, width=120, height=42).pack(side="left")
        ctk.CTkButton(nav, text="Continue ->", command=self._next_step, fg_color=COLOR_PRIMARY,
                     hover_color=COLOR_PRIMARY_HOVER, text_color=COLOR_BG, font=FONT_BUTTON,
                     width=160, height=42).pack(side="right")

    def _browse_path(self):
        chosen = filedialog.askdirectory(title="Choose Vault Location")
        if chosen:
            self.vault_path_var.set(str(Path(chosen) / "VanguardKnight_Vault"))

    def _prev_step(self):
        self.step_index = max(0, self.step_index - 1)
        self._render_step()

    # ---------------------------------------------------------------
    # Step 3: Hand enrollment
    # ---------------------------------------------------------------
    def _build_hand_enroll(self):
        self._progress_dots(self.container)
        ctk.CTkLabel(self.container, text="Set Up Hand Verification", font=FONT_HEADING,
                    text_color=COLOR_PRIMARY).pack(pady=(16, 6))
        ctk.CTkLabel(self.container,
                    text="Show ONE hand clearly to your camera and hold a comfortable, "
                         "distinct pose (e.g. an open palm). This gesture will be required "
                         "to turn the shield off in the future -- nobody else can replicate it.",
                    font=FONT_BODY, text_color=COLOR_TEXT_MUTED, wraplength=580,
                    justify="center").pack(pady=(0, 16))

        self.camera_label = ctk.CTkLabel(self.container, text="", fg_color=COLOR_PANEL,
                                         width=400, height=300, corner_radius=12)
        self.camera_label.pack(pady=10)

        self.enroll_status = ctk.CTkLabel(self.container, text="Initializing camera...",
                                          font=FONT_BODY, text_color=COLOR_TEXT_MUTED)
        self.enroll_status.pack(pady=6)

        self.progress_bar = ctk.CTkProgressBar(self.container, width=400, height=14,
                                               progress_color=COLOR_PRIMARY)
        self.progress_bar.set(0)
        self.progress_bar.pack(pady=10)

        nav = ctk.CTkFrame(self.container, fg_color="transparent")
        nav.pack(side="bottom", fill="x", pady=10)
        ctk.CTkButton(nav, text="<- Back", command=self._prev_step, fg_color=COLOR_BORDER,
                     hover_color=COLOR_SECONDARY, width=120, height=42).pack(side="left")

        if not HAVE_VISION or cv2 is None:
            self.enroll_status.configure(
                text="[!] Camera libraries not available on this system "
                     "(opencv-python / mediapipe not installed).",
                text_color=COLOR_WARNING)
            return

        self._start_camera_preview()

    def _start_camera_preview(self):
        self._camera_active = True
        self._latest_frame_rgb = None
        self._latest_landmarks = None
        self._consecutive_stable_frames = 0
        self._enrollment_frames_buffer = []
        self._camera_error = None

        # IMPORTANT: camera open + frame-read loop runs in a background
        # thread. cv2.VideoCapture(0) can block for a noticeable moment
        # (or hang entirely if no camera exists), and doing that on the
        # Tkinter main thread would freeze the whole GUI. The background
        # thread just updates shared state; the GUI polls it via .after().
        self._camera_thread = threading.Thread(target=self._camera_worker, daemon=True)
        self._camera_thread.start()

        self.enroll_status.configure(text="Initializing camera...")
        self._poll_camera_state()

    def _camera_worker(self):
        try:
            import mediapipe as mp
            cap = cv2.VideoCapture(0)
            if not cap.isOpened():
                self._camera_error = "No camera detected."
                cap.release()
                return

            hands = mp.solutions.hands.Hands(
                static_image_mode=False, max_num_hands=1,
                min_detection_confidence=0.7, min_tracking_confidence=0.6
            )
        except AttributeError as e:
            # This is exactly the failure mode that previously caused the
            # UI to hang forever on "Initializing camera..." with no
            # explanation: if mediapipe/opencv are installed incorrectly
            # (e.g. a broken/partial install), this thread would crash
            # silently since nothing was watching for it. Now it's caught
            # and surfaced to the UI immediately.
            self._camera_error = (
                f"mediapipe/opencv appear to be installed incorrectly ({e}). "
                f"Try: pip uninstall mediapipe protobuf -y && pip install mediapipe==0.10.9"
            )
            return
        except Exception as e:
            self._camera_error = f"Camera initialization failed: {e}"
            return

        try:
            while self._camera_active:
                ok, frame = cap.read()
                if not ok:
                    time.sleep(0.05)
                    continue

                frame_rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
                results = hands.process(frame_rgb)

                if results.multi_hand_landmarks:
                    self._latest_landmarks = results.multi_hand_landmarks[0].landmark
                    self._consecutive_stable_frames += 1
                    # Collect this frame's landmarks for multi-frame
                    # averaging -- a much more robust baseline than using
                    # only the very last frame (see enroll_from_multiple_
                    # landmarks in hand_auth.py for why this matters).
                    self._enrollment_frames_buffer.append(self._latest_landmarks)
                else:
                    self._latest_landmarks = None
                    self._consecutive_stable_frames = 0
                    # Hand tracking was lost -- restart the buffer so we
                    # don't average frames from before/after a break in
                    # tracking (which could include a brief mis-tracked
                    # frame right at the loss/recovery boundary).
                    self._enrollment_frames_buffer = []

                self._latest_frame_rgb = frame_rgb
        except Exception as e:
            self._camera_error = f"Camera error during capture: {e}"
        finally:
            cap.release()
            hands.close()

    def _poll_camera_state(self):
        """Runs on the GUI thread via .after() -- reads shared state written
        by the background camera thread and updates the UI. Never touches
        the camera directly, so the GUI never blocks."""
        if not self._camera_active:
            return

        if self._camera_error:
            self.enroll_status.configure(text=f"[!] {self._camera_error}", text_color=COLOR_WARNING)
            self._camera_active = False
            return

        if self._latest_frame_rgb is not None:
            if self._latest_landmarks is not None:
                self.enroll_status.configure(
                    text=f"Hold steady... {self._consecutive_stable_frames}/{REQUIRED_CONSECUTIVE_MATCHES}",
                    text_color=COLOR_PRIMARY)
            else:
                self.enroll_status.configure(text="Show your hand to the camera...",
                                             text_color=COLOR_TEXT_MUTED)

            self.progress_bar.set(min(1.0, self._consecutive_stable_frames / REQUIRED_CONSECUTIVE_MATCHES))

            try:
                img = Image.fromarray(self._latest_frame_rgb).resize((400, 300))
                photo = ImageTk.PhotoImage(img)
                self.camera_label.configure(image=photo, text="")
                self.camera_label.image = photo
            except Exception:
                pass

            if self._consecutive_stable_frames >= REQUIRED_CONSECUTIVE_MATCHES:
                self._finish_enrollment()
                return

        self.after(40, self._poll_camera_state)

    def _finish_enrollment(self):
        self._camera_active = False
        if self._enrollment_frames_buffer:
            self.hand_mgr.enroll_from_multiple_landmarks(self._enrollment_frames_buffer)
        elif self._latest_landmarks is not None:
            # Fallback (shouldn't normally happen, but stays safe)
            self.hand_mgr.enroll_from_landmarks(self._latest_landmarks)
        self.enroll_status.configure(text="[OK] Hand verification set up successfully!",
                                     text_color=COLOR_PRIMARY)
        self.after(1000, self._next_step)

    # ---------------------------------------------------------------
    # Step 4: Recovery key
    # ---------------------------------------------------------------
    def _build_recovery_key(self):
        self._progress_dots(self.container)
        if not self.generated_recovery_key:
            self.generated_recovery_key = self.recovery_mgr.generate_and_store()

        ctk.CTkLabel(self.container, text="Your Recovery Key", font=FONT_HEADING,
                    text_color=COLOR_PRIMARY).pack(pady=(20, 6))
        ctk.CTkLabel(self.container,
                    text="Save this key somewhere safe (write it down, store it in a "
                         "password manager). It is the ONLY way to regain access if hand "
                         "verification ever becomes unavailable. It will not be shown again.",
                    font=FONT_BODY, text_color=COLOR_TEXT_MUTED, wraplength=560,
                    justify="center").pack(pady=(0, 24))

        key_card = ctk.CTkFrame(self.container, fg_color=COLOR_PANEL, corner_radius=14,
                                border_width=2, border_color=COLOR_PRIMARY)
        key_card.pack(pady=10, padx=40, fill="x")
        ctk.CTkLabel(key_card, text=self.generated_recovery_key,
                    font=(FONT_FAMILY, 22, "bold"), text_color=COLOR_PRIMARY
                    ).pack(pady=30)

        self.confirm_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(self.container, text="I have saved this key somewhere safe",
                       variable=self.confirm_var, font=FONT_BODY, text_color=COLOR_TEXT,
                       command=self._toggle_finish_button).pack(pady=20)

        self.finish_btn = ctk.CTkButton(self.container, text="I've Saved It -- Continue",
                                        command=self._next_step, fg_color=COLOR_SECONDARY,
                                        state="disabled", font=FONT_BUTTON, height=46, width=280)
        self.finish_btn.pack(pady=10)

    def _toggle_finish_button(self):
        if self.confirm_var.get():
            self.finish_btn.configure(state="normal", fg_color=COLOR_PRIMARY,
                                      hover_color=COLOR_PRIMARY_HOVER, text_color=COLOR_BG)
        else:
            self.finish_btn.configure(state="disabled", fg_color=COLOR_SECONDARY)

    # ---------------------------------------------------------------
    # Step 5: Done
    # ---------------------------------------------------------------
    def _build_done(self):
        ctk.CTkLabel(self.container, text="[OK]", font=(FONT_FAMILY, 48, "bold"),
                    text_color=COLOR_PRIMARY).pack(pady=(60, 10))
        ctk.CTkLabel(self.container, text="Setup Complete", font=FONT_TITLE,
                    text_color=COLOR_PRIMARY).pack()
        ctk.CTkLabel(self.container, text="Vanguard Knight is ready to protect your system.",
                    font=FONT_SUBTITLE, text_color=COLOR_TEXT_MUTED).pack(pady=(6, 40))

        ctk.CTkButton(self.container, text="Launch Dashboard ->", command=self._complete,
                     fg_color=COLOR_PRIMARY, hover_color=COLOR_PRIMARY_HOVER,
                     text_color=COLOR_BG, font=FONT_BUTTON, height=48, width=260
                     ).pack()

    def _complete(self):
        vault_path = self.vault_path_var.get()
        self.destroy()
        self.on_complete(vault_path)


if __name__ == "__main__":
    def on_done(vault_path):
        print(f"Wizard completed. Vault path: {vault_path}")

    app = SetupWizard(on_complete=on_done)
    app.mainloop()
