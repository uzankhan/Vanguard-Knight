#!/usr/bin/env python3
"""
Vanguard Knight - Deactivation Hand-Verification Dialog
============================================================
Shown when the user clicks DEACTIVATE on the main dashboard. Live camera
feed + progress ring, waiting for the enrolled hand gesture. Includes a
"Use Recovery Key instead" fallback for when the camera/hand isn't
available (matches the scenario the recovery key was designed for).

Camera runs on a background thread (same pattern as wizard.py's hand
enrollment step) so the dialog UI never freezes, even if camera init is
slow or a camera isn't present at all.
"""

import time
import threading

import customtkinter as ctk
from PIL import Image, ImageTk

from theme import *
from hand_auth import HandAuthManager, HAVE_VISION, REQUIRED_CONSECUTIVE_MATCHES, CAMERA_TIMEOUT_SECONDS
from recovery_key import RecoveryKeyManager

try:
    import cv2
except ImportError:
    cv2 = None


class HandVerifyDialog(ctk.CTkToplevel):
    """
    Modal dialog. Call with on_success callback -- fires only once the
    enrolled hand gesture (or a valid recovery key) has been confirmed.
    The dialog closes itself on success; on Cancel, on_success is never called.
    """

    def __init__(self, master, on_success, purpose_text="Deactivating Vanguard Knight"):
        super().__init__(master)
        self.title("Hand Verification Required")
        self.geometry("480x560")
        self.configure(fg_color=COLOR_BG)
        self.attributes("-topmost", True)
        self.resizable(False, False)
        self.grab_set()  # modal -- must resolve this dialog before touching the main window
        apply_window_icon(self)

        self.on_success = on_success
        self.hand_mgr = HandAuthManager()
        self.recovery_mgr = RecoveryKeyManager()

        self._camera_active = False
        self._latest_frame_rgb = None
        self._latest_landmarks = None
        self._consecutive_matches = 0
        self._camera_error = None
        self._start_time = time.time()

        self._build_verify_view(purpose_text)

    # ---------------------------------------------------------------
    # Primary view: live camera verification
    # ---------------------------------------------------------------

    def _build_verify_view(self, purpose_text):
        for w in self.winfo_children():
            w.destroy()

        ctk.CTkLabel(self, text="🔒", font=(FONT_FAMILY, 40), text_color=COLOR_PRIMARY).pack(pady=(24, 4))
        ctk.CTkLabel(self, text=purpose_text, font=FONT_HEADING, text_color=COLOR_TEXT).pack()
        ctk.CTkLabel(self, text="Show your enrolled hand to the camera to confirm it's you.",
                    font=FONT_BODY, text_color=COLOR_TEXT_MUTED, wraplength=400,
                    justify="center").pack(pady=(4, 16))

        self.camera_label = ctk.CTkLabel(self, text="", fg_color=COLOR_PANEL,
                                         width=360, height=270, corner_radius=12)
        self.camera_label.pack(pady=6)

        self.status_label = ctk.CTkLabel(self, text="Initializing camera...", font=FONT_BODY,
                                         text_color=COLOR_TEXT_MUTED)
        self.status_label.pack(pady=8)

        self.progress_bar = ctk.CTkProgressBar(self, width=360, height=12,
                                               progress_color=COLOR_PRIMARY)
        self.progress_bar.set(0)
        self.progress_bar.pack(pady=6)

        btn_row = ctk.CTkFrame(self, fg_color="transparent")
        btn_row.pack(pady=(16, 6))
        ctk.CTkButton(btn_row, text="Cancel", command=self._cancel, fg_color=COLOR_BORDER,
                     hover_color=COLOR_SECONDARY, width=140, height=40).pack(side="left", padx=8)

        ctk.CTkButton(self, text="Trouble verifying? Use Recovery Key instead",
                     command=self._show_recovery_view, fg_color="transparent",
                     hover_color=COLOR_PANEL, text_color=COLOR_ACCENT, font=FONT_SMALL,
                     height=28).pack(pady=(10, 0))

        if not self.hand_mgr.is_enrolled():
            self.status_label.configure(text="[!] No hand profile enrolled -- use Recovery Key.",
                                        text_color=COLOR_WARNING)
            return
        if not HAVE_VISION or cv2 is None:
            self.status_label.configure(text="[!] Camera libraries unavailable -- use Recovery Key.",
                                        text_color=COLOR_WARNING)
            return

        self._start_camera()

    def _start_camera(self):
        self._camera_active = True
        self._start_time = time.time()
        threading.Thread(target=self._camera_worker, daemon=True).start()
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
                    landmarks = results.multi_hand_landmarks[0].landmark
                    is_match, _, _ = self.hand_mgr.verify_landmarks(landmarks)
                    self._consecutive_matches = self._consecutive_matches + 1 if is_match else 0
                else:
                    self._consecutive_matches = 0

                self._latest_frame_rgb = frame_rgb
        except Exception as e:
            self._camera_error = f"Camera error during capture: {e}"
        finally:
            cap.release()
            hands.close()

    def _poll_camera_state(self):
        if not self._camera_active:
            return

        elapsed = time.time() - self._start_time
        if elapsed > CAMERA_TIMEOUT_SECONDS:
            self._camera_active = False
            self.status_label.configure(text="[!] Timed out. Try again or use Recovery Key.",
                                        text_color=COLOR_WARNING)
            return

        if self._camera_error:
            self.status_label.configure(text=f"[!] {self._camera_error}", text_color=COLOR_WARNING)
            self._camera_active = False
            return

        if self._latest_frame_rgb is not None:
            if self._consecutive_matches > 0:
                self.status_label.configure(
                    text=f"Verifying... {self._consecutive_matches}/{REQUIRED_CONSECUTIVE_MATCHES}",
                    text_color=COLOR_PRIMARY)
            else:
                self.status_label.configure(text="Show your enrolled hand gesture...",
                                            text_color=COLOR_TEXT_MUTED)

            self.progress_bar.set(min(1.0, self._consecutive_matches / REQUIRED_CONSECUTIVE_MATCHES))

            try:
                img = Image.fromarray(self._latest_frame_rgb).resize((360, 270))
                photo = ImageTk.PhotoImage(img)
                self.camera_label.configure(image=photo, text="")
                self.camera_label.image = photo
            except Exception:
                pass

            if self._consecutive_matches >= REQUIRED_CONSECUTIVE_MATCHES:
                self._verified()
                return

        self.after(40, self._poll_camera_state)

    def _verified(self):
        self._camera_active = False
        self.status_label.configure(text="[OK] Verified.", text_color=COLOR_PRIMARY)
        self.after(500, self._close_and_confirm)

    def _close_and_confirm(self):
        self._camera_active = False
        self.grab_release()
        self.destroy()
        self.on_success(method="hand")

    def _cancel(self):
        self._camera_active = False
        self.grab_release()
        self.destroy()

    # ---------------------------------------------------------------
    # Fallback view: recovery key entry
    # ---------------------------------------------------------------

    def _show_recovery_view(self):
        self._camera_active = False  # stop any running camera thread
        for w in self.winfo_children():
            w.destroy()

        ctk.CTkLabel(self, text="🔑", font=(FONT_FAMILY, 40), text_color=COLOR_ACCENT).pack(pady=(30, 6))
        ctk.CTkLabel(self, text="Enter Recovery Key", font=FONT_HEADING,
                    text_color=COLOR_TEXT).pack()
        ctk.CTkLabel(self, text="This is the one-time key you saved during setup.",
                    font=FONT_BODY, text_color=COLOR_TEXT_MUTED).pack(pady=(4, 24))

        self.key_entry = ctk.CTkEntry(self, width=340, height=44, font=(FONT_FAMILY, 14),
                                      placeholder_text="VK-XXXX-XXXX-XXXX-XXXX")
        self.key_entry.pack(pady=10)

        self.recovery_status = ctk.CTkLabel(self, text="", font=FONT_SMALL, text_color=COLOR_DANGER)
        self.recovery_status.pack(pady=6)

        ctk.CTkButton(self, text="Verify Key", command=self._verify_recovery_key,
                     fg_color=COLOR_PRIMARY, hover_color=COLOR_PRIMARY_HOVER,
                     text_color=COLOR_BG, font=FONT_BUTTON, height=44, width=200
                     ).pack(pady=16)

        ctk.CTkButton(self, text="← Back to hand verification", command=self._build_verify_view,
                     fg_color="transparent", hover_color=COLOR_PANEL, text_color=COLOR_ACCENT,
                     font=FONT_SMALL, height=28).pack(pady=6)
        ctk.CTkButton(self, text="Cancel", command=self._cancel, fg_color=COLOR_BORDER,
                     hover_color=COLOR_SECONDARY, width=140, height=38).pack(pady=(20, 0))

    def _verify_recovery_key(self):
        key = self.key_entry.get()
        if self.recovery_mgr.verify(key):
            self.recovery_status.configure(text="[OK] Key verified.", text_color=COLOR_PRIMARY)
            self.after(400, lambda: self._close_and_confirm_recovery())
        else:
            self.recovery_status.configure(text="[!] Invalid recovery key.", text_color=COLOR_DANGER)

    def _close_and_confirm_recovery(self):
        self.grab_release()
        self.destroy()
        self.on_success(method="recovery_key")


if __name__ == "__main__":
    root = ctk.CTk()
    root.geometry("400x300")
    root.configure(fg_color=COLOR_BG)

    result_label = ctk.CTkLabel(root, text="Not verified yet", font=FONT_BODY, text_color=COLOR_TEXT)
    result_label.pack(pady=40)

    def on_success(method):
        result_label.configure(text=f"Verified via: {method}")
        print(f"Deactivation authorized via: {method}")

    def open_dialog():
        HandVerifyDialog(root, on_success=on_success)

    ctk.CTkButton(root, text="Deactivate (test)", command=open_dialog).pack()

    root.mainloop()
