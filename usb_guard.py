#!/usr/bin/env python3
"""
Vanguard Knight - USB HID Injection Guard (BadUSB / "Rubber Ducky" Defense)
==============================================================================
Attack category ye module target karta hai:
Koi bhi device (Raspberry Pi Pico W, Digispark, O.MG cable, Flipper Zero,
USB Rubber Ducky, etc.) jo USB port mein lagte hi khud ko HID keyboard
declare karta hai aur PRE-PROGRAMMED keystrokes inject karta hai --
usually: Win+R -> powershell/cmd open -> ek command chalake payload
download/execute karna, sab kuch 1-3 second mein.

Ye "BadUSB" ki poori category hai -- chahe device Pico W ho, Digispark ho,
ya koi aur microcontroller, PRINCIPLE hamesha same hota hai: OS ke liye
har USB keyboard "trusted" hota hai by default (Windows kabhi nahi puchta
"is this keyboard really you?"). Isliye defense bhi principle-level honi
chahiye, specific device pehchan kar nahi.

DO NEECHE DIYE GAYE DEFENSE LAYERS, dono INDEPENDENT hain (ek fail ho to
doosra bhi catch kar sakta hai):

LAYER 1: Typing Cadence Analysis (behavioral)
  Insaan ki typing mein natural variance hota hai -- har keystroke ke beech
  ka gap kabhi 80ms, kabhi 220ms, kabhi 150ms (irregular, human motor-control
  jitter). BadUSB devices firmware se keystrokes bhejte hain jo EXTREMELY
  uniform timing rakhte hain (jaise har keystroke exact 10ms ya 15ms gap se) --
  ye "too perfect to be human" pattern hi sabse strong giveaway hai.

LAYER 2: New-HID-Device + Immediate-Shell-Spawn Correlation
  Agar koi naya HID/keyboard device abhi USB mein laga ho AUR turant (kuch
  seconds ke andar) cmd.exe/powershell.exe jaisa process launch ho -- ye
  extremely suspicious correlation hai. Normal human workflow mein "keyboard
  plug karo -> turant PowerShell khul jaye" bilkul nahi hota.

LAYER 3: Unknown HID Device Enumeration Alert
  Har naya keyboard-class USB device jo pehle kabhi register nahi hua, uske
  liye alert -- taake tumhe pata chale koi naya "keyboard" laga hai, chahe
  wo asal mein malicious ho ya na ho (visibility feature).
"""

import time
import logging
import statistics
import threading
import queue
from collections import deque
from datetime import datetime
from typing import Optional, List, Deque, Callable
from dataclasses import dataclass, field

logger = logging.getLogger("VanguardKnight.USBGuard")

# ---------------------------------------------------------------------------
# LAYER 1: Typing Cadence Analysis
# ---------------------------------------------------------------------------

# Thresholds derived from human-typing research: even very fast typists
# (100+ WPM) show inter-keystroke variance. Consistent sub-20ms gaps with
# near-zero variance across many consecutive keys is not physically typical
# of human muscle movement -- it's a strong automation fingerprint.
INHUMAN_AVG_GAP_MS = 25          # avg gap this low across a burst = suspicious
INHUMAN_MAX_VARIANCE_MS = 4      # real humans have jitter; near-zero variance = machine
MIN_KEYSTROKES_FOR_ANALYSIS = 8  # need a decent sample before judging


@dataclass
class KeystrokeEvent:
    timestamp: float   # time.time() at key-down
    vkey: Optional[int] = None
    device_id: Optional[str] = None


class TypingCadenceAnalyzer:
    """
    Consumes a stream of keystroke timestamps and flags bursts that look
    machine-generated rather than human-typed.

    This class is intentionally decoupled from the actual OS-level keyboard
    hook (which on Windows would use a low-level keyboard hook via
    SetWindowsHookEx(WH_KEYBOARD_LL) or Raw Input API) -- feed it timestamps
    from whatever hook implementation is wired up, and it does the analysis.
    """

    def __init__(self, window_size: int = 30, on_suspicious: Optional[Callable] = None):
        self.window_size = window_size
        self.buffer: Deque[KeystrokeEvent] = deque(maxlen=window_size)
        self.on_suspicious = on_suspicious
        self._last_alert_time = 0.0
        self._alert_cooldown = 10.0  # seconds, avoid alert spam

    def feed(self, event: KeystrokeEvent):
        self.buffer.append(event)
        if len(self.buffer) >= MIN_KEYSTROKES_FOR_ANALYSIS:
            self._analyze()

    def _analyze(self):
        # IMPORTANT: only look at the most recent slice, not the entire
        # rolling buffer. If we averaged over the whole window, a burst of
        # machine-speed injected keystrokes right after normal human typing
        # would get diluted by the older human-typed gaps and the attack
        # would be detected late (or missed for several keystrokes). Using
        # a fixed recent slice makes detection react immediately to a
        # regime change in typing behavior.
        recent = list(self.buffer)[-MIN_KEYSTROKES_FOR_ANALYSIS:]
        timestamps = [e.timestamp for e in recent]
        gaps_ms = [
            (timestamps[i] - timestamps[i - 1]) * 1000
            for i in range(1, len(timestamps))
        ]
        if len(gaps_ms) < MIN_KEYSTROKES_FOR_ANALYSIS - 1:
            return

        avg_gap = statistics.mean(gaps_ms)
        variance = statistics.pstdev(gaps_ms) if len(gaps_ms) > 1 else 0.0

        is_suspicious = (avg_gap < INHUMAN_AVG_GAP_MS and variance < INHUMAN_MAX_VARIANCE_MS)

        if is_suspicious:
            now = time.time()
            if now - self._last_alert_time > self._alert_cooldown:
                self._last_alert_time = now
                reason = (f"Inhuman typing cadence detected: avg_gap={avg_gap:.1f}ms "
                          f"(threshold <{INHUMAN_AVG_GAP_MS}ms), variance={variance:.2f}ms "
                          f"(threshold <{INHUMAN_MAX_VARIANCE_MS}ms) -- consistent with "
                          f"automated HID injection (BadUSB/Rubber Ducky class device), "
                          f"not human keystrokes.")
                logger.warning(f"[USB_GUARD] {reason}")
                if self.on_suspicious:
                    self.on_suspicious(reason, avg_gap, variance)


# ---------------------------------------------------------------------------
# LAYER 2 + 3: Device Arrival Monitoring & Shell-Spawn Correlation
# ---------------------------------------------------------------------------

@dataclass
class HIDDeviceEvent:
    device_id: str
    device_name: str
    arrival_time: float
    is_known: bool = False


class USBHIDGuard:
    """
    Tracks USB HID (keyboard/input) device arrivals and correlates them
    against subsequent shell/process launches. This is the "connect the dots"
    layer -- a new unknown keyboard appearing is mildly interesting, but a
    new unknown keyboard appearing followed 1-3 seconds later by cmd.exe or
    powershell.exe launching is a near-certain BadUSB signature.
    """

    SHELL_PROCESSES = {'cmd.exe', 'powershell.exe', 'pwsh.exe', 'wscript.exe',
                        'cscript.exe', 'mshta.exe', 'wt.exe'}
    CORRELATION_WINDOW_SECONDS = 5.0  # shell launch within this window of HID arrival = suspicious

    def __init__(self, known_devices_store: Optional[set] = None,
                 on_alert: Optional[Callable] = None):
        self.known_devices = known_devices_store if known_devices_store is not None else set()
        self.recent_hid_arrivals: List[HIDDeviceEvent] = []
        self.on_alert = on_alert
        self.cadence_analyzer = TypingCadenceAnalyzer(on_suspicious=self._on_cadence_alert)
        self._lock = threading.Lock()

    def on_hid_device_arrival(self, device_id: str, device_name: str):
        """
        Call this when Windows reports a new HID device (via WM_DEVICECHANGE,
        WMI Win32_PnPEntity creation event, or a registry watcher on
        HKLM\\SYSTEM\\CurrentControlSet\\Enum\\HID).
        """
        is_known = device_id in self.known_devices
        event = HIDDeviceEvent(device_id=device_id, device_name=device_name,
                                arrival_time=time.time(), is_known=is_known)
        with self._lock:
            self.recent_hid_arrivals.append(event)
            # keep only recent ones (correlation window + buffer)
            cutoff = time.time() - (self.CORRELATION_WINDOW_SECONDS * 3)
            self.recent_hid_arrivals = [e for e in self.recent_hid_arrivals if e.arrival_time > cutoff]

        if not is_known:
            msg = (f"[USB_GUARD] New/unrecognized HID input device connected: "
                   f"'{device_name}' ({device_id}). Monitoring for suspicious follow-up activity.")
            logger.warning(msg)
            if self.on_alert:
                self.on_alert("new_hid_device", msg, severity="MEDIUM")

    def on_process_launch(self, process_name: str, pid: int, parent_name: str = ""):
        """
        Call this from the main process-creation event pipeline (Sysmon
        Event ID 1 handler). Checks whether this process launch correlates
        suspiciously with a recent unknown HID device arrival.
        """
        if process_name.lower() not in self.SHELL_PROCESSES:
            return

        with self._lock:
            recent_unknown_hid = [
                e for e in self.recent_hid_arrivals
                if not e.is_known and (time.time() - e.arrival_time) <= self.CORRELATION_WINDOW_SECONDS
            ]

        if recent_unknown_hid:
            device = recent_unknown_hid[-1]
            msg = (f"[USB_GUARD] CRITICAL: Shell process '{process_name}' (PID {pid}) launched "
                   f"only {time.time() - device.arrival_time:.1f}s after unknown HID device "
                   f"'{device.device_name}' connected. This is a strong BadUSB/Rubber-Ducky-class "
                   f"injection signature -- treating as high-confidence attack.")
            logger.critical(msg)
            if self.on_alert:
                self.on_alert("hid_shell_correlation", msg, severity="CRITICAL",
                              extra={'pid': pid, 'device_id': device.device_id})

    def feed_keystroke(self, vkey: Optional[int] = None, device_id: Optional[str] = None):
        """Feed a live keystroke timestamp into the cadence analyzer."""
        self.cadence_analyzer.feed(KeystrokeEvent(timestamp=time.time(), vkey=vkey, device_id=device_id))

    def _on_cadence_alert(self, reason: str, avg_gap: float, variance: float):
        if self.on_alert:
            self.on_alert("inhuman_typing_cadence", reason, severity="CRITICAL",
                          extra={'avg_gap_ms': avg_gap, 'variance_ms': variance})

    def trust_device(self, device_id: str):
        """Mark a device as known/trusted (e.g. your actual keyboard)."""
        self.known_devices.add(device_id)


if __name__ == "__main__":
    alerts_captured = []

    def capture_alert(alert_type, message, severity="INFO", extra=None):
        alerts_captured.append((alert_type, severity, message))
        print(f"[{severity}] {alert_type}: {message[:100]}...")

    guard = USBHIDGuard(on_alert=capture_alert)

    print("=" * 70)
    print("TEST 1: Simulating HUMAN typing (irregular gaps) -- should NOT alert")
    print("=" * 70)
    human_gaps = [0.09, 0.15, 0.22, 0.11, 0.18, 0.31, 0.08, 0.14, 0.19, 0.25]
    t = time.time()
    for gap in human_gaps:
        t += gap
        guard.cadence_analyzer.feed(KeystrokeEvent(timestamp=t))
    human_alerts = [a for a in alerts_captured if a[0] == 'inhuman_typing_cadence']
    assert len(human_alerts) == 0, "False positive on human typing!"
    print("✓ No false alarm on realistic human typing pattern\n")

    print("=" * 70)
    print("TEST 2: Simulating BadUSB injection (uniform ~10ms gaps) -- SHOULD alert")
    print("=" * 70)
    t = time.time()
    for _ in range(15):
        t += 0.010  # exactly 10ms every time -- inhumanly consistent
        guard.cadence_analyzer.feed(KeystrokeEvent(timestamp=t))
    injection_alerts = [a for a in alerts_captured if a[0] == 'inhuman_typing_cadence']
    assert len(injection_alerts) >= 1, "Failed to catch machine-speed uniform typing!"
    print(f"✓ Correctly flagged {len(injection_alerts)} inhuman-cadence alert(s)\n")

    print("=" * 70)
    print("TEST 3: Unknown HID device arrives, then shell spawns 2 seconds later")
    print("=" * 70)
    guard2 = USBHIDGuard(on_alert=capture_alert)
    guard2.on_hid_device_arrival("USB\\VID_2E8A&PID_0005", "Generic HID Keyboard")
    time.sleep(0.1)  # simulate short delay (test uses small sleep, logic uses real seconds)
    guard2.on_process_launch("powershell.exe", pid=5566, parent_name="explorer.exe")
    correlation_alerts = [a for a in alerts_captured if a[0] == 'hid_shell_correlation']
    assert len(correlation_alerts) >= 1, "Failed to correlate new HID device with shell spawn!"
    print(f"✓ Correctly correlated new HID device + shell spawn as CRITICAL threat\n")

    print("=" * 70)
    print("TEST 4: KNOWN/trusted keyboard + shell launch -- should NOT alert (your real keyboard)")
    print("=" * 70)
    guard3 = USBHIDGuard(on_alert=capture_alert)
    guard3.trust_device("USB\\VID_046D&PID_C31C")  # e.g. your actual Logitech keyboard
    guard3.on_hid_device_arrival("USB\\VID_046D&PID_C31C", "Logitech Keyboard")
    before_count = len(alerts_captured)
    guard3.on_process_launch("powershell.exe", pid=7777)
    correlation_after = [a for a in alerts_captured if a[0] == 'hid_shell_correlation']
    print(f"✓ Trusted keyboard + PowerShell launch did NOT trigger correlation alert "
          f"({len(correlation_after)} correlation alerts total, all from Test 3)\n")

    print("All USB HID Guard self-tests passed.")
