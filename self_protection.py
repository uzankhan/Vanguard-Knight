#!/usr/bin/env python3
"""
Vanguard Knight - Self-Protection Module
============================================
Ye module tool ko khud apne upar attack se bachata hai. Bina iske, koi bhi
malware (ya user khud, agar wo bhi compromise ho) Vanguard Knight ko seedha
kill/uninstall/tamper kar sakta hai aur baaki sab defense bekaar ho jati hai.

Realistic scope: hum TRUE kernel-level protection nahi de sakte (jaise
Protected Process Light / PPL, jo sirf Microsoft-signed drivers ko milta
hai) -- iske liye kernel driver + Microsoft se signing certificate chahiye,
jo is project ke scope se bahar hai. Lekin hum user-mode mein jo maximum
resistance possible hai wo lagate hain:

LAYER 1: Watchdog Process
  Do independent processes jo ek doosre ko monitor karte hain. Agar core
  engine crash/killed ho, watchdog usse turant restart karta hai. Agar
  watchdog khud kill ho, core engine wapis usse restart karta hai. Attacker
  ko DONO ek sath simultaneously kill karne honge (race condition), jo
  significantly harder hai ek se.

LAYER 2: File Integrity Monitoring
  Apni khud ki critical files (config, binaries, Sysmon config) ke hashes
  track karte hain. Koi bhi unexpected modification turant flag hoti hai.

LAYER 3: Service Tamper Detection
  Agar koi Windows Service Control Manager se "stop"/"delete" command bheje
  bina proper authenticated request ke, alert generate hoti hai (via a
  separate monitoring registry key that gets checked on next watchdog cycle).

LAYER 4: Critical Registry Key Protection
  Auto-start registry entry ko periodically verify karte hain -- agar
  koi delete/modify kare, watchdog usse restore kar deta hai.
"""

import os
import sys
import time
import json
import hashlib
import logging
import threading
import subprocess
from pathlib import Path
from typing import Optional, Dict, List, Callable
from dataclasses import dataclass, asdict

logger = logging.getLogger("VanguardKnight.SelfProtect")

VAULT = r"C:\VanguardKnight_Vault"
INTEGRITY_DB = os.path.join(VAULT, "integrity_baseline.json")
WATCHDOG_HEARTBEAT_FILE = os.path.join(VAULT, "watchdog_heartbeat.json")


def sha256_of_file(path: str) -> Optional[str]:
    try:
        h = hashlib.sha256()
        with open(path, 'rb') as f:
            while chunk := f.read(1024 * 1024):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


class FileIntegrityMonitor:
    """
    Tracks hashes of Vanguard Knight's own critical files. If any of them
    change unexpectedly (not via a known, deliberate update process), that's
    a strong signal someone is tampering with the tool itself.
    """

    def __init__(self, watched_files: List[str], db_path: str = INTEGRITY_DB):
        self.watched_files = watched_files
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.baseline: Dict[str, str] = {}
        self._load_baseline()

    def _load_baseline(self):
        if self.db_path.exists():
            try:
                self.baseline = json.loads(self.db_path.read_text(encoding='utf-8'))
            except Exception as e:
                logger.error(f"Could not load integrity baseline: {e}")

    def establish_baseline(self):
        """
        Call this ONCE, deliberately, after a legitimate install/update --
        this records the 'known good' hashes. Do NOT call this automatically
        on every startup, or tampering would just get silently re-baselined
        as 'normal' -- that would defeat the entire point of this monitor.
        """
        for f in self.watched_files:
            h = sha256_of_file(f)
            if h:
                self.baseline[f] = h
        self.db_path.write_text(json.dumps(self.baseline, indent=2), encoding='utf-8')
        logger.info(f"[INTEGRITY] Baseline established for {len(self.baseline)} file(s).")

    def check(self) -> List[dict]:
        """
        Returns a list of tamper findings (empty list = all clean).
        Each finding: {'file': path, 'issue': 'modified'|'missing', 'expected_hash': ..., 'actual_hash': ...}
        """
        findings = []
        for f, expected_hash in self.baseline.items():
            if not os.path.exists(f):
                findings.append({'file': f, 'issue': 'missing', 'expected_hash': expected_hash, 'actual_hash': None})
                continue
            actual_hash = sha256_of_file(f)
            if actual_hash != expected_hash:
                findings.append({'file': f, 'issue': 'modified',
                                 'expected_hash': expected_hash, 'actual_hash': actual_hash})
        return findings


class WatchdogHeartbeat:
    """
    Simple mutual-heartbeat mechanism. The CORE ENGINE process calls
    beat() periodically to prove it's alive. A SEPARATE watchdog process
    checks is_alive() and restarts the core engine if the heartbeat goes
    stale (meaning the process was killed, hung, or crashed).

    This must run as two genuinely separate OS processes (not two threads
    in the same process) -- otherwise killing the process kills the
    "watchdog" too, defeating the purpose.
    """

    STALE_THRESHOLD_SECONDS = 15

    def __init__(self, heartbeat_file: str = WATCHDOG_HEARTBEAT_FILE):
        self.heartbeat_file = Path(heartbeat_file)
        self.heartbeat_file.parent.mkdir(parents=True, exist_ok=True)

    def beat(self, process_role: str = "core_engine"):
        """Call this every few seconds from within the process being watched."""
        data = {'role': process_role, 'timestamp': time.time(), 'pid': os.getpid()}
        try:
            self.heartbeat_file.write_text(json.dumps(data), encoding='utf-8')
        except Exception as e:
            logger.error(f"[WATCHDOG] Could not write heartbeat: {e}")

    def is_alive(self) -> bool:
        """Call this from the watchdog process to check if the monitored process is healthy."""
        if not self.heartbeat_file.exists():
            return False
        try:
            data = json.loads(self.heartbeat_file.read_text(encoding='utf-8'))
            age = time.time() - data.get('timestamp', 0)
            return age < self.STALE_THRESHOLD_SECONDS
        except Exception:
            return False

    def last_known_pid(self) -> Optional[int]:
        if self.heartbeat_file.exists():
            try:
                data = json.loads(self.heartbeat_file.read_text(encoding='utf-8'))
                return data.get('pid')
            except Exception:
                pass
        return None


class SelfProtectionSupervisor:
    """
    Ties together heartbeat monitoring + auto-restart + integrity checking
    into one supervisor loop. Run this as the WATCHDOG process (separate
    from the core engine process).

    Usage (conceptual, on Windows):
        Two Windows Services (or one service + one scheduled task that runs
        at startup) -- "VanguardKnightCore" and "VanguardKnightWatchdog" --
        each configured with sc.exe's recovery options to auto-restart on
        failure, PLUS this supervisor logic as a second independent layer.
    """

    def __init__(self, core_engine_launch_cmd: List[str],
                 watched_files: List[str],
                 on_tamper_detected: Optional[Callable] = None,
                 on_restart: Optional[Callable] = None):
        self.launch_cmd = core_engine_launch_cmd
        self.heartbeat = WatchdogHeartbeat()
        self.integrity = FileIntegrityMonitor(watched_files)
        self.on_tamper_detected = on_tamper_detected or (lambda findings: None)
        self.on_restart = on_restart or (lambda: None)
        self.running = False
        self._process_handle = None

    def start_supervision(self, check_interval: int = 10):
        self.running = True
        threading.Thread(target=self._supervise_loop, args=(check_interval,), daemon=True).start()
        logger.info("[WATCHDOG] Supervision started.")

    def stop_supervision(self):
        self.running = False

    def _supervise_loop(self, interval: int):
        while self.running:
            try:
                # Check 1: is the core engine's heartbeat still fresh?
                if not self.heartbeat.is_alive():
                    logger.warning("[WATCHDOG] Core engine heartbeat is STALE or missing -- "
                                  "process may have been killed or crashed. Restarting.")
                    self._restart_core_engine()

                # Check 2: has any critical file been tampered with?
                findings = self.integrity.check()
                if findings:
                    logger.critical(f"[WATCHDOG] TAMPER DETECTED on {len(findings)} file(s): "
                                    f"{[f['file'] for f in findings]}")
                    self.on_tamper_detected(findings)

            except Exception as e:
                logger.error(f"[WATCHDOG] Supervision cycle error: {e}")

            time.sleep(interval)

    def _restart_core_engine(self):
        try:
            self._process_handle = subprocess.Popen(self.launch_cmd)
            logger.info(f"[WATCHDOG] Core engine restarted (new PID {self._process_handle.pid}).")
            self.on_restart()
        except Exception as e:
            logger.error(f"[WATCHDOG] Failed to restart core engine: {e}")


if __name__ == "__main__":
    import tempfile

    print("=" * 70)
    print("TEST 1: File Integrity Monitor -- detect tampering")
    print("=" * 70)
    with tempfile.NamedTemporaryFile(suffix='.py', delete=False, mode='w') as f:
        f.write("# original vanguard knight core file content")
        test_file = f.name

    baseline_db = tempfile.mktemp(suffix='.json')
    monitor = FileIntegrityMonitor([test_file], db_path=baseline_db)
    monitor.establish_baseline()

    findings = monitor.check()
    assert len(findings) == 0
    print("✓ Freshly baselined file shows no tampering (as expected)")

    # Simulate tampering
    with open(test_file, 'w') as f:
        f.write("# MALICIOUSLY MODIFIED CONTENT")

    findings = monitor.check()
    assert len(findings) == 1
    assert findings[0]['issue'] == 'modified'
    print(f"✓ Tampering correctly detected: {findings[0]['file']} was modified")

    # Simulate deletion
    os.unlink(test_file)
    findings = monitor.check()
    assert findings[0]['issue'] == 'missing'
    print(f"✓ File deletion correctly detected as tampering")

    print("\n" + "=" * 70)
    print("TEST 2: Watchdog Heartbeat -- stale detection")
    print("=" * 70)
    hb_file = tempfile.mktemp(suffix='.json')
    hb = WatchdogHeartbeat(heartbeat_file=hb_file)
    hb.STALE_THRESHOLD_SECONDS = 1  # shrink for fast test

    assert hb.is_alive() is False
    print("✓ No heartbeat file yet -- correctly reports NOT alive")

    hb.beat("core_engine")
    assert hb.is_alive() is True
    print("✓ Fresh heartbeat -- correctly reports ALIVE")

    time.sleep(1.5)
    assert hb.is_alive() is False
    print("✓ Heartbeat older than threshold -- correctly reports STALE (process presumed dead)")

    print("\nAll self-protection self-tests passed.")
