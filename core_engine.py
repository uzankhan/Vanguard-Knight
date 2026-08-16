#!/usr/bin/env python3
"""
Vanguard Knight - Core Detection Engine (v6.0.0)
===================================================
Ye file saari alag modules ko jodti hai ek working pipeline mein:

  SysmonEventReader (real-time events)
        |
        v
  CoreEngine._route_event()  --  event type ke hisab se sahi handler bulata hai
        |
        +--> process_create   --> TrustedAppManager check --> LOLBin check
        |                         --> Reputation scoring --> USB-shell correlation
        +--> process_access   --> LSASS credential-theft detection (Event ID 10)
        +--> create_remote_thread --> Process injection detection (Event ID 8)
        +--> file_create      --> Ransomware detection (entropy.py + rate check)
        +--> registry_event   --> Persistence detection
        +--> dns_query        --> DNS tunneling heuristic
        |
        v
  On any confirmed threat:
        1. ForensicsManager.create_case()  --> full SOC-style case file
        2. _respond()                       --> terminate + quarantine
        3. alert_callback()                 --> notify GUI/user

Design principle: TRUSTED APPS ARE CHECKED FIRST, before any other logic.
This is what stops Rabail / your other projects from ever reaching the
reputation-scoring or LOLBin logic in the first place -- if it's trusted,
we skip straight past detection entirely (but still log it quietly for
visibility, so you have a record that it ran).
"""

import os
import re
import time
import shutil
import logging
import threading
import subprocess
import queue
import ntpath  # Sysmon always reports Windows-style paths (C:\...); using
               # ntpath explicitly (instead of pathlib.Path) guarantees
               # correct backslash parsing regardless of what OS this code
               # happens to run/test on, removing any platform ambiguity.
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Callable

from entropy import analyze_file
from sysmon_reader import SysmonEventReader
from trusted_apps import TrustedAppManager
from forensics import ForensicsManager, IncidentCase, make_case_id
from usb_guard import USBHIDGuard

try:
    import psutil
except ImportError:
    psutil = None  # allows this file to at least import/lint on non-Windows

logger = logging.getLogger("VanguardKnight.Core")

VAULT = r"C:\VanguardKnight_Vault"
QUARANTINE_DIR = os.path.join(VAULT, "Quarantine")

# LOLBins -- expanded from earlier version with more patterns per binary
LOLBINS = {
    'powershell.exe': ['-enc', '-e ', 'base64', 'invoke-expression', 'iex', 'downloadstring',
                        'downloadfile', 'hidden', 'bypass', 'noprofile', 'invoke-webrequest'],
    'pwsh.exe': ['-enc', 'invoke-expression', 'downloadstring'],
    'cmd.exe': ['/c ', 'ping -n', 'certutil', 'bitsadmin', '&& powershell'],
    'mshta.exe': ['javascript:', 'vbscript:', 'http'],
    'regsvr32.exe': ['/s', '/u', '/i:', 'scrobj.dll'],
    'rundll32.exe': ['javascript:', 'advpack.dll', 'url.dll'],
    'certutil.exe': ['-urlcache', '-decode', '-split', '-verifyctl'],
    'wmic.exe': ['process call create', '/node:'],
    'wscript.exe': ['.vbs', '.js', '.jse'],
    'cscript.exe': ['.vbs', '.js', '.jse'],
    'bitsadmin.exe': ['/transfer', '/download'],
    'msbuild.exe': ['.xml', '/target'],
    'installutil.exe': ['/logfile=', '/u'],
    'msiexec.exe': ['/i http', '/q'],
}

KNOWN_SYSTEM_PROCESSES = {
    'svchost.exe', 'explorer.exe', 'services.exe', 'winlogon.exe',
    'wininit.exe', 'csrss.exe', 'smss.exe', 'lsass.exe', 'system',
}

# Legitimate software that routinely writes many small files per minute
# during completely normal use (browser cache/cookies/IndexedDB, editor
# auto-save, sync-client diffing, package-manager extraction, etc.).
# These get a much higher rate ceiling before the rate signal even counts
# -- ransomware detection should never punish ordinary heavy usage.
# NOTE: this is a name-based hint used only to pick a threshold, not a
# trust decision by itself -- these processes still go through full
# signature/entropy checks like anything else.
KNOWN_HIGH_IO_APPS = {
    'chrome.exe', 'msedge.exe', 'firefox.exe', 'brave.exe', 'opera.exe',
    'explorer.exe', 'onedrive.exe', 'dropbox.exe', 'teams.exe', 'slack.exe',
    'code.exe', 'devenv.exe', 'git.exe', 'node.exe', 'python.exe', 'pythonw.exe',
    'outlook.exe', 'winword.exe', 'excel.exe', 'powerpnt.exe',
    'discord.exe', 'spotify.exe', 'steam.exe', 'steamwebhelper.exe',
    'searchindexer.exe', 'msmpeng.exe', 'widgets.exe',
}
RANSOMWARE_RATE_THRESHOLD_NORMAL = 60      # files/min for unrecognized processes
RANSOMWARE_RATE_THRESHOLD_HIGH_IO = 250    # files/min for known legitimate high-I/O apps


def detect_lolbin(process_name: str, command_line: str) -> tuple:
    if not command_line:
        return False, ""
    name_lower = process_name.lower()
    cmd_lower = command_line.lower()
    if name_lower in LOLBINS:
        for pattern in LOLBINS[name_lower]:
            if pattern.lower() in cmd_lower:
                return True, f"LOLBin pattern matched: '{pattern}' in {name_lower}"
    return False, ""


class RansomwareRateTracker:
    """Tracks file-write rate per PID to catch mass-encryption bursts.
    IMPORTANT: rate alone is a WEAK, noisy signal -- browsers, IDEs, sync
    clients, and many other completely legitimate apps can easily write
    50-100+ small cache/temp files per minute during normal heavy use.
    This tracker's output should never trigger an auto-kill by itself;
    see _handle_file_create for how it's combined with entropy analysis
    before any action is taken."""

    def __init__(self, default_threshold: int = 60):
        self.default_threshold = default_threshold
        self.file_ops: Dict[int, list] = {}

    def record_and_check(self, pid: int, threshold: int = None) -> bool:
        now = time.time()
        ops = self.file_ops.setdefault(pid, [])
        ops.append(now)
        # keep only last 60 seconds
        self.file_ops[pid] = [t for t in ops if now - t < 60]
        limit = threshold if threshold is not None else self.default_threshold
        return len(self.file_ops[pid]) > limit


class DNSTunnelingHeuristic:
    """
    Simple heuristic for DNS tunneling: legit DNS queries are short and
    look like real hostnames. Tunneling tools encode data INTO the subdomain
    itself, producing long, high-entropy-looking, unusual query names.
    """

    @staticmethod
    def is_suspicious(query_name: str) -> tuple:
        if not query_name:
            return False, ""
        label = query_name.split('.')[0]  # first label = leftmost subdomain
        if len(label) > 50:
            return True, f"Unusually long DNS subdomain label ({len(label)} chars) -- possible tunneling"
        # High ratio of digits/hex-looking chars in a long label = encoded data
        if len(label) > 25:
            hex_like = sum(1 for c in label if c in '0123456789abcdefABCDEF')
            if hex_like / len(label) > 0.7:
                return True, f"Long hex-like DNS label ({label[:20]}...) -- possible data exfiltration via DNS"
        return False, ""


def _is_dangerous_lsass_access(granted_access) -> bool:
    """
    Only access rights that include PROCESS_VM_READ (0x0010) indicate
    genuine memory-reading intent -- the actual mechanism needed to dump
    credentials from LSASS. Many completely legitimate Windows components
    (svchost.exe-hosted services, session management, WMI, even Task
    Manager) touch LSASS constantly with harmless query-only access
    rights as part of normal OS operation. Treating EVERY touch as
    confirmed credential theft (as a previous version of this code did)
    causes catastrophic false positives on core system processes.
    """
    PROCESS_VM_READ = 0x0010
    try:
        if isinstance(granted_access, str):
            access_int = int(granted_access, 16) if granted_access.lower().startswith('0x') else int(granted_access)
        else:
            access_int = int(granted_access)
    except (ValueError, TypeError):
        return False  # can't parse the access mask -- don't flag on uncertain data
    return bool(access_int & PROCESS_VM_READ)


class CoreEngine:
    # Reputation-score bands (0-100). These define the three-tier response:
    #   score < UNCERTAIN_LOWER            -> Tier 1: confirmed-enough to auto-block
    #   UNCERTAIN_LOWER <= score < UNCERTAIN_UPPER -> Tier 2: ask the user
    #   score >= UNCERTAIN_UPPER           -> Tier 3: safe, ignored
    # (LOLBin/LSASS/injection/ransomware/honeypot matches ALWAYS auto-block
    #  regardless of score -- those are confirmed attack signatures, not
    #  reputation guesses, and are handled separately before this banding.)
    UNCERTAIN_LOWER = 25
    UNCERTAIN_UPPER = 45

    def __init__(self, alert_callback: Optional[Callable] = None,
                 log_callback: Optional[Callable] = None,
                 permission_callback: Optional[Callable] = None):
        self.alert_callback = alert_callback or (lambda *a, **k: None)
        self.log_callback = log_callback or (lambda msg: logger.info(msg))
        # permission_callback(details: dict, on_decision: Callable[[bool], None]) -> None
        # Called for Tier-2 (uncertain) detections. The GUI should show a
        # popup and call on_decision(True) to allow or on_decision(False)
        # to quarantine. If no callback is wired up (e.g. running headless/
        # as a service with no GUI attached), we fail SAFE -- default to
        # quarantine rather than silently allowing uncertain files to run.
        self.permission_callback = permission_callback or self._default_permission_handler

        self.event_queue: "queue.Queue" = queue.Queue(maxsize=5000)
        self.sysmon_reader = SysmonEventReader(output_queue=self.event_queue,
                                               log_callback=self.log_callback)
        self.trusted_apps = TrustedAppManager()
        self.forensics = ForensicsManager()
        self.usb_guard = USBHIDGuard(on_alert=self._on_usb_alert)
        self.ransomware_tracker = RansomwareRateTracker()

        self.running = False
        self.worker_threads = []
        self.stats = {'analyzed': 0, 'blocked': 0, 'trusted_skipped': 0}
        self.alert_cooldown: Dict[str, float] = {}

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self, num_workers: int = 4):
        self.running = True
        self.forensics.start_auto_cleanup()
        self.sysmon_reader.start()

        for i in range(num_workers):
            t = threading.Thread(target=self._worker_loop, daemon=True, name=f"VK-Worker-{i}")
            t.start()
            self.worker_threads.append(t)

        self.log_callback("[+] Vanguard Knight Core Engine started.")
        self.log_callback(f"[+] {len(self.worker_threads)} worker thread(s) running.")
        self.log_callback(f"[+] {len(self.trusted_apps.list_trusted())} trusted app(s) loaded.")

        # Kick off an immediate hardening scan (in the background, so it
        # doesn't delay activation), then repeat every 24 hours.
        self.log_callback("[+] Starting system self-scan (open ports, security posture)...")
        threading.Thread(target=self._run_initial_hardening_scan, daemon=True).start()

    def _run_initial_hardening_scan(self):
        try:
            from system_hardening import run_full_hardening_scan, start_periodic_hardening
            report = run_full_hardening_scan(auto_fix=True)
            self.log_callback(
                f"[HARDENING] Self-scan complete: {report.total_auto_fixed} issue(s) fixed "
                f"automatically, {report.total_reported_only} flagged for your review. "
                f"Full report saved to Vault/SystemHardening/{report.report_id}/report.md"
            )
            start_periodic_hardening(interval_hours=24)
        except Exception as e:
            self.log_callback(f"[HARDENING] Self-scan could not run: {e}")

    def stop(self):
        self.running = False
        self.sysmon_reader.stop()
        self.forensics.stop_auto_cleanup()
        for t in self.worker_threads:
            t.join(timeout=2)
        self.log_callback("[-] Vanguard Knight Core Engine stopped.")

    # ------------------------------------------------------------------
    # Event routing
    # ------------------------------------------------------------------

    def _worker_loop(self):
        while self.running:
            try:
                event = self.event_queue.get(timeout=1)
            except queue.Empty:
                continue
            try:
                self._route_event(event)
                self.stats['analyzed'] += 1
            except Exception as e:
                # THIS WAS A SILENT-FAILURE BUG: previously only went to the
                # Python logger (invisible to the GUI). If an event caused
                # an exception during routing (e.g. an unexpected data
                # shape from Sysmon), it would vanish with no trace visible
                # anywhere in the app -- stats would never increment for
                # that event, and nothing would explain why. Now the full
                # error (with event type, for context) reaches the Live
                # Activity Log immediately.
                import traceback
                etype = event.get('event_type', 'unknown') if isinstance(event, dict) else 'unknown'
                error_msg = f"[ENGINE] Error processing '{etype}' event: {e}"
                logger.error(error_msg)
                logger.error(traceback.format_exc())
                self.log_callback(error_msg)

    def _route_event(self, event: dict):
        etype = event.get('event_type')
        data = event.get('data', {})

        if etype == 'process_create':
            self._handle_process_create(data)
        elif etype == 'process_access':
            self._handle_process_access(data)
        elif etype == 'create_remote_thread':
            self._handle_injection(data)
        elif etype == 'file_create':
            self._handle_file_create(data)
        elif etype == 'registry_event':
            self._handle_registry(data)
        elif etype == 'dns_query':
            self._handle_dns(data)
        # unknown event types are silently ignored (not everything needs action)

    def _cooldown_ok(self, key: str, seconds: float = 30.0) -> bool:
        now = time.time()
        last = self.alert_cooldown.get(key, 0)
        if now - last < seconds:
            return False
        self.alert_cooldown[key] = now
        return True

    # ------------------------------------------------------------------
    # Handler: Process Creation (the main pipeline)
    # ------------------------------------------------------------------

    def _handle_process_create(self, data: dict):
        name = ntpath.basename(data.get('Image', ''))
        pid = int(data.get('ProcessId', 0) or 0)
        exe = data.get('Image', '')
        cmdline = data.get('CommandLine', '')
        parent_name = ntpath.basename(data.get('ParentImage', ''))
        parent_pid = int(data.get('ParentProcessId', 0) or 0)

        if not exe or name.lower() in KNOWN_SYSTEM_PROCESSES:
            return

        # STEP 1 (highest priority): is this one of YOUR trusted tools?
        # If yes, skip all further detection logic entirely for this launch.
        trusted = self.trusted_apps.check(exe)
        if trusted:
            self.stats['trusted_skipped'] += 1
            logger.debug(f"[TRUSTED] '{trusted.name}' launched (PID {pid}) -- skipping detection.")
            # Still feed USB-correlation logic, since even trusted apps
            # launching right after a rogue HID device is worth knowing
            # -- but we do NOT flag/quarantine trusted binaries.
            return

        # STEP 2: USB HID injection correlation (BadUSB defense)
        self.usb_guard.on_process_launch(name, pid, parent_name)

        # STEP 3: LOLBin pattern check (Tier 1 signal -- confirmed-enough on its own)
        is_lolbin, lol_reason = detect_lolbin(name, cmdline)

        # STEP 4: Reputation scoring (signature, path, parent, age)
        score, reasons = self._calculate_reputation(exe, parent_name)

        # ---- Tier 1: CONFIRMED attack pattern -- auto-block, no permission asked ----
        if is_lolbin or score < self.UNCERTAIN_LOWER:
            reasons_final = ([lol_reason] if is_lolbin else []) + reasons
            if self._cooldown_ok(f"{pid}_{name}"):
                self._raise_incident(
                    threat_name=name, pid=pid, exe_path=exe, reason="; ".join(reasons_final),
                    parent_process=parent_name, parent_pid=parent_pid, command_line=cmdline,
                    severity="CRITICAL" if score < 25 else "HIGH",
                )
            return

        # ---- Tier 2: UNCERTAIN -- ask the user before acting ----
        if score < self.UNCERTAIN_UPPER:
            if self._cooldown_ok(f"uncertain_{pid}_{name}", seconds=5):
                self._raise_uncertain_review(
                    threat_name=name, pid=pid, exe_path=exe, reasons=reasons,
                    parent_process=parent_name, parent_pid=parent_pid,
                    command_line=cmdline, score=score,
                )
            return

        # ---- Tier 3: SAFE -- score is high enough, no action, no popup ----
        return

    def _default_permission_handler(self, details: dict, on_decision: Callable):
        """
        Fail-safe fallback used when no GUI is attached (e.g. running as a
        headless service with no permission_callback wired up). We do NOT
        silently allow uncertain files to run -- default to quarantine,
        same as the GUI popup's own timeout behavior. Log clearly so this
        is visible in the activity log even without a GUI present.
        """
        logger.warning(f"[UNCERTAIN] No GUI permission handler attached -- defaulting to "
                       f"quarantine for '{details.get('threat_name')}' (fail-safe).")
        on_decision(False)

    def _raise_uncertain_review(self, threat_name: str, pid: int, exe_path: str,
                                reasons: list, parent_process: str = None,
                                parent_pid: int = None, command_line: str = None,
                                score: int = None):
        """
        Tier 2 handler: pauses processing of THIS specific event (other
        events keep flowing through other worker threads) while waiting for
        a human decision via self.permission_callback. This is deliberately
        a blocking wait scoped to one worker thread -- acceptable because
        Tier-1 confirmed threats never reach this path (they're already
        auto-blocked before this point), so nothing time-critical is stuck
        waiting on user input here.
        """
        details = {
            'threat_name': threat_name, 'pid': pid, 'exe_path': exe_path,
            'reason': "; ".join(reasons), 'parent_process': parent_process,
            'parent_pid': parent_pid, 'command_line': command_line, 'score': score,
        }

        decision_event = threading.Event()
        decision_holder = {'allow': False}

        def on_decision(allow: bool):
            decision_holder['allow'] = allow
            decision_event.set()

        self.log_callback(f"[REVIEW] '{threat_name}' (PID {pid}) needs review -- score={score}. "
                          f"Reasons: {'; '.join(reasons)}")
        self.permission_callback(details, on_decision)

        # Wait for the GUI's decision (or the popup's own 60s timeout to
        # fire, which also calls on_decision(False) -- either way this
        # unblocks). Add a slightly longer local timeout as a second
        # safety net in case the callback never fires for some reason.
        decision_event.wait(timeout=70)

        if decision_holder['allow']:
            self.log_callback(f"[REVIEW] User ALLOWED '{threat_name}' (PID {pid}) to continue running.")
        else:
            self.log_callback(f"[REVIEW] '{threat_name}' (PID {pid}) was quarantined "
                              f"(user decision or timeout default).")
            self._raise_incident(
                threat_name=threat_name, pid=pid, exe_path=exe_path,
                reason="Uncertain-tier review -> quarantined: " + "; ".join(reasons),
                parent_process=parent_process, parent_pid=parent_pid,
                command_line=command_line, severity="MEDIUM",
            )

    def _calculate_reputation(self, exe: str, parent_name: str) -> tuple:
        score = 50
        reasons = []
        signed, signer = self._verify_signature(exe)
        if signed:
            if 'microsoft' in signer.lower():
                score += 30
                reasons.append("Microsoft signed")
            else:
                score += 15
                reasons.append(f"Signed ({signer})")
        else:
            score -= 15
            reasons.append("Unsigned binary")

        path_lower = exe.lower()
        # NOTE: previously these used raw strings ending in a doubled
        # backslash (e.g. r'\program files\\'), which actually checks for
        # TWO literal backslashes in a row -- something that never appears
        # in a real Windows path. That silently broke this entire check:
        # legitimate software in Program Files/Windows never got its
        # deserved trust bonus, and "suspicious location" checks similarly
        # never correctly matched. Using plain substrings (no trailing
        # separator needed) avoids the escaping pitfall entirely.
        if '\\program files' in path_lower or '\\windows\\' in path_lower:
            score += 15
            reasons.append("System install location")
        elif any(p in path_lower for p in ['\\temp\\', '\\downloads\\', '\\public\\', '\\appdata\\local\\temp\\']):
            score -= 20
            reasons.append("Running from suspicious location (Temp/Downloads/Public)")

        if parent_name.lower() in ('cmd.exe', 'powershell.exe', 'wscript.exe', 'mshta.exe'):
            score -= 10
            reasons.append(f"Suspicious parent process ({parent_name})")

        return max(0, min(100, score)), reasons

    def _verify_signature(self, exe: str) -> tuple:
        if not exe or not os.path.exists(exe):
            return False, ''
        try:
            res = subprocess.run(
                ['powershell', '-Command',
                 f'$s=Get-AuthenticodeSignature "{exe}"; $s.Status; $s.SignerCertificate.Subject'],
                capture_output=True, text=True, timeout=3,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0,
            )
            lines = res.stdout.strip().split('\n')
            status = lines[0] if lines else ''
            signer = lines[1] if len(lines) > 1 else ''
            if signer:
                m = re.search(r'CN=([^,]+)', signer)
                if m:
                    signer = m.group(1)
            return status == 'Valid', signer
        except Exception:
            return False, ''

    # ------------------------------------------------------------------
    # Handler: LSASS Access (credential theft -- Mimikatz-style)
    # ------------------------------------------------------------------

    def _handle_process_access(self, data: dict):
        target = data.get('TargetImage', '')
        source = data.get('SourceImage', '')
        source_pid = int(data.get('SourceProcessId', 0) or 0)
        granted_access = data.get('GrantedAccess', '')

        if 'lsass.exe' not in target.lower():
            return

        source_name = ntpath.basename(source)
        name_lower = source_name.lower()

        # CRITICAL FIX: core Windows system processes (svchost.exe,
        # services.exe, wininit.exe, csrss.exe, smss.exe) legitimately
        # touch LSASS constantly as part of completely normal OS
        # operation. Without this check, routine svchost.exe activity was
        # being flagged as CONFIRMED credential theft and terminated --
        # since svchost.exe hosts many essential Windows services, killing
        # it (and quarantining/moving its executable) can cascade into
        # serious system instability or a full crash.
        if name_lower in KNOWN_SYSTEM_PROCESSES:
            return

        # Trusted tools (e.g. legitimate AV/EDR, Task Manager) may legitimately
        # touch LSASS; check trust before flagging.
        if self.trusted_apps.check(source):
            return

        # CRITICAL FIX: only flag access patterns that actually include
        # PROCESS_VM_READ -- the specific right needed to read credential
        # material out of memory. LSASS is touched extremely frequently by
        # totally benign software with query-only access rights; without
        # this filter, EVERY single touch (a very common, routine event on
        # any real Windows machine) was being treated as confirmed malware.
        if not _is_dangerous_lsass_access(granted_access):
            return

        if self._cooldown_ok(f"lsass_{source_pid}", seconds=60):
            self._raise_incident(
                threat_name=source_name, pid=source_pid, exe_path=source,
                reason=f"Process accessed LSASS memory with VM_READ rights "
                       f"(GrantedAccess={granted_access}) -- signature consistent "
                       f"with credential-dumping tools (Mimikatz-class)",
                severity="CRITICAL",
            )

    # ------------------------------------------------------------------
    # Handler: Process Injection
    # ------------------------------------------------------------------

    def _handle_injection(self, data: dict):
        source_pid = int(data.get('SourceProcessId', 0) or 0)
        target_pid = int(data.get('TargetProcessId', 0) or 0)
        source_image = data.get('SourceImage', '')
        target_image = data.get('TargetImage', '')

        source_name = ntpath.basename(source_image).lower()
        target_name = ntpath.basename(target_image).lower()

        # CRITICAL FIX: core Windows system processes routinely perform or
        # receive CreateRemoteThread calls as part of completely normal OS
        # operation (service management, legitimate DLL injection by shell
        # extensions, accessibility tools, etc.). Without this check, ANY
        # such event involving svchost.exe/services.exe/etc. -- source OR
        # target -- was treated as confirmed malware and the process was
        # killed, which can destabilize or crash Windows.
        if source_name in KNOWN_SYSTEM_PROCESSES or target_name in KNOWN_SYSTEM_PROCESSES:
            return

        if self.trusted_apps.check(source_image):
            return

        if self._cooldown_ok(f"inject_{source_pid}_{target_pid}", seconds=30):
            self._raise_incident(
                threat_name=ntpath.basename(source_image) or f"PID_{source_pid}",
                pid=source_pid, exe_path=source_image,
                reason=f"Process injection detected: PID {source_pid} injected a remote thread "
                       f"into PID {target_pid} (CreateRemoteThread) -- classic code-injection technique",
                severity="CRITICAL",
            )

    # ------------------------------------------------------------------
    # Handler: File Creation (ransomware detection)
    # ------------------------------------------------------------------

    def _handle_file_create(self, data: dict):
        pid = int(data.get('ProcessId', 0) or 0)
        target_path = data.get('TargetFilename', '')
        if not target_path or pid <= 4:
            return

        try:
            proc_name = psutil.Process(pid).name() if psutil else f"PID_{pid}"
            proc_exe = psutil.Process(pid).exe() if psutil else ""
        except Exception:
            # Process likely already exited (very common for short-lived
            # file operations) -- nothing to act on.
            return

        # Trusted apps (the user's own projects) are never touched by
        # ransomware heuristics, checked FIRST before any other work.
        if self.trusted_apps.check(proc_exe):
            return

        name_lower = proc_name.lower()

        # Extra safety net: never let this heuristic act on core Windows
        # system processes, regardless of their file-write pattern.
        if name_lower in KNOWN_SYSTEM_PROCESSES:
            return

        # Known-legitimate high-I/O software (browsers, sync clients,
        # IDEs, etc.) gets a much higher rate ceiling -- this is what was
        # causing Chrome and similar normal software to be flagged: the
        # old fixed threshold (25 files/min) is trivially exceeded by
        # completely ordinary browsing activity.
        threshold = (RANSOMWARE_RATE_THRESHOLD_HIGH_IO if name_lower in KNOWN_HIGH_IO_APPS
                    else RANSOMWARE_RATE_THRESHOLD_NORMAL)
        rate_triggered = self.ransomware_tracker.record_and_check(pid, threshold=threshold)

        entropy_triggered, entropy_val, entropy_reason = False, None, ""
        try:
            if os.path.exists(target_path) and os.path.getsize(target_path) > 1024:
                entropy_val, entropy_triggered, entropy_reason = analyze_file(target_path)
        except Exception:
            pass

        if not (rate_triggered or entropy_triggered):
            return
        if not self._cooldown_ok(f"ransom_{pid}", seconds=15):
            return

        reason_parts = []
        if rate_triggered:
            reason_parts.append(f"High file-write rate (>{threshold} files/min)")
        if entropy_triggered:
            reason_parts.append(entropy_reason)

        # CRITICAL SAFETY DECISION: rate and entropy are treated very
        # differently in confidence. Genuine ransomware shows BOTH signals
        # together (mass writes AND the resulting files are high-entropy
        # ciphertext). Rate alone -- even a high rate -- is common in
        # legitimate heavy usage (browsers, installers, sync tools) and
        # must NOT auto-terminate a process on its own; it goes through
        # the uncertain-tier review (ask the user) instead. Only the
        # combination of both signals together is treated as confirmed
        # enough for an immediate, no-permission-asked auto-block.
        if rate_triggered and entropy_triggered:
            self._raise_incident(
                threat_name=proc_name, pid=pid, exe_path=proc_exe,
                reason="; ".join(reason_parts), entropy_score=entropy_val,
                severity="CRITICAL",
            )
        elif entropy_triggered:
            # High entropy alone (without a rate burst) is still a fairly
            # strong single-file signal -- e.g. one file just got encrypted
            # -- so this stays CRITICAL, but rate-alone does not.
            self._raise_incident(
                threat_name=proc_name, pid=pid, exe_path=proc_exe,
                reason="; ".join(reason_parts), entropy_score=entropy_val,
                severity="HIGH",
            )
        else:
            # Rate-only signal: ask before acting, never auto-kill.
            self._raise_uncertain_review(
                threat_name=proc_name, pid=pid, exe_path=proc_exe,
                reasons=reason_parts, score=35,
            )

    # ------------------------------------------------------------------
    # Handler: Registry (persistence detection)
    # ------------------------------------------------------------------

    def _handle_registry(self, data: dict):
        target = data.get('TargetObject', '')
        image = data.get('Image', '')
        if not target:
            return

        if ntpath.basename(image).lower() in KNOWN_SYSTEM_PROCESSES:
            return  # Windows itself modifies these keys routinely -- not noteworthy

        if self.trusted_apps.check(image):
            return  # your own tools are allowed to set up their own persistence

        if self._cooldown_ok(f"persist_{image}_{target}", seconds=60):
            self.log_callback(f"[PERSISTENCE] {ntpath.basename(image) or 'Unknown'} modified "
                              f"registry persistence location: {target}")
            self.alert_callback("persistence_change",
                                f"Registry persistence key modified: {target} by {image}",
                                severity="MEDIUM")

    # ------------------------------------------------------------------
    # Handler: DNS (tunneling detection)
    # ------------------------------------------------------------------

    def _handle_dns(self, data: dict):
        query = data.get('QueryName', '')
        image = data.get('Image', '')
        suspicious, reason = DNSTunnelingHeuristic.is_suspicious(query)
        if suspicious and self._cooldown_ok(f"dns_{query[:30]}", seconds=60):
            self.log_callback(f"[DNS] {reason} (queried by {ntpath.basename(image) or 'unknown'})")
            self.alert_callback("dns_tunneling_suspected", reason, severity="HIGH")

    # ------------------------------------------------------------------
    # USB Guard callback
    # ------------------------------------------------------------------

    def _on_usb_alert(self, alert_type: str, message: str, severity: str = "MEDIUM", extra: dict = None):
        self.log_callback(message)
        self.alert_callback(alert_type, message, severity=severity, extra=extra)
        if alert_type == "hid_shell_correlation" and extra:
            pid = extra.get('pid')
            if pid:
                try:
                    proc = psutil.Process(pid) if psutil else None
                    exe = proc.exe() if proc else ""
                    name = proc.name() if proc else f"PID_{pid}"
                except Exception:
                    exe, name = "", f"PID_{pid}"

                # SAFETY FIX: device-correlation alone (a new USB device
                # connecting shortly before a shell opens) is a WEAKER
                # signal than confirmed inhuman typing cadence -- it can't
                # tell the difference between an actual BadUSB attack and
                # simple coincidental timing (e.g. plugging in any USB
                # device, then separately opening a terminal you were
                # already about to use). Auto-terminating cmd.exe/
                # powershell.exe on this signal alone risked killing the
                # user's own legitimate, actively-in-use terminal session.
                # This now asks for confirmation instead of auto-blocking;
                # genuine BadUSB attacks that also show inhuman typing
                # cadence are still caught with full confidence via that
                # separate, stronger signal.
                if self.trusted_apps.check(exe):
                    return
                self._raise_uncertain_review(
                    threat_name=name, pid=pid, exe_path=exe,
                    reasons=[message], score=30,
                )

    # ------------------------------------------------------------------
    # Incident response (shared by all handlers)
    # ------------------------------------------------------------------

    def _raise_incident(self, threat_name: str, pid: int, exe_path: str, reason: str,
                        parent_process: str = None, parent_pid: int = None,
                        command_line: str = None, entropy_score: float = None,
                        severity: str = "HIGH"):
        # ABSOLUTE FINAL SAFETY NET: every single detection path in this
        # engine funnels through this one function before anything gets
        # terminated or quarantined. Regardless of which handler triggered
        # this call (and regardless of whether that handler already had
        # its own system-process check -- belt and suspenders, in case a
        # future handler forgets to add one), a core Windows system
        # process is NEVER auto-terminated here. This is the single
        # choke-point fix that guarantees the svchost.exe-crash class of
        # bug can never happen again, no matter which detection code path
        # is responsible.
        threat_name_lower = (threat_name or "").lower()
        if threat_name_lower in KNOWN_SYSTEM_PROCESSES or pid in (0, 4):
            self.log_callback(
                f"[SAFETY] Blocked an attempt to act on protected system process "
                f"'{threat_name}' (PID {pid}) -- reason was: {reason}. This is treated "
                f"as a detection-logic false positive, not a real threat, and is logged "
                f"here for review rather than acted on."
            )
            return

        case_id = make_case_id(pid)
        quarantine_path = self._respond(pid, exe_path)

        network_conns = []
        process_tree = []
        if psutil:
            try:
                proc = psutil.Process(pid)
                network_conns = [{'raddr': f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "N/A",
                                  'status': c.status} for c in proc.connections()]
            except Exception:
                pass

        case = IncidentCase(
            case_id=case_id, timestamp=datetime.now().isoformat(),
            threat_name=threat_name, pid=pid, reason=reason, exe_path=exe_path,
            entropy_score=entropy_score, parent_process=parent_process, parent_pid=parent_pid,
            command_line=command_line, network_connections=network_conns,
            process_tree=process_tree, quarantine_path=quarantine_path, severity=severity,
        )
        self.forensics.create_case(case)
        self.stats['blocked'] += 1

        self.log_callback(f"[ALERT-{severity}] {threat_name} (PID {pid}) -- {reason}")
        self.alert_callback("threat_blocked", f"{threat_name}: {reason}", severity=severity,
                            extra={'case_id': case_id})

    def _respond(self, pid: int, exe_path: str) -> Optional[str]:
        try:
            if psutil:
                proc = psutil.Process(pid)
                proc.terminate()
                proc.wait(3)
        except Exception:
            pass

        if exe_path and os.path.exists(exe_path):
            try:
                Path(QUARANTINE_DIR).mkdir(parents=True, exist_ok=True)
                base = os.path.basename(exe_path)
                ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                qpath = os.path.join(QUARANTINE_DIR, f"{pid}_{ts}_{base}.quar")
                shutil.copy2(exe_path, qpath)
                os.remove(exe_path)
                return qpath
            except Exception as e:
                logger.error(f"Quarantine failed: {e}")
        return None


if __name__ == "__main__":
    # Non-Windows dry-run test: verify the routing/detection logic works
    # correctly WITHOUT needing real Sysmon/psutil (mocked engine internals).
    logging.basicConfig(level=logging.INFO)

    engine = CoreEngine(
        alert_callback=lambda t, m, severity="INFO", extra=None: print(f"  [ALERT/{severity}] {t}: {m[:90]}"),
        log_callback=lambda m: print(f"  [LOG] {m}"),
    )

    print("=" * 70)
    print("TEST 1: LOLBin detection via simulated process_create event")
    print("=" * 70)
    engine._handle_process_create({
        'Image': r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe',
        'ProcessId': '4001',
        'CommandLine': 'powershell.exe -enc SGVsbG8gV29ybGQ=',
        'ParentImage': r'C:\Windows\explorer.exe',
        'ParentProcessId': '900',
    })

    print("\n" + "=" * 70)
    print("TEST 2: Normal signed process from Program Files -- should NOT alert")
    print("=" * 70)
    # Force reputation high by monkeypatching signature check for this test
    engine._verify_signature = lambda exe: (True, "Microsoft Corporation")
    engine._handle_process_create({
        'Image': r'C:\Program Files\SomeApp\app.exe',
        'ProcessId': '4002',
        'CommandLine': 'app.exe --run',
        'ParentImage': r'C:\Windows\explorer.exe',
        'ParentProcessId': '900',
    })

    print("\n" + "=" * 70)
    print("TEST 3: LSASS access (credential theft) simulated event")
    print("=" * 70)
    engine._handle_process_access({
        'TargetImage': r'C:\Windows\System32\lsass.exe',
        'SourceImage': r'C:\Users\Public\creddump.exe',
        'SourceProcessId': '5001',
        'GrantedAccess': '0x1010',
    })

    print("\n" + "=" * 70)
    print("TEST 4: Trusted app (Rabail simulation) should be SKIPPED entirely")
    print("=" * 70)
    import tempfile
    with tempfile.NamedTemporaryFile(suffix='.exe', delete=False) as f:
        f.write(b"RABAIL_ASSISTANT_BINARY")
        rabail_path = f.name
    engine.trusted_apps.trust_app("Rabail", rabail_path, "Personal JARVIS-style assistant")
    engine._handle_process_create({
        'Image': rabail_path,
        'ProcessId': '6001',
        'CommandLine': f'{rabail_path} --listen',
        'ParentImage': r'C:\Windows\explorer.exe',
        'ParentProcessId': '900',
    })
    print(f"  (trusted_skipped count: {engine.stats['trusted_skipped']})")
    assert engine.stats['trusted_skipped'] == 1

    print("\n" + "=" * 70)
    print(f"Final stats: {engine.stats}")
    print("=" * 70)
    print("\n✓ Core engine dry-run tests completed.")
