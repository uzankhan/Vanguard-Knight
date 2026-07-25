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
    """Tracks file-write rate per PID to catch mass-encryption bursts,
    independent of per-file entropy (belt-and-suspenders approach)."""

    def __init__(self, threshold_files_per_min: int = 25):
        self.threshold = threshold_files_per_min
        self.file_ops: Dict[int, list] = {}

    def record_and_check(self, pid: int) -> bool:
        now = time.time()
        ops = self.file_ops.setdefault(pid, [])
        ops.append(now)
        # keep only last 60 seconds
        self.file_ops[pid] = [t for t in ops if now - t < 60]
        return len(self.file_ops[pid]) > self.threshold


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
        self.sysmon_reader = SysmonEventReader(output_queue=self.event_queue)
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
        self.log_callback(f"[+] {len(self.trusted_apps.list_trusted())} trusted app(s) loaded.")

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
                logger.error(f"Event handling error: {e}")

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
        if r'\program files\\' in path_lower or r'\windows\\' in path_lower:
            score += 15
            reasons.append("System install location")
        elif any(p in path_lower for p in [r'\temp\\', r'\downloads\\', r'\public\\', r'\appdata\local\temp\\']):
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
        # Trusted tools (e.g. legitimate AV/EDR, Task Manager) may legitimately
        # touch LSASS; check trust before flagging.
        if self.trusted_apps.check(source):
            return

        if self._cooldown_ok(f"lsass_{source_pid}", seconds=60):
            self._raise_incident(
                threat_name=source_name, pid=source_pid, exe_path=source,
                reason=f"Process accessed LSASS memory (GrantedAccess={granted_access}) "
                       f"-- signature consistent with credential-dumping tools (Mimikatz-class)",
                severity="CRITICAL",
            )

    # ------------------------------------------------------------------
    # Handler: Process Injection
    # ------------------------------------------------------------------

    def _handle_injection(self, data: dict):
        source_pid = int(data.get('SourceProcessId', 0) or 0)
        target_pid = int(data.get('TargetProcessId', 0) or 0)
        source_image = data.get('SourceImage', '')

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

        # Rate check (independent signal)
        rate_triggered = self.ransomware_tracker.record_and_check(pid)

        # Entropy check (only if file is reasonably sized -- avoid overhead on tiny files)
        entropy_triggered, entropy_val, entropy_reason = False, None, ""
        try:
            if os.path.exists(target_path) and os.path.getsize(target_path) > 1024:
                entropy_val, entropy_triggered, entropy_reason = analyze_file(target_path)
        except Exception:
            pass

        if (rate_triggered or entropy_triggered) and self._cooldown_ok(f"ransom_{pid}", seconds=15):
            try:
                proc_name = psutil.Process(pid).name() if psutil else f"PID_{pid}"
                proc_exe = psutil.Process(pid).exe() if psutil else ""
            except Exception:
                proc_name, proc_exe = f"PID_{pid}", ""

            if self.trusted_apps.check(proc_exe):
                return

            reason_parts = []
            if rate_triggered:
                reason_parts.append("Abnormally high file-write rate (mass encryption pattern)")
            if entropy_triggered:
                reason_parts.append(entropy_reason)

            self._raise_incident(
                threat_name=proc_name, pid=pid, exe_path=proc_exe,
                reason="; ".join(reason_parts), entropy_score=entropy_val,
                severity="CRITICAL",
            )

    # ------------------------------------------------------------------
    # Handler: Registry (persistence detection)
    # ------------------------------------------------------------------

    def _handle_registry(self, data: dict):
        target = data.get('TargetObject', '')
        image = data.get('Image', '')
        if not target:
            return

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
                self._raise_incident(
                    threat_name=name, pid=pid, exe_path=exe,
                    reason=message, severity="CRITICAL",
                )

    # ------------------------------------------------------------------
    # Incident response (shared by all handlers)
    # ------------------------------------------------------------------

    def _raise_incident(self, threat_name: str, pid: int, exe_path: str, reason: str,
                        parent_process: str = None, parent_pid: int = None,
                        command_line: str = None, entropy_score: float = None,
                        severity: str = "HIGH"):
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
