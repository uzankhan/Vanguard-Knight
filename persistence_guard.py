#!/usr/bin/env python3
"""
Vanguard Knight - Log Tamper & Extended Persistence Detection
==================================================================
Do gaps close kar rahe hain:

1. EVENT LOG CLEARING DETECTION
   Attacker apne traces mitane ke liye Windows Event Log clear karta hai
   (Security-Auditing Event ID 1102, ya Sysmon log khud clear karna).
   Ye khud EK STRONG SIGNAL hai -- koi legitimate reason nahi hota poora
   event log clear karne ka. Isko catch karna zaroori hai kyunki agar
   Vanguard Knight Sysmon logs pe depend karta hai, aur attacker wo logs
   hi clear kar de, to hum "blind" ho jate hain -- is event ko catch karna
   khud ek self-protection feature bhi hai.

2. SCHEDULED TASK + WMI PERSISTENCE
   Registry Run keys ke ilawa, malware persistence ke liye ye bhi use karta
   hai:
   - Scheduled Tasks (schtasks.exe se create hote hain, ya Task Scheduler
     COM API se)
   - WMI Event Subscriptions (permanent WMI backdoors -- bohat stealthy,
     kam log hote hain traditional tools mein)

   Dono ko Sysmon Event ID 1 (process creation) ke through track karte hain
   -- jab bhi 'schtasks.exe /create' ya WMI subscription-creation commands
   chalein.
"""

import re
import logging
from datetime import datetime
from typing import Optional, Callable, List
from dataclasses import dataclass

logger = logging.getLogger("VanguardKnight.PersistenceGuard")

# Event ID 1102 = "The audit log was cleared" (Security log)
# Sysmon Event ID 1 with wevtutil/Clear-EventLog command = Sysmon log itself cleared
EVENT_ID_LOG_CLEARED = 1102

SCHTASKS_CREATE_PATTERN = re.compile(r'/create', re.IGNORECASE)
WMI_SUBSCRIPTION_INDICATORS = [
    '__eventfilter', '__eventconsumer', '__filtertoconsumerbinding',
    'commandlineeventconsumer', 'activescripteventconsumer',
]
LOG_CLEAR_COMMAND_INDICATORS = [
    'wevtutil cl', 'wevtutil.exe cl', 'clear-eventlog', 'clear-log',
    'wevtutil el', # enumerate-then-clear pattern sometimes seen together
]


@dataclass
class PersistenceFinding:
    finding_type: str      # 'scheduled_task' | 'wmi_subscription' | 'log_cleared'
    process_name: str
    pid: int
    command_line: str
    detail: str
    severity: str = "HIGH"


class PersistenceAndTamperGuard:
    """
    Wire this into core_engine.py's process_create handler (feed every
    process_create event to check_process()) and into a Security-log
    watcher for check_security_log_event() (Event ID 1102).
    """

    def __init__(self, on_finding: Optional[Callable] = None):
        self.on_finding = on_finding or (lambda f: None)

    def check_process(self, process_name: str, pid: int, command_line: str) -> Optional[PersistenceFinding]:
        if not command_line:
            return None
        cmd_lower = command_line.lower()
        name_lower = process_name.lower()

        # --- Scheduled Task persistence ---
        if name_lower == 'schtasks.exe' and SCHTASKS_CREATE_PATTERN.search(cmd_lower):
            finding = PersistenceFinding(
                finding_type='scheduled_task', process_name=process_name, pid=pid,
                command_line=command_line,
                detail="New Scheduled Task created -- common persistence mechanism. "
                       "Review the task action/trigger to confirm legitimacy.",
                severity="MEDIUM",
            )
            self._emit(finding)
            return finding

        # --- WMI Event Subscription persistence (stealthy, less commonly monitored) ---
        if any(ind in cmd_lower for ind in WMI_SUBSCRIPTION_INDICATORS):
            finding = PersistenceFinding(
                finding_type='wmi_subscription', process_name=process_name, pid=pid,
                command_line=command_line,
                detail="WMI Event Subscription creation detected -- this is a stealthy "
                       "persistence technique (permanent WMI backdoor) often missed by "
                       "traditional monitoring. High-priority review recommended.",
                severity="HIGH",
            )
            self._emit(finding)
            return finding

        # --- Log clearing via command line (wevtutil/PowerShell) ---
        if any(ind in cmd_lower for ind in LOG_CLEAR_COMMAND_INDICATORS):
            finding = PersistenceFinding(
                finding_type='log_cleared', process_name=process_name, pid=pid,
                command_line=command_line,
                detail="Command-line event log clearing detected. This is a classic "
                       "anti-forensics move -- an attacker covering their tracks after "
                       "an intrusion. Treat as high-confidence evidence of compromise.",
                severity="CRITICAL",
            )
            self._emit(finding)
            return finding

        return None

    def check_security_log_event(self, event_id: int, source_process: str = "unknown",
                                  pid: int = 0) -> Optional[PersistenceFinding]:
        """Call this from a Security-channel event watcher for Event ID 1102."""
        if event_id != EVENT_ID_LOG_CLEARED:
            return None
        finding = PersistenceFinding(
            finding_type='log_cleared', process_name=source_process, pid=pid,
            command_line="", detail="Windows Security Audit Log was CLEARED (Event ID 1102). "
                                     "This is one of the strongest anti-forensics signals -- "
                                     "attackers clear this log specifically to hide their tracks "
                                     "after gaining access. Investigate immediately.",
            severity="CRITICAL",
        )
        self._emit(finding)
        return finding

    def _emit(self, finding: PersistenceFinding):
        logger.log(
            logging.CRITICAL if finding.severity == "CRITICAL" else logging.WARNING,
            f"[PERSISTENCE/{finding.severity}] {finding.finding_type}: {finding.detail}"
        )
        self.on_finding(finding)


if __name__ == "__main__":
    findings_captured = []
    guard = PersistenceAndTamperGuard(on_finding=lambda f: findings_captured.append(f))

    print("=" * 70)
    print("TEST 1: Scheduled Task creation")
    print("=" * 70)
    r = guard.check_process("schtasks.exe", 3001,
                            'schtasks.exe /create /tn "UpdaterTask" /tr "malware.exe" /sc onlogon')
    assert r is not None and r.finding_type == 'scheduled_task'
    print(f"✓ Detected: {r.finding_type} (severity={r.severity})")

    print("\n" + "=" * 70)
    print("TEST 2: WMI Event Subscription (stealthy persistence)")
    print("=" * 70)
    r = guard.check_process("wmic.exe", 3002,
                            'wmic.exe /namespace:\\\\root\\subscription PATH __EventFilter CREATE ...')
    assert r is not None and r.finding_type == 'wmi_subscription'
    print(f"✓ Detected: {r.finding_type} (severity={r.severity})")

    print("\n" + "=" * 70)
    print("TEST 3: Log clearing via wevtutil (anti-forensics)")
    print("=" * 70)
    r = guard.check_process("cmd.exe", 3003, 'cmd.exe /c wevtutil cl Security')
    assert r is not None and r.finding_type == 'log_cleared'
    assert r.severity == "CRITICAL"
    print(f"✓ Detected: {r.finding_type} (severity={r.severity})")

    print("\n" + "=" * 70)
    print("TEST 4: Security Event ID 1102 (log cleared via audit event)")
    print("=" * 70)
    r = guard.check_security_log_event(1102, source_process="unknown", pid=0)
    assert r is not None
    print(f"✓ Detected Event ID 1102 log-clear event (severity={r.severity})")

    print("\n" + "=" * 70)
    print("TEST 5: Normal, benign process launch -- should NOT trigger")
    print("=" * 70)
    r = guard.check_process("notepad.exe", 3004, "notepad.exe document.txt")
    assert r is None
    print("✓ Benign process correctly ignored")

    print(f"\nTotal findings captured across tests: {len(findings_captured)}")
    print("All persistence/tamper-guard self-tests passed.")
