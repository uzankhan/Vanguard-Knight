#!/usr/bin/env python3
"""
Vanguard Knight - System Hardening (Self-Scan + Auto-Remediation)
======================================================================
Scans THIS machine's own attack surface (open ports, risky legacy
services, security-feature status) and, where it's genuinely SAFE to do
so automatically, fixes what it finds. Everything is written to a
plain-English report in the Vault, and old reports are purged after 7
days (matching forensics.py's retention pattern).

SAFETY PHILOSOPHY -- this is the most important design decision here:
Not every finding is auto-fixed. Findings are split into two categories:

  AUTO-FIXABLE (safe to fix without asking):
    Legacy protocols and features that are essentially NEVER intentionally
    needed by an ordinary user and are almost always either leftover
    defaults or misconfigurations (Telnet server, SMBv1). Also: turning
    ON a security feature that's OFF (Windows Firewall, Defender
    real-time protection) is always safe to automate -- there's no
    legitimate reason to want these off, and turning them ON can't break
    anything the user intentionally set up.

  REPORT-ONLY (flagged with a clear explanation + suggested fix, but
  NOT executed automatically):
    An arbitrary open port that matches a "commonly risky" pattern (e.g.
    port 5432/Postgres, 6379/Redis, 3389/RDP) might be something the user
    deliberately runs for their own development work. Automatically
    killing a database the user is actively using would be actively
    harmful. These are surfaced clearly so the user can decide.

This mirrors the same Tier-1/Tier-2 confirmed-vs-uncertain philosophy
used throughout the rest of Vanguard Knight: only act automatically on
things that are unambiguous.
"""

import os
import json
import shutil
import logging
import subprocess
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Optional
from dataclasses import dataclass, field, asdict

from network_recon import scan_ports, RISKY_SERVICES

logger = logging.getLogger("VanguardKnight.SystemHardening")

VAULT_DIR = r"C:\VanguardKnight_Vault"
HARDENING_DIR = os.path.join(VAULT_DIR, "SystemHardening")
RETENTION_DAYS = 7

# Windows service names for legacy protocols that are essentially never
# intentionally needed and are always safe to disable automatically.
AUTO_FIXABLE_SERVICES = {
    23: {'service': 'TlntSvr', 'label': 'Telnet Server',
        'reason': 'Telnet transmits everything -- including passwords -- in plain text. '
                  'There is no legitimate reason for this to be running on a personal machine.'},
}

# Ports that are commonly risky but MIGHT be something the user
# deliberately runs (databases, RDP for legitimate remote access, etc.) --
# these are reported with a clear recommendation but never auto-closed.
REPORT_ONLY_PORTS = {21, 135, 139, 445, 1433, 3306, 3389, 5900, 6379, 27017}


@dataclass
class HardeningFinding:
    port: Optional[int]
    service_name: str
    risk_description: str
    action_taken: str  # "auto_fixed" | "reported_only" | "already_secure"
    fix_command: Optional[str] = None


@dataclass
class SecurityPostureCheck:
    feature: str
    was_enabled: bool
    action_taken: str  # "already_enabled" | "auto_enabled" | "check_failed"


@dataclass
class HardeningReport:
    report_id: str
    timestamp: str
    port_findings: List[HardeningFinding] = field(default_factory=list)
    posture_checks: List[SecurityPostureCheck] = field(default_factory=list)
    total_auto_fixed: int = 0
    total_reported_only: int = 0


def _run_powershell(command: str, timeout: int = 15) -> Optional[str]:
    try:
        result = subprocess.run(
            ['powershell', '-NoProfile', '-Command', command],
            capture_output=True, text=True, timeout=timeout,
        )
        return result.stdout.strip()
    except Exception as e:
        logger.error(f"PowerShell command failed: {e}")
        return None


def _check_and_fix_firewall() -> SecurityPostureCheck:
    """Windows Firewall should always be on -- enabling it if it's off is
    always safe (there's no legitimate reason to want it disabled)."""
    output = _run_powershell(
        "(Get-NetFirewallProfile -Profile Domain,Public,Private | "
        "Where-Object {$_.Enabled -eq 'False'}).Count"
    )
    already_on = (output == '0' or output == '')
    if already_on:
        return SecurityPostureCheck("Windows Firewall", True, "already_enabled")

    fix_result = _run_powershell("Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True")
    success = fix_result is not None
    return SecurityPostureCheck("Windows Firewall", False,
                                "auto_enabled" if success else "check_failed")


def _check_and_fix_defender() -> SecurityPostureCheck:
    """Windows Defender real-time protection should always be on (unless
    a third-party AV is installed and managing this deliberately -- we
    check for that first to avoid fighting another security product)."""
    third_party_av = _run_powershell(
        "(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | "
        "Where-Object {$_.displayName -notlike '*Defender*'}).Count"
    )
    if third_party_av and third_party_av != '0':
        return SecurityPostureCheck("Windows Defender Real-Time Protection", True, "already_enabled")

    output = _run_powershell("(Get-MpPreference).DisableRealtimeMonitoring")
    already_on = (output == 'False')
    if already_on:
        return SecurityPostureCheck("Windows Defender Real-Time Protection", True, "already_enabled")

    fix_result = _run_powershell("Set-MpPreference -DisableRealtimeMonitoring $false")
    success = fix_result is not None
    return SecurityPostureCheck("Windows Defender Real-Time Protection", False,
                                "auto_enabled" if success else "check_failed")


def _check_smb1() -> SecurityPostureCheck:
    """SMBv1 is a legacy, vulnerable protocol (the EternalBlue/WannaCry
    exploit family targeted it directly) -- disabling it if enabled is safe;
    modern Windows/software has not required SMBv1 for many years."""
    output = _run_powershell(
        "(Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol).State"
    )
    if output is None:
        return SecurityPostureCheck("SMBv1 Protocol", False, "check_failed")
    if output == 'Disabled':
        return SecurityPostureCheck("SMBv1 Protocol (legacy, vulnerable)", True, "already_enabled")

    fix_result = _run_powershell(
        "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart"
    )
    success = fix_result is not None
    return SecurityPostureCheck("SMBv1 Protocol (legacy, vulnerable)", False,
                                "auto_enabled" if success else "check_failed")


def _fix_telnet_server() -> Optional[str]:
    """Stops and disables the Telnet server service. Returns the command
    used, for the report, or None if the service isn't present/failed."""
    check = _run_powershell("(Get-Service -Name TlntSvr -ErrorAction SilentlyContinue).Status")
    if not check:
        return None  # not installed -- nothing to fix
    _run_powershell("Stop-Service -Name TlntSvr -Force -ErrorAction SilentlyContinue")
    _run_powershell("Set-Service -Name TlntSvr -StartupType Disabled -ErrorAction SilentlyContinue")
    return "Stop-Service TlntSvr; Set-Service TlntSvr -StartupType Disabled"


def run_full_hardening_scan(auto_fix: bool = True) -> HardeningReport:
    """
    Main entry point: scans localhost for open/risky ports, checks core
    security posture (Firewall, Defender, SMBv1), auto-fixes what's safe
    to auto-fix, and reports the rest for manual review.
    """
    report_id = f"HARDEN-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
    logger.info(f"[HARDENING] Starting system self-scan ({report_id})...")

    findings: List[HardeningFinding] = []

    try:
        scanned = scan_ports("127.0.0.1")
        for port_result in scanned.ports:
            if port_result.state != 'open' or not port_result.is_risky:
                continue

            port = port_result.port
            if port in AUTO_FIXABLE_SERVICES and auto_fix:
                fix_info = AUTO_FIXABLE_SERVICES[port]
                cmd = _fix_telnet_server() if port == 23 else None
                if cmd:
                    findings.append(HardeningFinding(
                        port=port, service_name=fix_info['service'],
                        risk_description=fix_info['reason'],
                        action_taken="auto_fixed", fix_command=cmd,
                    ))
                    logger.info(f"[HARDENING] Auto-fixed: {fix_info['service']} (port {port})")
                else:
                    findings.append(HardeningFinding(
                        port=port, service_name=fix_info['service'],
                        risk_description=fix_info['reason'] + " (service not present or fix failed)",
                        action_taken="already_secure",
                    ))
            else:
                findings.append(HardeningFinding(
                    port=port, service_name=port_result.service,
                    risk_description=port_result.risk_note,
                    action_taken="reported_only",
                    fix_command=f"Review what's using port {port} and close it manually if unneeded "
                               f"(e.g. via 'netsh advfirewall firewall add rule ... action=block').",
                ))
    except Exception as e:
        logger.error(f"[HARDENING] Port scan failed: {e}")

    posture_checks = []
    if auto_fix:
        try:
            posture_checks.append(_check_and_fix_firewall())
            posture_checks.append(_check_and_fix_defender())
            posture_checks.append(_check_smb1())
        except Exception as e:
            logger.error(f"[HARDENING] Posture check failed: {e}")

    report = HardeningReport(
        report_id=report_id,
        timestamp=datetime.now().isoformat(),
        port_findings=findings,
        posture_checks=posture_checks,
        total_auto_fixed=sum(1 for f in findings if f.action_taken == "auto_fixed") +
                         sum(1 for p in posture_checks if p.action_taken == "auto_enabled"),
        total_reported_only=sum(1 for f in findings if f.action_taken == "reported_only"),
    )

    _write_report(report)
    logger.info(f"[HARDENING] Scan complete: {report.total_auto_fixed} auto-fixed, "
               f"{report.total_reported_only} flagged for manual review.")
    return report


def _write_report(report: HardeningReport):
    Path(HARDENING_DIR).mkdir(parents=True, exist_ok=True)
    folder = Path(HARDENING_DIR) / report.report_id
    folder.mkdir(parents=True, exist_ok=True)

    (folder / "report.json").write_text(json.dumps(asdict(report), indent=2), encoding='utf-8')

    lines = [
        "# Vanguard Knight -- System Hardening Report",
        f"\n**Scan ID:** {report.report_id}",
        f"**Time:** {report.timestamp}",
        f"\n## Summary",
        f"- {report.total_auto_fixed} issue(s) automatically fixed",
        f"- {report.total_reported_only} issue(s) flagged for your review (not auto-changed, "
        f"since they might be something you deliberately run)",
        "\n## Open Ports & Risky Services",
    ]
    if report.port_findings:
        for f in report.port_findings:
            status_label = {
                "auto_fixed": "FIXED AUTOMATICALLY",
                "reported_only": "NEEDS YOUR REVIEW",
                "already_secure": "OK",
            }.get(f.action_taken, f.action_taken)
            lines.append(f"\n### Port {f.port} -- {f.service_name} [{status_label}]")
            lines.append(f"{f.risk_description}")
            if f.fix_command:
                lines.append(f"\n`{f.fix_command}`")
    else:
        lines.append("\nNo risky open ports found. Good.")

    lines.append("\n## Security Feature Status")
    if report.posture_checks:
        for p in report.posture_checks:
            status_label = {
                "already_enabled": "Already ON (good)",
                "auto_enabled": "Was OFF -- turned ON automatically",
                "check_failed": "Could not check (may need Administrator rights)",
            }.get(p.action_taken, p.action_taken)
            lines.append(f"- **{p.feature}**: {status_label}")
    else:
        lines.append("\nNot checked this run.")

    lines.append(f"\n---\n*This report will be automatically removed after {RETENTION_DAYS} days.*")
    (folder / "report.md").write_text("\n".join(lines), encoding='utf-8')


def cleanup_old_reports() -> int:
    """Removes hardening reports older than RETENTION_DAYS. Same pattern
    as forensics.py's retention cleanup."""
    if not os.path.exists(HARDENING_DIR):
        return 0
    cutoff = datetime.now() - timedelta(days=RETENTION_DAYS)
    removed = 0
    for folder in Path(HARDENING_DIR).iterdir():
        if not folder.is_dir():
            continue
        try:
            parts = folder.name.split('-')
            if len(parts) >= 3:
                folder_time = datetime.strptime(parts[1] + parts[2], "%Y%m%d%H%M%S")
            else:
                folder_time = datetime.fromtimestamp(folder.stat().st_mtime)
            if folder_time < cutoff:
                shutil.rmtree(folder, ignore_errors=True)
                removed += 1
        except Exception as e:
            logger.warning(f"[HARDENING] Could not evaluate {folder.name} for cleanup: {e}")
    if removed:
        logger.info(f"[HARDENING] Cleaned up {removed} report(s) older than {RETENTION_DAYS} days.")
    return removed


def start_periodic_hardening(interval_hours: int = 24):
    """Runs a hardening scan + cleanup on a recurring schedule in the
    background. Call once when the engine starts."""
    def loop():
        while True:
            try:
                run_full_hardening_scan(auto_fix=True)
                cleanup_old_reports()
            except Exception as e:
                logger.error(f"[HARDENING] Periodic scan failed: {e}")
            time.sleep(interval_hours * 3600)
    threading.Thread(target=loop, daemon=True).start()


if __name__ == "__main__":
    import tempfile

    HARDENING_DIR = tempfile.mkdtemp()

    print("=" * 70)
    print("TEST 1: Report generation with mixed findings")
    print("=" * 70)
    test_report = HardeningReport(
        report_id="HARDEN-TEST-001",
        timestamp=datetime.now().isoformat(),
        port_findings=[
            HardeningFinding(port=23, service_name="Telnet Server",
                            risk_description="Transmits passwords in plain text.",
                            action_taken="auto_fixed", fix_command="Stop-Service TlntSvr"),
            HardeningFinding(port=3389, service_name="RDP",
                            risk_description="Verify Network Level Authentication is enabled.",
                            action_taken="reported_only"),
        ],
        posture_checks=[
            SecurityPostureCheck("Windows Firewall", False, "auto_enabled"),
            SecurityPostureCheck("Windows Defender Real-Time Protection", True, "already_enabled"),
        ],
        total_auto_fixed=2, total_reported_only=1,
    )
    _write_report(test_report)
    report_folder = Path(HARDENING_DIR) / "HARDEN-TEST-001"
    assert (report_folder / "report.json").exists()
    assert (report_folder / "report.md").exists()
    print("✓ Both JSON and Markdown reports generated correctly")

    md_content = (report_folder / "report.md").read_text()
    assert "Telnet Server" in md_content
    assert "FIXED AUTOMATICALLY" in md_content
    assert "NEEDS YOUR REVIEW" in md_content
    print("✓ Report correctly distinguishes auto-fixed vs needs-review items")

    print("\n" + "=" * 70)
    print("TEST 2: 7-day retention cleanup")
    print("=" * 70)
    old_report = HardeningReport(
        report_id=f"HARDEN-{(datetime.now() - timedelta(days=10)).strftime('%Y%m%d-%H%M%S')}",
        timestamp=(datetime.now() - timedelta(days=10)).isoformat(),
    )
    _write_report(old_report)
    old_folder = Path(HARDENING_DIR) / old_report.report_id
    assert old_folder.exists()

    removed = cleanup_old_reports()
    assert removed == 1, f"Expected 1 old report removed, got {removed}"
    assert not old_folder.exists(), "Old report should be deleted!"
    assert report_folder.exists(), "Fresh report should survive cleanup!"
    print("✓ 7-day-old report correctly purged, fresh report correctly preserved")

    print("\nAll system-hardening self-tests passed.")
