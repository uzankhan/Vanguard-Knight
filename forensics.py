#!/usr/bin/env python3
"""
Vanguard Knight - Forensics & Evidence Manager
=================================================
"SOC Analyst" feature ko strengthen kar rahe hain: jab bhi koi threat block/
quarantine hoti hai, ek complete incident case-file banti hai (jaisa real
SOC analyst banata hai) -- sirf file quarantine nahi, balke:

  - Kya process tha, kis parent se launch hua, kya command-line thi
  - Us waqt system pe kaun kaun se network connections active thay
  - File ka hash, entropy score, signature status
  - Poori process tree (ancestors + children) snapshot
  - Human-readable incident summary (taake baad mein khud padh kar samjho)
  - Har cheez ek dedicated per-incident folder mein, JSON + Markdown dono format mein

Phir 7-din-purani evidence apne aap delete hoti hai (disk space na bhare),
LEKIN delete karne se pehle ek chhota "index summary" (sirf metadata, files
nahi) permanent record mein reh jata hai -- taake purani history ka trace
rahe bina disk bhare.
"""

import json
import shutil
import logging
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict, List
from dataclasses import dataclass, asdict, field

logger = logging.getLogger("VanguardKnight.Forensics")

DEFAULT_FORENSICS_DIR = r"C:\VanguardKnight_Vault\Forensics"
DEFAULT_INDEX_FILE = r"C:\VanguardKnight_Vault\Forensics\_incident_index.json"
RETENTION_DAYS = 7


@dataclass
class IncidentCase:
    """A complete SOC-style case file for a single detected threat."""
    case_id: str                       # e.g. "VK-20260717-103045-4821"
    timestamp: str                     # ISO format
    threat_name: str                   # process name
    pid: int
    reason: str                        # why it was flagged
    exe_path: str
    sha256: Optional[str] = None
    entropy_score: Optional[float] = None
    signed: Optional[bool] = None
    signer: Optional[str] = None
    parent_process: Optional[str] = None
    parent_pid: Optional[int] = None
    command_line: Optional[str] = None
    network_connections: List[dict] = field(default_factory=list)
    process_tree: List[dict] = field(default_factory=list)  # ancestors + children snapshot
    action_taken: str = "terminated_and_quarantined"
    quarantine_path: Optional[str] = None
    severity: str = "HIGH"             # LOW / MEDIUM / HIGH / CRITICAL


class ForensicsManager:
    """
    Builds and manages per-incident evidence folders, and runs a background
    cleanup thread that purges evidence older than RETENTION_DAYS while
    keeping a lightweight permanent index of what happened.
    """

    def __init__(self, forensics_dir: str = DEFAULT_FORENSICS_DIR,
                 retention_days: int = RETENTION_DAYS):
        self.forensics_dir = Path(forensics_dir)
        self.forensics_dir.mkdir(parents=True, exist_ok=True)
        self.index_file = self.forensics_dir / "_incident_index.json"
        self.retention_days = retention_days
        self._cleanup_thread = None
        self._running = False

    # ---------------------- Case creation ----------------------

    def create_case(self, case: IncidentCase) -> Path:
        """
        Creates a dedicated folder for this incident:
            Forensics/VK-20260717-103045-4821/
                case_summary.json      <- structured data for programs
                case_report.md         <- human-readable report for you
                (quarantined binary copy is referenced, not duplicated here
                 -- it already lives in the Quarantine folder)
        """
        case_folder = self.forensics_dir / case.case_id
        case_folder.mkdir(parents=True, exist_ok=True)

        # Machine-readable
        (case_folder / "case_summary.json").write_text(
            json.dumps(asdict(case), indent=2), encoding='utf-8'
        )

        # Human-readable Markdown report -- this is the "SOC analyst" touch:
        # a real analyst would write exactly this kind of incident summary.
        report = self._build_markdown_report(case)
        (case_folder / "case_report.md").write_text(report, encoding='utf-8')

        # Update the lightweight permanent index (kept even after the full
        # evidence folder is cleaned up after retention_days)
        self._append_to_index(case)

        logger.info(f"[FORENSICS] Case {case.case_id} created at {case_folder}")
        return case_folder

    def _build_markdown_report(self, case: IncidentCase) -> str:
        conn_lines = "\n".join(
            f"  - {c.get('raddr', 'N/A')} (status: {c.get('status', 'N/A')})"
            for c in case.network_connections
        ) or "  - None observed"

        tree_lines = "\n".join(
            f"  - {p.get('name', '?')} (PID {p.get('pid', '?')}) - {p.get('relation', '?')}"
            for p in case.process_tree
        ) or "  - Not captured"

        return f"""# Vanguard Knight - Incident Report

**Case ID:** {case.case_id}
**Timestamp:** {case.timestamp}
**Severity:** {case.severity}

## Summary
Process **{case.threat_name}** (PID {case.pid}) was flagged and **{case.action_taken}**.

**Reason for detection:** {case.reason}

## Process Details
| Field | Value |
|---|---|
| Executable Path | `{case.exe_path}` |
| SHA-256 | `{case.sha256 or 'not computed'}` |
| Entropy Score | {case.entropy_score if case.entropy_score is not None else 'N/A'} / 8.0 |
| Digitally Signed | {case.signed if case.signed is not None else 'Unknown'} |
| Signer | {case.signer or 'N/A'} |
| Parent Process | {case.parent_process or 'Unknown'} (PID {case.parent_pid or 'N/A'}) |
| Command Line | `{case.command_line or 'Not captured'}` |

## Network Connections at Time of Detection
{conn_lines}

## Process Tree Snapshot
{tree_lines}

## Action Taken
- Action: **{case.action_taken}**
- Quarantine location: `{case.quarantine_path or 'N/A'}`

---
*This report was auto-generated by Vanguard Knight's forensics engine.
Evidence for this case will be automatically purged after {RETENTION_DAYS} days
to manage disk space; this summary's metadata will remain in the permanent
incident index.*
"""

    def _append_to_index(self, case: IncidentCase):
        """Lightweight permanent record -- survives even after the full
        evidence folder is cleaned up. Just enough to answer 'what happened
        and when', not the full forensic bundle."""
        index = self._load_index()
        index.append({
            'case_id': case.case_id,
            'timestamp': case.timestamp,
            'threat_name': case.threat_name,
            'reason': case.reason,
            'severity': case.severity,
            'sha256': case.sha256,
        })
        self.index_file.write_text(json.dumps(index, indent=2), encoding='utf-8')

    def _load_index(self) -> list:
        if self.index_file.exists():
            try:
                return json.loads(self.index_file.read_text(encoding='utf-8'))
            except Exception:
                return []
        return []

    # ---------------------- Retention / cleanup ----------------------

    def start_auto_cleanup(self, check_interval_seconds: int = 3600):
        """Starts a background thread that checks hourly for evidence older
        than retention_days and removes it (index entries are preserved)."""
        self._running = True
        self._cleanup_thread = threading.Thread(
            target=self._cleanup_loop, args=(check_interval_seconds,), daemon=True
        )
        self._cleanup_thread.start()
        logger.info(f"[FORENSICS] Auto-cleanup started (retention={self.retention_days} days).")

    def stop_auto_cleanup(self):
        self._running = False
        if self._cleanup_thread:
            self._cleanup_thread.join(timeout=2)

    def _cleanup_loop(self, interval: int):
        while self._running:
            try:
                self.run_cleanup_now()
            except Exception as e:
                logger.error(f"[FORENSICS] Cleanup error: {e}")
            time.sleep(interval)

    def run_cleanup_now(self) -> int:
        """
        Deletes case folders older than retention_days. Returns count removed.
        Safe to call manually any time (e.g. wired up to a GUI 'Clean Now' button).
        """
        cutoff = datetime.now() - timedelta(days=self.retention_days)
        removed = 0

        for case_folder in self.forensics_dir.iterdir():
            if not case_folder.is_dir():
                continue
            if case_folder.name.startswith('_'):
                continue  # skip internal files like _incident_index.json's folder guard

            try:
                # Parse timestamp from folder name: VK-YYYYMMDD-HHMMSS-PID
                parts = case_folder.name.split('-')
                if len(parts) >= 3:
                    date_str, time_str = parts[1], parts[2]
                    folder_time = datetime.strptime(date_str + time_str, "%Y%m%d%H%M%S")
                else:
                    # Fallback: use folder modification time if name doesn't parse
                    folder_time = datetime.fromtimestamp(case_folder.stat().st_mtime)

                if folder_time < cutoff:
                    shutil.rmtree(case_folder, ignore_errors=True)
                    removed += 1
                    logger.info(f"[FORENSICS] Purged expired evidence: {case_folder.name} "
                               f"(age > {self.retention_days} days)")
            except Exception as e:
                logger.warning(f"[FORENSICS] Could not evaluate {case_folder.name} for cleanup: {e}")

        if removed:
            logger.info(f"[FORENSICS] Cleanup complete -- {removed} expired case(s) removed. "
                       f"Their summaries remain in the permanent index.")
        return removed

    def get_incident_history(self, limit: int = 50) -> list:
        """Returns the permanent lightweight index -- works even for cases
        whose full evidence has already been cleaned up."""
        index = self._load_index()
        return index[-limit:]


def make_case_id(pid: int, dt: Optional[datetime] = None) -> str:
    """Generates a unique, sortable case ID: VK-YYYYMMDD-HHMMSS-PID"""
    dt = dt or datetime.now()
    return f"VK-{dt.strftime('%Y%m%d-%H%M%S')}-{pid}"


if __name__ == "__main__":
    import tempfile

    test_dir = tempfile.mkdtemp()
    fm = ForensicsManager(forensics_dir=test_dir, retention_days=7)

    # Create a "fresh" case (today)
    fresh_case = IncidentCase(
        case_id=make_case_id(4821),
        timestamp=datetime.now().isoformat(),
        threat_name="suspicious_loader.exe",
        pid=4821,
        reason="LOLBin pattern: certutil -decode",
        exe_path=r"C:\Users\Public\suspicious_loader.exe",
        sha256="a1b2c3d4e5f6...",
        entropy_score=7.91,
        signed=False,
        parent_process="cmd.exe",
        parent_pid=1200,
        command_line="suspicious_loader.exe -decode payload.b64",
        network_connections=[{'raddr': '203.0.113.5:443', 'status': 'ESTABLISHED'}],
        process_tree=[{'name': 'explorer.exe', 'pid': 900, 'relation': 'grandparent'},
                      {'name': 'cmd.exe', 'pid': 1200, 'relation': 'parent'}],
        quarantine_path=r"C:\VanguardKnight_Vault\Quarantine\4821_20260717_suspicious_loader.exe.quar",
        severity="CRITICAL",
    )
    folder = fm.create_case(fresh_case)
    print(f"✓ Fresh case created at: {folder}")
    assert (folder / "case_summary.json").exists()
    assert (folder / "case_report.md").exists()
    print("✓ Both JSON and Markdown report generated")

    # Create an "old" case (8 days ago) to test cleanup
    old_dt = datetime.now() - timedelta(days=8)
    old_case = IncidentCase(
        case_id=make_case_id(9999, old_dt),
        timestamp=old_dt.isoformat(),
        threat_name="old_threat.exe",
        pid=9999,
        reason="Test old case for cleanup",
        exe_path=r"C:\Temp\old_threat.exe",
    )
    old_folder = fm.create_case(old_case)
    print(f"✓ Simulated 8-day-old case created at: {old_folder}")

    # Run cleanup -- old case should be purged, fresh case should survive
    removed_count = fm.run_cleanup_now()
    print(f"\nCleanup run: {removed_count} case(s) removed")

    assert not old_folder.exists(), "Old case should have been deleted!"
    assert folder.exists(), "Fresh case should NOT have been deleted!"
    print("✓ Old case correctly purged, fresh case correctly preserved")

    # Verify index still has BOTH entries even though old folder is gone
    history = fm.get_incident_history()
    assert len(history) == 2
    print(f"✓ Permanent index still shows {len(history)} incidents (metadata survives cleanup)")

    print("\nAll forensics self-tests passed.")
