#!/usr/bin/env python3
"""
Vanguard Knight - Deception Layer (Honeypots / Honeytokens)
================================================================
Ye tumhare "attacker hairan reh jaye" wale idea ka LEGAL aur professional
version hai. Hum attacker pe counter-attack nahi karte (jo illegal hoga),
lekin hum use CONFUSE aur TRAP kar sakte hain apne hi system ke andar --
ye technique real enterprise EDR/SOC teams "deception technology" kehte hain.

Concept: Hum jaan-boojh kar FAKE tempting files/registry-keys/credentials
system mein rakhte hain jo koi legitimate program KABHI touch nahi karega
-- sirf koi cheez jo manually explore kar rahi ho (malware ya attacker)
unhe dekhegi aur interact karegi. Jaise hi koi in decoys ko touch kare,
ye NEAR-100% CONFIDENCE signal hai ke ye malicious activity hai (kyunki
koi legitimate reason nahi hai in files ko access karne ka) -- bohat kam
false-positive rate, ransomware/recon tools ke against bohat effective.

Types of honeytokens implemented:
1. Honeyfiles -- fake "passwords.txt", "bank_details.xlsx" jaisi files
   jo tempting lagti hain data-stealing malware/attacker ke liye
2. Honeyfolders -- fake "Confidential" folder jismein honeyfiles rakhte hain
3. Registry honeytokens -- fake registry keys jo credential-harvesting
   malware scan karta hai (browser-saved-password style keys)
4. Decoy network shares indicator (documented, actual share setup needs
   admin-level Windows configuration outside Python's scope)

Jab koi honeytoken touch/read/modify ho, ye INSTANT CRITICAL alert deta hai
-- kyunki ye "fake success" attacker ko milta hai (wo file khol lega,
sochega usne kuch valuable churaya), lekin real mein usne khud ko turant
expose kar diya. Ye bilkul tumhare "attacker hairan reh jaye" wale
spirit ko deliver karta hai -- bina kisi counter-attack ke.
"""

import os
import time
import logging
import threading
from pathlib import Path
from datetime import datetime
from typing import List, Callable, Optional
from dataclasses import dataclass

logger = logging.getLogger("VanguardKnight.Deception")

HONEYPOT_BASE = r"C:\Users\Public\Documents"  # visible, tempting location
                                                # (real user data lives elsewhere)

# Believable-sounding decoy filenames -- crafted to be the FIRST things
# an attacker/infostealer would grep for.
HONEYFILE_TEMPLATES = {
    "passwords_backup.txt": (
        "Gmail: ********\nBank Login: ********\nNetflix: ********\n"
        "(This is a monitored decoy file. Access is logged.)"
    ),
    "Crypto_Wallet_Seed_Phrase.txt": (
        "wallet recovery phrase - DO NOT SHARE\n"
        "[decoy content -- monitored]"
    ),
    "Company_Financial_Records_2026.xlsx.txt": (
        "placeholder -- monitored decoy file"
    ),
    "SSH_Private_Keys_Backup\\id_rsa_backup.txt": (
        "-----BEGIN OPENSSH PRIVATE KEY-----\n[decoy -- monitored]\n-----END-----"
    ),
}


@dataclass
class HoneytokenTrigger:
    honeytoken_path: str
    access_type: str       # 'read', 'modified', 'deleted'
    timestamp: str
    accessing_process: Optional[str] = None
    accessing_pid: Optional[int] = None


class HoneypotManager:
    """
    Deploys and monitors honeyfiles. Monitoring approach: track each
    honeyfile's last-modified/last-accessed timestamp and content hash;
    any change from the deployed baseline (even a READ, detectable via
    NTFS last-access-time if enabled, or more reliably via a Sysmon
    FileCreate/file-handle-open event referencing the honeyfile path)
    means someone/something touched a file that legitimately NOTHING
    should ever touch.

    Practical wiring: feed this manager's `check_path_against_honeypots()`
    into the core engine's file-event handler (any FileCreate/access event
    whose path matches a deployed honeypot -> instant CRITICAL alert).
    """

    def __init__(self, base_dir: str = HONEYPOT_BASE, on_trigger: Optional[Callable] = None):
        self.base_dir = Path(base_dir)
        self.on_trigger = on_trigger or (lambda t: None)
        self.deployed_paths: set = set()

    def deploy(self) -> List[str]:
        """Creates honeyfiles on disk. Call once at setup/startup."""
        deployed = []
        for rel_path, content in HONEYFILE_TEMPLATES.items():
            full_path = self.base_dir / rel_path
            try:
                full_path.parent.mkdir(parents=True, exist_ok=True)
                full_path.write_text(content, encoding='utf-8')
                self.deployed_paths.add(str(full_path.resolve()))
                deployed.append(str(full_path))
                logger.info(f"[HONEYPOT] Deployed decoy: {full_path}")
            except Exception as e:
                logger.error(f"[HONEYPOT] Failed to deploy {full_path}: {e}")
        return deployed

    def is_honeypot_path(self, path: str) -> bool:
        """Core check -- call this against any file path seen in file-system
        events (from Sysmon FileCreate, or a file-access monitor)."""
        if not path:
            return False
        try:
            resolved = str(Path(path).resolve())
        except Exception:
            resolved = path
        return resolved in self.deployed_paths or any(
            resolved.lower() == p.lower() for p in self.deployed_paths
        )

    def handle_access_event(self, path: str, access_type: str,
                            process_name: str = None, pid: int = None):
        """
        Call this whenever a file-system event touches a path -- it checks
        if that path is a honeypot, and if so, fires a maximum-confidence alert.
        """
        if not self.is_honeypot_path(path):
            return None

        trigger = HoneytokenTrigger(
            honeytoken_path=path, access_type=access_type,
            timestamp=datetime.now().isoformat(),
            accessing_process=process_name, accessing_pid=pid,
        )
        msg = (f"[HONEYPOT TRIGGERED] Decoy file '{path}' was {access_type} by "
               f"{process_name or 'unknown process'} (PID {pid or '?'}). "
               f"NO legitimate program should ever touch this file -- this is "
               f"maximum-confidence evidence of malicious reconnaissance/data theft "
               f"in progress.")
        logger.critical(msg)
        self.on_trigger(trigger)
        return trigger


class RegistryHoneytoken:
    """
    Fake registry entries mimicking what credential-harvesting malware looks
    for (e.g. fake saved-password-style keys). Accessing/enumerating these
    via a non-standard process (not a known password manager / browser) is
    a strong signal.

    NOTE: actually setting up a registry ACCESS audit (SACL) requires admin
    privileges and Windows auditing (auditpol.exe) to be configured; this
    class documents and creates the honeytoken key itself, while the actual
    "who touched it" detection integrates with Sysmon Event ID 12/13/14
    (RegistryEvent) in core_engine.py -- any process (other than the
    documented trusted managers) that queries this key triggers an alert.
    """

    HONEYTOKEN_KEY = r"Software\VanguardKnight\_decoy_credential_cache"

    @staticmethod
    def deploy_note() -> str:
        return (
            "Registry honeytoken setup (run manually as part of installer, "
            "requires winreg on Windows):\n"
            "  Key: HKEY_CURRENT_USER\\Software\\VanguardKnight\\_decoy_credential_cache\n"
            "  Values: fake 'SavedLogin1', 'SavedLogin2' entries with decoy data.\n"
            "  Monitored via Sysmon RegistryEvent (already covered by "
            "sysmon_config.xml's persistence-monitoring RuleGroup) -- any read/query "
            "of this key by a process other than vanguard_knight.exe itself is a "
            "high-confidence credential-harvesting signal."
        )


if __name__ == "__main__":
    import tempfile

    alerts_fired = []

    def capture(trigger: HoneytokenTrigger):
        alerts_fired.append(trigger)
        print(f"  🚨 ALERT: {trigger.honeytoken_path} -- {trigger.access_type} "
              f"by {trigger.accessing_process} (PID {trigger.accessing_pid})")

    test_dir = tempfile.mkdtemp()
    hp = HoneypotManager(base_dir=test_dir, on_trigger=capture)

    print("=" * 70)
    print("TEST 1: Deploy honeyfiles")
    print("=" * 70)
    deployed = hp.deploy()
    print(f"✓ Deployed {len(deployed)} honeyfile(s):")
    for d in deployed:
        print(f"    {d}")
    assert len(deployed) == len(HONEYFILE_TEMPLATES)

    print("\n" + "=" * 70)
    print("TEST 2: Legitimate-looking path (NOT a honeypot) -- should be silent")
    print("=" * 70)
    result = hp.handle_access_event(
        path=str(Path(test_dir) / "some_real_document.docx"),
        access_type="read", process_name="winword.exe", pid=1234,
    )
    assert result is None
    print("✓ Non-honeypot file access correctly ignored (no false alarm)")

    print("\n" + "=" * 70)
    print("TEST 3: Malware touching a honeyfile -- should fire CRITICAL alert")
    print("=" * 70)
    honeypot_path = deployed[0]
    result = hp.handle_access_event(
        path=honeypot_path, access_type="read",
        process_name="suspicious_stealer.exe", pid=6666,
    )
    assert result is not None
    assert len(alerts_fired) == 1
    print(f"✓ Honeypot trigger correctly fired ({len(alerts_fired)} alert)")

    print("\nAll deception-layer self-tests passed.")
