#!/usr/bin/env python3
"""
Vanguard Knight - Watchdog Runner
======================================
A SEPARATE, lightweight process from the main service (windows_service.py).
This is deliberate: if the main service is killed, THIS process (running
independently) notices the heartbeat go stale and restarts it. If an
attacker wants to permanently disable Vanguard Knight, they now have to
find and kill BOTH processes, ideally at the same time -- meaningfully
harder than killing one.

Deployment: install this as its own minimal Windows Service (or a
Scheduled Task set to run at startup, with "restart on failure" enabled)
-- separate from VanguardKnightService itself. Two independent lines of
defense instead of one.

Usage:
    python watchdog_main.py debug      Run in console for testing
"""

import sys
import os
import time
import logging
from pathlib import Path

VAULT_DIR = r"C:\VanguardKnight_Vault"
LOG_DIR = os.path.join(VAULT_DIR, "Logs")
Path(LOG_DIR).mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(LOG_DIR, f"watchdog_{time.strftime('%Y%m%d')}.log")),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger("VanguardKnight.WatchdogRunner")

from self_protection import SelfProtectionSupervisor

SERVICE_NAME = "VanguardKnight"

# Files this watchdog verifies haven't been tampered with (kept in sync
# with windows_service.py's own SELF_INTEGRITY_FILES list -- the watchdog
# checks independently rather than trusting the main service's own report,
# since if the main service WAS compromised, its self-report can't be
# trusted either).
_here = os.path.dirname(os.path.abspath(__file__))
WATCHED_FILES = [
    os.path.join(_here, "windows_service.py"),
    os.path.join(_here, "core_engine.py"),
    os.path.join(_here, "entropy.py"),
    os.path.join(_here, "trusted_apps.py"),
    os.path.join(_here, "self_protection.py"),
]


def on_tamper_detected(findings):
    logger.critical(f"[WATCHDOG] TAMPER DETECTED on {len(findings)} core file(s): "
                    f"{[f['file'] for f in findings]}")
    # Findings are logged; the actual response (alerting, forensics case)
    # happens on the main service side when it next runs its own check --
    # this watchdog's job is detection + restart, not full incident handling,
    # to keep it minimal and less likely to have its own bugs/attack surface.


def main():
    supervisor = SelfProtectionSupervisor(
        core_engine_launch_cmd=["net", "start", SERVICE_NAME],
        watched_files=WATCHED_FILES,
        on_tamper_detected=on_tamper_detected,
        on_restart=lambda: logger.info("[WATCHDOG] Restart command issued."),
    )

    # Establish integrity baseline on first run only.
    if not supervisor.integrity.baseline:
        logger.info("[WATCHDOG] No integrity baseline found -- establishing one now.")
        supervisor.integrity.establish_baseline()

    logger.info("[WATCHDOG] Starting supervision loop (checking every 10s).")
    supervisor.start_supervision(check_interval=10)

    try:
        while True:
            time.sleep(60)
    except KeyboardInterrupt:
        supervisor.stop_supervision()
        logger.info("[WATCHDOG] Stopped.")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "debug":
        print("[DEBUG] Running watchdog in console mode...")
    main()
