#!/usr/bin/env python3
"""
Vanguard Knight - Windows Service Wrapper
==============================================
Runs CoreEngine as a proper background Windows Service, so protection is
active even when no one is logged in / the GUI isn't open, and starts
automatically on boot.

Usage (run as Administrator):
    python windows_service.py install     Install the service + configure
                                           auto-restart-on-crash
    python windows_service.py start
    python windows_service.py stop
    python windows_service.py remove
    python windows_service.py debug       Run in console (no service, for testing)

Two independent layers of "keep this running" protection are combined here:

  LAYER A: Windows Service Control Manager (SCM) recovery actions
    Configured via `sc.exe failure` right after install. If the service
    process crashes OR is killed, Windows itself automatically restarts it
    (this is the same mechanism most commercial security products rely on
    for their core service resilience -- it's simple and very reliable).

  LAYER B: File-integrity + heartbeat monitoring (self_protection.py)
    Runs INSIDE the service, checking that Vanguard Knight's own files
    haven't been tampered with, and maintaining the heartbeat file that a
    companion watchdog (or the GUI, when open) can check.

Because the service has no GUI, Tier-2 "uncertain" detections use
core_engine's built-in fail-safe default (auto-quarantine rather than
silently allow) -- see core_engine.py's _default_permission_handler.
"""

import os
import sys
import time
import logging
import subprocess
from pathlib import Path

import win32serviceutil
import win32service
import win32event
import servicemanager

from core_engine import CoreEngine
from self_protection import FileIntegrityMonitor, WatchdogHeartbeat

VAULT_DIR = r"C:\VanguardKnight_Vault"
LOG_DIR = os.path.join(VAULT_DIR, "Logs")
Path(LOG_DIR).mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(LOG_DIR, f"service_{time.strftime('%Y%m%d')}.log")),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger("VanguardKnight.Service")

SERVICE_NAME = "VanguardKnight"
SERVICE_DISPLAY_NAME = "Vanguard Knight - Immortal Shield"
SERVICE_DESCRIPTION = "Real-time endpoint threat detection and response. Made by Uzan Khan."

# Files whose integrity the service watches on itself (extend this list to
# match whatever set of .py files you deploy alongside this service).
SELF_INTEGRITY_FILES = [
    __file__,
    os.path.join(os.path.dirname(__file__), "core_engine.py"),
    os.path.join(os.path.dirname(__file__), "entropy.py"),
    os.path.join(os.path.dirname(__file__), "trusted_apps.py"),
]


class VanguardKnightService(win32serviceutil.ServiceFramework):
    _svc_name_ = SERVICE_NAME
    _svc_display_name_ = SERVICE_DISPLAY_NAME
    _svc_description_ = SERVICE_DESCRIPTION

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        self.running = True
        self.engine = None
        self.heartbeat = WatchdogHeartbeat()
        self.integrity_monitor = FileIntegrityMonitor(SELF_INTEGRITY_FILES)

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        logger.info("Service stop requested.")
        self.running = False
        if self.engine:
            self.engine.stop()
        win32event.SetEvent(self.hWaitStop)

    def SvcDoRun(self):
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STARTED,
            (self._svc_name_, ''),
        )
        self.main()

    def main(self):
        logger.info("Vanguard Knight service starting.")

        # Establish integrity baseline on first run only (if none exists yet).
        # We do NOT re-baseline automatically on every service start --
        # that would silently accept tampering as the new "normal". A
        # missing baseline means this is either a fresh install or someone
        # deleted the baseline file itself (also worth investigating).
        if not self.integrity_monitor.baseline:
            logger.info("No integrity baseline found -- establishing one now (first run).")
            self.integrity_monitor.establish_baseline()

        self.engine = CoreEngine(
            alert_callback=self._service_alert_callback,
            log_callback=self._service_log_callback,
            # No permission_callback passed -- headless service correctly
            # falls back to CoreEngine's built-in fail-safe (auto-quarantine
            # uncertain-tier detections rather than silently allowing them).
        )
        self.engine.start()
        logger.info("Core engine started under service.")

        last_integrity_check = time.time()
        while self.running:
            # Heartbeat -- lets a companion watchdog/GUI know this process is alive.
            self.heartbeat.beat("core_engine_service")

            # Periodic self-integrity check (every 60s)
            if time.time() - last_integrity_check > 60:
                findings = self.integrity_monitor.check()
                if findings:
                    logger.critical(f"[TAMPER DETECTED] {len(findings)} file(s) modified/missing: "
                                    f"{[f['file'] for f in findings]}")
                    self._service_alert_callback(
                        "self_tamper_detected",
                        f"{len(findings)} core Vanguard Knight file(s) were modified or deleted "
                        f"outside of a normal update -- possible tampering attempt.",
                        severity="CRITICAL",
                    )
                last_integrity_check = time.time()

            # Wait up to 5s for a stop signal, otherwise loop again
            result = win32event.WaitForSingleObject(self.hWaitStop, 5000)
            if result == win32event.WAIT_OBJECT_0:
                break

        logger.info("Vanguard Knight service main loop exiting.")

    def _service_log_callback(self, message: str):
        logger.info(message)

    def _service_alert_callback(self, alert_type: str, text: str, severity: str = "INFO", extra=None):
        logger.warning(f"[{severity}] {alert_type}: {text}")
        # Also write to the Windows Application Event Log so alerts are
        # visible via Event Viewer even if no one checks the text log file.
        try:
            event_type = (servicemanager.EVENTLOG_ERROR_TYPE if severity in ("HIGH", "CRITICAL")
                         else servicemanager.EVENTLOG_WARNING_TYPE)
            servicemanager.LogMsg(event_type, 0, (SERVICE_NAME, f"{alert_type}: {text}"))
        except Exception:
            pass


def _configure_auto_recovery():
    """
    Configures Windows Service Control Manager to automatically restart
    this service if it crashes or is killed -- run once, right after
    installing the service. This is Layer A of the self-protection design.
    """
    try:
        subprocess.run(
            ['sc', 'failure', SERVICE_NAME,
             'reset=', '86400',                       # reset failure count after 1 day of stability
             'actions=', 'restart/5000/restart/5000/restart/5000'],  # restart after 5s, 3 times
            check=True, capture_output=True, text=True,
        )
        subprocess.run(
            ['sc', 'failureflag', SERVICE_NAME, '1'],  # also trigger recovery on non-crash stops
            check=False, capture_output=True, text=True,
        )
        logger.info("Auto-recovery configured: service will restart automatically if killed/crashed.")
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to configure auto-recovery: {e.stderr}")


def main():
    # IMPORTANT: Jab Windows SCM service start karta hai, koi extra args nahi hote.
    # Is case mein HandleCommandLine ko call karna zaroori hai taake service dispatcher chale.
    if len(sys.argv) == 1:
        win32serviceutil.HandleCommandLine(VanguardKnightService)
        return

    if sys.argv[1] == 'install':
        win32serviceutil.InstallService(
            VanguardKnightService._svc_name_,  # better than None
            SERVICE_NAME,
            SERVICE_DISPLAY_NAME,
            startType=win32service.SERVICE_AUTO_START,
            description=SERVICE_DESCRIPTION,
            exeName=sys.executable,
            exeArgs=f'"{os.path.abspath(__file__)}"',
        )
        print(f"[+] Service '{SERVICE_NAME}' installed.")
        _configure_auto_recovery()
        print("[+] Auto-restart-on-crash configured.")

    elif sys.argv[1] == 'remove':
        win32serviceutil.RemoveService(SERVICE_NAME)
        print(f"[-] Service '{SERVICE_NAME}' removed.")

    elif sys.argv[1] == 'start':
        win32serviceutil.StartService(SERVICE_NAME)
        print(f"[+] Service '{SERVICE_NAME}' started.")

    elif sys.argv[1] == 'stop':
        win32serviceutil.StopService(SERVICE_NAME)
        print(f"[-] Service '{SERVICE_NAME}' stopped.")

    elif sys.argv[1] == 'debug':
        print("[DEBUG] Running Vanguard Knight core engine in console mode (no service)...")
        engine = CoreEngine(
            alert_callback=lambda t, m, severity="INFO", extra=None: print(f"[{severity}] {t}: {m}"),
            log_callback=lambda m: print(f"[LOG] {m}"),
        )
        engine.start()
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            engine.stop()
            print("Stopped.")

    else:
        print(f"Usage: python {os.path.basename(__file__)} [install|start|stop|remove|debug]")
        print("  install  - Install the service and configure auto-restart-on-crash")
        print("  start    - Start the service")
        print("  stop     - Stop the service")
        print("  remove   - Uninstall the service")
        print("  debug    - Run in console (no service, useful for testing)")
if __name__ == "__main__":
    main()
