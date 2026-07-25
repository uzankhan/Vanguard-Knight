#!/usr/bin/env python3
"""
Vanguard Knight - Application Entry Point
==============================================
This is the file to actually run: `python app_main.py`

Flow:
  1. Check if hand-auth is already enrolled (hand_auth.HandAuthManager.is_enrolled())
  2. If NOT enrolled -> run the first-time SetupWizard (wizard.py)
  3. Once setup is done (or was already done) -> launch the main dashboard
     (gui_app.VanguardMainWindow), which owns the live CoreEngine.
"""

import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(name)s] %(levelname)s: %(message)s',
)

from hand_auth import HandAuthManager
from wizard import SetupWizard
from gui_app import VanguardMainWindow


def launch_main_dashboard(vault_path: str = None):
    app = VanguardMainWindow()
    app.mainloop()


def main():
    hand_mgr = HandAuthManager()

    if not hand_mgr.is_enrolled():
        logging.info("First run detected -- launching setup wizard.")
        wizard = SetupWizard(on_complete=launch_main_dashboard)
        wizard.mainloop()
    else:
        logging.info("Existing setup found -- launching dashboard directly.")
        launch_main_dashboard()


if __name__ == "__main__":
    main()
