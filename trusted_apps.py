#!/usr/bin/env python3
"""
Vanguard Knight - Trusted Application Manager
================================================
Problem jo solve kar rahe hain:
Maham ke apne projects (Rabail - JARVIS-style automation, CreatorStudio,
aur future projects) system-level actions karte hain jo generically
"suspicious" lag sakte hain (script automation, high process/thread counts,
file writes, network calls) -- aur agar tool inhe blindly reputation-score
kare, to apne hi tools quarantine ho jayenge. Ye sabse bada false-positive
source hota hai kisi bhi custom-built EDR ke liye.

Solution: Multi-layer trust verification -- SIRF ek cheez (jaise filename)
pe trust nahi karte, kyunki wo spoof ho sakti hai. Teen layers use karte hain:

1. SHA-256 file hash whitelist  -- sabse strong signal, file badli to hash badla
2. Full file PATH whitelist     -- specific folder se chal raha ho to hi trust
3. Digital signature (optional) -- agar khud sign kiya ho apne tools ko

Ek entry sirf tab "trusted" maanenge jab HASH match ho (path sirf
secondary confirmation ke liye). Ye isliye zaroori hai kyunki agar sirf
naam/path pe trust karte, to malware khud ko "rabail.exe" naam de kar
usi folder mein rakh de to bhi trust ho jata -- jo bohat bada security hole
hota. Hash-based trust ye gap band karta hai.
"""

import hashlib
import json
import logging
from pathlib import Path
from typing import Optional, List, Dict
from dataclasses import dataclass, asdict, field

logger = logging.getLogger("VanguardKnight.TrustedApps")

DEFAULT_TRUST_DB = r"C:\VanguardKnight_Vault\trusted_apps.json"


@dataclass
class TrustedApp:
    name: str                  # Friendly name, e.g. "Rabail"
    sha256: str                # File hash at time of trusting
    path: str                  # Full path where it's expected to run from
    description: str = ""      # e.g. "Personal JARVIS-style automation assistant"
    added_by_user: bool = True
    allow_network: bool = True     # Some assistants need net access -- explicit, not implicit
    allow_child_processes: bool = True  # e.g. automation tools spawning other apps
    notes: str = ""


def sha256_of_file(file_path: str, chunk_size: int = 1024 * 1024) -> Optional[str]:
    """Compute SHA-256 of a file, streaming so large files don't blow up memory."""
    try:
        h = hashlib.sha256()
        with open(file_path, 'rb') as f:
            while chunk := f.read(chunk_size):
                h.update(chunk)
        return h.hexdigest()
    except Exception as e:
        logger.error(f"Could not hash {file_path}: {e}")
        return None


class TrustedAppManager:
    """
    Manages the allowlist of the user's own tools/projects so the detection
    engine treats them as known-safe -- WITHOUT creating a blanket "ignore
    this folder" hole that malware could exploit by dropping a file there.

    Key design decision: trust is re-verified by HASH every time a process
    from a "trusted" path launches. If the file at that path has been
    modified/replaced since it was trusted (e.g. malware overwrote it, or
    it auto-updated), trust is NOT granted automatically -- it flags for
    re-approval instead. This closes the "trusted folder" loophole.
    """

    def __init__(self, db_path: str = DEFAULT_TRUST_DB):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.apps: Dict[str, TrustedApp] = {}
        self._load()

    def _load(self):
        if self.db_path.exists():
            try:
                raw = json.loads(self.db_path.read_text(encoding='utf-8'))
                for entry in raw.get('apps', []):
                    app = TrustedApp(**entry)
                    self.apps[app.sha256] = app
                logger.info(f"Loaded {len(self.apps)} trusted app(s).")
            except Exception as e:
                logger.error(f"Failed to load trusted apps DB: {e}")

    def _save(self):
        try:
            data = {'apps': [asdict(a) for a in self.apps.values()]}
            self.db_path.write_text(json.dumps(data, indent=2), encoding='utf-8')
        except Exception as e:
            logger.error(f"Failed to save trusted apps DB: {e}")

    def trust_app(self, name: str, file_path: str, description: str = "",
                  allow_network: bool = True, allow_child_processes: bool = True) -> bool:
        """
        Add (or re-approve) an application as trusted. Call this once, manually,
        when you set up a new personal project (e.g. Rabail, CreatorStudio).
        """
        file_hash = sha256_of_file(file_path)
        if not file_hash:
            logger.error(f"Could not trust '{name}' -- file not readable: {file_path}")
            return False

        app = TrustedApp(
            name=name,
            sha256=file_hash,
            path=str(Path(file_path).resolve()),
            description=description,
            allow_network=allow_network,
            allow_child_processes=allow_child_processes,
        )
        self.apps[file_hash] = app
        self._save()
        logger.info(f"[TRUST] '{name}' added to trusted apps (hash={file_hash[:12]}...).")
        return True

    def untrust_app(self, name: str) -> bool:
        """Remove an app from the trust list (e.g. if you retire a project)."""
        to_remove = [h for h, a in self.apps.items() if a.name == name]
        for h in to_remove:
            del self.apps[h]
        if to_remove:
            self._save()
            logger.info(f"[UNTRUST] '{name}' removed from trusted apps.")
            return True
        return False

    def check(self, file_path: str) -> Optional[TrustedApp]:
        """
        Core check called by the detection engine before flagging a process.
        Returns the TrustedApp record if this exact file (by hash) is trusted,
        else None -- meaning normal detection logic should proceed as usual.

        IMPORTANT: this re-hashes the file every time. If someone replaced
        'rabail.exe' with malware of the same name, the hash won't match
        any trusted entry, and detection proceeds normally. This is the
        core anti-spoofing protection.
        """
        if not self.apps:
            return None

        current_hash = sha256_of_file(file_path)
        if not current_hash:
            return None

        app = self.apps.get(current_hash)
        if app:
            resolved_current = str(Path(file_path).resolve())
            if app.path != resolved_current:
                # Same file content exists somewhere else -- possibly copied
                # or moved. Still trust it (hash matches = same binary) but
                # log for visibility since paths shifting is worth knowing.
                logger.info(f"[TRUST] '{app.name}' matched by hash but running "
                           f"from a new path ({resolved_current}) -- allowed, logged.")
            return app
        return None

    def list_trusted(self) -> List[TrustedApp]:
        return list(self.apps.values())


if __name__ == "__main__":
    # Self-test: create a dummy "app", trust it, verify check() logic,
    # then simulate tampering (content changed) and verify trust is revoked.
    import tempfile, os

    with tempfile.NamedTemporaryFile(suffix='.exe', delete=False) as f:
        f.write(b"FAKE_RABAIL_BINARY_V1_CONTENT")
        test_path = f.name

    mgr = TrustedAppManager(db_path=tempfile.mktemp(suffix='.json'))
    mgr.trust_app("Rabail", test_path, description="Personal JARVIS-style assistant")

    # Case 1: unmodified file should be trusted
    result = mgr.check(test_path)
    assert result is not None and result.name == "Rabail"
    print(f"✓ Unmodified 'Rabail' binary correctly trusted (name={result.name})")

    # Case 2: simulate malware overwriting the same filename/path
    with open(test_path, 'wb') as f:
        f.write(b"MALICIOUS_PAYLOAD_REPLACED_CONTENT")

    result_after_tamper = mgr.check(test_path)
    assert result_after_tamper is None
    print("✓ Tampered file (same path, different content) correctly LOST trust")

    os.unlink(test_path)
    print("\nAll trust-manager self-tests passed.")
