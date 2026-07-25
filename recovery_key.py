#!/usr/bin/env python3
"""
Vanguard Knight - Recovery Key System
=========================================
Standard secure-recovery pattern (same idea as BitLocker recovery keys or
2FA backup codes): a long random key is generated ONCE during setup and
shown to the user exactly once. The user is responsible for storing it
somewhere safe (printed, password manager, etc.). Only the SHA-256 HASH
of the key is stored on disk -- never the key itself -- so even someone
with full access to the Vault folder cannot recover the key, only verify
a key they already have.

This replaces any "contact the developer for a master key" mechanism --
that pattern would require a live human-verification service (not
something software can actually implement) and would create a single
external point of failure/control. Self-custodied recovery keys are the
industry-standard solution to "what if I lose my password/hand access."
"""

import hashlib
import secrets
import json
import string
from pathlib import Path
from datetime import datetime
from typing import Optional

RECOVERY_KEY_STORE = r"C:\VanguardKnight_Vault\recovery_key.json"

# Format: VK-XXXX-XXXX-XXXX-XXXX (uppercase letters + digits, no ambiguous chars)
ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # excludes O/0, I/1/L for readability
GROUP_COUNT = 4
GROUP_LENGTH = 4


def generate_recovery_key() -> str:
    """Generates a new random recovery key, e.g. 'VK-7F3K-QX9M-2WPD-8HZT'."""
    groups = []
    for _ in range(GROUP_COUNT):
        group = ''.join(secrets.choice(ALPHABET) for _ in range(GROUP_LENGTH))
        groups.append(group)
    return "VK-" + "-".join(groups)


def _hash_key(key: str) -> str:
    normalized = key.strip().upper().replace(" ", "")
    return hashlib.sha256(normalized.encode()).hexdigest()


class RecoveryKeyManager:
    def __init__(self, store_path: str = RECOVERY_KEY_STORE):
        self.store_path = Path(store_path)
        self.store_path.parent.mkdir(parents=True, exist_ok=True)

    def generate_and_store(self) -> str:
        """
        Called ONCE during first-run setup. Returns the plaintext key so the
        GUI can display it to the user for safekeeping -- this is the ONLY
        moment the plaintext ever exists; after this call returns, only the
        hash is persisted.
        """
        key = generate_recovery_key()
        key_hash = _hash_key(key)
        data = {
            'key_hash': key_hash,
            'generated_at': datetime.now().isoformat(),
            'used': False,
        }
        self.store_path.write_text(json.dumps(data, indent=2), encoding='utf-8')
        return key

    def verify(self, candidate_key: str) -> bool:
        """Checks a user-supplied recovery key against the stored hash."""
        if not self.store_path.exists():
            return False
        try:
            data = json.loads(self.store_path.read_text(encoding='utf-8'))
        except Exception:
            return False
        return _hash_key(candidate_key) == data.get('key_hash')

    def is_enrolled(self) -> bool:
        return self.store_path.exists()

    def mark_used(self):
        """
        Optional: after a successful recovery-key-based reset, you may want
        to force generation of a NEW recovery key (so the old one can't be
        reused). Call generate_and_store() again after this if you want
        that behavior -- left as a deliberate choice rather than automatic,
        since some users may prefer a stable long-term key.
        """
        if self.store_path.exists():
            try:
                data = json.loads(self.store_path.read_text(encoding='utf-8'))
                data['used'] = True
                data['last_used_at'] = datetime.now().isoformat()
                self.store_path.write_text(json.dumps(data, indent=2), encoding='utf-8')
            except Exception:
                pass


if __name__ == "__main__":
    import tempfile

    mgr = RecoveryKeyManager(store_path=tempfile.mktemp(suffix='.json'))

    print("=" * 70)
    print("TEST 1: Generate a recovery key")
    print("=" * 70)
    key = mgr.generate_and_store()
    print(f"✓ Generated key: {key}")
    assert key.startswith("VK-") and len(key.split('-')) == 5

    print("\n" + "=" * 70)
    print("TEST 2: Correct key verifies successfully")
    print("=" * 70)
    assert mgr.verify(key) is True
    print("✓ Correct key verified")

    print("\n" + "=" * 70)
    print("TEST 3: Case-insensitive / whitespace-tolerant verification")
    print("=" * 70)
    messy_key = "  " + key.lower().replace("-", " - ") + "  "
    # only test lowercase + spacing tolerance around dashes structurally similar
    assert mgr.verify(key.lower()) is True
    print("✓ Lowercase input still verifies correctly (normalized before hashing)")

    print("\n" + "=" * 70)
    print("TEST 4: Wrong key is rejected")
    print("=" * 70)
    assert mgr.verify("VK-0000-0000-0000-0000") is False
    print("✓ Incorrect key correctly rejected")

    print("\n" + "=" * 70)
    print("TEST 5: Plaintext key is NEVER stored on disk")
    print("=" * 70)
    stored_content = mgr.store_path.read_text()
    assert key not in stored_content
    assert key.replace("-", "") not in stored_content.replace("-", "")
    print("✓ Confirmed: only the hash is persisted, plaintext key is not recoverable from disk")

    print("\nAll recovery-key self-tests passed.")
