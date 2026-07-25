#!/usr/bin/env python3
"""
Vanguard Knight - Entropy Analysis Module
===========================================
Purana bug: entropy -= p * (p.bit_length() - 1)  --> ye galat hai, p ek float hai
Sahi Shannon Entropy formula: H(X) = -sum(p_i * log2(p_i))

Entropy use hoti hai ransomware detection ke liye:
- Normal files (text, code, docs): entropy ~3.5 - 6.0
- Compressed files (zip, jpg, mp4): entropy ~7.0 - 7.5 (already dense)
- ENCRYPTED files (ransomware output): entropy ~7.8 - 8.0 (bilkul random data)

Isliye sirf "high entropy" pe alert karna kaafi nahi -- zip/jpg bhi high entropy
honge aur false positive denge. Humein isko smarter banana hoga:
1. File extension ka baseline dekhna (kya ye already compressed format hai?)
2. Rate of change dekhna (achanak entropy jump -- normal file se encrypted ban gayi)
3. Header/magic-byte check (encrypted files ka koi valid header nahi hota)
"""

import math
import os
from pathlib import Path
from typing import Optional, Tuple

# File extensions jo naturally high-entropy hote hain (already compressed/encoded)
# Inhe False positive se bachane ke liye baseline treat karenge
KNOWN_COMPRESSED_EXTENSIONS = {
    '.zip', '.rar', '.7z', '.gz', '.bz2', '.xz', '.tar',
    '.jpg', '.jpeg', '.png', '.gif', '.webp', '.bmp',
    '.mp3', '.mp4', '.avi', '.mkv', '.mov', '.wmv',
    '.pdf',  # PDFs can have compressed streams internally
    '.docx', '.xlsx', '.pptx',  # these are actually zip containers
    '.exe', '.dll', '.msi',  # often packed/compressed
}

# Known "magic bytes" (file signatures) for common legitimate high-entropy formats.
# Encrypted-by-ransomware files usually have NO valid magic bytes (random garbage
# from the very first byte), which is a strong forensic signal.
MAGIC_BYTES = {
    b'\x50\x4B\x03\x04': 'ZIP/DOCX/XLSX container',
    b'\xFF\xD8\xFF': 'JPEG',
    b'\x89\x50\x4E\x47': 'PNG',
    b'\x25\x50\x44\x46': 'PDF',
    b'\x1F\x8B': 'GZIP',
    b'\x37\x7A\xBC\xAF': '7-Zip',
    b'\x52\x61\x72\x21': 'RAR',
    b'\x4D\x5A': 'PE executable (EXE/DLL)',
}


def calculate_entropy(data: bytes) -> float:
    """
    Correct Shannon Entropy formula.
    H(X) = -sum(p_i * log2(p_i)) for each unique byte value.
    Range: 0.0 (all same byte) to 8.0 (perfectly random / encrypted).
    """
    if not data:
        return 0.0

    length = len(data)
    freq = [0] * 256
    for b in data:
        freq[b] += 1

    entropy = 0.0
    for count in freq:
        if count == 0:
            continue
        p = count / length
        entropy -= p * math.log2(p)   # <-- FIXED: correct Shannon formula

    return entropy


def has_valid_magic_bytes(data: bytes) -> Optional[str]:
    """Check if file starts with a known legitimate file signature."""
    for magic, filetype in MAGIC_BYTES.items():
        if data.startswith(magic):
            return filetype
    return None


def analyze_file(file_path: str, sample_size: int = 65536) -> Tuple[float, bool, str]:
    """
    Full forensic entropy analysis of a file.

    Returns: (entropy_score, is_suspicious, reason)

    Logic:
    - Read first `sample_size` bytes (64KB default -- fast, and ransomware
      typically encrypts from the start of the file).
    - Calculate real Shannon entropy.
    - Check extension against known-compressed baseline.
    - Check magic bytes for a valid legitimate header.
    - Only flag suspicious if entropy is high AND (extension doesn't explain it
      OR magic bytes are missing/invalid) -- this cuts false positives hugely
      compared to the old "entropy > 7.5 = ransomware" logic.
    """
    try:
        path = Path(file_path)
        if not path.exists() or not path.is_file():
            return 0.0, False, "File not accessible"

        file_size = path.stat().st_size
        if file_size < 256:
            return 0.0, False, "File too small to analyze reliably"

        with open(file_path, 'rb') as f:
            data = f.read(sample_size)

        entropy = calculate_entropy(data)
        ext = path.suffix.lower()
        magic = has_valid_magic_bytes(data)

        # Case 1: Extension says it should be compressed/high-entropy AND
        # magic bytes confirm it's genuinely that format --> not suspicious.
        if ext in KNOWN_COMPRESSED_EXTENSIONS and magic:
            return entropy, False, f"High entropy expected ({magic})"

        # Case 2: High entropy but extension is normally LOW entropy
        # (e.g. .txt, .docx-renamed-but-not-really, .jpg-renamed-but-no-magic)
        # This is the classic ransomware fingerprint: original file extension
        # kept or changed, but content is now pure random ciphertext with NO
        # valid header.
        if entropy > 7.5 and not magic:
            reason = (f"High entropy ({entropy:.2f}/8.0) with NO valid file "
                      f"signature -- classic encrypted-file fingerprint")
            return entropy, True, reason

        # Case 3: High entropy, extension doesn't explain it, but magic bytes
        # ARE present (e.g. a .txt file that's secretly a renamed zip) --
        # still worth a lower-confidence flag.
        if entropy > 7.5 and ext not in KNOWN_COMPRESSED_EXTENSIONS:
            reason = f"High entropy ({entropy:.2f}/8.0), unexpected for '{ext}' files"
            return entropy, True, reason

        return entropy, False, "Normal entropy range"

    except PermissionError:
        return 0.0, False, "Permission denied"
    except Exception as e:
        return 0.0, False, f"Analysis error: {e}"


if __name__ == "__main__":
    # Quick self-test
    test_data_random = os.urandom(4096)
    test_data_text = b"The quick brown fox jumps over the lazy dog. " * 100
    test_data_zeros = b"\x00" * 4096

    print(f"Random bytes entropy   : {calculate_entropy(test_data_random):.4f}  (expect ~8.0)")
    print(f"Repeated text entropy  : {calculate_entropy(test_data_text):.4f}  (expect ~4.0-4.5)")
    print(f"All-zero bytes entropy : {calculate_entropy(test_data_zeros):.4f}  (expect 0.0)")
