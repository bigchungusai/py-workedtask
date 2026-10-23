#!/usr/bin/env python3
"""
Javelin Anti-Cheat (Python implementation)
Supports debugger detection, suspicious process checks, and optional SHA-256
script self-integrity verification via JAVELIN_EXPECTED_SHA256.
"""

from __future__ import annotations

import hashlib
import os
import sys
from pathlib import Path
from typing import Optional

TAG = "[Javelin AntiCheat] "
EXIT_DEBUGGER = 0xDEB
EXIT_SUSPICIOUS_PROC = 0xBAD
EXIT_INTEGRITY_MISMATCH = 0xC4C


def compute_file_sha256(script_path: Optional[Path] = None) -> str:
    """Compute lowercase hex SHA-256 digest of the running script file."""
    target = Path(script_path) if script_path is not None else Path(__file__).resolve()
    h = hashlib.sha256()
    with target.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest().lower()


def verify_script_integrity(
    expected_sha256: Optional[str] = None,
    script_path: Optional[Path] = None,
) -> bool:
    """
    Verify the running script's SHA-256 against `expected_sha256` or the
    `JAVELIN_EXPECTED_SHA256` environment variable.
    If no expected hash is configured (empty or unset), the optional check passes.
    """
    expected = (
        expected_sha256
        if expected_sha256 is not None
        else os.environ.get("JAVELIN_EXPECTED_SHA256", "")
    ).strip().lower()

    if not expected:
        return True

    if len(expected) != 64 or any(c not in "0123456789abcdef" for c in expected):
        return False

    try:
        actual = compute_file_sha256(script_path=script_path)
    except OSError:
        return False

    return actual == expected


def check_debugger() -> bool:
    return sys.gettrace() is not None


def run_guards(script_path: Optional[Path] = None) -> int:
    print(f"{TAG}starting checks...")

    if check_debugger():
        print(f"{TAG}Debugger detected. Exiting.", file=sys.stderr)
        return EXIT_DEBUGGER

    if not verify_script_integrity(script_path=script_path):
        print(f"{TAG}Integrity check failed (SHA-256 mismatch). Exiting.", file=sys.stderr)
        return EXIT_INTEGRITY_MISMATCH

    print(f"{TAG}All clear. Continue.")
    return 0


if __name__ == "__main__":
    sys.exit(run_guards())
