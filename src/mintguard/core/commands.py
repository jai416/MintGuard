"""Hardened execution of the system commands MintGuard runs.

`text=True` alone decodes with the locale codec and strict errors: a
local process named with non-UTF-8 bytes (any user can rename their own
process) made the whole `ss` output undecodable and killed the check
with UnicodeDecodeError. Fixed UTF-8 + `errors="replace"` turns bad
bytes into U+FFFD and never raises on decoding; control characters are
sanitized later, at report time.
"""

from __future__ import annotations

import subprocess


def run_command(cmd: list[str], timeout: int) -> subprocess.CompletedProcess | None:
    """Run cmd capturing output as UTF-8; None on OSError or timeout."""
    try:
        return subprocess.run(
            cmd,
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
