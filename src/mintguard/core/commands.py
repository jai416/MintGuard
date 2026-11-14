"""Hardened execution of the system commands MintGuard runs.

`text=True` alone decodes with the locale codec and strict errors: a
local process named with non-UTF-8 bytes (any user can rename their own
process) made the whole `ss` output undecodable and killed the check
with UnicodeDecodeError. Fixed UTF-8 + `errors="replace"` turns bad
bytes into U+FFFD and never raises on decoding; control characters are
sanitized later, at report time.
"""

from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path

# Standard system locations, in order. PATH is NOT searched: under sudo
# the inherited PATH can point at a user-writable directory (~/.local/bin)
# and that binary would run as root.
SYSTEM_BIN_DIRS = (
    "/usr/bin",
    "/bin",
    "/usr/sbin",
    "/sbin",
    "/usr/local/bin",
    "/usr/local/sbin",
)


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


def _is_trusted(info: os.stat_result) -> bool:
    """True for a file we may execute as root: root's, and not writable by others."""
    return (
        stat.S_ISREG(info.st_mode)
        and info.st_uid == 0
        and not info.st_mode & 0o022
    )


def resolve_binary(name: str) -> str | None:
    """Absolute path of a trusted system binary, or None if there is none.

    Only root-owned files in the standard directories are accepted: a
    binary resolved through PATH can live in a directory the user
    writes, and under sudo it would run as root. A system whose tools
    live elsewhere (NixOS…) is reported as "not available" rather than
    executed blindly.
    """
    for directory in SYSTEM_BIN_DIRS:
        candidate = Path(directory) / name
        try:
            info = candidate.stat()
        except OSError:
            continue
        if _is_trusted(info) and os.access(candidate, os.X_OK):
            return str(candidate)
    return None
