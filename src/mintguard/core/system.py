"""Lightweight system information read from /proc (no subprocesses)."""

from __future__ import annotations

import os
import platform
from dataclasses import dataclass


@dataclass
class SystemInfo:
    hostname: str
    kernel: str
    arch: str
    cpu_model: str
    cpu_count: int
    ram_total_mb: int
    uptime_text: str


def _cpu_model() -> str:
    try:
        with open("/proc/cpuinfo", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                if line.startswith("model name"):
                    return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return ""


def _ram_total_mb() -> int:
    try:
        with open("/proc/meminfo", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                if line.startswith("MemTotal:"):
                    return round(int(line.split()[1]) / 1024)
    except (OSError, ValueError, IndexError):
        pass
    return 0


def _uptime_text() -> str:
    try:
        seconds = int(float(open("/proc/uptime", encoding="utf-8").read().split()[0]))
    except (OSError, ValueError, IndexError):
        return ""
    days, remainder = divmod(seconds, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes = remainder // 60
    return f"{days}d {hours}h {minutes}m"


def collect_system_info() -> SystemInfo:
    uname = platform.uname()
    return SystemInfo(
        hostname=uname.node,
        kernel=uname.release,
        arch=uname.machine,
        cpu_model=_cpu_model(),
        cpu_count=os.cpu_count() or 0,
        ram_total_mb=_ram_total_mb(),
        uptime_text=_uptime_text(),
    )
