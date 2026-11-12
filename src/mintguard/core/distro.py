"""Distribution and environment detection (filesystem based, no subprocesses)."""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path

OS_RELEASE_PATH = Path("/etc/os-release")

SUPPORTED_PACKAGE_MANAGERS = ("apt", "dnf", "pacman", "zypper")


@dataclass
class PackageManager:
    name: str
    path: str


@dataclass
class DistroInfo:
    distro_id: str
    name: str
    version: str
    package_manager: PackageManager | None
    has_systemd: bool
    mac_module: str | None  # "AppArmor" | "SELinux"
    firewall_tool: str | None  # "UFW" | "firewalld" | "nftables" | "iptables"


def _read_os_release() -> dict[str, str]:
    data: dict[str, str] = {}
    try:
        for line in OS_RELEASE_PATH.read_text(encoding="utf-8", errors="replace").splitlines():
            key, sep, value = line.partition("=")
            if sep:
                data[key.strip()] = value.strip().strip('"')
    except OSError:
        pass
    return data


def _detect_package_manager() -> PackageManager | None:
    for name in SUPPORTED_PACKAGE_MANAGERS:
        path = shutil.which(name)
        if path:
            return PackageManager(name=name, path=path)
    path = shutil.which("apt-get")
    if path:
        return PackageManager(name="apt", path=path)
    return None


def _has_systemd() -> bool:
    if Path("/run/systemd/system").is_dir():
        return True
    try:
        return Path("/proc/1/comm").read_text(encoding="utf-8", errors="replace").strip() == "systemd"
    except OSError:
        return False


def _detect_mac_module() -> str | None:
    if Path("/sys/kernel/security/apparmor").exists():
        return "AppArmor"
    if Path("/sys/fs/selinux").exists():
        return "SELinux"
    return None


def _detect_firewall_tool() -> str | None:
    for command, label in (("ufw", "UFW"), ("firewall-cmd", "firewalld"), ("nft", "nftables"), ("iptables", "iptables")):
        if shutil.which(command):
            return label
    return None


def detect_distro() -> DistroInfo:
    data = _read_os_release()
    return DistroInfo(
        distro_id=data.get("ID", "unknown"),
        name=data.get("PRETTY_NAME") or data.get("NAME") or "Distribución desconocida",
        version=data.get("VERSION_ID", ""),
        package_manager=_detect_package_manager(),
        has_systemd=_has_systemd(),
        mac_module=_detect_mac_module(),
        firewall_tool=_detect_firewall_tool(),
    )
