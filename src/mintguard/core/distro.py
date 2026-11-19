"""Distribution and environment detection (filesystem based, no subprocesses)."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from mintguard.core.commands import resolve_binary

OS_RELEASE_PATH = Path("/etc/os-release")

# Init-system markers (read-only detection; no subprocesses).
SYSTEMD_RUN_DIR = Path("/run/systemd/system")
OPENRC_RUN_DIR = Path("/run/openrc")
RUNIT_ETC_DIR = Path("/etc/runit")
RUNIT_RUN_DIR = Path("/run/runit")
SYSVINIT_INITCTL = Path("/run/initctl")
PID1_COMM_PATH = Path("/proc/1/comm")

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
    # "systemd" | "openrc" | "runit" | "sysvinit" | "desconocido"
    init_system: str = "desconocido"


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
        path = resolve_binary(name)
        if path:
            return PackageManager(name=name, path=path)
    path = resolve_binary("apt-get")
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


def _detect_init() -> str:
    """Init system from filesystem markers (feedback: don't assume systemd).

    Order: the running init's own directories first, then `/proc/1/comm`
    as the fallback. No subprocesses, no distro guessing.
    """
    if SYSTEMD_RUN_DIR.is_dir():
        return "systemd"
    if OPENRC_RUN_DIR.exists():
        return "openrc"
    if RUNIT_ETC_DIR.is_dir() or RUNIT_RUN_DIR.is_dir():
        return "runit"
    if SYSVINIT_INITCTL.exists():
        return "sysvinit"
    try:
        comm = PID1_COMM_PATH.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return "desconocido"
    if comm in ("openrc-init", "openrc"):
        return "openrc"
    if comm in ("runit", "runit-init"):
        return "runit"
    if comm == "systemd":
        return "systemd"
    if comm == "init":
        # sysvinit's /sbin/init; busybox+openrc is caught by /run/openrc above.
        return "sysvinit"
    return "desconocido"


def _detect_mac_module() -> str | None:
    if Path("/sys/kernel/security/apparmor").exists():
        return "AppArmor"
    if Path("/sys/fs/selinux").exists():
        return "SELinux"
    return None


def _detect_firewall_tool() -> str | None:
    for command, label in (("ufw", "UFW"), ("firewall-cmd", "firewalld"), ("nft", "nftables"), ("iptables", "iptables")):
        if resolve_binary(command):
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
        init_system=_detect_init(),
    )
