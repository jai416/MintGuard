"""Firewall active-state check.

"Installed but not active" is a real security finding (ALTA): everything
listening on the network is left unfiltered. Determined without root via
`systemctl is-active`; with root, `ufw status` is authoritative.
"""

from __future__ import annotations

import os
import subprocess

from mintguard.core.distro import DistroInfo
from mintguard.core.prioritizer import Finding, Severidad

_RUN_TIMEOUT = 15

_SERVICE_CANDIDATES: dict[str, tuple[str, ...]] = {
    "UFW": ("ufw",),
    "firewalld": ("firewalld",),
    "nftables": ("nftables",),
    "iptables": ("netfilter-persistent", "iptables"),
}

_SUGGESTION_BY_TOOL = {
    "UFW": "`sudo ufw enable`",
    "firewalld": "`sudo systemctl enable --now firewalld`",
    "nftables": "carga tu ruleset y actívalo: `sudo systemctl enable --now nftables`",
    "iptables": "restaura tus reglas y actívalas: `sudo systemctl enable --now netfilter-persistent`",
}

# ufw output may be localized; accept the common Spanish variants too.
_STATUS_KEYS = {"status", "estado"}
_ACTIVE_VALUES = {"active", "activo", "activa"}
_INACTIVE_VALUES = {"inactive", "inactivo", "inactiva"}


# --- pure parsers (no subprocess, no I/O) ------------------------------------


def parse_ufw_status(text: str) -> str | None:
    """'active'/'inactive' from `ufw status`; None when not determinable."""
    for line in text.splitlines():
        key, separator, value = line.partition(":")
        if separator and key.strip().lower() in _STATUS_KEYS:
            value = value.strip().lower()
            if value in _ACTIVE_VALUES:
                return "active"
            if value in _INACTIVE_VALUES:
                return "inactive"
            return None  # recognized key, unrecognized value (e.g. an error)
    return None


def parse_firewall_cmd_state(text: str) -> str | None:
    """'active'/'inactive' from `firewall-cmd --state` (running / not running)."""
    value = text.strip().lower()
    if value == "running":
        return "active"
    if "not running" in value:
        return "inactive"
    return None


def parse_systemctl_is_active(text: str) -> str | None:
    """'active'/'inactive' from `systemctl is-active`; None when unknown.

    Some systemd versions print `inactive` even for a nonexistent unit;
    the service is only consulted when the tool binary is in PATH, so
    this edge case is accepted.
    """
    value = text.strip().lower()
    if value == "active":
        return "active"
    if value in ("inactive", "failed"):
        return "inactive"
    return None


def firewall_finding(tool: str | None, state: str) -> Finding:
    """Decision matrix (pure, testable). state: active|inactive|desconocido."""
    if tool is None:
        return Finding(
            title="No se detectó ningún firewall",
            severity=Severidad.MEDIA,
            detail="No se encontraron ufw, firewalld, nftables ni iptables en el PATH.",
            suggestion=(
                "Instala y activa uno: `sudo apt install ufw` y `sudo ufw enable` "
                "(Debian/Mint/Ubuntu); en Fedora, firewalld; en Arch/openSUSE, "
                "consulta la documentación de tu distribución."
            ),
            source="network",
        )
    if state == "active":
        return Finding(
            title=f"Firewall activo ({tool})",
            severity=Severidad.INFO,
            detail="El firewall está cargado y filtrando tráfico.",
            source="network",
        )
    if state == "inactive":
        return Finding(
            title=f"Firewall instalado pero no activo ({tool})",
            severity=Severidad.ALTA,
            detail="Está instalado pero no filtra tráfico: lo que escuche en la red queda expuesto.",
            suggestion=(
                "Actívalo: "
                + _SUGGESTION_BY_TOOL.get(tool, "consulta la documentación de tu distribución")
                + "."
            ),
            source="network",
        )
    return Finding(
        title=f"No se pudo determinar el estado del firewall ({tool})",
        severity=Severidad.BAJA,
        detail="El comando de consulta no respondió con un estado reconocible.",
        suggestion=(
            f"Compruébalo a mano: `sudo ufw status` o `systemctl status {tool.lower()}`."
        ),
        source="network",
    )


# --- checker -----------------------------------------------------------------


def _run(cmd: list[str]) -> subprocess.CompletedProcess | None:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=_RUN_TIMEOUT, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None


def _state_from_systemctl(services: tuple[str, ...]) -> str | None:
    for service in services:
        result = _run(["systemctl", "is-active", service])
        if result is None:
            continue  # a one-off timeout must not abort the other candidates
        state = parse_systemctl_is_active(result.stdout)
        if state is not None:
            return state
    return None


def firewall_state(distro: DistroInfo) -> str:
    """Return 'active', 'inactive' or 'desconocido' for the detected tool."""
    tool = distro.firewall_tool
    if tool is None:
        return "desconocido"
    if tool == "firewalld":
        # Talks to D-Bus: answers without root when the daemon runs.
        result = _run(["firewall-cmd", "--state"])
        if result is not None:
            state = parse_firewall_cmd_state(result.stdout)
            if state is not None:
                return state
    if tool == "UFW" and os.geteuid() == 0:
        # Authoritative when root; localized errors yield None and fall back.
        result = _run(["ufw", "status"])
        if result is not None:
            state = parse_ufw_status(result.stdout)
            if state is not None:
                return state
    if distro.has_systemd:
        state = _state_from_systemctl(_SERVICE_CANDIDATES.get(tool, ()))
        if state is not None:
            return state
    return "desconocido"


def comprobar_firewall(distro: DistroInfo) -> list[Finding]:
    return [firewall_finding(distro.firewall_tool, firewall_state(distro))]
