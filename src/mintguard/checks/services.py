"""Enabled services check per init system (on demand, read-only).

systemd via `systemctl`; openrc via `rc-update show default`; runit and
sysvinit by scanning their service directories (no subprocesses for
those). No init guess: DistroInfo.init_system decides the branch.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from mintguard.core.commands import resolve_binary, run_command
from mintguard.core.confidence import Signal
from mintguard.core.distro import DistroInfo
from mintguard.core.prioritizer import Finding, Severidad

RISKY_SERVICE_KEYWORDS = ("telnet", "tftp", "rsh", "rlogin", "rexec", "finger")

# Where enabled services live without systemd (read-only, no guessing).
RUNIT_SERVICE_DIRS = (Path("/etc/service"), Path("/var/service"), Path("/service"))
SYSVINIT_RC_DIRS = tuple(Path(f"/etc/rc{level}.d") for level in (2, 3, 4, 5))


def risky_service_names(services: list[str]) -> list[str]:
    """Service names running legacy remote access, matched by exact stem.

    Matches telnet/telnetd, tftp/tftpd... without substring false
    positives such as `rshim.service`, which merely contains "rsh".
    Templated units (`tftp@.service`) are reduced to their stem too.
    """
    risky: list[str] = []
    for service in services:
        stem = service.split("@", 1)[0].split(".", 1)[0].lower()
        base = stem[:-1] if stem.endswith("d") else stem
        if stem in RISKY_SERVICE_KEYWORDS or base in RISKY_SERVICE_KEYWORDS:
            risky.append(service)
    return risky


def enabled_service_names(text: str) -> list[str]:
    """Unit names from `systemctl list-unit-files --no-legend` output."""
    return [line.split()[0] for line in text.splitlines() if line.strip()]


def parse_rc_update_show(text: str) -> list[str]:
    """`rc-update show` → servicios en el nivel `default`.

    Líneas con el formato ` * nombre | niveles` (p. ej.
    ` * sshd | boot default`); solo cuenta lo que está en `default`.
    """
    servicios: list[str] = []
    for raw in text.splitlines():
        if "|" not in raw:
            continue
        izquierda, _, niveles = raw.partition("|")
        if "default" not in niveles.split():
            continue
        nombre = izquierda.strip().lstrip("*").strip()
        if nombre:
            servicios.append(nombre)
    return servicios


def runit_service_names(directories: tuple[Path, ...]) -> list[str]:
    """Entradas de los directorios de svscan de runit (enlaces o dirs)."""
    nombres: set[str] = set()
    for directorio in directories:
        try:
            entradas = os.scandir(directorio)
        except OSError:
            continue
        with entradas:
            for entrada in entradas:
                if entrada.name not in (".", ".."):
                    nombres.add(entrada.name)
    return sorted(nombres)


def sysvinit_enabled_names(directories: tuple[Path, ...]) -> list[str]:
    """Symlinks `S##nombre` de /etc/rcN.d: el prefijo S## se quita."""
    nombres: set[str] = set()
    for directorio in directories:
        try:
            entradas = os.scandir(directorio)
        except OSError:
            continue
        with entradas:
            for entrada in entradas:
                nombre = entrada.name
                if nombre.startswith("S") and nombre[1:2].isdigit():
                    nombres.add(nombre.lstrip("S0123456789") or nombre)
    return sorted(nombres)


def _run(cmd: list[str], timeout: int = 60) -> subprocess.CompletedProcess | None:
    return run_command(cmd, timeout)


def _sugerencia_desactivar(init: str, service: str) -> str:
    """Cómo desactivar un servicio, según el init."""
    if init == "openrc":
        return f"`sudo rc-update del {service} default`"
    if init == "runit":
        return f"quita el enlace de `/etc/service/{service}`"
    if init == "sysvinit":
        return f"`sudo update-rc.d {service} remove`"
    return f"`sudo systemctl disable --now {service}`"


def _hallazgos_servicios(servicios: list[str], init: str) -> list[Finding]:
    """Riesgosos (cualquier init) + recuento; el init solo cambia el cómo."""
    findings: list[Finding] = []
    for service in risky_service_names(servicios):
        findings.append(
            Finding(
                title=f"Servicio inseguro habilitado: {service}",
                severity=Severidad.ALTA,
                detail="Servicio de acceso remoto antiguo habilitado al arranque.",
                suggestion=(
                    f"Desactívalo si no lo necesitas: {_sugerencia_desactivar(init, service)}."
                ),
                evidence=[service],
                signals=[
                    Signal.for_(
                        "Se arranca con el sistema y queda escuchando: es un acceso remoto "
                        "sin cifrado moderno."
                    ),
                ],
                source="services",
            )
        )
    conteo = {
        "openrc": "Desactiva los que no uses: `sudo rc-update del <servicio> default`.",
        "runit": "Desactiva los que no uses: quita los enlaces de tus directorios de servicios.",
        "sysvinit": "Desactiva los que no uses: `sudo update-rc.d <servicio> remove`.",
    }.get(init, "Desactiva los que no uses: `sudo systemctl disable --now <servicio>`.")
    findings.append(
        Finding(
            title=f"{len(servicios)} servicios habilitados al arranque",
            severity=Severidad.INFO,
            detail="Cada servicio habilitado aumenta la superficie de ataque y el tiempo de arranque.",
            suggestion=conteo,
            evidence=servicios[:50],
            source="services",
        )
    )
    return findings


def _servicios_de_init(init: str) -> tuple[list[str], str]:
    """(servicios habilitados, motivo de fallo) para un init sin systemd."""
    if init == "openrc":
        binario = resolve_binary("rc-update")
        if binario is None:
            return [], "el comando rc-update no está disponible"
        result = _run([binario, "show", "default"], timeout=30)
        if result is None:
            return [], "rc-update show default no respondió dentro del tiempo límite"
        if result.returncode != 0 and not result.stdout.strip():
            # A failed query must never be reported as "0 services enabled".
            return [], f"rc-update terminó con error (código {result.returncode}) y sin datos"
        return parse_rc_update_show(result.stdout), ""
    if init == "runit":
        if not any(directorio.exists() for directorio in RUNIT_SERVICE_DIRS):
            return [], "no se encontró ningún directorio de servicios de runit"
        return runit_service_names(RUNIT_SERVICE_DIRS), ""
    if not any(directorio.exists() for directorio in SYSVINIT_RC_DIRS):
        return [], "no se encontró ningún directorio /etc/rcN.d"
    return sysvinit_enabled_names(SYSVINIT_RC_DIRS), ""


def comprobar_servicios(distro: DistroInfo) -> list[Finding]:
    """Servicios habilitados al arranque según el init (solo lectura)."""
    init = distro.init_system
    if init in ("openrc", "runit", "sysvinit"):
        servicios, error = _servicios_de_init(init)
        if error:
            return [
                Finding(
                    title=f"Servicios ({init}): no verificable",
                    severity=Severidad.INFO,
                    detail=f"No se ha podido comprobar ({error}).",
                    suggestion="Revisa los servicios de tu distribución a mano.",
                    source="services",
                )
            ]
        return _hallazgos_servicios(servicios, init)
    if not distro.has_systemd:
        return [
            Finding(
                title="Sistema de arranque no reconocido",
                severity=Severidad.INFO,
                detail=(
                    "No se pudo determinar el init (systemd, openrc, runit, sysvinit): "
                    "sin él no hay una forma estándar de listar los servicios "
                    "habilitados."
                ),
                suggestion="Revisa los servicios de tu distribución a mano.",
                source="services",
            )
        ]
    systemctl_path = resolve_binary("systemctl")
    if systemctl_path is None:
        return [
            Finding(
                title="No se pudo consultar systemctl",
                severity=Severidad.BAJA,
                detail="El comando no está disponible en este sistema.",
                source="services",
            )
        ]
    # Absolute path from a standard system directory: under sudo, a PATH
    # lookup would resolve `systemctl` in the inherited user PATH (same
    # rationale as `ss`).
    result = _run(
        [
            systemctl_path,
            "list-unit-files",
            "--type=service",
            "--state=enabled",
            "--no-legend",
            "--no-pager",
        ]
    )
    if result is None:
        return [
            Finding(
                title="No se pudo consultar systemctl",
                severity=Severidad.BAJA,
                detail="El comando no respondió dentro del tiempo límite.",
                source="services",
            )
        ]
    if result.returncode != 0 and not result.stdout.strip():
        # A failed query must never be reported as "0 services enabled".
        return [
            Finding(
                title="No se pudo consultar systemctl",
                severity=Severidad.BAJA,
                detail=f"El comando terminó con error (código {result.returncode}) y sin datos.",
                source="services",
            )
        ]
    services = enabled_service_names(result.stdout)
    return _hallazgos_servicios(services, "systemd")
