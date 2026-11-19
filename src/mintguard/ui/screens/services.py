"""Enabled services check screen."""

from __future__ import annotations

from mintguard.checks.services import comprobar_servicios
from mintguard.core.distro import DistroInfo
from mintguard.core.prioritizer import Finding
from mintguard.ui.screens.base import BaseCheckScreen


class ServicesScreen(BaseCheckScreen):
    TITLE = "Servicios"
    check_title = "Servicios habilitados"
    check_source = "services"
    check_hint = (
        "Lista los servicios habilitados al arranque (systemd, openrc, runit\n"
        "o sysvinit, según tu sistema) y marca los inseguros conocidos\n"
        "(telnet, tftp, rsh, etc.).\n"
        "Pulsa Enter o el botón para ejecutar el chequeo."
    )

    def _check(self, distro: DistroInfo) -> list[Finding]:
        return comprobar_servicios(distro)
