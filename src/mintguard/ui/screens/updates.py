"""Updates check screen."""

from __future__ import annotations

from mintguard.checks.updates import comprobar_actualizaciones
from mintguard.core.distro import DistroInfo
from mintguard.core.prioritizer import Finding
from mintguard.ui.screens.base import BaseCheckScreen


class UpdatesScreen(BaseCheckScreen):
    title = "Actualizaciones"
    check_title = "Actualizaciones y vulnerabilidades"
    check_source = "updates"
    check_running_note = "la simulación de dist-upgrade puede tardar ~30 s en hardware lento."
    check_hint = (
        "Consulta los paquetes actualizables según tu gestor (apt, dnf, pacman o zypper).\n"
        "Con sudo se refrescan primero los datos; sin sudo se usa la caché local.\n"
        "Pulsa Enter o el botón para ejecutar el chequeo. Puedes cancelar con x."
    )

    def _check(self, distro: DistroInfo) -> list[Finding]:
        return comprobar_actualizaciones(distro)
