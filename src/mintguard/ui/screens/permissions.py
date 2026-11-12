"""Permissions and dangerous users check screen."""

from __future__ import annotations

from mintguard.checks.permissions import comprobar_permisos
from mintguard.core.distro import DistroInfo
from mintguard.core.prioritizer import Finding
from mintguard.ui.screens.base import BaseCheckScreen


class PermissionsScreen(BaseCheckScreen):
    title = "Permisos"
    check_title = "Permisos y usuarios peligrosos"
    check_source = "permissions"
    check_hint = (
        "Revisa UID 0, contraseñas vacías, permisos de archivos críticos,\n"
        "miembros de sudo y la configuración de SSH. Solo lectura de archivos.\n"
        "Pulsa Enter o el botón para ejecutar el chequeo."
    )

    def _check(self, distro: DistroInfo) -> list[Finding]:
        return comprobar_permisos(distro)
