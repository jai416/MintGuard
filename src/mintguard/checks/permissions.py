"""Cheap permission/user checks based on system files (no disk scans).

Pure parsers live at module level so they are unit-testable; the checkers
only feed them lines read from system files.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

from mintguard.core.distro import DistroInfo
from mintguard.core.prioritizer import Finding, Severidad

PASSWD_PATH = Path("/etc/passwd")
SHADOW_PATH = Path("/etc/shadow")
GROUP_PATH = Path("/etc/group")
SUDOERS_PATH = Path("/etc/sudoers")
SSHD_CONFIG_PATH = Path("/etc/ssh/sshd_config")
SSHD_CONFIG_DIR = Path("/etc/ssh/sshd_config.d")

SUDO_GROUP_NAMES = ("sudo", "wheel", "admin")
_WORLD_WRITABLE = 0o002


# --- pure parsers (no I/O) ---------------------------------------------------


def uid_zero_names(lines: list[str]) -> list[str]:
    """Account names with UID 0 found in passwd-like lines."""
    names: list[str] = []
    for line in lines:
        fields = line.split(":")
        if len(fields) < 3:
            continue
        try:
            uid = int(fields[2])
        except ValueError:
            continue
        if uid == 0:
            names.append(fields[0])
    return names


def accounts_without_password(lines: list[str]) -> list[str]:
    """Account names with an empty password hash in shadow-like lines."""
    return [
        fields[0]
        for line in lines
        if len(fields := line.split(":")) >= 2 and fields[1] == ""
    ]


def sshd_settings(lines: list[str]) -> dict[str, str]:
    """Effective PermitRootLogin / PasswordAuthentication from sshd config lines.

    sshd uses the first occurrence of a keyword, so only the first
    uncommented value is kept (later lines are ignored, like sshd does).
    """
    settings: dict[str, str] = {}
    for raw in lines:
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        key, _, value = line.partition(" ")
        key = key.strip().lower()
        value = value.strip().lower()
        if key in ("permitrootlogin", "passwordauthentication") and value:
            settings.setdefault(key, value)
    return settings


def sudo_members(lines: list[str]) -> tuple[list[str], list[str]]:
    """(groups found, members) of the admin groups in group-like lines."""
    members: list[str] = []
    seen_groups: list[str] = []
    for line in lines:
        fields = line.split(":")
        if len(fields) < 4:
            continue
        group, user_list = fields[0], fields[3]
        if group in SUDO_GROUP_NAMES:
            seen_groups.append(group)
            members.extend(user for user in user_list.split(",") if user)
    return seen_groups, members


# --- checkers ----------------------------------------------------------------


def comprobar_permisos(distro: DistroInfo) -> list[Finding]:
    findings: list[Finding] = []
    findings += _check_uid_zero()
    findings += _check_empty_passwords()
    findings += _check_file_modes()
    findings += _check_sudo_members()
    findings += _check_sshd_config()
    return findings


def _read_lines(path: Path) -> list[str]:
    try:
        return path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []


def _check_uid_zero() -> list[Finding]:
    roots = uid_zero_names(_read_lines(PASSWD_PATH))
    extra = [name for name in roots if name != "root"]
    if extra:
        return [
            Finding(
                title="Usuarios con UID 0 además de root",
                severity=Severidad.CRITICA,
                detail="Cuentas con privilegios totales de root pero con otro nombre.",
                suggestion="Elimina o desactiva esas cuentas salvo que tengas una razón muy concreta.",
                evidence=extra,
                source="permissions",
            )
        ]
    return [
        Finding(
            title="Solo `root` tiene UID 0",
            severity=Severidad.INFO,
            detail="Configuración esperada.",
            source="permissions",
        )
    ]


def _check_empty_passwords() -> list[Finding]:
    if not os.access(SHADOW_PATH, os.R_OK):
        return [
            Finding(
                title="Revisión de contraseñas vacías incompleta",
                severity=Severidad.BAJA,
                detail="`/etc/shadow` no es legible sin privilegios de administrador.",
                suggestion="Ejecuta MintGuard con `sudo` para completar esta revisión.",
                source="permissions",
            )
        ]
    empty = accounts_without_password(_read_lines(SHADOW_PATH))
    if empty:
        return [
            Finding(
                title="Cuentas sin contraseña",
                severity=Severidad.CRITICA,
                detail="Estas cuentas pueden entrar sin escribir contraseña.",
                suggestion="Establece contraseña o bloquea la cuenta: `sudo passwd -l usuario`.",
                evidence=empty,
                source="permissions",
            )
        ]
    return [
        Finding(
            title="Ninguna cuenta sin contraseña",
            severity=Severidad.INFO,
            detail="Todas las cuentas revisadas tienen contraseña o bloqueo.",
            source="permissions",
        )
    ]


def _check_file_modes() -> list[Finding]:
    findings: list[Finding] = []
    for path, label in ((PASSWD_PATH, "/etc/passwd"), (SHADOW_PATH, "/etc/shadow"), (SUDOERS_PATH, "/etc/sudoers")):
        if not path.exists():
            continue
        mode = stat.S_IMODE(path.stat().st_mode)
        if mode & _WORLD_WRITABLE:
            findings.append(
                Finding(
                    title=f"{label} modificable por cualquier usuario",
                    severity=Severidad.CRITICA if label != "/etc/passwd" else Severidad.ALTA,
                    detail=f"Permisos actuales: {oct(mode)}.",
                    suggestion=f"Corrige con `sudo chmod o-w {label}` y revisa quién lo modificó.",
                    source="permissions",
                )
            )
    if not findings:
        findings.append(
            Finding(
                title="Permisos correctos en archivos críticos",
                severity=Severidad.INFO,
                detail="passwd, shadow y sudoers no son modificables por otros usuarios.",
                source="permissions",
            )
        )
    return findings


def _check_sudo_members() -> list[Finding]:
    lines = _read_lines(GROUP_PATH)
    if not lines:
        return [
            Finding(
                title="No se pudo leer /etc/group",
                severity=Severidad.BAJA,
                detail="Sin esta información no se revisan los grupos de administradores.",
                source="permissions",
            )
        ]
    seen_groups, members = sudo_members(lines)
    if not seen_groups:
        return [
            Finding(
                title="No se detectó grupo de administradores",
                severity=Severidad.BAJA,
                detail="No existe ningún grupo sudo/wheel/admin en /etc/group.",
                suggestion="Revisa cómo se otorgan privilegios en tu distribución.",
                source="permissions",
            )
        ]
    normal = [member for member in members if member != "root"]
    return [
        Finding(
            title="Usuarios con privilegios de administrador (sudo)",
            severity=Severidad.INFO,
            detail=f"Grupos: {', '.join(seen_groups)}. Mantén la lista corta: cada usuario de sudo es superficie de ataque.",
            evidence=normal,
            source="permissions",
        )
    ]


def _check_sshd_config() -> list[Finding]:
    if not SSHD_CONFIG_PATH.exists():
        return [
            Finding(
                title="Servidor SSH no instalado",
                severity=Severidad.INFO,
                detail="No existe /etc/ssh/sshd_config; nada que revisar aquí.",
                source="permissions",
            )
        ]
    texts = _read_lines(SSHD_CONFIG_PATH)
    if SSHD_CONFIG_DIR.is_dir():
        for extra in sorted(SSHD_CONFIG_DIR.glob("*.conf")):
            texts += _read_lines(extra)
    settings = sshd_settings(texts)
    root_login = settings.get("permitrootlogin", "")
    password_auth = settings.get("passwordauthentication", "")

    findings: list[Finding] = []
    if root_login == "yes":
        findings.append(
            Finding(
                title="SSH permite inicio de sesión directo de root",
                severity=Severidad.ALTA,
                detail="PermitRootLogin yes en la configuración de sshd.",
                suggestion="Cámbialo a `prohibit-password` o `no` y reinicia el servicio ssh.",
                source="permissions",
            )
        )
    else:
        findings.append(
            Finding(
                title="SSH sin acceso root directo",
                severity=Severidad.INFO,
                detail="PermitRootLogin no está en `yes`.",
                source="permissions",
            )
        )
    if (password_auth or "yes") == "yes":  # sshd default is `yes`
        findings.append(
            Finding(
                title="SSH acepta autenticación por contraseña",
                severity=Severidad.MEDIA,
                detail="PasswordAuthentication está en `yes` (explícito o por defecto).",
                suggestion="Usa claves SSH y pon `PasswordAuthentication no` si es posible.",
                source="permissions",
            )
        )
    else:
        findings.append(
            Finding(
                title="SSH configurado con claves (sin contraseñas)",
                severity=Severidad.INFO,
                detail="PasswordAuthentication no.",
                source="permissions",
            )
        )
    return findings
