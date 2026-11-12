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
    Tab-separated directives are accepted (valid in sshd_config).
    """
    settings: dict[str, str] = {}
    for raw in lines:
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split(None, 1)
        if len(parts) != 2:
            continue
        key, value = parts
        key = key.lower()
        value = value.lower()
        if key in ("permitrootlogin", "passwordauthentication") and value:
            settings.setdefault(key, value)
    return settings


def merge_sshd_texts(main: list[str], extras: list[list[str]]) -> list[str]:
    """Merge sshd_config with sshd_config.d/*.conf contents, extras first.

    sshd honours the FIRST occurrence of a keyword. Debian/Ubuntu put
    `Include /etc/ssh/sshd_config.d/*.conf` at the top of the main file,
    so the .conf files win over the main file: prepending them matches
    what sshd really applies.
    """
    merged: list[str] = []
    for extra in extras:
        merged += extra
    return merged + main


def sudo_members(lines: list[str]) -> tuple[list[str], list[str]]:
    """(groups found, deduplicated members) of the admin groups in group lines."""
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
    return seen_groups, list(dict.fromkeys(members))


# --- checkers ----------------------------------------------------------------


def comprobar_permisos(distro: DistroInfo) -> list[Finding]:
    findings: list[Finding] = []
    findings += _check_uid_zero()
    findings += _check_empty_passwords()
    findings += _check_file_modes()
    findings += _check_sudo_members()
    findings += _check_sshd_config()
    return findings


def _read_lines(path: Path) -> list[str] | None:
    """File lines, or None when it cannot be read.

    None is distinct from an empty file: callers must report "unreadable"
    instead of pretending everything is fine (a silent false negative here
    is the worst outcome for this tool).
    """
    try:
        return path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None


def _unreadable_finding(label: str, reason: str) -> Finding:
    return Finding(
        title=f"No se pudo leer {label}",
        severity=Severidad.BAJA,
        detail=reason,
        source="permissions",
    )


def _check_uid_zero() -> list[Finding]:
    lines = _read_lines(PASSWD_PATH)
    if lines is None:
        return [
            _unreadable_finding(
                "/etc/passwd",
                "Es anómalo que no sea legible; sin él no se revisan las cuentas UID 0.",
            )
        ]
    roots = uid_zero_names(lines)
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
    lines = _read_lines(SHADOW_PATH)
    if lines is None:
        return [
            Finding(
                title="Revisión de contraseñas vacías incompleta",
                severity=Severidad.BAJA,
                detail="`/etc/shadow` no es legible sin privilegios de administrador.",
                suggestion="Ejecuta MintGuard con `sudo` para completar esta revisión.",
                source="permissions",
            )
        ]
    empty = accounts_without_password(lines)
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
    for path, label in (
        (PASSWD_PATH, "/etc/passwd"),
        (SHADOW_PATH, "/etc/shadow"),
        (SUDOERS_PATH, "/etc/sudoers"),
    ):
        if not path.exists():
            continue
        try:
            # stat() right away: exists()+stat() as two steps would race
            # with the file disappearing between both syscalls.
            mode = stat.S_IMODE(path.stat().st_mode)
        except OSError:
            findings.append(
                Finding(
                    title=f"No se pudo examinar {label}",
                    severity=Severidad.BAJA,
                    detail="Existe pero no se pudo consultar su modo en este momento.",
                    source="permissions",
                )
            )
            continue
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
        elif label == "/etc/shadow" and mode & 0o004:
            findings.append(
                Finding(
                    title="/etc/shadow legible por cualquier usuario",
                    severity=Severidad.ALTA,
                    detail=f"Permisos actuales: {oct(mode)}; los hashes de contraseñas quedan expuestos.",
                    suggestion=f"Corrige con `sudo chmod o-r {label}`.",
                    source="permissions",
                )
            )
        elif label == "/etc/sudoers" and mode & 0o004:
            findings.append(
                Finding(
                    title="/etc/sudoers legible por cualquier usuario",
                    severity=Severidad.MEDIA,
                    detail=f"Permisos actuales: {oct(mode)}; la política de sudo queda expuesta.",
                    suggestion=f"Corrige con `sudo chmod o-r {label}`.",
                    source="permissions",
                )
            )
    if not findings:
        findings.append(
            Finding(
                title="Permisos correctos en archivos críticos",
                severity=Severidad.INFO,
                detail="passwd, shadow y sudoers no son modificables ni legibles por otros usuarios.",
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
    main_lines = _read_lines(SSHD_CONFIG_PATH)
    if main_lines is None:
        return [
            _unreadable_finding(
                "/etc/ssh/sshd_config",
                "No se puede revisar la configuración de SSH sin leer el fichero.",
            )
        ]
    extras: list[list[str]] = []
    if SSHD_CONFIG_DIR.is_dir():
        for extra in sorted(SSHD_CONFIG_DIR.glob("*.conf")):
            extra_lines = _read_lines(extra)
            if extra_lines is not None:
                extras.append(extra_lines)
    settings = sshd_settings(merge_sshd_texts(main_lines, extras))
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
