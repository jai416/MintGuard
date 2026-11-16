"""Read-only hardening audit of the machine (kernel, hardware, rules).

Everything here only READS: /proc, /sys, /etc and a couple of query
commands. MintGuard never changes the system: it says what it found
and what to do, and the user does it (or not).

Pure parsers live at module level so they can be unit-tested without
touching the machine; the checkers only feed them lines read from the
system. A file that cannot be read is never a crash: it becomes an
INFO "no verificable" finding and the check carries on.
"""

from __future__ import annotations

import os
import re
import stat
from pathlib import Path
from typing import NamedTuple

from mintguard.core.commands import resolve_binary, run_command
from mintguard.core.confidence import Signal
from mintguard.core.distro import DistroInfo
from mintguard.core.prioritizer import Finding, Severidad

SOURCE = "sistema"

# --- paths (standard on Linux; no distro-specific guesses) -------------------

TAINTED_PATH = Path("/proc/sys/kernel/tainted")
CORE_PATTERN_PATH = Path("/proc/sys/kernel/core_pattern")
LIMITS_PATH = Path("/proc/self/limits")
CPU_VULNERABILITIES_DIR = Path("/sys/devices/system/cpu/vulnerabilities")
IOMMU_DIR = Path("/sys/class/iommu")
EFI_DIR = Path("/sys/firmware/efi")
SUDOERS_PATH = Path("/etc/sudoers")
SUDOERS_DIR = Path("/etc/sudoers.d")
APPARMOR_PROFILES_PATH = Path("/sys/kernel/security/apparmor/profiles")
# Rutas donde vive el software del sistema (no el del usuario).
SYSTEM_BIN_DIRS = ("/usr/bin", "/bin", "/usr/sbin", "/sbin", "/usr/local/bin", "/usr/local/sbin")

# Bits of /proc/sys/kernel/tainted
# (Documentation/admin-guide/tainted-kernels.rst).
_TAINT_BITS = (
    (0, "se cargó un módulo propietario"),
    (1, "se cargó un módulo defectuoso a la fuerza"),
    (2, "se forzó la carga de un módulo"),
    (3, "el kernel está en modo lockdown"),
    (4, "se forzó el estado tainted"),
    (5, "se cargó un módulo fuera del árbol del kernel"),
    (6, "se cargó un módulo fuera del árbol sin firmar"),
    (7, "un módulo se cargó con force unload"),
    (8, "el kernel está tainted por un problema de hardware"),
    (9, "el kernel está tainted por una carga de firmware"),
    (10, "el kernel está tainted por un módulo auxiliar"),
    (11, "el kernel está tainted por un módulo cargado desde un sistema vivo"),
    (12, "el kernel se parcheó en caliente (live patch)"),
    (13, "el kernel está tainted por un driver de GPU u otro"),
    (14, "el kernel está tainted por un módulo sin firmar"),
    (15, "el kernel está tainted por un módulo propietario"),
)
_TAINT_BIT_SECURITY = 13  # bit 13: el revisor lo trata como fallo de seguridad

# Editors and pagers that spawn a shell: `sudo /usr/bin/vim *` is root.
_SUDOERS_EDITORS = re.compile(r"/(vim|vi|nano|less|more|find|awk|man|ftp)\b.*\*")
_SUDOERS_ALIAS = re.compile(r"^\s*(\w+)\s*=\s*(.+)$")


# --- pure parsers (no I/O) ---------------------------------------------------


def parse_tainted(text: str) -> tuple[int, list[str]]:
    """(valor, motivos) del bitmask de /proc/sys/kernel/tainted.

    -1 when the file does not hold a number.
    """
    try:
        value = int(text.strip())
    except (ValueError, AttributeError):
        return -1, []
    reasons = [reason for bit, reason in _TAINT_BITS if value & (1 << bit)]
    return value, reasons


def parse_core_limit(text: str) -> int | None:
    """Límite del volcado de memoria en bytes (None si no se encuentra).

    0 means "no dumps", -1 means "unlimited".
    """
    for line in text.splitlines():
        if line.lower().startswith("core file size"):
            fields = line.split()
            if len(fields) < 4:
                return None
            value = fields[3].lower()
            if value == "unlimited":
                return -1
            try:
                return int(value)
            except ValueError:
                return None
    return None


def parse_vulnerability_status(text: str) -> str:
    """Estado de una vulnerabilidad de CPU: vulnerable|mitigated|not-affected|unknown."""
    cleaned = (text or "").strip()
    if "Not affected" in cleaned:
        return "not-affected"
    if "Mitigation" in cleaned:
        return "mitigated"
    if "Vulnerable" in cleaned:
        return "vulnerable"
    return "unknown"


def sudoers_command_spec(line: str) -> str:
    """Parte de comando de una regla de sudoers (lo que va tras el '=')."""
    if "=" not in line:
        return ""
    spec = line.split("=", 1)[1].strip()
    if spec.startswith("("):  # runas "(root:root)"
        closing = spec.find(")")
        if closing != -1:
            spec = spec[closing + 1 :].strip()
    lowered = spec.lower()
    for tag in ("nopasswd:", "passwd:", "noexec:", "exec:", "setenv:", "nosetenv:"):
        if lowered.startswith(tag):
            spec = spec[len(tag) :].strip()
            break
    return spec


def parse_sudoers_rules(lines: list[str]) -> list[tuple[str, str]]:
    """(tipo, línea) de las reglas problemáticas de sudoers.

    Types: "nopasswd_all", "env_keep", "wildcard".
    """
    issues: list[tuple[str, str]] = []
    for raw in lines:
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        lowered = line.lower()
        if "env_keep" in lowered and ("ld_preload" in lowered or "ld_library_path" in lowered):
            issues.append(("env_keep", line))
            continue
        spec = sudoers_command_spec(line)
        if not spec:
            continue
        if "nopasswd" in lowered and spec.split()[0].lower() == "all":
            issues.append(("nopasswd_all", line))
            continue
        if _SUDOERS_EDITORS.search(spec):
            issues.append(("wildcard", line))
    return issues


def parse_sudoers_aliases(lines: list[str]) -> list[str]:
    """Alias definidos en sudoers (User_Alias, Host_Alias, Cmnd_Alias)."""
    aliases: list[str] = []
    for raw in lines:
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        fields = line.split(None, 1)
        if len(fields) != 2:
            continue
        keyword = fields[0].lower()
        if keyword in ("user_alias", "host_alias", "cmnd_alias"):
            aliases.append(fields[1].split("=", 1)[0].strip())
    return aliases


def parse_apparmor_profiles(text: str) -> tuple[int, int, list[str]]:
    """(perfiles en enforce, perfiles en complain, nombres en complain)."""
    enforce = 0
    complain: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.endswith("(complain)"):
            complain.append(line.split()[0])
        elif line.endswith("(enforce)"):
            enforce += 1
    return enforce, len(complain), complain


# --- reading helpers ---------------------------------------------------------


def _read_text(path: Path) -> tuple[str | None, str]:
    """(contenido, motivo del fallo). El motivo va vacío si se pudo leer."""
    try:
        return path.read_text(encoding="utf-8", errors="replace"), ""
    except FileNotFoundError:
        return None, "no existe"
    except PermissionError:
        return None, "sin permiso de lectura"
    except OSError:
        return None, "no se pudo leer"


def _no_verifiable(what: str, reason: str, suggestion: str = "") -> Finding:
    return Finding(
        title=f"{what}: no verificable",
        severity=Severidad.INFO,
        detail=f"No se ha podido comprobar ({reason}).",
        suggestion=suggestion,
        source=SOURCE,
    )


# --- checks ------------------------------------------------------------------


def check_kernel_taint() -> list[Finding]:
    """A) Estado 'tainted' del kernel: módulos propietarios, parches en caliente…"""
    content, error = _read_text(TAINTED_PATH)
    if content is None:
        return [
            _no_verifiable(
                "Estado del kernel (tainted)",
                error,
                "Con sudo se puede comprobar: `cat /proc/sys/kernel/tainted`.",
            )
        ]
    value, reasons = parse_tainted(content)
    if value < 0:
        return [
            _no_verifiable(
                "Estado del kernel (tainted)",
                "el fichero no contiene un número",
                "Con sudo se puede comprobar: `cat /proc/sys/kernel/tainted`.",
            )
        ]
    if value == 0:
        return [
            Finding(
                title="Kernel sin 'tainted'",
                severity=Severidad.INFO,
                detail="El kernel no está marcado como contaminado: solo carga módulos firmados.",
                source=SOURCE,
            )
        ]
    severity = Severidad.ALTA if value & (1 << _TAINT_BIT_SECURITY) else Severidad.MEDIA
    return [
        Finding(
            title="Kernel marcado como 'tainted'",
            severity=severity,
            detail=(
                f"El kernel está marcado como contaminado (valor {value}): "
                + "; ".join(reasons)
                + ". Un kernel tainted no puede garantizar la integridad de sus módulos."
            ),
            suggestion=(
                "Normal con drivers propietarios (NVIDIA, VirtualBox). Si no los usas, "
                "revisa qué módulo los carga."
            ),
            evidence=[f"tainted={value}"] + reasons,
            signals=[
                Signal.for_(
                    "El kernel está marcado como contaminado: carga módulos que no "
                    "puede verificar."
                ),
                Signal.against(
                    "Los drivers propietarios (NVIDIA, VirtualBox) lo marcan así por "
                    "diseño; no implica por sí solo un módulo malicioso."
                ),
            ],
            source=SOURCE,
        )
    ]


def check_core_dumps() -> list[Finding]:
    """B) Volcados de memoria: pueden escribir contraseñas a disco."""
    pattern, error = _read_text(CORE_PATTERN_PATH)
    if pattern is None:
        return [
            _no_verifiable(
                "Volcados de memoria",
                error,
                "Con sudo se puede comprobar: `cat /proc/sys/kernel/core_pattern`.",
            )
        ]
    pattern = pattern.strip()
    limits, limits_error = _read_text(LIMITS_PATH)
    limit = parse_core_limit(limits) if limits is not None else None

    if pattern.startswith("|"):
        return [
            Finding(
                title="Los volcados de memoria van a un gestor",
                severity=Severidad.INFO,
                detail=(
                    f"El patrón de volcado es `{pattern}`: el kernel delega la escritura "
                    "(normalmente systemd-coredump o apport)."
                ),
                source=SOURCE,
            )
        ]
    if limit is None:
        return [
            _no_verifiable(
                "Volcados de memoria",
                "no se pudo leer el límite de tamaño del fichero",
                "Compruébalo con `ulimit -c`.",
            )
        ]
    if limit != 0:
        return [
            Finding(
                title="Los volcados de memoria se escriben a disco",
                severity=Severidad.ALTA,
                detail=(
                    f"El patrón de volcado es `{pattern}` y el límite de tamaño no es 0 "
                    f"({limit} bytes): un proceso que se cuelgue deja su memoria (con "
                    "contraseñas y claves) en un fichero del disco."
                ),
                suggestion=(
                    "Pon el límite a 0 (`ulimit -c 0`) o delega los volcados a "
                    "systemd-coredump."
                ),
                evidence=[f"core_pattern={pattern}", f"límite={limit}"],
                signals=[
                    Signal.for_(
                        "El límite de tamaño del volcado no es 0: la memoria del proceso "
                        "se escribe en un fichero del disco."
                    ),
                    Signal.against(
                        "Solo se activa si un proceso se cuelga; no es un acceso remoto "
                        "a tu máquina."
                    ),
                ],
                source=SOURCE,
            )
        ]
    return [
        Finding(
            title="Sin volcados de memoria a disco",
            severity=Severidad.INFO,
            detail=(
                f"El patrón de volcado es `{pattern}` y el límite de tamaño es 0: "
                "un proceso que se cuelgue no deja su memoria en el disco."
            ),
            source=SOURCE,
        )
    ]


def check_cpu_mitigations() -> list[Finding]:
    """C) Mitigaciones de CPU (Spectre, Meltdown, MDS…)."""
    try:
        entries = sorted(CPU_VULNERABILITIES_DIR.iterdir())
    except FileNotFoundError:
        return [
            _no_verifiable(
                "Mitigaciones de CPU",
                "el kernel no expone el directorio de vulnerabilidades",
            )
        ]
    except PermissionError:
        return [
            _no_verifiable(
                "Mitigaciones de CPU",
                "sin permiso de lectura",
                "Con sudo se puede comprobar.",
            )
        ]
    except OSError:
        return [
            _no_verifiable("Mitigaciones de CPU", "no se pudo leer el directorio")
        ]

    vulnerable: list[str] = []
    mitigated = 0
    not_affected = 0
    for entry in entries:
        content, error = _read_text(entry)
        if content is None:
            continue
        status = parse_vulnerability_status(content)
        if status == "vulnerable":
            vulnerable.append(entry.name)
        elif status == "mitigated":
            mitigated += 1
        elif status == "not-affected":
            not_affected += 1

    if vulnerable:
        return [
            Finding(
                title=f"{len(vulnerable)} vulnerabilidad(es) de CPU sin mitigar",
                severity=Severidad.ALTA,
                detail=(
                    "El kernel expone estas vulnerabilidades sin mitigación activa: "
                    + ", ".join(vulnerable)
                    + ". Sin mitigación, un atacante local puede exploitearlas."
                ),
                suggestion=(
                    "Actualiza el kernel y comprueba `/sys/devices/system/cpu/vulnerabilities/`."
                ),
                evidence=vulnerable,
                signals=[
                    Signal.for_(
                        f"El kernel expone {len(vulnerable)} vulnerabilidad(es) de CPU sin "
                        "mitigar."
                    ),
                    Signal.against(
                        "Solo son explotables de forma local, por un atacante que ya "
                        "estuviera en la máquina."
                    ),
                ],
                source=SOURCE,
            )
        ]
    return [
        Finding(
            title="Mitigaciones de CPU activas",
            severity=Severidad.INFO,
            detail=(
                f"{mitigated} mitigación(es) activas y {not_affected} sin afección "
                f"({len(entries)} avisos del kernel revisados)."
            ),
            source=SOURCE,
        )
    ]


def check_iommu() -> list[Finding]:
    """D) IOMMU: protege la RAM frente a dispositivos DMA."""
    try:
        entries = list(IOMMU_DIR.iterdir())
    except FileNotFoundError:
        return [
            Finding(
                title="IOMMU no disponible",
                severity=Severidad.MEDIA,
                detail=(
                    "El kernel no expone IOMMU: un dispositivo PCIe con acceso directo a "
                    "la memoria (una GPU, una Thunderbolt) puede leer y escribir la RAM "
                    "sin dejar rastro, sin pasar por el sistema operativo."
                ),
                suggestion="Activa VT-d (Intel) o AMD-Vi en la BIOS.",
                source=SOURCE,
            )
        ]
    except PermissionError:
        return [_no_verifiable("IOMMU", "sin permiso de lectura", "Con sudo se puede comprobar.")]
    except OSError:
        return [_no_verifiable("IOMMU", "no se pudo leer el directorio")]

    if not entries:
        return [
            Finding(
                title="IOMMU presente pero sin dominios activos",
                severity=Severidad.MEDIA,
                detail=(
                    "El kernel expone IOMMU pero no hay ningún dominio configurado: la "
                    "protección frente a DMA no está en uso."
                ),
                suggestion="Activa VT-d (Intel) o AMD-Vi en la BIOS.",
                signals=[
                    Signal.for_("El kernel expone IOMMU."),
                    Signal.for_("No hay ningún dominio IOMMU configurado."),
                    Signal.against(
                        "Es normal en un equipo sin virtualización ni dispositivos PCIe "
                        "con acceso directo a memoria."
                    ),
                ],
                source=SOURCE,
            )
        ]
    return [
        Finding(
            title="IOMMU activo",
            severity=Severidad.INFO,
            detail=(
                f"IOMMU con {len(entries)} dominio(s): los dispositivos con acceso directo "
                "a memoria quedan confinados."
            ),
            evidence=[entry.name for entry in entries],
            signals=[Signal.for_("Hay dominios IOMMU activos: el DMA queda confinado.")],
            source=SOURCE,
        )
    ]


def check_secure_boot() -> list[Finding]:
    """E) Secure Boot: firmware firmado en el arranque."""
    if not EFI_DIR.exists():
        return [
            Finding(
                title="Secure Boot no aplica (arranque legacy)",
                severity=Severidad.INFO,
                detail=(
                    "El sistema no arranca por UEFI (arranque legacy): no hay firmware "
                    "firmado que verificar en el arranque."
                ),
                source=SOURCE,
            )
        ]
    variables = sorted(EFI_DIR.glob("efivars/SecureBoot-*"))
    if not variables:
        return [
            Finding(
                title="Secure Boot no verificable",
                severity=Severidad.INFO,
                detail=(
                    "El firmware expone UEFI pero no se encuentra la variable SecureBoot: "
                    "no se puede confirmar si está activa."
                ),
                suggestion="Compruébalo con `bootctl status` o `efi-readvar SecureBoot`.",
                source=SOURCE,
            )
        ]
    try:
        data = variables[0].read_bytes()
    except PermissionError:
        return [
            _no_verifiable(
                "Secure Boot",
                "sin permiso de lectura de las variables UEFI",
                "Con sudo se puede comprobar.",
            )
        ]
    except OSError:
        return [_no_verifiable("Secure Boot", "no se pudo leer la variable UEFI")]

    if not data:
        return [_no_verifiable("Secure Boot", "la variable UEFI está vacía")]
    enabled = data[-1] == 1
    if enabled:
        return [
            Finding(
                title="Secure Boot activo",
                severity=Severidad.INFO,
                detail=(
                    "El firmware valida las firmas en el arranque: el kernel y los "
                    "módulos deben estar firmados."
                ),
                source=SOURCE,
            )
        ]
    return [
        Finding(
            title="Secure Boot desactivado",
            severity=Severidad.ALTA,
            detail=(
                "El firmware no valida las firmas en el arranque: cualquiera con acceso "
                "de arranque puede ejecutar código sin firmar (un live USB, un disco "
                "externo, un cargador de arranque manipulado)."
            ),
            suggestion="Actívalo en la BIOS/UEFI (o usa `mokutil --enroll-key` si ya hay claves).",
            signals=[
                Signal.for_(
                    "El firmware no valida las firmas: se puede arrancar código sin "
                    "firmar."
                ),
                Signal.against(
                    "Hace falta acceso físico al arranque (un Live USB o un disco externo)."
                ),
            ],
            source=SOURCE,
        )
    ]


def check_sudoers() -> list[Finding]:
    """F) Reglas de sudoers: escalada de privilegios trivial."""
    paths = [SUDOERS_PATH]
    if SUDOERS_DIR.is_dir():
        paths += sorted(SUDOERS_DIR.glob("*"))

    findings: list[Finding] = []
    unreadable: list[str] = []
    alias_names: set[str] = set()
    rules: list[tuple[str, str, str]] = []  # (tipo, ruta, línea)
    skipped_alias = 0

    for path in paths:
        content, error = _read_text(path)
        if content is None:
            if error == "sin permiso de lectura":
                unreadable.append(str(path))
            continue
        lines = content.splitlines()
        aliases = parse_sudoers_aliases(lines)
        alias_names.update(aliases)
        for kind, line in parse_sudoers_rules(lines):
            # A rule whose user side is an alias cannot be judged here:
            # resolving it needs to know which users the alias groups.
            if line.split()[0] in alias_names:
                skipped_alias += 1
                continue
            rules.append((kind, str(path), line))

    if unreadable:
        findings.append(
            _no_verifiable(
                "Reglas de sudoers",
                f"sin permiso de lectura en {', '.join(unreadable)}",
                "Con sudo se pueden revisar: `sudo cat /etc/sudoers /etc/sudoers.d/*`.",
            )
        )
    if alias_names:
        detail = (
            "Se han encontrado alias ("
            + ", ".join(sorted(alias_names))
            + "): las reglas que los usan no se evalúan, porque resolverlos exige "
            "saber qué usuarios y hosts agrupan."
        )
        if skipped_alias:
            detail += f" ({skipped_alias} regla(s) sin evaluar por esto)"
        findings.append(
            Finding(
                title=f"{len(alias_names)} alias en sudoers sin resolver",
                severity=Severidad.INFO,
                detail=detail,
                suggestion="Revisa esas reglas a mano con `sudo visudo`.",
                source=SOURCE,
            )
        )
    for kind, path, line in rules:
        if kind == "nopasswd_all":
            findings.append(
                Finding(
                    title="Regla NOPASSWD: ALL en sudoers",
                    severity=Severidad.CRITICA,
                    detail=(
                        "Hay una regla NOPASSWD: ALL en sudoers: quien entre en ella "
                        "consigue root sin contraseña. Es una escalada de privilegios "
                        "directa."
                    ),
                    suggestion=(
                        "Usa NOPASSWD solo con comandos concretos e inofensivos, y revisa "
                        "esa regla con `sudo visudo -c`."
                    ),
                    evidence=[f"{path}: {line}"],
                    signals=[
                        Signal.for_(
                            "Quien entre en esa regla consigue root sin escribir "
                            "contraseña: es una escalada de privilegios directa."
                        ),
                    ],
                    source=SOURCE,
                )
            )
        elif kind == "env_keep":
            findings.append(
                Finding(
                    title="Variable de entorno peligrosa conservada en sudoers",
                    severity=Severidad.ALTA,
                    detail=(
                        "Hay una regla que conserva LD_PRELOAD o LD_LIBRARY_PATH: un "
                        "usuario puede cargar su propia librería en un programa que corre "
                        "como root."
                    ),
                    suggestion="Quita LD_PRELOAD y LD_LIBRARY_PATH de env_keep.",
                    evidence=[f"{path}: {line}"],
                    signals=[
                        Signal.for_(
                            "Con LD_PRELOAD o LD_LIBRARY_PATH conservado, un usuario "
                            "puede cargar su propia librería en un programa de root."
                        ),
                    ],
                    source=SOURCE,
                )
            )
        elif kind == "wildcard":
            findings.append(
                Finding(
                    title="Comodín peligroso en sudoers",
                    severity=Severidad.MEDIA,
                    detail=(
                        "Hay una regla de sudoers con un comodín sobre un editor o un "
                        "paginador: con él se puede abrir una shell como root "
                        "(`:!bash` en vim, `!sh` en less)."
                    ),
                    suggestion="Indica el comando exacto, sin comodines, o usa `--` con un editor seguro.",
                    evidence=[f"{path}: {line}"],
                    signals=[
                        Signal.for_(
                            "Un editor o un paginador con comodín puede abrir una shell "
                            "como root."
                        ),
                        Signal.against(
                            "Solo afecta a quien ya está en la lista de sudo."
                        ),
                    ],
                    source=SOURCE,
                )
            )
    if not findings:
        findings.append(
            Finding(
                title="Sin reglas de escalada evidente en sudoers",
                severity=Severidad.INFO,
                detail=(
                    "No se han encontrado NOPASSWD: ALL, variables de entorno "
                    "peligrosas conservadas ni comodines sobre editores o paginadores."
                ),
                source=SOURCE,
            )
        )
    return findings


def parse_desktop_exec(lines: list[str]) -> list[str]:
    """Valores `Exec=` de un fichero .desktop de autoarranque."""
    entries: list[str] = []
    for raw in lines:
        line = raw.strip()
        if line.lower().startswith("exec="):
            entries.append(line.split("=", 1)[1].strip())
    return entries


# Patrones de "descarga y ejecuta" (las partes tienen que estar todas).
_SUSPICIOUS_PATTERNS = (
    ("curl", "| bash"),
    ("curl", "|sh"),
    ("wget", "| sh"),
    ("wget", "|bash"),
    ("base64 -d",),
    ("base64 --decode",),
    ("eval $(",),
)


def parse_suspicious_commands(lines: list[str]) -> list[str]:
    """Líneas de un fichero de inicio con patrones sospechosos."""
    suspicious: list[str] = []
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if _looks_suspicious(line):
            suspicious.append(line)
    return suspicious


def _looks_suspicious(command: str) -> bool:
    """True when the command downloads and executes code in one go."""
    lowered = command.lower()
    for parts in _SUSPICIOUS_PATTERNS:
        if all(part in lowered for part in parts):
            return True
    return False


def parse_kernel_errors(text: str) -> list[str]:
    """Líneas del kernel que indican un fallo grave."""
    markers = ("BUG:", "Oops:", "WARNING:", "general protection fault", "kernel panic")
    found: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if any(marker.lower() in line.lower() for marker in markers):
            found.append(line)
    return found


_KNOWN_PATH_PREFIXES = (
    "/usr/bin",
    "/usr/sbin",
    "/bin",
    "/sbin",
    "/usr/local/bin",
    "/usr/local/sbin",
    "/opt",
)


def _is_known_path(command: str) -> bool:
    """True when the command points to a standard system location.

    A bare command name ("guake") is a PATH lookup: that is normal and
    is NOT flagged.
    """
    if "/" not in command:
        return True
    return any(command.startswith(prefix + "/") for prefix in _KNOWN_PATH_PREFIXES)


def check_persistence(distro: DistroInfo) -> list[Finding]:
    """H) Puntos de persistencia: qué se ejecuta al iniciar la sesión."""
    findings: list[Finding] = []
    home = Path.home()
    unknown: list[str] = []
    suspicious: list[str] = []
    entries = 0

    # 1) Autoarranque de la sesión de escritorio.
    autostart = home / ".config" / "autostart"
    if autostart.is_dir():
        for entry in sorted(autostart.glob("*.desktop")):
            content, error = _read_text(entry)
            if content is None:
                continue
            for command in parse_desktop_exec(content.splitlines()):
                entries += 1
                if _looks_suspicious(command):
                    suspicious.append(f"{entry.name}: {command}")
                elif not _is_known_path(command):
                    unknown.append(f"{entry.name}: {command}")

    # 2) /etc/rc.local
    rc_local = Path("/etc/rc.local")
    if rc_local.exists():
        content, error = _read_text(rc_local)
        if content is not None:
            for line in content.splitlines():
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                if "=" in stripped.split()[0] and not stripped.startswith("/"):
                    continue  # asignación de variable (PATH=…): no es un comando
                entries += 1
                if _looks_suspicious(stripped):
                    suspicious.append(f"/etc/rc.local: {stripped}")
                elif not _is_known_path(stripped.split()[0]):
                    unknown.append(f"/etc/rc.local: {stripped}")

    # 3) Ficheros de inicio del shell (solo los últimos suspicious).
    for name in (".bashrc", ".profile", ".zshrc"):
        path = home / name
        if not path.exists():
            continue
        content, error = _read_text(path)
        if content is None:
            continue
        lines = content.splitlines()[-20:]
        for line in parse_suspicious_commands(lines):
            suspicious.append(f"{name}: {line}")

    # 4) Crontab del usuario: se revisa como el resto de la persistencia
    # (un `curl | bash` en el crontab es igual de malo que en .bashrc).
    crontab = resolve_binary("crontab")
    if crontab is not None:
        result = run_command([crontab, "-l"], timeout=10)
        if result is not None and result.returncode == 0:
            for line in result.stdout.splitlines():
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                entries += 1
                if _looks_suspicious(stripped):
                    suspicious.append(f"crontab: {stripped}")
                else:
                    command = stripped.split()[-1] if stripped.split() else ""
                    if command and not _is_known_path(command):
                        unknown.append(f"crontab: {stripped}")

    if suspicious:
        findings.append(
            Finding(
                title="Comando sospechoso en un fichero de inicio",
                severity=Severidad.MEDIA,
                detail=(
                    "Se ha encontrado un patrón de descarga y ejecución directa en un "
                    "fichero de inicio del shell: eso instala y ejecuta código sin "
                    "revisar."
                ),
                suggestion="Revisa la línea y bórrala si no la reconoces.",
                evidence=suspicious[:5],
                source=SOURCE,
            )
        )
    if unknown:
        findings.append(
            Finding(
                title="Persistencia fuera de las rutas del sistema",
                severity=Severidad.ALTA,
                detail=(
                    "Hay entradas de autoarranque que apuntan a rutas que no son del "
                    "sistema: una ruta en el directorio personal o temporal se puede "
                    "cambiar sin dejar rastro en el gestor de paquetes."
                ),
                suggestion="Comprueba quién las instala y si te son necesarias.",
                evidence=unknown[:5],
                source=SOURCE,
            )
        )
    if not findings:
        findings.append(
            Finding(
                title="Sin persistencia sospechosa detectada",
                severity=Severidad.INFO,
                detail=(
                    f"{entries} entrada(s) de autoarranque revisadas (escritorio, "
                    "rc.local, crontab): ninguna apunta fuera de las rutas del sistema "
                    "y ningún fichero de inicio trae un patrón de descarga y ejecución."
                ),
                source=SOURCE,
            )
        )
    return findings


def check_kernel_errors(distro: DistroInfo) -> list[Finding]:
    """I) Errores del kernel: para reportar upstream."""
    content = None
    dmesg = resolve_binary("dmesg")
    if dmesg is not None:
        result = run_command([dmesg], timeout=10)
        if result is not None and result.returncode == 0:
            content = result.stdout
    if content is None:
        kern_log = Path("/var/log/kern.log")
        content, error = _read_text(kern_log)
        if content is None:
            return [
                _no_verifiable(
                    "Errores del kernel",
                    error,
                    "Con sudo se puede comprobar: `sudo dmesg | grep -iE 'bug|oops|warning'`.",
                )
            ]
    errors = parse_kernel_errors(content)
    if not errors:
        return [
            Finding(
                title="Sin errores graves en el log del kernel",
                severity=Severidad.INFO,
                detail=(
                    "El log del kernel no muestra BUG, Oops, WARNING, fallos de "
                    "protección general ni pánicos."
                ),
                source=SOURCE,
            )
        ]
    manager = distro.package_manager.name if distro.package_manager else ""
    report = {
        "apt": "`ubuntu-bug linux` (Mint/Ubuntu)",
        "dnf": "`abrt-cli report` (Fedora/RHEL)",
        "pacman": "bugzilla.kernel.org (Arch)",
        "zypper": "bugzilla.opensuse.org (openSUSE)",
    }.get(manager, "el reporte de errores de tu distribución")
    return [
        Finding(
            title=f"{len(errors)} error(es) del kernel en el log",
            severity=Severidad.INFO,
            detail=(
                "El log del kernel muestra avisos o fallos que conviene reportar al "
                "upstream. Esto no es un fallo de seguridad por sí solo."
            ),
            suggestion=f"Repórtalos con {report}.",
            evidence=errors[:3],
            source=SOURCE,
        )
    ]


def check_apparmor() -> list[Finding]:
    """G) AppArmor: perfiles que solo registran (complain) y no bloquean."""
    if not APPARMOR_PROFILES_PATH.exists():
        return [
            Finding(
                title="AppArmor no disponible",
                severity=Severidad.INFO,
                detail=(
                    "El módulo de AppArmor no está montado o no está instalado en este "
                    "sistema: no hay Mandatory Access Control que revisar."
                ),
                source=SOURCE,
            )
        ]
    content, error = _read_text(APPARMOR_PROFILES_PATH)
    if content is None:
        return [
            _no_verifiable(
                "Perfiles de AppArmor",
                error,
                "Con sudo se puede comprobar: `sudo aa-status`.",
            )
        ]
    enforce, complain, names = parse_apparmor_profiles(content)
    if complain:
        return [
            Finding(
                title=f"{complain} perfil(es) de AppArmor en modo complain",
                severity=Severidad.BAJA,
                detail=(
                    "Esos perfiles solo registran lo que ocurre: no bloquean nada, así "
                    "que no protegen frente a un ataque."
                ),
                suggestion="Actívalos con `sudo aa-enforce <perfil>`.",
                evidence=names[:5],
                signals=[
                    Signal.for_("El perfil solo registra: no bloquea lo no permitido."),
                    Signal.against(
                        "Los demás perfiles pueden estar en enforce: el control sigue "
                        "aplicándose en parte."
                    ),
                ],
                source=SOURCE,
            )
        ]
    return [
        Finding(
            title=f"AppArmor con {enforce} perfil(es) protegiendo",
            severity=Severidad.INFO,
            detail=(
                f"{enforce} perfil(es) en modo enforce: bloquean lo que no está permitido."
            ),
            source=SOURCE,
        )
    ]


class SuidBinary(NamedTuple):
    """Un binario con el bit setuid o setgid."""

    path: str
    uid: int
    mode: int
    kind: str  # "suid" | "sgid"


def scan_suid_binaries(directories: tuple[str, ...] = SYSTEM_BIN_DIRS) -> list[SuidBinary]:
    """Binarios SUID/SGID de las rutas del sistema (os.scandir, sin fork).

    Recorre solo las rutas del sistema: un binario setuid en el
    directorio personal es aún más sospechoso, y ese caso lo detecta
    el chequeo de persistencia.

    Los enlaces se **siguen**: un setuid detrás de un enlace (por
    ejemplo `/usr/local/bin/herramienta` → `/home/usuario/herramienta`)
    es una escalada de privilegios y no puede quedarse fuera. El
    mismo binario por dos rutas se cuenta una vez (mismo inodo).

    Coste: un `stat` por entrada (el bit setuid vive en el inodo, no
    en el enlace) y nada más: con `/bin` → `/usr/bin` (usrmerge) se
    recorre el directorio una sola vez.
    """
    found: list[SuidBinary] = []
    seen: set[tuple[int, int]] = set()
    visited: set[str] = set()
    for directory in directories:
        real = os.path.realpath(directory)
        if real in visited:
            continue
        visited.add(real)
        try:
            entries = os.scandir(directory)
        except OSError:
            continue
        with entries:
            # Orden alfabético: el informe tiene que ser el mismo en cada
            # ejecución (el orden del sistema de ficheros no lo es).
            for entry in sorted(entries, key=lambda item: item.name):
                try:
                    info = entry.stat()
                except OSError:
                    continue
                if not stat.S_ISREG(info.st_mode):
                    continue
                if not info.st_mode & (stat.S_ISUID | stat.S_ISGID):
                    continue
                key = (info.st_dev, info.st_ino)
                if key in seen:  # el mismo binario por dos rutas
                    continue
                seen.add(key)
                kind = "suid" if info.st_mode & stat.S_ISUID else "sgid"
                found.append(SuidBinary(entry.path, info.st_uid, info.st_mode, kind))
    return found


def check_suid_binaries() -> list[Finding]:
    """J) Binarios SUID/SGID: ejecutarlos ES ejecutarlos como root."""
    binaries = scan_suid_binaries(SYSTEM_BIN_DIRS)
    if not binaries:
        return [
            Finding(
                title="Sin binarios SUID/SGID en las rutas del sistema",
                severity=Severidad.INFO,
                detail="No se ha encontrado ningún programa con privilegio extra.",
                source=SOURCE,
            )
        ]
    findings: list[Finding] = []
    sospechosos = [
        binary
        for binary in binaries
        if binary.uid != 0 or binary.mode & 0o022
    ]
    if sospechosos:
        findings.append(
            Finding(
                title=f"{len(sospechosos)} binario(s) SUID/SGID con permisos incorrectos",
                severity=Severidad.ALTA,
                detail=(
                    "Un programa con el bit setuid o setgid se ejecuta con privilegios de "
                    "root. Si ese programa no es de root, o se puede modificar, cualquiera "
                    "que lo ejecute consigue root sin más: es una escalada de privilegios "
                    "directa."
                ),
                suggestion=(
                    "Quita el bit setuid/setgid (`chmod u-s`) y devuelve el fichero a "
                    "root:root."
                ),
                evidence=[
                    f"{binary.path} ({binary.kind}, uid={binary.uid}, {oct(binary.mode & 0o7777)})"
                    for binary in sospechosos[:5]
                ],
                source=SOURCE,
            )
        )
    findings.append(
        Finding(
            title=f"{len(binaries)} binario(s) con SUID/SGID en el sistema",
            severity=Severidad.INFO,
            detail=(
                "Estos programas se ejecutan con privilegios de root aunque se lancen "
                "como usuario normal (sudo, su, passwd, mount…). Es lo normal, pero "
                "conviene saber cuáles son."
            ),
            evidence=[binary.path for binary in binaries],
            source=SOURCE,
        )
    )
    return findings


def comprobar_sistema(distro: DistroInfo) -> list[Finding]:
    """Auditoría de endurecimiento del sistema (solo lectura, nada se aplica)."""
    findings: list[Finding] = []
    for check in (
        check_kernel_taint,
        check_core_dumps,
        check_cpu_mitigations,
        check_iommu,
        check_secure_boot,
        check_sudoers,
        check_apparmor,
        check_suid_binaries,
        lambda: check_persistence(distro),
        lambda: check_kernel_errors(distro),
    ):
        try:
            findings += check()
        except Exception as exc:  # noqa: BLE001 - defensive by design
            findings.append(
                Finding(
                    title=f"Error en el chequeo de {check.__name__}",
                    severity=Severidad.BAJA,
                    detail=str(exc),
                    source=SOURCE,
                )
            )
    return findings
