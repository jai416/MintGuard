"""Updates check adapted to the detected package manager.

Pure parsers live at module level so they can be unit-tested without
running any subprocess (a broken parser here means false negatives in
security, which is the worst outcome for this tool).
"""

from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path

from mintguard.core.commands import resolve_binary, run_command
from mintguard.core.distro import DistroInfo
from mintguard.core.prioritizer import Finding, Severidad

UPDATE_TIMEOUT = 300

_SUGGESTIONS = {
    "apt": "`sudo apt upgrade`",
    "dnf": "`sudo dnf upgrade`",
    "pacman": "`sudo pacman -Syu`",
    "zypper": "`sudo zypper update`",
}


# --- pure parsers (no subprocess, no I/O) -----------------------------------


def parse_apt_upgradable(text: str) -> list[str]:
    """Package names from `apt list --upgradable` output."""
    names: list[str] = []
    for line in text.splitlines():
        if "/" in line and not line.startswith("Listing"):
            names.append(line.split("/", 1)[0].strip())
    return names


def parse_apt_sim_security(text: str) -> tuple[int, bool]:
    """(security count, is_estimate) from `apt-get -s dist-upgrade --print-uris`.

    Two real formats:
    - With root the command emits `.deb` URI lines: counted exactly by
      count_apt_security_uris (origin host) → estimate=False.
    - Without root it only emits `Inst name [old] (new repo1, repo2)`
      lines (verified on Mint 22.3: rc 0, 49 Inst, 0 URIs) — a package
      counts as security when its candidate origins include a repo
      ending in `-security` (noble-security, bookworm-security). Only
      the parenthesised origin section is searched: a package name like
      "foo-security" must not create a match. This is an estimate (the
      simulation labels repos, not update kinds) → estimate=True.
    """
    if any(".deb" in line for line in text.splitlines()):
        return count_apt_security_uris(text), False
    count = 0
    for line in text.splitlines():
        if not line.startswith("Inst "):
            continue
        origins = line.partition("(")[2].lower()
        if "-security" in origins:
            count += 1
    return count, True


def count_apt_security_uris(text: str) -> int:
    """Count .deb URIs that come from security repositories.

    Works on the output of `apt-get -s dist-upgrade --print-uris`.
    """
    count = 0
    for line in text.splitlines():
        fields = line.split()
        if not fields:
            continue
        uri = fields[0].strip("'\"")
        if not uri.endswith(".deb"):
            continue
        host = uri.split("//", 1)[-1].split("/", 1)[0]
        if "/security/" in uri or host.split(".", 1)[0] == "security":
            count += 1
    return count


def parse_dnf_check_update(text: str) -> tuple[list[str], int]:
    """(package names, security count) from `dnf -q check-update` output."""
    packages: list[str] = []
    security = 0
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 2:
            continue
        packages.append(fields[0])
        if len(fields) >= 3 and "security" in fields[-1].lower():
            security += 1
    return packages, security


def parse_pacman_sync_qu(text: str) -> list[str]:
    """Package names from `pacman -Qu` output.

    Real format (verified in an Arch container, pacman 7.1.0):
    `name oldver -> newver`. Match the `->` marker instead of assuming
    the version starts with a digit (svn-style versions like `r1234`
    would be dropped silently).
    """
    packages: list[str] = []
    for line in text.splitlines():
        fields = line.split()
        if len(fields) >= 4 and fields[2] == "->":
            packages.append(fields[0])
    return packages


def parse_zypper_list_updates(text: str) -> list[str]:
    """Package names from `zypper list-updates` output (lines starting with 'v ')."""
    packages: list[str] = []
    for line in text.splitlines():
        if not line.startswith("v "):
            continue
        fields = [f.strip() for f in line.split("|")]
        if len(fields) >= 4:
            packages.append(fields[2])
    return packages


def parse_zypper_list_patches(text: str) -> int:
    """Count security patches from `zypper list-patches` output.

    Table columns: status | repository | name | category | severity | ...
    """
    security = 0
    for line in text.splitlines():
        if not line.startswith("v "):
            continue
        fields = [f.strip() for f in line.split("|")]
        if len(fields) >= 5 and fields[3].lower() == "security":
            security += 1
    return security


# --- subprocess helpers and checkers ----------------------------------------


def _run(cmd: list[str], timeout: int = UPDATE_TIMEOUT) -> subprocess.CompletedProcess | None:
    return run_command(cmd, timeout)


def _no_updates(manager: str) -> list[Finding]:
    return [
        Finding(
            title="No hay actualizaciones pendientes",
            severity=Severidad.INFO,
            detail=f"`{manager}` no reporta paquetes actualizables.",
            source="updates",
        )
    ]


def _unavailable(manager: str) -> list[Finding]:
    return [
        Finding(
            title=f"No se pudo consultar {manager}",
            severity=Severidad.BAJA,
            detail=(
                "El gestor de paquetes no respondió dentro del tiempo límite "
                "o terminó con error."
            ),
            suggestion="Inténtalo de nuevo o revisa si hay otra actualización en curso.",
            source="updates",
        )
    ]


def _updates_finding(
    manager: str,
    packages: list[str],
    security: int | None,
    security_approx: bool = False,
) -> list[Finding]:
    total = len(packages)
    if total == 0 and not security:
        return _no_updates(manager)
    parts: list[str] = []
    severity = Severidad.BAJA
    if total:
        parts.append(f"{total} paquete(s) con actualizaciones disponibles.")
        severity = Severidad.MEDIA if total >= 10 else Severidad.BAJA
    if security is None:
        parts.append("No se pudo estimar cuántas corresponden a seguridad.")
    elif security > 0:
        if security_approx:
            parts.append(
                f"{security} proceden de repositorios de seguridad "
                "(conteo estimado; con sudo es exacto)."
            )
        else:
            parts.append(f"{security} proceden de repositorios de seguridad.")
        severity = Severidad.ALTA
    return [
        Finding(
            title=f"{total} actualización(es) disponibles ({manager})",
            severity=severity,
            detail=" ".join(parts),
            suggestion=(
                "Aplica las actualizaciones con "
                f"{_SUGGESTIONS.get(manager, 'el comando de tu gestor de paquetes')}."
            ),
            evidence=packages[:30],
            source="updates",
        )
    ]


_APT_LISTS_DIR = Path("/var/lib/apt/lists")
_CACHE_MAX_AGE_DAYS = 7


def _cache_is_stale(cache_mtime: float, now: float) -> bool:
    """Pure: the apt index is older than the honest-reading threshold."""
    return (now - cache_mtime) > _CACHE_MAX_AGE_DAYS * 86400


def _apt_lists_mtime(path: Path = _APT_LISTS_DIR) -> float | None:
    """Newest mtime inside the apt lists dir; None when unreadable or empty."""
    try:
        return max(entry.stat().st_mtime for entry in path.iterdir())
    except (OSError, ValueError):
        return None


def _stale_cache_finding(now: float | None = None) -> Finding | None:
    """BAJA warning when the apt index behind the results is old.

    Without root there is no `apt-get update`, so `apt list --upgradable`
    may reflect a cache weeks old: saying "no updates" from it would be a
    silent false negative. With root, update refreshes it first and this
    stays quiet.
    """
    mtime = _apt_lists_mtime()
    if mtime is None:
        return None
    now = time.time() if now is None else now
    if not _cache_is_stale(mtime, now):
        return None
    days = max(1, int((now - mtime) / 86400))
    return Finding(
        title="La caché de paquetes puede estar desactualizada",
        severity=Severidad.BAJA,
        detail=(
            f"El índice de apt no se refresca desde hace unos {days} días; "
            "los resultados pueden no reflejar los repositorios actuales."
        ),
        suggestion="Ejecuta `sudo apt-get update` y vuelve a lanzar el chequeo de actualizaciones.",
        source="updates",
    )


def _refresh_failed_finding(refresh: subprocess.CompletedProcess | None) -> Finding | None:
    """BAJA when the root index refresh failed: results may be stale.

    `apt-get update -qq` used to be fire-and-forget: a failed refresh
    (lock, no network) left us silently reporting from the old index as
    if nothing had happened.
    """
    if refresh is None or refresh.returncode == 0:
        return None
    return Finding(
        title="Índice de paquetes sin refrescar",
        severity=Severidad.BAJA,
        detail=(
            f"`apt-get update` terminó con error (código {refresh.returncode}); "
            "los resultados usan el índice anterior y pueden estar desactualizados."
        ),
        suggestion=(
            "Ejecuta `sudo apt update` y revisa la línea de error: suele ser un "
            "repositorio caído o falta de red. Luego vuelve a lanzar el chequeo."
        ),
        source="updates",
    )


def _check_apt(path: str) -> list[Finding]:
    apt_get = resolve_binary("apt-get")
    # Only refresh the index with root; without root the local cache is used.
    # Absolute path from a standard system directory: under sudo, a PATH
    # lookup would resolve `apt-get` in the inherited user PATH — and its
    # root hooks would run with it.
    refresh: subprocess.CompletedProcess | None = None
    if os.geteuid() == 0 and apt_get is not None:
        refresh = _run([apt_get, "update", "-qq"])
    result = _run([path, "list", "--upgradable"])
    # A broken cache exits nonzero with no package list: reporting that as
    # "no updates" would hide a failed check (the worst failure mode here).
    if result is None or result.returncode != 0:
        return _unavailable("apt")
    packages = parse_apt_upgradable(result.stdout)
    if not packages:
        findings = _no_updates("apt")
    else:
        # The dist-upgrade simulation is the only cheap way to know which
        # updates come from security repos; it costs ~24 s on the target
        # hardware (HDD). With nothing to upgrade it adds nothing: skip it.
        simulation = _run([apt_get, "-s", "dist-upgrade", "--print-uris"]) if apt_get else None
        security: int | None = None
        security_approx = False
        if simulation is not None and simulation.returncode == 0:
            security, security_approx = parse_apt_sim_security(simulation.stdout)
        findings = _updates_finding("apt", packages, security, security_approx)
    extra = _refresh_failed_finding(refresh)
    stale = _stale_cache_finding()
    for extra_finding in (extra, stale):
        if extra_finding is not None:
            findings = [*findings, extra_finding]
    return findings


def _dnf_security_count(path: str) -> tuple[int | None, bool]:
    """(count, approximate) of security updates; (None, False) when unknown.

    `dnf check-upgrade --security` lists ONLY security updates (verified
    on dnf5 5.4.7 / Fedora 45 in a container: exit 100 when present,
    exit 0 when none, and the repo column says "updates" for all lines —
    so security must be counted this way, not by column text).
    Older dnf variants that reject the command fall back to
    `check-update --security`; anything else reports None honestly.
    """
    for args in (
        ("-q", "check-upgrade", "--security"),
        ("-q", "check-update", "--security"),
    ):
        result = _run([path, *args], timeout=120)
        if result is None or result.returncode not in (0, 100):
            continue
        if "Unknown argument" in result.stderr:
            continue
        packages, _ = parse_dnf_check_update(result.stdout)
        return len(packages), False
    return None, False


def _check_dnf(path: str) -> list[Finding]:
    result = _run([path, "-q", "check-update"])
    if result is None:
        return _unavailable("dnf")
    if result.returncode == 0:
        return _no_updates("dnf")
    packages, _column_security = parse_dnf_check_update(result.stdout)
    if not packages:
        # rc != 0 with no package lines (e.g. metadata download failure):
        # never report it as "no updates".
        return _unavailable("dnf")
    security, security_approx = _dnf_security_count(path)
    return _updates_finding("dnf", packages, security, security_approx)


def _check_pacman(path: str) -> list[Finding]:
    result = _run([path, "-Qu"], timeout=120)
    # Nonzero exit (e.g. database locked by another pacman) must not become
    # an INFO "no updates": report the failure instead.
    if result is None or result.returncode != 0:
        return _unavailable("pacman")
    return _updates_finding("pacman", parse_pacman_sync_qu(result.stdout), None)


def _check_zypper(path: str) -> list[Finding]:
    updates = _run([path, "-q", "list-updates"])
    if updates is None or updates.returncode != 0:
        return _unavailable("zypper")
    packages = parse_zypper_list_updates(updates.stdout)
    security: int | None = None
    patches = _run([path, "-q", "list-patches"])
    if patches is not None and patches.returncode == 0:
        security = parse_zypper_list_patches(patches.stdout)
    return _updates_finding("zypper", packages, security)


def comprobar_actualizaciones(distro: DistroInfo) -> list[Finding]:
    manager = distro.package_manager
    if manager is None:
        return [
            Finding(
                title="Gestor de paquetes no detectado",
                severity=Severidad.BAJA,
                detail="No se encontró apt, dnf, pacman ni zypper en el PATH.",
                suggestion="MintGuard soporta Debian/Ubuntu/Mint, Fedora/RHEL, Arch y openSUSE.",
                source="updates",
            )
        ]
    dispatch = {
        "apt": _check_apt,
        "dnf": _check_dnf,
        "pacman": _check_pacman,
        "zypper": _check_zypper,
    }
    checker = dispatch.get(manager.name)
    if checker is None:
        return [
            Finding(
                title=f"Gestor {manager.name} sin soporte todavía",
                severity=Severidad.BAJA,
                source="updates",
            )
        ]
    try:
        return checker(manager.path)
    except Exception as exc:  # defensive: keep the UI alive
        return [
            Finding(
                title="Error revisando actualizaciones",
                severity=Severidad.BAJA,
                detail=str(exc),
                source="updates",
            )
        ]
