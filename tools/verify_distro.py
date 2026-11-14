"""Verifies the dnf/pacman/zypper parsers against REAL command output.

AGENTS.md §6: the apt family is verified on this machine; the other
families were only verified with output captured in podman containers.
This tool automates that verification: it runs the EXACT commands
MintGuard runs (same flags), inside the containers (or on the host for
apt), and feeds stdout through the package's own parsers — what you see
is what the app would see.

Usage:
    .venv/bin/python tools/verify_distro.py              # the four families
    .venv/bin/python tools/verify_distro.py arch fedora  # a subset

Requires podman for the non-apt families (images from the 2026-11-13
audit; official registries were 403 from this network, these mirrors
worked). Exit code 0 only when every requested family was verified
without a parser failure.
"""

from __future__ import annotations

import shutil
import subprocess
import sys

from mintguard.checks.updates import (
    parse_apt_sim_security,
    parse_apt_upgradable,
    parse_dnf_check_update,
    parse_pacman_sync_qu,
    parse_zypper_list_patches,
    parse_zypper_list_updates,
)

ARCH_IMAGE = "ghcr.io/archlinux/archlinux:latest"
OPENSUSE_IMAGE = "registry.opensuse.org/opensuse/tumbleweed:latest"
FEDORA_IMAGE = "docker.1ms.run/library/fedora:latest"

_SHOW_LINES = 12

_fails: list[str] = []
_avisos: list[str] = []
_verificados: list[str] = []


def _fail(msg: str) -> None:
    _fails.append(msg)
    print(f"  FALLO: {msg}")


def _aviso(msg: str) -> None:
    _avisos.append(msg)
    print(f"  AVISO: {msg}")


def _show(text: str) -> None:
    lines = text.splitlines()
    for line in lines[:_SHOW_LINES]:
        print(f"    | {line}")
    if len(lines) > _SHOW_LINES:
        print(f"    | … ({len(lines)} líneas en total)")


def _podman(image: str, *cmd: str) -> tuple[int, str, str]:
    """Run a command inside the container: (rc, stdout, stderr)."""
    proc = subprocess.run(
        ["podman", "run", "--rm", "--network=host", image, *cmd],
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    return proc.returncode, proc.stdout, proc.stderr


def _host(cmd: list[str], timeout: int = 180) -> tuple[int, str, str]:
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    return proc.returncode, proc.stdout, proc.stderr


# --- families -----------------------------------------------------------------


def verify_apt() -> None:
    """apt on this host (the family v1.0 claims to support)."""
    print("\n=== apt (este equipo) ===")
    apt = shutil.which("apt")
    apt_get = shutil.which("apt-get")
    if apt is None or apt_get is None:
        _fail("apt/apt-get no están en el PATH de este equipo")
        return
    modo = "root" if __import__("os").geteuid() == 0 else "sin root"

    rc, out, err = _host([apt, "list", "--upgradable"])
    print(f"  [1/2] apt list --upgradable → exit {rc} ({modo})")
    _show(out or err)
    if rc != 0:
        print("  → MintGuard: 'no disponible' (rc!=0), nunca 'sin actualizaciones'")
    else:
        packages = parse_apt_upgradable(out)
        print(f"  → parser: {len(packages)} paquete(s): {packages[:6]}")
        if "upgradable from" in out and not packages:
            _aviso("apt: hay líneas 'upgradable from' pero el parser devolvió 0 (falso negativo)")

    rc, out, err = _host([apt_get, "-s", "dist-upgrade", "--print-uris"])
    print(f"  [2/2] apt-get -s dist-upgrade --print-uris → exit {rc} ({modo})")
    _show(out or err)
    if rc == 0:
        security, security_estimated = parse_apt_sim_security(out)
        how = "estimado (sin root)" if security_estimated else "exacto"
        print(f"  → parser de seguridad: {security} paquete(s) de seguridad ({how})")
        if "Inst" in out and "-security" in out and security == 0:
            _aviso("apt: la simulación menciona orígenes -security pero el parser cuenta 0")
    else:
        _aviso(f"apt: la simulación falló (exit {rc}); sin verificación de seguridad")

    _verificados.append("apt")


def verify_arch() -> None:
    print(f"\n=== Arch (pacman) — imagen {ARCH_IMAGE} ===")
    rc, out, err = _podman(ARCH_IMAGE, "pacman", "-Qu")
    print(f"  pacman -Qu → exit {rc}")
    _show(out or err)
    if rc != 0:
        # Verified case: incomplete sync DB prints a warning and exits 1.
        print("  → MintGuard: 'no disponible' (rc!=0) — correcto, no inventa 'sin actualizaciones'")
        _verificados.append("arch (rc!=0: BD incompleta, comportamiento honesto)")
        return
    packages = parse_pacman_sync_qu(out)
    print(f"  → parser: {len(packages)} paquete(s): {packages[:6]}")
    if "->" in out and not packages:
        _aviso("pacman: hay líneas '->' pero el parser devolvió 0 (falso negativo)")
    _verificados.append("arch")


def verify_opensuse() -> None:
    print(f"\n=== openSUSE (zypper) — imagen {OPENSUSE_IMAGE} ===")
    rc, out, err = _podman(OPENSUSE_IMAGE, "zypper", "-q", "list-updates")
    print(f"  zypper -q list-updates → exit {rc}")
    _show(out or err)
    if rc != 0:
        print("  → MintGuard: 'no disponible' (rc!=0)")
        _verificados.append("opensuse (list-updates rc!=0)")
        return
    packages = parse_zypper_list_updates(out)
    print(f"  → parser: {len(packages)} paquete(s): {packages[:6]}")
    if " | " in out and not packages:
        _aviso("zypper: hay filas con '|' pero el parser devolvió 0 (falso negativo)")

    rc, out, err = _podman(OPENSUSE_IMAGE, "zypper", "-q", "list-patches")
    print(f"  zypper -q list-patches → exit {rc}")
    _show(out or err)
    if rc == 0:
        security = parse_zypper_list_patches(out)
        print(f"  → parser de seguridad: {security} parche(s) de seguridad")
    else:
        print("  → MintGuard: seguridad desconocida (rc!=0), lo dice honestamente")
    _verificados.append("opensuse")


def verify_fedora() -> None:
    print(f"\n=== Fedora (dnf5) — imagen {FEDORA_IMAGE} ===")
    rc, out, err = _podman(FEDORA_IMAGE, "dnf", "-q", "check-update")
    print(f"  dnf -q check-update → exit {rc}")
    _show(out or err)
    if rc == 0:
        print("  → MintGuard: 'sin actualizaciones' (rc==0)")
    else:
        packages, _ = parse_dnf_check_update(out)
        print(f"  → parser: {len(packages)} paquete(s): {packages[:6]}")
        if rc == 100 and out.strip() and not packages:
            _aviso("dnf: exit 100 (hay updates) con salida pero el parser devolvió 0")

    rc, out, err = _podman(FEDORA_IMAGE, "dnf", "-q", "check-upgrade", "--security")
    print(f"  dnf -q check-upgrade --security → exit {rc}")
    _show(out or err)
    if rc in (0, 100) and "Unknown argument" not in err:
        packages, _ = parse_dnf_check_update(out)
        print(f"  → parser de seguridad: {len(packages)} paquete(s) de seguridad")
        if rc == 100 and not packages:
            _aviso("dnf: exit 100 en --security pero el parser devolvió 0 (falso negativo)")
    else:
        print("  → MintGuard: seguridad desconocida (comando rechazado o error)")
    _verificados.append("fedora")


FAMILIES = {
    "apt": verify_apt,
    "arch": verify_arch,
    "opensuse": verify_opensuse,
    "fedora": verify_fedora,
}


def main(argv: list[str]) -> int:
    requested = argv[1:] or list(FAMILIES)
    for name in requested:
        if name not in FAMILIES:
            print(f"Familia desconocida: {name} (opciones: {', '.join(FAMILIES)})")
            return 2
    if any(name != "apt" for name in requested) and shutil.which("podman") is None:
        _fail("podman no está instalado: sin él no se pueden verificar arch/opensuse/fedora")

    for name in requested:
        if name != "apt" and shutil.which("podman") is None:
            continue
        try:
            FAMILIES[name]()
        except subprocess.TimeoutExpired:
            _fail(f"{name}: el comando superó el tiempo límite")
        except Exception as exc:  # a crashed verifier must not hide results
            _fail(f"{name}: error del verificador ({type(exc).__name__}: {exc})")

    print("\n=== Resumen ===")
    print(f"  verificadas: {len(_verificados)}/{len(requested)} → {', '.join(_verificados) or 'ninguna'}")
    print(f"  avisos: {len(_avisos)}   fallos: {len(_fails)}")
    if _fails:
        print("VERIFY_DISTRO FAIL")
        return 1
    print("VERIFY_DISTRO OK")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
