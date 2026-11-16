"""MintGuard: TUI de seguridad ligera en español para Linux."""

from pathlib import Path
from importlib.metadata import PackageNotFoundError, version as _pkg_version

# Orden de fuentes de la versión (todas acaban en pyproject.toml):
# 1. `mintguard/_version.py` — escrito por tools/build_zipapp.py dentro del
#    ejecutable único (un zipapp no lleva .dist-info del propio paquete).
# 2. Metadata del paquete instalado (pip install -e .).
# 3. pyproject.toml leído del árbol de fuentes, si se ejecuta sin instalar.
# Un número a pelo aquí se quedó viejo una vez (0.2.0 vs 0.3.0).
try:
    from mintguard._version import VERSION as __version__
except ImportError:
    try:
        __version__ = _pkg_version("mintguard")
    except PackageNotFoundError:
        try:
            import tomllib

            with open(Path(__file__).resolve().parents[2] / "pyproject.toml", "rb") as fichero:
                __version__ = tomllib.load(fichero)["project"]["version"]
        except Exception:
            __version__ = "0.0.0"
