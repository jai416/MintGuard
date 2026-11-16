"""Construye el ejecutable único `mintguard.pyz` (Reto C).

Sin venv, sin pip, sin instalar nada: un solo fichero que lleva dentro
la aplicación **y** Textual, y que se ejecuta con el Python del sistema:

    ./dist/mintguard.pyz

Ventaja para quien no programa: es copiar, dar permisos de ejecución y
lanzarlo. Para un grupo de programación sigue estando el `pip install -e .`.

    .venv/bin/python tools/build_zipapp.py            # -> dist/mintguard.pyz

Cómo funciona: `zipapp` empaqueta un directorio en un zip con un
`__main__.py`; Python lo ejecuta desde el zip (zipimport). Van dentro
los `.dist-info` de las dependencias (Textual lee su versión con
`importlib.metadata`) y, como cinturón de seguridad, un `__main__.py`
que responde por las versiones incrustadas si la metadata no se
descubre desde el zip.
"""

from __future__ import annotations

import compileall
import importlib.metadata as md
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
SRC = RAIZ / "src"
DIST = RAIZ / "dist"
SALIDA = DIST / "mintguard.pyz"

# Dependencia base del árbol (todo lo demás son sus requisitos).
BASE = "textual"

# Un nombre de distribución: letras, dígitos, punto, guión y guión bajo.
# Partir por <>=!;( deja pegados los modificadores (`mdurl~` de `mdurl~=0.1`).
_NOMBRE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")

_MAIN_TEMPLATE = '''"""Ejecutable único de MintGuard."""

try:
    import importlib.metadata as _md
    import _embedded_versions
except Exception:  # sin el shim, MintGuard sigue siendo ejecutable
    _md = None

if _md is not None:

    class _EmbeddedDistribution(_md.Distribution):
        """Distribución mínima con la versión incrustada en el zip."""

        def __init__(self, name: str, version: str) -> None:
            self._name = name
            self._version = version

        @property
        def name(self) -> str:
            return self._name

        @property
        def version(self) -> str:
            return self._version

        @property
        def metadata(self):
            from email.parser import Parser

            texto = (
                f"Metadata-Version: 2.1\\n"
                f"Name: {self._name}\\n"
                f"Version: {self._version}\\n"
            )
            return Parser().parsestr(texto)

        def read_text(self, filename: str):
            if filename == "METADATA":
                return self.metadata.as_string()
            return None

        def read_binary(self, filename: str) -> bytes:
            if filename == "METADATA":
                return self.metadata.as_bytes()
            return b""

        def locate_file(self, path):
            return None  # nada que localizar fuera del zip

    _original_distribution = _md.distribution

    def _distribution(name):
        try:
            return _original_distribution(name)
        except _md.PackageNotFoundError:
            version = _embedded_versions.VERSIONS.get(name)
            if version is None:
                raise
            return _EmbeddedDistribution(name, version)

    _md.distribution = _distribution

from mintguard.main import main

if __name__ == "__main__":
    main()
'''


def _nombre_de_requisito(requisito: str) -> str:
    """Nombre de distribución de una línea de Requires-Dist."""
    base = requisito.split(";", 1)[0]
    match = _NOMBRE.match(base.strip())
    return match.group(0) if match else ""


def _extras_de_requisito(requisito: str) -> list[str]:
    """Extras que el requisito pide (`markdown-it-py[linkify]` -> ["linkify"])."""
    base = requisito.split(";", 1)[0]
    return [
        pieza.strip()
        for grupo in re.findall(r"\[([^\]]+)\]", base)
        for pieza in grupo.split(",")
    ]


def dependencias() -> list[str]:
    """Distribuciones que el ejecutable necesita, en tiempo de ejecución.

    Recorre el árbol de requisitos de `textual`. Las reglas:

    - Un requisito con marcador de `extra` solo entra si su paquete padre
      pidió ese extra (los extras `syntax` de tree-sitter no van dentro).
    - Un marcador solo de `python_version` se ignora: se incluye igual
      (superconjunto seguro; typing-extensions no se deja fuera).
    - Una dependencia no instalada en el venv entra por su nombre y el
      AVISO saldrá al copiarla.
    - Un paquete puede visitarse más de una vez si lo piden con extras
      distintos (rich pide markdown-it-py sin extras y textual con
      linkify). Los requisitos sin marcador se procesan UNA vez por
      nombre; los marcados por `extra ==`, UNA vez por extra pedido.
    """
    base_hecho: set[str] = set()
    extras_hechos: dict[str, set[str]] = {}
    pendientes: list[tuple[str, tuple[str, ...]]] = [(BASE, ())]
    while pendientes:
        nombre, extras = pendientes.pop()
        vistos = extras_hechos.setdefault(nombre, set())
        faltantes = [extra for extra in extras if extra not in vistos]
        if nombre in base_hecho and not faltantes:
            continue
        base_hecho.add(nombre)
        vistos.update(faltantes)
        try:
            requisitos = md.requires(nombre) or []
        except md.PackageNotFoundError:
            continue  # no está instalada: el AVISO saldrá al copiar
        for requisito in requisitos:
            marcador = requisito.split(";", 1)[1] if ";" in requisito else ""
            if marcador and "extra ==" in marcador:
                if not any(f'extra == "{extra}"' in marcador for extra in extras):
                    continue
            nombre_hijo = _nombre_de_requisito(requisito)
            if not nombre_hijo:
                continue
            pendientes.append((nombre_hijo, tuple(_extras_de_requisito(requisito))))
    return sorted(base_hecho)


def _copiar_distribucion(nombre: str, destino: Path) -> None:
    """Copia los ficheros de una distribución instalada (sin __pycache__)."""
    dist = md.distribution(nombre)
    for fichero in dist.files or []:
        ruta = str(fichero)
        if "__pycache__" in ruta or ruta.endswith(".pyc"):
            continue
        if ruta.startswith(".."):
            # Script o entry point fuera del paquete (p. ej. bin/markdown-it):
            # no va dentro del zipapp y además escaparía del directorio de build.
            continue
        origen = fichero.locate()
        destino_final = destino / ruta
        if origen.is_dir():
            destino_final.mkdir(parents=True, exist_ok=True)
            continue
        if not origen.exists():
            continue
        destino_final.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(origen, destino_final)


def _version_de_pyproject() -> str:
    """La versión sale de pyproject.toml (fuente única)."""
    for linea in (RAIZ / "pyproject.toml").read_text(encoding="utf-8").splitlines():
        if linea.strip().startswith("version"):
            return linea.split("=", 1)[1].strip().strip('"')
    return "0.0.0"


def _bytecode_legacy(raiz: Path) -> tuple[int, int]:
    """Pasa el bytecode de `__pycache__` a ubicación legacy (dir/nombre.pyc).

    Dentro de un zip, zipimport **ignora** el .pyc de `__pycache__` si hay
    fuente (recompila todo: ~13 s por arranque, medido) y un paquete
    pyc-only ni siquiera encuentra sus submódulos. El .pyc legacy al lado
    del fuente SÍ se usa cuando el magic encaja (~20 ms el módulo), y si
    el Python es de otra versión cae al fuente: funciona en cualquier
    lado, solo arranca lento.
    """
    version = f"cpython-{sys.version_info.major}{sys.version_info.minor}"
    movidos = quitados = 0
    for cache in list(raiz.rglob("__pycache__")):
        for pyc in sorted(cache.glob(f"*.{version}.pyc")):
            base = pyc.name[: -len(f".{version}.pyc")]
            destino = cache.parent / f"{base}.pyc"
            shutil.move(str(pyc), str(destino))
            movidos += 1
            if base == "__main__":
                continue  # punto de entrada del zipapp: zipapp lo exige como fuente
            fuente = cache.parent / f"{base}.py"
            if fuente.exists():
                fuente.unlink()
                quitados += 1
    return movidos, quitados


def main() -> int:
    version = _version_de_pyproject()
    deps = dependencias()
    print(f"version {version} | dependencias: {', '.join(deps)}")

    versiones: dict[str, str] = {"mintguard": version}
    with tempfile.TemporaryDirectory() as tmp:
        build = Path(tmp) / "build"
        build.mkdir(parents=True)

        # 1) La aplicación.
        shutil.copytree(
            SRC / "mintguard",
            build / "mintguard",
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
        )
        # La versión va dentro (en un zipapp no hay metadata del paquete).
        (build / "mintguard" / "_version.py").write_text(
            f'"""Versión incrustada en el ejecutable único."""\n\nVERSION = "{version}"\n',
            encoding="utf-8",
        )

        # 2) Las dependencias (con sus .dist-info).
        for nombre in deps:
            try:
                _copiar_distribucion(nombre, build)
                versiones[nombre] = md.version(nombre)
            except md.PackageNotFoundError:
                print(f"AVISO: {nombre} no está instalado; no va dentro", file=sys.stderr)

        (build / "_embedded_versions.py").write_text(
            "VERSIONS = {\n"
            + "".join(f'    "{n}": "{v}",\n' for n, v in sorted(versiones.items()))
            + "}\n",
            encoding="utf-8",
        )

        # 3) El punto de entrada (con el shim de versiones).
        (build / "__main__.py").write_text(_MAIN_TEMPLATE, encoding="utf-8")

        # 4) Bytecode dentro del zip: la primera partida no compila Textual.
        compileall.compile_dir(str(build), quiet=1)

        # 5) Bytecode legacy + fuentes fuera: dentro de un zip, zipimport
        #    ignora el .pyc de __pycache__ si hay fuente (recompilaba todo
        #    Textual: ~13 s por arranque). El .pyc al lado del fuente (legacy)
        #    se usa; si el magic no encaja, cae al fuente y compila: funciona
        #    en cualquier Python 3, solo arranca más lento.
        movidos, quitados = _bytecode_legacy(build)
        print(f"pyc movidos a legacy: {movidos} | fuentes quitados: {quitados}")

        # 6) El zipapp.
        DIST.mkdir(exist_ok=True)
        subprocess.run(
            [
                sys.executable,
                "-m",
                "zipapp",
                str(build),
                "-o",
                str(SALIDA),
                "-p",
                "/usr/bin/env python3",
                "-c",
            ],
            check=True,
        )
    SALIDA.chmod(0o755)
    print(f"{SALIDA} ({SALIDA.stat().st_size // 1024} KB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
