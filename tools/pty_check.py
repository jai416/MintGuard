"""Prueba de la app en un terminal REAL (pty), no headless.

`run_test` (Textual) y el smoke usan el driver headless: no pasan por el
terminal de verdad. Esta herramienta lanza la app real en un pty, le
manda teclas reales y comprueba que todo responde:

    .venv/bin/python tools/pty_check.py

Qué comprueba: arranque, navegación por teclado (incluida la pantalla
«Sistema»), que Enter ejecuta el chequeo (los botones de la barra no
pueden robarlo: `can_focus=False`), la generación del reporte, el
guardado (fichero del usuario, modo 0600, legible sin sudo) y una
salida limpia.

Lo que NO puede comprobar (necesita la contraseña del usuario):
`sudo .venv/bin/mintguard` → generar reporte → guardar → comprobar que
el fichero es del usuario y no de root. Eso hay que hacerlo a mano.
"""

from __future__ import annotations

import fcntl
import os
import pty
import select
import struct
import sys
import termios
import time
from pathlib import Path

APP = Path(__file__).resolve().parent.parent / ".venv" / "bin" / "mintguard"
WORKDIR = Path("/tmp/mintguard-pty-check")
COLS, ROWS = 80, 24


def read_available(fd: int, seconds: float = 1.0) -> str:
    out: list[str] = []
    deadline = time.time() + seconds
    while time.time() < deadline:
        ready, _, _ = select.select([fd], [], [], 0.1)
        if not ready:
            continue
        try:
            chunk = os.read(fd, 65536)
        except OSError:
            break
        if not chunk:
            break
        out.append(chunk.decode("utf-8", "replace"))
    return "".join(out)


def send(fd: int, keys: str, wait: float = 1.0) -> str:
    os.write(fd, keys.encode())
    time.sleep(0.3)
    return read_available(fd, wait)


def main() -> int:
    if not APP.exists():
        print(f"No está la app: {APP}", file=sys.stderr)
        return 2
    WORKDIR.mkdir(parents=True, exist_ok=True)
    for old in WORKDIR.glob("reporte-mintguard-*.txt"):
        old.unlink()

    pid, fd = pty.fork()
    if pid == 0:  # hijo
        os.chdir(WORKDIR)
        os.environ["TERM"] = "xterm-256color"
        os.environ["COLUMNS"] = str(COLS)
        os.environ["LINES"] = str(ROWS)
        os.execv(str(APP), ["mintguard"])
        os._exit(1)

    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", ROWS, COLS, 0, 0))
    fallos = 0
    arranque = read_available(fd, 4.0)
    print(f"[1] arranque en un pty real: {len(arranque)} bytes")
    fallos += 0 if "MintGuard" in arranque else 1

    salida = send(fd, "k", 1.5)
    print(f"[2] tecla k -> pantalla Sistema: {'Sistema' in salida}")
    fallos += 0 if "Sistema" in salida else 1

    salida = send(fd, "\r", 4.0) + read_available(fd, 3.0)
    print(f"[3] Enter -> ejecuta el chequeo: {'Ejecutando' in salida}")
    fallos += 0 if "Ejecutando" in salida else 1

    send(fd, "d", 1.0)
    salida = send(fd, "r", 1.5)
    print(f"[4] tecla r -> pantalla Reporte: {'Reporte' in salida}")
    fallos += 0 if "Reporte" in salida else 1

    salida = send(fd, "\r", 2.5)
    print(f"[5] Enter -> genera el reporte: {'Reporte de seguridad' in salida}")
    fallos += 0 if "Reporte de seguridad" in salida else 1

    salida = send(fd, "g", 2.0)
    print(f"[6] tecla g -> guarda el reporte: {'guardado' in salida.lower()}")
    fallos += 0 if "guardado" in salida.lower() else 1

    send(fd, "q", 1.5)
    try:
        os.close(fd)
    except OSError:
        pass
    _, status = os.waitpid(pid, 0)
    limpio = os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0
    print(f"[7] salida limpia: {limpio}")
    fallos += 0 if limpio else 1

    guardados = sorted(WORKDIR.glob("reporte-mintguard-*.txt"))
    if not guardados:
        print("[8] NO se guardó ningún reporte")
        return 1
    path = guardados[-1]
    info = path.stat()
    print(f"[8] reporte: {path.name} uid={info.st_uid} modo={oct(info.st_mode & 0o777)}")
    fallos += 0 if info.st_uid == os.getuid() else 1
    fallos += 0 if info.st_mode & 0o777 == 0o600 else 1
    contenido = path.read_text(encoding="utf-8")
    print(f"[9] legible sin sudo: {len(contenido)} bytes, {contenido.count('###')} hallazgos")

    print("\nPENDIENTE A MANO (necesita tu contraseña):")
    print("  sudo .venv/bin/mintguard  ->  genera el reporte  ->  guarda (g)")
    print("  ->  ls -l reporte-mintguard-*.txt   (debe ser de tu usuario, no root)")
    return 1 if fallos else 0


if __name__ == "__main__":
    sys.exit(main())
