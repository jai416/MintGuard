# MintGuard - Instrucciones para el Agente (OpenCode)

## 1. Qué es este proyecto y en qué estado está

MintGuard es una TUI de seguridad ligera para Linux hecha con **Textual**, 100% en español.
Detecta problemas, los prioriza según la **exposición real** de la máquina, sugiere
correcciones y genera reportes limpios. NO es antivirus ni escáner de malware/rootkits
(no compite con rkhunter/clamav) y **no hay que llamarlo "innovador"** en docs ni mensajes:
el valor es la ejecución de un nicho (TUI moderna, español, exposición real, ultraligero).

**Estado (2026-11-16): versión 0.5.0 publicada (0.3.0 → 0.3.1 → 0.4.0 → 0.5.0, las
cuatro en github.com/jai416/MintGuard).** 0.5.0 añade el sistema de confianza y
señales (§5.6) y el ejecutable único `dist/mintguard.pyz` (§2), que también sale como
asset del release. Estructura completa (core, checks, reporting, ui),
**395 tests unittest OK (~4 s)**, smoke UI headless en verde (~70 s, incluye 4 pruebas
pilot de regresión de UI), repo git propio dentro de `MintGuard/`. Arranque medido:
**~0,9-2,1 s** total (detección de distro+sistema < 60 ms; el resto es el primer frame
de Textual). Parsers de pacman/zypper/dnf5 **verificados con salida real en contenedores
podman** (Arch 7.1.0, openSUSE Tumbleweed/zypper 1.14.102, Fedora 45/dnf5 5.4.7; la
re-verificación del 2026-11-14 solo pudo confirmar apt y arch: la descarga de metadatos
de dnf/zypper en contenedor agotó el tiempo por red). Cuatro auditorías con subagentes
(arquitectura, Python/Textual, seguridad ×2) aplicadas: ver §3 y §5; más una ronda de
caza de bugs (fuzz de parsers, tests de detección, cobertura al 100 %): ver §2 y §6.

## 2. Comandos (verificados)

- El Python del sistema está protegido por **PEP 668** → todo dentro del venv:
  ```bash
  python3 -m venv .venv
  .venv/bin/pip install -e .        # única dependencia: textual (probado con 8.2.8)
  .venv/bin/mintguard               # ejecutar la TUI
  .venv/bin/mintguard --version
  ```
- **Ejecutable único sin venv** (`dist/mintguard.pyz`, Reto C):
  ```bash
  .venv/bin/python tools/build_zipapp.py   # -> dist/mintguard.pyz (~7 MB)
  /usr/bin/python3 dist/mintguard.pyz --version
  ```
  Empaqueta la app + Textual y dependencias (con sus `.dist-info`, que
  `importlib.metadata` sí descubre desde un zip). Tres trampas medidas: en un zip
  **zipimport ignora el .pyc de `__pycache__` si hay fuente** (recompilaba todo:
  ~13 s por arranque) y un paquete pyc-only ni siquiera encuentra sus submódulos →
  el constructor pasa el bytecode a ubicación legacy (`dir/nombre.pyc`, que zipimport
  sí usa; si el magic de otro Python no encaja, cae al fuente y compila: lento pero
  funciona) y deja `__main__.py` como fuente (zipapp lo exige); y el RECORRIDO de
  requisitos deduplica por nombre **y** unión de extras (rich pide markdown-it-py
  sin extras y textual con linkify: deduplicar solo por nombre perdía
  linkify-it-py). Tras construir, probar con el python del sistema: `--version` +
  un arranque de UI headless. La versión incrustada va en `mintguard/_version.py`,
  que `__init__.py` prefiere antes que la metadata (y como último recurso lee
  pyproject.toml; ya no hay número a pelo).
- **Tests (regla NUEVA, sustituye la antigua de "no inventar tests")**:
  ```bash
  .venv/bin/python -m unittest discover -s tests
  ```
  **Todo parser de salida de comandos (apt/dnf/pacman/zypper/ss/systemctl/passwd/shadow/
  sshd_config) DEBE tener tests unitarios con unittest de la stdlib.** Un parser roto
  produce falsos negativos de seguridad, que es el peor fallo posible de esta herramienta.
- **Caza de bugs (ronda de 2026-11-15)**: además de los tests normales, la suite incluye
  un *fuzz* de los 38 parsers con basura determinista (`tests/test_parsers_fuzz.py`), tests
  de **detección** (que el caso malo se vea, no que no reviente:
  `tests/test_detection.py`) y tests de **arranque** (`tests/test_startup.py`).
  Cobertura medida con `trace` (stdlib): 100 % de las líneas de `core`, `checks` y
  `reporting` (suite) y de `ui` (pruebas pilot). Reglas que salieron de esa ronda:
  un parser **no** se amplifica (nada de devolver 3000 elementos por una línea), una IP
  concreta **jamás** sobrevive al enmascarado, y un fichero ilegible es un INFO
  "no verificable", nunca una excepción.
- Smoke UI headless (~70 s: ejecuta los chequeos de verdad, incluida la simulación apt,
  y al final las **4 pruebas pilot** de `tools/ui_pilot_tests.py` en su propio proceso).
  NO lo recoge `unittest discover` a propósito (es lento):
  ```bash
  .venv/bin/python tools/smoke_ui.py
  ```
- **Prueba en un terminal real** (pty, no headless): `tools/pty_check.py` lanza la app
  de verdad, le manda teclas y comprueba navegación, Enter, reporte y guardado. Lo que
  necesita la contraseña del usuario (`sudo mintguard` → guardar → comprobar el
  chown) sigue siendo manual: no hay `sudo` interno por diseño.
  Las pruebas pilot (regresión: chequeo por pantalla, carrera cancelar→reejecutar,
  generación del reporte y panel de prioridades del Inicio) se pueden correr solas
  (~30 s, cada `run_test` cuesta 7-12 s en este hardware):
  ```bash
  cd tools && ../.venv/bin/python ui_pilot_tests.py
  ```
- Medición de arranque y regeneración de screenshots:
  ```bash
  .venv/bin/python tools/boot_time.py
  .venv/bin/python tools/make_screens.py   # regenera docs/img/*.svg
  ```
- **Puerta de calidad completa** (suite + smoke + arranque; sale !=0 si algo falla):
  ```bash
  tools/verify.sh
  ```
- **CI en GitHub**: `.github/workflows/ci.yml` corre la suite en Python 3.10 y 3.12 en
  cada push/PR. Los checks pesados (smoke, arranque, contenedores) siguen siendo locales.
- **Verificación de las familias no apt con salida REAL en contenedores podman**
  (ejecuta los mismos comandos que MintGuard y los pasa por sus parsers; detecta
  falsos negativos como AVISO, falla si una familia no se pudo verificar):
  ```bash
  .venv/bin/python tools/verify_distro.py            # apt + arch + opensuse + fedora
  .venv/bin/python tools/verify_distro.py arch fedora # solo algunas
  ```
  Imágenes usadas (los registros oficiales dan 403 desde esta red):
  `ghcr.io/archlinux/archlinux`, `registry.opensuse.org/opensuse/tumbleweed`,
  `docker.1ms.run/library/fedora` (todas con `--network=host`).
- No hay lint/typecheck configurados; si se agregan, definirlos en `pyproject.toml` y
  documentarlos aquí.
- Las APIs de Textual **deben verificarse contra el fuente** en
  `.venv/lib/python3.12/site-packages/textual/` antes de asumir firma o asincronía
  (p. ej. `save_screenshot` NO es async).

## 3. Trampas de Textual 8.2.8 (todas sufridas; cada una costó horas)

1. **No pisar hooks privados del framework** en widgets/pantallas (`_render`, `_compose`,
   `_refresh`…): `Widget._render` debe devolver un Visual; un override que devuelve `None`
   rompe el renderizado (`'NoneType' object has no attribute 'render_strips'`). Usar
   nombres propios (p. ej. `_refresh_summary`).
2. **No sobreescribir `App.get_default_screen`**: la pantalla por defecto no tiene
   callbacks de resultado y `switch_screen` hace `.pop()` sobre esa lista vacía
   (`IndexError: pop from empty list`). Patrón correcto: pantalla base por defecto +
   `push_screen` en `on_mount` + navegar solo con `switch_screen`.
3. **No asignar atributos privados que pisen internals de `MessagePump`/`Widget`**.
   Caso real: `self._running = False` en `on_mount` de una Screen rompió el montaje con
   `SignalError: Node must be running to subscribe to a signal` en `Screen._on_mount`
   (porque `_running` es el flag que respalda `is_running`). Regla: **todo estado privado
   de una pantalla lleva prefijo propio** (`check_running`, `check_worker`,
   `check_cancel_requested`, `check_findings`).
4. **Las pantallas registradas por nombre en `SCREENS` se REUTILIZAN, no se re-montan**
   (`get_screen` cachea la instancia y `is_running` sigue True): `on_mount` NO vuelve a
   correr al volver a esa pantalla. Refrescar datos en `on_screen_resume` (patrón en
   `ui/screens/base.py` y `dashboard.py`).
5. **Hilos**: nunca tocar el DOM ni mutar estado de la app desde un worker
   (`@work(thread=True)`); capturar widgets en el hilo de UI y mutar solo vía
   `call_from_thread`.
6. **Cancelación de chequeo largo**: bandera `check_cancel_requested` + `worker.cancel()`;
   el subproceso sigue hasta su timeout y su resultado se descarta (limitación
   documentada en la UI misma). Tecla `x`.
7. Si se reemplaza `App.COMMANDS`, **incluir `get_system_commands_provider`** o se pierden
   los comandos del sistema (salir, temas, paleta…).
8. **LoadingIndicator** se oculta con `display: none` en CSS y se muestra con
   `display: block` (no `visibility`).
9. **Rendimiento**: arranque ~0.9 s; la simulación `apt-get -s dist-upgrade --print-uris`
   tarda ~24-30 s en el hardware objetivo (Celeron N3050 + HDD). No es un cuelgue: es el
   coste real de simular dist-upgrade, y la UI lo anuncia y permite cancelar.
   Cronometraje real por chequeo (2026-11-12, esa máquina): updates 25,7 s · network 49 ms
   · permissions 4 ms · services 5,1 s (systemctl tocando disco, no un bug) · firewall
   23 ms · "t" todos ~30 s. Con 0 paquetes apt la simulación se salta (mitad del coste).
10. **`call_from_thread` solo existe en `App`**, NO en `Screen` ni `Widget`
    (`hasattr(Screen, 'call_from_thread') == False`). Un worker que llama
    `self.call_from_thread` dentro de una pantalla muere con `AttributeError` y, como
    `@work` tiene `exit_on_error=True` por defecto, **cierra la app entera**. Usar
    `self.app.call_from_thread(...)` (bug real: ejecutar un chequeo desde su pantalla
    crasheaba la TUI; lo destapó la prueba pilot, no el smoke, que solo ejercita "t").
11. **`Worker.cancel()` NO mata el hilo** de un worker `thread=True`: cancela la task
    asyncio y el hilo sigue hasta terminar (y `call_from_thread` entrega igual). Con
    cancelar→reejecutar, el hilo viejo publicaba resultados obsoletos y reseteaba el
    estado de la ejecución nueva. Patrón obligatorio: **token por ejecución**, ya
    centralizado en `core/checkrun.py` (`CheckRun`: `start()` devuelve el token,
    `publish(token, …)` devuelve False si es obsoleto, `cancel()` lo invalida).
    Lo usan `base.py` (`_check_run`) y `app.py` (`_run_all_check`); si se añade un
    nuevo flujo con workers, usar CheckRun en vez de reimplementar flags.
12. **El atributo de clase `title = "..."` en una Screen MUERE**: `Screen.__init__` hace
    `self.title = self.TITLE` (TITLE=None) y pisar `title` con un str no llega al header
    (muestra siempre el título de la app). El descriptor `Reactive` de `Screen.title` se
    reemplaza por el str de clase. La API correcta es `TITLE` (consumida por __init__).
13. Las pruebas con `run_test` cuestan ~7 s cada una en este hardware: viven en
    `tools/ui_pilot_tests.py` (no en `tests/`) para que la suite rápida siga en ~0,1 s.
    `IsolatedAsyncioTestCase` NO puede correrse dentro del loop del smoke: el smoke las
    lanza en subproceso.
14. **Enmascarado de IPs: los dígitos son hex válido.** La máscara de IPv6-con-zona
    (`[0-9A-Fa-f:]{2,}%`) matcheaba el ÚLTIMO OCTETO de un IPv4 con 2+ dígitos y dejaba
    los tres primeros en claro (`100.99.183.44%tailscale0` → `100.99.183.<ip>…`): fuga
    real vista en un reporte (fallo de privacidad peor posible aquí). Regla: la máscara
    de zona EXIGE dos puntos (IPv6) y la IPv4 consume la `%zona` opcional conservándola
    tras `<ip>`. Tests de regresión con 1/2/3 dígitos en `test_reporter.py`.
15. **Ficheros creados bajo sudo: fchown ANTES de cerrar el fd.** Un reporte guardado
    con `sudo mintguard` quedaba root-owned 0600 en el directorio del usuario.
    `guardar_reporte` lee `SUDO_UID`/`SUDO_GID` (solo con euid 0) y hace
    `os.fchown(fd, …)` con el descriptor aún abierto (`fchown` lo necesita; tras
    `fdopen` ya no hay fd). Un chown fallido NO debe perder el reporte ya escrito.
    (Trampa clásica; mordió en primera persona el 2026-11-13.)
16. **El nombre de un proceso no prueba nada; un binario del PATH corre como root.**
    `ss -p` imprime el comm, que el proceso elige (`prctl(PR_SET_NAME)`): por eso una
    etiqueta de "esperado en su contexto" solo sobrevive si `/proc/<pid>/exe` es el
    binario de verdad (`core/expected_services.py::context_is_authentic`, fail closed).
    Y `shutil.which` busca en el PATH heredado: con `sudo -E`, un `~/.local/bin/ss`
    plantado se ejecutaría como root → `core/commands.py::resolve_binary` solo acepta
    binarios de root en las rutas estándar. Además, la salida de un comando puede NO
    ser UTF-8 (nombre de proceso con bytes inválidos): `text=True` en modo estricto
    lanzaba `UnicodeDecodeError` y tumbaba el chequeo entero → todos los comandos
    pasan por `core/commands.py::run_command` (UTF-8 + `errors="replace"`).

## 4. Estrategia de privilegios (decisión de diseño, CERRADA)

- **Nunca pedir contraseña ni bloquear la TUI**: no existe `sudo` interno, no hay prompts.
- Se hace **lo que se pueda sin privilegios**; cada hallazgo incompleto lo dice y sugiere
  `sudo` explícitamente.
- Qué cambia con sudo: refresh del índice apt (`apt-get update`), `/etc/shadow` legible,
  `ss -tulnp` muestra procesos.
- Ejecutar con `sudo .venv/bin/mintguard` es opcional, decisión del usuario (app de solo lectura).

## 5. Modelo de exposición (el diferenciador; contrato)

Responde a 4 preguntas: ¿expuesto a internet, a LAN o solo a localhost? ¿hay NAT delante?
¿el firewall está realmente activo o solo instalado? ¿ese `0.0.0.0` es real o está tras NAT?

Dónde vive cada dimensión (qué entra, qué sale):
1. **Alcance del bind** — `core/exposure.py::classify_address(address)` → `todas`
   (0.0.0.0/::/*), `interfaz` (IP concreta, o wildcard atado a dispositivo:
   `0.0.0.0%virbr0` = solo esa interfaz, NO "todas"), `local` (127.0.0.0/8 y ::1).
   El parser de `ss` soporta formato moderno (columna State, dirección local en índice 4)
   y antiguo (índice 3); `ss` que falla NUNCA es "no hay puertos" (error explícito).
2. **Severidad base por exposición** — `checks/network.py::severity_by_exposure(port,
   service_known, scope, nature)`: FTP/Telnet (21/23) CRITICA siempre; servicio conocido
   ALTA (todas) / MEDIA (interfaz); desconocido MEDIA/BAJA. La exposición pesa más que
   el nombre del servicio.
3. **Firewall real** — `checks/firewall.py::firewall_state` + `severity_with_firewall`:
   `systemctl is-active` sin root, `ufw status` autoridad con root, `firewall-cmd
   --state`. **El exit code manda, no el texto** (`is-active` de unidad inexistente =
   "desconocido", nunca "inactive"; falsa ALTA verificada). Ponderación (F2, UNA consulta
   por chequeo): activo baja 1 (piso BAJA), inactivo sube 1 (techo ALTA), desconocido no
   altera, **INFO y CRITICA inmóviles** (INFO con firewall activo = ValueError real,
   visto en máquina). El detail explica el cambio.
4. **Servicio esperado en su contexto** — `core/expected_services.py::classify(process,
   address, port, protocol)` → `tailscale` | `libvirt` | `avahi` | None. La etiqueta SOLO
   aplica si TODOS los miembros del grupo (protocolo, puerto) coinciden; grupo mixto
   conserva severidad y evidencia. La señal de Tailscale es el PROCESO (sshd en
   tailscale0 conserva su severidad); UDP 41641 → INFO en cualquier dirección; `dnsmasq`
   en 192.168.122.0/24 o `%virbr*`/`%docker*` → INFO; `avahi-daemon` en UDP efímero
   (≥32768) se pliega en el hallazgo BAJA de descubrimiento; `systemd` dueño de un puerto
   conocido → "socket-activado; probablemente {servicio}". Añadir contexto nuevo (snap,
   KVM, podman…) = un if más en `classify()`.
   **La etiqueta se tiene que poder PROBAR**: el nombre del proceso es falsificable
   (`prctl(PR_SET_NAME)`), así que `context_is_authentic(process, pid, context)` exige que
   `/proc/<pid>/exe` sea el demonio de la etiqueta (`tailscaled`/`dnsmasq`/`avahi-daemon`);
   si no, la etiqueta CAE (fail closed) y el puerto vuelve a su severidad normal. Sin
   sudo no hay pid: la regla del puerto 41641 se mantiene (nada la contradice) y el
   hallazgo lo dice. Un proceso desaparecido también pierde la etiqueta.
5. **Naturaleza de la interfaz** — `core/exposure.py::interface_nature(zone, ip)` →
   `public|lan|cgnat|loopback|link-local|virtual|unknown` (+ `socket_nature`,
   `worst_nature`). La zona manda para bridges (`virbr*`, `docker*`, `br-*` → virtual);
   100.64.0.0/10 → cgnat ANTES que LAN (Python también la marca `is_private`). Matriz:
   virtual → INFO, link-local → BAJA, cgnat como LAN (MEDIA/BAJA), public como "todas"
   (ALTA/MEDIA), unknown/lan → matriz base. Grupos mixtos: manda la naturaleza MÁS
   expuesta; **"unknown" > "public" a propósito** (un wildcard nunca se suaviza). El
   texto usa `_NATURE_SCOPE_TEXT`.
6. **Confianza y señales** — `core/confidence.py`: cada hallazgo puede llevar señales
   (`Signal.for_` / `Signal.against`) que son **las mismas entradas que la severidad ya
   usó** (la naturaleza de la interfaz, el contexto esperado, el estado del firewall, el
   binario verificado). La confianza sale de ellas: solo a favor → **Alta**, mezcladas →
   **Media**, solo en contra → **Baja**; sin señales **no hay confianza** (no se inventa).
   Reglas de la capa:
   - La confianza **explica** la severidad, no la recalcula: nunca pueden contradecirse
     (nada de "ALTA · confianza Media" por dos cuentas distintas).
   - Una confianza baja **NO esconde** el hallazgo (ocultar = falso negativo): se marca.
   - Las señales son texto genérico (sin cuentas ni rutas): se muestran también en modo
     anonimizado; la evidencia sigue las reglas de privacidad de siempre.
   - Los hallazgos INFO (una comprobación que pasó bien) no llevan señales.

Invariantes que no se negocian:
- **Un hallazgo por servicio real** (grupo protocolo+puerto; direcciones como evidencia);
  clientes DHCP (68/546 udp) ignorados; mDNS/LLMNR en un hallazgo BAJA; sockets localhost
  INFO.
- **NAT perimetral no es detectable**: declarado "posible" en el reporte y el hint de Red.
- **Privacidad**: IPs concretas enmascaradas SIEMPRE (ver trampa 14); wildcards, puerto y
  `%zona` visibles.
- **Límites honestos**: wildcard sin zona = "unknown" hasta v1.1; IP privada de bridge
  SIN zona se ve como LAN; separar el conteo de seguridad de dnf4 (dnf5 ya lo hace).
- **Una confianza baja no esconde nada**: el hallazgo sale en la tabla y en el reporte
  igual que los demás; la confianza solo matiza.
- **La explicación técnica completa** (reglas con ejemplos, matrices, caso real de la
  máquina del review) vive en `docs/exposure_model.md`: si cambia el contrato,
  actualizar AMBOS.

Pendiente (v1.1+): perfiles laptop/servidor; naturaleza de los wildcards usando las
direcciones globales de la máquina (`ip addr`).

## 6. Chequeos de endurecimiento (solo lectura)

`src/mintguard/checks/hardening.py` (pantalla "Sistema", tecla `k`, fuente `sistema`).
Audita el estado real del sistema; **nunca escribe ni aplica nada**:

| Chequeo | Fuente | Qué mira |
| --- | --- | --- |
| Taint del kernel | `/proc/sys/kernel/tainted` | módulo propietario, parche en caliente, driver sin firmar (bits según `Documentation/admin-guide/tainted-kernels.rst`) |
| Volcados de memoria | `/proc/sys/kernel/core_pattern` + `/proc/self/limits` | si un crash escribe la memoria (con contraseñas) a disco |
| Mitigaciones de CPU | `/sys/devices/system/cpu/vulnerabilities/` | Spectre, Meltdown, MDS… sin mitigar |
| IOMMU | `/sys/class/iommu` | DMA sin confinar (VT-d / AMD-Vi) |
| Secure Boot | `/sys/firmware/efi/efivars/SecureBoot-*` | firmware validado en el arranque |
| Sudoers | `/etc/sudoers`, `/etc/sudoers.d/` | `NOPASSWD: ALL`, `env_keep` con `LD_PRELOAD`, comodines sobre editores |
| AppArmor/SELinux | `/sys/module/apparmor`, `/proc/cmdline`, `/etc/apparmor.d/`, `/sys/kernel/security/apparmor/profiles`, `/proc/<pid>/attr/current`, `/sys/fs/selinux/enforce` | módulo activo o `apparmor=0`, perfiles definidos y `.disabled` en disco, estado cargado (complain; solo root lo lee) y **confinamiento real en ejecución** (legible sin sudo, trae hasta el modo del perfil); SELinux: enforcing vs permisivo |
| Persistencia | autostart, `/etc/rc.local`, `crontab`, ficheros de inicio | rutas fuera del sistema, descarga y ejecución directa |
| Errores del kernel | `dmesg` / `/var/log/kern.log` | `BUG:`, `Oops:`, `WARNING:` (para reportar upstream) |
| Binarios SUID/SGID | `/usr/bin`, `/bin`, `/usr/sbin`, `/sbin`, `/usr/local/*` | un setuid que **no es de root** o que se puede modificar = escalada trivial |

Reglas de la capa:
- **Nunca auto-endurecer**: ni un `sysctl`, ni una regla de nftables, ni un cambio.
  El texto dice qué hacer; lo hace el usuario.
- **Nunca pedir sudo**: si un dato necesita root, el hallazgo es INFO "no verificable"
  y sugiere el comando. Un fichero ilegible **nunca** es una excepción: es un INFO.
- Los parsers puros viven a nivel de módulo (`parse_tainted`, `parse_sudoers_rules`,
  `parse_vulnerability_status`…) y tienen tests con fixtures; los checkers solo leen.
- Los detalles no llevan rutas ni nombres de usuario (eso va en la evidencia, que el
  modo anonimizado oculta junto a `permissions` y `services`).
- Coste: cada chequeo < 50 ms salvo tres, medidos y justificados: `dmesg` (~90 ms, es
  un fork), el escaneo de binarios SUID/SGID (~70 ms: un `lstat` por binario del
  sistema; con `/bin` → `/usr/bin` el directorio se recorre una sola vez) y el
  escaneo de confinamiento en ejecución (~85 ms: una lectura de
  `/proc/<pid>/attr/current` por PID visible, sin fork; va en su propio chequeo
  `check_mac_runtime` para no frenar al resto).
- Los alias de sudoers (`User_Alias`, `Host_Alias`) **no se resuelven**: las reglas que
  los usan no se evalúan y se dice en el hallazgo.

## 7. Alcance honesto y roadmap

- **v1.0 = familia apt verificada** (Debian/Ubuntu/Mint) en esta máquina, con
  `tools/verify.sh` en verde. Los parsers dnf/pacman/zypper tienen tests con fixtures
  y están verificados con **salida real en contenedores podman**
  (`tools/verify_distro.py`), pero **falta la pasada manual en instalación real** de
  esas distros antes de darlos por terminados (v1.1).
- Permisos y servicios incluidos (baratos: lectura de ficheros + `systemctl`).
- **Historial (fase 10 original): APLAZADO** hasta que haya usuarios; no hay carpeta `data/`.
- **Nombre CONFIRMADO por el usuario (2026-11-12): MintGuard se queda.** El README ya
  aclara que funciona en cualquier distro Linux; no hay que renombrar ni replantear branding.
- Las limitaciones ("snapshot, no monitorización") se documentan en README y UI.
- **Privacidad del reporte (decisión implementada)**: IPs concretas enmascaradas
  SIEMPRE (`<ip>`; quedan wildcards, puerto y zona `%iface`); tecla `a` en la pantalla
  de reporte activa el modo anonimizado (kernel → mayor.menor, distro → versión mayor,
  CPU sin modelo, sin listas de permissions/services). La nota de privacidad de la UI
  es dinámica según el modo. Regex de IPv6 solo con zona o ≥3 grupos: evita comerse
  horas ("02:50:03") y el residuo `:::41641` del ss antiguo.

## 8. Git (trampa)

- MintGuard tiene repo propio dentro de `MintGuard/` (**creado por petición explícita del
  usuario**). Verificar siempre `git rev-parse --show-toplevel` → `/home/jai/MintGuard`.
- **PÚBLICO desde 0.3.0 (2026-11-14)**: `origin` = `github.com/jai416/MintGuard`
  (release v0.3.0 publicado). Todo lo que entra a `main` es visible; sin datos de la
  máquina real en capturas ni reportes (los `reporte-mintguard-*.txt` están gitignored).
- **Jamás** `git add`/`git commit`/`git init` en `/home/jai`: ahí hay un repo accidental
  vacío cuyo `.gitignore` ignora todo, e indexaría secretos del home.
- Antes de tocar algo fuera de `MintGuard/`, leer `/home/jai/AGENTS.md`.

## 9. Principios no negociables (mandan sobre cualquier duda de diseño)

- **Rendimiento primero**: cada chequeo debe medirse por su impacto en CPU, RAM y disco.
- **Todo bajo demanda**: sin demonios, servicios en segundo plano ni escaneos automáticos.
- **Multi-distro real**: nunca asumir Mint/Ubuntu. Matiz sobre rutas: `/etc/os-release`,
  `/etc/passwd`, `/etc/shadow` son estándar y está bien leerlos; la regla útil es
  "no asumir rutas/comandos que varían por distro", no "cero rutas hardcodeadas".
- **Pocas dependencias**: biblioteca estándar primero; Textual obligatorio para la UI;
  justificar cada librería nueva antes de agregarla.
- **UI 100% en español neutro**; nombres de variables, funciones y clases en inglés.
- **Navegable con mouse Y teclado**: toda acción clave tiene botón (barra
  `NavButtons` en todas las pantallas, ejecutar/cancelar, tarjetas del inicio). Los
  botones "de mouse" (`MouseButton`) llevan `can_focus=False` para no robar la tecla
  Enter de las pantallas (Textual enfoca el primer widget enfocable). El pie y la
  paleta `ctrl+p` siguen siendo la guía de atajos, como en OpenCode.
- Sin Electron, navegadores embebidos ni interfaces web pesadas.
- Solo implementar lo pedido explícitamente; fases pequeñas y comprobables.
- Preferir soluciones simples y legibles antes que "inteligentes" pero complejas.
- Cada hallazgo debe poder explicarse de forma sencilla, sugerir corrección y entrar en
  el reporte.

## 10. Detección requerida (contrato de `core/distro.py`)

Desde `/etc/os-release` y herramientas del sistema: distribución y versión; gestor de
paquetes disponible; presencia de systemd; AppArmor o SELinux; firewall (UFW, firewalld,
nftables). Soporte prioritario:

- Debian / Ubuntu / Linux Mint → `apt`
- Fedora / RHEL / CentOS / Rocky → `dnf`
- Arch Linux y derivadas → `pacman`
- openSUSE → `zypper`

## 11. Layout (real, actualizado)

```text
MintGuard/
├── AGENTS.md
├── README.md
├── pyproject.toml
├── docs/img/*.svg          # capturas del README (tools/make_screens.py)
├── tools/                  # smoke_ui.py, boot_time.py, make_screens.py (no son tests)
├── tests/                  # unittest, solo biblioteca estándar
└── src/mintguard/
    ├── main.py             # punto de entrada
    ├── core/               # distro, system, exposure, prioritizer
    ├── checks/             # updates, network, permissions, services
    ├── reporting/reporter.py
    └── ui/                 # app.py, screens/, widgets/
```

## 12. Fuente de verdad

- Este archivo manda ante cualquier duda de diseño, prioridad o alcance.
- Tras cada avance importante, verificar que siguen cumpliéndose los principios de
  ligereza, honestidad de alcance y multi-distro.
