# MintGuard - Instrucciones para el Agente (OpenCode)

## 1. Qué es este proyecto y en qué estado está

MintGuard es una TUI de seguridad ligera para Linux hecha con **Textual**, 100% en español.
Detecta problemas, los prioriza según la **exposición real** de la máquina, sugiere
correcciones y genera reportes limpios. NO es antivirus ni escáner de malware/rootkits
(no compite con rkhunter/clamav) y **no hay que llamarlo "innovador"** en docs ni mensajes:
el valor es la ejecución de un nicho (TUI moderna, español, exposición real, ultraligero).

**Estado (verificado 2026-11-12): versión 0.2.0.** Estructura completa (core, checks,
reporting, ui), **72 tests unittest OK**, smoke UI headless en verde, repo git propio
dentro de `MintGuard/`. Arranque medido: **~0.9 s** total (detección de distro+sistema
< 60 ms; el resto es el primer frame de Textual).

## 2. Comandos (verificados)

- El Python del sistema está protegido por **PEP 668** → todo dentro del venv:
  ```bash
  python3 -m venv .venv
  .venv/bin/pip install -e .        # única dependencia: textual (probado con 8.2.8)
  .venv/bin/mintguard               # ejecutar la TUI
  .venv/bin/mintguard --version
  ```
- **Tests (regla NUEVA, sustituye la antigua de "no inventar tests")**:
  ```bash
  .venv/bin/python -m unittest discover -s tests
  ```
  **Todo parser de salida de comandos (apt/dnf/pacman/zypper/ss/systemctl/passwd/shadow/
  sshd_config) DEBE tener tests unitarios con unittest de la stdlib.** Un parser roto
  produce falsos negativos de seguridad, que es el peor fallo posible de esta herramienta.
- Smoke UI headless (~35 s; ejecuta los chequeos de verdad, incluida la simulación apt).
  NO lo recoge `unittest discover` a propósito (es lento):
  ```bash
  .venv/bin/python tools/smoke_ui.py
  ```
- Medición de arranque y regeneración de screenshots:
  ```bash
  .venv/bin/python tools/boot_time.py
  .venv/bin/python tools/make_screens.py   # regenera docs/img/*.svg
  ```
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

## 4. Estrategia de privilegios (decisión de diseño, CERRADA)

- **Nunca pedir contraseña ni bloquear la TUI**: no existe `sudo` interno, no hay prompts.
- Se hace **lo que se pueda sin privilegios**; cada hallazgo incompleto lo dice y sugiere
  `sudo` explícitamente.
- Qué cambia con sudo: refresh del índice apt (`apt-get update`), `/etc/shadow` legible,
  `ss -tulnp` muestra procesos.
- Ejecutar con `sudo .venv/bin/mintguard` es opcional, decisión del usuario (app de solo lectura).

## 5. Modelo de exposición (el diferenciador; diseñado, implementación parcial)

Preguntas que el modelo debe responder: ¿expuesto a internet, a LAN o solo a localhost?
¿hay NAT delante? ¿el firewall está realmente activo o solo instalado? ¿ese `0.0.0.0` es
real o está tras NAT?

**Implementado hoy** (`core/exposure.py` + `checks/network.py`):
- Clasificación por socket: `todas` (0.0.0.0/::/*), `interfaz` (IP concreta, **o wildcard
  atado a un dispositivo**: `0.0.0.0%virbr0` = solo esa interfaz, NO "todas"), `local`
  (todo 127.0.0.0/8 y ::1).
- **Severidad por exposición** (`severity_by_exposure`): FTP/Telnet (21/23) CRITICA
  siempre; servicio conocido ALTA en "todas" / MEDIA en "interfaz"; puerto desconocido
  MEDIA en "todas" / BAJA en "interfaz". La exposición pesa más que el nombre del
  servicio.
- Clientes DHCP (68/546 udp) ignorados; mDNS/LLMNR (5353/5355) agrupados en un hallazgo BAJA.
- **Un hallazgo por servicio real** (grupo protocolo+puerto; las direcciones van como
  evidencia) para no inundar el reporte con duplicados IPv4/IPv6/interfaz.
- **Estado real del firewall** (`checks/firewall.py`, hallazgos bajo la fuente "network"):
  `systemctl is-active` sin root (ufw/firewalld/nftables/netfilter-persistent/iptables),
  `ufw status` como autoridad con root, `firewall-cmd --state` para firewalld. Instalado
  pero inactivo = ALTA; no detectado ninguno = MEDIA. El parser de `ufw status` acepta
  variantes localizadas (la salida de error de ufw está traducida).
- Sockets de localhost listados como INFO ("correcto").
- Parser de `ss` soporta el formato moderno (con columna State; dirección local en el
  índice 4) y el antiguo (índice 3), con tests de regresión: el bug original era un
  **falso negativo real** ("no hay puertos") en una máquina con puertos abiertos.

**Pendiente (v1.1+)**: perfiles laptop/servidor, usar el estado del firewall (ya
detectado) como factor de priorización, tratamiento de NAT (no detectable localmente;
asumir "posible" y decirlo).

## 6. Alcance honesto y roadmap

- **v1.0 = familia apt verificada** (Debian/Ubuntu/Mint). Los parsers dnf/pacman/zypper
  existen con tests, pero sin verificación en hardware real de esas distros.
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

## 7. Git (trampa)

- MintGuard tiene repo propio dentro de `MintGuard/` (**creado por petición explícita del
  usuario**). Verificar siempre `git rev-parse --show-toplevel` → `/home/jai/MintGuard`.
- **Jamás** `git add`/`git commit`/`git init` en `/home/jai`: ahí hay un repo accidental
  vacío cuyo `.gitignore` ignora todo, e indexaría secretos del home.
- Antes de tocar algo fuera de `MintGuard/`, leer `/home/jai/AGENTS.md`.

## 8. Principios no negociables (mandan sobre cualquier duda de diseño)

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

## 9. Detección requerida (contrato de `core/distro.py`)

Desde `/etc/os-release` y herramientas del sistema: distribución y versión; gestor de
paquetes disponible; presencia de systemd; AppArmor o SELinux; firewall (UFW, firewalld,
nftables). Soporte prioritario:

- Debian / Ubuntu / Linux Mint → `apt`
- Fedora / RHEL / CentOS / Rocky → `dnf`
- Arch Linux y derivadas → `pacman`
- openSUSE → `zypper`

## 10. Layout (real, actualizado)

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

## 11. Fuente de verdad

- Este archivo manda ante cualquier duda de diseño, prioridad o alcance.
- Tras cada avance importante, verificar que siguen cumpliéndose los principios de
  ligereza, honestidad de alcance y multi-distro.
