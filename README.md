# MintGuard

![Inicio](docs/img/inicio.svg)

TUI de seguridad **ligera** para Linux, hecha con [Textual](https://textual.textualize.io),
**100% en español**. Detecta problemas, los prioriza según la **exposición real** de tu
máquina, sugiere correcciones concretas y genera reportes limpios para copiar.

No compite con Lynis ni con rkhunter, y no es un antivirus: es una herramienta de
**revisión rápida y legible para equipos de escritorio**, pensada para hardware modesto
(Celeron, 8 GB RAM, HDD) donde los scanners clásicos tardan demasiado.

## Alcance honesto (0.2.x)

- **Verificado en esta máquina (Linux Mint 22.3, apt)** y con **salida real capturada en
  contenedores podman** (2026-11-13): `pacman` 7.1.0 (Arch), `zypper` 1.14.102
  (openSUSE Tumbleweed) y `dnf5` 5.4.7 (Fedora 45, incluido el conteo de seguridad con
  `check-upgrade --security`). Queda por verificar a mano en instalación real de esas
  distros.
- Revisa 4 áreas: actualizaciones, red, permisos y servicios. No escanea malware ni rootkits.
- **Snapshot, no monitorización**: cada chequeo es una foto del momento. Nada corre en
  segundo plano ni al abrir la app; los datos de red son intrínsecamente dinámicos.

## Qué revisa

| Área | Qué hace | Mejora con `sudo` |
| --- | --- | --- |
| Actualizaciones | paquetes actualizables + cuántos son de seguridad (simulación de `apt dist-upgrade`; en dnf5 vía `check-upgrade --security`) | refresca el índice |
| Red | puertos en escucha (`ss`) clasificados por exposición **y ponderados por el estado real del firewall** + estado del firewall (activo vs instalado pero inactivo) | muestra el proceso dueño |
| Permisos | UID 0 extraños, contraseñas vacías, permisos de `passwd`/`shadow`/`sudoers` (incluida escritura por grupo), configuración de sshd (incluidos bloques `Match`) | lee `/etc/shadow` |
| Servicios | servicios systemd habilitados al arranque; marca telnet, tftp, rsh… | (sin cambios) |

Un matiz que el reporte **declara siempre**: la exposición se evalúa desde la propia
máquina; un NAT perimetral delante (router, VPS) puede reducirla y MintGuard no puede
verlo. Si el firewall está activo, la severidad de los puertos expuestos baja un nivel;
si está instalado pero inactivo, sube.

## Estrategia de privilegios

- **Nunca pide contraseña y nunca bloquea la TUI** esperando nada: no hay `sudo` interno.
- Sin privilegios funciona con datos limitados, y cada hallazgo incompleto lo dice y
  sugiere cómo completarlo.
- Si quieres la revisión completa: `sudo .venv/bin/mintguard` (la app es de solo lectura).

## Chequeo lento, sin sensación de cuelgue

La simulación de `dist-upgrade` tarda **~30 s en hardware lento** (HDD): es el coste real
de saber qué updates son de seguridad. La pantalla muestra spinner y aviso del tiempo, y
puedes **cancelar con `x`**: la interfaz responde al instante; el comando en curso termina
en su timeout y su resultado se descarta.

## Privacidad del reporte

Las **IPs concretas se enmascaran siempre** (`<ip>`); se conservan las wildcard
(`0.0.0.0`, `::`), el puerto y la zona de interfaz (`%tailscale0`). Con la tecla `a`
en la pantalla de reporte se activa el **modo anonimizado**: kernel reducido a
mayor.menor, versión de distro reducida a la mayor, CPU sin modelo y sin las listas
de usuarios ni servicios. La pantalla te avisa del nivel de detalle antes de copiar
o guardar.

![Red](docs/img/red.svg)

## Instalación y uso

```bash
python3 -m venv .venv
.venv/bin/pip install -e .      # única dependencia: textual
.venv/bin/mintguard
```

Todo se puede usar **con el mouse**: la barra de navegación superior, las tarjetas
del inicio, los botones de ejecutar/cancelar y las filas de las tablas responden a
clic. Las teclas quedan como atajos para quien las prefiera:

| Tecla | Acción |
| --- | --- |
| `d` `u` `n` `p` `s` `r` | Inicio · Actualizaciones · Red · Permisos · Servicios · Reporte |
| `t` | ejecutar todos los chequeos |
| `Enter` | ejecutar el chequeo de la pantalla actual |
| `x` | cancelar el chequeo en curso (o "ejecutar todos") |
| `f5` | refrescar datos del sistema |
| `ctrl+p` | paleta de comandos |
| `q` | salir |

## Tests

En una herramienta de seguridad, un parser roto produce **falsos negativos**: el usuario
cree estar protegido y no lo está. Por eso todo parser (`apt`, `dnf`, `pacman`, `zypper`,
`ss`, `systemctl`, `passwd`, `shadow`, `sshd_config`) tiene tests unitarios con `unittest`
de la biblioteca estándar, sin dependencias extra:

```bash
.venv/bin/python -m unittest discover -s tests
```

Además hay un smoke test de la interfaz completo (headless, ~70 s: ejecuta los chequeos
de verdad y las pruebas de regresión de UI con pilot — ejecutar un chequeo desde su
propia pantalla, la carrera cancelar→reejecutar y el reporte):
`.venv/bin/python tools/smoke_ui.py`

![Reporte](docs/img/reporte.svg)

## Limitaciones conocidas

- **Snapshot**: lo que ves es el estado del momento, no vigilancia continua.
- La clasificación de exposición es local y heurística: `0.0.0.0` se marca como expuesto
  y el reporte asume **posible NAT** porque no se puede saber si hay un router delante
  desde la propia máquina.
- `dnf`/`pacman`/`zypper`: verificados con salida real en contenedores, sin instalación
  real aún de esas distros.

## Estructura

```text
MintGuard/
├── AGENTS.md               # contrato para agentes de código
├── README.md
├── pyproject.toml
├── docs/img/               # capturas del README
├── tools/                  # smoke de UI, medición de arranque, capturas
├── tests/                  # unittest (solo biblioteca estándar)
└── src/mintguard/
    ├── main.py             # punto de entrada
    ├── core/               # distro, sistema, exposición, priorización
    ├── checks/             # updates, network, permissions, services
    ├── reporting/          # generador de reportes
    └── ui/                 # app Textual, pantallas y widgets
```
