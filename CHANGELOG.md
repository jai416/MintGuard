# Changelog

Formato basado en [Keep a Changelog](https://keepachangelog.com/); versionado SemVer.

## [Sin publicar]

### Corregido

- **El parser de `ss` aceptaba puertos imposibles** (99999, -1): una línea malformada
  metía un endpoint falso en el reporte. Ahora se descartan las líneas con un puerto
  fuera de rango.
- **`worst_nature` podía devolver una cadena que no es una naturaleza** (y reventaba
  con una lista vacía). Ahora siempre devuelve una naturaleza válida: lo desconocido se
  traduce a `unknown`, que es el valor más expuesto de la matriz.

### Añadido

- **Fuzz de los parsers** (`tests/test_parsers_fuzz.py`): 38 parsers alimentados con
  basura determinista (bytes no UTF-8, escapes ANSI, líneas de 10 000 caracteres,
  campos vacíos, números absurdos) con tres invariantes: ninguno revienta, ninguno
  amplifica su entrada (un parser que devuelve 3000 elementos por una línea está tan
  roto como uno que explota) y **una IP concreta nunca sobrevive al enmascarado**.
  Ya ha encontrado los dos fallos de arriba.


### Añadido

- **`tools/pty_check.py`**: prueba de la app en un **terminal real** (pty), no headless.
  Lanza el binario de verdad, le manda teclas y comprueba el arranque, la navegación
  por teclado (incluida la pantalla «Sistema»), que Enter ejecuta el chequeo (los
  botones de la barra no lo roban), la generación del reporte y el guardado (fichero
  del usuario, modo 0600, legible sin sudo). Lo que necesita la contraseña —el
  `sudo mintguard` real— sigue siendo manual a propósito: no hay `sudo` interno.


## [0.4.0] — 2026-11-15

### Añadido

- **Chequeo de binarios SUID/SGID** (en la pantalla «Sistema»): recorre con
  `os.scandir` las rutas del sistema (`/usr/bin`, `/bin`, `/usr/sbin`, `/sbin`,
  `/usr/local/*`) sin lanzar ningún proceso, y avisa cuando un programa con el bit
  setuid o setgid **no es de root** o **se puede modificar**: ejecutarlo ya es
  ejecutarlo como root, así que es una escalada de privilegios directa. El inventario
  de los setuid normales del sistema (sudo, su, passwd, mount…) se informa aparte,
  como INFO.

### Corregido

- La verificación de contenedores (`tools/verify_distro.py`) **depende de la red**: los
  metadatos de `dnf`/`zypper` se descargan dentro del contenedor, así que si la red
  falla o va muy lenta esa verificación se salta. No es un fallo de los parsers (quedan
  verificados con salida real del 2026-11-13) y ahora el README lo dice.

## [0.3.1] — 2026-11-14

### Añadido

- **Auditoría de endurecimiento del sistema (pantalla «Sistema», tecla `k`)**: nueve
  chequeos de **solo lectura** que miran el estado real de la máquina y dicen qué hacer,
  sin cambiar nada:
  - *taint del kernel* (`/proc/sys/kernel/tainted`): módulo propietario, parche en
    caliente, driver sin firmar;
  - *volcados de memoria*: si un crash escribe la memoria (con contraseñas) a disco;
  - *mitigaciones de CPU* (Spectre, Meltdown, MDS…): lo que sigue sin mitigar;
  - *IOMMU*: DMA sin confinar (VT-d / AMD-Vi);
  - *Secure Boot*: si el firmware valida las firmas en el arranque;
  - *sudoers*: `NOPASSWD: ALL`, `env_keep` con `LD_PRELOAD` y comodines sobre editores
    o paginadores (el `sudo vim *` de toda la vida);
  - *AppArmor*: perfiles en modo `complain`, que registran pero no bloquean;
  - *persistencia*: autoarranque, `/etc/rc.local`, `crontab` y ficheros de inicio con
    rutas fuera del sistema o con descarga y ejecución directa;
  - *errores del kernel* (`dmesg`): para reportar upstream.
  Los datos que necesitan root se marcan como «no verificable» y sugieren el comando;
  un fichero ilegible nunca es un error. En modo anonimizado sus rutas y reglas de
  sudoers quedan fuera del reporte.

### Corregido


- **La configuración de SSH se lee en el orden en que la aplica sshd.** El merge ponía
  siempre los ficheros de `sshd_config.d/` antes: con el `Include` al final del fichero
  principal (que sí es válido) manda el principal, y la lectura mintenía. Ahora los
  drop-ins se aplican donde aparece el `Include`, y si no hay `Include` no se aplican
  (sshd no los lee).

- **Una avalancha de puertos ya no inunda el reporte.** Un proceso puede abrir miles de
  sockets: el chequeo detallaba un hallazgo por cada uno y el reporte dejaba de ser
  legible (y servía de camuflaje). Ahora se detallan como máximo 50 y el resto se cuenta
  en un hallazgo honesto.

- **Un `Include` de sshd fuera del directorio revisado se aceptaba por prefijo.**
  `/etc/ssh/sshd_config.d2/evil.conf` (o un `..` que sale del directorio) se tomaba
  por interno y su configuración efectiva no se veía. Ahora se compara el directorio
  de verdad.

- **Los nombres de proceso y de paquete ya no pueden traeverse escapes ANSI ni
  líneas giganticas al reporte.** Un nombre de proceso lo elige el proceso (cualquier
  usuario puede poner `\x1b[31m` en el suyo) y llegaba al reporte tal cual: el usuario
  que lo imprimiera en su terminal vería la salida repintada. Ahora el texto
  semi-confiable se sanea (los caracteres de control se sustituyen) y se corta a 120
  caracteres, en el origen, en el reporte y en el panel de detalle de la UI.

- **Los comandos del sistema ya no se resuelven por el PATH.** El código usaba rutas
  absolutas, pero las obtenía con `shutil.which`, que **sí** busca en el PATH: con
  `sudo -E` (o un `sudoers` que conserve el PATH), un `ss` plantado en `~/.local/bin`
  se ejecutaba como root. Ahora los binarios se resuelven en las rutas estándar
  (`/usr/bin`, `/bin`, `/usr/sbin`, `/sbin`, `/usr/local/*`) y solo se aceptan si son
  de root y no escribibles por el grupo o por otros; si no están, se dice honestamente
  que no están disponibles en vez de ejecutar el primero que aparezca.

- **El loopback IPv4-mapeado (`::ffff:127.0.0.1`) se contaba como interfaz expuesta.**
  Es el bind habitual de los sockets dual-stack (Java, Go): no es la LAN, es el
  localhost. Ahora `classify_address` lo trata como local y `interface_nature` como
  loopback (Python no lo marca como loopback y lo metía en "lan").

- **La etiqueta de la distro en modo anonimizado revelaba el codename y dejaba espacios
  dobles** ("Linux Mint  Una 21", "Ubuntu  LTS 24"). Ahora solo nombre y versión mayor.

- **El hallazgo de descubrimiento (mDNS/LLMNR) se quedaba sin evidencia cuando no
  había avahi**: el detalle nombraba los puertos, pero el reporte no listaba ninguno.

- **Las etiquetas de "servicio esperado" ya no se pueden falsificar con el nombre del
  proceso.** El nombre que imprime `ss` lo elige el proceso (`prctl(PR_SET_NAME)`): un
  proceso llamado `dnsmasq` o `tailscaled` se libraba de la exposición real y el
  chequeo lo daba por "esperado en su contexto". Ahora `ss -p` aporta el pid y la
  etiqueta solo se mantiene si `/proc/<pid>/exe` es el binario de verdad
  (`tailscaled`/`dnsmasq`/`avahi-daemon`); si no, cae (fail closed) y el puerto vuelve
  a su severidad normal. Sin sudo no hay pid: la regla del puerto 41641 se mantiene
  (nada la contradice) y el hallazgo lo dice. Un proceso desaparecido también pierde
  la etiqueta.

- **Un proceso local con nombre no-UTF-8 tumbaba el chequeo de Red entero.** La
  salida de `ss` se decodificaba en modo estricto: cualquier usuario puede
  renombrar su propio proceso con bytes que no son UTF-8, y eso hacía que el
  chequeo de Red terminara en un único error (y en actualizaciones, igual),
  sin un solo hallazgo real. Ahora los comandos se ejecutan con UTF-8 fijo y
  `errors="replace"` (nunca lanza al decodificar) en un único helper
  (`core/commands.py`), con tests.

- **Privacidad del reporte: IPv6 comprimidas y formas completas sin `%zona` pasaban
  enteras en claro.** `ss` imprime los binds ULA/link-local/globales sin zona
  (`fd7a:9918:1e6c::cd45:22` — la forma habitual de la ULA de Tailscale — o
  `fd00::5`), y la regla anterior (3-6 grupos de dos puntos terminados en hex) no
  las matcheaba; las formas de 8 grupos dejaban la cola sin enmascarar. Ahora se
  enmascara cualquier hex antes de `::` y la forma completa hasta 7 grupos + puerto
  (`<ip>:443`). Las horas (`02:50:03`), el residuo comodín del `ss` antiguo
  (`:::41641`) y las zonas (`%virbr0`) siguen intactos. Tests de regresión nuevos.

## [0.3.0] — 2026-11-14

Primer release público.

### Añadido

- **Reglas de "servicio esperado en su contexto"** (`core/expected_services.py`, nuevo):
  la exposición se juzga por contexto, no solo por dirección de bind. Tailscale
  (proceso `tailscaled` en su interfaz/overlay y UDP 41641) y el `dnsmasq` de libvirt
  (192.168.122.0/24 o bridge virtual) pasan a INFO con la explicación de por qué son
  normales; los puertos UDP efímeros de `avahi-daemon` se pliegan en el hallazgo BAJA
  de descubrimiento. Un grupo mixto (p. ej. nginx + tailscaled en el mismo puerto)
  conserva su severidad y toda la evidencia. En la máquina del review: 11 ALTA → 4
  accionables. El proceso `systemd` dueño de un puerto conocido se anota como
  "socket-activado; probablemente {servicio}".
- **Naturaleza de la interfaz** (`interface_nature`, cuarta dimensión de la severidad):
  pública / LAN / CGNAT / loopback / link-local / virtual, deducida de la zona (`%virbr*`,
  `%docker*`) y/o la IP concreta del bind. Un servicio en un bridge virtual pasa a INFO,
  en enlace local a BAJA, y un bind a IP pública real sube a ALTA (internet). El detalle
  describe qué puede alcanzar al servicio ("accesible desde internet", "no enrutable
  desde internet"). El wildcard sin zona queda "unknown" con la matriz original (juzgarlo
  exige ver las demás direcciones de la máquina: v1.1).
- **Panel «Prioridades» en el Inicio** (respuesta a la prueba de uso): plan de
  acción global que explica cómo empezar antes de ejecutar, muestra «ejecutando…»
  durante la pasada y, al terminar, lista los 3 hallazgos más graves **con su
  recomendación** ordenados por prioridad, más el resto y un puntero al informe.
- **Pantallas de chequeo más explícitas**: el panel inferior se titula
  «Explicación y recomendación» y la línea de estado recuerda *↑↓ o clic* para
  moverse por las filas.
- El firewall detectado ahora **pondera la severidad** de cada puerto expuesto:
  activo baja un nivel (piso BAJA), inactivo sube uno (techo ALTA), FTP/Telnet
  nunca cambia. El reporte declara la **nota de NAT** (un router delante no es
  visible desde la máquina).
- **Modelo `CheckRun`** (core/checkrun.py): la vida de un chequeo como máquina de
  estados con el guard de resultados obsoletos centralizado; lo usan las pantallas
  y "ejecutar todos" (9 tests de las reglas de carrera).
- **Puerta de calidad `tools/verify.sh`**: suite + smoke + medición de arranque en
  un solo comando (sale distinto de cero si algo falla).
- **`tools/verify_distro.py`**: verifica dnf/pacman/zypper con salida REAL en
  contenedores podman ejecutando los mismos comandos que MintGuard; detecta falsos
  negativos. Verificado 2026-11-13: apt 43/26 seguridad, Arch rc=1 BD incompleta,
  openSUSE 1 paquete (cabecera "S |" saltada), Fedora 18 paquetes / 6 seguridad.
- Verificación real de parsers en contenedores podman: `pacman -Qu` (Arch 7.1.0),
  `zypper lu` (openSUSE Tumbleweed 1.14.102), `dnf5 check-upgrade --security`
  (Fedora 45 / dnf5 5.4.7) — fixtures con las salidas reales capturadas.
- Conteo de seguridad en dnf5 vía `check-upgrade --security` (la columna repo
  siempre dice "updates", nunca "security").
- Aviso de caché de apt vieja sin root (índice con más de 7 días).
- Detección de bloques `Match` e `Include` externos en sshd_config (directivas
  condicionales que antes se leían como globales).

### Corregido

- `mintguard --version` ya no puede divergir de `pyproject.toml`: la versión se lee
  de los metadatos del paquete instalado (fallback declarado si corre desde el fuente
  sin instalar). El drift 0.2.0/0.3.0 se vio el día del release.

- El panel «Explicación y recomendación» es desplazable: en terminales bajos
  (80×24) recortaba las líneas de continuación del hallazgo y la nota
  "conteo estimado; con sudo es exacto" quedaba fuera de la vista. Con la
  rueda del mouse se ve el texto completo.
- **Fuga de privacidad en IPv4 con `%zona`** (visto en un reporte real): la máscara
  de IPv6-con-zona también matcheaba el último octeto de un IPv4 cuando tenía
  2+ dígitos (los dígitos son hex válido), dejando `100.99.183.` en claro en
  `100.99.183.44%tailscale0:443`. Ahora la máscara de zona exige dos puntos
  (IPv6) y la de IPv4 consume la `%zona` y la conserva: `<ip>%tailscale0:443`.
  Tests de regresión con los tres casos (1, 2 y 3 dígitos).
- Reporte guardado con `sudo` ya no queda como root: se restaura el propietario
  del usuario que invocó (`SUDO_UID`/`SUDO_GID`) con `os.fchown` mientras el fd
  sigue abierto; un chown fallido no pierde el reporte ya escrito.
- **"Aproximadamente 26" ha desaparecido**: con root el conteo de seguridad de
  apt es exacto (URIs de la simulación) y se dice sin matices; sin root el
  conteo declara su método: "conteo estimado; con sudo es exacto". La
  sugerencia del índice sin refrescar ahora dice qué mirar (línea de error,
  repositorio caído o falta de red).
- **INFO es inmóvil para el firewall** (regresión real, destapada por la pasada
  en la máquina tras el paso 5): con firewall activo, una severidad INFO
  (puente virtual, hallazgos esperados) subía/bajaba fuera del enum y mataba
  el chequeo de red entero con `ValueError: -1 is not a valid Severidad`.

- Ejecución de binarios por **ruta absoluta** (`ss`, `systemctl`, `apt-get`, `ufw`,
  `firewall-cmd`): bajo sudo, el PATH heredado ya no decide qué binario corre como root.
- `systemctl is-active` con unidad inexistente (exit 4) ya no se interpreta como
  "firewall inactivo" (falsa ALTA en sistemas sin unidades del firewall).
- `ss`/`systemctl` que terminan con error y sin datos ya no se reportan como
  "no hay puertos"/"0 servicios" (falsos negativos).
- Sin root, el conteo de seguridad de apt usa las líneas `Inst` de la simulación
  (con `--print-uris` sin root no se emiten URIs `.deb`: el conteo antiguo daba 0).
- Escritura del reporte segura: no sigue symlinks, no sobrescribe (colisión →
  nombre con sufijo) y permisos 0600 forzados.
- `call_from_thread` en pantallas de chequeo: existía solo en `App`; ejecutar un
  chequeo desde su pantalla cerraba la app completa (crash al pulsar Enter).
- Carrera cancelar→reejecutar: los resultados obsoletos del worker cancelado ya no
  se publican sobre la ejecución nueva (token por ejecución).

## [0.2.0] — 2026-11-12

### Añadido
- Chequeo del estado real del firewall: activo vs instalado pero inactivo
  (UFW, firewalld, nftables, iptables) — "instalado pero no activo" es hallazgo ALTA.
- Priorización por **exposición real** de los puertos en escucha: FTP/Telnet siempre
  CRITICA; servicio conocido ALTA en todas las interfaces / MEDIA en una; puerto
  desconocido MEDIA / BAJA.
- Modo anonimizado del reporte (tecla `a`): kernel reducido, distro a versión mayor,
  CPU sin modelo, RAM por rangos y sin listas de usuarios/servicios.
- Navegación y acciones 100% accesibles con mouse: barra de navegación en todas
  las pantallas, tarjetas del inicio, botones de ejecutar/cancelar.
- Enmascarado de IPs concretas (`<ip>`) en el reporte, siempre.

### Corregido
- Parsers de gestores con `returncode` ignorado: un gestor que falla ya no se
  reporta como "sin actualizaciones".
