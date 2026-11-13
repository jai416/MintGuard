# Changelog

Formato basado en [Keep a Changelog](https://keepachangelog.com/); versionado SemVer.

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

## [Sin publicar]

### Añadido
- El firewall detectado ahora **pondera la severidad** de cada puerto expuesto:
  activo baja un nivel (piso BAJA), inactivo sube uno (techo ALTA), FTP/Telnet
  nunca cambia. El reporte declara la **nota de NAT** (un router delante no es
  visible desde la máquina).
- Verificación real de parsers en contenedores podman: `pacman -Qu` (Arch 7.1.0),
  `zypper lu` (openSUSE Tumbleweed 1.14.102), `dnf5 check-upgrade --security`
  (Fedora 45 / dnf5 5.4.7) — fixtures con las salidas reales capturadas.
- Conteo de seguridad en dnf5 vía `check-upgrade --security` (la columna repo
  siempre dice "updates", nunca "security").
- Aviso de caché de apt vieja sin root (índice con más de 7 días).
- Detección de bloques `Match` e `Include` externos en sshd_config (directivas
  condicionales que antes se leían como globales).

### Corregido
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
