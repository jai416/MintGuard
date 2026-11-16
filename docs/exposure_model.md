# El modelo de exposición de MintGuard

La mayoría de herramientas listan puertos en escucha y dicen "abierto". Eso deja dos
preguntas sin respuesta: **¿alguien puede llegar de verdad hasta aquí?** y **¿esto es
normal en mi sistema?**. Un informe que grita ALTA por Tailscale, por el DHCP de las
máquinas virtuales y por el servidor que sí tenías que tener abierto acaba entrenando
al usuario a ignorar el ALTA de verdad.

MintGuard pondera cada puerto en escucha con **cuatro dimensiones**. Este documento
explica qué miran, sus matrices y sus límites declarados.

Las cuatro preguntas que responde el modelo:

1. ¿El servicio escucha para **todas las interfaces**, para una concreta, o solo en
   localhost?
2. ¿El firewall está **activo de verdad** o solo instalado?
3. ¿Es un servicio **esperado en su contexto** (Tailscale, libvirt, avahi…) o inesperado?
4. ¿Qué **es** la interfaz donde escucha: pública, LAN, CGNAT, loopback, enlace local o
   bridge virtual?

---

## 1. Alcance del bind (`core/exposure.py::classify_address`)

Cada socket que reporta `ss` se clasifica por su dirección de bind:

| Dirección | Clasificación |
| --- | --- |
| `0.0.0.0`, `::`, `*` | `todas` |
| IP concreta (`192.168.122.1`) | `interfaz` |
| Wildcard atado a un dispositivo (`0.0.0.0%virbr0`) | `interfaz` — **solo esa interfaz**, no "todas" |
| `127.0.0.0/8`, `::1` | `local` (INFO: correcto) |

El matiz del wildcard con zona importa: `0.0.0.0%virbr0` no expone a la LAN real; expone
al bridge virtual.

Los clientes DHCP (68/546 udp) se ignoran — son clientes, no exposición. mDNS/LLMNR
(5353/5355) se agrupan en un único hallazgo BAJA de "descubrimiento".

**Un hallazgo por servicio real**: los sockets se agrupan por (protocolo, puerto); las
direcciones de cada familia quedan como evidencia. Un servidor con IPv4 e IPv6 no genera
dos alarmas.

## 2. Severidad base por exposición (`checks/network.py::severity_by_exposure`)

| Servicio | `todas` | `interfaz` |
| --- | --- | --- |
| FTP / Telnet (21/23) | CRITICA | CRITICA |
| Servicio conocido (22, 80, 445…) | ALTA | MEDIA |
| Puerto desconocido | MEDIA | BAJA |

La exposición pesa más que el nombre del servicio: lo que decide no es *qué* es sino
*quién puede llegar*.

## 3. El firewall real (`checks/firewall.py`)

"Tenemos ufw instalado" no es lo mismo que "estamos filtrando". El chequeo pregunta el
estado real: `systemctl is-active` (sin root) de ufw/firewalld/nftables/
netfilter-persistent/iptables, `ufw status` como autoridad cuando hay root y
`firewall-cmd --state` para firewalld.

- **Instalado pero inactivo** → hallazgo ALTA: lo que escuche queda expuesto.
- **Ninguno detectado** → MEDIA.
- **El exit code manda, no el texto**: `systemctl is-active <unidad-inexistente>`
  imprime "inactive" con código 4; si no hay ninguna unidad, el estado es
  "desconocido", nunca "inactive" (esa falsa ALTA se verificó en una máquina real).

Con ese estado se pondera cada puerto (`severity_with_firewall`): el firewall **activo
baja un nivel** (piso BAJA) y el **inactivo sube uno** (techo ALTA); el estado
desconocido no altera. CRITICA e INFO nunca se mueven: FTP/Telnet es grave siempre, e
INFO marca "esperado/correcto", no un veredicto del firewall. El texto del hallazgo
explica el cambio ("Sin firewall activo: la exposición es directa." / "El firewall
activo reduce el riesgo.").

El estado se consulta **una vez por chequeo** y se reutiliza (también para el hallazgo
del propio firewall).

## 4. Servicio esperado en su contexto (`core/expected_services.py::classify`)

Un sistema con Tailscale, libvirt o avahi *tiene* puertos en escucha que son así **por
diseño**. `classify(process, address, port, protocol)` etiqueta esos casos:

| Regla | Etiqueta |
| --- | --- |
| `tailscaled` en su interfaz/overlay (`%tailscale*` o IP en 100.64.0.0/10) | `tailscale` → INFO "puerto operativo de Tailscale" |
| UDP 41641 en cualquier dirección (DISCO/handshake, escucha en 0.0.0.0 por diseño) | `tailscale` → INFO |
| `dnsmasq` en 192.168.122.0/24 o en bridge virtual (`%virbr*`, `%docker*`) | `libvirt` → INFO "DHCP/DNS para VMs; no accesible desde la LAN real" |
| `avahi-daemon` en UDP efímero (≥ 32768) | `avahi` → se pliega en el hallazgo BAJA de descubrimiento (mismo servicio mDNS, no puertos nuevos) |

Reglas finas que evitan que la etiqueta esconda exposición:

- **La señal es el proceso**: un `sshd` atado a tailscale0 conserva su severidad — es
  una decisión de alguien, no el funcionamiento de Tailscale.
- **Un grupo solo cuenta como esperado si TODOS sus miembros comparten etiqueta**:
  nginx y tailscaled en el mismo puerto = grupo mixto → severidad normal y toda la
  evidencia visible.
- Un `dnsmasq` en la LAN real no se etiqueta.
- El proceso `systemd` dueño de un puerto conocido se anota como "socket-activado;
  probablemente {servicio}" (socket activation de systemd; "systemd" solo confunde).

### La etiqueta se tiene que poder probar (`context_is_authentic`)

El nombre del proceso **no es prueba**: cualquier usuario puede renombrar el suyo
con `prctl(PR_SET_NAME)`, y un proceso llamado `dnsmasq` se libraría de la
exposición real. Por eso la etiqueta solo sobrevive si el binario real la respalda:

- Con `sudo` (donde `ss -p` muestra el pid), `/proc/<pid>/exe` debe ser el demonio
  de la etiqueta (`tailscaled`, `dnsmasq`, `avahi-daemon`). Si no lo es → **la
  etiqueta cae** (fail closed): el puerto vuelve a su severidad normal.
- Sin `sudo` no se ven los procesos de otros usuarios: nada contradice la regla
  del puerto 41641, que se mantiene, y **el hallazgo lo dice** ("aquí no se ha
  podido comprobar qué programa escucha").
- Un proceso que desaparece entre la lectura de `ss` y la verificación también
  pierde la etiqueta (su socket está obsoleto).

Añadir un contexto nuevo (snap, KVM, podman…) es un `if` más en `classify()`, no un
refactor del chequeo de red.

## 4bis. Confianza y señales (`core/confidence.py`)

La severidad dice **cuánto** pesa un hallazgo; la confianza dice **cuán segura** es esa
lectura. No son dos cuentas: las señales que la confianza resume son **las mismas
entradas que la severidad ya usó** (la naturaleza de la interfaz, el contexto esperado,
el estado del firewall, el binario verificado en `/proc`), así que no pueden
contradecirse.

| Señales | Confianza | Se muestra como |
| --- | --- | --- |
| solo a favor | **Alta** | normal: el hallazgo se sostiene entero |
| a favor y en contra | **Media** | "revisar": la severidad es defendible, con matiz |
| solo en contra | **Baja** | "puede ser un falso positivo" |
| ninguna | — | no se inventa una confianza |

Ejemplo real (el chequeo de IOMMU):

- **A favor**: "El kernel expone IOMMU." · "No hay ningún dominio IOMMU configurado."
- **En contra**: "Es normal en un equipo sin virtualización ni dispositivos PCIe con
  acceso directo a memoria."

→ `MEDIA · Confianza: Media (2 a favor, 1 en contra)`.

Dos reglas que no se negocian:

- **Una confianza baja no esconde el hallazgo.** Ocultar un hallazgo por "dudoso" es un
  falso negativo, que es el peor fallo posible de esta herramienta. Se marca, no se
  esconde.
- **Las señales son texto genérico** (no llevan cuentas ni rutas), así que se muestran
  también en modo anonimizado; la evidencia sigue las reglas de privacidad de siempre.

Coste: **cero**. Las señales no hacen ninguna comprobación nueva: son las razones que
el chequeo ya tenía delante al decidir la severidad.

## 5. Naturaleza de la interfaz (`core/exposure.py::interface_nature`)

La cuarta dimensión separa "dirección de bind" de "exposición real": ¿qué es la interfaz
donde se escucha? Se deduce de la zona (`%virbr*`, `%docker*`, `%br-*` → virtual) y de
la IP concreta del bind:

| Naturaleza | Severidad (conocido / desconocido) | Texto del hallazgo |
| --- | --- | --- |
| `public` | ALTA / MEDIA | "una IP pública (accesible desde internet)" |
| `lan` / `unknown` | matriz base (ALTA/MEDIA · MEDIA/BAJA) | — |
| `cgnat` (100.64.0.0/10, p. ej. mesh) | MEDIA / BAJA | "una red mesh/overlay (no enrutable desde internet)" |
| `link-local` | BAJA | "el enlace local (no pasa del segmento de red)" |
| `virtual` (bridges) | INFO | "el bridge virtual (solo VMs/contenedores, no la LAN real)" |
| loopback | — (ya es `local` en la dimensión 1) | — |

Detalles que importan:

- **100.64.0.0/10 se comprueba ANTES del bucket LAN**: Python también la marca
  `is_private`, y un overlay mesh no es tu LAN.
- **Grupos mixtos: manda la naturaleza MÁS expuesta** (`worst_nature`), y "unknown" >
  "public" a propósito — un wildcard (0.0.0.0/::) expone por todas las interfaces,
  incluida una pública; mezclar nunca suaviza el veredicto.

## Límites declarados (honestidad de alcance)

- **NAT perimetral**: no es detectable desde la máquina. El reporte y el hint de la
  pantalla Red lo dicen explícitamente y asumen "posible": ese `0.0.0.0` puede estar
  detrás de un router.
- **Wildcard sin zona** (0.0.0.0/::) queda como `unknown` — juzgarlo exige ver las demás
  direcciones de la máquina (v1.1, con `ip addr`).
- **IP privada de bridge sin zona** (`172.17.0.1` sin `%docker0`) se ve como LAN, no
  como virtual.
- **Snapshot, no monitorización**: cada chequeo es una foto del momento; nada corre en
  segundo plano.

## El caso real que lo motivó

Máquina del review (Linux Mint 22.3, apt, 2026-11-14):

- **Antes**: 11 hallazgos ALTA, 7 de ellos ruido normal (Tailscale + libvirt + avahi).
- **Después**: 1 ALTA accionable (43 actualizaciones, 26 de seguridad estimadas), 3
  MEDIA (lighttpd y sshd expuestos, con el firewall recién activado bajando un nivel),
  9 BAJA y 9 INFO.
- El reporte anterior marcó el firewall inactivo; el usuario activó UFW y los servicios
  expuestos **bajaron solos** — la ponderación del firewall haciendo su trabajo.

## Cómo se prueba

- `tests/test_exposure.py`: parser de `ss` moderno y antiguo (el bug original era un
  falso negativo real: "no hay puertos" en una máquina con puertos abiertos) y
  `interface_nature` caso a caso.
- `tests/test_expected_services.py`: las reglas de contexto con direcciones reales de
  `ss`.
- `tests/test_network_grouping.py`: agrupación por servicio, matriz del firewall
  (incluida la regresión del INFO con firewall activo) y la integración completa con el
  escenario de la máquina del review.
- `tools/verify_distro.py`: los mismos comandos que ejecuta MintGuard, pasados por sus
  parsers con **salida real** en contenedores podman (Arch, openSUSE, Fedora).
