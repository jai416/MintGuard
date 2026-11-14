"""Network exposure check based on listening sockets."""

from __future__ import annotations

from mintguard.checks.firewall import comprobar_firewall, firewall_state
from mintguard.core.distro import DistroInfo
from mintguard.core.expected_services import classify, context_is_authentic
from mintguard.core.exposure import (
    ListeningSocket,
    listening_sockets,
    service_name,
    socket_nature,
    worst_nature,
)
from mintguard.core.prioritizer import Finding, Severidad
from mintguard.core.text import sanitize

_CLIENT_UDP_PORTS = {68, 546}  # DHCP clients: normal traffic, not an entry point
_DISCOVERY_PORTS = {5353, 5355}  # mDNS / LLMNR
# Cap of detailed exposure findings per check: a process can open as many
# sockets as it wants and the report has to stay readable.
_MAX_EXPOSED_FINDINGS = 50

_SCOPE_TEXT = {
    "todas": "todas las interfaces (accesible desde la red)",
    "interfaz": "una interfaz concreta (accesible desde la red local)",
}
_SCOPE_RANK = {"todas": 2, "interfaz": 1}

# When the interface's nature is known, it replaces the scope text: it is
# the honest description of what can actually reach the listener.
_NATURE_SCOPE_TEXT = {
    "public": "una IP pública (accesible desde internet)",
    "cgnat": "una red mesh/overlay (no enrutable desde internet)",
    "link-local": "el enlace local (no pasa del segmento de red)",
    "virtual": "el bridge virtual (solo VMs/contenedores, no la LAN real)",
}

_CRITICALLY_INSECURE_PORTS = {21, 23}  # FTP y Telnet


def _normalize_protocol(protocol: str) -> str:
    """tcp6/udp6 (old ss output) are the same real service as tcp/udp."""
    return protocol.rstrip("0123456789").lower()


def severity_by_exposure(
    port: int, service_known: bool, scope: str, nature: str = "unknown"
) -> Severidad:
    """Severity of an exposed endpoint, weighted by real exposure.

    Exposure weighs more than the service name: a known service on one
    concrete interface (LAN) is a smaller risk than the same service on
    all interfaces, and an unknown port on an interface is barely a risk.
    Legacy always-critical services (FTP/Telnet) stay CRITICA anywhere.

    `nature` is the interface's nature (interface_nature): it can only
    raise or lower the interface-level cases —
    - public: a concrete public IP is effectively internet-exposed,
      same as "todas" for known services;
    - virtual (virbr/docker): serves VMs/containers only → INFO;
    - cgnat (mesh overlay, e.g. Tailscale without its daemon tag):
      not internet-routable, treated like a LAN interface;
    - link-local: not routable beyond the link → BAJA;
    - unknown/lan: the original matrix (a plain wildcard stays there
      until the machine's own addresses can be seen, v1.1).
    """
    if port in _CRITICALLY_INSECURE_PORTS:
        return Severidad.CRITICA
    if nature == "virtual":
        return Severidad.INFO
    if nature == "link-local":
        return Severidad.BAJA
    if nature == "public":
        return Severidad.ALTA if service_known else Severidad.MEDIA
    if nature == "cgnat":
        return Severidad.MEDIA if service_known else Severidad.BAJA
    if service_known:
        return Severidad.ALTA if scope == "todas" else Severidad.MEDIA
    return Severidad.MEDIA if scope == "todas" else Severidad.BAJA


def severity_with_firewall(severity: Severidad, state: str) -> Severidad:
    """Weight an exposed endpoint's severity by the real firewall state.

    FTP/Telnet (CRITICA) never changes; an
    active firewall lowers one level with BAJA as floor; an inactive
    one raises one with ALTA as ceiling; unknown state changes nothing.
    INFO is immovable in every state: it marks "expected/correct", not
    a firewall verdict, and lowering it would underflow the enum (real
    ValueError seen with an active firewall on a docker bridge).
    """
    if severity in (Severidad.INFO, Severidad.CRITICA):
        return severity
    if state == "active" and severity != Severidad.BAJA:
        return Severidad(int(severity) - 1)
    if state == "inactive" and severity != Severidad.ALTA:
        return Severidad(int(severity) + 1)
    return severity


def group_endpoints(sockets: list[ListeningSocket]) -> dict[tuple[str, int], dict]:
    """Group listening sockets by (protocol, port).

    Modern stacks list the same service once per address family and per
    interface; one finding per real service keeps the report readable,
    with every address kept as evidence. Each socket's expected-services
    context (classify) is kept per group: a group only counts as
    expected when EVERY member shares the same tag — a mixed group
    (nginx and tailscaled on the same port) stays fully visible with
    its normal severity.
    """
    groups: dict[tuple[str, int], dict] = {}
    for sock in sockets:
        key = (_normalize_protocol(sock.protocol), sock.port)
        group = groups.setdefault(
            key,
            {
                "addresses": [],
                "processes": [],
                "scope": "",
                "contexts": [],
                "natures": [],
            },
        )
        if sock.address not in group["addresses"]:
            group["addresses"].append(sock.address)
        if sock.process and sock.process not in group["processes"]:
            # The process name comes from the system: it can carry escape
            # sequences and it lands in the report and in the UI.
            group["processes"].append(sanitize(sock.process))
        if _SCOPE_RANK.get(sock.scope, 0) > _SCOPE_RANK.get(group["scope"], 0):
            group["scope"] = sock.scope
        # The tag only survives if the real binary behind the pid backs
        # it: the process name can be faked by any local user.
        context = classify(sock.process, sock.address, sock.port, sock.protocol)
        if not context_is_authentic(sock.process, sock.pid, context):
            context = None
        group["contexts"].append(context)
        group["natures"].append(socket_nature(sock.address))
    return groups


def _group_context(group: dict) -> str | None:
    """The group's expected-services tag, only when uniform across members."""
    contexts = set(group["contexts"])
    if len(contexts) == 1:
        return next(iter(contexts))
    return None


# Text for expected-in-context listeners (INFO): the point is to say WHY
# it is expected, so the user learns the difference between "normal for
# this system" and "unexpected on this interface".
_EXPECTED_FINDINGS = {
    "tailscale": {
        "title": "Puerto operativo de Tailscale (esperado)",
        "detail": (
            "Tailscale funciona así: el tráfico viaja cifrado por la red mesh "
            "(100.64.0.0/10), no por la LAN ni por internet."
        ),
        "suggestion": (
            "Correcto si usas Tailscale. Si no lo esperabas, revisa `tailscale status`."
        ),
    },
    "libvirt": {
        "title": "Red virtual de libvirt en escucha (esperado)",
        "detail": (
            "DHCP/DNS de libvirt para las máquinas virtuales: solo accesible desde "
            "el bridge virtual, no desde la LAN real."
        ),
        "suggestion": "Correcto si usas máquinas virtuales con libvirt.",
    },
}


def _expected_finding(context: str, group: dict, endpoints: list[str]) -> Finding:
    text = _EXPECTED_FINDINGS[context]
    scope_text = _SCOPE_TEXT.get(group["scope"], group["scope"])
    process_text = f", proceso `{', '.join(group['processes'])}`" if group["processes"] else ""
    # Without root `ss` shows no processes: the tag could not be checked
    # against the real binary, and the finding must say so out loud.
    unverified = (
        ""
        if group["processes"]
        else (
            " Sin sudo no se ven los procesos de otros usuarios: aquí no se ha "
            "podido comprobar qué programa escucha."
        )
    )
    return Finding(
        title=text["title"],
        severity=Severidad.INFO,
        detail=(
            f"{', '.join(endpoints)} escuchando en {scope_text}{process_text}. "
            f"{text['detail']}{unverified}"
        ),
        suggestion=text["suggestion"],
        evidence=endpoints,
        source="network",
    )


def comprobar_red(distro: DistroInfo) -> list[Finding]:
    sockets, error = listening_sockets()
    if error:
        return [
            Finding(
                title="No se pudo inspeccionar la red",
                severity=Severidad.BAJA,
                detail=error,
                suggestion="Instala el paquete `iproute2` (comando `ss`) y vuelve a intentarlo.",
                source="network",
            )
        ]

    discovery: list[str] = []
    local_sockets: list[ListeningSocket] = []
    exposed: list[ListeningSocket] = []
    for sock in sockets:
        if sock.scope == "local":
            local_sockets.append(sock)
        elif _normalize_protocol(sock.protocol) == "udp" and sock.port in _CLIENT_UDP_PORTS:
            continue
        elif sock.port in _DISCOVERY_PORTS:
            discovery.append(f"{_normalize_protocol(sock.protocol)}/{sock.port}")
        else:
            exposed.append(sock)

    # One firewall consultation for the whole check: it weights the
    # exposed endpoints (below) and feeds its own finding (below).
    firewall_estado = firewall_state(distro)

    findings: list[Finding] = []
    avahi_ephemeral: list[str] = []
    detailed = 0
    omitted = 0
    for (protocol, port), group in group_endpoints(exposed).items():
        service = service_name(port, protocol)
        nature = worst_nature(group["natures"])
        scope_text = _NATURE_SCOPE_TEXT.get(nature) or _SCOPE_TEXT.get(
            group["scope"], group["scope"]
        )
        process_text = f", proceso `{', '.join(group['processes'])}`" if group["processes"] else ""
        endpoints = [f"{protocol.upper()} {address}:{port}" for address in group["addresses"]]

        # Expected in its context: not new exposure. avahi's ephemeral
        # sockets fold into the discovery finding; tailscale/libvirt get
        # their own INFO finding explaining why they are normal.
        context = _group_context(group)
        if context == "avahi":
            avahi_ephemeral.extend(endpoints)
            continue
        if context in _EXPECTED_FINDINGS:
            findings.append(_expected_finding(context, group, endpoints))
            continue

        # A process can open as many sockets as it wants: the report
        # would become unreadable noise. The rest is counted, not hidden.
        if detailed >= _MAX_EXPOSED_FINDINGS:
            omitted += 1
            continue
        detailed += 1

        severity = severity_by_exposure(port, bool(service), group["scope"], nature)
        weighted = severity_with_firewall(severity, firewall_estado)
        if weighted != severity:
            note = (
                " Sin firewall activo: la exposición es directa."
                if firewall_estado == "inactive"
                else " El firewall activo reduce el riesgo."
            )
        else:
            note = ""
        # `systemd` as the process of e.g. port 22 means systemd socket
        # activation (ss -p shows pid 1): say it, "systemd" alone confuses.
        if group["processes"] == ["systemd"]:
            guess = f"; probablemente {service.lower()}" if service else ""
            process_text = f", proceso `systemd` (socket-activado{guess})"
        title = f"Servicio {service} expuesto en la red" if service else "Puerto abierto en la red"
        findings.append(
            Finding(
                title=title,
                severity=weighted,
                detail=f"{', '.join(endpoints)} escuchando en {scope_text}{process_text}.{note}",
                suggestion=(
                    "Cierra el servicio si no lo usas o restringe el acceso con tu firewall "
                    "(UFW, firewalld o nftables)."
                ),
                evidence=endpoints,
                source="network",
            )
        )

    if omitted:
        findings.append(
            Finding(
                title=f"{omitted} puerto(s) expuesto(s) más no se detallan",
                severity=Severidad.BAJA,
                detail=(
                    f"El chequeo detalla como máximo {_MAX_EXPOSED_FINDINGS} puertos "
                    f"expuestos; hay {omitted} más que revisar a mano."
                ),
                suggestion="Míralos con `ss -tuln` para ver quién los escucha.",
                source="network",
            )
        )

    if discovery or avahi_ephemeral:
        bits: list[str] = []
        if discovery:
            bits.append(
                f"descubrimiento local activo: {', '.join(sorted(set(discovery)))} (mDNS/LLMNR)"
            )
        if avahi_ephemeral:
            bits.append(
                "avahi-daemon responde mDNS desde puertos UDP efímeros ("
                + ", ".join(avahi_ephemeral)
                + "): el mismo servicio, no puertos nuevos"
            )
        findings.append(
            Finding(
                title="Servicios de descubrimiento en red activos",
                severity=Severidad.BAJA,
                detail="; ".join(bits) + ".",
                suggestion="Desactívalos si no los necesitas; pueden filtrar nombres de equipo.",
                evidence=avahi_ephemeral or sorted(set(discovery)),
                source="network",
            )
        )

    if local_sockets:
        summary = ", ".join(sorted({_normalize_protocol(s.protocol) + f"/{s.port}" for s in local_sockets}))
        findings.append(
            Finding(
                title="Servicios escuchando solo en localhost",
                severity=Severidad.INFO,
                detail=f"{len(local_sockets)} socket(s): {summary}.",
                suggestion="Correcto: no son accesibles desde la red.",
                source="network",
            )
        )

    if not findings:
        findings.append(
            Finding(
                title="No hay puertos en escucha",
                severity=Severidad.INFO,
                detail="No se detectaron servicios escuchando en el sistema.",
                source="network",
            )
        )

    # Firewall state belongs to the exposure story of the "Red" screen;
    # reuse the state already computed above (no second consultation).
    findings += comprobar_firewall(distro, estado=firewall_estado)
    return findings
