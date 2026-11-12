"""Network exposure check based on listening sockets."""

from __future__ import annotations

from mintguard.checks.firewall import comprobar_firewall
from mintguard.core.distro import DistroInfo
from mintguard.core.exposure import ListeningSocket, listening_sockets, service_name
from mintguard.core.prioritizer import Finding, Severidad

_CLIENT_UDP_PORTS = {68, 546}  # DHCP clients: normal traffic, not an entry point
_DISCOVERY_PORTS = {5353, 5355}  # mDNS / LLMNR

_SCOPE_TEXT = {
    "todas": "todas las interfaces (accesible desde la red)",
    "interfaz": "una interfaz concreta (accesible desde la red local)",
}
_SCOPE_RANK = {"todas": 2, "interfaz": 1}

_CRITICALLY_INSECURE_PORTS = {21, 23}  # FTP y Telnet


def severity_by_exposure(port: int, service_known: bool, scope: str) -> Severidad:
    """Severity of an exposed endpoint, weighted by real exposure.

    Exposure weighs more than the service name: a known service on one
    concrete interface (LAN) is a smaller risk than the same service on
    all interfaces, and an unknown port on an interface is barely a risk.
    Legacy always-critical services (FTP/Telnet) stay CRITICA anywhere.
    """
    if port in _CRITICALLY_INSECURE_PORTS:
        return Severidad.CRITICA
    if service_known:
        return Severidad.ALTA if scope == "todas" else Severidad.MEDIA
    return Severidad.MEDIA if scope == "todas" else Severidad.BAJA


def group_endpoints(sockets: list[ListeningSocket]) -> dict[tuple[str, int], dict]:
    """Group listening sockets by (protocol, port).

    Modern stacks list the same service once per address family and per
    interface; one finding per real service keeps the report readable,
    with every address kept as evidence.
    """
    groups: dict[tuple[str, int], dict] = {}
    for sock in sockets:
        key = (sock.protocol.lower(), sock.port)
        group = groups.setdefault(key, {"addresses": [], "processes": [], "scope": ""})
        if sock.address not in group["addresses"]:
            group["addresses"].append(sock.address)
        if sock.process and sock.process not in group["processes"]:
            group["processes"].append(sock.process)
        if _SCOPE_RANK.get(sock.scope, 0) > _SCOPE_RANK.get(group["scope"], 0):
            group["scope"] = sock.scope
    return groups


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
        elif sock.protocol == "udp" and sock.port in _CLIENT_UDP_PORTS:
            continue
        elif sock.port in _DISCOVERY_PORTS:
            discovery.append(f"{sock.protocol}/{sock.port}")
        else:
            exposed.append(sock)

    findings: list[Finding] = []
    for (protocol, port), group in group_endpoints(exposed).items():
        service = service_name(port, protocol)
        scope_text = _SCOPE_TEXT.get(group["scope"], group["scope"])
        process_text = f", proceso `{', '.join(group['processes'])}`" if group["processes"] else ""
        endpoints = [f"{protocol.upper()} {address}:{port}" for address in group["addresses"]]
        severity = severity_by_exposure(port, bool(service), group["scope"])
        title = f"Servicio {service} expuesto en la red" if service else "Puerto abierto en la red"
        findings.append(
            Finding(
                title=title,
                severity=severity,
                detail=f"{', '.join(endpoints)} escuchando en {scope_text}{process_text}.",
                suggestion=(
                    "Cierra el servicio si no lo usas o restringe el acceso con tu firewall "
                    "(UFW, firewalld o nftables)."
                ),
                evidence=endpoints,
                source="network",
            )
        )

    if discovery:
        findings.append(
            Finding(
                title="Servicios de descubrimiento en red activos",
                severity=Severidad.BAJA,
                detail=f"Descubrimiento local activo: {', '.join(sorted(set(discovery)))} (mDNS/LLMNR).",
                suggestion="Desactívalos si no los necesitas; pueden filtrar nombres de equipo.",
                source="network",
            )
        )

    if local_sockets:
        summary = ", ".join(sorted({f"{s.protocol}/{s.port}" for s in local_sockets}))
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

    # Firewall state belongs to the exposure story of the "Red" screen.
    findings += comprobar_firewall(distro)
    return findings
