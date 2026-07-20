"""
Guard anti-SSRF.

Vertex Auto-Auditor recibe dominios de usuarios no confiables y hace peticiones
salientes. Sin este guard, `domain` = "169.254.169.254" o "evil.com@db" convierte
la plataforma en un proxy hacia la red interna.

Regla: se valida la IP RESUELTA, no el hostname. Y se revalida en cada redirect
para cortar DNS rebinding.
"""
from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
from urllib.parse import urlparse

# Hostname RFC-1123. Rechaza userinfo (@), puertos, paths, espacios.
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-zA-Z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[a-zA-Z0-9-]{1,63}(?<!-))+$"
)

# Metadata endpoints de cloud. Bloqueo explicito ademas del rango link-local.
_METADATA_HOSTS = {
    "169.254.169.254",
    "metadata.google.internal",
    "metadata.goog",
    "instance-data",
}

_BLOCKED_TLDS = {"local", "internal", "localhost", "home", "lan", "corp"}


class ScopeViolation(Exception):
    """El target esta fuera del alcance permitido. Nunca se ejecuta el request."""

    def __init__(self, target: str, reason: str):
        self.target = target
        self.reason = reason
        super().__init__(f"Target rechazado '{target}': {reason}")


def _is_forbidden_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str | None:
    # Orden importa: is_private es True tambien para loopback y link-local,
    # asi que los casos especificos se evaluan primero para dar un motivo util.
    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "link-local / metadata cloud"
    if ip.is_private:
        return "IP privada (RFC1918)"
    if ip.is_reserved:
        return "rango reservado"
    if ip.is_multicast:
        return "multicast"
    if ip.is_unspecified:
        return "direccion no especificada"
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        inner = _is_forbidden_ip(ip.ipv4_mapped)
        if inner:
            return f"IPv6-mapped -> {inner}"
    return None


def validate_hostname(domain: str) -> str:
    """Valida la forma del hostname. No hace red. Lanza ScopeViolation."""
    host = (domain or "").strip().lower().rstrip(".")

    if not host:
        raise ScopeViolation(domain, "vacio")
    if "@" in host or "/" in host or ":" in host or " " in host:
        raise ScopeViolation(domain, "contiene caracteres de URL (posible bypass de userinfo)")
    if host in _METADATA_HOSTS:
        raise ScopeViolation(domain, "endpoint de metadata cloud")
    if host.split(".")[-1] in _BLOCKED_TLDS:
        raise ScopeViolation(domain, "TLD de red interna")

    # Si es una IP literal, se valida directo
    try:
        ip = ipaddress.ip_address(host)
        if reason := _is_forbidden_ip(ip):
            raise ScopeViolation(domain, reason)
        return host
    except ValueError:
        pass

    if not _HOSTNAME_RE.match(host):
        raise ScopeViolation(domain, "hostname mal formado")
    return host


async def resolve_and_validate(domain: str) -> tuple[str, list[str]]:
    """
    Valida forma + resuelve DNS + valida TODAS las IPs devueltas.

    Returns: (hostname_normalizado, ips_validadas)
    Raises: ScopeViolation
    """
    host = validate_hostname(domain)

    try:
        ip_literal = ipaddress.ip_address(host)
        return host, [str(ip_literal)]
    except ValueError:
        pass

    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as e:
        raise ScopeViolation(domain, f"DNS no resuelve: {e}") from e

    ips = sorted({info[4][0] for info in infos})
    if not ips:
        raise ScopeViolation(domain, "DNS sin registros A/AAAA")

    for raw in ips:
        ip = ipaddress.ip_address(raw)
        if reason := _is_forbidden_ip(ip):
            # Basta que UNA resuelva a interna para rechazar todo el target
            raise ScopeViolation(domain, f"{raw} -> {reason}")

    return host, ips


async def validate_redirect(url: str) -> None:
    """Revalida cada hop de redirect. Corta DNS rebinding y redirect-to-internal."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ScopeViolation(url, f"esquema no permitido: {parsed.scheme}")
    if not parsed.hostname:
        raise ScopeViolation(url, "redirect sin hostname")
    await resolve_and_validate(parsed.hostname)