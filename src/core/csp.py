
"""
Parser de Content-Security-Policy y matching de origenes.

Motivacion: una CSP mal configurada bloquea recursos del PROPIO sitio. El
navegador lo reporta en consola, pero un escaneo HTTP normal ve un 200 limpio
con todas las cabeceras de seguridad presentes y da el sitio por sano.

Caso real (vertexcoders.com, 2026-07-20): CSP con `style-src 'self'
'unsafe-inline'` bloqueaba https://fonts.googleapis.com. El sitio cargaba sin
su tipografia. securityheaders.com dio grado A. Nuestro escaner dio 100/100.

Este modulo es deterministico: no necesita navegador ni headless.
"""
from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse

# Directiva efectiva -> directiva de la que hereda si no esta declarada.
# Fuente: CSP Level 3, seccion "Fetch Directives".
FALLBACK_CHAIN: dict[str, tuple[str, ...]] = {
    "script-src-elem": ("script-src", "default-src"),
    "script-src": ("default-src",),
    "style-src-elem": ("style-src", "default-src"),
    "style-src": ("default-src",),
    "img-src": ("default-src",),
    "font-src": ("default-src",),
    "connect-src": ("default-src",),
    "worker-src": ("script-src", "default-src"),
    "manifest-src": ("default-src",),
    "media-src": ("default-src",),
    "frame-src": ("child-src", "default-src"),
}


@dataclass(frozen=True)
class CspPolicy:
    directives: dict[str, tuple[str, ...]]

    @classmethod
    def parse(cls, header_value: str) -> "CspPolicy":
        out: dict[str, tuple[str, ...]] = {}
        for raw in header_value.split(";"):
            parts = raw.strip().split()
            if not parts:
                continue
            name = parts[0].lower()
            # Primera declaracion gana (comportamiento de navegador)
            out.setdefault(name, tuple(p for p in parts[1:]))
        return cls(directives=out)

    def effective_sources(self, directive: str) -> tuple[str, ...] | None:
        """Fuentes que aplican a una directiva, siguiendo la cadena de fallback.
        None = no hay politica aplicable (todo permitido)."""
        if directive in self.directives:
            return self.directives[directive]
        for parent in FALLBACK_CHAIN.get(directive, ()):
            if parent in self.directives:
                return self.directives[parent]
        return None


def _host_matches(pattern_host: str, host: str) -> bool:
    pattern_host = pattern_host.lower()
    host = host.lower()
    if pattern_host == host:
        return True
    if pattern_host.startswith("*."):
        return host.endswith(pattern_host[1:]) and host != pattern_host[2:]
    return False


def source_allows(source: str, url: str, page_origin: str) -> bool:
    """Evalua si UNA source-expression permite una URL concreta."""
    source = source.strip()
    low = source.lower()

    if low in ("'none'",):
        return False
    if low == "*":
        return True
    if low == "'self'":
        return urlparse(url).netloc.lower() == urlparse(page_origin).netloc.lower()
    # Keywords que no aplican a URLs externas (inline/eval/hashes/nonces)
    if low.startswith("'"):
        return False
    # scheme-source: "https:", "data:", "blob:"
    if low.endswith(":") and "//" not in low:
        return urlparse(url).scheme.lower() == low[:-1]

    parsed_src = urlparse(source if "//" in source else f"//{source}")
    parsed_url = urlparse(url)

    if parsed_src.scheme and parsed_src.scheme != parsed_url.scheme:
        return False

    src_host = parsed_src.hostname or ""
    if not src_host:
        return False
    if not _host_matches(src_host, parsed_url.hostname or ""):
        return False

    if parsed_src.port and parsed_src.port != (parsed_url.port or _default_port(parsed_url.scheme)):
        return False
    return True


def _default_port(scheme: str) -> int | None:
    return {"http": 80, "https": 443}.get(scheme.lower())


def is_blocked(policy: CspPolicy, directive: str, url: str, page_origin: str) -> bool:
    """True si la CSP bloquearia esta URL bajo esta directiva."""
    sources = policy.effective_sources(directive)
    if sources is None:
        return False  # sin politica aplicable
    if not sources:
        return True   # directiva declarada vacia = todo bloqueado
    return not any(source_allows(s, url, page_origin) for s in sources)