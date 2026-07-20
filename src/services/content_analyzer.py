"""
Checks de contenido: lo que un escaner de cabeceras no ve.

Los tres casos reales que motivaron este modulo (vertexcoders.com, 2026-07-20):

  1. Netlify servia su pagina "Page not found" por un publish directory mal
     configurado. HTTP 200, TLS valido, las 5 cabeceras de seguridad presentes.
     Nuestro escaner: 100/100. securityheaders.com: grado A. El sitio: caido.

  2. CSP bloqueaba https://fonts.googleapis.com. El sitio cargaba sin su
     tipografia. Ningun check lo detecto.

  3. El endpoint /contact devolvia 504. Invisible para un escaneo de la home.

Regla de diseno: NO se usa `content.has_body`. Toda SPA (Angular, React, Vue)
sirve un <body> practicamente vacio y lo puebla con JS. Ese check daria falso
positivo en el 100% de los targets modernos.
"""
from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

from src.core.csp import CspPolicy, is_blocked
from src.schemas.recon import Check, CheckStatus

# --- Firmas de paginas de error servidas con 200 -----------------------------

# IMPORTANTE: cada patron debe describir un SEGMENTO COMPLETO del titulo, no un
# prefijo. Sin este anclaje, "Server Error Monitoring Tools" marcaba FAIL.
# El titulo se parte por | y - antes de evaluar, asi "404 | Vertex" si entra.
TITLE_ERROR_PATTERNS = (
    r"^page not found$",
    r"^not found$",
    r"^404( error)?$",
    r"^(error )?50[0-9]( error)?$",
    r"^site not found$",
    r"^application error$",
    r"^server error$",
    r"^internal server error$",
    r"^bad gateway$",
    r"^service unavailable$",
    r"^under construction$",
    r"^index of /.*$",
    r"^welcome to nginx!?$",
    r"^apache2? \w* ?default page$",
    r"^error$",
    # Codigo + frase en el mismo segmento: "502 Bad Gateway", "404 Not Found"
    r"^50[0-9] (bad gateway|service unavailable|gateway timeout|internal server error)$",
    r"^40[0-9] (not found|page not found|forbidden|unauthorized|bad request)$",
    r"^(bad gateway|service unavailable|gateway timeout) 50[0-9]$",
)

_TITLE_SPLIT_RE = re.compile(r"\s*[|\u2013\u2014·]\s*|\s+[-–—]\s+")


def _title_segments(title: str) -> list[str]:
    """Parte el titulo por separadores tipicos. '404 | Vertex Coders' -> ['404', 'Vertex Coders']"""
    return [s.strip().lower() for s in _TITLE_SPLIT_RE.split(title) if s.strip()]

# Frases especificas de proveedores. Alta confianza, cero ambiguedad.
BODY_ERROR_SIGNATURES = {
    "netlify": "looks like you've followed a broken link",
    "netlify-alt": '"page not found" support guide',
    "vercel": "deployment_not_found",
    "vercel-alt": "this deployment cannot be found",
    "cloudflare-522": "connection timed out</h1>",
    "cloudflare-523": "origin is unreachable",
    "github-pages": "there isn't a github pages site here",
    "heroku": "application error</h1>",
    "s3": "<code>nosuchbucket</code>",
    "nginx-default": "thank you for using nginx",
    "apache-default": "it works!</h1>",
    "iis": "iis windows server</title>",
}

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
_SCRIPT_RE = re.compile(r"<script\b[^>]*\bsrc\s*=\s*[\"']([^\"']+)[\"']", re.I)
_LINK_RE = re.compile(r"<link\b([^>]*)>", re.I)
_ATTR_RE = re.compile(r"(\w[\w-]*)\s*=\s*[\"']([^\"']*)[\"']")


def extract_title(html: str) -> str | None:
    m = _TITLE_RE.search(html)
    if not m:
        return None
    return re.sub(r"\s+", " ", m.group(1)).strip()


def extract_resources(html: str, base_url: str) -> list[tuple[str, str]]:
    """Devuelve [(directiva_csp, url_absoluta)] de los recursos del documento."""
    out: list[tuple[str, str]] = []

    for src in _SCRIPT_RE.findall(html):
        out.append(("script-src-elem", urljoin(base_url, src)))

    for attrs_raw in _LINK_RE.findall(html):
        attrs = {k.lower(): v for k, v in _ATTR_RE.findall(attrs_raw)}
        href = attrs.get("href")
        if not href:
            continue
        rel = (attrs.get("rel") or "").lower()
        as_ = (attrs.get("as") or "").lower()

        if "stylesheet" in rel:
            out.append(("style-src-elem", urljoin(base_url, href)))
        elif "manifest" in rel:
            out.append(("manifest-src", urljoin(base_url, href)))
        elif "preconnect" in rel or "dns-prefetch" in rel:
            continue  # no cargan recurso, no aplican a CSP
        elif "preload" in rel:
            directive = {
                "style": "style-src-elem",
                "script": "script-src-elem",
                "font": "font-src",
                "image": "img-src",
            }.get(as_)
            if directive:
                out.append((directive, urljoin(base_url, href)))

    # Deduplicar conservando orden
    seen: set[tuple[str, str]] = set()
    return [x for x in out if not (x in seen or seen.add(x))]


# --- Checks -----------------------------------------------------------------

# Cuerpos de error en texto plano (Netlify, ALB, algunos proxies).
# Se exigen cortos: un articulo largo puede contener la frase legitimamente.
PLAINTEXT_ERROR_PATTERNS = (
    r"^not found\b",
    r"^page not found\b",
    r"^site not found\b",
    r"^forbidden\b",
    r"^internal server error\b",
    r"^bad gateway\b",
    r"^service unavailable\b",
    r"^gateway time-?out\b",
    r"^\d{3} .{0,40}$",
)
PLAINTEXT_MAX_LEN = 500


def check_not_error_page(
    body: str, status_code: int, final_url: str, *, content_type: str = "text/html"
) -> Check:
    """Detecta paginas de error, tanto HTML de marca como cuerpos en texto plano.

    Cubre dos casos distintos observados en produccion:
      - HTML: Netlify sirviendo su pagina "Page not found" por publish dir mal
        configurado, con HTTP 200.
      - text/plain: Netlify devolviendo "Not Found - Request ID: ..." con 404
        para un subdominio inexistente.
    """
    is_html = "html" in (content_type or "").lower()

    if not is_html:
        stripped = body.strip()
        evidence: dict = {
            "content_type": content_type,
            "status_code": status_code,
            "final_url": final_url,
            "body_preview": stripped[:120],
            "body_length": len(stripped),
        }
        if not stripped:
            return Check(id="content.not_error_page",
                         title="El documento servido no es una pagina de error",
                         status=CheckStatus.NOT_ASSESSED,
                         error="cuerpo vacio", evidence=evidence)
        if len(stripped) <= PLAINTEXT_MAX_LEN:
            for pattern in PLAINTEXT_ERROR_PATTERNS:
                if re.match(pattern, stripped, re.I):
                    evidence["matched_plaintext_pattern"] = pattern
                    return Check(id="content.not_error_page",
                                 title="El documento servido no es una pagina de error",
                                 status=CheckStatus.FAIL, evidence=evidence)
        return Check(id="content.not_error_page",
                     title="El documento servido no es una pagina de error",
                     status=CheckStatus.NOT_ASSESSED,
                     error=f"la respuesta no es HTML (content-type: {content_type or 'ausente'})",
                     evidence=evidence)

    html = body
    title = extract_title(html)
    lowered = html.lower()
    evidence = {"title": title, "status_code": status_code, "final_url": final_url}

    for vendor, signature in BODY_ERROR_SIGNATURES.items():
        if signature in lowered:
            evidence["matched_signature"] = vendor
            return Check(
                id="content.not_error_page",
                title="El documento servido no es una pagina de error",
                status=CheckStatus.FAIL,
                evidence=evidence,
            )

    if title:
        for segment in _title_segments(title):
            for pattern in TITLE_ERROR_PATTERNS:
                if re.fullmatch(pattern, segment, re.I):
                    evidence["matched_title_segment"] = segment
                    evidence["matched_title_pattern"] = pattern
                    return Check(
                        id="content.not_error_page",
                        title="El documento servido no es una pagina de error",
                        status=CheckStatus.FAIL,
                        evidence=evidence,
                    )

    if title is None:
        # Sin <title> no se puede afirmar ni negar
        return Check(
            id="content.not_error_page",
            title="El documento servido no es una pagina de error",
            status=CheckStatus.NOT_ASSESSED,
            error="el documento no expone <title>",
            evidence=evidence,
        )

    return Check(
        id="content.not_error_page",
        title="El documento servido no es una pagina de error",
        status=CheckStatus.PASS,
        evidence=evidence,
    )


def check_csp_self_block(
    html: str, csp_header: str | None, final_url: str
) -> Check:
    """Detecta CSP que bloquea recursos declarados en el propio documento."""
    if not csp_header:
        return Check(
            id="content.csp_self_block",
            title="La CSP no bloquea recursos del propio sitio",
            status=CheckStatus.NOT_ASSESSED,
            error="no hay cabecera Content-Security-Policy que evaluar",
        )

    policy = CspPolicy.parse(csp_header)
    resources = extract_resources(html, final_url)

    if not resources:
        return Check(
            id="content.csp_self_block",
            title="La CSP no bloquea recursos del propio sitio",
            status=CheckStatus.NOT_ASSESSED,
            error="el documento no declara scripts ni hojas de estilo externas",
        )

    blocked = [
        {"directive": d, "url": u, "effective_sources": list(policy.effective_sources(d) or [])}
        for d, u in resources
        if is_blocked(policy, d, u, final_url)
    ]

    evidence = {
        "resources_checked": len(resources),
        "blocked_count": len(blocked),
        "blocked": blocked[:10],
    }

    return Check(
        id="content.csp_self_block",
        title="La CSP no bloquea recursos del propio sitio",
        status=CheckStatus.FAIL if blocked else CheckStatus.PASS,
        evidence=evidence,
    )