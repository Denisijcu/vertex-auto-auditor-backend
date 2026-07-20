"""
SecurityAgent v2.

Cambio clave: NO lee campos que el scraper no produce. Itera sobre los
Check reales y solo emite Finding cuando status == FAIL. Un check
NOT_ASSESSED no genera hallazgo NI puntua.
"""
from __future__ import annotations

from dataclasses import dataclass

from src.agents.base import ScanAgent
from src.schemas.finding import Confidence, Finding, Severity
from src.schemas.recon import CheckStatus, ReconResult


@dataclass(frozen=True)
class Rule:
    finding_id: str
    check_id: str
    title: str
    severity: Severity
    description: str
    remediation: str
    cwe: str | None = None
    owasp: str | None = None


SECURITY_RULES: tuple[Rule, ...] = (
    Rule(
        "VTX-TLS-001", "tls.certificate.valid",
        "Certificado TLS invalido o no confiable",
        Severity.CRITICAL,
        "La cadena de certificacion no valida contra las CA de confianza. El trafico "
        "es interceptable y los navegadores mostraran advertencia de seguridad.",
        "Reemitir el certificado con una CA reconocida e instalar la cadena intermedia completa.",
        cwe="CWE-295", owasp="A02:2021",
    ),
    Rule(
        "VTX-TLS-002", "tls.certificate.expiry",
        "Certificado TLS proximo a expirar",
        Severity.HIGH,
        "El certificado vence en menos de 30 dias. Al expirar, el sitio queda inaccesible "
        "con error de seguridad en todos los navegadores.",
        "Renovar el certificado y automatizar la renovacion (certbot / ACME).",
        cwe="CWE-324",
    ),
    Rule(
        "VTX-TLS-003", "tls.version.modern",
        "Version de TLS obsoleta negociada",
        Severity.HIGH,
        "El servidor acepta TLS 1.0/1.1, deprecados por RFC 8996 y vulnerables a "
        "ataques de downgrade.",
        "Deshabilitar TLS < 1.2 en la configuracion del servidor.",
        cwe="CWE-327", owasp="A02:2021",
    ),
    Rule(
        "VTX-HDR-001", "http.header.csp",
        "Content-Security-Policy ausente",
        Severity.MEDIUM,
        "Sin CSP no hay mitigacion en profundidad frente a XSS ni control sobre el "
        "origen de scripts cargados.",
        "Definir una CSP restrictiva partiendo de default-src 'self' en modo "
        "Report-Only antes de aplicarla en bloqueo.",
        cwe="CWE-693", owasp="A05:2021",
    ),
    Rule(
        "VTX-HDR-002", "http.header.hsts",
        "Strict-Transport-Security ausente",
        Severity.MEDIUM,
        "Sin HSTS la primera visita es degradable a HTTP, habilitando SSL stripping.",
        "Anadir: Strict-Transport-Security: max-age=31536000; includeSubDomains",
        cwe="CWE-319", owasp="A02:2021",
    ),
    Rule(
        "VTX-HDR-003", "http.header.xfo",
        "X-Frame-Options ausente",
        Severity.MEDIUM,
        "La pagina puede embeberse en un iframe de terceros, habilitando clickjacking.",
        "Anadir X-Frame-Options: DENY o la directiva frame-ancestors 'none' en la CSP.",
        cwe="CWE-1021", owasp="A05:2021",
    ),
    Rule(
        "VTX-HDR-004", "http.header.xcto",
        "X-Content-Type-Options ausente",
        Severity.LOW,
        "El navegador puede inferir el MIME type e interpretar como script contenido "
        "subido por usuarios.",
        "Anadir: X-Content-Type-Options: nosniff",
        cwe="CWE-430",
    ),
    Rule(
        "VTX-HDR-005", "http.header.referrer",
        "Referrer-Policy ausente",
        Severity.LOW,
        "Se pueden filtrar rutas internas y parametros a dominios de terceros.",
        "Anadir: Referrer-Policy: strict-origin-when-cross-origin",
        cwe="CWE-200",
    ),
    Rule(
        "VTX-HDR-006", "http.header.permissions",
        "Permissions-Policy ausente",
        Severity.LOW,
        "Sin restriccion explicita sobre camara, microfono y geolocalizacion para "
        "contenido embebido.",
        "Anadir: Permissions-Policy: geolocation=(), microphone=(), camera=()",
    ),
    Rule(
        "VTX-INF-001", "http.server_banner",
        "Version de software expuesta en cabecera Server",
        Severity.LOW,
        "El banner revela producto y version, facilitando la busqueda de exploits "
        "publicos conocidos.",
        "Ocultar la version (server_tokens off en nginx/openresty).",
        cwe="CWE-200",
    ),
    Rule(
        "VTX-INF-002", "http.redirect_https",
        "Sin redireccion permanente de HTTP a HTTPS",
        Severity.MEDIUM,
        "El contenido sigue sirviendose por HTTP en claro o sin redireccion 301/308.",
        "Configurar return 301 https://$host$request_uri en el bloque puerto 80.",
        cwe="CWE-319",
    ),
    Rule(
        "VTX-DNS-001", "dns.spf",
        "Politica SPF no publicada",
        Severity.MEDIUM,
        "Sin SPF, cualquiera puede falsificar correo saliente desde el dominio.",
        "Publicar un registro TXT: v=spf1 include:_spf.proveedor.com -all",
        cwe="CWE-290",
    ),
    Rule(
        "VTX-AVL-001", "http.reachable",
        "La raiz del dominio no responde correctamente",
        Severity.CRITICAL,
        "El servidor devuelve un codigo de error HTTP en la raiz del dominio. "
        "El sitio no esta disponible para visitantes ni para buscadores.",
        "Revisar la configuracion del hosting: publish directory, reglas de "
        "routing y estado del backend de origen.",
        cwe="CWE-1188",
    ),
    Rule(
        "VTX-CNT-001", "content.not_error_page",
        "El sitio sirve una pagina de error",
        Severity.CRITICAL,
        "El servidor responde 200 pero el documento entregado es una pagina de error "
        "de la plataforma de hosting, no el sitio real. Para un visitante el sitio "
        "esta caido, aunque el monitoreo por codigo HTTP no lo detecte.",
        "Revisar el publish directory y la configuracion de rutas del hosting. "
        "Verificar que index.html se sirva desde la raiz de publicacion.",
        cwe="CWE-1188",
    ),
    Rule(
        "VTX-CNT-002", "content.csp_self_block",
        "La CSP bloquea recursos del propio sitio",
        Severity.HIGH,
        "La politica declarada impide cargar scripts, hojas de estilo o fuentes que "
        "el propio documento referencia. El navegador los descarta en silencio: la "
        "pagina responde 200 y el fallo solo se ve en la consola del cliente.",
        "Anadir los origenes legitimos a la directiva correspondiente, o desplegar "
        "primero como Content-Security-Policy-Report-Only para recoger violaciones "
        "reales antes de bloquear.",
        cwe="CWE-693", owasp="A05:2021",
    ),
)


class SecurityAgent(ScanAgent):
    name = "Vertex Security Auditor"
    agent_type = "SECURITY_OSINT"
    check_prefixes = ("tls.", "http.", "dns.spf", "content.")

    async def analyze(self, recon: ReconResult) -> list[Finding]:
        findings: list[Finding] = []

        for rule in SECURITY_RULES:
            check = recon.get(rule.check_id)
            # Check inexistente o no evaluado -> silencio. No se inventa hallazgo.
            if check is None or check.status is not CheckStatus.FAIL:
                continue

            findings.append(Finding(
                id=rule.finding_id,
                check_id=rule.check_id,
                title=rule.title,
                severity=rule.severity,
                confidence=Confidence.CONFIRMED,
                asset=recon.target,
                description=rule.description,
                remediation=rule.remediation,
                evidence=check.evidence,  # lo observado, verificable por el cliente
                cwe=rule.cwe,
                owasp=rule.owasp,
                category="security",
            ))

        findings.sort(key=lambda f: list(Severity).index(f.severity))
        return findings