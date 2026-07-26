"""
ScraperService v2.

Cambios frente a v1:
  - Devuelve ReconResult tipado, no un dict con llaves fantasma.
  - Valida SSL de verdad (cadena, expiracion, hostname). Antes se asumia True.
  - Mide load_time_ms de verdad. Antes se asumia 1200.
  - Guard anti-SSRF antes de cualquier request y en cada redirect.
  - Todo fallo produce NOT_ASSESSED con motivo, nunca un default optimista.
  - User-Agent honesto: somos una empresa de auditoria, no evadimos deteccion.
  - Los checks que dependen de controlar la zona DNS no se evaluan en hosting
    compartido: el titular no puede corregirlos.
"""
from __future__ import annotations

import asyncio
import logging
import ssl
import time
from datetime import datetime, timezone

import dns.asyncresolver
import httpx

from src.core.hosting import shared_hosting_suffix, zone_not_controllable_reason
from src.core.target_guard import ScopeViolation, resolve_and_validate, validate_redirect
from src.services.content_analyzer import check_csp_self_block, check_not_error_page
from src.schemas.recon import Check, CheckStatus, ReconResult

logger = logging.getLogger("vertex.scraper")

SECURITY_HEADERS = {
    "content-security-policy": "http.header.csp",
    "strict-transport-security": "http.header.hsts",
    "x-frame-options": "http.header.xfo",
    "x-content-type-options": "http.header.xcto",
    "referrer-policy": "http.header.referrer",
    "permissions-policy": "http.header.permissions",
}

DNS_RECORD_TYPES = ("A", "AAAA", "MX", "TXT", "NS")

USER_AGENT = (
    "VertexAutoAuditor/0.2 (+https://vertexcoders.com/auditor; "
    "auditoria pasiva de superficie publica; contacto: abuse@vertexcoders.com)"
)

# Umbral de rendimiento documentado, no un numero magico suelto
LOAD_TIME_BUDGET_MS = 2500


class ScraperService:
    def __init__(self, *, timeout: float = 10.0, connect_timeout: float = 5.0):
        self.timeout = httpx.Timeout(timeout, connect=connect_timeout)
        self.headers = {"User-Agent": USER_AGENT, "Accept": "*/*"}

    # ------------------------------------------------------------------ DNS

    async def _check_dns(self, host: str) -> list[Check]:
        checks: list[Check] = []
        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = 5.0

        for rtype in DNS_RECORD_TYPES:
            cid = f"dns.{rtype.lower()}"
            try:
                answers = await resolver.resolve(host, rtype)
                values = sorted(str(r) for r in answers)
                checks.append(Check(
                    id=cid,
                    title=f"Registro DNS {rtype}",
                    status=CheckStatus.PASS,
                    evidence={"records": values, "count": len(values)},
                    source="dns",
                ))
            except dns.resolver.NoAnswer:
                # Ausencia confirmada: SI es un dato medido
                checks.append(Check(
                    id=cid,
                    title=f"Registro DNS {rtype}",
                    status=CheckStatus.PASS,
                    evidence={"records": [], "count": 0, "note": "sin registros de este tipo"},
                    source="dns",
                ))
            except Exception as e:
                # No se pudo determinar: NOT_ASSESSED, no se inventa nada
                checks.append(Check(
                    id=cid,
                    title=f"Registro DNS {rtype}",
                    status=CheckStatus.NOT_ASSESSED,
                    error=f"{type(e).__name__}: {e}",
                    source="dns",
                ))

        # SPF derivado de TXT, solo si TXT se pudo leer.
        #
        # En hosting compartido (algo.netlify.app, algo.hf.space...) el titular
        # NO controla la zona DNS del sufijo. Reportarle "SPF no publicada" es
        # tecnicamente cierto e inaccionable: no puede publicar ese registro
        # aunque quiera. Un hallazgo que el cliente no puede corregir baja el
        # score sin motivo y resta credibilidad a los que si son accionables.
        #
        # Se aplica el principio del motor: no se puede medir != esta mal.
        shared = shared_hosting_suffix(host)
        txt = next((c for c in checks if c.id == "dns.txt"), None)

        if shared:
            checks.append(Check(
                id="dns.spf",
                title="Politica SPF publicada",
                status=CheckStatus.NOT_ASSESSED,
                error=zone_not_controllable_reason(shared),
                evidence={"shared_hosting_suffix": shared},
                source="dns",
            ))
        elif txt and txt.assessed:
            records = [r.lower() for r in txt.evidence.get("records", [])]
            has_spf = any("v=spf1" in r for r in records)
            checks.append(Check(
                id="dns.spf",
                title="Politica SPF publicada",
                status=CheckStatus.PASS if has_spf else CheckStatus.FAIL,
                evidence={"found": has_spf, "source_records": records[:5]},
                source="dns",
            ))
        else:
            checks.append(Check(
                id="dns.spf",
                title="Politica SPF publicada",
                status=CheckStatus.NOT_ASSESSED,
                error="registros TXT no disponibles",
                source="dns",
            ))
        return checks

    # ------------------------------------------------------------------ TLS

    async def _check_tls(self, host: str, port: int = 443) -> list[Check]:
        """Handshake TLS real. Valida cadena, hostname y expiracion."""
        cid_valid, cid_exp = "tls.certificate.valid", "tls.certificate.expiry"
        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ctx, server_hostname=host),
                timeout=8.0,
            )
        except ssl.SSLCertVerificationError as e:
            fail = Check(
                id=cid_valid,
                title="Certificado TLS valido y de confianza",
                status=CheckStatus.FAIL,
                evidence={"verify_error": str(e.verify_message or e), "code": e.verify_code},
                source="tls",
            )
            return [fail, Check(
                id=cid_exp, title="Certificado TLS vigente",
                status=CheckStatus.NOT_ASSESSED,
                error="no se pudo verificar la cadena, expiracion no evaluable",
                source="tls",
            )]
        except Exception as e:
            err = f"{type(e).__name__}: {e}"
            return [
                Check(id=cid_valid, title="Certificado TLS valido y de confianza",
                      status=CheckStatus.NOT_ASSESSED, error=err, source="tls"),
                Check(id=cid_exp, title="Certificado TLS vigente",
                      status=CheckStatus.NOT_ASSESSED, error=err, source="tls"),
            ]

        try:
            sslobj = writer.get_extra_info("ssl_object")
            cert = sslobj.getpeercert() or {}
            version = sslobj.version()
            cipher = sslobj.cipher()
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

        checks = [Check(
            id=cid_valid,
            title="Certificado TLS valido y de confianza",
            status=CheckStatus.PASS,
            evidence={
                "subject": dict(x[0] for x in cert.get("subject", ())),
                "issuer": dict(x[0] for x in cert.get("issuer", ())),
                "tls_version": version,
                "cipher": cipher[0] if cipher else None,
            },
            source="tls",
        )]

        not_after = cert.get("notAfter")
        if not not_after:
            checks.append(Check(
                id=cid_exp, title="Certificado TLS vigente",
                status=CheckStatus.NOT_ASSESSED,
                error="el certificado no expone notAfter", source="tls",
            ))
            return checks

        try:
            exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        except ValueError as e:
            checks.append(Check(
                id=cid_exp, title="Certificado TLS vigente",
                status=CheckStatus.NOT_ASSESSED,
                error=f"formato de fecha no parseable: {e}", source="tls",
            ))
            return checks

        days_left = (exp - datetime.now(timezone.utc)).days
        checks.append(Check(
            id=cid_exp,
            title="Certificado TLS vigente",
            # <30 dias se marca FAIL: renovacion urgente es un hallazgo real
            status=CheckStatus.PASS if days_left > 30 else CheckStatus.FAIL,
            evidence={"not_after": exp.isoformat(), "days_remaining": days_left},
            source="tls",
        ))

        # TLS obsoleto
        if version:
            legacy = version in ("TLSv1", "TLSv1.1", "SSLv3")
            checks.append(Check(
                id="tls.version.modern",
                title="Version de TLS moderna (>= 1.2)",
                status=CheckStatus.FAIL if legacy else CheckStatus.PASS,
                evidence={"negotiated": version},
                source="tls",
            ))
        return checks

    # ----------------------------------------------------------------- HTTP
    
    async def _check_http(self, host: str) -> list[Check]:
        url = f"https://{host}"
        checks: list[Check] = []

        async def _on_response(resp: httpx.Response) -> None:
            if resp.has_redirect_location:
                await validate_redirect(str(resp.next_request.url))

        try:
            async with httpx.AsyncClient(
                timeout=self.timeout,
                headers=self.headers,
                follow_redirects=True,
                max_redirects=5,
                event_hooks={"response": [_on_response]},
            ) as client:
                t0 = time.perf_counter()
                resp = await client.get(url)
                elapsed_ms = int((time.perf_counter() - t0) * 1000)
        except ScopeViolation as e:
            err = f"redirect fuera de alcance: {e.reason}"
            return self._http_all_not_assessed(err)
        except Exception as e:
            err = f"{type(e).__name__}: {e}"
            return self._http_all_not_assessed(err)

        h = {k.lower(): v for k, v in resp.headers.items()}
        content_type = h.get("content-type", "")
        is_html = "html" in content_type
        # Cuerpo acotado: 512 KB bastan para <head> y las etiquetas de recursos.
        body = resp.text[:512_000]
        html = body if is_html else ""

        # BUG CORREGIDO: antes era PASS incondicional. Un 404/500 en la raiz del
        # dominio se contaba como "accesible" porque no lanzaba excepcion.
        ok_status = resp.status_code < 400
        checks.append(Check(
            id="http.reachable",
            title="La raiz del dominio responde con un estado correcto",
            status=CheckStatus.PASS if ok_status else CheckStatus.FAIL,
            evidence={
                "status_code": resp.status_code,
                "reason": resp.reason_phrase,
                "final_url": str(resp.url),
                "redirects": len(resp.history),
                "content_type": h.get("content-type"),
            },
        ))

        # Cabeceras de seguridad — ausencia AQUI si es dato medido (FAIL, no NOT_ASSESSED)
        for header, cid in SECURITY_HEADERS.items():
            present = header in h
            checks.append(Check(
                id=cid,
                title=f"Cabecera {header}",
                status=CheckStatus.PASS if present else CheckStatus.FAIL,
                evidence={"present": present, "value": h.get(header)},
            ))

        # Rendimiento — ahora medido, no asumido
        checks.append(Check(
            id="perf.load_time",
            title=f"Tiempo de respuesta bajo presupuesto ({LOAD_TIME_BUDGET_MS} ms)",
            status=CheckStatus.PASS if elapsed_ms <= LOAD_TIME_BUDGET_MS else CheckStatus.FAIL,
            evidence={
                "load_time_ms": elapsed_ms,
                "budget_ms": LOAD_TIME_BUDGET_MS,
                "note": "TTFB+cuerpo desde un unico punto de medicion, no sintetico multi-region",
            },
        ))

        # Fuga de version del servidor
        server = h.get("server")
        checks.append(Check(
            id="http.server_banner",
            title="Banner de servidor sin version expuesta",
            status=CheckStatus.FAIL if server and any(ch.isdigit() for ch in server) else CheckStatus.PASS,
            evidence={"server": server or "no expuesto"},
        ))

        # --- Checks de contenido: lo que un escaner de cabeceras no ve ---
        checks.append(check_not_error_page(
            body, resp.status_code, str(resp.url), content_type=content_type))

        if is_html:
            checks.append(check_csp_self_block(
                html, h.get("content-security-policy"), str(resp.url)))
        else:
            checks.append(Check(
                id="content.csp_self_block",
                title="La CSP no bloquea recursos del propio sitio",
                status=CheckStatus.NOT_ASSESSED,
                error=f"la respuesta no es HTML (content-type: {content_type or 'ausente'})"))

        # Redirect HTTP -> HTTPS
        checks.append(await self._check_http_redirect(host))
        return checks

    def _http_all_not_assessed(self, err: str) -> list[Check]:
        ids = [("http.reachable", "Servicio HTTPS accesible"),
               ("perf.load_time", "Tiempo de respuesta"),
               ("http.server_banner", "Banner de servidor"),
               ("http.redirect_https", "Redireccion HTTP a HTTPS"),
               ("content.not_error_page", "El documento no es una pagina de error"),
               ("content.csp_self_block", "La CSP no bloquea recursos propios")]
        ids += [(cid, f"Cabecera {hdr}") for hdr, cid in SECURITY_HEADERS.items()]
        return [
            Check(id=cid, title=title, status=CheckStatus.NOT_ASSESSED, error=err)
            for cid, title in ids
        ]

    async def _check_http_redirect(self, host: str) -> Check:
        try:
            async with httpx.AsyncClient(
                timeout=self.timeout, headers=self.headers, follow_redirects=False
            ) as client:
                resp = await client.get(f"http://{host}")
            loc = resp.headers.get("location", "")
            ok = resp.status_code in (301, 308) and loc.startswith("https://")
            return Check(
                id="http.redirect_https",
                title="Redireccion permanente HTTP -> HTTPS",
                status=CheckStatus.PASS if ok else CheckStatus.FAIL,
                evidence={"status_code": resp.status_code, "location": loc},
            )
        except Exception as e:
            return Check(
                id="http.redirect_https",
                title="Redireccion permanente HTTP -> HTTPS",
                status=CheckStatus.NOT_ASSESSED,
                error=f"{type(e).__name__}: {e}",
            )

    # ------------------------------------------------------------ orquestador

    async def run_full_recon(self, domain: str) -> ReconResult:
        """
        Punto de entrada unico. Valida scope, ejecuta en paralelo, agrega.
        Nunca lanza por fallo de un check individual: lo marca NOT_ASSESSED.
        """
        result = ReconResult(target=domain)

        try:
            host, ips = await resolve_and_validate(domain)
            result.target = host
            result.resolved_ips = ips
        except ScopeViolation as e:
            logger.warning("scope_violation target=%s reason=%s", domain, e.reason)
            result.checks = self._http_all_not_assessed(f"target rechazado: {e.reason}")
            result.finished_at = datetime.now(timezone.utc)
            return result

        groups = await asyncio.gather(
            self._check_dns(host),
            self._check_tls(host),
            self._check_http(host),
            return_exceptions=True,
        )

        for g in groups:
            if isinstance(g, BaseException):
                logger.exception("grupo de checks fallo", exc_info=g)
                continue
            result.checks.extend(g)

        result.finished_at = datetime.now(timezone.utc)
        logger.info("recon_done target=%s coverage=%s", host, result.coverage_label)
        return result