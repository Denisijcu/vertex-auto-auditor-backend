"""
OptimizationAgent v2.

v1 devolvia SIEMPRE 100 porque leia `load_time_ms` y `google_maps_indexed`,
campos que el scraper nunca produjo. Aqui solo evalua lo que existe.

Nota honesta de alcance: sin integracion con PageSpeed/CrUX y sin Google
Business Profile API, la cobertura de esta categoria es baja a proposito.
El reporte lo declara en vez de rellenarlo con supuestos.
"""
from __future__ import annotations

from src.agents.base import ScanAgent
from src.schemas.finding import Confidence, Finding, Severity
from src.schemas.recon import CheckStatus, ReconResult


class OptimizationAgent(ScanAgent):
    name = "Vertex Performance & SEO Auditor"
    agent_type = "SEO_VISIBILITY"
    check_prefixes = ("perf.", "http.reachable")

    async def analyze(self, recon: ReconResult) -> list[Finding]:
        findings: list[Finding] = []

        perf = recon.get("perf.load_time")
        if perf and perf.status is CheckStatus.FAIL:
            ms = perf.evidence.get("load_time_ms")
            budget = perf.evidence.get("budget_ms")
            findings.append(Finding(
                id="VTX-PERF-001",
                check_id="perf.load_time",
                title="Tiempo de respuesta por encima del presupuesto",
                severity=Severity.MEDIUM if (ms or 0) < 5000 else Severity.HIGH,
                confidence=Confidence.CONFIRMED,
                asset=recon.target,
                description=(
                    f"El servidor tardo {ms} ms en responder, sobre el presupuesto de "
                    f"{budget} ms. Impacta Core Web Vitals y tasa de rebote."
                ),
                remediation=(
                    "Activar compresion (brotli/gzip), cache HTTP con Cache-Control, "
                    "CDN para estaticos y revisar consultas lentas en backend."
                ),
                evidence=perf.evidence,
                category="optimization",
            ))

        return findings