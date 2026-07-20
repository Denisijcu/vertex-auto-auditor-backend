"""
ReportConsolidator v2.

Ya no hereda de ScanAgent (no analiza nada). Recibe hallazgos de N agentes
y aplica el scoring por categoria, respetando la regla de cobertura.
"""
from __future__ import annotations

from src.agents.base import Consolidator
from src.core.scoring import SCORING_VERSION, category_coverage, compute_score, verdict_for
from src.schemas.finding import AuditReport, Finding
from src.schemas.recon import Coverage, ReconResult

SECURITY_PREFIXES = ("tls.", "http.", "dns.spf", "content.")
OPTIMIZATION_PREFIXES = ("perf.",)


class ReportConsolidator(Consolidator):
    name = "Vertex Executive Summarizer"

    async def consolidate(
        self, recon: ReconResult, findings_by_agent: dict[str, list[Finding]]
    ) -> AuditReport:
        all_findings: list[Finding] = []
        for group in findings_by_agent.values():
            all_findings.extend(group)

        sec_findings = [f for f in all_findings if f.category == "security"]
        opt_findings = [f for f in all_findings if f.category == "optimization"]

        sec_score = compute_score(sec_findings, *category_coverage(recon, SECURITY_PREFIXES))
        opt_score = compute_score(opt_findings, *category_coverage(recon, OPTIMIZATION_PREFIXES))

        coverage = Coverage.from_recon(recon)

        return AuditReport(
            target=recon.target,
            security_score=sec_score,
            optimization_score=opt_score,
            verdict=verdict_for(sec_score, opt_score),
            findings=all_findings,
            coverage=coverage.model_dump(mode="json"),
            scoring_method=SCORING_VERSION,
        )