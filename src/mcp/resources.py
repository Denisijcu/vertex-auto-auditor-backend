"""
Recursos MCP — bugs corregidos.

v1: `scalar_one_or_none()` sin `.limit(1)` -> MultipleResultsFound (500) en
cuanto una compania tenia dos reportes. Funcionaba solo la primera auditoria.
v1: `UUID(company_id)` sin guarda -> 500 con cualquier string mal formado.
"""
from __future__ import annotations

from typing import Any
from uuid import UUID

from sqlalchemy import select

from src.core.database import AsyncSessionLocal
from src.mcp.server import mcp_server
from src.models.audit_report import AuditReport


@mcp_server.register_resource(
    uri_pattern="auditor://companies/{company_id}/latest-report",
    description="JSON consolidado del ultimo reporte de auditoria de una compania.",
)
async def get_latest_report_resource(company_id: str) -> dict[str, Any]:
    try:
        cid = UUID(company_id)
    except (ValueError, AttributeError, TypeError):
        return {"error": "company_id no es un UUID valido", "received": str(company_id)}

    async with AsyncSessionLocal() as session:
        stmt = (
            select(AuditReport)
            .where(AuditReport.company_id == cid)
            .order_by(AuditReport.created_at.desc())
            .limit(1)  # sin esto, la segunda auditoria rompe el recurso
        )
        report = (await session.execute(stmt)).scalar_one_or_none()

    if not report:
        return {"error": f"Sin reportes generados para la compania {company_id}"}

    payload = report.findings or {}
    coverage = payload.get("coverage", {})

    return {
        "report_id": str(report.id),
        "security_score": report.security_score,
        "optimization_score": report.optimization_score,
        # Senal explicita para el LLM: si no es fiable, que no afirme conclusiones
        "reliable": coverage.get("reliable", False),
        "coverage": coverage,
        "verdict": payload.get("verdict"),
        "findings": payload.get("findings", []),
        "scoring_method": payload.get("scoring_method"),
        "created_at": report.created_at.isoformat(),
    }