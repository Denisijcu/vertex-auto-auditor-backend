"""Recursos MCP. Todo acceso queda acotado al tenant del contexto."""
from __future__ import annotations

from typing import Any
from uuid import UUID

from sqlalchemy import select

from src.core.auth import AuthContext, Scope
from src.core.database import AsyncSessionLocal
from src.mcp.server import mcp_server
from src.models.audit_report import AuditReport


@mcp_server.register_resource(
    uri_pattern="auditor://companies/{company_id}/latest-report",
    description="JSON consolidado del ultimo reporte de auditoria de una compania.",
    scope=Scope.READ,
)
async def get_latest_report_resource(company_id: str, *, ctx: AuthContext) -> dict[str, Any]:
    try:
        cid = UUID(company_id)
    except (ValueError, AttributeError, TypeError):
        return {"error": "company_id no es un UUID valido"}

    async with AsyncSessionLocal() as session:
        stmt = (
            select(AuditReport)
            .where(
                AuditReport.company_id == cid,
                # Sin este filtro, cambiar el UUID de la URI lee el inventario
                # de vulnerabilidades de otro tenant.
                AuditReport.tenant_id == ctx.tenant_id,
            )
            .order_by(AuditReport.created_at.desc())
            .limit(1)  # sin esto, la 2a auditoria rompe con MultipleResultsFound
        )
        report = (await session.execute(stmt)).scalar_one_or_none()

    if not report:
        return {"error": f"Sin reportes para la compania {company_id}"}

    payload = report.findings or {}
    coverage = payload.get("coverage", {})
    return {
        "report_id": str(report.id),
        "security_score": report.security_score,
        "optimization_score": report.optimization_score,
        # Señal explicita para el LLM: si no es fiable, que no afirme conclusiones.
        "reliable": coverage.get("reliable", False),
        "coverage": coverage,
        "verdict": payload.get("verdict"),
        "findings": payload.get("findings", []),
        "scoring_method": payload.get("scoring_method"),
        "created_at": report.created_at.isoformat(),
    }