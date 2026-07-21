"""
Herramientas MCP. Cada una declara su modelo de entrada con extra="forbid".
"""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from src.core.auth import AuthContext, Scope
from src.core.database import AsyncSessionLocal
from src.core.target_guard import ScopeViolation, validate_hostname
from src.mcp.server import mcp_server
from src.models.audit_task import AuditTask
from src.models.company import Company


class TriggerAuditInput(BaseModel):
    # extra="forbid" rechaza cualquier campo no declarado. Sin esto, el cliente
    # puede colar tenant_id, id, o cualquier atributo del modelo ORM.
    model_config = ConfigDict(extra="forbid")

    domain: str = Field(..., min_length=4, max_length=253)
    name: str = Field(..., min_length=1, max_length=255)
    industry: str | None = Field(default=None, max_length=100)


@mcp_server.register_tool(
    name="trigger_audit",
    description=(
        "Registra un dominio y encola su auditoria OSINT de superficie publica. "
        "Devuelve el company_id para consultar el reporte."
    ),
    input_model=TriggerAuditInput,
    scope=Scope.WRITE,
)
async def trigger_audit(
    domain: str, name: str, industry: str | None = None, *, ctx: AuthContext
) -> dict[str, Any]:
    # El guard corre ANTES de tocar la base: un dominio fuera de alcance no
    # llega ni a crear fila.
    try:
        host = validate_hostname(domain)
    except ScopeViolation as e:
        return {"status": "REJECTED", "reason": e.reason, "domain": domain}

    async with AsyncSessionLocal() as session:
        company = Company(
            name=name, domain=host, industry=industry, tenant_id=ctx.tenant_id
        )
        session.add(company)
        try:
            await session.flush()
        except IntegrityError:
            # check-then-insert tiene carrera; se resuelve por la restriccion unique.
            await session.rollback()
            stmt = select(Company).where(
                Company.domain == host, Company.tenant_id == ctx.tenant_id
            )
            company = (await session.execute(stmt)).scalar_one_or_none()
            if company is None:
                return {"status": "ERROR", "reason": "dominio en conflicto"}

        session.add_all([
            AuditTask(company_id=company.id, tenant_id=ctx.tenant_id,
                      agent_type="SECURITY_OSINT", status="PENDING"),
            AuditTask(company_id=company.id, tenant_id=ctx.tenant_id,
                      agent_type="SEO_VISIBILITY", status="PENDING"),
        ])
        await session.commit()
        company_id = str(company.id)

    return {
        "status": "QUEUED",
        "company_id": company_id,
        "domain": host,
        "next": f"auditor://companies/{company_id}/latest-report",
    }