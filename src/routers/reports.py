"""
Router de reportes. Auth obligatoria y aislamiento por tenant en todo acceso.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.agents.optimization_agent import OptimizationAgent
from src.agents.report_agent import ReportConsolidator
from src.agents.security_agent import SecurityAgent
from src.core.auth import AuthContext, Scope, require, scoped
from src.core.database import AsyncSessionLocal, get_db
from src.models.audit_report import AuditReport as AuditReportModel
from src.models.audit_task import AuditTask
from src.models.company import Company
from src.services.scraper_service import ScraperService

logger = logging.getLogger("vertex.reports")
router = APIRouter(prefix="/reports", tags=["Reports"])


async def _mark_tasks(session: AsyncSession, company_id: UUID, value: str) -> None:
    stmt = select(AuditTask).where(
        AuditTask.company_id == company_id,
        AuditTask.status.in_(["PENDING", "RUNNING"]),
    )
    now = datetime.now(timezone.utc)
    for task in (await session.execute(stmt)).scalars().all():
        task.status = value
        if value == "RUNNING":
            task.started_at = now
        else:
            task.completed_at = now
            if value == "FAILED":
                task.attempts = (task.attempts or 0) + 1


async def pipeline_full_audit(company_id: UUID, domain: str, tenant_id: UUID) -> None:
    """Pipeline OSINT. Gestiona su propia sesion: get_db es una dependencia de
    FastAPI, no una factory reutilizable fuera del ciclo de request."""
    logger.info("audit_start company=%s domain=%s", company_id, domain)

    async with AsyncSessionLocal() as session:
        try:
            await _mark_tasks(session, company_id, "RUNNING")
            await session.commit()
        except Exception:
            await session.rollback()
            logger.exception("no se pudo marcar tareas RUNNING")

    try:
        recon = await ScraperService().run_full_recon(domain)
        findings_by_agent = {
            "security": await SecurityAgent().analyze(recon),
            "optimization": await OptimizationAgent().analyze(recon),
        }
        report = await ReportConsolidator().consolidate(recon, findings_by_agent)
    except Exception:
        logger.exception("pipeline fallo domain=%s", domain)
        async with AsyncSessionLocal() as session:
            try:
                await _mark_tasks(session, company_id, "FAILED")
                await session.commit()
            except Exception:
                await session.rollback()
        return

    # El PDF es opcional: su fallo no debe impedir persistir el reporte.
    pdf_url = None
    try:
        from src.services.pdf_generator import PDFGenerator
        pdf_url = await PDFGenerator.render_audit_pdf(report.model_dump(mode="json"))
    except Exception:
        logger.warning("pdf_generation_failed domain=%s", domain, exc_info=True)

    async with AsyncSessionLocal() as session:
        try:
            session.add(AuditReportModel(
                tenant_id=tenant_id,
                company_id=company_id,
                security_score=report.security_score,        # puede ser None
                optimization_score=report.optimization_score,
                findings=report.model_dump(mode="json"),
                pdf_url=pdf_url,
            ))
            await _mark_tasks(session, company_id, "COMPLETED")
            await session.commit()
        except Exception:
            await session.rollback()
            logger.exception("persistencia fallo domain=%s", domain)
            return

    logger.info("audit_done domain=%s sec=%s cov=%s/%s reliable=%s",
                domain, report.security_score,
                report.coverage["assessed"], report.coverage["total_checks"],
                report.coverage["reliable"])


@router.post("/trigger/{company_id}", status_code=status.HTTP_202_ACCEPTED)
async def run_full_audit(
    company_id: UUID,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    ctx: AuthContext = Depends(require(Scope.WRITE)),
):
    # scoped() impide lanzar auditorias contra companias de otro tenant.
    stmt = scoped(select(Company).where(Company.id == company_id), Company, ctx)
    company = (await db.execute(stmt)).scalar_one_or_none()
    if not company:
        raise HTTPException(404, detail="Compania no encontrada")

    background_tasks.add_task(
        pipeline_full_audit, company.id, company.domain, ctx.tenant_id
    )
    return {
        "status": "PROCESSING",
        "company_id": str(company.id),
        "domain": company.domain,
    }


@router.get("/{company_id}/latest")
async def get_latest_report(
    company_id: UUID,
    db: AsyncSession = Depends(get_db),
    ctx: AuthContext = Depends(require(Scope.READ)),
):
    stmt = scoped(
        select(AuditReportModel)
        .where(AuditReportModel.company_id == company_id)
        .order_by(AuditReportModel.created_at.desc())
        .limit(1),   # sin limit(1), scalar_one_or_none rompe con 2+ reportes
        AuditReportModel, ctx,
    )
    report = (await db.execute(stmt)).scalar_one_or_none()
    if not report:
        raise HTTPException(404, detail="Sin reportes para esta compania")

    return {
        "report_id": str(report.id),
        "security_score": report.security_score,
        "optimization_score": report.optimization_score,
        "findings": report.findings,
        "pdf_url": report.pdf_url,
        "created_at": report.created_at.isoformat(),
    }