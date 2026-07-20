"""
Router de reportes — reconectado al pipeline v2.

Cambios frente a v1:
  - Usa ReconResult tipado en vez de dict.
  - ReportAgent -> ReportConsolidator (la clase se renombro).
  - Sesion de DB propia con AsyncSessionLocal, no `async for db in get_db()`
    (get_db es una dependencia de FastAPI, no una factory reutilizable:
    usarla fuera del request no cierra bien el generador y filtra conexiones).
  - Cierra el ciclo de AuditTask: RUNNING -> COMPLETED/FAILED. Antes las filas
    creadas por la tool MCP `trigger_audit` quedaban PENDING para siempre.
  - Scores None-safe: si la cobertura fue insuficiente, se persiste NULL,
    no un 100 enganoso.
  - PDF opcional: si falla la generacion, el reporte igual se guarda.

NOTA: BackgroundTasks sigue siendo provisional. Muere con el contenedor y no
tiene reintentos. Migrar a ARQ en Sprint 2.
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
from src.core.database import AsyncSessionLocal, get_db
from src.models.audit_report import AuditReport as AuditReportModel
from src.models.audit_task import AuditTask
from src.models.company import Company
from src.services.scraper_service import ScraperService

logger = logging.getLogger("vertex.reports")
router = APIRouter(prefix="/reports", tags=["Reports"])


async def _mark_tasks(session: AsyncSession, company_id: UUID, status_value: str) -> None:
    """Avanza el estado de las AuditTask pendientes de una compania."""
    stmt = select(AuditTask).where(
        AuditTask.company_id == company_id,
        AuditTask.status.in_(["PENDING", "RUNNING"]),
    )
    tasks = (await session.execute(stmt)).scalars().all()
    now = datetime.now(timezone.utc)
    for t in tasks:
        t.status = status_value
        if status_value == "RUNNING":
            t.started_at = now
        else:
            t.completed_at = now


async def pipeline_full_audit(company_id: UUID, domain: str) -> None:
    """Pipeline OSINT completo. Gestiona su propia sesion de DB."""
    logger.info("audit_start company=%s domain=%s", company_id, domain)

    async with AsyncSessionLocal() as session:
        try:
            await _mark_tasks(session, company_id, "RUNNING")
            await session.commit()
        except Exception:
            await session.rollback()
            logger.exception("no se pudo marcar tareas RUNNING")

    try:
        # 1. Recon tipado. No lanza por checks individuales.
        recon = await ScraperService().run_full_recon(domain)

        # 2. Agentes. Cada uno emite Findings solo sobre checks realmente medidos.
        findings_by_agent = {
            "security": await SecurityAgent().analyze(recon),
            "optimization": await OptimizationAgent().analyze(recon),
        }

        # 3. Consolidacion + scoring consciente de cobertura.
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

    # 4. PDF opcional: nunca debe tumbar la persistencia del reporte.
    pdf_url = None
    try:
        from src.services.pdf_generator import PDFGenerator
        pdf_url = await PDFGenerator.render_audit_pdf(report.model_dump(mode="json"))
    except Exception:
        logger.warning("pdf_generation_failed domain=%s", domain, exc_info=True)

    # 5. Persistencia
    async with AsyncSessionLocal() as session:
        try:
            session.add(AuditReportModel(
                company_id=company_id,
                security_score=report.security_score,        # puede ser None
                optimization_score=report.optimization_score,  # puede ser None
                findings=report.model_dump(mode="json"),
                pdf_url=pdf_url,
            ))
            await _mark_tasks(session, company_id, "COMPLETED")
            await session.commit()
        except Exception:
            await session.rollback()
            logger.exception("persistencia fallo domain=%s", domain)
            return

    logger.info(
        "audit_done domain=%s sec=%s opt=%s coverage=%s/%s reliable=%s",
        domain, report.security_score, report.optimization_score,
        report.coverage["assessed"], report.coverage["total_checks"],
        report.coverage["reliable"],
    )


@router.post("/trigger/{company_id}", status_code=status.HTTP_202_ACCEPTED)
async def run_full_audit(
    company_id: UUID,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    company = await db.get(Company, company_id)
    if not company:
        raise HTTPException(status_code=404, detail="Negocio no encontrado.")

    background_tasks.add_task(pipeline_full_audit, company.id, company.domain)

    return {
        "status": "PROCESSING",
        "company_id": str(company.id),
        "domain": company.domain,
        "message": "Pipeline de auditoria iniciado en segundo plano.",
    }


@router.get("/{company_id}/latest")
async def get_latest_report(company_id: UUID, db: AsyncSession = Depends(get_db)):
    """Ultimo reporte. `.limit(1)` es obligatorio: sin el, scalar_one_or_none()
    lanza MultipleResultsFound en cuanto hay mas de una auditoria."""
    stmt = (
        select(AuditReportModel)
        .where(AuditReportModel.company_id == company_id)
        .order_by(AuditReportModel.created_at.desc())
        .limit(1)
    )
    report = (await db.execute(stmt)).scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=404, detail="Sin reportes para esta compania.")

    return {
        "report_id": str(report.id),
        "security_score": report.security_score,
        "optimization_score": report.optimization_score,
        "findings": report.findings,
        "pdf_url": report.pdf_url,
        "created_at": report.created_at.isoformat(),
    }