"""
Router de reportes. Auth obligatoria y aislamiento por tenant en todo acceso.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.agents.optimization_agent import OptimizationAgent
from src.agents.report_agent import ReportConsolidator
from src.agents.security_agent import SecurityAgent
from src.config import settings
from src.core.auth import AuthContext, Scope, require, scoped
from src.core.database import AsyncSessionLocal, get_db
from src.models.audit_report import AuditReport as AuditReportModel
from src.models.audit_task import AuditTask
from src.models.company import Company
from src.services.pdf_generator import PDFGenerator
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

    payload = report.model_dump(mode="json")

    # El PDF es opcional: render_audit_pdf ya captura sus propios errores y
    # devuelve None. Un fallo de renderizado no debe impedir persistir el
    # reporte, que es el dato de valor.
    pdf_url = await PDFGenerator.render_audit_pdf(
        payload,
        reports_dir=settings.REPORTS_DIR,
        company_id=str(company_id),
    )

    async with AsyncSessionLocal() as session:
        try:
            session.add(AuditReportModel(
                tenant_id=tenant_id,
                company_id=company_id,
                security_score=report.security_score,        # puede ser None
                optimization_score=report.optimization_score,
                findings=payload,
                pdf_url=pdf_url,
            ))
            await _mark_tasks(session, company_id, "COMPLETED")
            await session.commit()
        except Exception:
            await session.rollback()
            logger.exception("persistencia fallo domain=%s", domain)
            return

    logger.info("audit_done domain=%s sec=%s cov=%s/%s reliable=%s pdf=%s",
                domain, report.security_score,
                report.coverage["assessed"], report.coverage["total_checks"],
                report.coverage["reliable"], bool(pdf_url))


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
        "pdf_url": f"/reports/{report.id}/pdf" if report.pdf_url else None,
        "created_at": report.created_at.isoformat(),
    }


@router.get("/{report_id}/pdf")
async def download_report_pdf(
    report_id: UUID,
    db: AsyncSession = Depends(get_db),
    ctx: AuthContext = Depends(require(Scope.READ)),
):
    """Descarga el PDF de un reporte.

    Se sirve POR ID DE REPORTE, no por ruta de archivo. Con un identificador
    opaco no hay superficie de path traversal: el cliente nunca controla una
    ruta, y la fila que se consulta ya esta acotada al tenant.
    """
    stmt = scoped(
        select(AuditReportModel).where(AuditReportModel.id == report_id),
        AuditReportModel, ctx,
    )
    report = (await db.execute(stmt)).scalar_one_or_none()
    # 404 y no 403: no se revela que el reporte existe en otro tenant.
    if not report or not report.pdf_url:
        raise HTTPException(404, detail="PDF no disponible para este reporte")

    base = Path(settings.REPORTS_DIR).resolve()
    path = (base / report.pdf_url.lstrip("/")).resolve()

    # Cinturon y tirantes: aunque la ruta salga de la base de datos y no del
    # cliente, se verifica que no escape del directorio de reportes.
    if not path.is_relative_to(base) or not path.is_file():
        logger.error("pdf_missing report=%s path=%s", report_id, path)
        raise HTTPException(404, detail="El archivo del reporte no esta disponible")

    return FileResponse(
        path,
        media_type="application/pdf",
        filename=f"auditoria-{report_id}.pdf",
        headers={"Cache-Control": "private, no-store"},
    )