"""
Router de reportes.

El pipeline de auditoria vive ahora en src/workers/tasks.py y corre en un
proceso aparte. Este modulo solo encola, consulta estado y sirve resultados.
"""
from __future__ import annotations

import logging
from pathlib import Path
from uuid import UUID

from arq.jobs import Job, JobStatus
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.config import settings
from src.core.auth import AuthContext, Scope, require, scoped
from src.core.database import get_db
from src.core.queue import get_queue
from src.models.audit_report import AuditReport as AuditReportModel
from src.models.audit_task import AuditTask
from src.models.company import Company

logger = logging.getLogger("vertex.reports")
router = APIRouter(prefix="/reports", tags=["Reports"])


@router.post("/trigger/{company_id}", status_code=status.HTTP_202_ACCEPTED)
async def run_full_audit(
    company_id: UUID,
    db: AsyncSession = Depends(get_db),
    ctx: AuthContext = Depends(require(Scope.WRITE)),
):
    """Encola la auditoria y devuelve el job_id para hacer polling.

    Antes se usaba BackgroundTasks: el trabajo moria con el proceso, no tenia
    reintentos y no habia forma de consultar su estado.
    """
    stmt = scoped(select(Company).where(Company.id == company_id), Company, ctx)
    company = (await db.execute(stmt)).scalar_one_or_none()
    if not company:
        raise HTTPException(404, detail="Compania no encontrada")

    # Idempotencia: no se encolan dos auditorias del mismo dominio a la vez.
    running = await db.execute(
        select(AuditTask).where(
            AuditTask.company_id == company_id,
            AuditTask.status.in_(["PENDING", "RUNNING"]),
        ).limit(1)
    )
    if running.scalar_one_or_none():
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail="Ya hay una auditoria en curso para esta compania",
        )

    db.add_all([
        AuditTask(company_id=company.id, tenant_id=ctx.tenant_id,
                  agent_type="SECURITY_OSINT", status="PENDING"),
        AuditTask(company_id=company.id, tenant_id=ctx.tenant_id,
                  agent_type="SEO_VISIBILITY", status="PENDING"),
    ])
    await db.commit()

    job = await get_queue().enqueue_job(
        "run_audit", str(company.id), company.domain, str(ctx.tenant_id)
    )

    return {
        "status": "QUEUED",
        "job_id": job.job_id,
        "company_id": str(company.id),
        "domain": company.domain,
        "poll": f"/reports/jobs/{job.job_id}",
    }


@router.get("/jobs/{job_id}")
async def get_job_status(
    job_id: str,
    ctx: AuthContext = Depends(require(Scope.READ)),
):
    """Estado de un trabajo encolado. Sustituye al polling a ciegas sobre
    /latest, que no distinguia 'aun corriendo' de 'fallo'."""
    job = Job(job_id, redis=get_queue())
    try:
        st = await job.status()
    except Exception:
        raise HTTPException(404, detail="Trabajo no encontrado")

    if st is JobStatus.not_found:
        raise HTTPException(404, detail="Trabajo no encontrado o expirado")

    body: dict = {"job_id": job_id, "state": st.value}

    if st is JobStatus.complete:
        try:
            body["result"] = await job.result(timeout=0)
        except Exception as exc:
            body["state"] = "failed"
            body["error"] = type(exc).__name__
    return body


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
    ruta, y la fila consultada ya esta acotada al tenant.
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

    # Cinturon y tirantes: la ruta sale de la base y no del cliente, pero si
    # una fila se corrompiera no debe poder servir nada fuera del directorio.
    if not path.is_relative_to(base) or not path.is_file():
        logger.error("pdf_missing report=%s path=%s", report_id, path)
        raise HTTPException(404, detail="El archivo del reporte no esta disponible")

    return FileResponse(
        path,
        media_type="application/pdf",
        filename=f"auditoria-{report_id}.pdf",
        headers={"Cache-Control": "private, no-store"},
    )