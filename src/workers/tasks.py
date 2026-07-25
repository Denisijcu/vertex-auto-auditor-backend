"""
Trabajos de ARQ.

Sustituye a BackgroundTasks, que tenia tres problemas serios para produccion:
  - Muere con el proceso: un deploy o un reinicio pierde las auditorias en vuelo
    sin dejar rastro.
  - Sin reintentos: un fallo transitorio de DNS marcaba la auditoria como FAILED
    para siempre.
  - Sin backpressure: 500 disparos simultaneos abren 500 corrutinas dentro del
    proceso web y tumban la API.

Con ARQ el trabajo se persiste en Redis, sobrevive al reinicio, reintenta con
backoff y se ejecuta en un proceso aparte del que atiende HTTP.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from uuid import UUID

from arq import Retry
from sqlalchemy import select

from src.agents.optimization_agent import OptimizationAgent
from src.agents.report_agent import ReportConsolidator
from src.agents.security_agent import SecurityAgent
from src.config import settings
from src.core.database import AsyncSessionLocal
from src.models.audit_report import AuditReport as AuditReportModel
from src.models.audit_task import AuditTask
from src.services.pdf_generator import PDFGenerator
from src.services.scraper_service import ScraperService

logger = logging.getLogger("vertex.worker")

# Fallos transitorios (DNS caido, timeout puntual) merecen reintento.
# Un dominio que no existe, no: reintentarlo 3 veces solo gasta cuota.
TRANSIENT_ERRORS = ("TimeoutError", "ConnectError", "ReadTimeout", "PoolTimeout")


async def _set_tasks(company_id: UUID, status: str, error: str | None = None) -> None:
    async with AsyncSessionLocal() as session:
        try:
            stmt = select(AuditTask).where(
                AuditTask.company_id == company_id,
                AuditTask.status.in_(["PENDING", "RUNNING"]),
            )
            now = datetime.now(timezone.utc)
            for task in (await session.execute(stmt)).scalars().all():
                task.status = status
                if status == "RUNNING":
                    task.started_at = now
                else:
                    task.completed_at = now
                if error:
                    task.error = error[:2000]
                if status == "FAILED":
                    task.attempts = (task.attempts or 0) + 1
            await session.commit()
        except Exception:
            await session.rollback()
            logger.exception("no se pudo actualizar AuditTask company=%s", company_id)


async def run_audit(
    ctx: dict, company_id: str, domain: str, tenant_id: str,
    target_type: str = "website",
) -> dict:
    """Job principal. `ctx` lo inyecta ARQ e incluye job_try para el backoff.

    target_type ('website' | 'api') se declara al registrar el dominio y modula
    que checks aplican. Default 'website' para jobs encolados antes de este
    cambio: sin el, se comportan como siempre.
    """
    cid, tid = UUID(company_id), UUID(tenant_id)
    attempt = ctx.get("job_try", 1)
    logger.info("audit_start domain=%s type=%s attempt=%s", domain, target_type, attempt)

    await _set_tasks(cid, "RUNNING")

    try:
        recon = await ScraperService().run_full_recon(domain, target_type=target_type)
        findings = {
            "security": await SecurityAgent().analyze(recon),
            "optimization": await OptimizationAgent().analyze(recon),
        }
        report = await ReportConsolidator().consolidate(recon, findings)
    except Exception as exc:
        name = type(exc).__name__
        if name in TRANSIENT_ERRORS and attempt < settings.WORKER_MAX_TRIES:
            # Backoff exponencial: 10s, 20s, 40s.
            delay = 10 * (2 ** (attempt - 1))
            logger.warning("recon transitorio domain=%s %s, reintento en %ss",
                           domain, name, delay)
            raise Retry(defer=delay) from exc

        logger.exception("recon fallo definitivo domain=%s", domain)
        await _set_tasks(cid, "FAILED", f"{name}: {exc}")
        return {"status": "FAILED", "domain": domain, "error": name}

    payload = report.model_dump(mode="json")

    # El PDF captura sus propios errores y devuelve None: un fallo de
    # renderizado no puede impedir persistir el reporte, que es el dato de valor.
    pdf_bytes = await PDFGenerator.render_audit_pdf_bytes(payload)
   
    

    async with AsyncSessionLocal() as session:
        try:
            row = AuditReportModel(
                tenant_id=tid, company_id=cid,
                security_score=report.security_score,
                optimization_score=report.optimization_score,
                findings=payload, pdf_bytes=pdf_bytes,
            )
            session.add(row)
            await session.commit()
            await session.refresh(row)
            report_id = str(row.id)
        except Exception as exc:
            await session.rollback()
            logger.exception("persistencia fallo domain=%s", domain)
            # La base es una dependencia critica: aqui SI se reintenta.
            if attempt < settings.WORKER_MAX_TRIES:
                raise Retry(defer=15) from exc
            await _set_tasks(cid, "FAILED", f"persistencia: {exc}")
            return {"status": "FAILED", "domain": domain, "error": "persistence"}

    await _set_tasks(cid, "COMPLETED")
    logger.info("audit_done domain=%s sec=%s cov=%s/%s reliable=%s",
                domain, report.security_score,
                report.coverage["assessed"], report.coverage["total_checks"],
                report.coverage["reliable"])

    return {
        "status": "COMPLETED",
        "domain": domain,
        "report_id": report_id,
        "security_score": report.security_score,
        "optimization_score": report.optimization_score,
        "coverage": report.coverage,
        "findings_count": len(report.findings),
        "pdf_available": bool(pdf_bytes),
    }