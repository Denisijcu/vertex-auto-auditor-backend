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


from src.core.diff import compare, fingerprint

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

    # FUENTE UNICA DE VERDAD: el payload, no la columna.
    #
    # `audit_reports.security_score` es un indice desnormalizado para poder
    # listar sin deserializar el JSONB. Puede desincronizarse del payload, y
    # cuando eso pasa gana la columna, que es la fuente menos fiable.
    #
    # Caso real (reporte del 20/07 de dentiapro.com): la columna decia 80 y el
    # payload no tenia ni `security_score` ni `target`. Ese 80 lo produjo la
    # version del motor anterior al scoring documentado, y no se podia
    # reconstruir desde ninguna evidencia. Un null publicandose como 80 le dice
    # al cliente "estas bastante bien" cuando la verdad es "no medi nada".
    #
    # Es el principio del motor aplicado a la capa de lectura: si no se puede
    # reconstruir desde la evidencia, no se publica.
    payload = report.findings or {}
    has_payload_score = "security_score" in payload

    return {
        "report_id": str(report.id),
        "security_score": payload.get("security_score") if has_payload_score else None,
        "optimization_score": payload.get("optimization_score") if has_payload_score else None,
        "findings": payload,
        # Distingue "no se pudo medir" de "reporte de una version anterior del
        # motor". Sin esta bandera, el panel y el MCP los muestran igual.
        "legacy": not has_payload_score,
        "pdf_url": f"/reports/{report.id}/pdf" if report.pdf_url else None,
        "created_at": report.created_at.isoformat(),
    }


@router.get("/{company_id}/history")
async def get_report_history(
    company_id: UUID,
    limit: int = 30,
    db: AsyncSession = Depends(get_db),
    ctx: AuthContext = Depends(require(Scope.READ)),
):
    """Linea temporal de auditorias de una compania.

    Devuelve solo lo necesario para dibujar la evolucion: puntuacion,
    penalizacion, cobertura y recuento de hallazgos. El payload completo de
    cada informe pesa decenas de KB y aqui no hace falta.
    """
    limit = max(1, min(limit, 100))

    stmt = scoped(
        select(AuditReportModel)
        .where(AuditReportModel.company_id == company_id)
        .order_by(AuditReportModel.created_at.desc())
        .limit(limit),
        AuditReportModel, ctx,
    )
    reports = (await db.execute(stmt)).scalars().all()

    if not reports:
        raise HTTPException(404, detail="Sin reportes para esta compania")

    entries = []
    for r in reports:
        p = r.findings or {}
        cov = p.get("coverage", {}) or {}
        # Un informe anterior a `checks[]` no se puede interpretar con las
        # reglas actuales. Se marca en lugar de mezclarlo con los demas.
        legacy = "security_score" not in p

        entries.append({
            "report_id": str(r.id),
            "audited_at": r.created_at.isoformat(),
            "security_score": None if legacy else p.get("security_score"),
            "optimization_score": None if legacy else p.get("optimization_score"),
            "raw_penalty": p.get("raw_penalty_security"),
            "verdict": p.get("verdict"),
            "findings_count": len(p.get("findings", []) or []),
            "severity_counts": _severity_counts(p.get("findings", []) or []),
            "coverage": {
                "assessed": cov.get("assessed"),
                "total": cov.get("total_checks"),
                "reliable": cov.get("reliable"),
            },
            "fingerprint": None if legacy else fingerprint(p),
            "has_pdf": bool(r.pdf_url),
            "legacy": legacy,
        })

    return {
        "target": (reports[0].findings or {}).get("target"),
        "count": len(entries),
        # Mas reciente primero: es el orden en que se consulta.
        "entries": entries,
    }


def _severity_counts(findings: list[dict]) -> dict[str, int]:
    out = {s: 0 for s in ("critical", "high", "medium", "low", "info")}
    for f in findings:
        sev = f.get("severity", "info")
        out[sev] = out.get(sev, 0) + 1
    return out

@router.get("/{company_id}/diff")
async def get_report_diff(
    company_id: UUID,
    db: AsyncSession = Depends(get_db),
    ctx: AuthContext = Depends(require(Scope.READ)),
):
    """Compara las dos ultimas auditorias de una compania.

    Es lo que convierte un informe puntual en un servicio: no "esto tienes mal
    hoy" sino "esto cambio desde la ultima vez".
    """
    stmt = scoped(
        select(AuditReportModel)
        .where(AuditReportModel.company_id == company_id)
        .order_by(AuditReportModel.created_at.desc())
        .limit(2),
        AuditReportModel, ctx,
    )
    reports = (await db.execute(stmt)).scalars().all()

    if not reports:
        raise HTTPException(404, detail="Sin reportes para esta compania")
    if len(reports) < 2:
        return {
            "comparable": False,
            "reason": "Solo hay una auditoria de este dominio. La comparacion "
                      "requiere al menos dos.",
            "current": {
                "report_id": str(reports[0].id),
                "audited_at": reports[0].created_at.isoformat(),
                "security_score": (reports[0].findings or {}).get("security_score"),
            },
        }

    current, previous = reports[0], reports[1]

    curr_payload = current.findings or {}
    prev_payload = previous.findings or {}

    # Los reportes anteriores a `checks[]` no permiten distinguir un hallazgo
    # corregido de uno que dejo de medirse. Antes que producir un diff que
    # parece fiable y no lo es, se declara no comparable.
    if "security_score" not in prev_payload or "security_score" not in curr_payload:
        return {
            "comparable": False,
            "reason": "Uno de los informes se genero con una version anterior "
                      "del motor y no contiene los datos necesarios para "
                      "compararlo. Vuelve a auditar para obtener una "
                      "comparacion fiable.",
        }

    return compare(
        prev_payload, curr_payload,
        previous_meta={
            "report_id": str(previous.id),
            "created_at": previous.created_at.isoformat(),
            "fingerprint": fingerprint(prev_payload),
        },
        current_meta={
            "report_id": str(current.id),
            "created_at": current.created_at.isoformat(),
            "fingerprint": fingerprint(curr_payload),
        },
    )

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