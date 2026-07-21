"""
Router de companies. Toda ruta exige API key y toda query pasa por scoped().
"""
from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.auth import AuthContext, Scope, require, scoped
from src.core.database import get_db
from src.core.target_guard import ScopeViolation, validate_hostname
from src.models.company import Company
from src.schemas.company import CompanyResponse

router = APIRouter(prefix="/companies", tags=["Companies"])


class CompanyCreate(BaseModel):
    # extra="forbid": sin esto el cliente puede colar tenant_id o id en el body
    # y crear registros a nombre de otro tenant.
    model_config = ConfigDict(extra="forbid")

    name: str = Field(..., min_length=1, max_length=255)
    domain: str = Field(..., min_length=4, max_length=253)
    industry: str | None = Field(default=None, max_length=100)
    location: dict | None = None


@router.post("/", response_model=CompanyResponse, status_code=status.HTTP_201_CREATED)
async def create_company(
    payload: CompanyCreate,
    db: AsyncSession = Depends(get_db),
    ctx: AuthContext = Depends(require(Scope.WRITE)),
):
    # El guard corre antes de tocar la base.
    try:
        host = validate_hostname(payload.domain)
    except ScopeViolation as e:
        raise HTTPException(422, detail=f"Dominio fuera de alcance: {e.reason}")

    company = Company(
        name=payload.name,
        domain=host,
        industry=payload.industry,
        location=payload.location,
        tenant_id=ctx.tenant_id,   # del contexto, NUNCA del payload
    )
    db.add(company)
    try:
        await db.commit()
    except IntegrityError:
        # v1 hacia check-then-insert: dos requests simultaneos pasaban el check
        # y el segundo reventaba con 500. Ahora lo resuelve la restriccion.
        await db.rollback()
        stmt = scoped(select(Company).where(Company.domain == host), Company, ctx)
        existing = (await db.execute(stmt)).scalar_one()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,   # 409, no 400: el payload es valido
            detail={"message": "Dominio ya registrado", "company_id": str(existing.id)},
        )

    await db.refresh(company)
    return company


@router.get("/", response_model=list[CompanyResponse])
async def list_companies(
    db: AsyncSession = Depends(get_db),
    ctx: AuthContext = Depends(require(Scope.READ)),
):
    stmt = scoped(select(Company).order_by(Company.created_at.desc()), Company, ctx)
    return (await db.execute(stmt)).scalars().all()


@router.get("/{company_id}", response_model=CompanyResponse)
async def get_company(
    company_id: UUID,
    db: AsyncSession = Depends(get_db),
    ctx: AuthContext = Depends(require(Scope.READ)),
):
    stmt = scoped(select(Company).where(Company.id == company_id), Company, ctx)
    company = (await db.execute(stmt)).scalar_one_or_none()
    if not company:
        # 404 y no 403: no se revela que el recurso existe en otro tenant.
        raise HTTPException(404, detail="Compania no encontrada")
    return company