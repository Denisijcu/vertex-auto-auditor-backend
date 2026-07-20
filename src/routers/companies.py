
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from src.core.database import get_db
from src.models.company import Company
from src.schemas.company import CompanyCreate, CompanyResponse
from typing import List

router = APIRouter(prefix="/companies", tags=["Companies"])

@router.post("/", response_model=CompanyResponse, status_code=status.HTTP_201_CREATED)
async def create_company(payload: CompanyCreate, db: AsyncSession = Depends(get_db)):
    # Validar duplicados de dominio
    result = await db.execute(select(Company).where(Company.domain == payload.domain))
    if result.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="El dominio ya se encuentra registrado.")
        
    new_company = Company(**payload.model_dump())
    db.add(new_company)
    await db.commit()
    await db.refresh(new_company)
    return new_company

@router.get("/", response_model=List[CompanyResponse])
async def list_companies(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Company))
    return result.scalars().all()