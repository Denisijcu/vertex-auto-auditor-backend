from pydantic import BaseModel, HttpUrl, Field
from uuid import UUID
from datetime import datetime
from typing import Optional, Dict, Any, Literal


class CompanyBase(BaseModel):
    name: str = Field(..., max_length=255, examples=["DentiaPro Logistics"])
    domain: str = Field(..., examples=["dentiapro.com"])
    industry: Optional[str] = Field(default=None, max_length=100)
    location: Optional[Dict[str, Any]] = Field(default=None)

    # 'website' (HTML, se renderiza en navegador) | 'api' (JSON, la consume un
    # cliente). Se DECLARA al registrar, no se infiere del content-type.
    # Literal en vez de str: la API rechaza cualquier otro valor con un error
    # claro en lugar de guardar basura.
    target_type: Literal["website", "api"] = Field(
        default="website",
        description="'website' para sitios HTML, 'api' para endpoints JSON. "
                    "Con 'api' no se evaluan los checks que asumen un navegador.",
    )


class CompanyCreate(CompanyBase):
    pass


class CompanyResponse(CompanyBase):
    id: UUID
    created_at: datetime

    class Config:
        from_attributes = True

        