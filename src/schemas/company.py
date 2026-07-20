from pydantic import BaseModel, HttpUrl, Field
from uuid import UUID
from datetime import datetime
from typing import Optional, Dict, Any

class CompanyBase(BaseModel):
    name: str = Field(..., max_length=255, examples=["DentiaPro Logistics"])
    domain: str = Field(..., examples=["dentiapro.com"])
    industry: Optional[str] = Field(default=None, max_length=100)
    location: Optional[Dict[str, Any]] = Field(default=None)

class CompanyCreate(CompanyBase):
    pass

class CompanyResponse(CompanyBase):
    id: UUID
    created_at: datetime

    class Config:
        from_attributes = True