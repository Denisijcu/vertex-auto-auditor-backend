from pydantic import BaseModel, Field
from uuid import UUID
from datetime import datetime
from typing import Optional, Dict, Any

class AuditReportResponse(BaseModel):
    id: UUID
    company_id: UUID
    security_score: int = Field(ge=0, le=100)
    optimization_score: int = Field(ge=0, le=100)
    findings: Dict[str, Any]
    pdf_url: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True