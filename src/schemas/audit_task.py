
from pydantic import BaseModel
from uuid import UUID
from datetime import datetime
from typing import Optional, Dict, Any

class AuditTaskResponse(BaseModel):
    id: UUID
    company_id: UUID
    agent_type: str
    status: str
    raw_output: Optional[Dict[str, Any]] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None

    class Config:
        from_attributes = True