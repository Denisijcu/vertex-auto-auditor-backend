
import uuid
from sqlalchemy import Column, String, DateTime, ForeignKey
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from src.core.database import Base

class AuditTask(Base):
    __tablename__ = "audit_tasks"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    company_id = Column(UUID(as_uuid=True), ForeignKey("companies.id", ondelete="CASCADE"), nullable=False)
    agent_type = Column(String(50), nullable=False)  # SECURITY_OSINT, SEO_VISIBILITY, INFRASTRUCTURE
    status = Column(String(50), nullable=False, default="PENDING")  # PENDING, RUNNING, COMPLETED, FAILED
    raw_output = Column(JSONB, nullable=True)
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)

    # Relación
    company = relationship("Company", back_populates="tasks")