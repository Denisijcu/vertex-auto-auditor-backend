"""
AuditReport — scores ahora nullable.

Antes: `nullable=False, default=100`. Ese default significaba que un reporte
sin datos se guardaba como 100/100. NULL = "no se pudo determinar", que es
informacion distinta de 0 y distinta de 100.
"""
import uuid

from sqlalchemy import Column, DateTime, ForeignKey, Index, Integer, String
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from src.core.database import Base


class AuditReport(Base):
    __tablename__ = "audit_reports"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    company_id = Column(
        UUID(as_uuid=True),
        ForeignKey("companies.id", ondelete="CASCADE"),
        nullable=False,
    )
    # NULL = cobertura insuficiente, no evaluable. Nunca asumir 100.
    security_score = Column(Integer, nullable=True)
    optimization_score = Column(Integer, nullable=True)
    findings = Column(JSONB, nullable=False)
    pdf_url = Column(String(512), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    company = relationship("Company", back_populates="reports")

    __table_args__ = (
        # La consulta caliente es "ultimo reporte de esta compania"
        Index("ix_audit_reports_company_created", "company_id", created_at.desc()),
    )