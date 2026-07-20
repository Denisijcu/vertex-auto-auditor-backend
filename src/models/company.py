
import uuid
from sqlalchemy import Column, String, DateTime
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from src.core.database import Base

from src.models.audit_task import AuditTask

class Company(Base):
    __tablename__ = "companies"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False)
    domain = Column(String(255), nullable=False, unique=True, index=True)
    industry = Column(String(100), nullable=True)
    location = Column(JSONB, nullable=True)  # {"city": "Miami", "coordinates": {...}}
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    # Relaciones
    tasks = relationship("AuditTask", back_populates="company", cascade="all, delete-orphan")
    reports = relationship("AuditReport", back_populates="company", cascade="all, delete-orphan")