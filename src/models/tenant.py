"""
Tenant. Hoy solo existe el tenant por defecto (single-tenant operativo), pero
la tabla y las FK estan desde el dia uno para que activar multi-tenant no
requiera migracion con backfill ni revisar cada query existente.
"""
import uuid

from sqlalchemy import Boolean, Column, DateTime, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from src.core.database import Base

DEFAULT_TENANT_ID = uuid.UUID("00000000-0000-0000-0000-000000000001")


class Tenant(Base):
    __tablename__ = "tenants"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False)
    slug = Column(String(100), nullable=False, unique=True, index=True)
    is_active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    api_keys = relationship("ApiKey", back_populates="tenant", cascade="all, delete-orphan")