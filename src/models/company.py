import uuid
from sqlalchemy import Column, DateTime, ForeignKey, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from src.core.database import Base


class Company(Base):
    __tablename__ = "companies"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(
        UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    name = Column(String(255), nullable=False)
    # Sin unique global: el dominio es unico POR TENANT (ver __table_args__).
    # Dos clientes distintos pueden auditar el mismo dominio.
    domain = Column(String(255), nullable=False, index=True)
    industry = Column(String(100), nullable=True)

    # 'website' (HTML, se renderiza en navegador) | 'api' (JSON, la consume un
    # cliente). Se DECLARA al registrar, no se infiere del content-type:
    # inferir es adivinar, y un sitio roto tambien devuelve JSON. Con 'api',
    # los checks que asumen un navegador salen not_assessed en vez de disparar
    # un critico falso sobre un endpoint sano.
    target_type = Column(String(20), nullable=False, server_default="website")

    location = Column(JSONB, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    tasks = relationship("AuditTask", back_populates="company", cascade="all, delete-orphan")
    reports = relationship("AuditReport", back_populates="company", cascade="all, delete-orphan")

    __table_args__ = (
        UniqueConstraint("tenant_id", "domain", name="uq_companies_tenant_domain"),
    )