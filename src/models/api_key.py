"""
API key.

Del secreto solo se persiste el SHA-256. El prefijo se guarda en claro para
poder identificar la clave en la UI y en los logs sin exponer nada util.
"""
import uuid

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Index, String
from sqlalchemy.dialects.postgresql import ARRAY, UUID
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func

from src.core.database import Base


class ApiKey(Base):
    __tablename__ = "api_keys"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(
        UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False
    )
    name = Column(String(120), nullable=False)
    # Identificador publico. No permite reconstruir la clave.
    prefix = Column(String(16), nullable=False, index=True)
    # SHA-256 de la clave completa. Nunca se guarda el secreto en claro.
    key_hash = Column(String(64), nullable=False, unique=True)
    scopes = Column(ARRAY(String), nullable=False, default=list)
    is_active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    last_used_at = Column(DateTime(timezone=True), nullable=True)
    expires_at = Column(DateTime(timezone=True), nullable=True)

    tenant = relationship("Tenant", back_populates="api_keys")

    __table_args__ = (
        Index("ix_api_keys_prefix_active", "prefix", "is_active"),
    )