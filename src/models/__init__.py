# src/models/__init__.py
from  src.core.database import Base  # O de donde importes tu declarative_base
from src.models.company import Company
from src.models.audit_task import AuditTask  # Asegúrate de importar el modelo que falta

__all__ = ["Base", "Company", "AuditTask"]