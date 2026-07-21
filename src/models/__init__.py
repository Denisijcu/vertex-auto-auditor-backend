"""
Registro central de modelos.

Todo modelo debe importarse aqui. SQLAlchemy resuelve las relaciones por
nombre de clase al configurar los mappers, asi que un modelo no importado
hace fallar cualquier relationship que lo referencie.

AuditReport faltaba: funcionaba solo porque routers/reports.py lo importaba
antes por casualidad.
"""
from src.core.database import Base

from src.models.tenant import Tenant
from src.models.api_key import ApiKey
from src.models.company import Company
from src.models.audit_task import AuditTask
from src.models.audit_report import AuditReport

__all__ = [
    "Base",
    "Tenant",
    "ApiKey",
    "Company",
    "AuditTask",
    "AuditReport",
]