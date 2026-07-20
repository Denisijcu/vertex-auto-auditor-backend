from src.mcp.server import mcp_server
from src.core.database import AsyncSessionLocal
from src.models.company import Company
from src.models.audit_task import AuditTask
from sqlalchemy import select
from typing import Dict, Any

@mcp_server.register_tool(
    name="trigger_audit",
    description="Inicializa un escaneo pasivo de salud técnica para un dominio y un sector comercial específico."
)
async def trigger_audit(domain: str, name: str, industry: str) -> Dict[str, Any]:
    async with AsyncSessionLocal() as session:
        # Verificar si existe el dominio
        result = await session.execute(select(Company).where(Company.domain == domain))
        company = result.scalar_one_or_none()
        
        if not company:
            company = Company(name=name, domain=domain, industry=industry)
            session.add(company)
            await session.flush() # Obtener ID asignado sin cerrar transacción
            
        # Generar las subtareas agénticas iniciales
        task_sec = AuditTask(company_id=company.id, agent_type="SECURITY_OSINT", status="PENDING")
        task_opt = AuditTask(company_id=company.id, agent_type="SEO_VISIBILITY", status="PENDING")
        session.add_all([task_sec, task_opt])
        await session.commit()
        
        return {
            "status": "QUEUED",
            "company_id": str(company.id),
            "message": f"Flujos de auditoría agéntica en cola para el dominio: {domain}"
        }