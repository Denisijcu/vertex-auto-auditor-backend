from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from src.config import settings
from src.core.database import engine

# Importaciones de endpoints tradicionales
from src.routers import companies, reports 

# [MCP ROUTER] Importación absoluta desde la arquitectura agéntica
from src.api.v1 import mcp as mcp_api

# [HARDENING] Importamos la Base declarativa con los modelos registrados en el __init__
from src.models import Base 

# [MCP REGISTRATION] Forzar la carga de herramientas y recursos para activar los decoradores
import src.mcp.resources
import src.mcp.tools

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Manejador del ciclo de vida de Vertex Auto-Auditor.
    Gestiona la inicialización de recursos y la desconexión segura.
    """
    # [START-UP] Acciones al encender el servidor
    print(f"[VERTEX INFO] Inicializando {settings.PROJECT_NAME} en entorno: {settings.ENVIRONMENT}")
    
    # [DATABASE HARDENING] Forzar la creación de las tablas si no existen en Postgres (Async Engine)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    print("[VERTEX INFO] Infraestructura y tablas de base de datos verificadas/creadas con éxito.")
    
    yield
    
    # [SHUTDOWN] Acciones al apagar el servidor
    print("[VERTEX INFO] Cerrando recursos y liberando conexiones de base de datos...")
    await engine.dispose()

# Inicialización de FastAPI con metadatos OpenAPI 3.1
app = FastAPI(
    title=settings.PROJECT_NAME,
    version="0.1.0",
    description="Motor agéntico para auditoría automatizada de seguridad y optimización SaaS.",
    lifespan=lifespan
)

# Inclusión de Routers
app.include_router(companies.router)
app.include_router(reports.router)

# [MCP ROUTING] Registro del módulo en el árbol principal
app.include_router(mcp_api.router)

# Configuración de CORS estricta pero flexible para desarrollo (Netlify/Localhost)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Modificar en producción con los dominios oficiales de Vertex
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Endpoints base de verificación de salud (Health check)
@app.get("/health", tags=["Infrastructure"])
async def health_check():
    return {
        "status": "healthy",
        "project": settings.PROJECT_NAME,
        "mcp_ready": True
    }