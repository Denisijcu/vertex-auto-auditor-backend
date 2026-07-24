"""Punto de entrada."""
from __future__ import annotations

import logging
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import text

from src.config import settings
from src.core.database import engine
from src.core.queue import close_queue, init_queue, queue_healthy
from src.mcp.server import mcp_server
from src.routers import companies, mcp_router, reports

logging.basicConfig(
    level=logging.DEBUG if settings.DEBUG else logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
    force=True,   # uvicorn ya instalo handlers; sin force cada log sale dos veces
)
logger = logging.getLogger("vertex")


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("startup env=%s version=%s", settings.ENVIRONMENT, settings.VERSION)
    # Base.metadata.create_all ELIMINADO a proposito: pisaba Alembic, dejaba
    # alembic_version desincronizada y no altera tablas existentes.
    async with engine.connect() as conn:
        await conn.execute(text("SELECT 1"))
    await init_queue()
    logger.info("database ok, tools=%d resources=%d",
                len(mcp_server.tools), len(mcp_server.resources))
    yield
    logger.info("shutdown")
    await close_queue()
    await engine.dispose()


app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Motor de auditoria OSINT de superficie publica.",
    lifespan=lifespan,
    # En produccion el Swagger es un mapa del ataque: se cierra.
    docs_url=None if settings.is_production else "/docs",
    redoc_url=None if settings.is_production else "/redoc",
    openapi_url=None if settings.is_production else "/openapi.json",
)


# Rutas que sirven HTML y necesitan cargar recursos externos. La politica
# estricta de abajo las romperia.
_HTML_PATHS = ("/docs", "/redoc", "/openapi.json")


@app.middleware("http")
async def security_headers(request: Request, call_next):
    """Cabeceras de seguridad en toda respuesta.

    Una API JSON no renderiza nada en el navegador, asi que la politica puede
    ser mas estricta que la de un sitio web: `default-src 'none'` porque este
    servicio no sirve ningun recurso.

    Se exceptua Swagger, que si es HTML y carga JS y CSS de un CDN. En
    produccion esas rutas estan cerradas y la excepcion no aplica.
    """
    response = await call_next(request)

    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    # HSTS solo tiene sentido sobre HTTPS. En local sobre http es ruido.
    if settings.is_production:
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )

    if not request.url.path.startswith(_HTML_PATHS):
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
        )

    return response


app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=False,  # autenticamos por header, no por cookie
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
    allow_headers=["Authorization", "Content-Type", "X-API-Key"],
)

app.include_router(companies.router)
app.include_router(reports.router)
app.include_router(mcp_router.router)


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    """Traceback al log con un id; al cliente solo le llega el id.
    Sin esto, str(e) expone nombres de tablas, columnas y rutas del sistema."""
    error_id = uuid.uuid4().hex[:12]
    logger.exception("unhandled id=%s %s %s", error_id, request.method, request.url.path)
    return JSONResponse(
        status_code=500,
        content={"error_id": error_id, "detail": "Error interno del servidor"},
    )


@app.get("/", tags=["Infrastructure"])
async def root():
    """Identifica el servicio.

    Sin esta ruta, FastAPI devuelve 404 en la raiz. Para un cliente HTTP eso
    es indistinguible de un servicio caido o mal desplegado, y cualquier
    monitor externo —incluido este mismo auditor— lo reporta como hallazgo
    critico. Una API debe decir que es al ser preguntada.
    """
    return {
        "service": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "description": "Motor de auditoria OSINT de superficie publica",
        "vendor": "Vertex Coders LLC",
        "health": "/health",
        "ready": "/ready",
        "docs": None if settings.is_production else "/docs",
    }


@app.get("/health", tags=["Infrastructure"])
async def liveness():
    """Liveness: el proceso responde. No toca dependencias."""
    return {"status": "ok", "version": settings.VERSION}


@app.get("/ready", tags=["Infrastructure"])
async def readiness():
    """Readiness: las dependencias estan disponibles. Es la que debe mirar el
    orquestador."""
    checks: dict = {}
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        checks["database"] = "ok"
    except Exception:
        logger.exception("readiness: database down")
        checks["database"] = "down"

    checks["queue"] = "ok" if await queue_healthy() else "down"
    checks["mcp_tools"] = len(mcp_server.tools)
    checks["mcp_resources"] = len(mcp_server.resources)

    # tools == 0 delata que los decoradores no se registraron: fallo silencioso
    # clasico del registro por import con efecto secundario.
    healthy = (checks["database"] == "ok" and checks["queue"] == "ok"
               and checks["mcp_tools"] > 0)
    if not healthy:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, detail=checks)
    return checks