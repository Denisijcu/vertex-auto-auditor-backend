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
    # alembic_version desincronizada y no altera tablas existentes (una columna
    # nueva reventaba en runtime). Las migraciones se corren como paso previo.
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


@app.get("/health", tags=["Infrastructure"])
async def liveness():
    """Liveness: el proceso responde. No toca dependencias."""
    return {"status": "ok", "version": settings.VERSION}


@app.get("/ready", tags=["Infrastructure"])
async def readiness():
    """Readiness: las dependencias estan disponibles. Es la que debe mirar el
    orquestador. El /health de v1 devolvia mcp_ready=True literal y 200 aunque
    Postgres estuviera caido."""
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