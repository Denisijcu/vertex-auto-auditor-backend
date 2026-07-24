"""Configuracion global. Los defaults son los de PRODUCCION, no los de desarrollo."""
from __future__ import annotations

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    PROJECT_NAME: str = Field(default="Vertex Auto-Auditor SaaS")
    VERSION: str = Field(default="0.3.0")

    # development | staging | production
    ENVIRONMENT: str = Field(default="production")

    # CAMBIO IMPORTANTE: antes el default era True. Si la variable falta en
    # Railway, la app arrancaba en produccion con echo=True y SQLAlchemy
    # logueaba cada consulta con sus parametros. Un default inseguro solo se
    # nota cuando ya se filtro algo.
    DEBUG: bool = Field(default=False)

    DATABASE_URL: str = Field(..., validation_alias="DATABASE_URL")
    DB_POOL_SIZE: int = Field(default=5)
    DB_MAX_OVERFLOW: int = Field(default=5)

    # Lista explicita. NUNCA "*" junto con allow_credentials: Starlette refleja
    # el Origin del atacante y se convierte en CSRF.
    CORS_ORIGINS: str = Field(default="http://localhost:4200")

    OPENAI_API_KEY: str | None = Field(default=None)
    ANTHROPIC_API_KEY: str | None = Field(default=None)

    # ---- Cola de trabajos ----
    REDIS_URL: str = Field(default="redis://redis:6379")
    # Auditorias concurrentes por worker. Es el backpressure que
    # BackgroundTasks no tenia.
    WORKER_CONCURRENCY: int = Field(default=5)
    # Cota superior por trabajo: un target que cuelga no ocupa un slot para siempre.
    WORKER_JOB_TIMEOUT: int = Field(default=180)
    WORKER_MAX_TRIES: int = Field(default=3)

    # Directorio de PDFs generados. Debe ser un volumen persistente: si vive
    # solo en la capa del contenedor, los reportes desaparecen en cada deploy.
    REPORTS_DIR: str = Field(default="/app/reports")

    MCP_SERVER_NAME: str = Field(default="vertex-auditor-mcp")
    MCP_SERVER_VERSION: str = Field(default="0.3.0")

    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )

    @field_validator("ENVIRONMENT")
    @classmethod
    def _valid_env(cls, v: str) -> str:
        v = v.lower().strip()
        if v not in ("development", "staging", "production"):
            raise ValueError(f"ENVIRONMENT invalido: {v}")
        return v

    @field_validator("DATABASE_URL")
    @classmethod
    def _async_driver(cls, v: str) -> str:
        """Normaliza el esquema al driver asincrono.

        Railway inyecta DATABASE_URL con `postgresql://`, que es lo que espera
        psycopg. SQLAlchemy en modo asyncio necesita el driver explicito, y sin
        esto el arranque falla con "The asyncio extension requires an async
        driver". Se reescribe aqui en vez de obligar a recordar el formato
        correcto en cada entorno.

        El primer `if` cubre el esquema `postgres://` heredado que algunos
        proveedores todavia inyectan.
        """
        v = v.strip()
        if v.startswith("postgres://"):
            v = v.replace("postgres://", "postgresql://", 1)
        if v.startswith("postgresql://"):
            v = v.replace("postgresql://", "postgresql+asyncpg://", 1)
        return v

    @property
    def is_production(self) -> bool:
        return self.ENVIRONMENT == "production"

    @property
    def cors_origins_list(self) -> list[str]:
        return [o.strip() for o in self.CORS_ORIGINS.split(",") if o.strip()]


settings = Settings()

# Falla al arrancar, no en el primer request: un despliegue roto es preferible
# a uno que corre filtrando credenciales en los logs.
if settings.is_production:
    if settings.DEBUG:
        raise RuntimeError("DEBUG=true en produccion: SQLAlchemy loguearia credenciales")
    if "*" in settings.cors_origins_list:
        raise RuntimeError("CORS_ORIGINS='*' en produccion no esta permitido")