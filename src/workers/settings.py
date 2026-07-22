"""
Configuracion del worker ARQ.

    arq src.workers.settings.WorkerSettings
"""
from __future__ import annotations

import logging

from arq.connections import RedisSettings

from src.config import settings
from src.core.database import engine
from src.workers.tasks import run_audit

logging.basicConfig(
    level=logging.DEBUG if settings.DEBUG else logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
    force=True,   # sin esto los handlers se duplican y cada log sale dos veces
)
logger = logging.getLogger("vertex.worker")


async def startup(ctx: dict) -> None:
    logger.info("worker up env=%s concurrency=%s",
                settings.ENVIRONMENT, settings.WORKER_CONCURRENCY)


async def shutdown(ctx: dict) -> None:
    logger.info("worker down")
    await engine.dispose()


class WorkerSettings:
    functions = [run_audit]
    on_startup = startup
    on_shutdown = shutdown
    redis_settings = RedisSettings.from_dsn(settings.REDIS_URL)

    # Limita cuantas auditorias corren a la vez. Es el backpressure que
    # BackgroundTasks no tenia: sin esto, 500 disparos abren 500 corrutinas.
    max_jobs = settings.WORKER_CONCURRENCY

    # Cota superior por trabajo. Un target que cuelga no puede ocupar un slot
    # indefinidamente.
    job_timeout = settings.WORKER_JOB_TIMEOUT

    max_tries = settings.WORKER_MAX_TRIES
    keep_result = 3600          # resultados consultables durante 1 hora
    health_check_interval = 30