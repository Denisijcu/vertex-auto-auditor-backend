
"""
Pool de Redis compartido para encolar trabajos desde la API.

Se crea una sola vez en el lifespan. Abrir una conexion por request es una
fuga de descriptores esperando a ocurrir.
"""
from __future__ import annotations

import logging

from arq import create_pool
from arq.connections import ArqRedis, RedisSettings

from src.config import settings

logger = logging.getLogger("vertex.queue")

_pool: ArqRedis | None = None


async def init_queue() -> None:
    global _pool
    _pool = await create_pool(RedisSettings.from_dsn(settings.REDIS_URL))
    logger.info("queue conectada")


async def close_queue() -> None:
    global _pool
    if _pool is not None:
        await _pool.aclose()
        _pool = None


def get_queue() -> ArqRedis:
    if _pool is None:
        raise RuntimeError("La cola no esta inicializada (falta init_queue en el lifespan)")
    return _pool


async def queue_healthy() -> bool:
    try:
        await get_queue().ping()
        return True
    except Exception:
        return False