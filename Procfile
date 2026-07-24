web: uvicorn src.main:app --host 0.0.0.0 --port $PORT
worker: arq src.workers.settings.WorkerSettings
release: alembic upgrade head