
"""
Crea una API key. La clave completa se muestra UNA sola vez.

    docker compose -f docker/docker-compose.yml exec api \
        python -m src.scripts.create_api_key --name "cli-local" --scopes read write
"""
from __future__ import annotations

import argparse
import asyncio

from sqlalchemy import select

from src.core.auth import Scope, generate_api_key
from src.core.database import AsyncSessionLocal
from src.models.api_key import ApiKey
from src.models.tenant import DEFAULT_TENANT_ID, Tenant


async def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--name", required=True)
    ap.add_argument("--scopes", nargs="+", default=["read"],
                    choices=[s.value for s in Scope])
    ap.add_argument("--tenant", default=str(DEFAULT_TENANT_ID))
    args = ap.parse_args()

    full, prefix, key_hash = generate_api_key()

    async with AsyncSessionLocal() as session:
        tenant = (await session.execute(
            select(Tenant).where(Tenant.id == args.tenant))).scalar_one_or_none()
        if tenant is None:
            raise SystemExit(f"Tenant {args.tenant} no existe. Corre alembic upgrade head.")

        session.add(ApiKey(tenant_id=tenant.id, name=args.name,
                           prefix=prefix, key_hash=key_hash, scopes=args.scopes))
        await session.commit()

    print("\n" + "=" * 64)
    print("  API KEY CREADA - se muestra una sola vez, guardala ahora")
    print("=" * 64)
    print(f"  nombre : {args.name}")
    print(f"  tenant : {tenant.name}")
    print(f"  scopes : {', '.join(args.scopes)}")
    print(f"\n  {full}\n")
    print("  Uso:  curl -H 'X-API-Key: <clave>' localhost:8000/mcp/tools")
    print("=" * 64 + "\n")


if __name__ == "__main__":
    asyncio.run(main())