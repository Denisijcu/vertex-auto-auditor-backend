"""
Autenticacion por API key.

Modelo: single-tenant operativo, pero con tenant_id cableado desde el dia uno.
Hoy todas las keys pertenecen al tenant por defecto; el dia que entre un cliente
externo solo cambia como se resuelve el tenant_id en esta capa, no las queries.

Formato de clave:  vtx_<prefix:8>_<secret:43>
  - El prefijo se guarda en claro para poder identificar la clave en la UI y en
    los logs sin exponer el secreto.
  - Del secreto solo se persiste el SHA-256. Si la base se filtra, las claves no
    son utilizables.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from uuid import UUID

from fastapi import Depends, Header, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.database import get_db
from src.models.api_key import ApiKey

KEY_PREFIX = "vtx"
PREFIX_LEN = 8


class Scope(str, Enum):
    READ = "read"      # consultar companies y reportes
    WRITE = "write"    # crear companies, lanzar auditorias
    ADMIN = "admin"    # gestionar API keys


@dataclass(frozen=True)
class AuthContext:
    """Identidad resuelta de la peticion. Se inyecta, NUNCA viene del payload.

    Esta es la defensa central contra mass assignment: si el tenant_id saliera
    del cuerpo JSON, cualquiera auditaria en nombre de otro.
    """
    key_id: UUID
    tenant_id: UUID
    key_name: str
    scopes: frozenset[Scope]

    def has(self, scope: Scope) -> bool:
        return Scope.ADMIN in self.scopes or scope in self.scopes

    @property
    def can_read(self) -> bool:
        return self.has(Scope.READ)

    @property
    def can_write(self) -> bool:
        return self.has(Scope.WRITE)


def generate_api_key() -> tuple[str, str, str]:
    """Genera una clave nueva. Devuelve (clave_completa, prefijo, hash).

    La clave completa se muestra UNA sola vez al crearla. No se puede recuperar.
    """
    prefix = secrets.token_hex(PREFIX_LEN // 2)
    secret = secrets.token_urlsafe(32)
    full = f"{KEY_PREFIX}_{prefix}_{secret}"
    return full, prefix, hash_api_key(full)


def hash_api_key(full_key: str) -> str:
    return hashlib.sha256(full_key.encode("utf-8")).hexdigest()


def _parse_prefix(full_key: str) -> str | None:
    parts = full_key.split("_", 2)
    if len(parts) != 3 or parts[0] != KEY_PREFIX:
        return None
    return parts[1]


async def resolve_api_key(raw_key: str, db: AsyncSession) -> AuthContext:
    """Valida la clave y devuelve el contexto. Lanza 401 si no es valida."""
    unauthorized = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="API key invalida o expirada",
        headers={"WWW-Authenticate": "ApiKey"},
    )

    prefix = _parse_prefix(raw_key)
    if not prefix:
        raise unauthorized

    # El prefijo acota la busqueda; la comparacion real es sobre el hash.
    stmt = select(ApiKey).where(ApiKey.prefix == prefix, ApiKey.is_active.is_(True))
    candidate = (await db.execute(stmt)).scalar_one_or_none()
    if candidate is None:
        raise unauthorized

    # compare_digest: comparacion en tiempo constante, sin fuga por timing.
    if not hmac.compare_digest(candidate.key_hash, hash_api_key(raw_key)):
        raise unauthorized

    now = datetime.now(timezone.utc)
    if candidate.expires_at and candidate.expires_at < now:
        raise unauthorized

    candidate.last_used_at = now
    await db.commit()

    return AuthContext(
        key_id=candidate.id,
        tenant_id=candidate.tenant_id,
        key_name=candidate.name,
        scopes=frozenset(Scope(s) for s in (candidate.scopes or [])),
    )


async def get_auth_context(
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
    authorization: str | None = Header(default=None),
    db: AsyncSession = Depends(get_db),
) -> AuthContext:
    """Dependencia base. Acepta `X-API-Key: vtx_...` o `Authorization: Bearer vtx_...`."""
    raw = x_api_key
    if not raw and authorization and authorization.lower().startswith("bearer "):
        raw = authorization[7:].strip()

    if not raw:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Falta la cabecera X-API-Key",
            headers={"WWW-Authenticate": "ApiKey"},
        )
    return await resolve_api_key(raw, db)


def require(scope: Scope):
    """Dependencia parametrizada por scope.

    Uso:  ctx: AuthContext = Depends(require(Scope.WRITE))
    """
    async def _dep(ctx: AuthContext = Depends(get_auth_context)) -> AuthContext:
        if not ctx.has(scope):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"La API key no tiene el permiso '{scope.value}'",
            )
        return ctx
    return _dep


def scoped(stmt, model, ctx: AuthContext):
    """Filtra una query por el tenant del contexto.

    TODA consulta sobre datos de tenant pasa por aqui. Sin excepciones: un
    select() crudo es una fuga de datos entre clientes esperando a ocurrir.
    """
    return stmt.where(model.tenant_id == ctx.tenant_id)