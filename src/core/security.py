
import os
from datetime import datetime, timedelta, timezone
from typing import Any
from fastapi import HTTPException, Security, status
from fastapi.security import APIKeyHeader
from jose import JWTError, jwt
from passlib.context import CryptContext

# Contexto de hashing para contraseñas (Estándar de Vertex Coders para almacenamiento seguro)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Configuración de Seguridad Pasiva (Por ejemplo, tokens para endpoints restringidos o webhooks)
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "vertex_default_super_secret_key_change_in_production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# Cabecera esperada para llamadas internas entre nodos o SDK mediante API Key
API_KEY_NAME = "X-Vertex-Auth"
api_key_header = API_KEY_HEADER = API_KEYHeader(name=API_KEY_NAME, auto_error=False)
VERTEX_INTERNAL_KEY = os.getenv("VERTEX_INTERNAL_KEY", "vertex-internal-secret-token")

def hash_password(password: str) -> str:
    """Genera el hash seguro de una contraseña."""
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifica si una contraseña en texto plano coincide con el hash almacenado."""
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    """Genera un token JWT firmado criptográficamente para sesiones de API."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def verify_internal_node_key(api_key: str = Security(api_key_header)) -> str:
    """
    Dependency Injection para FastAPI.
    Valida que las peticiones entrantes de los nodos de scrapeo o del SDK 
    posean la API Key interna correcta para evitar accesos no autorizados.
    """
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Falta la cabecera de autenticación X-Vertex-Auth."
        )
    if api_key != VERTEX_INTERNAL_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciales de Vertex invalidas o expiradas."
        )
    return api_key