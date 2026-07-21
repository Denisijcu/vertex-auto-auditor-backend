"""
Router MCP. Toda ruta exige API key; los errores no filtran trazas internas.
"""
from __future__ import annotations

import logging
import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field

from src.core.auth import AuthContext, Scope, get_auth_context, require
from src.mcp.server import (
    ResourceNotFound, ToolForbidden, ToolInputInvalid, ToolNotFound, mcp_server,
)

# Cargar los decoradores de registro
import src.mcp.resources  # noqa: F401
import src.mcp.tools      # noqa: F401

logger = logging.getLogger("vertex.mcp")
router = APIRouter(prefix="/mcp", tags=["Model Context Protocol"])


class ToolExecutionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(..., max_length=100)
    arguments: dict[str, Any] = Field(default_factory=dict)


@router.get("/tools")
async def list_mcp_tools(ctx: AuthContext = Depends(get_auth_context)):
    return await mcp_server.list_tools(ctx)


@router.get("/resources")
async def list_mcp_resources(ctx: AuthContext = Depends(get_auth_context)):
    return await mcp_server.list_resources(ctx)


@router.get("/resources/lookup")
async def read_mcp_resource(
    uri: str = Query(..., max_length=500),
    ctx: AuthContext = Depends(require(Scope.READ)),
):
    try:
        return await mcp_server.read_resource(uri, ctx=ctx)
    except ResourceNotFound:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Recurso no encontrado")
    except ToolForbidden as e:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail=str(e))
    except Exception:
        error_id = uuid.uuid4().hex[:12]
        logger.exception("resource_error id=%s uri=%s key=%s", error_id, uri, ctx.key_name)
        raise HTTPException(500, detail={"error_id": error_id, "message": "Error interno"})


@router.post("/tools/execute")
async def execute_mcp_tool(
    payload: ToolExecutionRequest,
    ctx: AuthContext = Depends(get_auth_context),
):
    try:
        result = await mcp_server.execute_tool(payload.name, payload.arguments, ctx=ctx)
        return {"success": True, "result": result}
    except ToolNotFound:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Tool no registrada")
    except ToolForbidden as e:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail=str(e))
    except ToolInputInvalid as e:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            detail={"message": "Argumentos invalidos", "errors": e.errors})
    except Exception:
        # El traceback va al log con un id; al cliente solo le llega el id.
        # v1 devolvia str(e), que exponia nombres de tablas y columnas.
        error_id = uuid.uuid4().hex[:12]
        logger.exception("tool_error id=%s tool=%s key=%s",
                         error_id, payload.name, ctx.key_name)
        raise HTTPException(500, detail={"error_id": error_id, "message": "Error interno"})