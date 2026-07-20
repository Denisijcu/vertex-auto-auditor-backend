from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, Field
from typing import Dict, Any, List
from src.mcp.server import mcp_server

# Asegurar que las herramientas y recursos se carguen al importar el router
import src.mcp.resources
import src.mcp.tools

router = APIRouter(prefix="/mcp", tags=["Model Context Protocol"])

class ToolExecutionRequest(BaseModel):
    name: str = Field(..., description="Nombre exacto de la herramienta MCP a ejecutar")
    arguments: Dict[str, Any] = Field(default_factory=dict, description="Payload de argumentos pasados a la función")

@router.get("/tools", response_model=List[Dict[str, Any]])
async def list_mcp_tools():
    """Muestra todas las herramientas de automatización disponibles para el LLM."""
    return await mcp_server.list_tools()

@router.get("/resources", response_model=List[Dict[str, Any]])
async def list_mcp_resources():
    """Muestra todas las fuentes de datos estructuradas que el LLM puede leer."""
    return await mcp_server.list_resources()

@router.get("/resources/lookup")
async def read_mcp_resource(uri: str):
    """
    Resuelve y lee un recurso dinámico del sistema mediante su URI estructurada.
    Ejemplo: uri=auditor://companies/47fa24ce-f2ad-4a11-bd0b-748d5589939e/latest-report
    """
    try:
        return await mcp_server.read_resource(uri)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Fallo en la resolución del recurso: {str(e)}")

@router.post("/tools/execute")
async def execute_mcp_tool(payload: ToolExecutionRequest):
    """
    Punto de entrada único para la ejecución agéntica de herramientas.
    El LLM envía el nombre de la tool y sus parámetros deducidos.
    """
    try:
        result = await mcp_server.execute_tool(payload.name, payload.arguments)
        return {"success": True, "result": result}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        # Hardening: No filtrar trazas de error crudas de la DB al cliente en producción
        raise HTTPException(status_code=500, detail=f"Error interno ejecutando la Tool MCP: {str(e)}")