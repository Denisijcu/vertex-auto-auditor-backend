import asyncio
from typing import Dict, Any, List
from src.config import settings

class MCPServer:
    """
    Servidor nativo Model Context Protocol (MCP) para Vertex Coders.
    Expone recursos dinámicos y herramientas (Tools) directo a nuestro SDK de IA.
    """
    def __init__(self):
        self.name = settings.MCP_SERVER_NAME
        self.version = settings.MCP_SERVER_VERSION
        self.tools = {}
        self.resources = {}

    def register_tool(self, name: str, description: str):
        def decorator(func):
            self.tools[name] = {"func": func, "description": description}
            return func
        return decorator

    def register_resource(self, uri_pattern: str, description: str):
        def decorator(func):
            self.resources[uri_pattern] = {"func": func, "description": description}
            return func
        return decorator

    async def list_tools(self) -> List[Dict[str, Any]]:
        """Devuelve el catálogo de herramientas listas para el LLM."""
        return [
            {"name": name, "description": data["description"]}
            for name, data in self.tools.items()
        ]

    async def list_resources(self) -> List[Dict[str, Any]]:
        """Devuelve el catálogo de recursos dinámicos expuestos."""
        return [
            {"uri_pattern": uri, "description": data["description"]}
            for uri, data in self.resources.items()
        ]

    async def read_resource(self, uri: str) -> Dict[str, Any]:
        """Resuelve dinámicamente el recurso solicitado mapeando variables de la URI."""
        # Búsqueda de coincidencia simple de patrones (ej. auditor://companies/{id}/latest-report)
        for pattern, data in self.resources.items():
            if "companies" in uri and "latest-report" in uri:
                # Extraer el UUID incrustado en la URI
                try:
                    parts = uri.split("/")
                    company_id = parts[3]  # Basado en auditor://companies/{company_id}/latest-report
                    return await data["func"](company_id=company_id)
                except Exception as e:
                    return {"error": f"Error parseando URI del recurso MCP: {str(e)}"}
        raise ValueError(f"Recurso MCP '{uri}' no encontrado.")

    async def execute_tool(self, name: str, arguments: Dict[str, Any]) -> Any:
        if name not in self.tools:
            raise ValueError(f"Tool {name} no registrada en el servidor MCP.")
        return await self.tools[name]["func"](**arguments)

mcp_server = MCPServer()