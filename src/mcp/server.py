"""
Servidor de herramientas y recursos.

Cambios frente a v1, todos derivados del mismo agujero:

    return await self.tools[name]["func"](**arguments)

Ese `**arguments` dejaba que el cliente controlara TODOS los parametros de
cualquier funcion registrada, sin auth y sin validacion. Mass assignment puro:
bastaba conocer el nombre de una tool para invocarla con lo que fuera.

Ahora:
  - Cada tool declara un `input_model` Pydantic con extra="forbid".
  - Cada tool declara un scope; el contexto decide si puede ejecutarla.
  - El AuthContext se inyecta por keyword, nunca sale del payload.
  - `read_resource` hace matching real del patron de URI (v1 ignoraba el
    patron y ejecutaba el primer recurso que cayera en un if).

NOTA: esto sigue sin ser Model Context Protocol. Es REST con la terminologia
prestada; no habla JSON-RPC 2.0 ni soporta el handshake `initialize`, asi que
los clientes MCP estandar no pueden conectarse. Migrar al SDK oficial esta en
la hoja de ruta.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Callable

from pydantic import BaseModel, ValidationError

from src.config import settings
from src.core.auth import AuthContext, Scope


class ToolNotFound(Exception):
    pass


class ResourceNotFound(Exception):
    pass


class ToolForbidden(Exception):
    def __init__(self, tool: str, scope: Scope):
        self.tool, self.scope = tool, scope
        super().__init__(f"La tool '{tool}' requiere el permiso '{scope.value}'")


class ToolInputInvalid(Exception):
    def __init__(self, tool: str, errors: list[dict]):
        self.tool, self.errors = tool, errors
        super().__init__(f"Argumentos invalidos para '{tool}'")


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    func: Callable
    input_model: type[BaseModel]
    scope: Scope


@dataclass(frozen=True)
class ResourceSpec:
    uri_pattern: str
    description: str
    func: Callable
    regex: re.Pattern
    scope: Scope


def _compile_uri(pattern: str) -> re.Pattern:
    """auditor://companies/{company_id}/latest-report -> regex con grupos."""
    parts = re.split(r"(\{\w+\})", pattern)
    out = "".join(
        f"(?P<{p[1:-1]}>[^/]+)" if p.startswith("{") and p.endswith("}") else re.escape(p)
        for p in parts
    )
    return re.compile(f"^{out}$")


class MCPServer:
    def __init__(self) -> None:
        self.name = settings.MCP_SERVER_NAME
        self.version = settings.MCP_SERVER_VERSION
        self.tools: dict[str, ToolSpec] = {}
        self.resources: dict[str, ResourceSpec] = {}

    # ------------------------------------------------------------- registro

    def register_tool(
        self,
        name: str,
        description: str,
        input_model: type[BaseModel],
        scope: Scope = Scope.WRITE,
    ):
        """input_model es OBLIGATORIO: sin el no hay forma de acotar argumentos
        ni de publicar el esquema que el LLM necesita para no alucinar el payload."""
        def decorator(func: Callable):
            self.tools[name] = ToolSpec(
                name=name, description=description, func=func,
                input_model=input_model, scope=scope,
            )
            return func
        return decorator

    def register_resource(
        self, uri_pattern: str, description: str, scope: Scope = Scope.READ
    ):
        def decorator(func: Callable):
            self.resources[uri_pattern] = ResourceSpec(
                uri_pattern=uri_pattern, description=description, func=func,
                regex=_compile_uri(uri_pattern), scope=scope,
            )
            return func
        return decorator

    # ----------------------------------------------------------- catalogos

    async def list_tools(self, ctx: AuthContext) -> list[dict[str, Any]]:
        """Solo se listan las tools que el contexto puede ejecutar: el catalogo
        no revela capacidades que la clave no tiene."""
        return [
            {
                "name": spec.name,
                "description": spec.description,
                "scope": spec.scope.value,
                # El esquema JSON es lo que permite al LLM construir el payload
                # correcto en vez de inventarlo.
                "input_schema": spec.input_model.model_json_schema(),
            }
            for spec in self.tools.values()
            if ctx.has(spec.scope)
        ]

    async def list_resources(self, ctx: AuthContext) -> list[dict[str, Any]]:
        return [
            {
                "uri_pattern": spec.uri_pattern,
                "description": spec.description,
                "scope": spec.scope.value,
            }
            for spec in self.resources.values()
            if ctx.has(spec.scope)
        ]

    # ---------------------------------------------------------- ejecucion

    async def execute_tool(
        self, name: str, arguments: dict[str, Any], *, ctx: AuthContext
    ) -> Any:
        spec = self.tools.get(name)
        if spec is None:
            raise ToolNotFound(name)
        if not ctx.has(spec.scope):
            raise ToolForbidden(name, spec.scope)

        try:
            validated = spec.input_model.model_validate(arguments or {})
        except ValidationError as e:
            raise ToolInputInvalid(name, e.errors(include_url=False)) from e

        # ctx va por keyword: la funcion no puede recibirlo desde el payload.
        return await spec.func(**validated.model_dump(), ctx=ctx)

    async def read_resource(self, uri: str, *, ctx: AuthContext) -> Any:
        for spec in self.resources.values():
            match = spec.regex.match(uri)
            if not match:
                continue
            if not ctx.has(spec.scope):
                raise ToolForbidden(spec.uri_pattern, spec.scope)
            return await spec.func(**match.groupdict(), ctx=ctx)
        raise ResourceNotFound(uri)


mcp_server = MCPServer()