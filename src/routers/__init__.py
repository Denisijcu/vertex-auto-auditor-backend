from .companies import router as companies_router
from .reports import router as reports_router
#from .mcp import router as mcp_router  # ← Agrega esta línea

# Si tienes un __all__, asegúrate de incluirlo:
__all__ = ["companies", "reports"]