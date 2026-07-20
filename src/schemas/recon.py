"""
Modelos tipados del reconocimiento OSINT.

REGLA CENTRAL DE VERTEX AUTO-AUDITOR:
    Ausencia de dato != ausencia de problema.

Ningun agente puede volver a hacer `raw_data.get("campo", default)`.
Si un check no se pudo ejecutar, su status es NOT_ASSESSED y NO puntua.
"""
from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class CheckStatus(str, Enum):
    """Tri-estado obligatorio. Nunca booleano."""
    PASS = "pass"                  # se midio y esta bien
    FAIL = "fail"                  # se midio y esta mal
    NOT_ASSESSED = "not_assessed"  # no se pudo medir -> NO puntua


class Check(BaseModel):
    """Resultado atomico de una comprobacion. Autocontenido y auditable."""
    model_config = ConfigDict(extra="forbid")

    id: str = Field(..., description="Identificador estable, ej. 'http.header.csp'")
    title: str
    status: CheckStatus
    evidence: dict[str, Any] = Field(
        default_factory=dict,
        description="Lo que se observo en crudo. Sin esto el hallazgo no es verificable.",
    )
    error: str | None = Field(
        default=None,
        description="Motivo por el que no se pudo evaluar. Obligatorio si NOT_ASSESSED.",
    )
    source: str = Field(
        default="active-http",
        description="De donde salio el dato: dns, tls, active-http, shodan, crtsh...",
    )
    observed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def assessed(self) -> bool:
        return self.status is not CheckStatus.NOT_ASSESSED


class ReconResult(BaseModel):
    """
    Salida completa del ScraperService. Contrato unico entre recon y agentes.

    Los agentes reciben ESTO, no un dict. Si un campo no existe, es un
    AttributeError en tiempo de desarrollo, no un default silencioso en produccion.
    """
    model_config = ConfigDict(extra="forbid")

    target: str
    resolved_ips: list[str] = Field(default_factory=list)
    checks: list[Check] = Field(default_factory=list)
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    finished_at: datetime | None = None

    # --- helpers de consulta ---

    def get(self, check_id: str) -> Check | None:
        for c in self.checks:
            if c.id == check_id:
                return c
        return None

    def by_prefix(self, prefix: str) -> list[Check]:
        return [c for c in self.checks if c.id.startswith(prefix)]

    @property
    def assessed_checks(self) -> list[Check]:
        return [c for c in self.checks if c.assessed]

    @property
    def coverage(self) -> float:
        """Fraccion de checks que realmente se pudieron ejecutar. 0.0 - 1.0"""
        if not self.checks:
            return 0.0
        return len(self.assessed_checks) / len(self.checks)

    @property
    def coverage_label(self) -> str:
        return f"{len(self.assessed_checks)}/{len(self.checks)} checks ejecutados"


class Coverage(BaseModel):
    """Bloque de cobertura que va SIEMPRE en el reporte final."""
    model_config = ConfigDict(extra="forbid")

    total_checks: int
    assessed: int
    not_assessed: int
    ratio: float
    reliable: bool = Field(
        ...,
        description="False si ratio < 0.7. Un reporte no fiable no se firma ni se factura.",
    )
    not_assessed_detail: list[dict[str, str]] = Field(default_factory=list)

    @classmethod
    def from_recon(cls, recon: ReconResult, threshold: float = 0.7) -> "Coverage":
        na = [c for c in recon.checks if not c.assessed]
        return cls(
            total_checks=len(recon.checks),
            assessed=len(recon.assessed_checks),
            not_assessed=len(na),
            ratio=round(recon.coverage, 3),
            reliable=recon.coverage >= threshold,
            not_assessed_detail=[
                {"id": c.id, "title": c.title, "reason": c.error or "desconocido"}
                for c in na
            ],
        )