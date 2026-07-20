"""
Modelo estructurado de hallazgos.

Reemplaza `vulnerabilities: List[str]`. Sin evidencia un hallazgo no es
verificable por el cliente; sin ID estable no hay diff entre auditorias.
"""
from __future__ import annotations

from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Confidence(str, Enum):
    CONFIRMED = "confirmed"          # observado directamente
    PROBABLE = "probable"            # inferido de una firma o banner
    INFORMATIONAL = "informational"  # contexto, no afirma vulnerabilidad


class Finding(BaseModel):
    """
    Un hallazgo defendible ante un cliente.

    Todo Finding debe poder responder: que viste, donde, cual es el impacto
    y como se arregla. Si falta `evidence`, el hallazgo no se emite.
    """
    model_config = ConfigDict(extra="forbid")

    id: str = Field(..., description="ID estable de la regla, ej. VTX-HDR-001")
    check_id: str = Field(..., description="Check del que se deriva, ej. http.header.csp")
    title: str
    severity: Severity
    confidence: Confidence = Confidence.CONFIRMED
    asset: str = Field(..., description="Dominio, IP o endpoint afectado")
    description: str
    remediation: str
    evidence: dict[str, Any] = Field(default_factory=dict)
    cwe: str | None = Field(default=None, description="ej. CWE-693")
    owasp: str | None = Field(default=None, description="ej. A05:2021")
    category: Literal["security", "optimization"] = "security"


class AuditReport(BaseModel):
    """Payload consolidado que se persiste en `audit_reports.findings`."""
    model_config = ConfigDict(extra="forbid")

    target: str
    security_score: int | None = Field(
        None, description="None si la cobertura de seguridad fue insuficiente"
    )
    optimization_score: int | None = None
    verdict: str
    findings: list[Finding] = Field(default_factory=list)
    coverage: dict[str, Any]
    scoring_method: str = Field(
        default="vertex-severity-v1",
        description="Version de la formula de scoring, para trazabilidad entre auditorias",
    )

    @property
    def counts_by_severity(self) -> dict[str, int]:
        out = {s.value: 0 for s in Severity}
        for f in self.findings:
            out[f.severity.value] += 1
        return out