"""
Jerarquia de agentes corregida.

v1 tenia ReportAgent heredando de BaseAgent y lanzando NotImplementedError
en `analyze` -> violacion de Liskov. Aqui son dos abstracciones distintas.
"""
from __future__ import annotations

from abc import ABC, abstractmethod

from src.schemas.finding import AuditReport, Finding
from src.schemas.recon import ReconResult


class ScanAgent(ABC):
    """Analiza un ReconResult y emite hallazgos. No puntua, no consolida."""

    name: str
    agent_type: str
    check_prefixes: tuple[str, ...]

    @abstractmethod
    async def analyze(self, recon: ReconResult) -> list[Finding]:
        ...


class Consolidator(ABC):
    """Toma hallazgos de N agentes y produce el reporte final."""

    @abstractmethod
    async def consolidate(
        self, recon: ReconResult, findings_by_agent: dict[str, list[Finding]]
    ) -> AuditReport:
        ...