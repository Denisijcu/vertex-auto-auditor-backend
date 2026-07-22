"""
Motor de scoring: vertex-severity-v1

Reemplaza los `score -= 5` sueltos. La formula es publicable y defendible
ante un cliente que pregunte "por que 72 y no 80".

    penalizacion_bruta = sum(peso(severidad_i) for i in hallazgos)
    score              = max(0, 100 - penalizacion_bruta)

Los pesos derivan de rangos CVSS v3.1:
    critical 9.0-10.0 -> 40
    high     7.0-8.9  -> 20
    medium   4.0-6.9  -> 10
    low      0.1-3.9  -> 3
    info     0.0      -> 0

REGLA DE COBERTURA: si menos del 70% de los checks de una categoria se
pudieron ejecutar, el score es None. No se publica un numero calculado
sobre datos que no existen.

SUELO EN 0: el score se limita a 0 por abajo. Eso hace que dos sitios muy
distintos (129 y 300 de penalizacion) muestren el mismo numero, y que un
cliente que arregla la mitad de sus problemas no vea ningun avance. Por eso
se reporta ademas `raw_penalty`, que si se mueve: es la metrica de progreso
entre auditorias consecutivas.
"""
from __future__ import annotations

from src.schemas.finding import Finding, Severity
from src.schemas.recon import CheckStatus, ReconResult

SCORING_VERSION = "vertex-severity-v1"
COVERAGE_THRESHOLD = 0.7

SEVERITY_WEIGHTS: dict[Severity, int] = {
    Severity.CRITICAL: 40,
    Severity.HIGH: 20,
    Severity.MEDIUM: 10,
    Severity.LOW: 3,
    Severity.INFO: 0,
}


def category_coverage(recon: ReconResult, check_prefixes: tuple[str, ...]) -> tuple[int, int]:
    """Devuelve (evaluados, total) de los checks que pertenecen a una categoria."""
    relevant = [c for c in recon.checks if c.id.startswith(check_prefixes)]
    assessed = [c for c in relevant if c.status is not CheckStatus.NOT_ASSESSED]
    return len(assessed), len(relevant)


def raw_penalty(findings: list[Finding]) -> int:
    """Penalizacion SIN el suelo en 0.

    Es lo unico que permite mostrar progreso cuando el score esta clavado en
    0: si el cliente arregla dos cabeceras, el score no se mueve pero esto
    baja de 129 a 109.
    """
    return sum(SEVERITY_WEIGHTS[f.severity] for f in findings)


def compute_score(
    findings: list[Finding],
    assessed: int,
    total: int,
    threshold: float = COVERAGE_THRESHOLD,
) -> int | None:
    """
    None si la cobertura es insuficiente. Un None obliga a la UI a mostrar
    "cobertura insuficiente" en vez de un numero verde enganoso.
    """
    if total == 0:
        return None
    if (assessed / total) < threshold:
        return None
    return max(0, 100 - raw_penalty(findings))


def verdict_for(security: int | None, optimization: int | None) -> str:
    if security is None or optimization is None:
        return "Cobertura insuficiente - auditoria no concluyente"
    worst = min(security, optimization)
    if worst < 50:
        return "Accion urgente requerida"
    if worst < 70:
        return "Accion requerida"
    if worst < 90:
        return "Mejoras recomendadas"
    return "Estado optimo"