"""
Comparacion entre dos auditorias del mismo objetivo.

Esto es lo que convierte un informe puntual en un servicio: no "esto tienes
mal hoy" sino "esto cambio desde la ultima vez". Los Finding ya tienen ID
estable (VTX-HDR-001...) y el payload lleva huella SHA-256, asi que las piezas
estaban; faltaba juntarlas.

TRES DECISIONES QUE DEFINEN EL RESULTADO
----------------------------------------

1. La huella se compara PRIMERO. Si dos auditorias del mismo objetivo producen
   el mismo hash canonico, nada cambio y no hace falta recorrer hallazgos. Es
   la respuesta mas util y la mas barata.

2. Un hallazgo que desaparece NO siempre es un hallazgo resuelto. Si el check
   que lo producia paso a `not_assessed`, el problema no se arreglo: dejo de
   medirse. Se distinguen como categorias separadas — confundirlas convierte
   una perdida de cobertura en una mejora aparente, que es exactamente la
   mentira que este motor existe para evitar.

3. Se compara `raw_penalty` ademas del score. Con el suelo en 0, un objetivo
   puede corregir cuatro hallazgos criticos y seguir marcando 0. La
   penalizacion bruta si se mueve, y es la unica forma de mostrar progreso
   cuando el score esta clavado.
"""
from __future__ import annotations

from typing import Any, Literal

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITY_ORDER)}


def _checks_by_status(payload: dict) -> dict[str, str]:
    """id de check -> estado. Vacio si el reporte es anterior a checks[]."""
    return {
        c.get("id", ""): c.get("status", "")
        for c in payload.get("checks", []) or []
    }


def _findings_by_id(payload: dict) -> dict[str, dict]:
    return {f["id"]: f for f in payload.get("findings", []) or []}


def _severity_counts(findings: list[dict]) -> dict[str, int]:
    out = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        sev = f.get("severity", "info")
        out[sev] = out.get(sev, 0) + 1
    return out


def _delta(new: int | None, old: int | None) -> int | None:
    if new is None or old is None:
        return None
    return new - old


def compare(
    previous: dict[str, Any],
    current: dict[str, Any],
    *,
    previous_meta: dict[str, Any] | None = None,
    current_meta: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Compara dos payloads de AuditReport del mismo objetivo.

    `previous` y `current` son el contenido de `audit_reports.findings`.
    `*_meta` lleva report_id y created_at para poder citar los informes.
    """
    prev_meta = previous_meta or {}
    curr_meta = current_meta or {}

    prev_f = _findings_by_id(previous)
    curr_f = _findings_by_id(current)
    prev_checks = _checks_by_status(previous)
    curr_checks = _checks_by_status(current)

    prev_ids, curr_ids = set(prev_f), set(curr_f)

    # --- Hallazgos que ya no aparecen -------------------------------------
    #
    # Se separan en dos categorias porque significan cosas opuestas:
    #   resolved    -> el check volvio a ejecutarse y ahora pasa
    #   unverifiable-> el check dejo de poder ejecutarse; no sabemos nada
    #
    # Meterlos juntos como "resueltos" convertiria una perdida de cobertura en
    # una mejora aparente.
    resolved: list[dict] = []
    unverifiable: list[dict] = []

    for fid in prev_ids - curr_ids:
        finding = prev_f[fid]
        check_id = finding.get("check_id", "")
        now_status = curr_checks.get(check_id)

        if now_status == "not_assessed":
            reason = next(
                (d.get("reason") for d in current.get("coverage", {}).get("not_assessed_detail", [])
                 if d.get("id") == check_id),
                "la comprobacion no se pudo ejecutar en esta auditoria",
            )
            unverifiable.append({
                "id": fid,
                "title": finding.get("title"),
                "severity": finding.get("severity"),
                "check_id": check_id,
                "reason": reason,
            })
        else:
            resolved.append({
                "id": fid,
                "title": finding.get("title"),
                "severity": finding.get("severity"),
                "check_id": check_id,
            })

    # --- Nuevos y persistentes --------------------------------------------
    new = [
        {"id": fid, "title": curr_f[fid].get("title"),
         "severity": curr_f[fid].get("severity"),
         "check_id": curr_f[fid].get("check_id")}
        for fid in curr_ids - prev_ids
    ]

    persisting: list[dict] = []
    for fid in prev_ids & curr_ids:
        old_sev = prev_f[fid].get("severity")
        new_sev = curr_f[fid].get("severity")
        entry = {
            "id": fid,
            "title": curr_f[fid].get("title"),
            "severity": new_sev,
            "check_id": curr_f[fid].get("check_id"),
        }
        # Una regla puede cambiar de severidad entre versiones del motor.
        if old_sev != new_sev:
            entry["severity_changed_from"] = old_sev
        persisting.append(entry)

    for group in (resolved, unverifiable, new, persisting):
        group.sort(key=lambda x: (SEVERITY_RANK.get(x.get("severity", "info"), 9), x["id"]))

    # --- Cobertura ---------------------------------------------------------
    prev_cov = previous.get("coverage", {}) or {}
    curr_cov = current.get("coverage", {}) or {}

    lost_checks = [
        cid for cid, st in curr_checks.items()
        if st == "not_assessed" and prev_checks.get(cid) not in (None, "not_assessed")
    ]
    gained_checks = [
        cid for cid, st in curr_checks.items()
        if st != "not_assessed" and prev_checks.get(cid) == "not_assessed"
    ]

    # --- Veredicto ---------------------------------------------------------
    same_fingerprint = (
        prev_meta.get("fingerprint")
        and prev_meta.get("fingerprint") == curr_meta.get("fingerprint")
    )

    if same_fingerprint:
        verdict = "sin_cambios"
        headline = "El contenido auditado es identico al de la auditoria anterior."
    elif new and any(f["severity"] in ("critical", "high") for f in new):
        verdict = "regresion"
        headline = "Aparecieron hallazgos nuevos de severidad alta o critica."
    elif new:
        verdict = "regresion_menor"
        headline = "Aparecieron hallazgos nuevos."
    elif resolved and not unverifiable:
        verdict = "mejora"
        headline = f"Se corrigieron {len(resolved)} hallazgos y no aparecieron nuevos."
    elif resolved and unverifiable:
        verdict = "mejora_parcial"
        headline = (
            f"Se corrigieron {len(resolved)} hallazgos, pero {len(unverifiable)} "
            f"dejaron de poder verificarse."
        )
    elif unverifiable:
        verdict = "cobertura_reducida"
        headline = (
            f"{len(unverifiable)} hallazgos dejaron de poder verificarse. "
            f"No se corrigieron: dejaron de medirse."
        )
    else:
        verdict = "estable"
        headline = "Los mismos hallazgos que en la auditoria anterior."

    sec_delta = _delta(current.get("security_score"), previous.get("security_score"))

    return {
        "target": current.get("target"),
        "verdict": verdict,
        "headline": headline,
        "same_fingerprint": bool(same_fingerprint),

        "previous": {
            "report_id": prev_meta.get("report_id"),
            "audited_at": prev_meta.get("created_at"),
            "security_score": previous.get("security_score"),
            "raw_penalty": previous.get("raw_penalty_security"),
            "findings_count": len(prev_ids),
            "coverage": {"assessed": prev_cov.get("assessed"),
                         "total": prev_cov.get("total_checks"),
                         "reliable": prev_cov.get("reliable")},
        },
        "current": {
            "report_id": curr_meta.get("report_id"),
            "audited_at": curr_meta.get("created_at"),
            "security_score": current.get("security_score"),
            "raw_penalty": current.get("raw_penalty_security"),
            "findings_count": len(curr_ids),
            "coverage": {"assessed": curr_cov.get("assessed"),
                         "total": curr_cov.get("total_checks"),
                         "reliable": curr_cov.get("reliable")},
        },

        "score_delta": sec_delta,
        # Con el suelo en 0 el score puede no moverse aunque se corrijan
        # hallazgos. Esta cifra si se mueve: es la metrica de progreso real.
        "penalty_delta": _delta(current.get("raw_penalty_security"),
                                previous.get("raw_penalty_security")),
        "score_note": (
            "Una o ambas auditorias no pudieron calcular puntuacion por "
            "cobertura insuficiente; la variacion no es comparable."
            if sec_delta is None else None
        ),

        "findings": {
            "new": new,
            "resolved": resolved,
            # Separado de `resolved` a proposito: no se arreglaron, dejaron de
            # poder medirse.
            "unverifiable": unverifiable,
            "persisting": persisting,
        },
        "counts": {
            "new": len(new),
            "resolved": len(resolved),
            "unverifiable": len(unverifiable),
            "persisting": len(persisting),
        },
        "severity_before": _severity_counts(list(prev_f.values())),
        "severity_after": _severity_counts(list(curr_f.values())),

        "coverage_changes": {
            "checks_lost": sorted(lost_checks),
            "checks_gained": sorted(gained_checks),
            "comparable": not lost_checks and not gained_checks,
        },
    }

def fingerprint(payload: dict[str, Any]) -> str:
    """SHA-256 canonico del ESTADO DE SEGURIDAD del objetivo.

    No cubre el payload entero a proposito. `perf.load_time` guarda el tiempo
    medido en milisegundos, que varia en cada corrida: incluirlo hace que dos
    auditorias de un sitio que no cambio produzcan hashes distintos, y la
    huella deja de servir para detectar "nada cambio".

    Se hashean los hallazgos por id+severidad y el estado de cada check. Eso
    es lo que define la postura de seguridad; el resto es telemetria.
    """
    import hashlib
    import json

    canonical = {
        "target": payload.get("target"),
        "findings": sorted(
            (f["id"], f.get("severity"), f.get("check_id"))
            for f in payload.get("findings", []) or []
        ),
        "checks": sorted(
            (c.get("id"), c.get("status"))
            for c in payload.get("checks", []) or []
        ),
    }
    blob = json.dumps(canonical, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()