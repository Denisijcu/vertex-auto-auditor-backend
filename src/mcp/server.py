"""
Servidor MCP de Vertex Auto-Auditor.

Habla el protocolo real (JSON-RPC 2.0 sobre stdio) usando el SDK oficial, asi
que cualquier cliente MCP puede conectarse: Claude Desktop, Cursor, VS Code.
El modulo `src/mcp/` anterior usaba la terminologia de MCP sobre REST, pero no
implementaba la especificacion; ningun cliente estandar podia hablar con el.

DECISION DE ARQUITECTURA
------------------------
Este servidor es un CLIENTE FINO sobre la API HTTP del auditor. No duplica
logica de negocio ni de autenticacion: valida argumentos, llama a la API con
la API key, y traduce la respuesta a algo que un modelo pueda leer.

El motivo es que el aislamiento por tenant, los scopes y el guard anti-SSRF ya
viven en la API y estan probados. Duplicarlos aqui crearia dos caminos de
autorizacion que se desincronizan: el clasico agujero por el que se cuela una
peticion que la API habria rechazado.

LAS TOOLS NO ESPEJAN LOS ENDPOINTS
----------------------------------
La API pide un `company_id` en UUID. Un modelo no tiene UUIDs, tiene nombres
de dominio. Exponer la API tal cual obligaria al modelo a encadenar cuatro
llamadas (listar, buscar, disparar, consultar) y a inventarse identificadores
por el camino.

Aqui `audit_domain("kontia.com")` resuelve o crea la compania, encola, espera
y devuelve el resultado. Una tool debe corresponder a una INTENCION, no a una
ruta HTTP.

AUTENTICACION
-------------
Sobre stdio el cliente lanza este proceso como hijo suyo, asi que no hay auth
por conexion: la API key se lee del entorno al arrancar. Conviene usar una
clave dedicada para el MCP, distinta de la del panel, para poder revocarla sin
afectar a lo demas.

USO
---
    pip install "mcp[cli]>=1.28,<2"
    VERTEX_API_KEY=vtx_... VERTEX_API_URL=http://localhost:8000 \
        python -m src.mcp_server.server
"""
from __future__ import annotations

import asyncio
import os
import sys
from typing import Any

import httpx
from mcp.server.fastmcp import FastMCP

API_URL = os.environ.get("VERTEX_API_URL", "http://localhost:8000").rstrip("/")
API_KEY = os.environ.get("VERTEX_API_KEY", "")

# Cuanto esperar a que el worker termine una auditoria antes de devolver el
# job_id y dejar que el modelo consulte despues. 90s cubre el caso normal
# (~20s) con margen para un target lento sin colgar la conversacion.
AUDIT_TIMEOUT_S = 90
POLL_INTERVAL_S = 3

mcp = FastMCP("vertex-auditor")


class ApiError(RuntimeError):
    pass


def _client() -> httpx.AsyncClient:
    if not API_KEY:
        raise ApiError(
            "Falta VERTEX_API_KEY en el entorno. Genera una clave con "
            "`python -m src.scripts.create_api_key --name mcp --scopes read write`"
        )
    return httpx.AsyncClient(
        base_url=API_URL,
        headers={"X-API-Key": API_KEY},
        timeout=httpx.Timeout(30.0, connect=10.0),
    )


async def _request(method: str, path: str, **kw: Any) -> Any:
    """Llama a la API y traduce los errores a mensajes accionables.

    Un modelo no puede hacer nada con un 403 pelado; si con "esta clave no
    tiene permiso de escritura".
    """
    async with _client() as c:
        try:
            r = await c.request(method, path, **kw)
        except httpx.ConnectError as e:
            raise ApiError(f"No hay conexion con el motor en {API_URL}") from e

        if r.status_code == 401:
            raise ApiError("La API key no es valida o fue revocada.")
        if r.status_code == 403:
            raise ApiError("Esta API key no tiene permiso para esta operacion.")
        if r.status_code == 404:
            raise ApiError("No encontrado.")
        if r.status_code == 409:
            detail = r.json().get("detail")
            raise ApiError(detail if isinstance(detail, str) else "Conflicto.")
        if r.status_code == 422:
            raise ApiError(f"El motor rechazo los datos: {r.text[:300]}")
        if r.status_code >= 500:
            body = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
            ref = body.get("error_id", "")
            raise ApiError(f"Error del motor{f' (ref {ref})' if ref else ''}.")
        r.raise_for_status()
        return r.json() if r.content else None


async def _find_company(domain: str) -> dict | None:
    domain = domain.strip().lower().removeprefix("https://").removeprefix("http://")
    domain = domain.split("/")[0].removeprefix("www.")
    for c in await _request("GET", "/companies/"):
        if c["domain"].lower() == domain:
            return c
    return None


def _summarize(payload: dict) -> dict:
    """Reduce el payload a lo que un modelo necesita para razonar.

    Se omite la evidencia cruda de cada hallazgo: son cientos de tokens que el
    modelo casi nunca necesita. Para eso esta `get_finding_detail`.

    Lo que NO se omite es el inventario de checks. Un resumen con solo
    contadores hace que un informe limpio sea indistinguible de uno que no
    midio nada: "0 hallazgos" no dice si SPF paso o si SPF ni se comprueba.
    Sin esta lista, un modelo razonando sobre el informe concluye que el
    auditor no mide correo — es el mismo error que el motor existe para
    evitar, reproducido en la capa de presentacion.
    """
    cov = payload.get("coverage", {})
    findings = payload.get("findings", [])
    checks = payload.get("checks", [])
    failed_ids = {f["check_id"] for f in findings}

    inventory: dict[str, list[str]] = {"passed": [], "failed": [], "not_assessed": []}
    for c in checks:
        cid = c.get("id", "")
        status = c.get("status", "")
        if status == "not_assessed":
            inventory["not_assessed"].append(cid)
        elif status == "fail" or cid in failed_ids:
            inventory["failed"].append(cid)
        else:
            inventory["passed"].append(cid)

    return {
        "target": payload.get("target"),
        "security_score": payload.get("security_score"),
        "optimization_score": payload.get("optimization_score"),
        "verdict": payload.get("verdict"),
        "score_note": (
            "null significa que la cobertura fue insuficiente para calcular: "
            "NO equivale a 0 ni a 100"
            if payload.get("security_score") is None else None
        ),
        "raw_penalty_security": payload.get("raw_penalty_security"),
        "coverage": {
            "assessed": cov.get("assessed"),
            "total": cov.get("total_checks"),
            "reliable": cov.get("reliable"),
            "not_assessed": [
                {"check": d.get("id"), "reason": d.get("reason")}
                for d in cov.get("not_assessed_detail", [])
            ],
        },
        "findings": [
            {
                "id": f["id"],
                "severity": f["severity"],
                "title": f["title"],
                "check": f["check_id"],
                "cwe": f.get("cwe"),
            }
            for f in findings
        ],
        "findings_count": len(findings),
        # Que se comprobo exactamente. Permite responder "se midio X?" sin
        # tener que inferirlo de la ausencia de hallazgos.
        "checks_run": inventory if checks else None,
        "checks_note": (
            None if checks else
            "Este informe se genero antes de que el motor expusiera el "
            "inventario de checks. Vuelve a auditar para obtenerlo."
        ),
    }


# --------------------------------------------------------------------- tools

@mcp.tool()
async def list_domains() -> list[dict]:
    """Lista los dominios bajo seguimiento con su ultima puntuacion conocida.

    Punto de partida habitual: permite saber que hay auditado antes de decidir
    que hacer.
    """
    companies = await _request("GET", "/companies/")
    out = []
    for c in companies:
        entry = {"domain": c["domain"], "name": c["name"], "industry": c.get("industry")}
        try:
            rep = await _request("GET", f"/reports/{c['id']}/latest")
            entry["security_score"] = rep["security_score"]
            entry["last_audit"] = rep["created_at"]
            entry["findings_count"] = len(rep["findings"].get("findings", []))
        except ApiError:
            entry["security_score"] = None
            entry["last_audit"] = None
            entry["note"] = "sin auditorias previas"
        out.append(entry)
    return out


@mcp.tool()
async def audit_domain(domain: str, name: str | None = None) -> dict:
    """Audita la superficie publica de un dominio y devuelve el resultado.

    Registra el dominio si no estaba, encola la auditoria, espera a que termine
    y devuelve las puntuaciones, la cobertura y los hallazgos.

    El escaneo es PASIVO: DNS, TLS y peticiones HTTP equivalentes a las de un
    visitante. No hay escaneo de puertos, fuzzing ni explotacion.

    Puntos que conviene tener presentes al interpretar el resultado:
      - Un `security_score` en null significa que no se pudo medir lo
        suficiente. No es un 0 ni un 100.
      - Las comprobaciones en `not_assessed` no implican ausencia de riesgo:
        significan que no se pudieron determinar.
      - `raw_penalty_security` no tiene suelo, asi que sirve para comparar dos
        auditorias cuando la puntuacion esta clavada en 0.

    Args:
        domain: dominio a auditar, por ejemplo "ejemplo.com".
        name: nombre de la organizacion. Si se omite, se usa el dominio.
    """
    company = await _find_company(domain)
    if not company:
        clean = domain.strip().lower().removeprefix("https://").removeprefix("http://")
        clean = clean.split("/")[0].removeprefix("www.")
        company = await _request(
            "POST", "/companies/",
            json={"name": name or clean, "domain": clean},
        )

    try:
        job = await _request("POST", f"/reports/trigger/{company['id']}")
    except ApiError as e:
        if "en curso" in str(e):
            return {"status": "already_running", "domain": company["domain"],
                    "note": "Ya hay una auditoria en curso para este dominio."}
        raise

    waited = 0
    while waited < AUDIT_TIMEOUT_S:
        await asyncio.sleep(POLL_INTERVAL_S)
        waited += POLL_INTERVAL_S
        state = await _request("GET", f"/reports/jobs/{job['job_id']}")
        if state["state"] != "complete":
            continue

        result = state.get("result", {})
        if result.get("status") == "FAILED":
            return {"status": "failed", "domain": company["domain"],
                    "error": result.get("error", "motivo desconocido")}

        rep = await _request("GET", f"/reports/{company['id']}/latest")
        summary = _summarize(rep["findings"])
        summary["status"] = "completed"
        summary["report_id"] = rep["report_id"]
        return summary

    return {
        "status": "still_running",
        "domain": company["domain"],
        "job_id": job["job_id"],
        "note": f"La auditoria sigue en curso tras {AUDIT_TIMEOUT_S}s. "
                f"Usa get_report('{company['domain']}') en unos segundos.",
    }


@mcp.tool()
async def get_report(domain: str) -> dict:
    """Devuelve el ultimo informe de un dominio sin lanzar una auditoria nueva.

    Args:
        domain: dominio ya registrado, por ejemplo "ejemplo.com".
    """
    company = await _find_company(domain)
    if not company:
        raise ApiError(f"El dominio {domain} no esta registrado. Usa audit_domain para auditarlo.")

    rep = await _request("GET", f"/reports/{company['id']}/latest")
    summary = _summarize(rep["findings"])
    summary["report_id"] = rep["report_id"]
    summary["audited_at"] = rep["created_at"]
    return summary


@mcp.tool()
async def compare_audits(domain: str) -> dict:
    """Compara las dos ultimas auditorias de un dominio.

    Responde "que cambio desde la ultima vez", no "que hay mal hoy".

    AL INTERPRETAR EL RESULTADO, la distincion que importa:

      - `resolved`     -> la comprobacion volvio a ejecutarse y ahora pasa.
                          El problema esta corregido.
      - `unverifiable` -> el hallazgo desaparecio porque la comprobacion DEJO
                          DE PODER EJECUTARSE. NO esta corregido: dejo de
                          medirse. Reportarlo como una mejora es falso.

    Un `score_delta` positivo con hallazgos en `unverifiable` NO es
    necesariamente una mejora: puede ser una perdida de cobertura.

    Ademas, `penalty_delta` no tiene suelo. Cuando la puntuacion esta clavada
    en 0, esta cifra es la unica que refleja progreso real.

    Args:
        domain: dominio ya registrado, por ejemplo "ejemplo.com".
    """
    company = await _find_company(domain)
    if not company:
        raise ApiError(f"El dominio {domain} no esta registrado.")

    d = await _request("GET", f"/reports/{company['id']}/diff")

    if d.get("comparable") is False:
        return {"comparable": False, "reason": d.get("reason")}

    cov = d.get("coverage_changes", {})
    return {
        "target": d.get("target"),
        "verdict": d.get("verdict"),
        "headline": d.get("headline"),
        "unchanged": d.get("same_fingerprint"),
        "previous": {
            "audited_at": d["previous"]["audited_at"],
            "score": d["previous"]["security_score"],
            "penalty": d["previous"]["raw_penalty"],
            "coverage": f"{d['previous']['coverage']['assessed']}/{d['previous']['coverage']['total']}",
        },
        "current": {
            "audited_at": d["current"]["audited_at"],
            "score": d["current"]["security_score"],
            "penalty": d["current"]["raw_penalty"],
            "coverage": f"{d['current']['coverage']['assessed']}/{d['current']['coverage']['total']}",
        },
        "score_delta": d.get("score_delta"),
        "penalty_delta": d.get("penalty_delta"),
        "score_note": d.get("score_note"),
        "resolved": d["findings"]["resolved"],
        # Separados de `resolved` a proposito: no se corrigieron.
        "unverifiable": d["findings"]["unverifiable"],
        "new": d["findings"]["new"],
        "still_present": d["findings"]["persisting"],
        "counts": d.get("counts"),
        "coverage_comparable": cov.get("comparable"),
        "checks_lost": cov.get("checks_lost"),
        "checks_gained": cov.get("checks_gained"),
    }


@mcp.tool()
async def audit_history(domain: str, limit: int = 15) -> dict:
    """Linea temporal de auditorias de un dominio.

    Util para responder "como ha evolucionado" o "cuando se rompio esto".

    AVISO AL COMPARAR ENTRADAS: el campo `total_checks` puede variar entre
    auditorias cuando se añaden comprobaciones al motor. Dos puntuaciones
    medidas contra distinto denominador no son estrictamente comparables,
    aunque el numero se parezca. Las entradas marcan `scale_changed` cuando eso
    ocurre.

    Las entradas con `legacy: true` proceden de una version anterior del motor
    y no contienen los datos necesarios para interpretarlas.

    Args:
        domain: dominio ya registrado.
        limit: numero maximo de auditorias a devolver.
    """
    company = await _find_company(domain)
    if not company:
        raise ApiError(f"El dominio {domain} no esta registrado.")

    h = await _request("GET", f"/reports/{company['id']}/history",
                       params={"limit": max(1, min(limit, 100))})

    entries = h.get("entries", [])
    out = []
    prev_total = None
    # El historial llega de mas reciente a mas antiguo; se recorre al reves
    # para poder comparar cada entrada con la que la precede en el tiempo.
    for e in reversed(entries):
        total = e.get("coverage", {}).get("total")
        out.append({
            "audited_at": e["audited_at"],
            "score": e["security_score"],
            "penalty": e.get("raw_penalty"),
            "verdict": e.get("verdict"),
            "findings_count": e["findings_count"],
            "assessed": e.get("coverage", {}).get("assessed"),
            "total_checks": total,
            "scale_changed": prev_total is not None and total != prev_total,
            "legacy": e.get("legacy", False),
        })
        prev_total = total

    out.reverse()
    return {"target": h.get("target"), "count": h.get("count"), "entries": out}


@mcp.tool()
async def get_finding_detail(domain: str, finding_id: str) -> dict:
    """Devuelve la evidencia y la remediacion completas de un hallazgo.

    Separado del informe a proposito: la evidencia cruda de todos los hallazgos
    ocuparia cientos de tokens que casi nunca hacen falta.

    Args:
        domain: dominio del informe.
        finding_id: identificador del hallazgo, por ejemplo "VTX-HDR-001".
    """
    company = await _find_company(domain)
    if not company:
        raise ApiError(f"El dominio {domain} no esta registrado.")

    rep = await _request("GET", f"/reports/{company['id']}/latest")
    for f in rep["findings"].get("findings", []):
        if f["id"].upper() == finding_id.upper():
            return f

    available = [f["id"] for f in rep["findings"].get("findings", [])]
    raise ApiError(
        f"No hay ningun hallazgo {finding_id} en el ultimo informe de {domain}. "
        f"Disponibles: {', '.join(available) or 'ninguno'}"
    )


# ----------------------------------------------------------------- resources

@mcp.resource("audit://{domain}/latest")
async def latest_report_resource(domain: str) -> str:
    """Ultimo informe de un dominio, como recurso legible."""
    company = await _find_company(domain)
    if not company:
        return f"El dominio {domain} no esta registrado en el auditor."

    rep = await _request("GET", f"/reports/{company['id']}/latest")
    p = rep["findings"]
    cov = p.get("coverage", {})

    score = p.get("security_score")
    score_txt = "sin determinar (cobertura insuficiente)" if score is None else str(score)

    lines = [
        f"# Auditoria de {p['target']}",
        f"Emitido: {rep['created_at']}",
        "",
        f"Seguridad: {score_txt}",
        f"Optimizacion: {p.get('optimization_score') if p.get('optimization_score') is not None else 'sin determinar'}",
        f"Veredicto: {p.get('verdict')}",
        f"Cobertura: {cov.get('assessed')}/{cov.get('total_checks')} "
        f"({'fiable' if cov.get('reliable') else 'INSUFICIENTE'})",
        "",
        "## Hallazgos",
    ]
    findings = p.get("findings", [])
    if not findings:
        lines.append("Ninguno en las comprobaciones ejecutadas. Eso no significa "
                     "que el sistema sea seguro.")
    for f in findings:
        lines.append(f"- [{f['severity'].upper()}] {f['id']}: {f['title']}")

    na = cov.get("not_assessed_detail", [])
    if na:
        lines += ["", "## Sin determinar"]
        for d in na:
            lines.append(f"- {d.get('id')}: {d.get('reason')}")
        lines.append("")
        lines.append("Una comprobacion sin determinar no implica ausencia de riesgo.")

    return "\n".join(lines)


def main() -> None:
    if not API_KEY:
        print("ERROR: falta VERTEX_API_KEY en el entorno", file=sys.stderr)
        raise SystemExit(1)
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()