# Vertex Auto-Auditor

Motor de auditoría OSINT de superficie pública para dominios. Recibe un dominio,
mide su exposición externa y emite un reporte con hallazgos clasificados por
severidad, mapeados a CWE/OWASP y con evidencia verificable.

Desarrollado por **Vertex Coders LLC** (Miami, FL) como componente de VIC
(Vertex Intelligence Core).

> **Principio de diseño:** ausencia de dato ≠ ausencia de problema.
> Si un check no se puede ejecutar, su resultado es `not_assessed` y **no
> puntúa**. Un reporte con cobertura insuficiente devuelve `null`, no un 100.

---

## Estado actual

| Componente | Estado |
| :--- | :--- |
| Pipeline de recon tipado | ✅ Funcional |
| 21 checks (DNS, TLS, HTTP, contenido, rendimiento) | ✅ Funcional |
| Guard anti-SSRF | ✅ Funcional |
| Scoring `vertex-severity-v1` | ✅ Funcional |
| Reportes con evidencia y CWE/OWASP | ✅ Funcional |
| Capa MCP (REST propietaria) | ⚠️ Funcional, no compatible con la spec MCP |
| Autenticación | ❌ **No implementada** |
| Cola de trabajos | ⚠️ `BackgroundTasks`, sin reintentos ni persistencia |
| Generación de PDF | ❌ Devuelve una URL simulada |
| Diff entre auditorías | ❌ Pendiente |

**No desplegar fuera de `localhost` hasta cerrar la autenticación.**
`POST /mcp/tools/execute` acepta hoy cualquier petición sin credenciales.

---

## Alcance y límites legales

El escaneo es **pasivo sobre superficie pública**:

- Resolución DNS y lectura de registros públicos
- Handshake TLS para inspeccionar el certificado
- Peticiones HTTP `GET` equivalentes a las de un visitante normal

**No se ejecuta** escaneo de puertos, fuzzing, explotación ni ninguna
interacción que exceda lo que hace un navegador al abrir la página.

El User-Agent se identifica de forma honesta e incluye una dirección de
contacto para abuso. Nunca se suplanta un navegador para evadir detección.

---

## Requisitos

- Docker y Docker Compose v2
- Python 3.11+ (solo para desarrollo local sin contenedores)
- PostgreSQL 16 (lo levanta el compose)

---

## Puesta en marcha

```bash
cp .env.example .env          # editar DATABASE_URL y claves
docker compose -f docker/docker-compose.yml up -d --build
docker compose -f docker/docker-compose.yml exec api alembic upgrade head
```

Documentación interactiva en `http://localhost:8000/docs`.

> Las migraciones son obligatorias. `security_score` y `optimization_score`
> son `NULL`-ables desde la revisión `b1c2d3e4f5a6`; sin aplicarla, un reporte
> con cobertura insuficiente rompe con `IntegrityError`.

### Comandos

| Acción | Comando |
| :--- | :--- |
| Levantar | `docker compose -f docker/docker-compose.yml up -d` |
| Reconstruir | `docker compose -f docker/docker-compose.yml up --build` |
| Logs | `docker compose -f docker/docker-compose.yml logs -f api` |
| Migrar | `docker compose -f docker/docker-compose.yml exec api alembic upgrade head` |
| Limpiar | `docker compose -f docker/docker-compose.yml down --remove-orphans` |

---

## Uso

```bash
# 1. Registrar el dominio a auditar
curl -s -X POST localhost:8000/companies/ \
  -H "Content-Type: application/json" \
  -d '{"name":"Ejemplo SA","domain":"ejemplo.com","industry":"Retail"}'

# 2. Lanzar la auditoría (asíncrona)
curl -s -X POST localhost:8000/reports/trigger/{company_id}

# 3. Consultar el resultado
curl -s localhost:8000/reports/{company_id}/latest
```

### Endpoints

| Método | Ruta | Descripción |
| :--- | :--- | :--- |
| `POST` | `/companies/` | Registra un dominio objetivo |
| `GET` | `/companies/` | Lista los dominios registrados |
| `POST` | `/reports/trigger/{company_id}` | Lanza la auditoría en segundo plano |
| `GET` | `/reports/{company_id}/latest` | Último reporte consolidado |
| `GET` | `/mcp/tools` | Catálogo de herramientas |
| `POST` | `/mcp/tools/execute` | Ejecuta una herramienta |
| `GET` | `/mcp/resources/lookup?uri=…` | Lee un recurso por URI |
| `GET` | `/health` | Verificación de vida |

---

## Checks implementados

**DNS** (`dns.*`) — registros A, AAAA, MX, TXT, NS y política SPF.

**TLS** (`tls.*`) — validez de la cadena y del hostname, expiración
(FAIL a menos de 30 días) y versión negociada (FAIL bajo TLS 1.2).

**HTTP** (`http.*`) — estado de la raíz, seis cabeceras de seguridad,
exposición de versión en el banner y redirección permanente a HTTPS.

**Contenido** (`content.*`) — los dos que un escáner de cabeceras no ve:

- `content.not_error_page` — detecta que el documento servido sea el sitio
  real y no la página de error del proveedor. Reconoce firmas de Netlify,
  Vercel, Cloudflare, GitHub Pages, Heroku, S3, nginx y Apache, además de
  patrones en `<title>` anclados a segmento completo. Cubre HTML y cuerpos
  `text/plain` acotados.
- `content.csp_self_block` — parsea la CSP declarada, extrae los recursos del
  documento y verifica que la política no bloquee los suyos propios.
  Implementa la cadena de *fallback* de CSP Level 3, wildcards de host,
  scheme-sources y puertos.

**Rendimiento** (`perf.*`) — tiempo de respuesta contra un presupuesto de
2500 ms, medido desde un único punto (no es una medición sintética
multi-región).

> `content.has_body` está **descartado a propósito**: toda SPA sirve un
> `<body>` prácticamente vacío y lo puebla con JS. Ese check daría falso
> positivo en el 100% de los targets modernos.

---

## Scoring

Método `vertex-severity-v1`:

```
penalización = Σ peso(severidad de cada hallazgo)
score        = max(0, 100 − penalización)
```

Pesos derivados de los rangos CVSS v3.1:

| Severidad | CVSS | Peso |
| :--- | :--- | ---: |
| critical | 9.0–10.0 | 40 |
| high | 7.0–8.9 | 20 |
| medium | 4.0–6.9 | 10 |
| low | 0.1–3.9 | 3 |
| info | 0.0 | 0 |

**Regla de cobertura:** si menos del 70 % de los checks de una categoría se
pudieron ejecutar, el score de esa categoría es `null` y el veredicto pasa a
*"Cobertura insuficiente – auditoría no concluyente"*. No se publica un número
calculado sobre datos que no existen.

Todo reporte incluye un bloque `coverage` con el detalle de qué no se pudo
medir y por qué.

*Limitación conocida:* el suelo en 0 pierde información. Un target con dos
hallazgos críticos y otro con ocho puntúan igual, lo que impide mostrar
progreso entre auditorías consecutivas cuando el score está en el suelo.

---

## Seguridad del propio motor

El servicio recibe dominios de entrada no confiable y emite peticiones
salientes, así que el guard anti-SSRF (`src/core/target_guard.py`) es
obligatorio antes de cualquier request:

- Rechaza RFC1918, loopback, link-local y rangos reservados
- Bloquea los endpoints de metadata de nube (169.254.169.254 y equivalentes)
- Rechaza TLDs de red interna (`.local`, `.internal`, `.lan`, `.corp`)
- Corta el bypass por *userinfo* (`evil.com@interno`)
- **Valida la IP resuelta, no el hostname**, y revalida en cada salto de
  redirección para cortar DNS rebinding

Basta con que una sola IP del conjunto resuelto sea interna para rechazar el
objetivo completo.

---

## Arquitectura

```text
vertex-auto-auditor-backend/
├── docker/                     # Compose y Dockerfiles
├── migrations/                 # Alembic
└── src/
    ├── agents/
    │   ├── base.py             # ScanAgent y Consolidator (abstracciones separadas)
    │   ├── security_agent.py   # Reglas declarativas → Findings
    │   ├── optimization_agent.py
    │   └── report_agent.py     # ReportConsolidator
    ├── core/
    │   ├── csp.py              # Parser de CSP y matching de orígenes
    │   ├── database.py
    │   ├── scoring.py          # vertex-severity-v1
    │   └── target_guard.py     # Anti-SSRF
    ├── mcp/                    # Servidor y registro de tools/resources
    ├── models/                 # ORM
    ├── routers/                # Endpoints
    ├── schemas/
    │   ├── recon.py            # Check, ReconResult, Coverage
    │   └── finding.py          # Finding, AuditReport
    ├── services/
    │   ├── content_analyzer.py
    │   └── scraper_service.py
    └── main.py
```

**Flujo:** `ScraperService` → `ReconResult` (tipado) → agentes emiten
`Finding` → `ReportConsolidator` aplica el scoring → persistencia.

Los agentes reciben un modelo tipado, nunca un `dict`. Un campo inexistente es
un error en tiempo de desarrollo, no un valor por defecto silencioso en
producción.

---

## Sobre la capa MCP

El módulo `src/mcp/` expone herramientas y recursos por REST usando la
terminología de Model Context Protocol, pero **no implementa la especificación
MCP**: no habla JSON-RPC 2.0 ni soporta el handshake `initialize`.

En consecuencia, **los clientes MCP estándar no pueden conectarse**. El
catálogo tampoco publica el esquema de argumentos de cada herramienta, así que
un LLM que la consuma tiene que inferir el payload.

Migrar al SDK oficial (`pip install "mcp[cli]"`) está pendiente.

---

## Hoja de ruta

1. Autenticación por API key (SHA-256) y validación estricta de argumentos en
   `execute_tool`
2. Cola real (ARQ + Redis) en lugar de `BackgroundTasks`
3. Generación de PDF con evidencia
4. Diff entre auditorías consecutivas (los `Finding` ya tienen ID estable)
5. Migración al SDK oficial de MCP
6. Tests de regresión en CI

---

## Desarrollo

```bash
python -m venv venv && source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
pytest
```

Nueva migración:

```bash
alembic revision --autogenerate -m "descripcion"
alembic upgrade head
```

---

## Licencia

Propietario — Vertex Coders LLC. Todos los derechos reservados.