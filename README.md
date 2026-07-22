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

## Estado actual — v0.2.0

| Componente | Estado |
| :--- | :--- |
| Pipeline de recon tipado | ✅ Funcional |
| 21 checks (DNS, TLS, HTTP, contenido, rendimiento) | ✅ Funcional |
| Guard anti-SSRF | ✅ Funcional |
| Scoring `vertex-severity-v1` | ✅ Funcional |
| Autenticación por API key con scopes | ✅ Funcional |
| Aislamiento por tenant | ✅ Funcional |
| Generación de PDF con evidencia y huella SHA-256 | ✅ Funcional |
| Capa MCP (REST propietaria) | ⚠️ Funcional, no compatible con la spec MCP |
| Cola de trabajos | ⚠️ `BackgroundTasks`: sin reintentos ni persistencia |
| Diff entre auditorías | ❌ Pendiente |
| Tests automatizados | ❌ Pendiente (validación manual documentada) |

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

## Puesta en marcha

```bash
cp .env.example .env          # editar DATABASE_URL, CORS_ORIGINS
docker compose -f docker/docker-compose.yml up -d --build
docker compose -f docker/docker-compose.yml exec api alembic upgrade head
```

Crear la primera API key:

```bash
docker compose -f docker/docker-compose.yml exec api \
  python -m src.scripts.create_api_key --name "cli-local" --scopes read write
```

> La clave se muestra **una sola vez**. Solo se persiste su SHA-256; no hay
> forma de recuperarla, ni siquiera desde la base de datos.

Documentación interactiva en `http://localhost:8000/docs` (cerrada en producción).

### Comandos

| Acción | Comando |
| :--- | :--- |
| Levantar | `docker compose -f docker/docker-compose.yml up -d` |
| Reconstruir | `docker compose -f docker/docker-compose.yml up --build` |
| Logs | `docker compose -f docker/docker-compose.yml logs -f api` |
| Migrar | `docker compose -f docker/docker-compose.yml exec api alembic upgrade head` |
| Nueva API key | `... exec api python -m src.scripts.create_api_key --name X --scopes read write` |
| Limpiar | `docker compose -f docker/docker-compose.yml down --remove-orphans` |

> Las migraciones son obligatorias y `Base.metadata.create_all` está eliminado
> a propósito: pisaba Alembic, dejaba `alembic_version` desincronizada y no
> altera tablas existentes. Alembic es la única fuente de verdad del esquema.

---

## Autenticación

Todas las rutas salvo `/health` y `/ready` requieren API key:

```bash
curl -H "X-API-Key: vtx_..." localhost:8000/companies/
# o
curl -H "Authorization: Bearer vtx_..." localhost:8000/companies/
```

**Formato:** `vtx_<prefijo:8>_<secreto:43>`. El prefijo se guarda en claro para
identificar la clave en logs y UI sin exponer nada útil; del secreto solo se
persiste el SHA-256, comparado en tiempo constante.

**Scopes:**

| Scope | Permite |
| :--- | :--- |
| `read` | Consultar companies, reportes y descargar PDFs |
| `write` | Crear companies y lanzar auditorías |
| `admin` | Implica los anteriores |

Crea claves separadas por uso: una con `read` para el panel web, otra con
`read write` para automatización. Una clave filtrada desde el navegador no
debe poder lanzar auditorías.

**Aislamiento por tenant:** el `tenant_id` sale de la API key, nunca del cuerpo
de la petición. Toda consulta sobre datos de tenant pasa por el helper
`scoped()` de `src/core/auth.py`; un `select()` crudo es una fuga entre
clientes esperando a ocurrir.

---

## Uso

```bash
KEY="vtx_..."

# 1. Registrar el dominio a auditar
curl -X POST localhost:8000/companies/ \
  -H "X-API-Key: $KEY" -H "Content-Type: application/json" \
  -d '{"name":"Ejemplo SA","domain":"ejemplo.com","industry":"Retail"}'

# 2. Lanzar la auditoría (asíncrona)
curl -X POST -H "X-API-Key: $KEY" localhost:8000/reports/trigger/{company_id}

# 3. Consultar el resultado
curl -H "X-API-Key: $KEY" localhost:8000/reports/{company_id}/latest

# 4. Descargar el PDF
curl -H "X-API-Key: $KEY" localhost:8000/reports/{report_id}/pdf -o auditoria.pdf
```

### Endpoints

| Método | Ruta | Scope | Descripción |
| :--- | :--- | :--- | :--- |
| `POST` | `/companies/` | `write` | Registra un dominio objetivo |
| `GET` | `/companies/` | `read` | Lista los dominios del tenant |
| `GET` | `/companies/{id}` | `read` | Detalle de un dominio |
| `POST` | `/reports/trigger/{company_id}` | `write` | Lanza la auditoría |
| `GET` | `/reports/{company_id}/latest` | `read` | Último reporte consolidado |
| `GET` | `/reports/{report_id}/pdf` | `read` | Descarga el PDF |
| `GET` | `/mcp/tools` | — | Catálogo con JSON Schema |
| `POST` | `/mcp/tools/execute` | según tool | Ejecuta una herramienta |
| `GET` | `/mcp/resources/lookup?uri=…` | `read` | Lee un recurso por URI |
| `GET` | `/health` | público | Liveness |
| `GET` | `/ready` | público | Readiness: DB y registro de tools |

---

## Checks implementados

**DNS** (`dns.*`) — registros A, AAAA, MX, TXT, NS y política SPF.

**TLS** (`tls.*`) — validez de la cadena y del hostname, expiración
(FAIL a menos de 30 días) y versión negociada (FAIL bajo TLS 1.2).

**HTTP** (`http.*`) — estado de la raíz (FAIL con status ≥ 400), seis cabeceras
de seguridad, exposición de versión en el banner y redirección permanente a
HTTPS.

**Contenido** (`content.*`) — los que un escáner de cabeceras no ve:

- `content.not_error_page` — verifica que el documento servido sea el sitio
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

### Por qué existen los checks de contenido

Tres casos reales sobre el propio dominio de Vertex Coders donde el escáner
daba 100/100 y `securityheaders.com` daba grado A, con el sitio roto:

1. Netlify servía su página *"Page not found"* por un publish directory mal
   configurado. HTTP 200, TLS válido, las cinco cabeceras de seguridad
   presentes.
2. La CSP bloqueaba `fonts.googleapis.com`; el sitio cargaba sin su tipografía.
3. `http.reachable` marcaba PASS incondicional: guardaba el `status_code` como
   evidencia pero nunca lo evaluaba. Un 404 en la raíz pasaba como "accesible".

**Status 200 + cabeceras correctas ≠ sitio funcionando.**

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
*"Cobertura insuficiente – auditoría no concluyente"*.

Todo reporte incluye un bloque `coverage` con el detalle de qué no se pudo
medir y por qué.

*Limitación conocida:* el suelo en 0 pierde información. Un target con dos
hallazgos críticos y otro con ocho puntúan igual, lo que impide mostrar
progreso entre auditorías consecutivas cuando el score está en el suelo.

---

## Reportes PDF

Se generan en `REPORTS_DIR` (por defecto `/app/reports`, montado como volumen)
y se sirven **por `report_id`, nunca por ruta de archivo**: el cliente no
controla ninguna ruta, así que no hay superficie de path traversal, y la fila
consultada ya está acotada al tenant.

Estructura del documento:

- **Cobertura antes que los hallazgos.** Si el escaneo no pudo medir lo
  suficiente, el lector se entera antes de ver cualquier puntuación. Un
  reporte no fiable lleva un aviso destacado en la primera página.
- **Tabla de penalización impresa.** Si el cliente pregunta por qué 71 y no 80,
  la respuesta está en el documento.
- **Evidencia cruda por hallazgo**, reproducible con un `curl`.
- **Sección de limitaciones explícita.**
- **Huella SHA-256** del payload canónico en el pie de cada página.

La huella cubre el *contenido auditado*, no el documento: dos auditorías del
mismo sitio sin cambios producen la misma huella aunque difiera la fecha de
emisión. Eso permite detectar "nada cambió" sin comparar hallazgo por hallazgo.

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

**Otras defensas:**

- Todo `input_model` de tools y endpoints usa `extra="forbid"`: un campo no
  declarado (por ejemplo `tenant_id`) devuelve 422, no se ignora en silencio.
- Los errores no exponen trazas: el traceback va al log con un `error_id` y al
  cliente solo llega ese identificador.
- CORS con lista explícita y `allow_credentials=False`. La combinación `"*"` +
  credenciales hace que Starlette refleje el Origin del atacante.
- `config.py` impide arrancar en producción con `DEBUG=true` o `CORS_ORIGINS="*"`.
- Recursos de otro tenant devuelven 404, no 403: un 403 confirmaría que
  existen.

---

## Arquitectura

```text
vertex-auto-auditor-backend/
├── docker/                     # Compose y Dockerfiles
├── migrations/                 # Alembic — única fuente de verdad del esquema
└── src/
    ├── agents/
    │   ├── base.py             # ScanAgent y Consolidator (abstracciones separadas)
    │   ├── security_agent.py   # Reglas declarativas → Findings
    │   ├── optimization_agent.py
    │   └── report_agent.py     # ReportConsolidator
    ├── core/
    │   ├── auth.py             # AuthContext, API keys, scoped()
    │   ├── csp.py              # Parser de CSP y matching de orígenes
    │   ├── database.py
    │   ├── scoring.py          # vertex-severity-v1
    │   └── target_guard.py     # Anti-SSRF
    ├── mcp/                    # Servidor y registro de tools/resources
    ├── models/                 # ORM (Tenant, ApiKey, Company, AuditTask, AuditReport)
    ├── routers/                # companies, reports, mcp_router
    ├── schemas/
    │   ├── recon.py            # Check, ReconResult, Coverage
    │   └── finding.py          # Finding, AuditReport
    ├── scripts/                # create_api_key
    ├── services/
    │   ├── content_analyzer.py
    │   ├── pdf_generator.py
    │   └── scraper_service.py
    └── main.py
```

**Flujo:** `ScraperService` → `ReconResult` (tipado) → agentes emiten
`Finding` → `ReportConsolidator` aplica el scoring → PDF → persistencia.

Los agentes reciben un modelo tipado, nunca un `dict`. Un campo inexistente es
un error en tiempo de desarrollo, no un valor por defecto silencioso en
producción.

---

## Sobre la capa MCP

El módulo `src/mcp/` expone herramientas y recursos por REST usando la
terminología de Model Context Protocol, pero **no implementa la especificación
MCP**: no habla JSON-RPC 2.0 ni soporta el handshake `initialize`.

En consecuencia, **los clientes MCP estándar no pueden conectarse**. Sí publica
el JSON Schema de cada herramienta en `/mcp/tools`, de modo que un LLM puede
construir el payload correcto en lugar de inferirlo.

Migrar al SDK oficial (`pip install "mcp[cli]"`) está pendiente.

---

## Hoja de ruta

1. Cola real (ARQ + Redis) en lugar de `BackgroundTasks`, que muere con el
   contenedor y no tiene reintentos
2. Sección "verificado y correcto" en el PDF: listar lo que pasó, no solo lo
   que falló
3. Diff entre auditorías consecutivas (los `Finding` ya tienen ID estable y la
   huella SHA-256 permite descartar "sin cambios" de un vistazo)
4. Tests de regresión en CI (≈35 casos hoy validados a mano)
5. Migración al SDK oficial de MCP

---

## Desarrollo

```bash
python -m venv venv && source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

Nueva migración:

```bash
alembic revision --autogenerate -m "descripcion"
alembic upgrade head
```

---


# Añadidos al README

Tres inserciones. Ninguna reemplaza texto existente.

---

## 1. En la sección **Checks implementados**

Justo después del bloque de `DNS (dns.*)` y antes de `TLS`:

```markdown
> **Hosting compartido.** Si el objetivo es un subdominio de un proveedor
> (`algo.netlify.app`, `algo.hf.space`, `algo.up.railway.app`…), los checks que
> dependen de controlar la zona DNS pasan a `not_assessed` con motivo
> explícito, no a `fail`. El titular de ese subdominio no puede publicar un
> registro SPF en `netlify.app` aunque quiera: reportarlo sería técnicamente
> cierto e **inaccionable**.
>
> Un hallazgo que el cliente no puede corregir baja la puntuación sin motivo,
> ocupa espacio en el informe y resta credibilidad a los hallazgos que sí son
> accionables. Los sufijos están en `src/core/hosting.py`.
```

---

## 2. En **Arquitectura**, dentro del árbol

Añadir la línea a `src/core/`, manteniendo el orden alfabético:

```text
    ├── core/
    │   ├── auth.py             # AuthContext, API keys, scoped()
    │   ├── csp.py              # Parser de CSP y matching de orígenes
    │   ├── database.py
    │   ├── hosting.py          # Sufijos de hosting compartido; zona DNS no controlable
    │   ├── queue.py            # Pool de Redis compartido
    │   ├── scoring.py          # vertex-severity-v1
    │   └── target_guard.py     # Anti-SSRF
```

---

## 3. Sección nueva, después de **Scoring**

```markdown
## Hallazgos accionables

Un hallazgo solo se emite si el destinatario del informe puede hacer algo con
él. Cuando una comprobación falla por una condición que el titular del dominio
no controla, el resultado es `not_assessed` con el motivo, no un `fail`.

Hoy se aplica a los subdominios de hosting compartido: `src/core/hosting.py`
mantiene 26 sufijos (Netlify, Vercel, Cloudflare Pages, GitHub Pages, Railway,
Hugging Face Spaces, Heroku, Firebase, Workers…) y la lista
`ZONE_DEPENDENT_CHECKS` con las comprobaciones afectadas (`dns.spf` y, cuando
se implementen, `dns.dmarc`, `dns.dnssec` y `dns.caa`).

La coincidencia exige que el objetivo sea **subdominio** del sufijo:
`algo.netlify.app` lo es, `netlify.app` no — el proveedor sí controla su propia
zona. `netlify.app.attacker.com` y `minetlify.app` tampoco coinciden.

No es la Public Suffix List completa, sino una lista curada de los proveedores
donde la herramienta se usa en la práctica. Ante un proveedor no listado el
comportamiento es el anterior (se evalúa), que es el lado seguro del error:
preferible un falso positivo revisable a un falso negativo silencioso.

**Caso que lo originó:** `vertex-kontia.netlify.app` puntuaba 61 con seis
hallazgos, uno de ellos `VTX-DNS-001` (SPF no publicada). Tras la corrección
puntúa 71 con cinco, y `dns.spf` aparece como no evaluado explicando por qué.
`vertexcoders.com`, que sí controla su zona, no varió: sigue en 100 con 21/21.

El fallo solo se hizo visible al auditar un sitio **sano** en hosting
compartido; los objetivos rotos que se usaban como prueba lo enmascaraban con
otros hallazgos.
```

---

## 4. Opcional — en **Hoja de ruta**

Si quieres dejar constancia de lo que queda del tema:

```markdown
6. Ampliar `ZONE_DEPENDENT_CHECKS` cuando se implementen DMARC, DNSSEC y CAA
```

## Licencia

Propietario — Vertex Coders LLC. Todos los derechos reservados.