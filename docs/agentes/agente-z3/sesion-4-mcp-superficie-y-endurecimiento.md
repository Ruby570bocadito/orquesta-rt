# Sesión 4 — Servidores MCP, superficie OpenAPI y endurecimiento del proxy

> **Agente:** z3 · **Fecha:** 2026-09-12 · **Base auditada:** `main` @ `6f1f2e3`
> (v25) · **Alcance:** zonas NO cubiertas por las sesiones 1–3.

## Enfoque de esta ronda

Las sesiones anteriores cubrieron a fondo el núcleo (`auth.py`, `sso.py`,
`api.py`, `webhook.py`, `memory.py`, `transportes.py`, `guardrails.py`),
las integraciones con credenciales (TLS en sesiones 2) y los módulos de
razonamiento v24/v25. Esta ronda ataca sistemáticamente lo que quedaba:

1. **Servidores MCP** (`recon_server`, `osint_server`, `evidence_server`,
   `c2_adapter_server`) — la capa de herramientas del agente.
2. **Proxy de la consola → orquestador** (`src/app/api/orchestrator/`) y su
   interacción con la superficie HTTP del backend FastAPI.
3. **Módulos de núcleo no auditados**: `persistencia.py`, `respaldo.py`,
   `sidecar.py`, `graph.py` (Cypher), `evasion.py`, `ctem.py`,
   `threatled.py`, `cobertura_attack.py`, `sigma_valid.py`.
4. **Infraestructura**: CI (`.github/workflows/ci.yml`), manifiestos K8s,
   scripts de shell (`lab/`, `scripts/`, `install.sh`, `start.sh`).

Barridos aplicados: ejecución de comandos (`shell=True`, `Popen`,
`os.system`), inyección Cypher/SQL (f-strings en consultas),
deserialización insegura (`pickle`/`yaml.load`/`eval`), `verify=False`,
rutas de fichero dinámicas, zip-slip, regex no acotadas, privilegios en
manifiestos K8s y almacenamiento de sesión en la consola. Los patrones
encontrados y descartados se listan al final (transparencia de auditoría).

## Resultado: 6 hallazgos (3 MEDIO + 3 BAJO), todos remediados

| ID | Severidad | Hallazgo | Remediación |
|---|---|---|---|
| F25 | BAJO* | Superficie OpenAPI + path-traversal del proxy de la consola | `/docs`·`/redoc`·`/openapi.json` desactivados por defecto + guardia de segmentos `.`/`..` en el proxy |
| F26 | MEDIO | SSRF en `osint_server.robots_txt`: host sin validar (posición de autoridad de la URL) + redirects sin acotar | Validación estricta `dominio_valido()` + redirecciones seguidas a mano SOLO dentro del dominio |
| F27 | BAJO | `subdominios_crtsh`: query construida por f-string (inyección de parámetros en el proveedor público) | `params=` de httpx (codificación correcta) + misma validación de dominio |
| F28 | MEDIO | `recon_server` devolvía contenido externo SIN sanear (título, `Server`, `X-Powered-By`, meta generator) — inconsistencia LLM01 con osint | Saneado unificado `servidores_mcp/comun.py::saneado()` aplicado a todos los campos derivados del servidor externo |
| F29 | BAJO | Fallback TLS "fail-open" en los MCP: sin orchestrator, `httpx.Client(verify=False)` fijo | Política unificada `comun.cliente_recon()` (misma semántica `RECON_TLS_ESTRICTO` que `transportes`) + guardia AST anti-regresión |
| F30 | MEDIO | Los servidores MCP **no arrancaban con su invocación documentada**: el paquete local `platform/mcp/` sombrea el SDK PyPI `mcp` → `SystemExit("Falta el SDK de MCP")` | Paquete renombrado a `platform/servidores_mcp/`; las 4 invocaciones `python -m servidores_mcp.<server>` verificadas funcionales |

\* F25 se detectó con hipótesis de severidad ALTA y se **reclasificó a BAJO
contra el código real**: el middleware global de auth (`_auth_middleware`)
ya devolvía 401 en esas rutas porque `RUTAS_PUBLICAS` solo exime
endpoints `/api/*`. Los fixes se mantienen como defensa en profundidad
(cerrar la *clase* de path-normalization y eliminar superficie
documental redundante por si el middleware cambia en el futuro).

## Detalle técnico

### F25 — Superficie OpenAPI y path-traversal del proxy (BAJO)

**Cadena investigada.** El proxy `src/app/api/orchestrator/[...path]/route.ts`
reconstruye el destino como `${BASE}/api/${ruta}`. Un segmento `..`
(decodificado por Next desde `%2e%2e`) sobrevive a la re-codificación
(`encodeURIComponent("..") === ".."`) y el cliente HTTP de Node aplica la
normalización WHATWG: `http://127.0.0.1:8000/api/../openapi.json` →
`http://127.0.0.1:8000/openapi.json`. Eso alcanza rutas del backend
**fuera** de `/api`, que no atraviesan la lógica de sesión por ruta.

**Verificación honesta.** FastAPI expone `/docs`, `/redoc` y
`/openapi.json` sin autenticación propia, PERO el middleware global
`_auth_middleware` (añadido en el ciclo v21) exige `Bearer` en TODA ruta
no pública, así que el 401 llega antes. Sin sesión, la cadena no
revela el esquema. Quedaban dos debilidades reales: (a) la clase de
traversal no estaba cerrada — cualquier cambio futuro del middleware o de
`RUTAS_PUBLICAS` la hacía explotable; (b) la superficie documental es
innecesaria en producción y agranda el objetivo.

**Remediación.**
- `api.py`: `FastAPI(docs_url=None, redoc_url=None, openapi_url=None)`
  salvo `ORQUESTA_DOCS=1` (desarrollo).
- `route.ts`: los segmentos `.`/`..` se rechazan con 400 antes de
  construir el destino.

### F26 — SSRF en `osint_server.robots_txt` (MEDIO)

`robots_txt(dominio)` construía `f"{esquema}://{dominio}/robots.txt"`:
el valor del agente (manipulable por inyección indirecta de prompts,
LLM01) iba a la **posición de autoridad** de la URL. Con
`dominio="crt.sh@evil.com"` la petición iba a `evil.com`; con
`"evil.com:8080"` a un puerto arbitrario; y `follow_redirects=True`
permitía además que un 301 del dominio legítimo llevase al servidor MCP
(dentro de la red del lab) a cualquier host. El servidor osint no tenía
NINGUNA verificación de scope (recon sí la tiene).

**Remediación.** `comun.dominio_valido()` (regex de labels + TLD
alfabético, longitud ≤ 253, rechazo de `@ : / ? # % \` y espacios —
rechaza de paso IPs literales) aplicada en `robots_txt` y
`subdominios_crtsh`; redirecciones ahora se siguen **manualmente**
(máx. 3 saltos) validando que cada destino sea el dominio solicitado o
un subdominio suyo (`www.<dominio>` sigue funcionando; `evil.com`, no).

### F27 — Inyección de parámetros en crt.sh (BAJO)

`f"https://crt.sh/?q=%.{dominio}&output=json"`: un dominio con `&` o `#`
manipulaba la query del proveedor (p. ej. añadir `&q=...` adicional).
Remediado con `httpx.get("https://crt.sh/", params={...})` (codificación
RFC 3986 correcta) + la guardia F26, que ya rechaza esos caracteres.

### F28 — Saneado LLM01 inconsistente entre servidores MCP (MEDIO)

El servidor osint sanea el contenido externo (docstring cap. 5.2), pero
`recon_server` devolvía **sin sanear** el `<title>`, la cabecera
`Server`, `X-Powered-By` y el meta `generator` — todo ello controlado por
el servidor externo sondeado. El escudo del copiloto (v25) mitiga la vía
del copiloto, no otros consumidores de resultados MCP (informes, memoria,
bucles de agente). Remediado centralizando el saneado en
`servidores_mcp/comun.py::saneado()` y aplicándolo en `http_probe`
(título + cabeceras filtradas) y `tech_fingerprint` (server, framework,
generator).

### F29 — Fallback TLS fail-open en los MCP (BAJO)

Ambos servidores importaban el cliente de sondeo con un fallback:
`except Exception: httpx.Client(verify=False, **kw)`. En un despliegue
solo-MCP (sin `orchestrator` importable) el silencio era total. La
sesión 2 introdujo la política `RECON_TLS_ESTRICTO` en `transportes.py`,
pero el fallback la eludía. Remediado: `comun.cliente_recon()` aplica la
MISMA semántica (`verify = RECON_TLS_ESTRICTO == "1"`) y un test AST
impide reintroducir `verify=False` en código de `servidores_mcp/`.

### F30 — El paquete local `mcp` sombreaba el SDK PyPI `mcp` (MEDIO)

Invocación documentada: `python -m mcp.recon_server` (desde `platform/`).
Python resuelve `mcp` como el paquete LOCAL (`platform/mcp/`), por lo que
`from mcp.server.fastmcp import FastMCP` no encuentra el SDK real y el
servidor moría con `SystemExit("Falta el SDK de MCP")` — **la capa MCP
completa era inarrancable tal como estaba documentada**. Verificado
empíricamente contra el commit base. Remediado renombrando el paquete a
`platform/servidores_mcp/` (convención de nombres en español del repo),
actualizando docstrings de uso y el comentario de `transportes.py`.
Verificación: `python -m servidores_mcp.<server> --help` devuelve 0 para
los 4 servidores, y el modo script suelto también funciona (los imports
`from servidores_mcp.comun import ...` resuelven vía `sys.path` a
`platform/`).

## Verificación

- **Tests nuevos:** `platform/tests/test_z3_sesion4.py` — 37 tests, 37/37
  en verde. Incluyen: guardia AST anti-`verify=False`, arranque real por
  subprocess de los 4 servidores con su invocación documentada,
  redirecciones de `robots_txt` (bloqueada fuera de dominio / permitida
  dentro), inyección de parámetros crt.sh rechazada, saneado de título/
  cabeceras/generator, y coexistencia paquete local ↔ SDK.
- **Suite completa:** `10 failed, 383 passed, 8 skipped`. Los 10 fallos
  son EXACTAMENTE los preexistentes documentados desde la sesión 1
  (dependencias opcionales `yara`/`impacket`/`ldap3` ausentes en la
  máquina de auditoría: `test_v19`, `test_v20`, `test_integraciones`);
  cero regresiones. (`git stash` no sirve de baseline limpio aquí: con el
  rename en el índice rompe la importación de los tests nuevos.)
- **TypeScript:** `bunx tsc --noEmit` no reporta errores en los ficheros
  tocados (`route.ts`); los errores restantes son del entorno sin
  `node_modules` instalado y un error preexistente en `store.ts:1086`
  (no modificado).
- **Arranque MCP:** los 4 servidores en modo `-m` y modo script → OK.

## Patrones revisados y descartados (transparencia)

- `webhook.py:237` — SQL dinámico: claves fijas + valores parametrizados → seguro.
- `persistencia.py` — subprocess SIEMPRE en forma de lista (sin shell);
  rutas construidas sobre `raiz` del despliegue → sin inyección de argumentos.
- `respaldo.py` — solo CREA zips (sin `extractall`) → sin zip-slip.
- `transportes.py` / MCP `cert_info` — `CERT_NONE` es necesario
  funcionalmente (inspección de certificados potencialmente inválidos, el
  handshake verificado fallaría y no devolvería el DER); devuelve
  metadatos, no secretos.
- `sliver.py:134` — `shell=True` es la función central del C2 bajo ROE y
  aprobación humana (boundary del guardrail); sin exposure sin auth.
- Regex de `sigma_valid`/`purpleteam`/`threatled`/`busqueda` — acotadas,
  sin backtracking catastrófico.
- CI (`ci.yml`) — triggers correctos (`branches: [main]`), sin secretos
  en el workflow; `bun.lock` congelado en CI.
- K8s — `runAsNonRoot` en ambos deployments, `readOnlyRootFilesystem` en
  el orquestador, sin `hostPort`/`privileged`.
- Sesión en consola — el token sigue en `localStorage` (pendiente
  documentado desde la sesión 2: migrar a cookie httpOnly a medio plazo).

## Pendiente para el equipo

1. Rotar/revisar las credenciales publicadas históricamente (señalado en
   la sesión 1; sigue abierto: purge de historial con `git filter-repo`).
2. `JWT localStorage → cookie httpOnly` (sesión 2; medio plazo).
3. Decidir si `RECON_TLS_ESTRICTO=1` debe ser el default en el despliegue
   de producción real (hoy el default lab es verificar solo con la env).
