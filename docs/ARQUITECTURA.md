# Arquitectura de la Plataforma

Documento de referencia del núcleo. Complementa el blueprint comercial; aquí se
documenta lo que está construido y por qué.

## 1. Principios de diseño (no negociables)

1. **Operator-in-command en el límite de la herramienta.** El modelo propone; el
   boundary decide si puede pasar; el humano aprueba lo crítico. Los controles viven
   en `guardrails.py`, FUERA del prompt: un jailbreak no puede anularlos porque no
   están en el contexto del modelo.
2. **Memoria del caso sobre historial de conversación.** SQLite por caso +
   compaction por fase. Lo aprendido nunca se pierde entre fases; el contexto de los
   modelos se mantiene pequeño por diseño (economía del token como decisión de
   arquitectura desde el día uno).
3. **Integrar, no reinventar.** BloodHound, Sliver, Mythic, Burp, nuclei conviven
   con la plataforma vía adaptadores MCP. El núcleo orquesta; no reemplaza el
   tooling del equipo.
4. **Evidencias desde el minuto uno.** Cada acción genera evidencia firmada en el
   momento, no al final. El informe se consolida; no se reconstruye.
5. **Trabajo limpio.** Auditoría append-only, bóveda de credenciales con caducidad,
   certificado de borrado al cierre.

## 2. Capas

```
┌──────────────────────────────────────────────────────────────┐
│  CONSOLA (Next.js)                                           │
│  panel · pipeline · aprobaciones · hallazgos · evidencias ·  │
│  coste IA · cronología        ↕ REST /api/orchestrator/*     │
├──────────────────────────────────────────────────────────────┤
│  ORQUESTADOR (Python · LangGraph)                            │
│  grafo F0→cierre · agentes de fase · router de modelos ·     │
│  compaction · presupuestos por fase                          │
├──────────────────────────────────────────────────────────────┤
│  BOUNDARY (guardrails.py)  ← único punto de paso             │
│  scope + política ROE + clasificación de riesgo              │
│  → PERMITIR | REQUIERE_APROBACION | DENEGAR                  │
├──────────────────────────────────────────────────────────────┤
│  HERRAMIENTAS (servidores MCP)                               │
│  recon · evidencias · osint · adaptador C2 · adaptador AD ·  │
│  adaptador explotación · adaptador phishing (licenciados)    │
├──────────────────────────────────────────────────────────────┤
│  EJECUCIÓN Y DATOS                                           │
│  LLM local (vLLM/Ollama) · LLM frontera (API) · SQLite por   │
│  caso (auditoría append-only, cadena de custodia HMAC) ·     │
│  bóveda de credenciales                                      │
└──────────────────────────────────────────────────────────────┘
```

Cada capa se prueba y se vende por separado: los servidores MCP funcionan con
cualquier cliente MCP del mercado (producto autónomo); el grafo de estado mantiene
la memoria entre fases; el router ejecuta el grueso de llamadas en local.

## 3. El boundary en detalle

`MotorGuardrails.evaluar(herramienta, argumentos, fase)` aplica, en orden:

0. **Catálogo de riesgo** — herramientas destructivas (`destruir.*`, `wipe.*`) se
   DENIEGAN siempre; no son ejecutables por el agente ni con firma en línea.
1. **Scope** — dominio (coincidencia de sufijo) o IP (CIDR). Las exclusiones del
   ROE (`alcance_excluido`) ganan a cualquier otra regla.
2. **Política** — técnicas prohibidas (ATT&CK) deniegan; técnicas con firma crean
   petición de aprobación; techo de ruido agotado deniega con explicación;
   herramientas activas fuera de ventana horaria deniegan.
3. **Riesgo** — riesgo ALTA/CRÍTICA o herramienta desconocida → REQUIERE_APROBACION
   (menor privilegio por defecto).

Cada decisión se registra en la auditoría inmutable con actor, herramienta y hash
de parámetros. El resultado del boundary es la materia prima de la pestaña
"Aprobaciones" de la consola y del capítulo de cronología del informe.

## 4. Memoria del caso

Un SQLite por engagement (`casos/<id>.db`) con:

- `auditoria` — append-only (triggers de BD bloquean UPDATE/DELETE).
- `evidencias` — SHA-256 del contenido + firma HMAC con la clave del caso +
  encadenamiento al hash previo (genesis → e1 → e2 → …). `verificar_cadena()`
  re-hashea cada contenido y detecta manipulación.
- `aprobaciones` — cola operator-in-command; la decisión humana (actor, comentario,
  marca temporal) es parte del registro.
- `uso_tokens` — contabilidad por fase/modelo/llamada con coste calculado; alimenta
  la vista de economía y el margen del producto.
- `resumenes_fase` — compaction: resúmenes densos por fase que sustituyen a la
  historia lineal en el contexto del planner.

## 5. Servidores MCP

| Servidor | Herramientas | Notas de seguridad |
|---|---|---|
| `recon_server` | dns_enum, http_probe, cert_info, tech_fingerprint, port_scan | Lista blanca de puertos; doble verificación de scope local; sin evasión (el lab mide ruido real) |
| `evidence_server` | guardar, listar, verificar, exportar | Firma HMAC con clave del caso; exportable para auditoría del cliente |
| `osint_server` | subdominios_crtsh, robots_txt, buscar_filtraciones | Contenido externo saneado (anti inyección indirecta); filtraciones exige proveedor licenciado + aprobación humana |
| `c2_adapter_server` | registrar_implante, tarea_implante, estado, retirar | MOCK total del lab. Contrato estable: en producción apunta a Sliver/Mythic vía gRPC/API sin tocar el orquestador |

## 6. Router de modelos

- `clasificar_tarea()` — reglas declarativas tarea → clase (local/frontera). En
  producción puede sustituirse por un clasificador entrenado sin cambiar el contrato.
- Política `POLITICA_SALIDA=perimetro|hibrido`: con `perimetro`, las tareas críticas
  se degradan a local aunque exista clave de API (soberanía configurable).
- Presupuesto por fase: el router rechaza llamadas al acercarse al techo y obliga a
  compactar (no paga por contextos descontrolados).
- Compaction: `compactar()` produce el resumen que abre la fase siguiente; se ejecuta
  con el modelo local (barato) y su resultado vive en `resumenes_fase`.

## 7. Consola (Next.js)

- 7 vistas en una página; modo demo (motor de simulación local que reproduce el
  seeder `demo_seed.py`, con SHA-256 real del navegador para las evidencias) y modo
  live (proxy `/api/orchestrator/*` → FastAPI).
- La pestaña Aprobaciones se activa sola cuando el boundary detiene el grafo:
  aprobar/rechazar con comentario, que alimenta la auditoría y el plan B del agente.

## 8. Despliegue on-prem

`docker compose up -d` — orquestador + consola. Perfiles:

- `lab` — objetivo nginx simulado (ACME ficticio) para recorrer F0→F7 sin red real.
- `gpu` — vLLM con prefix caching para el LLM local de producción.

Actualizaciones: canal firmado de agentes y skills independiente del núcleo (la
biblioteca TTP evoluciona semanalmente sin tocar la instalación base del cliente).

## 9. Riesgos técnicos y mitigaciones (cap. 6.5 del blueprint)

| Riesgo | Mitigación implementada |
|---|---|
| Deriva del agente | Salidas estructuradas JSON + verificación contra evidencia real + boundary determinista |
| Dependencia de proveedores | Abstracción del router + soporte vLLM/Ollama local |
| Coste de la capa de seguridad | El boundary es requisito M1 de venta, no adorno; 13 tests lo pinnen |
| Cambio del ecosistema IA | Dependencias aisladas en la capa MCP y en adaptadores |

## 10. Ronda v6 — identidad, tiempo real y recuperación de memoria

### Autenticación de operadores (`orchestrator/auth.py`)

- Cuentas REALES en `usuarios.db` (SQLite dedicado, `USUARIOS_DB`): hash
  scrypt (n=2^14, r=8, p=1, dklen=32, salt único por cuenta), roles
  `admin`/`operador`.
- Token JWT HS256 (RFC 7519) emitido por el backend, secreto persistido en
  el propio almacén (sobrevive a reinicios); expiración `TOKEN_HORAS` (12 h).
- API **deny-by-default** vía middleware: toda ruta exige `Authorization:
  Bearer` salvo `/api/salud` y `/api/auth/{estado,login,registrar}`. Un
  endpoint nuevo queda protegido por defecto.
- Bootstrap: si no hay operadores, la primera cuenta creada desde la consola
  es admin; después, solo un admin autenticado da de alta cuentas.
- Anti fuerza bruta: bloqueo temporal (5 fallos → 5 min) por cuenta.
- Identidad real en la auditoría: las decisiones de firma ROE registran
  `decidida_por` desde el JWT; el cuerpo de la petición ya NO puede
  suplantar al operador. El proxy Next reenvía la cabecera Authorization.

### Eventos en vivo (SSE)

- `GET /api/engagements/{id}/eventos`: flujo Server-Sent Events con la
  auditoría nueva del caso (deltas por rowid, heartbeat, reciclaje a 4 min).
- La consola consume el flujo con fetch+ReadableStream (permite JWT en
  cabecera, a diferencia de EventSource) y hace **fallback automático al
  sondeo de 3 s** si el flujo no está disponible; latencia típica ~1,5 s.

### Búsqueda en la memoria del caso (`orchestrator/busqueda.py`)

- BM25 (Okapi k1=1.5 b=0.75) 100% local sobre evidencias, hallazgos,
  objetivos, auditoría, aprobaciones y resúmenes de fase.
- Tokenizador español tolerante a tildes con stopwords.
- Refuerzo semántico opcional por embeddings del backend LOCAL
  (`API_LOCAL_BASE` → /embeddings OpenAI-compat) fusionado con RRF: el
  contenido del caso jamás sale hacia la frontera.
- API `GET /api/engagements/{id}/memoria/buscar?q=...&tipos=...` + panel de
  búsqueda en la vista Memoria.

### Nuevos transportes reales (24 registrados)

- `osint.zone_transfer`: AXFR real (dnspython) contra los NS del dominio en
  alcance; si procede, hallazgo de exposición DNS con registros.
- `recon.nmap_servicios`: nmap -sV por subprocess con la lista blanca de
  puertos; sin binario → requisito exacto, nunca éxito fingido.
- Integrados en F1 (AXFR) y F2 (versiones de servicio) con clasificación
  del boundary (AXFR baja/sin ventana; nmap media/ventana).

### Informe HTML imprimible

- `construir_informe_html`: entregable autocontenido (CSS embebido, sin
  scripts, escapado) con resumen ejecutivo, cronología, hallazgos por
  severidad, superficie observada, cadena de custodia completa y economía
  de tokens. `GET /informe?formato=html|md` + botones en la consola.

### Determinismo del boundary

- `MotorGuardrails.evaluar(..., momento=None)`: reloj inyectable para tests
  deterministas y replay auditado (la ventana horaria del ROE ya no hace
  frágiles los tests ni la reproducción de decisiones).

## 11. Ronda v7 — producción, optimización y nuevas habilidades

### Puente IA (GLM real vía consola)

- `/api/ia` (Node, SDK z-ai): endpoint **OpenAI-compatible** (`chat/completions`,
  `models`) que da al router del orquestador un backend de frontera REAL sin
  claves en el código. Token interno persistido en `db/puente-ia.token` (0600),
  inyectado como `API_FRONTERA_CLAVE` al arrancar uvicorn; comparación en
  tiempo constante y 401 sin token.
- `MODELO_FRONTERA=glm-4.6`: la economía del token (contabilidad, caché,
  presupuestos por fase) funciona de punta a punta con el backend real.

### Copiloto del operador (IA con contexto del caso)

- `orchestrator/copiloto.py`: RAG local real (BM25 de busqueda.py sobre
  evidencias/hallazgos/resúmenes/aprobaciones) + estado del caso + ROE →
  router (tarea `analisis_caso` → frontera; local con política perimetro).
- Habilitación POR CASO, deshabilitado por defecto: activarlo es una decisión
  de perímetro consciente que firma la auditoría con identidad real. Cada
  consulta queda auditada (pregunta truncada + tokens + modelo). El copiloto
  NO ejecuta acciones; sugiere el canal (fase + aprobación).
- Vista "Copiloto IA" en la consola: conversación con fuentes citadas,
  tokens/coste por respuesta y sugerencias según la fase actual.

### Equipo: gestión admin de operadores

- Nuevos endpoints: `POST /api/auth/rol`, `POST /api/auth/restablecer`,
  y `/api/auth/registrar` corregido (verifica JWT explícito: era ruta pública
  para el bootstrap y devolvía 403 SIEMPRE tras el alta inicial — bug
  detectado en E2E con test de regresión).
- `auth.py`: `cambiar_rol` y `restablecer_contrasena` con protección de
  último admin y auto-bloqueo; reset administrativo desbloquea cuentas.
- Vista "Equipo" (solo admin): alta, rol, restablecimiento y baja con
  confirmaciones y avisos honestos.

### Entregables y análisis

- `GET /exportar`: copia de custodia del caso completo (orquestart-caso/1)
  con verificación de cadena incluida y evento auditado.
- `GET /hallazgos.csv`: exportación CSV real para ticketing/remediación.
- `GET /objetivos/dif?desde=&hasta=`: diferencial REAL de superficie entre
  repasos (normalización naive/UTC incluida). Sección propia en la vista
  Objetivos.

### Webhook real de aprobaciones

- `orchestrator/webhook.py`: POST HTTP real al receptor del equipo cuando el
  boundary exige firma humana, firmado `X-Orquesta-Firma: sha256=HMAC(...)`
  (`WEBHOOK_URL` + `WEBHOOK_SECRETO`), disparo en segundo plano, resultado
  auditable y "Probar conexión" honesto en Integraciones.

### Tres transportes nuevos (26 en total, todos reales)

- `recon.correos_seguridad`: SPF/DMARC/DKIM por DNS TXT real → hallazgo de
  postura de correo (alimenta F6).
- `osint.sitemap`: rutas publicadas por el propio objetivo (sitemap.xml) →
  superficie F1 sin ruido.
- `recon.rutas_sensibles`: exposición de .git/.env/backups/server-status
  (un GET por ruta candidata) → hallazgo alto si procede. Clasificados en el
  catálogo del boundary (ventana/ruido) y cableados en F1/F2.

### Endurecimiento y optimización

- Cabeceras de seguridad en la consola (X-Frame-Options, nosniff,
  Referrer-Policy, Permissions-Policy) y `poweredByHeader` desactivado.
- GZip en la API (informes/exportaciones), SQLite `synchronous=NORMAL` con
  WAL, índice de descubrimiento de objetivos, deduplicación de métodos
  duplicados en memoria.py (bug de mantenimiento).

## 12. Ronda v8 — razonamiento adaptativo y robustez de la IA

### Motor de razonamiento adaptativo (`orchestrator/razonador.py`)

Tres niveles de razonamiento, todos sobre datos REALES del caso y todos
propuesta (nada ejecuta acciones):

1. **Cobertura determinista** (`evaluar_cobertura`): inventario puro de la
   superficie (objetivos por tipo/estado, hallazgos por severidad,
   transportes aplicados según auditoría, huecos por fase). Sin LLM:
   instantáneo, determinista y auditable.
2. **Adaptabilidad sin modelo** (`prioridades_siguientes`): motor de reglas
   que reordena los siguientes pasos según lo descubierto (rutas en riesgo
   → verificación, ventana cerrada → pospone trabajo intrusivo, credenciales
   confirmadas → canal F3). La plataforma se adapta aunque no haya LLM.
3. **Plan y reflexión con IA** (`planificar_fase`, `reflexion_fase`): el
   modelo propone un plan de fase con confianza por paso, VALIDADO contra
   el catálogo real de 18 transportes (las herramientas inventadas se
   descartan y se auditan); la reflexión autocrítica de fase se estructura
   en Observaciones/Huecos/Hipótesis/Siguientes pasos. Sin backend: error
   503 con el requisito exacto, jamás un plan fingido.

Toda traza se persiste en la tabla `razonamientos` (append-only) con
SHA-256 de entrada y salida, modelo, tokens y coste: lo que la IA razonó
es evidencia verificable. Vista nueva **Razonamiento** en la consola.

### Router IA resiliente (`orchestrator/router.py`)

- **Circuit breaker** por backend: 3 fallos consecutivos abren el circuito
  60 s; el router enruta al otro backend si existe (frontera↔local) o
  documenta el requisito exacto (`BackendIndisponible`).
- **Reintentos con backoff exponencial + jitter** (2 por defecto) solo para
  errores transitorios (429/5xx/timeout/red); los 4xx no se reintentan.
- **Presupuesto duro por caso**: `config_caso['presupuesto_caso_tokens']`;
  superado el consumo real → `PresupuestoAgotado` (control consciente de
  economía, elevable por el operador).
- **Temperatura por tarea**: razonamiento analítico 0.1–0.2 (propuestas
  reproducibles), redacción 0.5–0.6. Nuevas tareas: `planificacion_adaptativa`
  y `reflexion_cobertura` (frontera).

### Copiloto con razonamiento estructurado

Respuesta obligatoria en secciones (Observaciones → Análisis → Riesgos y
OPSEC → Siguientes pasos) + bloque JSON final con **sugerencias
accionables** (título, detalle, confianza 0-1, canal correcto: fase o
aprobación) que la consola renderiza como chips clicables. Multi-turno
real: la consola envía el hilo reciente (el servidor no guarda estado de
conversación). Si el modelo no entrega el bloque JSON, el texto sigue
siendo válido y las sugerencias quedan vacías: nunca se fabrican.

### Producción

- `/api/salud` con componentes reales (memoria de casos, operadores,
  router con estado de circuito) para monitorización/HEALTHCHECK.
- **Limitador de tasa** en login/registro (ventana deslizante 10/min → 429
  con Retry-After); el proxy de la consola propaga `X-Forwarded-For` para
  no agrupar operadores en el cubo de 127.0.0.1 (bug detectado en E2E).
- **X-Request-ID** en toda respuesta (correlación con logs/proxies).
- Fix: `copiloto/config` POST devuelve el estado completo (política +
  backends); antes la UI perdía la configuración tras alternar.

### Validación v8

- 92/92 pytest (17 nuevos: cobertura, prioridades, validación de catálogo,
  circuito, presupuesto, trazas, auth de endpoints).
- E2E vivo `scripts/e2e_v8_razonador.py` (14/14): plan GLM real en ~5 s con
  6 pasos válidos, reflexión 4/4 secciones, trazas con hash, 429 real.
- Consola: vista Razonamiento verificada en navegador (cobertura, plan,
  reflexión, trazas), copiloto con sugerencias accionables, móvil 390px
  sin overflow, tsc y eslint limpios.

## 13. Ronda v9 — pulido de producción, concurrencia y respaldo de archivo

### Caza de bugs: hallazgos y correcciones

1. **Fuga de conexiones SQLite en la API** — más de quince endpoints abrían
   `MemoriaCaso` por petición sin cerrarla (solo el GC las recogía): fuga de
   descriptores, ficheros WAL sin checkpoint y riesgo de `database is locked`
   bajo carga. Corregido de forma sistemática: `MemoriaCaso` es ahora
   *context manager* (`__enter__/__exit__` con commit de cierre) y TODOS los
   endpoints usan `with _memoria_de(...) as memoria` o `try/finally`
   (incluido `/avanzar`, que además cierra el pool httpx del router, y el
   copiloto y razonamiento, que fugaban un httpx.Client por petición).
2. **Flujo SSE moría por hilos** — `sqlite3.ProgrammingError: SQLite objects
   created in a thread can only be used in that same thread` en los logs: el
   generador del stream se itera desde hilos worker distintos de anyio.
   Fix: conexión propia del generador con `check_same_thread=False` +
   `busy_timeout` (un único propietario, uso seguro). Verificado en vivo:
   cero errores de hilo tras el reinicio.
3. **Proxy corrupto para binarios** — el proxy de la consola hacía
   `r.text()` + re-encode de TODAS las respuestas: cualquier entrega binaria
   (respaldo ZIP) llegaba corrupta al navegador (bytes sustituidos por
   U+FFFD). Detectado en E2E de navegador (ZIP inválido con cabecera
   `PK\x03\x04\xEF\xBF\xBD`). Fix: el proxy transmite `r.body` como stream
   de bytes sin decodificar, preservando content-type y content-disposition.
4. **Limitador de tasa sin poda de memoria** — el diccionario de cubos
   crecía sin límite y la clave era suplantable vía `X-Forwarded-For` del
   cliente (acceso directo al :3000). Fix: poda de claves caducadas + tope
   duro de 10.000 claves expulsando las más antiguas; el proxy ahora usa
   `x-real-ip` (fijado por Caddy) o el ÚLTIMO salto de XFF, nunca el
   primero (controlado por el cliente).
5. **Registro de intentos de login sin poda** — usuarios inexistentes
   creaban claves infinitas en `auth._intentos` (fuerza bruta con nombres
   aleatorios = crecimiento de memoria). Fix: poda simétrica con tope duro.
6. **Techo de ruido del ROE no persistente** — `ruido_acumulado` del boundary
   arrancaba a 0 en cada petición: el techo de ruido acordado con el cliente
   solo vigilaba la fase en curso. Fix: el motor carga el ruido YA firmado
   del caso (suma de `ruido_estimado` de aprobaciones aprobadas).
7. **Auditoría sin identidad en `roe.actualizar`** — la auditoría decía
   "decisión humana" sin quién la firmó, y los modelos de petición
   (`PeticionParada`/`PeticionRoe`) aún traían un campo `operador` muerto
   editable por el cliente. Fix: identidad real del JWT en el detalle y
   campos eliminados (la identidad JAMÁS viaja en el cuerpo).
8. **Deprecaciones y código muerto** — `on_event("startup")` → `lifespan`
   con `@asynccontextmanager`; `datetime.utcnow()` (deprecado en 3.12) →
   `datetime.now(timezone.utc)` en fases y reporting; bucle no-op del CSV
   eliminado; imports redundantes en `crear()`.

### Concurrencia SQLite

- `PRAGMA busy_timeout=5000` en la memoria de casos, el almacén de
  operadores y la conexión del flujo SSE: los escritores se encolan en vez
  de fallar la petición del operador con `database is locked`.

### Nuevo entregable: respaldo de archivo del caso

- `GET /api/engagements/{id}/respaldo` — ZIP REAL con `caso.json`
  (paquete de custodia orquestart-caso/1 con cadena verificada),
  `informe.md`, `informe.html` y `MANIFIESTO.txt` (estado de la cadena,
  recuentos y fecha). Uso operativo: archivado al cierre, transferencia al
  gestor documental, conservación legal. Auditado como `caso.respaldo`.
- Consola: acción "Respaldo de archivo del caso (ZIP)" en la paleta
  (Ctrl/Cmd+K) con descarga vía proxy binario-seguro.

### Validación v9

- 102/102 pytest (10 nuevos: poda del limitador, poda de intentos, context
  manager con y sin excepción, ruido previo cargado, respaldo ZIP completo
  con manifiesto y custodia, 404/401 del respaldo, identidad en ROE).
- Smoke en vivo `scripts/smoke_v9.sh` (13/13) contra el backend real.
- E2E de navegador: login real → paleta → respaldo ZIP descargado y
  VALIDADO byte a byte (PK\x03\x04, custodia VÁLIDA, 4 entradas);
  flujo SSE estable con heartbeats; tsc y eslint limpios.
