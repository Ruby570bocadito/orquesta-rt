# OrquestaRT — Plataforma de Red Team Orquestado por IA

> Blueprint técnico · Ciberseguridad ofensiva · Código cerrado · Licencia on-prem
> España / LATAM · Septiembre 2026

Implementación del **blueprint "Red Team Orquestado por IA"**: arquitectura agéntica
completa para operaciones ofensivas autorizadas — orquestación multiagente (F0→F7),
servidores MCP, skills con progressive disclosure, guardrails ROE con
*operator-in-command* y economía del token. Despliegue on-prem, interfaz e informes
en español.

---

## ⚠️ Aviso legal y de uso

Este software es **herramienta profesional para pruebas de intrusión AUTORIZADAS**.
Su uso está condicionado a:

- **ROE firmado**: ningún engagement sin reglas de compromiso máquina-legibles firmadas por el operador y el cliente.
- **Operator-in-command**: toda acción crítica (explotación, escalada, C2, envío de campaña) exige firma humana en consola. El agente no ejecuta nada por encima del umbral de riesgo.
- **Boundary fuera del modelo**: los guardrails viven en el límite de cada tool call, no en el prompt. Intentar una acción destructiva (`T1485`, `T1489`, `T1490`) se bloquea y se registra, siempre.
- **Lab simulado**: los módulos sensibles (C2, explotación, phishing) son adaptadores MCP con MOCK de laboratorio. Nada de este repositorio contiene payloads operativos; la integración con tooling licenciado (Sliver/Mythic, plataformas de simulación) se hace vía el contrato MCP documentado.

El uso contra sistemas sin autorización expresa es ilegal. La auditoría inmutable
existe, entre otras cosas, para demostrar qué se hizo y quién lo aprobó.

## Estructura del repositorio

```
├── src/                        Consola del operador (Next.js 16, TypeScript)
│   ├── app/page.tsx            La raíz ES la consola: 10 vistas conectadas en vivo
│   ├── lib/store.ts            Cliente en vivo de la API del orquestador (sondeo 3 s)
│   ├── lib/tipos.ts            Contrato de datos (espejo de orchestrator/models.py)
│   ├── instrumentation.ts      Arranque del backend Python junto al servidor Next
│   └── app/api/orchestrator/   Proxy REST al orquestador (auto-bootstrap si está caído)
├── platform/                   Núcleo propietario (Python 3.12)
│   ├── orchestrator/
│   │   ├── models.py           Dominio: engagement, ROE, hallazgos, evidencias, aprobaciones
│   │   ├── guardrails.py       Motor del boundary: scope + ROE + riesgo → permitir/aprobación/denegar
│   │   ├── memory.py           SQLite por caso: auditoría append-only + cadena de custodia
│   │   ├── router.py           Router semántico de modelos + economía del token + compaction
│   │   ├── skills.py           Biblioteca de skills (progressive disclosure)
│   │   ├── graph.py            Orquestador del ciclo (grafo LangGraph, fases F0-F7)
│   │   ├── agents/fases.py     Agentes de fase (F0-F2 y F7 plenos; F3-F6 vía adaptadores)
│   │   ├── transportes.py      Herramientas REALES: httpx, DNS, sockets, TLS, crt.sh, HIBP
│   │   ├── sidecar.py          Guardián de resiliencia del despliegue
│   │   ├── reporting.py        Consolidación del informe (markdown español + ATT&CK)
│   │   ├── api.py              API FastAPI de la consola
│   │   ├── cli.py              CLI del operador (typer)
│   │   └── demo_seed.py        Escenario ACME de demostración
│   ├── mcp/                    Servidores MCP: recon, evidencias, OSINT, adaptador C2
│   ├── skills/                 Biblioteca de skills (ej.: kerberoasting_lab)
│   ├── roe/                    Plantilla de ROE máquina-legible
│   ├── tests/                  Tests del núcleo (pytest, 13 tests)
│   └── lab/                    Objetivo HTTP real del laboratorio (127.0.0.1:8080)
├── docker-compose.yml          Despliegue on-prem completo
└── docs/ARQUITECTURA.md        Documentación de arquitectura
```

## Arranque rápido

### Instalación en un paso (recomendada)

```bash
./install.sh   # crea .venv, instala backend + consola, verifica todo
./start.sh     # levanta orquestador (:8000), lab (:8080) y consola (:3000)
./stop.sh      # parada limpia
```

`install.sh` es idempotente (puedes relanzarlo): crea el entorno virtual
`.venv` con las dependencias del orquestador y las de la consola, y al
terminar **verifica de verdad** que uvicorn/fastapi/cryptography importan.
Así el backend arranca siempre, aunque el `python3` del sistema esté vacío
(fallo típico tras un reinicio: "No module named uvicorn" sin diagnóstico).

### Alternativa manual / desarrollo

```bash
pip install -r platform/requirements.txt   # dependencias del núcleo
bun install
bun run dev        # http://localhost:3000
```

Al arrancar, la consola levanta **el orquestador Python (puerto 8000) y el
objetivo del lab (127.0.0.1:8080)** como procesos supervisados, resolviendo
el intérprete en este orden: `ORQUESTA_PYTHON` → `.venv/bin/python3` →
`python3` del PATH (probando que importe uvicorn+fastapi). No hay modo
demostración: la consola opera SIEMPRE contra el backend real.

**Acceso de operador (v6):** la API es deny-by-default. En el primer arranque
la consola muestra el alta del primer operador (cuenta admin, contraseña con
scrypt + JWT HS256 en el backend); a partir de ahí, login obligatorio y cada
decisión de firma ROE queda vinculada a la identidad autenticada en la
auditoría inmutable. Eventos del caso en vivo por SSE con fallback a sondeo.
Reglas del usuario: 3-32 caracteres, letras/números y `. _ -` (sin espacios);
la consola valida el formato ANTES de enviar, y si la cuenta ya existe te
devuelve al login con un aviso claro en lugar de un error 400.

Flujo del operador:

1. **Casos → Nuevo engagement**: firma el ROE (dominios/CIDRs en alcance,
   exclusiones, técnicas MITRE prohibidas, techo de ruido, ventana horaria).
2. **Ejecutar fase**: el agente ejecuta la fase activa con herramientas reales
   acotadas al ROE (CT logs, DNS, robots.txt, barrido de puertos por socket,
   sondeo HTTP, TLS, fingerprint).
3. **Aprobaciones**: el boundary detiene cada acción por encima del umbral de
   riesgo y espera tu firma. La coincidencia de la firma es EXACTA (tool +
   argumentos): aprobar un vector no autoriza otro.
4. **Parada de emergencia**: kill switch del ROE — el boundary deniega toda
   tool call hasta que lo desactives. Queda en la auditoría inmutable.
5. **Informe**: el backend consolida el markdown con ATT&CK, cadena de
   custodia y decisiones del operador; la vista Evidencias re-verifica
   independientemente los hashes y el encadenado en el navegador.

Para operar contra el lab local, crea el caso con dominio `localhost` y CIDR
`127.0.0.0/8`. Para un cliente real, define su alcance real: el boundary
denegará todo lo demás (verificado: un objetivo fuera de scope recibe
"denegar" en el boundary y queda en la auditoría).

### Núcleo Python (tests + CLI)

```bash
cd platform
pip install -r requirements.txt
python -m pytest tests/ -v          # 13 tests del boundary y la memoria
python -m orchestrator.cli demo     # siembra el caso demo con datos reales del núcleo
python -m orchestrator.cli estado caso_demo_acme
python -m orchestrator.cli informe caso_demo_acme
```

### Despliegue on-prem completo

```bash
cp platform/.env.example platform/.env   # configurar claves
docker compose up -d                     # orquestador + consola
docker compose --profile lab up -d       # + objetivo simulado del lab
docker compose --profile gpu up -d       # + vLLM para inferencia 100% local
```

Para Kubernetes (namespace, secret, PVC, despliegues con sondas reales,
Ingress TLS y respaldos): **[deploy/README.md](deploy/README.md)**.

## 🎥 Demostración

La consola operando de verdad — cobertura ATT&CK entre campañas, purple
teaming y webhooks firmados — con capturas y GIF del uso real:
**[docs/DEMOSTRACION.md](docs/DEMOSTRACION.md)**.

¿Nuevo en el proyecto? La explicación en lenguaje llano — qué es, para quién,
cómo funciona y cómo se usa — está en
**[docs/COMO_FUNCIONA.md](docs/COMO_FUNCIONA.md)**.

## El ciclo ofensivo (F0→F7)

| Fase | Qué hace la IA | Qué aprueba el humano | Artefacto |
|------|----------------|----------------------|-----------|
| F0 Scoping | Redacta alcance, ROE y criterios de éxito | Firma el ROE | Contrato versionado |
| F1 OSINT | Recolectores paralelos, deduplica y puntúa | Autoriza filtraciones | Mapa de superficie |
| F2 Recon | Enumera, correlaciona, ordena vectores por probabilidad/ruido | Valida el vector inicial | Inventario ATT&CK |
| F3 Acceso | Prepara explotación vía adaptador, plan B ante rechazo | **Autoriza cada explotación** | Evidencias de entrada |
| F4 Dominio AD | Grafo del dominio, rutas a DA ordenadas por ruido | **Aprueba la escalada** | Ruta verificada |
| F5 C2 | Adaptador (mock) con jitter OPSEC y techo de ruido | **Autoriza implantes** | Telemetría postex |
| F6 Phishing | Plantillas de simulación personalizadas | **Aprueba plantilla y destinatarios** | Métricas de campaña |
| F7 Informe | Consolida evidencias, mapea ATT&CK, redacta | Revisa y firma | Informe DOCX/PDF |
| Cierre | Limpieza documentada | Valida la higiene | Certificado de borrado |

## Guardrails: el boundary no negocia

Toda tool call pasa por `guardrails.py` **antes** de ejecutarse, con tres verificaciones
independientes:

1. **Scope** — ¿el objetivo está en `alcance_dominios`/`alcance_cidrs` y fuera de `alcance_excluido`?
2. **Política ROE** — ¿técnica prohibida? ¿ventana horaria? ¿techo de ruido?
3. **Riesgo** — ¿acción destructiva (bloqueada siempre) o sensible (exige firma humana)?

Las instrucciones del prompt **no** son controles de seguridad: la aprobación vive
fuera del modelo (principio OWASP de prevención de inyección de prompts).

## Economía del token

- Router semántico: enumeración/parsing al LLM local (0 $/llamada); decisiones críticas al modelo de frontera.
- Prompt caching: prefijo estable (system + ROE + índice de skills) al principio del contexto.
- Compaction al cerrar cada fase: la siguiente arranca con un resumen denso, no con la historia lineal.
- Presupuestos por fase con techo; la memoria del caso guarda el consumo exacto por modelo.

## Roadmap (blueprint cap. 6.3)

- **M1 (este repositorio)** — núcleo orquestador + memoria + servidores MCP + consola + guardrails ROE ✔
- **M2** — agentes OSINT/recon con subagentes aislados + router con caching medido (< 0,05 $/sesión) ✔ (v5–v7)
- **M3** — agente AD completo (BloodHound real, skills de escalada, guardrails en lab de AD)
- **M4** — integración C2 (Sliver/Mythic vía API oficial) + políticas de ruido ✔ (v5)
- **M5** — phishing con métricas + reporting DOCX/PDF en español (< 1 h de revisión humana)

## Novedades v7 — producción, optimización y nuevas habilidades

- **Puente IA real**: `/api/ia` expone GLM (SDK de la consola) en formato
  OpenAI-compatible con token interno (0600); el router de modelos ahora
  tiene frontera REAL → copiloto del caso operativo con contabilidad de tokens.
- **Copiloto del caso**: análisis conversacional con RAG local (BM25) sobre
  la memoria del caso; habilitación por caso firmada en auditoría (decisión
  de perímetro consciente); nunca ejecuta acciones.
- **Equipo (admin)**: alta/rol/restablecimiento/baja de operadores con
  protección de último admin; regresión del alta post-bootstrap corregida
  con test dedicado.
- **Entregables**: exportación de custodia JSON (cadena verificada), CSV de
  hallazgos y diferencial de superficie por fecha en Objetivos.
- **Webhook firmado** (HMAC-SHA256) que notifica cada firma exigida por el
  boundary a Slack/Mattermost/n8n/endpoint propio.
- **3 transportes nuevos** (26 total): postura de correo (SPF/DMARC/DKIM),
  sitemap.xml y artefactos sensibles (.git/.env/backups).
- **Endurecimiento**: cabeceras de seguridad, GZip, SQLite synchronous=NORMAL,
  índice de descubrimiento. Smoke `scripts/smoke_v7.sh` (11 comprobaciones).

## Licencia

Software propietario de código cerrado. Véase [LICENSE](LICENSE). La distribución,
el uso en producción y la conexión de módulos ofensivos licenciados están sujetos
al contrato comercial del proveedor.

## Ronda v8 — razonamiento adaptativo

- **Motor de razonamiento adaptativo** (`razonador.py`): cobertura
  determinista de la superficie, prioridades por reglas (adaptabilidad sin
  LLM), plan de fase con IA validado contra el catálogo real de transportes
  (las herramientas inventadas se descartan) y reflexión autocrítica de
  fase. Toda traza con SHA-256 de entrada/salida en la tabla
  `razonamientos`. Nueva vista **Razonamiento** en la consola.
- **Router IA resiliente**: circuit breaker por backend con failover
  frontera↔local, reintentos con backoff exponencial para errores
  transitorios, presupuesto duro de tokens por caso
  (`presupuesto_caso_tokens`) y temperatura por tarea.
- **Copiloto estructurado**: Observaciones → Análisis → Riesgos/OPSEC →
  Siguientes pasos + sugerencias accionables con confianza y canal;
  conversación multi-turno real.
- **Producción**: `/api/salud` con componentes, limitador de tasa en
  autenticación (429 + X-Forwarded-For correcto vía proxy), X-Request-ID.
  Tests 92/92 · E2E `scripts/e2e_v8_razonador.py` (14 comprobaciones).

## Ronda v9 — pulido de producción y respaldo de archivo

Auditoría de concurrencia, seguridad y entrega binaria con **ocho correcciones
reales** (todas con test de regresión):

- **Sin fugas de recursos**: `MemoriaCaso` es context manager y toda la API
  cierra memoria SQLite y pool httpx del router (`try/finally`); el flujo SSE
  ya no muere al cambiar de hilo worker (`check_same_thread=False` propio del
  generador); `PRAGMA busy_timeout=5000` contra `database is locked`.
- **Proxy binario-seguro**: las descargas (respaldo ZIP) viajan como stream de
  bytes sin `r.text()` — antes el navegador recibía el ZIP corrupto (detectado
  en E2E con la cabecera `PK\x03\x04\xEF\xBF\xBD`).
- **Memoria acotada ante abuso**: poda + tope duro en el limitador de tasa y en
  el registro de intentos de login; la clave del cubo ya no es suplantable
  (`x-real-ip` / último salto XFF).
- **ROE más fiel al contrato**: techo de ruido PERSISTENTE (carga el ruido ya
  firmado del caso) e identidad real en la auditoría de `roe.actualizar`.
- **Nuevo entregable**: `GET /respaldo` — ZIP con custodia JSON + informes
  MD/HTML + manifiesto; acción "Respaldo de archivo del caso (ZIP)" en la
  paleta de comandos.

Validación: **102/102 pytest**, smoke en vivo `scripts/smoke_v9.sh` (**13/13**),
E2E de navegador con respaldo ZIP validado byte a byte, SSE estable, tsc/eslint
limpios. Detalle técnico en `docs/ARQUITECTURA.md` §13.
