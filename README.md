# OrquestaRT — Plataforma de Red Team Orquestado por IA

![CI](https://github.com/Ruby570bocadito/orquesta-rt/actions/workflows/ci.yml/badge.svg)
![Python](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)
![Next.js](https://img.shields.io/badge/Next.js-16-black?logo=next.js)
![Tests](https://img.shields.io/badge/pytest-290%20tests-2EA043)
![Licencia](https://img.shields.io/badge/Licencia-propietaria%20on--prem-red)

> Arquitectura agéntica completa para operaciones ofensivas **autorizadas**:
> orquestación multiagente (F0→F7), boundary ROE *operator-in-command*, cadena
> de custodia de evidencias, cadenas threat-led estilo Atomic Red Team,
> rutas de ataque reales con Neo4j/BloodHound, SSO federado y multi-tenant.
> Interfaz, informes y auditoría en español. Despliegue on-prem, Docker/K8s.

![Recorrido de la consola](docs/demo/recorrido.gif)

*Recorrido real: acceso del operador → campañas → matriz de cobertura ATT&CK
entre campañas → hallazgos con purple teaming → webhooks firmados. Todo
operando contra el orquestador y el laboratorio reales — sin maquetas.*

| | |
|---|---|
| ![Panel del operador](docs/demo/03-panel.png) | ![Cobertura ATT&CK](docs/demo/04-cobertura.png) |
| *Panel del caso en vivo (SSE): fases, aprobaciones, parada de emergencia.* | *Cobertura ATT&CK entre campañas: heatmap estilo Navigator, detección VECTR, técnicas recurrentes.* |

---

## ⚠️ Aviso legal y de uso

Este software es **herramienta profesional para pruebas de intrusión
AUTORIZADAS**. Su uso está condicionado a:

- **ROE firmado**: ningún engagement sin reglas de compromiso máquina-legibles
  firmadas por el operador y el cliente. El boundary deniega todo lo que esté
  fuera de alcance — verificado con tests y en E2E.
- **Operator-in-command**: toda acción crítica (explotación, escalada,
  movimiento lateral, envío de campaña, implantación de persistencia) exige
  firma humana en consola. La coincidencia de la firma es EXACTA (tool +
  argumentos): aprobar un vector no autoriza otro.
- **Boundary fuera del modelo**: los guardrails viven en el límite de cada
  tool call, no en el prompt. Las acciones destructivas (`T1485`, `T1489`,
  `T1490`) se bloquean y se auditan, siempre. Ninguna instrucción del modelo
  puede saltarse el boundary (principio OWASP contra inyección de prompts).
- **Laboratorio propio**: las capacidades ofensivas se ejecutan contra el
  laboratorio local (`127.0.0.1:8080`, dominio AD de laboratorio). Este
  repositorio no contiene payloads operativos contra terceros.

El uso contra sistemas sin autorización expresa es ilegal. La auditoría
append-only con cadena de custodia (SHA-256 + HMAC encadenados) existe,
entre otras cosas, para demostrar qué se hizo, cuándo y quién lo aprobó.

## Qué es y para quién es

**OrquestaRT** es la consola de mando de un equipo red team asistido por IA:
planifica campañas threat-led, ejecuta técnicas reales en el laboratorio bajo
ROE, registra hallazgos con evidencia verificable, mide la cobertura ATT&CK y
de detección del blue team, y produce el informe final en español. Está
pensada para equipos de seguridad ofensiva (red team / pentesting / threat
simulación) que necesitan **gobernanza**: nada se ejecuta sin ROE firmado,
nada crítico sin firma humana, y cada acción queda en una auditoría inmutable
que el cliente puede verificar.

Si vienes de herramientas tipo Caldera, Picus o SCYTHE, la diferencia es que
aquí el ciclo completo — scoping, OSINT, recon, acceso, AD, post-explotación,
phishing, informe — está orquestado por agentes con un boundary político
común, y la detección del defensor es un resultado de primera clase
(purple teaming integrado, no un anexo).

## Capacidades (reales, verificables)

| Capacidad | Estado | Detalle |
|---|---|---|
| Orquestación F0→F7 | ✅ Real | Grafo LangGraph; agentes de fase; pausa por aprobaciones; SSE en vivo |
| Boundary ROE + riesgo | ✅ Real | Scope (dominios/CIDRs), política (técnicas prohibidas, ventana, techo de ruido), riesgo; kill switch |
| Cadena de custodia | ✅ Real | SHA-256 + HMAC encadenados por evidencia; re-verificación en el navegador |
| OSINT + grafo de empleados | ✅ Real | Recolectores reales (CT logs, DNS, crt.sh, HIBP, SPF/DMARC/DKIM…), grafo en consola |
| Recon | ✅ Real | 26+ transportes: puertos por socket, TLS, fingerprint, sitemap, artefactos sensibles |
| Active Directory | ✅ Real en lab | LDAP, Kerberos (kerberoasting, AS-REP), movimiento lateral (SMB), DCSync bajo ROE |
| Persistencia | ✅ Real en lab | Implantación con aprobación explícita y limpieza certificada en el cierre |
| Evasión de AV | ✅ Real en lab | Módulos auditables con verificación de firmas YARA antes/después |
| Phishing | ✅ Real en lab | Campañas con plantilla y destinatarios aprobados, métricas, sigilo frente al blue team |
| Cadenas threat-led | ✅ Real | 4 cadenas estilo Atomic Red Team contrastadas contra la evidencia del caso (ruido prometido = ruido exigido) |
| Rutas de ataque | ✅ Real | Motor Neo4j con esquema BloodHound; rutas críticas resueltas por el servidor (allShortestPaths) |
| Threat intel | ✅ Real | MISP (protocolo oficial) + NVD público; sin instancia configurada exige el requisito exacto |
| SSO federado | ✅ Real | OIDC authorization-code + PKCE S256, verificación RS256 del id_token vía JWKS, alta JIT |
| Multi-tenant RBAC | ✅ Real | Roles admin/gestor/operador/lector firmados en el JWT; aislamiento de casos por organización en la API |
| Webhooks | ✅ Real | Entrega firmada HMAC-SHA256, reintentos acotados, anti-SSRF, historial de entregas |
| Purple teaming | ✅ Real | Registro de detección/preención por técnica (VECTR), esqueletos Sigma solo con fuente de logs conocida |
| Cobertura ATT&CK | ✅ Real | Matriz técnica × campaña entre casos, CSV exportable, capa Navigator |
| Copiloto IA | ✅ Real | GLM vía puente OpenAI-compatible; RAG BM25 sobre la memoria del caso; nunca ejecuta acciones |
| Informe + cierre | ✅ Real | Markdown español con ATT&CK, DOCX/PDF, certificado de borrado documentado |
| Despliegue | ✅ Real | Docker multi-stage no-root con healthcheck; K8s con sondas, TLS y PVC; devcontainer para Codespaces |

Cada integración externa (Keycloak, Neo4j/BloodHound, MISP) habla su protocolo
oficial con la instancia real del operador; **si no está configurada, la
plataforma no finge datos**: muestra el requisito exacto y el error real.

## Arquitectura

```
┌──────────────────────────────────────────────────────────────────┐
│  Consola del operador (Next.js 16 · :3000)                       │
│  18 vistas en vivo · SSE + sondeo · paleta Ctrl/Cmd+K · móvil    │
└───────────────▲──────────────────────────────────────────────────┘
                │ /api/orchestrator/* (proxy) + SSE
┌───────────────┴──────────────────────────────────────────────────┐
│  Orquestador (FastAPI + LangGraph · :8000)                       │
│  auth.py (scrypt+JWT, RBAC, SSO OIDC) · guardrails.py (boundary) │
│  memory.py (SQLite por caso, auditoría append-only, custodia)    │
│  graph.py + agents/fases.py (F0→F7) · threatled.py · razonador   │
│  copiloto.py · reporting.py · navigator.py · webhook.py          │
│  purpleteam.py · cobertura_attack.py · respaldo.py · sidecar.py  │
└──────┬───────────────┬───────────────┬───────────────────────────┘
       │               │               │
┌──────▼─────┐  ┌──────▼──────┐  ┌─────▼─────────────┐
│ Lab :8080  │  │ Integraciones│  │ Frontera IA (GLM) │
│ HTTP+AD de │  │ Neo4j/BloodH │  │ router semántico  │
│ laboratorio│  │ MISP · NVD   │  │ local↔frontera    │
└────────────┘  │ Keycloak SSO │  └───────────────────┘
                └─────────────┘
```

## Arranque rápido

### Local en dos comandos (recomendado)

```bash
./install.sh   # idempotente: crea .venv, instala backend+consola, VERIFICA imports
./start.sh     # orquestador (:8000) + lab (:8080) + consola (:3000)
./stop.sh      # parada limpia (SIGTERM + drenaje + relevo forzado)
```

En el primer arranque la consola guía el alta del primer administrador.
Sin modo demostración: la consola opera SIEMPRE contra el backend real.

### GitHub Codespaces

El repositorio incluye `.devcontainer/devcontainer.json` (Node 22 + Python
3.12 + bun, `./install.sh` como post-create). Abre el repo en Codespace y
ejecuta `./start.sh` — los puertos 3000/8000/8080/8081/7474/7687 ya están
declarados. Los servicios pesados del laboratorio (Keycloak, Neo4j) se
levantan con sus scripts de `lab/` cuando los necesites.

### Docker Compose y Kubernetes

```bash
cp platform/.env.example platform/.env   # configurar claves
docker compose up -d                     # orquestador + consola (no-root, healthcheck)
docker compose --profile lab up -d       # + laboratorio

# Kubernetes: namespace, secret con placeholders, PVC, sondas reales,
# Ingress TLS con timeouts SSE y respaldos VACUUM INTO → deploy/README.md
```

### Servicios del laboratorio (AD, SSO, grafo)

```bash
lab/keycloak_arrancar.sh && lab/provisionar_keycloak.sh   # IdP OIDC real (:8081)
lab/neo4j_arrancar.sh                                      # motor de rutas (:7474/:7687)
lab/coleccion_dominio.py                                   # colector → ingestión en Neo4j
```

### Flujo del operador

1. **Casos → Nuevo engagement**: firma el ROE (dominios/CIDRs, exclusiones,
   técnicas prohibidas, techo de ruido, ventana horaria).
2. **Ejecutar fase**: el agente ejecuta con herramientas reales acotadas al
   ROE; el razonador valida que cada herramienta del plan exista en el
   boundary (nada inventado).
3. **Aprobaciones**: el boundary detiene cada acción sensible y espera tu
   firma exacta. **Parada de emergencia**: kill switch auditable.
4. **Cadenas threat-led**: elige una cadena ART; la plataforma contrasta cada
   paso con la evidencia ya recogida del caso (ejercitado / disponible / manual).
5. **Integraciones**: conecta Keycloak (SSO), Neo4j/BloodHound (rutas),
   MISP/NVD (intel) y receptores de webhook — con prueba de conexión real.
6. **Informe + cierre**: consolidación markdown/DOCX-PDF con ATT&CK, custodia
   verificable y limpieza certificada.

Para operar contra el lab local, crea el caso con dominio `localhost` y CIDR
`127.0.0.0/8`: el boundary denegará todo lo demás y lo dejará en la auditoría.

## Estructura del repositorio

```
├── src/                          Consola del operador (Next.js 16, TypeScript)
│   ├── app/page.tsx              La raíz ES la consola (18 vistas)
│   ├── lib/store.ts              Cliente en vivo de la API (SSE + sondeo, fallback)
│   ├── instrumentation.ts        Arranque supervisado del backend Python
│   └── components/consola/       Vistas: panel, cadenas, rutas, cobertura,
│                                 integraciones, equipo, copiloto, webhooks…
├── platform/                     Núcleo propietario (Python 3.12)
│   ├── orchestrator/
│   │   ├── models.py             Dominio: engagement, ROE, hallazgos, evidencias
│   │   ├── guardrails.py         Boundary: scope + política + riesgo → permitir/firmar/denegar
│   │   ├── memory.py             SQLite por caso: auditoría append-only + custodia HMAC
│   │   ├── auth.py               scrypt + JWT, RBAC multi-tenant, organizaciones
│   │   ├── sso.py                OIDC + PKCE, verificación RS256 vía JWKS (stdlib pura)
│   │   ├── graph.py              Orquestador del ciclo (LangGraph F0→F7)
│   │   ├── agents/fases.py       Agentes de fase (OSINT, recon, AD, postex, phishing…)
│   │   ├── transportes.py        Herramientas reales de red (26+ transportes)
│   │   ├── ad.py / persistencia.py / evasion.py   Capacidades ofensivas (lab, bajo ROE)
│   │   ├── threatled.py          Cadenas Atomic Red Team + contraste con evidencia
│   │   ├── razonador.py          Plan de fase adaptativo validado contra el catálogo real
│   │   ├── copiloto.py           Copiloto IA (RAG BM25 sobre la memoria del caso)
│   │   ├── cobertura_attack.py   Matriz ATT&CK técnica × campaña entre casos
│   │   ├── purpleteam.py         Registro VECTR + esqueletos Sigma
│   │   ├── webhook.py            Receptores firmados HMAC + entregas
│   │   ├── navigator.py          Capas MITRE ATT&CK Navigator
│   │   ├── reporting.py          Informe español (MD/HTML) + ATT&CK
│   │   ├── respaldo.py           ZIP de archivo con manifiesto (VACUUM INTO)
│   │   └── api.py                API FastAPI de la consola
│   ├── integraciones/            bloodhound.py · misp.py · nvd.py (protocolo oficial)
│   ├── mcp/                      Servidores MCP: recon, evidencias, OSINT, adaptador C2
│   ├── skills/                   asrep_roasting_lab · kerberoasting_lab · llmnr_poisoning_lab
│   ├── roe/                      Plantilla de ROE máquina-legible
│   └── tests/                    Suite pytest (290 tests)
├── lab/                          Laboratorio: objetivo HTTP+AD, Keycloak, Neo4j,
│                                 colector de dominio, docker-compose.lab.yml
├── deploy/                       Kubernetes (manifiestos + guía de despliegue)
├── docs/                         ARQUITECTURA · COMO_FUNCIONA · DEMOSTRACION (+ media)
├── .devcontainer/                Codespaces (Node 22 + Python 3.12 + bun)
├── .github/workflows/ci.yml      CI: pytest completo + tsc + eslint
└── docker-compose.yml            Despliegue on-prem completo
```

## Seguridad del producto

- **Identidad**: scrypt + JWT HS256; roles jerárquicos (admin > gestor >
  operador > lector) firmados en el token; middleware deny-by-default — un
  endpoint nuevo de escritura queda protegido sin tocar su código.
- **Multi-tenant**: organizaciones que aíslan casos en la API (no en el
  cliente); otra organización → 403, inexistente → 404.
- **SSO**: flujo authorization-code + PKCE; `state` de un solo uso; el
  id_token se verifica criptográficamente contra el JWKS del IdP; alta JIT
  como lector con hash inalcanzable para login por contraseña.
- **Webhooks**: firma HMAC-SHA256 sobre el cuerpo crudo, cabecera de
  idempotencia, un reintento solo ante 5xx/red, veto SSRF a metadatos de nube.
- **Datos**: una SQLite por caso (respaldo `VACUUM INTO` con manifiesto);
  secretos nunca en el repo (anti-secretos en el empaquetado, CI sin
  credenciales).

## Roadmap

Hecho: M1 núcleo ✔ · M2 OSINT/recon + router con caching ✔ · M3 AD completo
con rutas BloodHound ✔ · M4 integración C2 vía contrato MCP ✔ · M5 phishing +
informe en español ✔ · SSO + multi-tenant + despliegue Docker/K8s ✔.

Siguiente:

- **Modo continuo CTEM**: programar cadenas y calcular el delta de cobertura,
  detecciones y superficie entre corridas (bucle de exposición continua).
- **Ingestión Azure/híbrida** en el motor de rutas (AzureHound).
- **Validación Sigma en vivo** contra los logs reales del laboratorio
  (cierre completo del bucle purple).
- **Instancia MISP de laboratorio** lista en `docker-compose.lab.yml`.

## Documentación

- **[docs/COMO_FUNCIONA.md](docs/COMO_FUNCIONA.md)** — explicación en lenguaje llano: qué es, para quién, cómo se usa.
- **[docs/ARQUITECTURA.md](docs/ARQUITECTURA.md)** — decisiones de diseño del núcleo.
- **[docs/DEMOSTRACION.md](docs/DEMOSTRACION.md)** — galería completa de capturas reales.
- **[deploy/README.md](deploy/README.md)** — Kubernetes en detalle.

## Licencia

Software propietario de código cerrado. Véase [LICENSE](LICENSE). La
distribución, el uso en producción y la conexión de módulos ofensivos
licenciados están sujetos al contrato comercial del proveedor.
