# Sesión 2 — 2026-09-12 · Profundización: TLS por defecto seguro, SSO endurecido, reducción de información (sobre el fix 10 de la sesión 1)

### Alcance revisado

Continuación sobre la sesión 1. Superficie revisada a fondo en esta ronda:
`platform/integraciones/` (metasploit.py, bloodhound.py, mythic.py,
misp.py, smtp_envio.py, nvd.py, rutas.py), `platform/mcp/` (recon_server,
osint_server, evidence_server, c2_adapter_server), `platform/orchestrator/`
(transportes.py completo, respaldo.py, sidecar.py, evasion.py, ad.py,
webhook.py (update parcial), persistencia.py, middleware y RUTAS_PUBLICAS de
api.py, `/api/salud`), además de los hallazgos P2 documentados en la
sesión 1 que esta sesión remedia.

Lo que se revisó y quedó BIEN (sin cambios): Cypher de rutas 100%
parametrizado (`$origen`/`$limite`, sin concatenación), SQL del webhook
(construcción de UPDATE por claves internas controladas), nmap invocado por
lista de argumentos con puertos en lista blanca, validador de dominios del
ROE a nivel Pydantic (ya rechaza objetivos que empiezan por '-'),
`/api/admin/respaldo-completo` (solo admin, auditado), servidores MCP
stdio (no expuestos en red), `_saneado()` anti inyección de prompts del
OSINT, EmailMessage de stdlib (bloquea inyección de cabeceras SMTP).

---

### Hallazgos remediados en esta sesión

#### F11 · TLS `verify=False` generalizado y silencioso — MEDIO (remedia P2 de la sesión 1)
- **Dónde:** 17 clientes HTTP: `transportes.py` (7), `recon_server.py` (2),
  `osint_server.py` (1), `metasploit.py` (2), `bloodhound.py` (3),
  `mythic.py` (1) — más STARTTLS SMTP sin contexto (F14).
- **Qué pasaba:** todas las conexiones HTTPS salientes aceptaban cualquier
  certificado sin advertencia. En las integraciones de infraestructura PROPIA
  (MSF RPC, BloodHound CE, Mythic) viajan credenciales y tokens de sesión en
  cada petición: un MITM activo las capturaba. Además el valor estaba
  hardcodeado, así que ninguna herramienta nueva podía heredar otra política.
- **Solución aplicada (dos políticas, ambas explícitas):**
  - **Integraciones con credenciales** → seguro por defecto:
    `MSF_TLS_VERIFICAR`, `BLOODHOUND_TLS_VERIFICAR`, `MYTHIC_TLS_VERIFICAR`
    (por defecto "1" = verifica; "0" = escape consciente para labs
    autofirmados, mismo patrón que el `MISP_SSL` existente).
  - **Recon/OSINT contra objetivos del alcance** → política centralizada
    `transportes.verificar_tls()` + `_cliente_http()`: por defecto admite
    autofirmados (los labs del ROE y la anomalía de certificado es en sí un
    hallazgo); `RECON_TLS_ESTRICTO=1` activa la verificación completa.
    Los servidores MCP (recon/osint) importan la MISMA política: sin
    duplicidad.
  - nvd.py, rutas.py, crt.sh y HIBP ya usaban verificación por defecto (OK).

#### F12 · Secuestro de cuentas vía SSO: vínculo automático por coincidencia de nombre — ALTO (remedia P2 de la sesión 1)
- **Dónde:** `auth.crear_o_vincular_sso()` + `sso.identificar()`.
- **Qué pasaba:** una identidad federada cuyo `preferred_username`
  coincidiera con una cuenta local se ENLAZABA automáticamente heredando su
  rol. Con un IdP que permita autorregistro (o un namespace de usernames
  cedidos/parkeds), alguien registra `admin` en el IdP, hace login SSO y
  hereda la cuenta admin local del despliegue.
- **Solución aplicada (sin romper el flujo lector/operador existente):**
  - Cuentas con rol **gestor o admin**: el vínculo exige PRE-APROBACIÓN
    explícita de un admin. Nueva tabla `sso_vinculos_preaprobados`
    (usuario, sso_sub, creado_por, creado_en; caduca a los 30 días).
    Comandos nuevos: `orquesta sso-preaprobar <usuario> <sso_sub>` y
    `orquesta sso-vinculos`. Toda pre-aprobación y vínculo queda en la
    auditoría de sistema (`sso.preaprobacion`, `sso.vinculo`, `sso.alta_jit`).
  - Política de dominios de confianza: `OIDC_DOMINIOS_PERMITIDOS=empresa.com`
    → cualquier alta JIT o vínculo exige `email` VERIFICADO
    (`email_verified=true`) de esos dominios. `sso.identificar()` ahora pasa
    los claims de email a la resolución.
  - Lector/operador sin variables nuevas: comportamiento anterior intacto
    (compatibilidad de despliegues existentes).
- **Acción recomendada al equipo:** definir `OIDC_DOMINIOS_PERMITIDOS` en
  producción y pre-aprobar con antelación los vínculos de cuentas de gestión.

#### F13 · `/api/salud` pública revela topología interna — MEDIO
- **Dónde:** `api.py`, endpoint en `RUTAS_PUBLICAS`.
- **Qué pasaba:** sin autenticación devolvía `estado_backends()` completo:
  URLs de los backends IA (frontera y local), nombres de modelos, estado de
  los circuitos, y ruta real de la raíz de casos y la BD de operadores.
  Reconocimiento perfecto para un atacante interno.
- **Solución aplicada:** llamador anónimo recibe SOLO
  `{estado, servicio, version}` (suficiente para HEALTHCHECK de Docker y el
  sidecar, que solo comprueban `r.ok`/estado). El detalle completo de
  componentes exige un Bearer token vivo (`verificar_token` + `sesion_viva`).

#### F14 · STARTTLS SMTP sin verificación de certificado — MEDIO
- **Dónde:** `smtp_envio.py` (`smtp.starttls()` sin `context`).
- **Qué pasaba:** sin contexto explícito, STARTTLS no verifica el
  certificado del servidor: un MITM activo capturaba `SMTP_CLAVE` y el
  contenido íntegro de las campañas de phishing autorizadas.
- **Solución aplicada:** `starttls(context=create_default_context())` por
  defecto; escape documentado `SMTP_TLS_SIN_VERIFICAR=1` para labs.

#### F15 · Inyección de argumentos en nmap — BAJO (defensa en profundidad)
- **Dónde:** `transportes.recon_nmap_servicios()`.
- **Qué pasaba:** `destino` se pasa como último argumento de nmap; si
  empezara por '-' nmap lo interpretaría como opción (p. ej. `-iL`, `-oX`)
  en vez de objetivo. El validador de ROEPolitica ya bloquea dominios con
  '-' (defensa primaria, verificada en test); el transporte no era barrera
  por sí mismo ante un ROE manipulado o llamada directa.
- **Solución aplicada:** guardia explícito en el transporte: objetivo que
  empiece por '-' → error, sin invocar el binario.

#### F16 · `platform/.env.example` referenciado pero inexistente — BAJO (operacional)
- **Dónde:** `README.md` y `docker-compose.yml` indican
  `cp platform/.env.example platform/.env`, pero el fichero nunca viajó en
  el repo (`.gitignore` excluye `.env*`).
- **Solución aplicada:** creado `platform/.env.example` SIN secretos con el
  catálogo completo de variables (incluye las nuevas de esta sesión) y
  excepción `!platform/.env.example` en `.gitignore`.

---

### Verificación

- Nuevos tests de regresión `platform/tests/test_z3_sesion2.py` (17 casos):
  SSO (bloqueo sin pre-aprobación, consumo de pre-aprobación, JIT con
  dominio de confianza, email sin verificar bloqueado, listar/retirar),
  salud anónima sin topología vs. autenticada con detalle, política TLS
  recon por defecto/estricta, MSF/BloodHound/Mythic verifican por defecto y
  respetan su escape, guardia nmap con objetivo malicioso y con objetivo
  legítimo → **17/17 en verde**.
- Suite completa: `pytest tests/` → **302 passed, 8 skipped** y los 10 fallos
  idénticos al entorno base (módulos opcionales `yara`/`ldap3` no instalados
  en la máquina de auditoría; mismos que la sesión 1 confirmó sobre el
  commit base). Cero regresiones.
- Los tests interceptan el constructor de `httpx.Client` para afirmar el
  valor REAL de `verify` con el que se abriría cada conexión: no hay red
  saliente en las pruebas.

### Variables nuevas introducidas (documentadas en `platform/.env.example`)

| Variable | Defecto | Efecto |
|---|---|---|
| `MSF_TLS_VERIFICAR` | `1` | verifica TLS del RPC (0 = escape labs) |
| `BLOODHOUND_TLS_VERIFICAR` | `1` | ídem BloodHound CE |
| `MYTHIC_TLS_VERIFICAR` | `1` | ídem Mythic |
| `RECON_TLS_ESTRICTO` | vacío | `1` = sondeos recon/OSINT verifican certificados |
| `SMTP_TLS_SIN_VERIFICAR` | vacío | `1` = no verifica STARTTLS (labs) |
| `OIDC_DOMINIOS_PERMITIDOS` | vacío | dominios de email federado verificado admitidos |

### Ficheros tocados en esta sesión

| Fichero | Cambio |
|---|---|
| `platform/orchestrator/transportes.py` | `verificar_tls()` + `_cliente_http()` (7 clientes), guardia nmap |
| `platform/mcp/recon_server.py` | política TLS centralizada (2 clientes) |
| `platform/mcp/osint_server.py` | ídem (robots_txt) |
| `platform/integraciones/metasploit.py` | `MSF_TLS_VERIFICAR`, verificar por defecto |
| `platform/integraciones/bloodhound.py` | `BLOODHOUND_TLS_VERIFICAR` (3 clientes) |
| `platform/integraciones/mythic.py` | `MYTHIC_TLS_VERIFICAR` |
| `platform/integraciones/smtp_envio.py` | STARTTLS con contexto verificado |
| `platform/orchestrator/auth.py` | tabla pre-aprobaciones SSO, política de vínculo, funciones de pre-aprobación, auditoría |
| `platform/orchestrator/sso.py` | claims de email hacia la resolución de cuenta |
| `platform/orchestrator/cli.py` | comandos `sso-preaprobar` y `sso-vinculos` |
| `platform/orchestrator/api.py` | `/api/salud` con detalle solo autenticado |
| `platform/.env.example` | NUEVO: plantilla sin secretos |
| `.gitignore` | excepción para la plantilla |
| `platform/tests/test_z3_sesion2.py` | NUEVO: 17 tests de regresión |
| `docs/agentes/z3.md` | bitácora de la sesión (hoy movida a `agente-z3/`) |
