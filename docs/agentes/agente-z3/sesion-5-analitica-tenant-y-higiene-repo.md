# Sesión 5 — Analítica cross-tenant, material sensible en git y cabeceras SMTP

> **Agente z3 · 2026-09-12 · rama `main`**
> Código base auditado: `main` @ 296c417 (sesión 4) + rondas z1/z2 intercaladas.
> Metodología idéntica a las sesiones previas: reconocimiento de superficie,
> barrido por patrones, lectura profunda módulo a módulo, fix mínimo con
> test de regresión y verificación contra la línea base.

## Alcance revisado en esta sesión

- `platform/orchestrator/api.py` (completo, 3.101 líneas): middleware de auth,
  RBAC, aislamiento tenant, endpoints admin, webhooks, SSO, SSE, analítica.
- `platform/orchestrator/`: `auth.py`, `sso.py`, `copiloto.py`, `skills.py`,
  `busqueda.py`, `memory.py` (constructor/custodia), `transportes.py`
  (recon/OSINT/exploit/phishing), `webhook.py`, `reporting.py`,
  `cobertura_attack.py`, `rutas` vía `integraciones/rutas.py`.
- `platform/integraciones/`: `smtp_envio.py`, `ldap.py`, `rutas.py`.
- Infra: `docker-compose.yml`, `Caddyfile`, `next.config.ts`,
  `instrumentation.ts`, `install.sh`, `.gitignore`, contenido trackeado del repo.
- Patrones descartados ya documentados en sesiones 1-4 (no re-abiertos):
  `sliver.py` shell bajo ROE, `CERT_NONE` de inspección de certificados,
  Cypher de `rutas.py` (100% parametrizado), escape HTML del informe
  (`reporting.py` usa `html.escape` sistemáticamente).

## Hallazgos y remediación

### F31 — Fuga cross-tenant en la analítica ATT&CK (MEDIO)

**Dónde:** `api.py` (`/api/analitica/cobertura-attack` y `.csv`) +
`cobertura_attack.py::construir_cobertura`.

**Problema:** la analítica de programa vive FUERA del árbol
`/api/engagements/{id}`, así que el middleware multi-tenant (que solo filtra
rutas con engagement) no podía protegerla: `construir_cobertura()` agregaba
SIEMPRE todas las BDs `caso_*.db` del despliegue y la respuesta incluía por
campaña su **nombre, cliente, fase, estado y resultados de detección**, además
de la matriz técnica × campaña. Cualquier cuenta autenticada — incluso un
`lector` JIT de otra organización — recibía la existencia y el contenido
operativo de campañas de clientes de OTROS tenants. Es la misma clase de fuga
que la sesión 1 corrigió en aprobaciones (F3): el aislamiento se aplicaba en
el árbol de casos pero no en las agregaciones globales.

**Remediación:** `_leer_caso()` ahora lee `tenant_id`; `construir_cobertura()`
acepta `tenant_filtro: str | None` y omite las BDs de otros tenants (sin
anotarlas como error — no lo son). Los dos endpoints calculan el filtro como
`None` para admin (vista de programa legítima) y `tenant_de(request)` para
todo el resto. El CSV hereda el mismo aislamiento. El JSON de un lector ya no
contiene NI el nombre ni el cliente de campañas ajenas (verificado por test).

### F32 — BDs de runtime de vuelta en el índice de git, incluida la de operadores (ALTO)

**Dónde:** raíz del repo — `usuarios.db` y 10 ficheros `casos/caso_*.db`.

**Problema:** la sesión 1 (F1) sacó las BDs del repo y escribió las reglas en
`.gitignore` (`usuarios.db`, `/casos/`, `*.db`). Pero `.gitignore` NO
des-trackea ficheros ya commiteados: rondas posteriores (tests y demos
ejecutados con las rutas por defecto en la raíz) re-añadieron `usuarios.db`
— **con el secreto de firma JWT (config.secreto_jwt) y el hash scrypt de una
cuenta admin** — y 10 BDs de caso. Cualquiera que clone el repo obtiene el
secreto JWT de ese despliegue de referencia (falsificación de tokens si el
despliegue lo conserva) y material para cracking offline de la credencial.
Regresión del hallazgo CRÍTICO original F1.

**Remediación:** `git rm --cached usuarios.db casos/*.db` (los ficheros quedan
en disco local, fuera del índice); las reglas de `.gitignore` ya vigentes
impiden re-añadirlos. Test de higiene `test_repo_sin_bds_trackeadas` impide
la recurrencia (`git ls-files` sin `.db`).

**PENDIENTE PARA EL EQUIPO (historial):** el secreto JWT y los hashes siguen
en la HISTORIA de git (commits anteriores). Mismo remedio ya señalado desde la
sesión 1: purga con `git filter-repo` + **rotación del secreto JWT** en todo
despliegue derivado (borrar `usuarios.db` y re-crearla, o rotar `secreto_jwt`
en `config` con revocación de sesiones).

### F33 — Cabeceras de correo sin validar en el envío de campañas (BAJO)

**Dónde:** `integraciones/smtp_envio.py::enviar` (vía
`transportes.phishing_enviar_campana`, fase F6 con aprobación humana).

**Problema:** `mensaje["To"] = ", ".join(destinatarios)` aceptaba cualquier
string: un destinatario con CRLF (`"a@b.com\r\nBcc: victima@x"`) o una lista
embebida no recibía validación alguna y el asunto aceptaba saltos de línea.
El `EmailMessage` de Python moderno neutraliza parte del riesgo al serializar,
pero la frontera era implícita (dependiente de versión/policy), no una
política del despliegue — y el ROE exige destinatarios acotados.

**Remediación:** `_validar_destinatarios()` exige dirección email verificable
(RFC 5322 práctico, sin CRLF/ángulos/comas); con CUALQUIER entrada inválida no
hay conexión SMTP ni envío parcial de los «buenos» (campaña autorizada: se
rechaza entera, se informa). `_asunto_seguro()` colapsa CR/LF del asunto a
espacio. La validación corre ANTES de cualquier I/O.

## Verificación

- **Tests nuevos:** `platform/tests/test_z3_sesion5.py` — 9 tests, 9/9 en
  verde: aislamiento unit y API real (admin ve todo / lector org-a no ve
  org-b en JSON ni CSV), tenant `predeterminada`, CSV filtrado, validación
  SMTP unitaria + rechazo sin tocar `smtplib`, asunto monolínea e higiene
  git. El test de higiene detectó el F32 real (`usuarios.db` trackeada) en
  su primera ejecución.
- **Suite completa:** `10 failed, 469 passed, 8 skipped` — los 10 fallos son
  EXACTAMENTE los preexistentes documentados desde la sesión 1 (módulos
  opcionales `yara`/`ldap3` ausentes en la máquina de auditoría:
  `test_v19`, `test_v20`, `test_integraciones`). Cero regresiones.
- **Cambios TS:** ninguno (no aplica `tsc`).

## Patrones revisados y descartados (transparencia)

- `rutas.py` — Cypher con parámetros (`$origen`, `$limite`), sin
  concatenación → sin inyección Cypher.
- `sso.py` — PKCE S256 + verificación RS256 stdlib + nonce + iss; sin
  canjes sin state. Sólido.
- `auth.py` — revocación de sesiones, bloqueo por fuerza bruta con poda,
  protección de último admin: revisado sin hallazgos nuevos en esta ronda.
- `instrumentation.ts` — spawn en forma de array, token del puente 0600,
  sin secretos nuevos en línea.
- `next.config.ts` — cabeceras de seguridad correctas; CSP de refuerzo
  conservada.
- `install.sh` — sin curl-pipe-a-shell, `set -euo pipefail`, rutas absolutas.
- `smtp_envio.py` STARTTLS — verificado por defecto (ya remediado sesión 2).
- `_limitadorTasa` y estados en proceso — poda y topes correctos (z2 ronda 3).

## Pendiente para el equipo (acumulado)

1. **Purga de historial + rotación del secreto JWT** (F32, esta sesión):
   `git filter-repo` y re-generar `usuarios.db` en despliegues derivados.
2. Rotar/revisar credenciales publicadas históricamente (sesión 1, sigue abierto).
3. `JWT localStorage → cookie httpOnly` (sesión 2; medio plazo).
4. Decidir `RECON_TLS_ESTRICTO=1` como default de producción (sesión 2).
