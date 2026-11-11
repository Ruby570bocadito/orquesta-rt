# OWNERSHIP — Zonas por ruta

Lo mantiene **DIR**. Cada rol solo crea / modifica / borra en SUS rutas. Fuera de tu zona → "Peticiones" en tu estado, nunca intervención directa.

## Zonas por rol

| ID | Rol | Zona que puede modificar / borrar |
|----|-----|-----------------------------------|
| **DIR** | Director | `docs/agentes/` (ROADMAP, OWNERSHIP, PROTOCOLO, PROGRESS). Único escritor de la cola y del roadmap de producto. No escribe funcionalidades. |
| **BACK** | Backend / orquestador | `platform/orchestrator/` **salvo la zona sagrada**: `models.py`, `graph.py`, `agents/`, `transportes.py`, `razonador.py`, `threatled.py`, `ctem.py`, `cobertura_attack.py`, `purpleteam.py`, `sigma_valid.py`, `navigator.py`, `reporting.py`, `respaldo.py`, `copiloto.py`, `api.py`, y sus tests en `platform/tests/`. |
| **FRONT** | Consola | `src/` completo (Next.js 16, TS): `app/`, `lib/store.ts`, `components/consola/`, estilos, y sus tests. Usa la skill de diseño frontend. |
| **INTEG** | Integraciones + MCP + lab | `platform/integraciones/` (bloodhound, misp, nvd), `platform/servidores_mcp/`, `platform/lab/`, `lab/`. |
| **SEG** | Seguridad + bugs | Transversal, **solo fixes mínimos con claim previo**. Audita (no reescribe) la zona sagrada. |
| **PUL** | Pulimiento | `install.sh`, `start.sh`, `stop.sh`, `docker-compose.yml`, `deploy/`, `.github/workflows/`, `pyproject.toml`/deps, `.devcontainer/`, limpieza y refactors sin cambio de comportamiento. |
| **DOC** | README vivo + media | `README.md`, `docs/COMO_FUNCIONA.md`, `docs/DEMOSTRACION.md`, `docs/ARQUITECTURA.md`, capturas y GIF. Levanta la plataforma y captura la consola real. |
| **TEST** | Tester E2E por personas | `platform/tests/`, tests en `src/`, `docs/agentes/hallazgos/`. **NUNCA** código de producto. |

## Zona sagrada — INTOCABLE sin firma humana explícita

| Ruta | Por qué |
|---|---|
| `platform/orchestrator/guardrails.py` | El boundary ROE. Vive FUERA del modelo a propósito (OWASP LLM01). |
| `platform/orchestrator/auth.py` | Identidad: scrypt + JWT, RBAC, deny-by-default. |
| `platform/orchestrator/sso.py` | OIDC / PKCE / verificación JWKS. |
| `platform/orchestrator/memory.py` → cadena de custodia | Auditoría append-only + HMAC encadenado. |
| `platform/roe/` | Plantilla de ROE máquina-legible. |

SEG lee, audita y abre hallazgos sobre estas rutas. Solo DIR, tras firma humana, promueve una tarea que las modifique, y esa tarea va SIEMPRE por PR revisado por el humano — nunca push directo. Cualquier claim sobre estas rutas que no sea de SEG (hallazgo) o DIR (tarea firmada) se anota como incidente en el estado de quien lo detecte.

Las capacidades ofensivas (`ad.py`, `persistencia.py`, `evasion.py`, `transportes.py`) se tocan solo para el laboratorio local (`127.0.0.0/8`, dominio AD de lab).

## Push directo vs PR

- **Por PR (mergea el humano):** BACK, INTEG, SEG, y cualquier tarea que toque la zona sagrada.
- **A `main` directo:** FRONT, DOC, TEST, PUL, DIR — no tocan la lógica ofensiva ni el boundary.
