# Agente z1 — carpeta de sesiones

**Agente:** z1 (Super Z)
**Misión:** revisión continua del proyecto OrquestaRT e investigación/razonamiento
sobre implementaciones de red team, IA, manejo del usuario web y herramientas
implementables. Cada sesión de trabajo queda documentada en esta carpeta como
un fichero independiente, de modo que cualquier otro agente (o humano) pueda
reconstruir el razonamiento completo de lo investigado, lo decidido y lo
implementado.

**Desde:** ronda v24 (2026-09-12) · **Carpeta compartida:** `docs/agentes/`
(z2, z3 y el resto del sistema mantienen sus propias bitácoras junto a esta).

## Índice de sesiones

| Sesión | Fichero | Ronda | Tema |
|---|---|---|---|
| 01 | [sesion-01-primeras-rondas.md](sesion-01-primeras-rondas.md) | pre-v24 y v24 | Revisión inicial, sesiones revocables (no publicada, superada por z3-F4) y escudo LLM01 (no publicada, recuperada en v25). Ronda v24: MISP de laboratorio + validación Sigma en vivo. |
| 02 | [sesion-02-v25-escudo-llm01-ui-sigma.md](sesion-02-v25-escudo-llm01-ui-sigma.md) | v25 | Re-implementación del escudo anti-inyección indirecta OWASP LLM01:2025 en el copiloto + UI de validación Sigma en la consola + entorno del lab para MISP. |
| 03 | [sesion-03-v26-eco-json-higiene-cuenta.md](sesion-03-v26-eco-json-higiene-cuenta.md) | v26 | Cierre del eco de JSON en la SALIDA del copiloto (procedencia del bloque de sugerencias + canales del contrato) + panel de higiene de cuenta en la consola (estado vivo + cerrar-todas). |
| 04 | [sesion-04-v27-bucle-ctem-sigma-transparencia.md](sesion-04-v27-bucle-ctem-sigma-transparencia.md) | v27 | Cierre del bucle CTEM↔purple↔Sigma (cobertura real = hallazgo × regla Sigma VALIDADA × detección VECTR, con transiciones y regresiones en el delta) + transparencia del escudo LLM01 en la respuesta del copiloto + aviso de caducidad próxima en la higiene. |
| 05 | [sesion-05-v28-dashboard-readme-arbol.md](sesion-05-v28-dashboard-readme-arbol.md) | v28 | Auditoría endpoint↔UI del dashboard (78 endpoints × store × 18 vistas): ROE vivo editable, auditoría del sistema en Equipo y reasignación cross-tenant; README con GIF + capturas reales v28; árbol ordenado (download/ fuera del repo). |
| 06 | [sesion-06-v34-sesiones-visibles-sso.md](sesion-06-v34-sesiones-visibles-sso.md) | v34 | Sesiones activas visibles en la higiene (registro de sesiones como espejo consultable del middleware, throttle 1/min, jti resumido) + acceso federado administrable (vincular/desvincular auditado; la brecha sso/vincular cerrada) + proxy reenviando User-Agent + test v21 hermetizado. Suite 574/0. |

## Convenciones

- Cada sesión es autocontenida: contexto de partida, investigación, decisiones
  con fundamento, implementación, validación y propuestas para la siguiente.
- Lo no publicado o superado se declara explícitamente (sin reescribir historia).
- El registro resumido de cada ronda vive además en el `worklog.md` raíz del
  repo (entrada por Task ID), y el detalle operativo queda aquí.
