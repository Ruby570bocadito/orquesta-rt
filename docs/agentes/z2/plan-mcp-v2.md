# Plan de migración al SDK MCP v2 (tarea propia de z2)

**Agente:** z2 · **Fecha:** 2026-09-12 · **Estado:** PLANIFICADA, no
ejecutada. Origen: orden #4 del z-director (sesión 01 §7) tras el
incidente de CI — el SDK 2.x renombró `FastMCP` y una instalación limpia
rompía los 4 servidores y 11 tests; el tope `mcp>=1.1.2,<2` puesto por el
director contiene el daño mientras la migración no llegue.

## 1. Alcance real de la rotura (verificado leyendo el código)

El SDK se toca en UN SOLO patrón, repetido en 4 ficheros + el runtime:

| Fichero | Uso del SDK |
|---|---|
| `servidores_mcp/osint_server.py` | `from mcp.server.fastmcp import FastMCP` → `FastMCP("osint", instructions=...)` → `@mcp.tool()` ×N → `mcp.run(transport=...)` |
| `servidores_mcp/recon_server.py` | ídem (transportes `stdio`/`sse`/`streamable-http`) |
| `servidores_mcp/evidence_server.py` | ídem |
| `servidores_mcp/c2_adapter_server.py` | ídem |
| `servidores_mcp/comun.py` | NO importa el SDK: utilidades compartidas (TLS, saneado, dominios) — intacto por la migración |

El resto del proyecto (orquestador, API, consola) NO importa `mcp`: los
servidores son procesos aparte que el orquestador invoca como
herramientas de agente. La superficie de migración es, por tanto, pequeña
y bien acotada: 4 puntos de importación + la construcción del servidor +
los decoradores de tool + `mcp.run()`.

## 2. Qué cambia en el SDK 2.x (según el incidente y su documentación)

- `FastMCP` pasa a `MCPServer` (renombre consumado que rompió la CI).
- Cambios adicionales de APIs que el director reportó ("renombra
  FastMCP y cambia otras APIs") — a inventariar EN la ronda de migración
  contra el changelog oficial del SDK 2.x, no de memoria.

## 3. Pasos propuestos (ronda dedicada, no de coladón)

1. **Entorno aislado**: venv nuevo con `mcp>=2` SIN el tope (el tope del
   repo NO se toca hasta que la migración esté completa y validada).
2. **Shim mínimo o importación dual**: cada servidor prueba primero la
   importación nueva y cae a la vieja (`try: from mcp.server import
   MCPServer as FastMCP / except ImportError: from mcp.server.fastmcp
   import FastMCP`) — permite un periodo de convivencia sin duplicar
   ficheros. Alternativa (más limpia, más coste): migrar de golpe los 4
   y borrar el tope en el mismo commit. Decidir en la ronda según el
   changelog real.
3. **Inventario de APIs**: por cada servidor, listar decoradores y
   parámetros usados (`@mcp.tool()`, `instructions=`, `transport=`) y
   verificar su equivalente en 2.x; `recon_server` es el más expuesto
   (3 transportes).
4. **Tests**: los 11 tests que la CI tenía en rojo (test_z3_sesion4.py)
   son EL criterio de aceptación — deben pasar con 2.x instalado. Los
   tests de contrato de tools (registro, saneado, dominios) no deberían
   tocar el SDK: si lo tocan, el shim del paso 2 los protege.
5. **Cierre**: quitar el tope `,<2` de `requirements.txt` CON comentario
   inverso (por qué ya no hace falta), suite completa en instalación
   limpia, badge verde, y bitácora de la ronda con el diff real de APIs.
6. **Riesgos**: que 2.x cambie la semántica de transportes (SSE→
   streamable-http ya quedó deprecated en 1.x: migrar `recon_server`
   directamente a `streamable-http` si SSE desaparece); que
   `instructions=` cambie de firma; que el arranque por
   `python -m servidores_mcp.X` cambie requisitos de entrada/salida
   stdio (los logs JSON de `_registro` van por stdout — NUNCA deben
   mezclarse con el canal stdio del protocolo: verificar en 2.x).

## 4. Por qué NO ahora

La ronda 10 entrega un feature de producto (salud derivada) con su suite
en verde. Mezclar una migración de SDK en la misma ronda rompería la
bioseguridad de rondas del proyecto: cada cambio separable, cada ronda
reversible. El tope `<2` mantiene la CI verde mientras tanto.
