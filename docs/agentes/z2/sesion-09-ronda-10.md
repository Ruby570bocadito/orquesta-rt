# Sesión 09 — Ronda 10: salud derivada por receptor en la vista Webhooks

**Agente:** z2 (pulimiento de funciones y mecánicas) · **Fecha:** 2026-09-12
**Estado del repo al empezar:** `main @ 1d8cfae` — clon FRESCO
post-purga del F32, según la orden del z-director de su sesión 02 §5; el
entorno anterior a esta sesión quedó archivado como
`orquesta-rt-prepurga-NO-PUSHEAR` y de él no se pushea nunca — un push
desde un clon pre-purga devolvería el secreto purgado a GitHub. (La
ronda se publica rebaseada sobre `9243d3e`: v28 de z1 + sesión 03 del
director — ver la nota de vuelo al final.)
Línea base de tests: **556 passed / 9 skipped** antes de tocar nada
(535 de z3 s7 + 21 de las rondas 8-9 restauradas; los 9 skipped son los
tests de langgraph/sigma profunda — opcionales no instalados aquí).

## 1. Contexto de partida: restauración tras la purga del F32

Esta sesión abre con un incidente de coordinación multi-agente resuelto
in situ. La purga del historial que publicó el z-director se hizo desde un
clon que se había quedado en la ronda 7 de z2 (`8b98e97` pre-purga): el
force-push arrastró consigo TRES commits que ya estaban publicados — la
sesión 6 de z3 (`0fc4e8b` pre-purga) y las rondas 8 y 9 de z2. Mi primer
`git pull` de la sesión detectó el forced update; el z-director lo había
documentado como "31 commits íntegros, ninguno perdido" porque su clon
nunca llegó a ver los tres commits posteriores.

Al clonar fresco para empezar la ronda, el remoto YA contenía la
restauración: z3 reaplicó su sesión 6, mis rondas 8 y 9, y añadió su
sesión 7 (F37) encima. Verificación de integridad antes de darla por
buena: exporté los árboles de mis commits originales (conservados en el
clon archivado) y los comparé con los restaurados (`diff -r` completo) —
idénticos salvo exactamente lo esperable: el trabajo intercalado del
director (tope `mcp<2`, badge 522, docs `z-director/`, worklog). Las
rondas 8 y 9 están íntegras; ninguna acción de restauración adicional.

Hallazgo colateral corregido en esta ronda: la restauración dejó en
`worklog.md` un encabezado huérfano `Task ID: 34 (z3-sesión-6)` SIN cuerpo
(la entrada real de z3 s6 vive en el Task ID 36) — un artefacto del
cherry-pick que rompía el parseo línea a línea del registro compartido.
Eliminado solo el encabezado huérfano: no se ha tocado contenido de
ningún otro agente.

## 2. Ronda 10: el candidato y por qué

De la lista de diferidos de la sesión 08 había cuatro candidatos:

- **Export Prometheus** — quinta ronda esperando decisión del operador.
  Se respeta el deferido: sin decisión explícita no se implementa.
- **Salud derivada por receptor** — abierta desde la sesión 05, la de
  mayor cola y la más sustanciosa: las métricas de 24 h (ronda 6) dicen
  ACTIVIDAD, no dicen si el canal funciona AHORA.
- **Reenvío en lote** — deferido sin fecha, condicionado a un despliegue
  con muchos receptores que no existe.
- **Realce en títulos** — marginal sobre la ronda 8.

Elegida **salud derivada por receptor**. La sesión 05 la dejó bien
planteada pero con una reserva sin resolver: "requiere decidir umbrales
con criterio operacional (qué es 'muerto' para un receptor que solo
recibe `roe.parada_emergencia`, que puede no dispararse en meses)". Esa
reserva es la razón por la que la ronda 6 entregó métricas y no estados:
un umbral de silencio mal colocado convertiría en "muerto" un receptor
suscrito solo a la parada de emergencia — que puede pasar meses sin
dispararse y estar PERFECTAMENTE sano. Esta ronda resuelve la reserva en
lugar de esquivarla (§4).

## 3. Investigación: qué datos hay y qué puede afirmarse con honestidad

- **Fuente única**: `webhook_entregas` (la misma tabla del historial y de
  las métricas 24 h) — cada entrega real, ping o reenvío deja una fila
  con `ok`, `creado_en` y `webhook_id`.
- **La poda no estropea el estado**: la poda es POR RECUENTO (100
  entregas reales + 20 pings por receptor, 500 global — ronda 5/6) y
  conserva siempre las ÚLTIMAS filas. Consecuencia clave: la última
  entrega JAMÁS se poda, así que un estado derivado de "la última fila"
  no puede inventarse por retención. El caso límite (poda activa,
  estado correcto) queda fijado por test.
- **El canal heredado "entorno"** recibe eventos reales (ronda 4) y deja
  filas en la misma tabla: misma salud, sin tratamiento especial.
- **No existía ningún concepto de "salud"** en webhook.py, api.py ni en
  la vista: el único asidero era la insignia roja de "N fallos en 24 h",
  que confunde volumen con estado actual (un receptor con 3 fallos y un
  éxito final está funcionando; uno con 1 fallo final y nada más, roto).

## 4. Decisiones con fundamento

1. **La ÚLTIMA fila manda.** El estado se deriva del resultado de la
   última entrega retenida: `"sano"` (éxito), `"con_fallos"` (fallo),
   `"sin_entregas"` (cero filas). Un fallo seguido de éxito es un canal
   recuperado — el fallo histórico queda en el historial y en
   `fallos_24h`, no se criminaliza; un éxito seguido de fallo es un canal
   caído aunque el día tuviera éxitos. Es el criterio que un operador
   aplica a mano mirando el historial; el backend lo formaliza.
2. **NO existe el estado "muerto por silencio".** Aquí se resuelve la
   reserva de la sesión 05: el silencio se publica como HECHO
   (`ultima_entrega`, timestamp ISO) y la VISTA lo presenta como
   información — insignia neutra "7+ días sin entregas" con tooltip que
   dice explícitamente que puede ser normal si el receptor solo está
   suscrito a eventos infrecuentes (p. ej. parada de emergencia). El
   juicio de "esto está muerto" lo firma un humano, no un umbral.
3. **En un receptor pausado el silencio no se señala.** Pausar es una
   decisión del operador: que no llegue tráfico es el comportamiento
   esperado, y señalarlo sería ruido. La insignia de estado sí se
   mantiene (el último hecho es un hecho).
4. **Pings y reenvíos cuentan como última entrega.** Son POSTs reales al
   receptor con la misma firma: un ping que responde demuestra el canal
   y un reenvío exitoso lo recupera — hilo directo con la ronda 9, fijado
   por test (`reenvío exitoso → "sano"`).
5. **El estado se calcula en el backend** (pytest, contrato en la API) y
   la presentación (tonos, umbrales de silencio, tooltips) en la vista.
   El JSON nunca miente pero tampoco juzga.

## 5. Implementación

**Backend — `platform/orchestrator/webhook.py`**

- Nueva `salud_receptores()`: una sola consulta con CTE y
  `ROW_NUMBER() OVER (PARTITION BY webhook_id ORDER BY creado_en DESC,
  id DESC)` — la ventana ordena por timestamp con desempate por `id`
  (inserciones en el mismo microsegundo), y de ahí salen `ultima_ok`,
  `ultima_entrega`, `ultimo_exito` y `ultimo_fallo` por receptor en un
  solo `GROUP BY`. Devuelve `{webhook_id: {"estado", "ultima_entrega",
  "ultimo_exito", "ultimo_fallo"}}`; BD ausente o rota → `{}` (fail-open
  de lectura, igual que las métricas 24 h). Docstring con los criterios
  operacionales completos — el porqué vive junto al código.

**Backend — `platform/orchestrator/api.py`**

- `GET /api/admin/webhooks` fusiona `salud` en cada receptor y en
  `canal_heredado`. Receptor sin entregas: contrato explícito
  `{"estado": "sin_entregas", "ultima_entrega": null, "ultimo_exito":
  null, "ultimo_fallo": null}` — el JSON no inventa estados (mismo
  criterio que los ceros de la ronda 6).

**Consola — `src/lib/store.ts`**

- `SaludReceptor` tipado (`estado` unión de los tres literales + tres
  timestamps nulables) y campo `salud?: SaludReceptor` en
  `ReceptorWebhook` y en `canalHeredado`.

**Consola — `src/components/consola/webhooks.tsx`**

- Nueva `InsigniaSalud`: "último POST ok" (esmeralda), "último POST
  falló" (rojo) o "sin entregas todavía" (slate), cada una con tooltip
  nativo que da las fechas ("Último fallo: … · último éxito: …"). Añade
  "7+ días sin entregas" (slate, solo receptores activos con última
  entrega > 7 días) con la reserva de eventos infrecuentes en el
  tooltip. Colocada tras activo/pausado y antes de las métricas 24 h:
  primero estado, después volumen.
- Componente compartido por receptores de BD y canal heredado.

**Consola — `src/components/consola/ui.tsx`**

- `Insignia` acepta `title?: string` opcional (retrocompatible, sin
  cambios en consumidores existentes): la salud explica sus fechas al
  pasar el ratón sin ocupar espacio en la tarjeta.

**Tests — `platform/tests/test_v34_z2.py`** (13)

1. Estados: sano tras éxito; con_fallos tras fallo final (el éxito
   previo no disimula); recuperado tras fallo→éxito (el fallo histórico
   queda como `ultimo_fallo`); solo fallos → `ultimo_exito` null;
   receptor virgen NO aparece en el mapa (el backend no inventa).
2. Pings y reenvíos: ping exitoso → sano (y la fila es
   `webhook.prueba`); reenvío exitoso tras fallo → sano (hilo ronda 9).
3. Poda: 25 pings sobre cuota de 20 → historial podado y estado
   CORRECTO (la última fila siempre está).
4. Canal heredado: "entorno" sano tras éxito y con_fallos tras fallo.
5. Robustez: BD inexistente/rota → `{}`.
6. E2E API: la lista expone salud derivada por receptor (con fallos
   finales y `ultimo_exito` intacto) y `sin_entregas` con nulls para el
   virgen; canal heredado activo expone su salud; sin canal heredado la
   respuesta no inventa el campo (`{"activo": false, "url": ""}`).

## 6. Validación de la ronda

- Instalación limpia verificada (orden del director, §7): clon FRESCO,
  `pip install` del entorno ya existente + `npm install` nuevo, suite
  completa verde y tsc/eslint sobre lo tocado en 0 — checklist de ronda
  añadida y ejecutada.
- `pytest tests/`: **570 passed, 8 skipped** (medido tras el rebase y
  con pyflakes instalado — guarda F34-F36 ahora activa en CI; sin
  pyflakes la misma suite da 569/9) — 13 tests nuevos en
  `test_v34_z2.py`, 0 fallos.
- `tsc --noEmit`: 0 errores · `eslint` sobre los tres ficheros tocados:
  0 errores.
- Badge de tests del README raíz actualizado a la cifra de ESTE push
  (orden del director: el badge quedaba congelado mientras la suite
  crece): el director lo dejó en 557 con su sesión 03 y esta ronda lo
  lleva a **570** (557 + 13 tests de la ronda, medido).
- Nota de entorno honesta: un `npm install` sin lockfile trae
  `eslint-plugin-react-hooks` 7.1.1 (el lockfile de bun fija 7.0.1) y la
  regla nueva `react-hooks/set-state-in-effect` marca 3 patrones
  PREEXISTENTES en `acceso.tsx`, `dialogo-fase.tsx` y `higiene.tsx`
  (ninguno mío). La CI instala con `bun install --frozen-lockfile`
  (7.0.1): sigue en 0. No lo toco — es código de z1 y el arreglo
  correcto es reestructurar esos effects, no silenciar la regla; queda
  como observación para z1 (§8).

## 7. Órdenes del director (sesión 01, orden #4) — ejecutadas aquí

La orden #4 manda a z2 tres cosas para esta ronda. Estado:

1. **Checklist de ronda "instalación limpia + badge de Actions verde tras
   el push"** — AÑADIDA a la checklist de la ronda y ejecutada: suite
   completa en el clon fresco antes de pushear (570/8 con pyflakes; la
   primera medición, sin pyflakes, dio 569/9) y verificación del
   badge CI en GitHub después del push (la CI corre pytest completo desde
   instalación limpia en cada push — es la guarda que habría destapado el
   incidente mcp y el desfase del badge).
2. **Revisión de topes en dependencias críticas** — hecha, con criterio
   documentado y SIN cambiar pins a la ligera:

   | Dependencia | Resuelta hoy | Riesgo tipo mcp | Decisión |
   |---|---|---|---|
   | mcp | 1.27.0 | REAL y consumado | Tope `<2` ya puesto por el director: correcto, no se toca |
   | fastapi | 0.128.0 | Bajo (0.x, pero la API usada es estable y la suite la cubre de punta a punta) | Sin tope: la CI limpia detecta la rotura el mismo día |
   | pydantic | 2.12.5 | Bajo (v2 estable; el salto a v3 será anunciado) | Sin tope + vigilancia CI |
   | langgraph / langchain-core | no instaladas aquí (opcionales, 9 skips) | MEDIO: son las de ciclo más rápido y aquí no hay suite que las cubra sin instalarlas | Sin tope, PERO la checklist de instalación limpia debe ejecutarse en un entorno CON opcionales para que la CI real cubra sus tests (los skipped de hoy no prueban langgraph) |
   | httpx / uvicorn / typer / rich | actuales | Bajo (API estable usada mínimamente) | Sin tope + vigilancia CI |
   | impacket / yara-python / ldap3 / msgpack | actuales | Bajo (librerías de protocolo, API lenta) | Sin tope |

   Criterio: un tope `<next-major` en TODO es otra forma de pudrirse —
   congela updates y esconde roturas hasta que el tope salta. La defensa
   real es la CI en instalación limpia (que ya corre) más la checklist de
   ronda. El caso mcp fue especial: dependencia ACTIVA con renombre de
   API anunciado y consumado — ahí el tope es correcto y se mantiene.
3. **Migración al SDK MCP v2 planificada como tarea propia** — PLAN en
   `docs/agentes/z2/plan-mcp-v2.md` (nueva): alcance real de la rotura
   (4 servidores + `comun.py`, todos con el punto único de importación
   `from mcp.server.fastmcp import FastMCP`), pasos propuestos, y la
   decisión de CUÁNDO (no ahora: la migración merece su propia ronda con
   el SDK 2.x instalado en un venv aparte; hacerla de coladón en esta
   ronda habría mezclado un feature de producto con una migración de
   SDK).

## 8. Propuestas para la siguiente ronda (investigadas, no implementadas)

- **Para z1 (observación, no mío)**: la regla nueva
  `react-hooks/set-state-in-effect` del plugin 7.1.x marca 3 effects
  existentes (acceso 48, dialogo-fase 47, higiene 96). Con el lockfile
  de bun la CI no lo ve; con una instalación fresca por npm sí. El
  arreglo es reestructurar (reset por `key` o mover el setState al
  callback async), no degradar el plugin.
- **Export Prometheus** — sexta ronda deferido: pedir decisión explícita
  al operador (aprobar o retirar del roadmap).
- **Refresh manual del desplegable de entregas** — barato, heredado de
  la ronda 9 (el ping y el reenvío ya refrescan; las entregas que llegan
  de fuera mientras el desplegable está abierto, no).
- **Salud en otras vistas**: el canal de webhook vive en Integraciones;
  si Cronología o Datos quieren mostrar "canales sanos", ya existe el
  contrato (`salud` en la lista de receptores) — YAGNI hasta que haya
  segundo consumidor.

## Validación cruzada del incidente de apertura (resumen)

- Remoto post-restauración verificado: rondas 8-9 íntegras (árboles
  comparados), z3 s6/s7 presentes, 0 BDs en el historial del clon fresco
  (`git rev-list --objects --all` sin `.db`).
- Protocolo del director respetado: trabajo SOLO desde clon fresco
  post-purga; el clon pre-purga quedó archivado con nombre explícito
  `orquesta-rt-prepurga-NO-PUSHEAR`.
- PUBLICACIÓN (nota de vuelo): mientras esta ronda estaba en curso, el
  remoto avanzó con v28 de z1 (dashboard) y la sesión 03 del director
  (revisión post-purga, saneado del worklog y guarda pyflakes en
  requirements). La ronda se publica REBASEADA sobre ese HEAD. Tres
  consecuencias de coordinación, resueltas:
  (a) el encabezado huérfano del worklog que saneé en paralelo ya lo
  había saneado el director — prevalece el suyo (publicado antes); (b)
  la colisión de Task ID (su sesión 03 y mi ronda tomaban el 40) se
  resuelve renumerando mi entrada a 41, su regla de numerar desde el
  máximo existente; (c) con la guarda pyflakes ahora en requirements,
  la medición de suite cambia de 9 a 8 skipped — números de esta ronda
  RE-MEDIDOS tras el rebase: línea base 557/8 (sin pyflakes local: 556/9)
  y final **570 passed / 8 skipped**. Badge actualizado 557 → 570.
