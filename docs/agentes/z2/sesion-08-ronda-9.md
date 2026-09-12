# Z2 — Sesión 08: Ronda 9 (reenvío manual de entregas webhook fallidas)

**Fecha**: 2026-09-12 · **Base**: `main` `f3ef61e` (ronda 8 publicada tras
rebase con z3-sesión-6) · **Línea base de tests**: 535 passed / 9 skipped ·
**Estado final**: 548 passed / 9 skipped (+13) · **tsc**: 0 · **eslint**: 0.

## Método

1. Pieza elegida: la propuesta más veterana de la cola (sesión 05, tres
   rondas en espera): el **reenvío manual de entregas webhook fallidas**.
   Hasta hoy, una entrega perdida (receptor caído, 5xx persistente, red
   rota) solo quedaba como fila de FALLO en el historial: el evento se
   perdía PARA SIEMPRE para ese receptor y el SIEM del operador quedaba
   con un agujero que ningún reintento futuro cubría.
2. Investigación del bloqueo histórico ("exige esquema nuevo"): la carga
   de cada evento NO se persistía — `webhook_entregas` solo guardaba
   metadatos (evento, engagement, ok, http, error, intentos). Sin carga no
   hay reenvío fiel; re-derivarla del estado ACTUAL del caso habría sido
   deshonesto (el reenvío llevaría datos distintos al evento original).

## Decisión de diseño (la importante de esta ronda)

| Opción | Evaluación |
|--------|------------|
| **Carga en la propia fila de entrega** (elegida) | Columna `carga TEXT` + `reenvio_de INTEGER` en `webhook_entregas` con migración idempotente (patrón `PRAGMA table_info` de auth.py/memory.py). La retención YA está acotada (podas por receptor ronda 5/6 + poda global): la carga no alarga ninguna ventana ni crea una tabla nueva que mantener sincronizada. |
| Tabla aparte de cargas con retención propia | Dos fuentes de verdad para una entrega (fila + carga) que podan a ritmos distintos → orfandad de cargas; más superficie, cero beneficio. Descartada. |
| Reenvío re-derivando la carga actual del caso | Deshonesto: envía el estado PRESENTE bajo el nombre del evento PASADO (un `hallazgo.registrado` re-enviado con severidad ya corregida miente). Descartada. |

## Mejoras implementadas

### BB. Reenvío manual end-to-end (webhook.py + api.py + webhooks.tsx + store.ts)

| # | Carencia | Corrección |
|---|----------|------------|
| BB1 | **La carga no se persistía**: imposible reconstruir una entrega fallida con fidelidad. | `_registrar_entrega` guarda la carga JSON de cada entrega (real y ping) en la fila; `_entregar` la traspasa. La migración gana las columnas sin perder datos (test con BD legado). |
| BB2 | **Sin vía de reenvío**: el operador no podía recuperar un evento perdido. | `reenviar_entrega(webhook_id, entrega_id)`: nueva entrega REAL (uuid, ts y firma nuevos) con la MISMA carga y la configuración ACTUAL del receptor — rotar URL/secreto tras arreglar el receptor es justo el caso de uso. Recorre el MISMO camino (veto SSRF por resolución incluido). Ruta `POST /api/admin/webhooks/{id}/entregas/{entrega_id}/reenviar` (mismo guard `_admin_webhooks`). |
| BB3 | **El historial ni identificaba sus filas**: `entregas_de` no exponía `id` — ni siquiera se podía APUNTAR a una entrega. | El historial expone `id`, `reenvio_de` (id de la ORIGINAL cuando la fila es reenvío) y `reenviable` (fallo real con carga). La CARGA no viaja por la API: puede contener datos del caso; el historial necesita el resultado HTTP, no repetir el payload. |
| BB4 | **UI ciega ante los reenvíos**. | Botón "Reenviar" en las filas fallidas reenviables (receptores de BD y canal heredado "entorno"); chip "reenvío de #N" en tono teal para las filas reenviadas (misma gramática visual que el chip de ping de la ronda 5); error del backend (400/404) pintado junto a la fila, nunca en silencio; el historial se refresca tras el reenvío (patrón del ping, ronda 6). |

### Honestidad del reenvío (reglas de negocio, cada una con test)

- **Solo fallos reales**: reenviar una entrega RECIBIDA duplicaría el
  evento en el receptor y su SIEM → 400 "ya llegó".
- **Los pings no se reenvían** (se relanzan con Probar; su cuota propia
  de ronda 6 no se sortea) → 400.
- **Fila anterior a la ronda (sin carga)**: declarada NO reenviable en vez
  de inventarse contenido → 400 "sin carga registrada".
- **El receptor debe existir, estar activo y seguir suscrito al evento** →
  404 / 400 con la razón legible.
- **Forma de estrella, no cadena**: re-reenviar un reenvío fallido crea
  una fila cuyo `reenvio_de` apunta a la ORIGINAL (una raíz, N reenvíos —
  el historial se lee sin perseguir una cadena).
- **El reenvío ES una entrega real**: entra en las mismas podas (ronda 5/6)
  y en las métricas de 24 h (ronda 6) — test que lo fija.

## Investigado y descartado o deferido (con razón técnica)

- **Cabecera nueva `X-Orquesta-Reenvio` en el wire**: el receptor ya
  recibe una entrega normal (uuid nuevo); marcar el reenvío en el PROTOCOLO
  extendía el contrato de cabeceras (ronda 4) sin necesidad operacional —
  la trazabilidad vive en el historial (`reenvio_de`). Deferido: añadirlo
  solo si un integrador lo pide.
- **Reenvío en lote (todos los fallos de un receptor de golpe)**: útil
  pero multiplica el riesgo de martilleo; el botón por fila ya cubre el
  caso real (el receptor se arregla y se recuperan los fallos visibles).
  Deferido sin fecha.
- **Export Prometheus** — quinta ronda deferido esperando decisión del
  operador (o se aprueba, o se retira del roadmap).
- **Salud derivada por receptor** (umbrales por tipo de receptor) —
  abierta desde la sesión 05.
- **Realce en títulos de búsqueda** — barato sobre la ronda 8, beneficio
  marginal.

## Validación de la ronda

- `pytest tests/`: **548 passed, 9 skipped** (línea base 535/9) — 13 tests
  nuevos en `test_v33_z2.py`, 0 fallos. tsc 0 · eslint 0.
- Los tests cubren: migración legado sin pérdida de datos, reenvío feliz
  (misma carga, cabeceras contractuales intactas, original intacta),
  estrella de re-reenvíos, las 5 negaciones honestas (recibida, ping,
  legado, desactivado, desuscrito), 404s, exposición `id`/`reenvio_de`/
  `reenviable`/carga-oculta en el historial, métricas 24 h y E2E de API
  (200/400/404).
- Hallazgo colateral corregido durante la implementación: el primer SELECT
  de `entregas_de` olvidaba la columna `id` — cazado por los tests (13
  fallos) antes de salir del entorno.

## Propuestas para la siguiente ronda (investigadas, no implementadas)

- **Export Prometheus**: pedir decisión explícita (quinta ronda deferido).
- **Salud derivada por receptor**: umbrales por tipo (sesión 05).
- **Reenvío en lote**: reconsiderar si aparece un despliegue con muchos
  receptores y fallos en ráfaga.
- **Búsqueda: realce en títulos** (marginal) y `limite` en la UI (YAGNI).
