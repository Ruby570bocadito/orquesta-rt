# Z2 — Sesión 05: Ronda 6 (métricas por receptor y pings que no ensucian el historial)

**Fecha**: 2026-09-12 · **Base**: `main` `f0967c7` (ronda 5 publicada, tras
rebase con z3 sesión 5 y z1 v27) · **Línea base de tests**: 511 passed /
8 skipped · **Estado final**: 518 passed / 8 skipped, tsc 0, eslint 0.

## Método

1. Ronda partida del `main` publicado por la propia ronda 5 (el rebase con
   la sesión 5 de z3 y la v27 de z1 entró limpio; conflicto único en
   `worklog.md` resuelto conservando TODAS las entradas — la de z1 usaba el
   Task ID 30, así que la entrada de z2 se renumeró a 31, misma disciplina
   de la ronda 4).
2. De las cinco propuestas de la sesión 04 se ejecutan las dos que no
   exigen decisiones del operador (Prometheus sigue pendiente de
   confirmación; SQLCipher deferido; rotación con doble ventana queda
   DEFERIDA con razonamiento técnico abajo), más una tercera de UX honesto
   detectada al implementar las métricas.

## Mejoras implementadas

### W. Métricas de 24 h por receptor, visibles en la tarjeta (`webhook.py`, `api.py`, `store.ts`, `webhooks.tsx`)

| # | Defecto | Corrección |
|---|---------|------------|
| W1 | **El receptor muerto era invisible hasta abrir el desplegable**: la fila del receptor no mostraba su tasa de fallo reciente; un receptor que llevaba 24 h fallando se veía tan sano como uno en silencio (ambos sin señal en la tarjeta). | Nueva helper `entregas_24h_por_receptor()` (UNA consulta agrupada sobre `webhook_entregas`, corte ISO calculado en Python — ambos lados con el mismo formato): `GET /api/admin/webhooks` decora cada receptor y el canal heredado con `entregas_24h` / `fallos_24h`. La tarjeta muestra insignia ROJA "N fallos en 24 h" si hay fallos, slate "N entregas en 24 h" si todo OK, y NADA si no hubo tráfico — el JSON cuenta CERO, no inventa actividad. |

Tests (4): conteo ok/fallos; la ventana IGNORA lo anterior a 24 h (entrega
de hace 48 h fuera, de hace 1 h dentro); API decora receptores y canal
heredado (con ceros honestos para el receptor sin tráfico); BD vacía →
dict vacío.

### X. Cuota PROPIA para los pings de prueba (`webhook.py`)

| # | Defecto | Corrección |
|---|---------|------------|
| X1 | **Martillear el botón Probar desplazaba las entregas REALES del propio receptor**: la poda por receptor de la ronda 5 igualó a los receptores ENTRE sí, pero dentro de un receptor el ping (manual, ilimitado por diseño) competía por el techo de 100 con el tráfico real — justo lo que se necesita diagnosticar cuando se usa el ping. | La poda por receptor se divide en DOS cuotas: entregas reales conservan las últimas `MAX_ENTREGAS_RECEPTOR=100` y los pings (`webhook.prueba`) la suya, `MAX_PINGS_RECEPTOR=20` — el historial útil de pings es corto (¿responde? ¿con qué HTTP?). Invariante de diseño fijado por test: `0 < MAX_PINGS_RECEPTOR < MAX_ENTREGAS_RECEPTOR`. |

Tests (3): 30 pings dejan las 10 entregas reales INTACTAS y se podan a 20
(la propiedad central); ambas cuotas aplican a la vez con tráfico lleno;
invariante entre constantes.

### Y. El historial se refresca tras un ping (`webhooks.tsx`)

| # | Defecto | Corrección |
|---|---------|------------|
| Y1 | **El ping recién hecho no aparecía en el desplegable abierto**: tras pulsar Probar con el historial desplegado, la fila nueva solo se veía plegando y volviendo a desplegar. | Si el desplegable de entregas está abierto al terminar el ping, se recarga — el resultado del ping aparece al momento (el propio bloque de entregas pinta su estado vacío si la recarga falla). |

## Investigado y DEFERIDO (con razón técnica)

- **Rotación de secreto de receptor con doble ventana** (propuesta de la
  sesión 04): aceptar el secreto anterior N segundos tras rotar suaviza el
  recorte, pero introduce DOS secretos válidos simultáneos por receptor —
  más estado por auditar (¿cuánto vive el viejo? ¿qué pasa con los
  reintentos en vuelo firmados con el nuevo?), todo para cubrir una
  ventanilla de segundos en receptores INTERNOS cuyo operador controla la
  rotación. El corte inmediato está documentado y la re-rotación es
  trivial. RELACIÓN coste/beneficio desfavorable: deferido sin fecha.
- **Export Prometheus**: sigue pendiente de confirmación del operador
  (abre contrato público nuevo; exige contadores acumulados, no ventana
  24 h — ahora la vista usa ventanas y Prometheus quiere acumulativos).
- **SQLCipher opt-in**: deferido a la ventanilla de despliegue (sesión 01 K).

## Validación de la ronda

- `pytest tests/`: **518 passed, 8 skipped** (línea base 511/8) — 7 tests
  nuevos en `test_v30_z2.py`; el contrato del canal heredado en
  `test_v28_z2.py` (ronda 4) se actualizó para aceptar la extensión de
  métricas (las claves nuevas con ceros honestos).
- `tsc --noEmit`: 0 errores · `eslint` (webhooks.tsx, store.ts): 0.
- Suite completa re-ejecutada tras todos los cambios: verde.

## Propuestas para la siguiente ronda (investigadas, no implementadas)

- **Export Prometheus** (`/api/metricas`, formato OpenMetrics): pendiente
  de confirmación del operador (ronda 3; tercera ronda que lo mantiene
  deferido — decidir o retirarlo del roadmap).
- **SQLCipher opt-in**: deferido a la ventanilla de despliegue.
- **Salud del receptor en la vista, no solo métricas**: con
  `entregas_24h`/`fallos_24h` ya en el JSON, la siguiente pieza natural es
  un estado derivado ("sano" / "con fallos" / "sin tráfico > 7 días") que
  combine actividad y fallos; requiere decidir umbrales con criterio
  operacional (qué es "muerto" para un receptor que solo recibe
  `roe.parada_emergencia`, que puede no dispararse en meses).
- **Reenvío manual de una entrega fallida**: desde el historial, un botón
  "reintentar" que re-dispache el evento original (hoy el único camino es
  el ping, que no reproduce el payload original); exige almacenar la carga
  o el evento en `webhook_entregas` (esquema nuevo — valorar retención).
- **`ETIQUETA_EVENTO` compartida**: la etiqueta del catálogo vive solo en
  `webhooks.tsx`; si otra vista (p. ej. cronología o datos) necesita
  traducir eventos, extraer a `lib/tipos.ts` — hoy no hay segundo
  consumidor: YAGNI, solo vigilarlo.
