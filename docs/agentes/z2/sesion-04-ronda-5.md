# Z2 — Sesión 04: Ronda 5 (ventana equitativa de entregas y catálogo sin deriva)

**Fecha**: 2026-09-12 · **Base**: `main` `053e93a` (v27 de z1 publicado) ·
**Línea base de tests**: 492 passed / 8 skipped · **Estado final**:
502 passed / 8 skipped, tsc 0, eslint 0.

## Método

1. Ronda partida del `main` recién integrado (v27 de z1: bucle
   CTEM↔purple↔Sigma + transparencia del escudo LLM01 + 15 tests).
2. Ejecutadas las TRES propuestas heredadas de la sesión 03 que no exigían
   decisiones del operador (Prometheus sigue pendiente de confirmación por
   abrir contrato público nuevo; SQLCipher sigue deferido a la ventanilla
   de despliegue). Durante la investigación apareció un cuarto defecto
   (S4) del mismo tipo de honestidad que la ronda, y entró en el paquete.

## Mejoras implementadas

### S. Poda de entregas POR RECEPTOR — ventana de diagnóstico equitativa (`webhook.py`)

| # | Defecto | Corrección |
|---|---------|------------|
| S1 | **La poda del registro de entregas era solo global** (`MAX_ENTREGAS=500` sobre toda la tabla): un receptor muy activo (suscrito a todo, en un despliegue con mucho tráfico) desplazaba el historial de los demás — la ventana de diagnóstico de 500 líneas se la comía un solo receptor y el admin dejaba de ver por qué el receptor silencioso no recibía nada. | Nueva constante `MAX_ENTREGAS_RECEPTOR = 100`: tras cada inserción, la poda conserva las últimas 100 entregas DE ESE receptor (incluido el canal heredado `"entorno"`, que no tiene fila en la tabla `webhooks` pero sí entregas con su id). La poda global se conserva como guarda del tamaño total del despliegue. Invariante de diseño fijado por test: el techo por receptor debe ser estrictamente menor que la poda global. |

Tests (5): techo del parlanchín (se conservan las MÁS RECIENTES); el
parlanchín no desplaza al silencioso (la propiedad central de la ronda);
techo aplicado al canal heredado; poda global sigue activa como guarda
(monkeypatch de ambas constantes); invariante `RECEPTOR < GLOBAL`.

### T. Etiqueta `ctem.corrida` + contrato catálogo↔frontend a prueba de deriva (`webhooks.tsx`, `test_v29_z2.py`)

| # | Defecto | Corrección |
|---|---------|------------|
| T1 | **`ctem.corrida` llevaba desde v23 sin etiqueta en la consola**: el catálogo `ETIQUETA_EVENTO` de `webhooks.tsx` se quedó atrás cuando el motor CTEM continuo añadió el evento, así que el chip de suscripción y las filas de entregas mostraban el nombre crudo `ctem.corrida`. | Etiqueta `"ctem.corrida": "Corrida CTEM"` añadida. |
| T2 | **Nada impedía que el defecto T1 volviera a ocurrir**: un evento nuevo en `webhook.EVENTOS` sin etiqueta en el frontend deriva en silencio (exactamente la clase de deriva que la ronda 4 cerró para las cabeceras). | Dos tests de contrato BIDIRECCIONALES: (1) todo evento del backend tiene etiqueta en `webhooks.tsx` (el parser quita los comentarios de línea para que un comentario no cuele etiquetas fantasma); (2) toda etiqueta del frontend es un evento REAL del backend (una etiqueta de un evento eliminado es basura que confunde al operador). Un evento nuevo obliga a tocar backend y frontend a la vez. |

### U. Pings de prueba distinguibles en el historial (`webhooks.tsx`)

| # | Defecto | Corrección |
|---|---------|------------|
| U1 | **Un ping de prueba se veía IGUAL que una entrega operativa real** en el historial de entregas: `probar_webhook` registra bajo el evento `webhook.prueba` con engagement "prueba", pero la fila tenía el mismo estilo que cualquier entrega — al diagnosticar un receptor era imposible distinguir a simple vista los pings manuales del tráfico real. | Las filas `webhook.prueba` llevan firma visual propia: borde discontinuo, fondo tenue y chip "ping de prueba" en tono slate (en lugar de la etiqueta normal de evento). El evento sigue apareciendo traducido en el catálogo de suscripción; solo el HISTORIAL distingue, que es donde se diagnostica. |

### V. Resumen de canales honesto cuando coexisten (`webhook.py`)

| # | Defecto | Corrección |
|---|---------|------------|
| V1 | **`estado()["servidor"]` tapaba un canal al otro**: con `WEBHOOK_URL` del entorno Y receptores de BD activos, el resumen mostraba solo la URL (`url or f"{activos} receptor(es) en BD"`) — un despliegue con ambos canales parecía tener solo el heredado. | El resumen nombra AMBOS canales: `"https://n8n.legacy/hook + 2 receptor(es) en BD"` (y sigue devolviendo solo uno cuando solo hay uno — 3 tests fijan las tres combinaciones). |

## Validación de la ronda

- `pytest tests/`: **502 passed, 8 skipped** (línea base 492/8) — 10 tests
  nuevos en `test_v29_z2.py`, 0 fallos.
- `tsc --noEmit`: 0 errores · `eslint` (webhooks.tsx): 0.
- Suite completa re-ejecutada tras todos los cambios: verde.

## Propuestas para la siguiente ronda (investigadas, no implementadas)

- **Export Prometheus** (`/api/metricas`, formato OpenMetrics): exige
  contadores acumulados (no ventana 24 h) — confirmación del operador por
  abrir contrato público nuevo (pendiente desde la ronda 3).
- **SQLCipher opt-in**: deferido a la ventanilla de despliegue (sesión 01 K).
- **Rotación de secreto de receptor con doble ventana**: al rotar el
  secreto de un receptor, el viejo deja de validar AL INSTANTE y los
  reintentos en vuelo del receptor fallan la verificación de firma; una
  rotación con superposición temporal (aceptar el secreto anterior N
  segundos) suaviza el recorte, a costa de un contrato más complejo —
  investigar si el beneficio compensa en la práctica operacional.
- **Métricas por receptor en la vista Webhooks**: la fila del receptor no
  muestra su tasa de fallo reciente (hay que abrir el desplegable de
  entregas); una insignia "N fallos en 24 h" (a partir de
  `webhook_entregas`, que ya es la fuente) avisaría del receptor muerto
  sin abrir nada.
- **`webhook.prueba` exento del techo por receptor**: hoy un operador que
  martillea el botón Probar desplaza (dentro de su techo de 100) las
  entregas reales del propio receptor; cuantificar si es un problema real
  antes de añadir la excepción.
