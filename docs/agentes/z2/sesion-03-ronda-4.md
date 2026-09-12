# Z2 — Sesión 03: Ronda 4 (canal heredado visible y contratos que no se cuelan)

**Fecha**: 2026-09-12 · **Base**: `main` `5950439` (ronda 3 publicada) ·
**Línea base de tests**: 433 passed / 8 skipped · **Estado final**:
440 passed / 8 skipped, tsc 0, eslint 0.

## Método

1. Ronda partida del `main` recién publicado por esta misma ronda 3
   (integrada vía rebase con z1 v26 sin pérdidas: conflicto único en
   `worklog.md`, resuelto conservando AMBAS entradas y renumerando la de
   z2 para no duplicar Task ID).
2. Tres propuestas de la sesión 02 ejecutadas — todas de contrato cerrado,
   sin decisiones de despliegue pendientes (SQLCipher sigue deferido con su
   razón técnica; Prometheus espera confirmación del operador porque abre
   un contrato público nuevo).

## Mejoras implementadas

### P. Canal heredado WEBHOOK_URL visible en la consola (`webhook.py`, `api.py`, `store.ts`, `webhooks.tsx`)

| # | Defecto | Corrección |
|---|---------|------------|
| P1 | **El canal heredado era invisible**: vive en el ENTORNO del despliegue (no en la BD) y sus entregas se registran bajo el id literal `"entorno"`, así que la vista Webhooks (que lista receptores de BD) no lo mostraba — un despliegue con `WEBHOOK_URL` activo parecía "sin notificaciones" y sus entregas daban 404 al admin. | `GET /api/admin/webhooks` devuelve ahora `canal_heredado: {activo, url}` (helper `canal_heredado_estado()`); `GET /api/admin/webhooks/entorno/entregas` devuelve las entregas del canal (404 honesto si no está configurado; 403 si no es admin — el canal no es excepción al RBAC). La consola lo muestra como tarjeta de solo-lectura con borde discontinuo, insignia "canal heredado · WEBHOOK_URL" y el mismo desplegable de entregas que los receptores de BD (`BloqueEntregas` extraído y compartido, sin duplicar el render). El estado vacío de la vista ya no miente: solo dice "sin canales" cuando de verdad no hay ninguno. |

Tests (5): canal activo/inactivo en la lista; entregas de "entorno"
consultables; 404 sin `WEBHOOK_URL`; solo admin.

### Q. Cola de aprobaciones con el ROE real (`aprobaciones.tsx`)

| # | Defecto | Corrección |
|---|---------|------------|
| Q1 | **El techo de ruido de la tarjeta estaba hardcodeado a 50**: con un ROE de techo 30 (o 80), la barra y la cifra `ruido/50` mentían en cada decisión. | La tarjeta recibe el techo REAL del ROE del caso (`engagement.roe.techo_ruido`, fallback 50 = valor por defecto del dominio). |
| Q2 | **La cola no avisaba del nivel ya cruzado**: el aviso de "techo superado" vivía en el motivo del guardrail y en el panel; el operador decidía cada aprobación sin el contexto del ruido acumulado del caso. | Con `ruidoAcumulado >= techoRuido`, cada tarjeta pendiente muestra la insignia ámbar "techo de ruido superado · acumulado X/Y" (el corte duro sigue en techo × 5: `_MARGEN_TECHO_RUIDO` — comentado en el código para que UI y backend no diverjan). |

### R. Contrato de cabeceras webhook a prueba de deriva (`webhook.py`, `test_v28_z2.py`)

| # | Defecto | Corrección |
|---|---------|------------|
| R1 | **Nada impedía añadir una cabecera al despacho sin documentarla** (o viceversa): el contrato del módulo y el código podían divergir en silencio — exactamente el tipo de deriva que un receptor industrial (n8n, Slack) sufre. | Dos tests de contrato: (1) la documentación del módulo declara las CINCO cabeceras `X-Orquesta-*`; (2) el despacho envía EXACTAMENTE ese conjunto (ni una más ni una menos). Una cabecera nueva obliga a actualizar la documentación y el test a la vez. |

## Validación de la ronda

- `pytest tests/`: **440 passed, 8 skipped** (línea base 433/8) — 7 tests
  nuevos en `test_v28_z2.py`, 0 fallos.
- `tsc --noEmit`: 0 errores · `eslint` (webhooks.tsx, aprobaciones.tsx,
  store.ts): 0.
- Suite completa re-ejecutada tras todos los cambios: verde.

## Propuestas para la siguiente ronda (investigadas, no implementadas)

- **Export Prometheus** (`/api/metricas`, formato OpenMetrics): exige
  contadores acumulados (no ventana 24 h) — confirmación del operador por
  abrir contrato público nuevo.
- **SQLCipher opt-in**: deferido a la ventanilla de despliegue (sesión 01 K).
- **`ctem.corrida` en la etiqueta de eventos de la consola**: el catálogo
  `ETIQUETA_EVENTO` de `webhooks.tsx` no lo traduce (cae al nombre crudo);
  trivial, buena para una ronda de higiene menor junto a otros sinsabores
  de etiquetas.
- **Purga de `webhook_entregas` por receptor**: la poda global
  (`MAX_ENTREGAS=500`) es del despliegue; un receptor muy activo puede
  desplazar el historial de los demás — podar por receptor (p. ej. 100 por
  id) mantiene la ventana de diagnóstico equitativa.
- **Firma de la prueba de webhook en la vista**: `probar_webhook` usa
  "prueba" como engagement_id; la UI podría distinguir visualmente los pings
  de prueba de las entregas reales en el historial (hoy se ven iguales).
