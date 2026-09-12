# Z2 — Sesión 02: Ronda 3 (visibilidad e idempotencia)

**Fecha**: 2026-09-12 · **Base**: `main` `148f161` (v26) · **Línea base de
tests**: 423 passed / 8 skipped · **Estado final**: 433 passed / 8 skipped,
tsc 0, eslint 0.

## Método

1. `git fetch` + `pull --ff-only` ANTES de tocar nada: había una ronda nueva
   de otro agente en `main` (v26: copiloto e higiene de cuenta). Suite
   completa ejecutada sobre esa base (423/8) para partir de verde.
2. Se retoman las 4 propuestas concretas que la Ronda 2 dejó investigadas
   (ver sesión 01), verificando cada supuesto en el código antes de
   implementar — mismo principio de siempre: el fix lleva el POR QUÉ y un
   test que fija el contrato.
3. La 5ª propuesta (SQLCipher opt-in) sigue deferida: es una decisión de
   despliegue (imagen nueva + ventanilla de migración), no de código —
   ver sesión 01, apartado K.

## Hallazgos y mejoras implementadas

### L. Webhooks — cabecera `X-Orquesta-Intento` (`webhook.py`)

| # | Mejora | Implementación |
|---|--------|----------------|
| L1 | **El receptor no distinguía un reintento del envío original**: `X-Orquesta-Entrega` es IGUAL en ambos intentos (mismo evento lógico — así debe ser, es la clave de idempotencia), así que un receptor con dedup por entrega tampoco puede saber si la primera entrega falló; su SIEM puede duplicar la alerta o sus métricas de entrega quedan infladas. | Cada intento lleva ahora `X-Orquesta-Intento: 1\|2`, documentado en la cabecera del módulo junto al resto del contrato. Práctica alineada con los reintentos de Svix/Stripe (intent explícito o similar). Los receptores del lab y el canal heredado la reciben también: la cabecera sale de `_entregar`, punto único. |

Tests (3): envío exitoso lleva `Intento: 1`; el reintento tras error de red
lleva `Intento: 2` con la MISMA `X-Orquesta-Entrega` (se distinguen SOLO por
intento); un 5xx también produce la secuencia `1→2` y el historial registra
`intentos=2`.

### M. Limitador de autenticación — métrica de bloqueos (`api.py`)

| # | Mejora | Implementación |
|---|--------|----------------|
| M1 | **La fuerza bruta era invisible**: el limitador devolvía 429 y olvidaba. Nadie puede saber desde la consola/monitorización si el login está bajo ataque (el proxy lo vería, pero el despliegue mínimo ni siquiera lo cruza). | `_LimitadorTasa` registra los bloqueos en un `deque` con PODA a 24 h al leer y **tope duro de memoria** (`MAX_BLOQUEOS = 10_000`, popleft): peticiones DENEGADAS tampoco pueden crecer la memoria sin límite — un atacante no controla el diccionario de claves, pero sí genera bloqueos en masa. Nueva `metrica()`: `bloqueos_24h` + `claves_activas`. |
| M2 | **¿Dónde exponerla sin abrir superficie?** z3 (sesión 2) dejó claro el principio: `/api/salud` anónima devuelve el mínimo (un booleano, sin topología). Un contador de 429 revela que el despliegue está bajo ataque — información para el defensor, no para el atacante. | La métrica entra en `componentes.limitador_auth` SOLO del detalle AUTENTICADO. Es métrica OPERACIONAL: NO participa en `ok_total` (bloqueos en masa significa que el limitador está FUNCIONANDO; los HEALTHCHECK de Docker no deben marcar el pod unhealthy por estar bajo ataque). Documentado en `deploy/README.md`. |

Tests (7): registro del 429; poda a 24 h (bloqueos de hace 25 h no cuentan);
tope duro del registro (20 intentos bloqueados → máx 5 en memoria con tope
pequeño); aislamiento por clave (el bloqueo de una IP no contamina a otra y
una clave nueva conserva presupuesto); `/api/salud` anónima NO expone
componentes y la autenticada sí trae `limitador_auth`; fuerza bruta REAL
contra la API (4 logins fallidos, límite 3) → el 4.º recibe 429, el bloqueo
aparece en la métrica y un cliente legítimo con OTRA IP (último salto de
X-Forwarded-For, diseño z3) conserva su presupuesto; y los bloqueos NO
degradan el `estado` del healthcheck.

### N. Panel — barra de ruido a escala honesta (`panel.tsx`)

| # | Mejora | Implementación |
|---|--------|----------------|
| N1 | **La barra escalaba al techo pactado (100 % = techo)**, así que el corte duro del boundary (techo × 5, `_MARGEN_TECHO_RUIDO`) quedaba FUERA de la escala dibujada: el operador veía una barra llena mientras el boundary seguía permitiendo 4 veces más ruido. La Ronda 2 ya mostraba el número del corte duro; la geometría seguía mintiendo. | La barra escala ahora al corte duro (100 % = techo × 5) y una marca vertical señala el nivel pactado (queda al 20 % de la escala — `techo/(techo·5)`). El COLOR mantiene la semántica de cercanía al pactado (`barraRuido` sigue recibiendo el porcentaje relativo al techo): verde/ámbar/rojo significan lo mismo que antes; lo que cambia es la longitud honesta de la barra. Leyenda actualizada: "barra a escala del corte duro, marca = techo pactado". |

Validación: `tsc --noEmit` 0, `eslint` 0.

### O. Documentación de endurecimiento (`deploy/README.md`)

La Ronda 2 propuso documentar las variables de endurecimiento en
`deploy/README.md` — fichero COMPARTIDO, así que se aplicó con mínimo diff:
una sección NUEVA al final, sin tocar el contenido existente de otros
agentes. Se documenta:

- **`*_TLS_VERIFICAR`** (`MSF_`, `BLOODHOUND_`, `MYTHIC_`): verificación ON
  por defecto, contrato exacto (solo `0` desactiva), y la receta correcta
  para CA corporativo (añadir el CA a la imagen, no apagar la verificación).
- **Webhooks**: veto de metadatos en 4 capas (alta y despacho, anti-
  rebinding), 3xx sin seguimiento, escape `WEBHOOK_PERMITIR_METADATOS=1`,
  canal heredado `WEBHOOK_URL`/`WEBHOOK_SECRETO` (y por qué preferir
  receptores de consola), y la cabecera nueva `X-Orquesta-Intento`.
- **SSO**: homonimia desactivada por defecto; `SSO_VINCULAR_POR_NOMBRE=1`
  solo para cuentas no privilegiadas; pre-aprobación de admin SIEMPRE para
  privilegiadas (`POST /api/auth/sso/vincular`, caducidad 30 días); los
  rechazos quedan en auditoría.
- **Métrica de fuerza bruta**: qué es `componentes.limitador_auth`, por qué
  el payload anónimo no la incluye y cómo cruzarla con los logs del proxy.

## Validación de la ronda

- `pytest tests/`: **433 passed, 8 skipped** (línea base 423/8) — 10 tests
  nuevos en `test_v27_z2.py`, 0 fallos.
- `tsc --noEmit`: 0 errores · `eslint` (panel.tsx): 0.
- Suite completa re-ejecutada tras todos los cambios: verde.

## Integración con el resto de agentes

- Rebase no hizo falta esta vez: la ronda partió del `main` actualizado
  (v26) y los ficheros tocados (`webhook.py`, `api.py`, `panel.tsx`,
  `deploy/README.md`, tests propios) no colisionan con las áreas activas
  de z1 (copiloto/consola v26) ni z3 (auditorías cerradas en sesiones 2-3).
- `deploy/README.md` es compartido: se tocó en modo append puro.
- La carpeta `docs/agentes/z2/` se crea al estilo de `z1/` (que ya hizo esta
  reorganización en v25): `z2.md` queda como punta de rastro que redirige
  aquí, sin borrar el historial de enlaces de otros agentes.

## Propuestas para la siguiente ronda (investigadas, no implementadas)

- **SQLCipher opt-in por despliegue** (deferido desde la Ronda 2): sigue
  esperando la ventanilla de despliegue (imagen con `sqlcipher3` + migración
  `.dump`). Documentado en sesión 01, apartado K.
- **Export de la métrica en formato Prometheus** (`/api/metricas` con
  `text/plain` version 0.0.4): `bloqueos_24h` ya existe; el formato exige
  contadores monotónicos acumulados (no ventanas), lo que implica cambiar el
  registro de bloqueos a contador + ventana — pequeño, pero toca contrato
  público nuevo: mejor con confirmación del operador.
- **Historial de entregas del canal heredado**: `WEBHOOK_URL` no tiene
  `webhook_id` real (`entorno`) y `entregas_de("entorno")` sí funciona de
  facto — exponerlo en la consola (vista Integraciones) para que el
  operador vea también las entregas del canal heredado.
- **Marca visual en la cola de aprobaciones cuando el ruido ya superó el
  pactado**: hoy el aviso vive en el motivo del guardrail y en el panel;
  la tarjeta de aprobación podría traer la insignia "techo superado" sin
  depender de que el operador recuerde el panel.
- **Test de contract para las cabeceras webhook documentadas**: fijar con
  un test la lista COMPLETA de cabeceras del contrato (Firma, Evento,
  Entrega, Intento, Id) para que una cabecera nueva no pueda añadirse sin
  pasar por la documentación del módulo.
