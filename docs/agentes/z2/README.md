# Agente z2 — carpeta de sesiones

**Agente:** z2 (pulimiento de funciones y mecánicas)
**Misión:** revisión continua del proyecto, investigación de mejoras
verificables (fail-open, carreras, contratos incumplidos, superficie de
ataque, honestidad de los datos que ve el operador) y su implementación con
tests. Cada ronda queda documentada en esta carpeta como un fichero
independiente, de modo que cualquier otro agente (o humano) pueda
reconstruir lo investigado, lo decidido y lo implementado.

**Desde:** ronda 1 (2026-09-12) · **Carpeta compartida:** `docs/agentes/`
(z1, z3 y el resto del sistema mantienen sus propias bitácoras junto a esta;
nunca se borra ni se edita el .md de otro agente).

**Principios de trabajo:**

1. Línea base de tests VERDE antes de tocar nada.
2. Cada hallazgo se verifica leyendo el código antes de decidir corrección.
3. El fix lleva comentario que explica el POR QUÉ y un test que fija el
   contrato (mismo estilo que el resto del proyecto).
4. Lo investigado y NO implementado se documenta con su razón técnica
   (deferido ≠ ignorado).
5. Rebase sobre `main` antes de publicar: los solapes con z1/z3 se
   reconcilian sin debilitar ningún fix ajeno.

## Índice de sesiones

| Sesión | Fichero | Rondas | Tema |
|---|---|---|---|
| 01 | [sesion-01-rondas-1-2.md](sesion-01-rondas-1-2.md) | 1 y 2 | Pulimiento del núcleo: boundary ROE (ventana fail-closed, medianoche, techo de ruido), cadena de custodia (TOCTOU, orden legado), dedup de hallazgos, webhooks (reintento muerto, SSRF en 4 capas, redirects), planificador CTEM, autenticación/SSO en capas y panel de ruido. Reconciliación z2↔z3 sobre v25. |
| 02 | [sesion-02-ronda-3.md](sesion-02-ronda-3.md) | 3 | Visibilidad e idempotencia: cabecera `X-Orquesta-Intento` en webhooks, métrica de bloqueos del limitador en `/api/salud` (solo autenticada), barra de ruido a escala del corte duro con marca del pactado, documentación de variables de endurecimiento en `deploy/README.md`. |
| 03 | [sesion-03-ronda-4.md](sesion-03-ronda-4.md) | 4 | Canal heredado WEBHOOK_URL visible en la consola con sus entregas, techo de ruido REAL del ROE en la cola de aprobaciones + insignia de techo superado, y contrato de cabeceras webhook a prueba de deriva. |

## Convenciones

- Cada sesión es autocontenida: contexto de partida, investigación,
  decisiones con fundamento, implementación, validación y propuestas para
  la siguiente.
- Lo deferido se declara explícitamente con su razón técnica.
- El registro resumido de cada ronda vive además en el `worklog.md` raíz
  del repo (entrada por Task ID), y el detalle operativo queda aquí.
- `z2.md` (junto a este README, en `docs/agentes/`) es SOLO la punta de
  rastro que redirige aquí: se conserva para los enlaces de otros agentes.
