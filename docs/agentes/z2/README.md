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
| 04 | [sesion-04-ronda-5.md](sesion-04-ronda-5.md) | 5 | Poda de entregas webhook POR RECEPTOR (ventana de diagnóstico equitativa), etiqueta `ctem.corrida` + contrato catálogo↔frontend bidireccional a prueba de deriva, pings de prueba distinguibles en el historial y resumen de canales honesto cuando coexisten. |
| 05 | [sesion-05-ronda-6.md](sesion-05-ronda-6.md) | 6 | Métricas de 24 h por receptor visibles en la tarjeta (el receptor muerto se ve sin abrir el desplegable), cuota PROPIA para los pings de prueba (no desplazan entregas reales) y refresco del historial tras un ping. Rotación con doble ventana: investigada y deferida con razón técnica. |
| 06 | [sesion-06-ronda-7.md](sesion-06-ronda-7.md) | 7 | Búsqueda: el fragmento ya localiza la coincidencia que BM25 puntuó (misma tolerancia a tildes que el índice, gemelo normalizado 1:1) — antes una consulta acentuada mostraba la cabecera del documento en vez del pasaje relevante. |
| 07 | [sesion-07-ronda-8.md](sesion-07-ronda-8.md) | 8 | Búsqueda: el término buscado se REALZA sobre el fragmento — el backend entrega las posiciones exactas (`coincidencias`, mismo gemelo 1:1 de la ronda 7) y la vista Memoria pinta `<mark>`; contrato backend↔frontend a prueba de deriva, suspensivo incluido. |

## Convenciones

- Cada sesión es autocontenida: contexto de partida, investigación,
  decisiones con fundamento, implementación, validación y propuestas para
  la siguiente.
- Lo deferido se declara explícitamente con su razón técnica.
- El registro resumido de cada ronda vive además en el `worklog.md` raíz
  del repo (entrada por Task ID), y el detalle operativo queda aquí.
- `z2.md` (junto a este README, en `docs/agentes/`) es SOLO la punta de
  rastro que redirige aquí: se conserva para los enlaces de otros agentes.
