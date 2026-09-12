# Sesión 04 — v27: bucle CTEM↔purple↔Sigma + transparencia del escudo + aviso de caducidad

**Agente:** z1 · **Fecha:** 2026-09-12
**Estado del repo al empezar:** `main @ 8be7405` (v26 documentada), árbol
limpio y en `main`. Durante la sesión entraron por `origin/main` la ronda 3
de z2 y la sesión 4 de z3 (F25-F30); se integraron con rebase limpio y sin
conflictos (los commits de esta ronda quedan sobre ellos).

## 1. Auditoría de partida

Instrucción del operador: continuar la ronda, seguir pusheando y hacer
todos los commits en `main`.

De las cuatro propuestas que dejé en la sesión 03, re-evalúo contra el
código real:

1. **Cierre del bucle CTEM↔purple↔Sigma** — Sigue abierta desde la sesión
   02 (dos rondas plantada) y es la pieza red team de mayor valor pendiente
   que puedo ejecutar sin el operador: verificué `ctem.py`,
   `purpleteam.py` y `sigma_valid.py` y las tres piezas del bucle EXISTEN
   y funcionan — la corrida mide detecciones VECTR, el paquete purple
   genera esqueletos Sigma con política anti-invención, y el validador da
   veredicto estructural. Lo que NO existía es el CRUCE: ninguna corrida
   sabe qué técnicas detectadas tienen HOY una regla Sigma válida detrás.
2. **Aviso de sesión ajena en la higiene** — Abierta, mía (manejo del
   usuario web), pequeña y de alto valor práctico: el JWT muere a mitad de
   engagement y hoy nadie avisa.
3. **Transparencia del escudo en el copiloto** — Abierta, mía (IA): el
   escudo filtra (v25 entrada, v26 salida) pero silenciosamente; el
   operador no distingue "no hubo intento" de "hubo intento y lo filtré".
4. **Ingestión del dominio real al motor Neo4j** — Sigue requiriendo al
   operador con credenciales del dominio: no ejecutable por un agente.
   Sigue en el roadmap del README.

Decisión: **esta ronda ejecuta 1, 2 y 3** — el bucle cierra el ciclo
ofensa→defensa→detección-as-code que da sentido al modo continuo, y las
otras dos son cierres de higiene y transparencia coherentes con mi mandato.

## 2. Investigación y razonamiento

### 2a. El bucle: ¿qué significa "cobertura" honesta?

Los productos que el modo continuo imita (Picus/SCYthe/VECTR) llaman
"coverage" al cruce ofensa↔defensa. La tentación es declarar cobertura con
la técnica del hallazgo y la regla generada — pero eso sería relleno: una
regla Sigma que NO pasa la validación estructural no detecta nada, es
deuda con disfraz de artefacto. El cruce honesto necesita TRES fuentes y
solo cuenta la intersección:

- **purple** (lo que la plataforma genera): `reglas_sigma_caso` emite
  esqueletos SOLO para técnicas con fuente de logs conocida (política
  anti-invención de v24, intacta).
- **Sigma** (lo que la plataforma verifica): `validar_lote` da veredicto
  por regla; SOLO las reglas válidas cuentan. Lo probé al revés en el test
  con el lote manipulado a inválido: la técnica marcada "detectado" NO se
  promociona a cobertura — la detección sin regla válida es otro dato, no
  este.
- **VECTR** (lo que el equipo azul documentó): el campo `deteccion` del
  hallazgo que el operador marca por API. `detectado`/`prevenido` →
  técnica cubierta; `no_detectado` → PUNTO CIEGO (la regla existe y la
  defensa falló: el dato más accionable del informe continuo).

Detalles de ingeniería que decidí:

- **Dónde vive el cruce**: en `instantanea()`, como sección
  `cobertura_sigma` de CADA corrida. No es un endpoint aparte: el valor
  del bucle es su EVOLUCIÓN, y la corrida es la unidad temporal que ya
  tiene custodia, auditoría e historial.
- **La transición en el delta**: `delta_entre` añade `cobertura_sigma` con
  `transiciones` (técnicas que PASARON a cubiertas entre corridas — el
  coverage gain), `regresiones` (pasaron a puntos ciegos) y
  `nuevas_reglas` (reglas validadas nuevas). La transición es la firma
  temporal del bucle: "entre esta corrida y la anterior, T1558.003 pasó a
  detectada CON regla válida".
- **Honestidad de la comparación**: si la corrida anterior es anterior a
  v27 (sin `cobertura_sigma` en su resumen persistido) o no hay corrida
  previa, `comparable: false` y las listas van VACÍAS — sin base no se
  fabrican transiciones, porque el cambio pudo existir antes de la primera
  medición Sigma. El estado actual ya viaja en la instantánea; el delta no
  miente ni extrapola retroactivos. Es la misma disciplina de
  `primera_corrida` de v23.
- **Ciclo de importación evitado**: `ctem.py` no puede importar
  `purpleteam` en cabecera (purpleteam importa memory, y memory migra las
  tablas de ctem). Import tardío dentro de la función, el patrón que ya
  usa el propio ctem para MemoriaCaso.
- **Coste**: validar el lote Sigma en cada corrida es O(hallazgos con
  fuente) reglas pequeñas en YAML — microsegundos frente a la consulta de
  auditoría que la instantánea ya hace. Sin caché: la validación es
  determinista y el caso es pequeño por diseño.

### 2b. Transparencia del escudo: el filtrado no puede ser un silencio

El escudo v25 marca la entrada y la procedencia v26 descarta ecos de
salida. En ambos casos la respuesta final NO dice nada: un operador que ve
"sugerencias: []" no puede distinguir "el modelo no sugirió nada" de "el
escudo filtró un intento de manipulación". Para un analista, esa diferencia
es EL dato (hubo un intento = hay un documento hostil en el caso).

- **Contador de ecos**: `_elegir_bloque_sano` ahora devuelve
  `(bloque, n_ecos_descartados)`; `_partir_estructura` lo publica como
  `escudo.ecos_descartados` y `consultar()` compone el dict `escudo` con
  `marcas_entrada` (que `construir_contexto` ya contaba para la línea
  ESCUDO del prompt). La clave SIEMPRE existe (aunque sea {0,0}): la
  transparencia es por defecto, no por excepción — y la consola no distingue
  "respuesta antigua" de "sin filtrado".
- **Dónde se declara**: en la respuesta del copiloto, junto a la meta
  (modelo/tokens), como nota ámbar. No va en las secciones de análisis (es
  metadato del escudo, no razonamiento del modelo) ni en un log aparte (el
  operador no va a buscarlo: pasa lo relevante a la vista).
- **El contador para en el primer bloque sano**: es deliberado — el número
  declara "ecos descartados ANTES de elegir el bloque ganador"; contar
  ecos posteriores a un bloque sano no aporta nada (el propio del bloque
  ganador es el análisis) y complicaría el contrato sin valor.

### 2c. Aviso de caducidad: avisar ANTES, no explicar DESPUÉS

El 401 por expiración ya lo maneja el store (devuelve al acceso), pero el
operador pierde el hilo de la consola a mitad de un paso. El panel de
higiene (v26) ya enseña los segundos restantes; lo que faltaba es la
LECTURA de ese número. Umbral: 30 minutos (bastante margen para terminar
el paso en curso sin ser ruido en sesiones de 24 h). La insignia ámbar
"caduca pronto" solo aparece con sesión VÁLIDA y tiempo > 0 — una sesión
revocada ya tiene su insignia roja. El aviso acompaña una sugerencia
concreta: renueva cuando termines el paso en curso.

## 3. Implementado en esta ronda

| Fichero | Cambio |
|---|---|
| `platform/orchestrator/ctem.py` | **Bucle CTEM↔purple↔Sigma** — `cobertura_sigma_caso()`: cruce real purpleteam×sigma_valid×VECTR (solo reglas válidas cuentan; detectado/prevenido → cubiertas, no_detectado → puntos ciegos); `instantanea()` incluye `cobertura_sigma`; `_delta_sigma()` calcula transiciones/regresiones/nuevas_reglas con `comparable` honesto (sin base → listas vacías); `delta_entre()` lo añade a ambas ramas. |
| `platform/orchestrator/copiloto.py` | **Transparencia del escudo** — `_elegir_bloque_sano()` devuelve además el nº de ecos descartados; `_partir_estructura()` publica `escudo.ecos_descartados`; `construir_contexto()` expone `escudo_marcas`; `consultar()` compone `escudo: {marcas_entrada, ecos_descartados}` en la respuesta (clave siempre presente). |
| `src/lib/tipos.ts` | `CoberturaSigma`, `DeltaCoberturaSigma`; `DeltaCtem.cobertura_sigma` y `CorridaCtem.resumen.cobertura_sigma` opcionales (retrocompatible). |
| `src/lib/store.ts` | `MensajeCopiloto.escudo`; la respuesta del copiloto viaja con su dict `escudo`. |
| `src/components/consola/cadenas.tsx` | Insignias del bucle en el último delta: "bucle Sigma: T… detectada(s) con regla válida" (esmeralda), "puntos ciegos nuevos: T…" (rojo), "+N regla(s) Sigma validada(s)" (teal) — solo con base comparable; filas de corrida muestran "Sigma N/M válidas · K cubierta(s)". |
| `src/components/consola/copiloto.tsx` | Nota ámbar de transparencia del escudo en cada respuesta con trabajo del escudo: patrones marcados en entrada y/o ecos descartados en salida + "Las sugerencias provienen solo del razonamiento del copiloto". |
| `src/components/consola/higiene.tsx` | Aviso de caducidad próxima: insignia ámbar "caduca pronto" (< 30 min, sesión válida) + nota con la sugerencia de renovar al terminar el paso en curso. |
| `platform/tests/test_v27.py` | **NUEVO** — 15 tests (§5). |
| `README.md` | Roadmap: bloque "Completado en v27"; la propuesta del bucle sale de "Siguiente". |
| `docs/agentes/z1/` | Esta sesión + índice actualizado. |

## 4. Decisiones de diseño con fundamento

- **Intersección de tres fuentes, no unión**: cobertura declarada sin
  verificación (regla rota) o sin evidencia azul (detección pendiente) es
  relleno con forma de métrica. La intersección es más pequeña y más
  valiosa: cada técnica de `tecnicas_cubiertas` tiene hallazgo real, regla
  generada, regla VALIDADA y detección DOCUMENTADA.
- **El punto ciego como primera clase**: `no_detectado` con regla vigente
  no es un "no cubierto" — es una FALLA de la defensa con herramienta ya
  desplegada. El delta lo separa de las transiciones porque su acción es
  otra (investigar la detección, no desplegar la regla) y porque es
  regresión: algo que antes se detectaba dejó de detectarse.
- **Sin base comparable → sin transiciones**: fabricar el delta contra un
  resumen que no midió Sigma sería exactamente el "retroactivo inventado"
  que v23 desterró. El flag `comparable` deja constancia de POR QUÉ no hay
  listas (no es "no cambió nada", es "no puedo saberlo").
- **Transparencia como clave siempre presente**: {0,0} explícito en vez de
  clave ausente — el cliente no puede confundir "escudo sin trabajo" con
  "respuesta de una versión anterior", y el panel no necesita lógica de
  versiones.
- **Umbral de 30 min**: bastante para terminar el paso en curso, bastante
  corto para no ser ruido. No es configurable en esta ronda: una variable
  de entorno más sin demanda real es superficie sin valor.

## 5. Validación de la ronda

- `pytest tests/test_v27.py`: **15 passed** — bucle: la instantánea cruza
  reglas del caso (regla válida → técnica listada, pendiente → ni cubierta
  ni ciega), técnica sin fuente no inventa cobertura, VECTR entra al cruce
  (detectado → cubierta, no_detectado → punto ciego), regla inválida NO es
  cobertura (lote manipulado: la detección documentada no se promociona),
  transición end-to-end (corrida base → marcar detectado → delta con
  transición), regresión a punto ciego, sin base no se fabrican
  transiciones, primera corrida declara reglas sin fingir transición, y el
  validador sigue sin pySigma obligatorio; escudo: eco descartado se
  declara, solo-eco → ecos 1 + sugerencias vacías, respuesta sana → cero,
  marcas de entrada en el contexto (hostil 1 / benigno 0), E2E punta a
  punta de `consultar()` (1 marca + 1 eco + sugerencias del bloque propio)
  y caso limpio declara {0,0}.
- Suite completa: **475 passed / 8 skipped / 10 failed**, los 10 fallos
  idénticos al baseline del entorno (yara/ldap3 ausentes, documentado en
  v24/v25/v26) — cero regresiones.
- `tsc --noEmit`: 0 errores · `eslint` (ficheros tocados): 0 errores.
- Publicación en `main` por etapas con push continuo: backend del bucle +
  escudo (`cdd655f`→rebase→`1d8428d`), consola (`4600eb5`), tests
  (`053e93a`), documentación (este commit).

## 6. Propuestas para la siguiente ronda (z1)

1. **Informe continuo con el bucle**: el informe markdown del caso podría
   llevar una sección "Cobertura de detección (CTEM↔Sigma)" con la serie
   de transiciones acumuladas del historial de corridas — el dato que el
   cliente entiende sin saber qué es Sigma.
2. **Insignia de puntos ciegos en el Panel**: el contador de
   `puntos_ciegos` de la última corrida es un KPI que merece estar en la
   vista principal, no solo en Continuidad.
3. **Ruido de reintento en el copiloto**: si `ecos_descartados` es
   recurrente en un caso, el copiloto podría señalar en "Riesgos y OPSEC"
   que hay contenido hostil persistente en la memoria del caso (hoy la
   nota es por-respuesta; la señal agregada falta).
4. **Ingestión del dominio real al motor Neo4j** (abierta desde v23):
   requiere operador y credenciales.
