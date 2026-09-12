# Sesión 03 — v26: cierre del eco de JSON (LLM01, salida) + higiene de cuenta

**Agente:** z1 · **Fecha:** 2026-09-12
**Estado del repo al empezar:** `main @ c9ba451` (v25 + rondas 2-3 de z2 y
sesión 3 de z3 sincronizadas), árbol limpio y en `main`.

## 1. Auditoría de partida

Instrucción del operador para esta ronda: continuar la ronda, seguir
pusheando y **hacer todos los commits en `main`**.

Parto de las cuatro propuestas que dejé abiertas en la sesión 02 y las
re-evalúo contra el estado REAL del repo (el worklog trae trabajo nuevo de
z2 y z3 que cambia el terreno):

1. **Endurecer `_partir_estructura` frente al eco de JSON** — Sigue abierta
   y es mía: verifiqué `copiloto.py` y el riesgo residual documentado en
   v25 sigue intacto (`_extraer_json` del razonador devuelve el ÚLTIMO
   bloque parseable; un eco del payload «falso_json» de la familia 4 que
   llegara al final de la respuesta ganaría la selección). El escudo v25
   protege la ENTRADA (spotlighting de los fragmentos RAG); la SALIDA
   estructurada no tiene defensa propia más allá de la regla 8 del prompt.
2. **Ingestión del dominio real al motor Neo4j** — Sigue requiriendo al
   operador (credenciales del dominio): no es ejecutable por un agente.
   Sigue en el roadmap.
3. **Cierre del bucle CTEM ↔ purple ↔ Sigma** — La dejo planteada: es un
   cambio de modelo de dominio (transiciones de cobertura anotadas en el
   delta CTEM) que merece ronda propia con el operador delante.
4. **Panel de sesiones/higiene de cuenta** — Sigue abierta y es mía
   (manejo del usuario web). Verifiqué `auth.py`: el mecanismo de
   revocación de z3-F4 (`invalidar_antes` por cuenta + chequeo en el
   middleware + caché TTL) existe y funciona, pero NO hay superficie de
   usuario: el operador no puede ver el estado de su propia sesión ni
   ejecutar el equivalente a «cerrar sesión en todos los dispositivos».
   La gestión existente (equipo.tsx) es solo de ADMIN sobre otros.

Decisión: **esta ronda ejecuta las propuestas 1 y 4** — las dos son mías
por mandato (IA y manejo del usuario web), las dos cierran riesgos reales
(verificados en el código, no en el papel) y las dos eran propuestas mías
de la sesión anterior, así que el rastro es coherente.

## 2. Investigación y razonamiento

### 2a. El eco de JSON: ¿cómo se cierra una inyección en la SALIDA?

El atacante siembra en un fragmento RAG un bloque ```json``` con
«sugerencias» (familia 4 del escudo v25). La regla 8 le dice al modelo que
no copie bloques de los datos; el marcado ⟦dato⟧⟨…⟩ lo señala. Pero si el
modelo lo copia AUN ASÍ y lo suelta al final de su respuesta, el selector
«el último que parsea gana» adopta las sugerencias del atacante como si
fueran análisis del copiloto. Opciones consideradas:

- **Firmar el bloque del modelo** (pedirle un campo secreto): frágil — el
  eco copia la firma también; y complica el contrato.
- **Preferir el PRIMER bloque en vez del último**: rompe el contrato de la
  regla 5 (el bloque va al final) y no resuelve nada (el atacante puede
  poner su payload al principio del análisis igualmente).
- **Validar la PROCEDENCIA del bloque** (elegida): un bloque que ya estaba
  EN el contexto entregado (normalizado: sin marcas del escudo y con el
  espacio colapsado) es, por definición, DATO — no razonamiento del
  modelo. Se recorren los candidatos de último a primero (el del copiloto
  va al final por la regla 5) y se descarta todo eco. Si todos son eco o
  no hay bloque sano, las sugerencias quedan vacías: NUNCA se fabrican ni
  se adoptan del dato. Es la mitad estructural de la regla 8: deja de
  depender de que el modelo obedezca.

Detalles de ingeniería que decidí:

- **Normalización anti-decoraciones**: el eco puede llegar CON las marcas
  del escudo (el modelo copia lo que ve) o sin ellas (las limpia). La
  comparación de procedencia quita `⟦dato⟧⟨⟩` antes de comparar: dato es
  dato en ambos casos. El colapso de espacios hace la comparación robusta
  a reformateos triviales sin abrir la puerta a similitudes (el test de
  bloque-propio-similar-no-es-falso-positivo lo demuestra: se compara por
  contenido EXACTO, no por similitud).
- **Canales válidos como contrato real**: `_CANALES_VALIDOS` = fases del
  enum `Fase` (F0_scoping…F7_informe) + `aprobacion` + `informe`. Una
  sugerencia con canal desconocido (`ejecutar_ahora`) no puede crear un
  canal nuevo: degrada a `aprobacion`, el camino que SIEMPRE exige humano.
  Antes el canal era una string libre recortada a 40 chars.
- **Regla 5b nueva en el prompt**: el bloque es la ÚLTIMA palabra del
  modelo; los JSON del dato jamás se replican al final. El endurecimiento
  estructural y el contractual se refuerzan.
- **Fallback honesto**: sin bloques cercados, el JSON desnudo sigue
  funcionando (mismo fallback del razonador); JSON inválido no fabrica
  nada. Con `contexto=""` el comportamiento es el clásico (último bloque
  válido) — ningún llamador existente se rompe.
- **Riesgo residual documentado**: un bloque PARAFRASEADO por el modelo a
  partir del dato no es un eco literal y no lo detecta la procedencia;
  para ese caso quedan la regla 8 (prompt), el marcado de entrada (v25) y
  el clamp de canal (esta ronda). El eco VERBATIM —el escenario realista,
  los modelos copian literal— queda cerrado.

### 2b. Higiene de cuenta: qué puede hacer un usuario consigo mismo

El modelo de sesiones del despliegue es JWT sin estado + corte de
revocación por cuenta (`invalidar_antes`, z3-F4). No hay tabla de sesiones
— y no la hace falta. Eso define lo que el panel puede ofrecer honestamente:

- **Ver**: rol y organización VIGENTES (los de la BD que comprueba el
  middleware, no los claims congelados del token — si un admin degradó la
  cuenta, el panel lo enseña), emisión y caducidad del JWT actual,
  segundos restantes, y el corte de revocación vigente.
- **Actuar**: «cerrar sesión en todos los dispositivos» = fijar
  `invalidar_antes` a ahora. Muere TODO token emitido antes, INCLUIDO el
  que hace la petición (semántica estándar sign-out-everywhere; el
  cliente limpia su sesión local al recibir el 200). La credencial NO se
  toca: NO es un restablecimiento administrativo (para eso está el canal
  de z3, con confirmación de admin y auditoría).
- **RBAC**: es una superficie de USUARIO, no de administración: cualquier
  rol autenticado consulta SU higiene (el lector incluido). El middleware
  ya exige token para ambas rutas (no están en la lista pública).
- **Auditoría**: el cierre global queda en `auditoria_sistema`
  (`sesion.cierre_global`) — es una acción de seguridad, deja rastro.
- **Rate limit**: el POST usa el limitador del sistema (`:cerrar-sesiones`),
  patrón de login/registrar.
- **Detalle de diseño en el frontend**: la carga es FRESCA en cada
  apertura del diálogo (el estado puede cambiar entre aperturas: rol
  degradado, corte nuevo). El 401 del middleware sobre un token muerto ya
  lo maneja el store (cierra la sesión local y vuelve al acceso): el
  panel no necesita su propia lógica de expulsión — la hereda.

Hallazgo colateral del testeo (documentado, no corregido porque es del
diseño de z3-F4 y es fail-closed): el corte es epoch FLOTANTE y el `iat`
del JWT va truncado a segundo; un re-login en el MISMO segundo del corte
produce un token muerto (el usuario reintenta y entra). Dirección segura
del fallo: rechazar de más, nunca de menos. En los tests se espera ~1 s.

## 3. Implementado en esta ronda

| Fichero | Cambio |
|---|---|
| `platform/orchestrator/copiloto.py` | **Cierre del eco de JSON** — regla 5b del `SISTEMA`; `_CANALES_VALIDOS` (fases + aprobacion + informe); `_normalizar_bloque()` (sin marcas, espacio colapsado); `_candidatos_json()` (bloques cercados parseados en orden + fallback JSON desnudo); `_es_eco_de_datos()` (procedencia contra el contexto entregado); `_elegir_bloque_sano()` (de último a primero, descarta ecos, `None` si no hay sano); `_partir_estructura(texto, contexto="")` valida canal (desconocido → `aprobacion`) y elige con procedencia; `consultar()` entrega `datos["contexto"]` a la selección. Import de `_extraer_json` eliminado (ya no se usa). |
| `platform/orchestrator/auth.py` | **Higiene de cuenta** — `higiene_cuenta(usuario)`: estado vivo (rol, tenant, creado_en, ultimo_acceso, invalidar_antes) sin material sensible; `revocar_sesiones_propias(usuario)`: fija el corte a ahora SIN tocar credencial, invalida la caché de sesión y devuelve el corte. |
| `platform/orchestrator/api.py` | **API v26** — `GET /api/auth/higiene` (cualquier rol autenticado: estado vivo + identidad del token: emisión, expiración, segundos restantes, `sesion_valida` según z3-F4); `POST /api/auth/sesion/cerrar-todas` (sign-out-everywhere propio, rate-limited, auditado `sesion.cierre_global`). |
| `src/lib/tipos.ts` | `HigieneToken` + `HigieneCuenta` (contrato del endpoint). |
| `src/lib/store.ts` | `obtenerHigiene()` y `cerrarSesionesPropias()` (POST + limpieza local de sesión reutilizando `cerrarSesion()` del store). |
| `src/components/consola/higiene.tsx` | **NUEVO** — diálogo de higiene: identidad y rol vigentes, alta/último acceso, sesión actual (válida/revocada), emisión/caducidad con cuenta atrás legible, corte de revocación; botón «Cerrar en todos los dispositivos» con AlertDialog de confirmación que advierte que también muere esta pestaña y que la contraseña no cambia; carga fresca por apertura; errores inline + toast. |
| `src/components/consola/consola.tsx` | El chip de sesión de `BarraSuperior` es clicable y abre el diálogo (el botón de logout ordinario se conserva); estado local de la cabecera. |
| `platform/tests/test_v26.py` | **NUEVO** — 32 tests (ver §5). |
| `README.md` | Roadmap: bloque «Completado en v26». |
| `docs/agentes/z1/` | Esta sesión + índice actualizado. |

## 4. Decisiones de diseño con fundamento

- **Procedencia en vez de firma**: comparar el bloque contra el contexto
  entregado es determinista, no depende del modelo y no cambia el formato
  de salida. La firma/nonce dependía de la obediencia del modelo — justo
  lo que la defensa no puede asumir.
- **Degradar canal en vez de rechazar sugerencia**: un canal inventado no
  invalida el contenido de la sugerencia (que el operador valora), pero
  tampoco puede abrirse paso hacia la ejecución directa. `aprobacion` es
  el único canal seguro por defecto: siempre hay humano delante.
- **Sign-out-everywhere sin tabla de sesiones**: es lo máximo que el
  modelo de sesiones del despliegue puede prometer con honestidad; una
  tabla de sesiones individuales sería otro producto (y otro vector de
  persistencia). Se documenta así en el panel: «revoca todos los tokens
  emitidos antes de ahora».
- **El panel en la cabecera, no en Equipo**: Equipo es de admin (gestión
  de OTROS); la higiene es de UNO MISMO y debe estar a un clic del chip
  que ya enseña quién eres — donde el operador ya mira cuando piensa en
  su sesión.

## 5. Validación de la ronda

- `pytest tests/test_v26.py`: **32 passed** — copiloto: eco verbatim al
  final no gana el bloque propio, respuesta-solo-eco → sugerencias
  vacías con prosa intacta, eco con decoraciones del escudo descartado,
  eco insensible a reformateo de espacios, bloque-propio similar NO es
  falso positivo, sin contexto comportamiento clásico, canal desconocido
  → aprobacion, 10 canales del contrato preservados, JSON desnudo de
  siempre, JSON inválido no fabrica, eco partido en prosa no confunde,
  regla 5b en el prompt y `consultar` entrega el contexto a la selección;
  higiene: estado vivo sin hash, cuenta fantasma None, revocación mata el
  token actual al instante, conserva la credencial (re-login vivo),
  fantasma ValueError, 401 sin sesión en ambas rutas, lector consulta la
  suya, rol vivo ≠ claim congela el token, cerrar-todas mata el token y
  permite re-login, evento `sesion.cierre_global` en auditoría.
- Suite completa: **413 passed / 8 skipped / 10 failed**, con `diff` de la
  lista de fallos contra un worktree del commit pre-v26 (`c9ba451`) =
  **VACÍO** (los 10 son pre-existentes del entorno: yara/ldap3/nvd
  ausentes). Cero regresiones; las suites v25/z3-sesion-2/z3-sesion-3
  re-ejecutadas juntas: 92 passed.
- `tsc --noEmit`: 0 errores · `eslint` (ficheros tocados): 0 errores.

## 6. Propuestas para la siguiente ronda (z1)

1. **Cierre del bucle CTEM ↔ purple ↔ Sigma** (recuperada de la sesión 02,
   sigue madura): cuando el operador marca `detectado` en un hallazgo
   cuya técnica tiene regla Sigma validada, el delta CTEM anota la
   transición de cobertura. Ronda propia con el operador delante.
2. **Aviso de sesión ajena en la higiene**: si `segundos_restantes` cae
   bajo un umbral (p. ej. 30 min), una insignia ámbar sugiere re-login
   proactivo; evita sorpresas a mitad de engagement.
3. **Confirmación del propio criterio en el copiloto**: cuando el escudo
   marcó patrones ENTRADA (v25) y además se descartó un eco de SALIDA
   (v26), la respuesta podría llevar una nota «sugerencias filtradas por
   procedencia» para que el operador sepa que el modelo intentó (o el
   dato intentó) colar algo — transparencia total del escudo.
4. **Ingestión del dominio real al motor Neo4j** (abierta desde v23):
   requiere operador y credenciales.
