# Sesión 05 — v28: dashboard completo + recorrido del README + árbol ordenado

**Agente:** z1 · **Fecha:** 2026-09-12
**Estado del repo al empezar:** `main @ a79b2f3` (v27 documentada + auditoría
z3 sesión 5). Instrucciones del operador en esta ronda: revisar si el
dashboard tiene todo, revisar si el README está actualizado, grabar GIF e
imágenes para el README, ordenar el árbol del proyecto y continuar con las
rondas.

## 1. Auditoría de partida

Antes de escribir una línea hice tres auditorías sobre el estado real:

### 1a. ¿El dashboard tiene todo? — inventario endpoint↔UI

Crucé los 78 endpoints de `api.py` contra las acciones de `store.ts` y las
18 vistas de la consola. El inventario confirmó que la inmensa mayoría del
backend ya tiene superficie (casos, pipeline, aprobaciones, hallazgos,
evidencias, rutas, arsenal, cadenas, CTEM, Sigma, webhooks, SSO, higiene…)
y dejó **tres brechas reales**:

1. **`POST /api/engagements/{id}/roe`** (ROE vivo) — el backend soporta
   cambiar en caliente techo de ruido, ventana horaria y exclusiones de
   alcance desde v16, pero NADIE lo llamaba desde la consola: el operador
   tenía que reimprimir el ROE o tirar de curl. Gobernanza crítica sin UI.
2. **`GET /api/admin/auditoria-sistema`** — la traza append-only del
   despliegue (altas/bajas, cambios de rol y organización, respaldos) solo
   existía en `usuarios.db`; el admin no la veía.
3. **`POST /api/auth/tenant`** — el admin podía crear cuentas en una
   organización pero no MOVER una cuenta existente de organización
   (cross-tenant), capacidad que el propio backend ya auditaba.

También revisé `sso/vincular` (cuarta brecha menor) y la dejé fuera de
alcance: el flujo de vinculación exige la interacción del IdP y conviene
diseñarla junto al onboarding SSO, no como parche suelto.

### 1b. ¿El README está actualizado? — tres desajustes

- El badge decía **290 tests**; `pytest --collect-only` reporta **509**.
  La cifra venía de rondas atrás (v22).
- El GIF y las dos capturas embebidas eran de la **era v17-v19**: faltaban
  el editor de ROE, el panel Sigma, el bucle CTEM, la auditoría del sistema
  y la higiene de cuenta — media plataforma era invisible para quien entra
  al repo.
- El árbol de "Estructura del repositorio" no mencionaba `ctem.py`,
  `sigma_valid.py`, ni la carpeta real `servidores_mcp/` (decía `mcp/`).

### 1c. ¿El árbol está ordenado? — dos focos de ruido

- **`download/`** en la raíz: 39 ficheros (capturas v12-v22, un duplicado
  EXACTO de `docs/demo/` llamado `orquesta-rt-demo/`, un `errores.txt`).
  Era el bus de entregas de rondas anteriores; ninguna referencia en docs
  lo apuntaba. Residuo con 2 MB de peso histórico.
- **`tsconfig.tsbuildinfo`** y 86 `caso_*.db` de residuo de tests en el
  árbol LOCAL (ninguno rastreado — z3 los sacó del índice en F32, bien —
  pero ensuciaban `git status` y el listado de casos de la consola).

## 2. Decisiones de implementación

### 2a. ROE vivo: editar lo mutable, blindar lo contractual

El endpoint distingue lo que puede cambiar en caliente (techo, ventana,
exclusiones) de lo que NO (alcance principal, técnicas prohibidas). El
diálogo respeta EXACTAMENTE esa frontera y lo dice en su texto: tocar el
alcance principal por un diálogo rápido sería sustituir el contrato firmado
por un formulario. Detalles de la implementación (`dialogo-roe.tsx`):

- Rehidratación del formulario CADA vez que se abre (el ROE puede cambiar
  por SSE desde la última edición).
- Solo se envía al backend el campo que realmente cambió (diff local contra
  el ROE vivo): evita "cambios fantasma" en la auditoría.
- El botón "Editar" se oculta al rol lector (el middleware devuelve 403 a
  escritura; no hace falta enseñarle una puerta cerrada).
- Validación cliente que replica la del servidor: entero 0-100, HH:MM,
  al menos un día (una ventana vacía detendría el ciclo — mejor denegarlo
  en el cliente con explicación que recibir el 422).

### 2b. Auditoría del sistema: otra traza, otro lugar

No la mezclé con la auditoría del caso (Memoria): viven en bases distintas
(`usuarios.db` vs SQLite del caso), con actores y semántica distintas. Va
como tarjeta propia al final de **Equipo** con refresco manual — es una
vista de administración de bajo tráfico, no un feed en vivo.

### 2c. Reasignación de tenant: deshabilitado sobre uno mismo

`asignar_tenant` invalida las sesiones previas de la cuenta movida. Mover
la PROPIA cuenta desde la UI te cerraría la sesión al instante (el backend
lo permite; la UI no debe facilitar un candado autoinfligido). El select
se deshabilita en la fila propia, igual que el cambio de rol.

### 2d. GIF y capturas: consola real, backend real, cero maqueta

Mismo estándar del repo: nada de fotos de maqueta. Monté el stack real
(uvicorn + lab + consola), sembré `caso_demo_acme` (el seeder del núcleo
que ejercita guardrails/custodia/auditoría reales) y recorrí la consola
con Playwright: 10 capturas (panel, diálogo ROE, aprobaciones, hallazgos
con Sigma, cobertura, cadenas, copiloto, equipo con auditoría, higiene y
móvil 390) + el GIF de 9 fotogramas con ffmpeg (paleta generada, 1280×800,
~1.7 s por escena).

De camino, la grabación destapó DOS defectos reales que corregí:

- **`pattern` inválido en el login**: `[A-Za-z0-9._-]{3,32}` no es válida
  bajo la semántica *v-flag* que los navegadores aplican hoy al atributo
  `pattern` (el guion suelto tras `.`). Chrome registraba un error en cada
  carga del acceso. Escapado a `[A-Za-z0-9._\-]{3,32}`.
- **Overlay de desarrollo en las demostraciones**: el indicador "Issues" de
  Next 16 contaba las 2 advertencias Edge de `instrumentation.ts` (ruido
  preexistente, solo dev) y aparecía en cada captura. `devIndicators: false`
  en `next.config.ts` — el despliegue real es producción standalone.

Los 86 `caso_*.db` de residuo de tests también se eliminaron del entorno
local: la lista de casos de la consola quedó con el caso demo real, que es
lo que las capturas debían mostrar.

## 3. Validación

- `tsc --noEmit` 0 · `eslint` 0 en los ficheros tocados.
- Suite completa: **490 passed / 8 skipped / 11 failed**. Los 11 fallos son
  TODOS de `test_z3_sesion4` (F26/F27/F30: red externa y SDK opcional del
  sandbox) y son IDÉNTICOS en un clon limpio de `main` — baseline del
  entorno, cero regresiones.
- Un falso positivo propio: `test_api_threatled_401_y_cadena_404` falló
  mientras mi `usuarios.db` local existía con operadores (el test salta la
  creación de `opv21` si `hay_operadores()`); apartada la base, verde.
  Anotado como característica del entorno, no bug del repo.
- La grabación E2E ES validación: login, selección de caso, todas las
  vistas, diálogo ROE y higiene operando contra el orquestador real.

## 4. Estado resultante

- Dashboard: las tres brechas cerradas; el inventario endpoint↔UI queda
  completo salvo `sso/vincular` (fuera de alcance, documentado).
- README: badge 509 tests, GIF + 4 capturas v28, capacidades CTEM e
  higiene de sesión añadidas, roadmap v28, árbol corregido.
- `docs/DEMOSTRACION.md`: sección 8 con las novedades v28 ilustradas.
- Árbol: `download/` eliminado del repo e ignorado; `tsconfig.tsbuildinfo`
  fuera del disco de trabajo.

## 5. Propuestas para la próxima ronda

1. **Vinculación SSO↔cuenta local** (`sso/vincular`): cerrar la cuarta
   brecha con un flujo desde la higiene de cuenta ("añade acceso SSO a tu
   cuenta"), con revocación del hash de contraseña si procede.
2. **Aviso de sesión ajena** (pendiente desde la sesión 03): notificar en
   la higiene cuántas sesiones activas tiene la cuenta y desde qué cabeceras
   — el backend ya registra las sesiones; falta la vista.
3. **Recorrido del GIF en dos actos**: el GIF actual es de 9 escenas;
   valoraría una variante por fases del ciclo (ofensiva y purple) para la
   documentación comercial, reutilizando el mismo rig de grabación.
4. **Ingestión del dominio real al Neo4j** sigue bloqueada por credenciales
   del operador (roadmap global, no ejecutable por agentes).
