# Sesión 01 — Auditoría directiva: veredicto del conjunto, F32 cerrado en historial y CI restaurada

**Agente:** z-director · **Fecha:** 2026-09-12
**Estado del repo al empezar:** `main @ 8b98e97` (ronda 7 de z2 publicada —
hash pre-purga; la reescritura de historial de esta sesión cambió todos los
hashes posteriores, ver §6). Árbol limpio, 29 commits, repo público.

## 1. Contexto y mandato

El operador pidió una revisión de dirección: ¿va el proyecto por buena
dirección, está funcionando? La revisión se hizo en tres planos:

1. **Bitácoras**: lectura completa de las 15 sesiones de los agentes
   (4 de z1, 6 de z2, 5 de z3) y del `worklog.md` (33+ Task IDs).
2. **Código real**: suite completa en un venv NUEVO (instalación limpia),
   `tsc --noEmit` y `eslint` sobre la consola, barrido de patrones y del
   historial git completo.
3. **Estado remoto**: badge de Actions e historial público de GitHub — lo
   que un tercero ve, no lo que los entornos de los agentes ven.

## 2. Verificación independiente de partida (línea base)

| Verificación | Resultado |
|---|---|
| venv limpio + `requirements.txt` tal como estaba | **11 failed / 511 passed / 8 skipped** — los 11 en `test_z3_sesion4.py`, todos por `mcp` 2.2.0 |
| Con `mcp<2` (tope manual) | **522 passed / 8 skipped** — coincide con lo reportado por z2 en su ronda 7 |
| `tsc --noEmit` | 0 errores |
| `eslint .` | 0 errores |
| Badge de Actions en GitHub | **"CI - failing"** — la CI SÍ corría y fallaba, en contradicción con el verde local de los agentes |
| Deuda de código | 0 TODO/FIXME/HACK; F1-F33 de z3 remediados con test de regresión |
| Documentación multi-agente | Excepcional: sesiones autocontenidas, "deferido ≠ ignorado", contratos fijados por test |

**Veredicto de dirección: correcto.** La trayectoria v22→v27 (bucle
CTEM↔purple↔Sigma, escudo LLM01 en entrada y salida, SSO federado,
endurecimiento continuo con 33 hallazgos remediados) es coherente,
disciplinada y de calidad profesional. El modelo de 3 agentes con bitácoras
por sesión y worklog compartido **está funcionando**. Los dos incidentes
que siguen no son de dirección técnica sino de **verdad remota**: nadie
miraba lo que GitHub muestra a un tercero.

## 3. Incidente A — F32: secreto JWT en el historial público (cierre)

**Hallazgo (verificado a mano):** `git cat-file -p 9cdab8d:usuarios.db`
(pre-purga) devolvía la BD de operadores con `config.secreto_jwt` real
(64 hex) y el hash scrypt de la cuenta admin. z3 lo detectó correctamente
en su sesión 5 (F32, severidad ALTA), retiró las BDs del índice y dejó la
purga de historial como "pendiente para el equipo" — y ahí se quedó,
mientras el repo es público y el secreto sigue siendo falsificable por
cualquiera que clone. Ventana de exposición: desde `9cdab8d` (v22 añadió
las BDs) hasta `a79b2f3` (sesión 5 de z3 las retiró del índice).

**Escaneo completo del historial** (todos los commits, todos los objetos):
el único material sensible en toda la historia son las 11 BDs
(`usuarios.db` + 10 `casos/caso_*.db`, que solo contienen esas 10 en toda
la historia). No hay `.env` con credenciales, ni `.pem`/`.key`, ni otros
secretos — el `.env.example` es plantilla legítima (F16).

**Remediación aplicada en esta sesión:**

- `git filter-repo --force --invert-paths --path usuarios.db --path casos/`
  sobre el historial completo: las 11 BDs desaparecen de TODOS los commits.
- Verificación de integridad: el árbol de HEAD es **idéntico** pre/post
  purga (mismo SHA de árbol `1f10abf4…`), los 30 commits se conservan
  (ninguno quedó vacío), y el blob antiguo del secreto ya no existe
  físicamente (`git cat-file` lo rechaza). Suite re-ejecutada tras la
  purga: 522 passed / 8 skipped.
- Copia temporal usada para la inspección: eliminada; en el informe solo
  quedó la longitud del secreto, nunca su valor.

**Lo que la purga NO arregla (rotación — orden para el operador/z3):**
mientras el secreto estuvo público, cualquier tercero pudo copiarlo. La
purga borra el historial; no borra la memoria de quien lo descargó. En todo
despliegue derivado que conserve la BD heredada:

1. Rotar el secreto (quirúrgico): generar uno nuevo con
   `python -c "import secrets;print(secrets.token_hex(32))"` y
   `sqlite3 usuarios.db "UPDATE config SET valor='<nuevo>' WHERE clave='secreto_jwt'"`,
   reiniciar. Al ser HS256, todos los JWT previos fallan la verificación de
   firma — equivale a un cerrar-todas criptográfico.
2. Rotar la contraseña de la cuenta admin (su hash scrypt también viajó en
   el historial: material de cracking offline).
3. Alternativa nuclear para despliegues de referencia/descartables: borrar
   `usuarios.db` — el arranque regenera secreto y bootstrap (auth.py
   `_secreto_jwt` auto-genera con `secreto_jwt()`; pierde
   organizaciones/cuentas).
4. Opcional: pedir a GitHub Support la limpieza de vistas cacheadas (los
   commits antiguos pueden seguir accesibles por SHA un tiempo tras el
   force-push — práctica estándar de remoción de datos sensibles).

**Advertencia operativa crítica:** los commits antiguos (con el secreto)
viven todavía en las ramas remotas `z3/auditoria-seguridad-sesion1` y
`z3/auditoria-seguridad-sesion3` (fusionadas en main; sus punteros apuntan
a historia pre-purga) y en los clones de los entornos de los agentes. Ver
§7.

## 4. Incidente B — CI roja en GitHub con suite verde local (cierre)

**Causa raíz única y confirmada:** `platform/requirements.txt` pedía
`mcp>=1.1.2` SIN tope. El SDK oficial de MCP publicó la serie 2.x
(`FastMCP` renombrado a `MCPServer`, otras APIs cambian), con lo que toda
instalación limpia — la de CI, la de cualquier tercero — recibe mcp 2.2.0:
los 4 servidores MCP no arrancan y **11 tests** de `test_z3_sesion4.py`
fallan. Los entornos de los agentes tenían mcp 1.x ya instalado y veían
verde; nadie validaba desde cero. Reproducido dos veces en venv nuevo:
con mcp 2.2.0 → 11 failed; con tope `mcp<2` → 522 passed.

**Falso positivo propio, declarado:** mi primera lectura del workflow
`.github/workflows/ci.yml` vía terminal mostraba `branches: ain]` y lo
reporté como trigger corrupto de nacimiento. Verificación con `od -c` +
`yaml.safe_load` demuestra que el fichero siempre dijo
`branches: [main]` (dos apariciones, YAML válido, filtro correcto) — el
"ain]" era un artefacto de renderizado del terminal que se comió los
caracteres `[m`. El hecho de que el badge dijera "failing" (y no "no
status") ya apuntaba a que la CI corría: la correlación estaba delante. Se
corrige aquí porque enterrar un error propio sería exactamente lo que este
proyecto no hace.

**Remediación aplicada:** tope `mcp>=1.1.2,<2` en `requirements.txt` con
comentario que explica el porqué y señala la migración al SDK v2 como
tarea planificada (no urgente). Sin tocar `ci.yml` — el trigger estaba
correcto. La resolución del tope verificada con pip (mcp 1.30.0, la versión
con la que pasan los 522).

## 5. Cambios publicados en esta sesión

| Fichero | Cambio |
|---|---|
| `platform/requirements.txt` | Tope `mcp>=1.1.2,<2` con comentario de razón (SDK 2.x rompe servidores y 11 tests en instalación limpia). |
| `README.md` | Badge de tests al día: 290 → 522 (el badge quedó congelado en v22; la suite creció con cada ronda). |
| `docs/agentes/z-director/` | Carpeta del agente: README (ficha e índice) + esta sesión. |
| `docs/agentes/z-director.md` | Punta de rastro hacia la carpeta (mismo convenio que z1/z2/z3). |
| `worklog.md` | Entrada de esta sesión por Task ID. |
| Historial git | **Reescritura completa** (purga F32): sin `usuarios.db` ni `casos/*.db` en ningún commit; árbol final idéntico. |

Commit del tope: `7a6d7ca` (pre-purga) → `990832d` tras la reescritura.
La documentación de esta sesión y el badge viajan en el commit siguiente.

## 6. Consecuencias de la reescritura de historial (importante)

Todos los hashes posteriores a v22 cambiaron. Las bitácoras de z1/z2/z3 y
el `worklog.md` citan hashes pre-purga (`8b98e97`, `79f32a1`, `a79b2f3`…):
quedan como referencias históricas válidas de SU momento, pero ya no
resuelven en el repo tras el force-push. No se reeditan las bitácoras de
otros agentes; las sesiones futuras deben citar hashes post-purga (o
fechas) y saber que los pre-purga son historia, no enlaces rotos por error.

## 7. Pendiente para el equipo (órdenes de dirección)

1. **Operador — publicar la purga (bloqueante, hoy):** force-push de
   `main` a origin y borrado de las dos ramas remotas antiguas
   (`z3/auditoria-seguridad-sesion1`, `z3/auditoria-seguridad-sesion3`):
   ambas están fusionadas en main y sus punteros conservan el historial
   con el secreto. Tras el push, verificar badge de CI en verde.
2. **Todos los entornos de agentes — re-clonar ANTES del próximo push
   (bloqueante):** si un agente pushea desde un clon pre-purga, el
   historial con el secreto VUELVE a GitHub y la purga se deshace.
   `git fetch && git reset --hard origin/main` también sirve; con re-clone
   no hay duda.
3. **z3 — rotación (esta semana):** ejecutar la rotación del secreto JWT y
   de la contraseña admin en todo despliegue derivado (§3), y cerrar el
   ítem "rotar/revisar credenciales publicadas históricamente" abierto
   desde su sesión 1, ahora con inventario: el escaneo completo de esta
   sesión confirma que lo único sensible en toda la historia eran las 11
   BDs.
4. **z2 — higiene de dependencias y CI (siguiente ronda):** añadir a la
   checklist de ronda "instalación limpia + badge de Actions verde tras el
   push" (esto habría destapado ambos incidentes hace rondas); revisar
   topes en el resto de dependencias críticas; planificar la migración al
   SDK MCP v2 como tarea propia.
5. **z1 — mantener roadmap:** ninguna incidencia abierta de su área; el
   Neo4j del dominio real sigue requiriendo operador.

## 8. Verificación de la sesión

- Historial: 0 BDs en commits y en objetos (`git log --all -- '*.db'` y
  `git rev-list --objects --all` vacíos); blob del secreto inexistente;
  árbol pre/post idéntico; 30 commits conservados.
- Suite post-purga (venv con el tope): **522 passed / 8 skipped**, 38 s.
- `tsc --noEmit`: 0 errores · `eslint`: 0 errores (sin cambios TS).
- `requirements.txt` resuelve sin conflictos con el tope (mcp 1.30.0).
- El workflow `ci.yml` se dejó intacto tras verificar (od -c + yaml) que
  su filtro de ramas siempre fue correcto.

## 9. Propuestas para la siguiente sesión de dirección

1. **Verificación post-push**: confirmar badge de CI en verde, ramas
   antiguas eliminadas y clone-limpio sin BDs; cerrar formalmente F32 en
   el estado acumulado de z3 cuando confirme la rotación.
2. **Métrica de verdad remota**: evaluar con el operador si la siguiente
   ronda de dirección revisa también la vista pública de GitHub
   (releases, demo embebida) con los mismos ojos de tercero.
3. **Auditoría de entornos de agentes**: lista de comprobación de que
   cada entorno partió de un clon post-purga antes de su próximo commit.
