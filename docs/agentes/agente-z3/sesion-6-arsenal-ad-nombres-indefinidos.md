# Sesión 6 — Arsenal AD roto por nombres indefinidos y compactación de fases muerta

> Agente z3 · auditoría de seguridad y revisión de código de orquesta-rt.
> Base auditada: commit `f0967c7` (main, tras incorporar la ronda 5 de z2).
> Estado final: **F34, F35, F36 remediados** con tests de regresión y una
> guarda sistémica contra toda la clase de defecto.

## Alcance de la ronda

Las sesiones 1-5 cubrieron la superficie expuesta (API, proxy, SSO, TLS,
MCP, analítica multi-tenant, higiene de git). Esta ronda ataca el hueco
restante con dos frentes complementarios:

1. **Módulos del backend nunca auditados a fondo**: `guardrails.py`
   (boundary completo), `ad.py` (arsenal AD ofensivo con impacket),
   `persistencia.py`, `navigator.py`, `ctem.py`, `purpleteam.py`,
   `sigma_valid.py`, `respaldo.py`, `sidecar.py`, `evasion.py`, `graph.py`,
   `agents/fases.py`, `cli.py`, `demo_seed.py`, `state.py` y las
   integraciones `metasploit`, `sliver`, `mythic`, `bloodhound`, `nvd`,
   `rutas`, `ldap`, `misp` y el servidor MISP de laboratorio.
2. **Consola Next.js** (`src/app/api/**`, `src/instrumentation.ts`,
   `src/lib/store.ts`): las tres rutas API (proxy orquestador, puente IA,
   healthcheck) y el bootstrap del backend.

La técnica que destapa los hallazgos de esta ronda es el **análisis
estático sistemático** (`pyflakes`) sobre todo el Python de la plataforma,
complementado con lectura línea a línea de los módulos con hallazgo. Las
rondas anteriores razonaron sobre patrones peligrosos (inyección, SSRF,
secretos); esta ronda demuestra que también hay que razonar sobre la
*salud sintáctica y de ligado de nombres* del código: tres símbolos que
nadie definió dejaban herramientas de producción fuera de servicio.

## Hallazgos y remediación

### F34 — ALTO (funcional): `ad.asrep()` muere con `NameError` en su caso de uso principal

- **Dónde**: `platform/orchestrator/ad.py`, línea 188 (pre-fix).
- **Qué había**: dentro de `asrep()` (AS-REP Roasting, T1558.004), la línea
  `etipo_clave = _enctype_table[23]`. `_enctype_table` no existe en el
  módulo ni se importa de `impacket.krb5.crypto` (su hogar real en
  impacket). La asignación era además **muerta**: el etype se lee de la
  propia `AS_REP` recibida y la lista solicitada ya viaja en
  `cuerpo["etype"]`.
- **Impacto**: `py_compile` pasa (es un error de *nombre*, no de sintaxis),
  así que el defecto era invisible para CI y para cualquier prueba de
  import. La línea está **fuera de todo try**: en cuanto el directorio
  declara cuentas sin preautenticación —exactamente el caso de uso de la
  herramienta— `asrep()` eleva `NameError` que sube intacta hasta
  `POST /api/engagements/{id}/arsenal/ad` y produce un **500 no
  controlado**. Con el directorio *vacío* de cuentas roastables la
  herramienta devolvía el resultado honesto y el bug pasaba inadvertido:
  el camino roto solo se pisa con datos reales.
- **Fix**: se elimina la línea muerta (comentado con el razonamiento
  completo en el código). Cero cambios de comportamiento en los caminos
  sanos.

### F35 — MEDIO (funcional): `ad.dcsync()` nunca funcionó (`username` inexistente)

- **Dónde**: `platform/orchestrator/ad.py`, línea 278 (pre-fix).
- **Qué había**: tras un login SMB correcto, `dcsync()` (DRSUAPI
  GetNCChanges, T1003.006) construía el transporte con
  `transport.SMBTransport(host, 445, r"\pipe\drsuapi", username, clave,
  ...)`. La variable del ámbito es `usuario`; `username` no existe.
- **Impacto**: `NameError` tras autenticarse, capturado por el `except
  Exception` genérico de la función y devuelto como `"DCSync falló contra
  el DC real: name 'username' is not defined"`. Dos consecuencias: (a)
  **DCSync jamás replicó nada**, ni con credenciales válidas y DC
  alcanzable; (b) el mensaje de error **acusaba a la red**, empujando al
  operador a depurar conectividad/SMB cuando el defecto era de código.
  Un fallo que se disfraza de problema de entorno es la peor clase de bug
  en una herramienta ofensiva catalogada.
- **Fix**: se usa el identificador correcto (`usuario`), comentado en el
  código. Verificado además que ningún otro nombre del módulo tiene el
  mismo defecto (guarda sistémica, abajo).

### F36 — BAJO (robustez/economía): compactación de fases muerta por `import json` ausente

- **Dónde**: `platform/orchestrator/graph.py` (pre-fix: sin `import json`).
- **Qué había**: `EjecutarFases.ejecutar_fase` serializa el resultado de
  cada fase con `json.dumps(res, ...)` para la compactación del resumen
  (economía del token, cap. 3.2 del blueprint). El módulo nunca importó
  `json`.
- **Impacto**: el `NameError` caía dentro del `try/except Exception` de la
  compactación y **se tragaba en silencio**: `router.compactar` jamás
  llegó a ejecutarse en ninguna fase de ningún caso, y cada fase degradaba
  al resumen crudo sin ningún aviso en la auditoría. Un except genérico
  convirtió un bug de ligado en una característica fantasma: la plataforma
  "funcionaba" y el presupuesto de tokens pagaba el sobrecoste sin que
  nadie pudiera verlo.
- **Fix**: `import json` al frente del módulo (comentado). La compactación
  vuelve a ser ejecutable y el `except` recupera su papel original:
  red de seguridad ante fallos *reales* del router, no ante errores de
  programación propios.

## Guarda sistémica (la lección de la ronda)

Los tres defectos comparten raíz: **nombres cargados que nadie definió ni
importó**, invisibles para `py_compile`, para la importación perezosa de
los módulos y para los tests que no pisan el camino con datos reales.

`tests/test_z3_sesion6.py::test_pyflakes_sin_nombres_indefinidos` ejecuta
pyflakes (si está disponible en el entorno de test; `pytest.importorskip`)
sobre **todo** el Python de la plataforma (orchestrator, agents,
integraciones, servidores_mcp, lab) y falla ante cualquier `undefined
name`. Los avisos de estilo (variables sin usar, redefiniciones) no
fallan: hay sondas estructurales deliberadas. Con esto, la clase de
defecto F34/F35/F36 no puede reincidir sin que la suite la detecte.

## Verificación

- `tests/test_z3_sesion6.py` — 5 tests:
  1. `test_f34_asrep_sin_nameerror_con_cuentas`: con impacket/pyasn1
     simulados en `sys.modules` y LDAP enumerando una cuenta sin preauth,
     `asrep()` completa la corrida (conectado=True, KDC simulado caído →
     errores_honestos) sin excepción.
  2. `test_f34_asrep_sin_cuentas_sigue_siendo_honesto`: el camino sin
     cuentas conserva su contrato honesto (guarda del fix).
  3. `test_f35_dcsync_sin_nombre_username_en_ast`: análisis AST de
     `dcsync()` — cualquier carga del nombre `username` hace fallar el
     test (el AST excluye comentarios por diseño).
  4. `test_f36_graph_expone_json`: el módulo expone el `json` real.
  5. `test_pyflakes_sin_nombres_indefinidos`: guarda sistémica.
- **Validación anti-falso-positivo**: con los fixes retirados (stash) los
  tests 1, 3, 4 y 5 fallan exactamente como deben; restaurados, pasan.
  Durante la construcción se detectó y corrigió una versión vacua de la
  guarda (uso de `pyflakes.api.check` en lugar de `checkPath`: la ruta
  se compilaba como código y no detectaba nada —la lección se aplicó a sí
  misma antes de entregar).
- **Suite completa**: `pytest tests/` → `10 failed, 506 passed, 8
  skipped`. Los 10 fallos son los preexistentes y documentados desde la
  sesión 5 (`ModuleNotFoundError: No module named 'yara'`, dependencia
  opcional no instalada en la máquina de auditoría; mismos tests, misma
  causa). Cero regresiones. 506 = 491 (base sesión 5) + 5 (esta ronda)
  + 10 (ronda 5 de z2, commit `f0967c7`).

## Superficie revisada sin hallazgos (constancia)

- **Consola Next.js**: proxy `/api/orchestrator/*` (guardia de segmentos
  `.`/`..`, XFF último salto, transmisión binaria y SSE), puente IA
  (token 0600, comparación en tiempo constante, 503/502 honestos) y
  `instrumentation.ts` (single-flight del bootstrap, token puente y clave
  de custodia generados, resolución de intérprete probando candidatos).
- **guardrails.py**: boundary completo — catálogo de riesgo con
  wildcard de destructivas, kill switch, decisión humana previa por hash
  exacto de tool+args, scope con exclusiones primero, CIDRs tolerantes,
  ventana horaria fail-closed (incluye cruce de medianoche), techo de
  ruido persistente con margen duro, aprobación de herramientas no
  catalogadas por menor privilegio, auditoría de cada veredicto.
- **ctem.py**: corridas con claim atómico del slot, delta honesto sin
  base comparable, timestamps naive autocurados, planificador tolerante a
  BDs corruptas.
- **Integraciones**: TLS verificado por defecto con opt-out explícito en
  MSF/Mythic/BloodHound/MISP (patrón compartido), Cypher parametrizado en
  `rutas.py`, techo de cortesía NVD, credenciales solo por entorno.
- **Lab**: MISP lab con techo de cuerpo, límite de `limit` y clave solo
  localhost; servidor lab sin superficie real.

## Pendiente para el equipo (sin cambios esta ronda)

- Purga del historial git (`filter-repo`) y rotación del secreto JWT de
  la `usuarios.db` histórica (F32, sesión 5) — sigue abierto.
- Rotación del PAT de GitHub usado para los push (expuesto en el chat).
