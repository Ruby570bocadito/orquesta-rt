# Sesión 7 — Confinamiento del arsenal de persistencia (F37)

**Fecha**: 2026-09-12 · **Agente**: z3 · **Base auditada**: main `0fc4e8b` (v27, tras ronda 7 de z2)

## Alcance de esta ronda

Séptima pasada sobre el código v27 con dos objetivos: (1) revisión profunda
de las superficies que las sesiones 1–6 dejaron con menor cobertura —
workflows de CI, scripts de instalación/supervisión, proxy de la consola,
puente IA, compose, Caddyfile — y (2) re-auditoría del arsenal de
persistencia con mentalidad de *threat model* del propio despliegue (¿qué
puede tocar realmente el endpoint en el host donde corre el orquestador?).

Revisado en esta sesión: `install.sh`, `start.sh`/`stop.sh`,
`scripts/dev-supervisor.sh`, `.github/workflows/ci.yml`, `docker-compose.yml`,
`Caddyfile`, `deploy/k8s/*.yaml`, proxy `src/app/api/orchestrator/[...path]`,
puente `src/app/api/ia/[[...ruta]]`, `src/instrumentation.ts`,
`lab/servidor_lab.py`, `orchestrator/persistencia.py` (lectura completa),
`orchestrator/api.py` (endpoints del arsenal + middleware + SSE),
`orchestrator/{busqueda,ctem,threatled,razonador,purpleteam,skills,
reporting,respaldo,webhook,sidecar,transportes,evasion}.py`,
`platform/.env.example` y el estado del índice git respecto de BDs.

## Hallazgo F37 — Persistencia del lab con `raiz` sin confinar (ALTO)

### Descripción

El endpoint `POST /api/engagements/{id}/arsenal/persistencia` acepta un
campo `raiz` libre (modelo `PeticionPersistencia`, máx. 253 chars) que
`persistencia.implantar()` solo sometía a dos comprobaciones:
`os.path.realpath()` y `os.path.isdir()`. Es decir: **cualquier directorio
existente del host que el proceso del orquestador pudiera escribir era un
destino válido**. El contrato documentado del módulo dice "implantación
REAL en el host del LABORATORIO (dentro del alcance del ROE: 127.0.0.1)" y
"raíz = HOME del usuario del lab", pero nada del código lo hacía cumplir.

### Impacto

Un operador autenticado (rol operador o superior, con la firma que exige
el boundary para `persistencia.implantar`) podía:

- `raiz=/root` (si el servicio corre como root, p. ej. en despliegues
  simples con `start.sh`) → implante en `/root/.bashrc` **más activación
  real**: `bash -i -c true` con `HOME=/root` ejecuta el bloque y toca el
  testigo — persistencia de comandos en el perfil de otra cuenta.
- `raiz=/home/usuario-ajeno` → clave SSH ed25519 propia añadida a
  `/home/usuario-ajeno/.ssh/authorized_keys` (el módulo genera el par y
  devuelve la privada en la respuesta): puerta trasera SSH material.
- `raiz=/etc` con `systemd_user` → unidad systemd escrita fuera del lab.

Agravante central: **el boundary no veía el destino real**. Los argumentos
evaluados eran `{"host": "127.0.0.1", "metodo": ..., "comando": ...}` —
la `raiz` viajaba fuera de la evaluación, de la aprobación y del registro
de auditoría. El operador firmaba (y el ROE cubría) "127.0.0.1", no la
ruta concreta donde caería el implante. Esto rompe el principio del
producto "la coincidencia de la firma es EXACTA (tool + argumentos)".

Defecto hermano (MEDIO, corregido en el mismo pase): el testigo de
activación se interpolaba **sin entrecomillar** en el bloque bashrc
(`echo $(date +%s) >> {testigo}`) — un hogar del lab con espacios en el
nombre partía la redirección y la activación daba falso negativo.

### Remediación (producción, mínima y compatible)

1. **Lista blanca de hogares del lab** (`persistencia.py`):
   - Nueva `_hogares_permitidos()`: lee `ORQUESTA_LAB_HOGARES` (rutas
     absolutas separadas por `:`); si no está definida, la lista es SOLO
     el `HOME` del usuario que ejecuta el orquestador — exactamente el
     comportamiento por defecto documentado del módulo.
   - Nueva `_raiz_confinada(raiz)`: la raíz **vacía/None** sigue
     significando "HOME del lab" (contrato previo, siempre autorizado);
     una raíz **explícita** debe resolver (realpath en ambos lados) al
     interior de un hogar de la lista. `..`, symlinks y enlaces
     alternativos no escapan: se resuelven antes de comparar.
2. Aplicado en los **cuatro** flujos: `implantar()` (rechaza ANTES de
   tocar nada), `verificar()` (también ejecuta shell y lee ficheros),
   `retirar()` (reescribe `.bashrc` y borra ficheros — la higiene no es
   excusa para salir del alcance) y `estado()` (lectura que expone
   presencia/hash del hogar consultado).
3. **Testigo entrecomillado** con `shlex.quote()` en `_implantar_bashrc`.
4. **El boundary ve el destino**: los tres endpoints del arsenal
   (`implantar`, `verificar`, `retirar`) incluyen ahora `"raiz"` en los
   argumentos que `motor.evaluar()` registra — la cola de aprobaciones
   muestra la ruta real y el ROE firmado cubre lo que de verdad se hace
   (la decisión exacta tool+argumentos del blueprint).
5. **Documentación**: `platform/.env.example` documenta
   `ORQUESTA_LAB_HOGARES` con su semántica y el aviso F37.

### Tests de regresión (`platform/tests/test_z3_sesion7.py`, 8 tests)

- Rechazo de raíz fuera del lab en `implantar`/`verificar`/`retirar`/
  `estado` (sin rastro en la raíz vetada).
- Semántica por defecto: sin env, solo el HOME del despliegue está
  autorizado; ruta ajena existente (`/etc`) rechazada.
- Hogar dedicado del lab vía `ORQUESTA_LAB_HOGARES` (multi-home) OK.
- **Traversal** (`..` hasta fuera) y **symlink** dentro del lab apuntando
  fuera: rechazados, sin escritura en el destino externo.
- Raíz inexistente sigue dando su error claro ("no existe en el host").
- Hogar con espacios: activación REAL del testigo (prueba del quoting).
- E2E por API: la aprobación pendiente expone `argumentos.raiz` con la
  ruta real; aprobada → ejecuta en el lab permitido; la variante con
  `raiz=/etc` pasa la firma del boundary y muere en el confinamiento con
  `estado: fallo` — sin tocar `/etc`.
- `tests/conftest.py`: fixture autouse `_hogares_lab_para_tests` declara
  el basetemp de pytest como lab autorizado (los tests de v20 que usan
  `tmp_path` siguen operando, ahora bajo el contrato explícito).

### Verificación

- Suite completa: **535 passed / 8 skipped / 0 failed** (la línea base
  preexistente era 8 fallos por `yara-python`/`ldap3` ausentes en la
  máquina de auditoría; instalados ambos y la suite completa queda en
  verde sin ninguna otra intervención).
- pyflakes limpio en los ficheros tocados (limpieza de `secrets`/
  `tempfile` muertos en `persistencia.py`, heredados).
- Contraste anti-falso-positivo: el flujo v20 `test_api_persistencia_
  flujo_completo_real` (implanta → activa → retira, tmp_path) sigue en
  verde, demostrando que el confinamiento no rompió el caso de uso
  legítimo del lab.

## Superficie revisada sin hallazgos nuevos (sesión 7)

- **CI (`ci.yml`)**: sin secretos, cache pip acotada a requirements;
  `bun install --frozen-lockfile`; sin `pull_request_target` ni inyección
  de nombres de rama/PR en `run:`.
- **install.sh / dev-supervisor.sh / stop.sh**: `set -euo pipefail`,
  rutas relativas a la raíz del repo, lockfile con verificación de zombie
  en /proc, rotación de log acotada. Sin curl|bash ni descargas.
- **docker-compose.yml**: API y vLLM solo en loopback (fijado en sesión
  1), lab en 127.0.0.1:8443, `no-new-privileges`, recursos limitados,
  skills/ROE read-only. **Caddyfile**: el transform de :81 eliminado en
  la sesión 1 sigue ausente; `X-Real-IP` fijado con `remote_host`.
- **Proxy consola → orquestador**: guardia `.`/`..` (sesión 4) intacta,
  reenvío binario sin re-decodificar, IP real del operador tomada del
  ÚLTIMO salto / `x-real-ip` (no suplantable), timeout 120 s salvo SSE.
- **Puente IA**: token persistido 0600, comparación en tiempo constante,
  401 honesto, sin fugas del token en errores (mensaje acotado a 200).
- **instrumentation.ts**: claves generadas y persistidas 0600, single-
  flight del bootstrap, resolución del intérprete probando candidatos,
  puerto con techo de espera. El `CLAVE_CASO_LEGADA` solo verifica
  evidencias antiguas (nunca firma nuevas) — correcto.
- **webhook.py**: veto de metadatos por IP literal + resolución DNS en
  alta y despacho (rebinding), firma HMAC sobre cuerpo crudo, cabeceras
  de idempotencia. Sin cambios necesarios.
- **busqueda.py / reporting.py / respaldo.py / ctem.py / threatled.py /
  razonador.py / navigator.py / cobertura_attack.py / purpleteam.py /
  sigma_valid.py**: SQL parametrizado, sin escrituras de fichero con
  nombres del cliente (engagement_id generado por servidor y guardia de
  ID en `_memoria_de`), YAML solo con `safe_load`, honestidad de deltas.
- **BDs fuera de git**: `platform/usuarios.db` no está en el índice
  (`git ls-files` limpio; `.gitignore` correcto tras F32). La **purga del
  historial git** sigue pendiente de decisión del equipo (F32).

## Estado acumulado

| ID | Severidad | Sesión | Estado |
|---|---|---|---|
| F37 | ALTO | 7 | Remediado (persistencia confinada a hogares del lab + raíz visible en el boundary + testigo entrecomillado) |
