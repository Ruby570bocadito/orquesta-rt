# Sesión 3 — 2026-09-12 · Tercera ronda: código v24, módulos de razonamiento/CTEM y endurecimiento transversal (commit base 11be212)

### Alcance revisado

Tres rondas de revisión sobre `main` actualizado a v24 (servidor MISP de
laboratorio + validación Sigma), que no existía cuando se hicieron las
sesiones 1-2, más los módulos del orquestador que ninguna sesión anterior
había cubierto a fondo:

- **Ronda 1 — código nuevo v24**: `platform/lab/servidor_misp_lab.py`
  (completo), `platform/orchestrator/sigma_valid.py` (completo), el endpoint
  nuevo `POST /api/engagements/{id}/sigma/validar`, los cambios de
  `purpleteam.py` (generador compartido `reglas_sigma_caso`, validación
  pre-entrega, `sigma/validacion.md`) y `platform/lab/docker-compose.lab.yml`.
- **Ronda 2 — módulos no auditados aún**: `copiloto.py`, `razonador.py`,
  `ctem.py`, `threatled.py`, `navigator.py`, `busqueda.py`, `state.py`,
  `reporting.py` (completos), y el conector real `integraciones/misp.py`
  contrastado con el servidor de lab.
- **Ronda 3 — superficie transversal**: inventario completo de rutas API
  FUERA del patrón `/api/engagements/{id}` (la clase de BOLA corregida en la
  sesión 1) para verificar aislamiento tenant y RBAC; `skills.py` (path
  traversal); `docker-compose.yml` y `docker-compose.lab.yml` (puertos
  publicados).

Lo que se revisó y quedó BIEN (sin cambios, constancia para futuras rondas):

- `sigma_valid.py`: usa `yaml.safe_load` (nunca `yaml.load`), nunca lanza
  (los problemas de parseo SON el resultado), regex lineales sin ReDoS,
  higiene de tags correcta (`strip()` antes de validar evita el truco de
  `$`/salto de línea en el ancla).
- Endpoint Sigma v24 en `api.py`: POST → exige RBAC nivel 2 por middleware;
  la ruta casa con `_RE_ENGAGEMENT` → aislamiento multi-tenant aplicado;
  acción auditada `caso.sigma_validar`. Sin bypass.
- `copiloto.py`: sin ejecución, sugerencias acotadas (confianza clampeada,
  truncados), contexto solo con datos reales del caso; `razonador.py`:
  pasos del plan IA validados contra el catálogo REAL de transportes (lo
  inventado se descarta y se audita), trazas con hash.
- `ctem.py`: SQL 100% parametrizado, intervalos acotados (1-720 h),
  corridas atómicas en un commit, fallos de una BD no detienen a las demás.
- `threatled.py` / `navigator.py` / `busqueda.py` / `state.py`: datos
  validados contra patrones ATT&CK, sin entradas de red, sin riesgos.
- `skills.ver_skill()`: la búsqueda es sobre el índice pre-construido
  (dict en memoria), NO sobre rutas del cliente → sin path traversal.
- `busqueda.py`: único detalle estético: accede a `memoria._conn` (privado)
  para los resúmenes de fase; sin impacto de seguridad.

---

### Hallazgos remediados en esta sesión

#### F17 · El informe markdown nunca incluía el mapeo MITRE ATT&CK — MEDIO (bug funcional)
- **Dónde:** `reporting.construir_informe` (informe markdown, sección 3).
- **Qué pasaba:** el código hacía `h.get("tecnica")`, pero la columna real de
  la BD y del dict de hallazgos es `tecnica_mitre` (la versión HTML sí usa la
  clave correcta). Resultado: el entregable markdown — el que se convierte a
  DOCX/PDF para el cliente — perdía SILENCIOSAMENTE el mapeo ATT&CK de cada
  hallazgo; informe e HTML contradecíanse.
- **Solución aplicada:** clave correcta `tecnica_mitre` + comentario que
  documenta la invarianta (informe y HTML deben decir lo mismo). Test de
  regresión que construye un informe real y afirma la línea
  `**MITRE ATT&CK:** \`T1558.003\``.

#### F18 · MISP de lab: lectura de cuerpo sin límite (DoS por memoria) — MEDIO
- **Dónde:** `servidor_misp_lab.py`, `do_POST` (`self.rfile.read(longitud)`).
- **Qué pasaba:** la Content-Length de la petición se leía sin techo: un
  cliente con cabecera de gigas monolitizaba memoria en el host antes de que
  cualquier lógica pudiera rechazar nada. El servidor escucha en loopback por
  defecto, pero en Docker se publica a la red del lab — y "es un lab" no
  significa "acepto OOM" (además el servicio puede acabar en despliegues de
  demostración con más exposición).
- **Solución aplicada:** techo duro `MAX_CUERPO_BYTES = 5 MB` verificado
  ANTES de leer el cuerpo → `413` explícito; `Content-Length` no numérica →
  `400` limpio. Test con socket crudo que envía la cabecera desbordada SIN
  cuerpo y afirma el 413.

#### F19 · MISP de lab: `int()` sin capturar mataban la hebra — MEDIO (robustez/DoS)
- **Dónde:** `_attrs_rest` / `_events_rest` (`limit`) y `_events_add`
  (`threat_level_id`, `analysis`).
- **Qué pasaba:** cualquier parámetro no numérico (`limit: "diezmil"`,
  `threat_level_id: "alta"`) lanzaba `ValueError` SIN capturar dentro del
  manejador: `ThreadingHTTPServer` sobrevive pero la hebra de esa petición
  moría sin enviar respuesta (cliente con timeout y sin diagnóstico;
  vector de agotamiento barato repitiendo la petición).
- **Solución aplicada:** helper `_entero_seguro(valor, defecto, minimo,
  maximo)` que nunca lanza: `limit` acotado a 1-10.000, `threat_level_id`
  al rango oficial MISP 1-4 y `analysis` 0-2 (defecto ante basura). Además
  el despacho de `do_GET`/`do_POST` va dentro de try/except que responde
  `500` JSON en vez de dejar la conexión muerta. Test: parámetros basura →
  200 con valores acotados y el servidor sigue sirviendo.

#### F20 · Comparación de la clave API no en tiempo constante — BAJO
- **Dónde:** `servidor_misp_lab.py`, `_autorizado()` (`==` nativo).
- **Qué pasaba:** la comparación `==` de cadenas cortocircuita en el primer
  byte distinto: filtraba por tiempo el prefijo correcto de la clave. En un
  servicio de lab el riesgo es teórico (clave por defecto pública, red
  aislada), pero la corrección es gratuita y evita que el patrón migre a
  producción por copia.
- **Solución aplicada:** `hmac.compare_digest` sobre bytes de la clave
  enviada vs. la configurada. Test de comportamiento preservado: clave
  errónea → 403, clave correcta → 200.

#### F21 · Persistencia de estado no atómica (estado corrupto al morir) — BAJO
- **Dónde:** `servidor_misp_lab.py`, `_guardar_estado()`.
- **Qué pasaba:** `write_text()` directo sobre el JSON de estado: si el
  proceso moría a mitad de escritura, el fichero quedaba truncado y el
  arranque siguiente lo descartaba ENTERO ("estado corrupto: se reinicia con
  la semilla") — pérdida silenciosa de los eventos exportados por el
  operador.
- **Solución aplicada:** escritura atómica: `NamedTemporaryFile` en el mismo
  directorio + `flush` + `fsync` + `os.replace` (atómico en POSIX). El
  estado queda o el anterior o el nuevo, nunca un JSON partido. Test:
  guardado real en tmp_path, JSON válido en disco y cero `.tmp` residuales.

#### F22 · Puertos del despliegue publicados en 0.0.0.0 — BAJO (endurecimiento)
- **Dónde:** `docker-compose.lab.yml` (lab-misp `8444:9000`, lab-objetivo
  `8443:443` y `8080:80`) y `docker-compose.yml` (vllm `8001:8000`,
  lab-objetivo `8443:443`).
- **Qué pasaba:** los binds por defecto publican en TODAS las interfaces del
  host. Casos sensibles: el MISP de lab acepta escritura de intel con la
  clave por defecto débil `clave-lab-misp`, y **vLLM no tiene autenticación
  alguna** (cualquier equipo de la red consumía el LLM local y era objetivo
  de SSRF interno, tal como se documentó en la sesión 1).
- **Solución aplicada:** todos los puertos publicados solo en loopback
  (`127.0.0.1:...`), mismo criterio que el orquestador desde la sesión 1;
  comentarios inline con la forma legítima de exponerlos (clave nueva ANTES
  de abrir bind, túnel SSH/ACL para compartir el lab). La conectividad
  backend↔lab y backend↔vLLM no cambia: sigue siendo por la red docker
  (`lab-misp:9000`, `vllm:8000`) o por loopback desde el host.

#### F23 · Colisiones de nombres en el paquete purple (ZIP y validación) — BAJO (bug)
- **Dónde:** `purpleteam.construir_paquete_purple`.
- **Qué pasaba:** el nombre del fichero Sigma es `{tecnica}-{slug(titulo)}.yml`.
  Dos hallazgos distintos pueden compartir técnica y slug (mismo título;
  activo distinto evita el dedup de memoria): el ZIP resultante contenía dos
  entradas con el MISMO nombre (ambiguo para el cliente) y el dict de
  validación perdía una de las reglas — el informe decía "1 de 1" con 2
  ficheros dentro.
- **Solución aplicada:** nuevo `_nombres_sigma_unicos()` — desambiguación
  estable con sufijo `-2`, `-3`… compartida por la validación y por el
  bucle de escritura del ZIP (el fichero y la fila del veredicto hablan
  SIEMPRE del mismo hallazgo). Tests: helper con colisión y E2E construyendo
  el ZIP real de un caso con dos hallazgos colisionados (2 ficheros únicos,
  `sigma_validas=2`).

#### F24 · Errores duplicados en el veredicto Sigma — BAJO (higiene)
- **Dónde:** `sigma_valid._extraer_identificadores`.
- **Qué pasaba:** una condición como `falta and falta` devolvía el nombre dos
  veces → dos errores idénticos en el veredicto (ruido en `validacion.md` y
  en la consola).
- **Solución aplicada:** dedup preservando orden (`vistos`). Test: un solo
  error para la selección inexistente repetida.

---

### Verificación

- Nuevos tests de regresión `platform/tests/test_z3_sesion3.py` (8 casos,
  uno por fix): F17 informe markdown con ATT&CK; F18 413 con socket crudo;
  F19 parámetros basura acotados y servidor vivo; F20 403/200 por clave;
  F21 persistencia atómica sin temporales; F23 helper de nombres únicos +
  ZIP E2E sin duplicados; F24 un solo error. → **8/8 en verde**.
- Regresión sobre la suite v24 completa: **19/19** en verde (el servidor de
  lab sigue hablando el protocolo real con el conector oficial intacto).
- Suite completa: `pytest tests/` → **329 passed, 8 skipped, 10 failed** —
  los 10 fallos son los mismos de SIEMPRE del entorno de auditoría (módulos
  opcionales `yara`/`ldap3` no instalados; mismos nombres que las sesiones 1
  y 2 confirmaron idénticos sobre el commit base). **Cero regresiones.**
- `py_compile` de los 4 ficheros Python tocados y `yaml.safe_load` de los 2
  compose: OK.

### Ficheros tocados en esta sesión

| Fichero | Cambio |
|---|---|
| `platform/orchestrator/reporting.py` | F17: clave `tecnica_mitre` en el informe markdown |
| `platform/lab/servidor_misp_lab.py` | F18-F21: techo de cuerpo 413, `_entero_seguro`, `compare_digest`, persistencia atómica, guardia 500 |
| `platform/lab/docker-compose.lab.yml` | F22: binds solo loopback (misp y objetivo) |
| `docker-compose.yml` | F22: binds solo loopback (vllm y objetivo del perfil lab) |
| `platform/orchestrator/purpleteam.py` | F23: `_nombres_sigma_unicos()` compartido validación/ZIP |
| `platform/orchestrator/sigma_valid.py` | F24: dedup de identificadores |
| `platform/tests/test_z3_sesion3.py` | NUEVO: 8 tests de regresión |
| `docs/agentes/agente-z3/` | NUEVO: esta carpeta con README + auditorías de las 3 sesiones |
| `docs/agentes/z3.md` | convertido en puntero hacia `agente-z3/` (compatibilidad de referencias) |
| `worklog.md` | registro de la ronda |

### Propuestas para la siguiente ronda

- `busqueda.py`: exponer un método público de memoria para los resúmenes de
  fase y eliminar el acceso a `memoria._conn` (higiene, no seguridad).
- JWT en localStorage → cookie httpOnly + CSRF (pendiente desde sesión 1).
- CI: añadir `pip install yara ldap3` al job de tests para que la suite sea
  100% verde en el entorno de integración y los fallos de entorno dejen de
  enmascarar regresiones.
- Considerar `bandit`/`pip-audit` en CI como barrido automático entre
  auditorías manuales.
