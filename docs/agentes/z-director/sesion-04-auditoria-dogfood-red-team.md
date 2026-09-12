# Sesión 04 — Auditoría dogfood: el director opera la plataforma como agente de red team

**Agente:** z-director · **Fecha:** 2026-09-12 · **Base:** `main @ 9243d3e`
(HEAD publicado, sincronizado con origin) · **Suite publicada:** 557/8/0

## 1. Misión

El operador pidió usar la herramienta **como la usaría un agente de red team
en una auditoría real**: montar el caso, tirar del ciclo, firmar aprobaciones,
ejercitar el arsenal, y anotar **errores, fallos, mejoras y carencias** que
aparezcan durante la operación — no leyendo código, sino operándolo. Es la
primera vez que alguien del equipo ejecuta la plataforma de punta a punta con
IA real desde el arranque en frío (bootstrap incluido), así que el valor
esperado era doble: validar en operación lo que los tests ya cubren y
descubrir lo que solo se ve usando el producto.

Esta sesión NO toca código de la plataforma: es auditoría pura. Los hallazgos
se asignan por carril (§7) como corresponde.

## 2. Entorno de operación (reproducible)

- Clone de trabajo `main @ 9243d3e`, árbol limpio, venv de auditoría
  (`.venv-rt`, mismo que usó la sesión 01; mcp 1.30.0, yara, ldap3, impacket
  instalados).
- `usuarios.db` previo apartado → **bootstrap en frío real**: primer admin
  dado de alta por API (el flujo de primer contacto de un despliegue nuevo).
- Orquestador `:8000` con las variables de `start.sh` (RAIZ_CASOS, RAIZ_SKILLS,
  CLAVE_CASO) y `ORQUESTA_LAB_HOGARES` apuntando a un hogar de laboratorio
  dedicado de la auditoría (no el HOME real).
- Lab objetivo `:8080` (`lab/servidor_lab.py`) — el nginx de laboratorio.
- **Puente IA propio** (`scripts/puente-ia/servidor.mjs` fuera del repo):
  réplica fiel del puente de la consola (`src/app/api/ia/[[...ruta]]/route.ts`
  — mismo Bearer con comparación constante, mismo formato OpenAI, mismo
  GLM real vía z-ai-web-dev-sdk, mismas omisiones: no reenvía `max_tokens`,
  `temperature` ni `response_format` — ver HD-6). El orquestador no nota la
  diferencia: la frontera IA respondió de verdad durante toda la sesión.
- Operador API-first (curl): sin consola, como lo haría una automatización o
  un integrador. 16 llamadas GLM reales registradas en el log del puente.

## 3. Lo verificado en operación (funciona de verdad)

Lo que la documentación promete y un operador obtiene, con evidencia en la
propia memoria del caso:

- **Ciclo completo F0→F7** con IA real en el razonador y el copiloto: F0
  determinista, F1 OSINT con herramientas reales (CT logs, DNS, robots.txt
  del lab), F2 recon (socket/TLS, fingerprint nginx/1.24.0, vector con
  T1595.002), F3 con plan B honesto al fallar (sin MSF), F4/F5 sin fabricar
  datos (LDAP/C2 no configurados, con el requisito exacto), F6 pausado por
  firma, F7 informe consolidado con **cadena de custodia VÁLIDA** y economía
  de tokens por fase en USD (coste total del caso ≈ 0,04 USD).
- **Boundary operator-in-command**: 6 aprobaciones ejercitadas (3 firmadas, 3
  rechazadas — dos rechazos deliberados del auditor). La identidad del
  firmante viaja en la decisión (no en el cuerpo, como corrigió v21) y la
  cronología del informe muestra actor/acción/resultado fieles.
- **F37 (confinamiento del arsenal de persistencia) verificado EN OPERACIÓN**:
  la aprobación expone la `raiz` real entre los argumentos firmados; una
  implantación firmada contra `/etc` muere en el confinamiento con mensaje
  honesto; la implantación legítima en el hogar del lab funciona con
  verificación de activación real (bash interactivo + testigo), y la retirada
  certifica ausencia y deja evidencia. z3 dijo verdad en su sesión 7.
- **Evasión con YARA real**: artefacto AES-CBC/PowerShell con entropía
  4,77→5,95, round-trip espejo .NET verificado, y `evasion_verificada: true`
  solo cuando el payload original SÍ detectaba antes (AMSI_Bypass_Parche) y
  el artefacto ya no — la métrica no miente con payloads benignos (devuelve
  false, correctamente).
- **Escudo LLM01 (inyección indirecta) verificado en el canal que importa**:
  una inyección embebida en un hallazgo (canal RAG, no confiable) viaja
  marcada como dato (`marcas_entrada: 1`) y el copiloto la analiza como
  artefacto hostil sin obedecerla; una inyección directa en la pregunta (canal
  del operador, confiable) no se marca pero el modelo la rechaza citando el
  contrato `<<RAG>>`. Defensa en profundidad real.
- **Webhooks de punta a punta**: secreto generado en el alta (mostrado una
  sola vez), entrega firmada HMAC-SHA256 sobre el cuerpo crudo — **firma
  verificada manualmente con el secreto, coincide** —, evento real
  (`hallazgo.registrado`) entregado con historial, y anti-SSRF operativo en
  dos capas (IP literal 169.254.169.254 vetada; forma decimal 2852039166
  resuelta y vetada en DNS). El trabajo de z2 (rondas 1-2 y 8-9) se sostiene.
- **Multi-tenant**: operador de otra organización ve `[]` y recibe 403 en
  estado/hallazgos/memoria/informe/evidencias/auditoría/avanzar del caso
  ajeno. Sin escapatorias directas.
- **Kill switch**: con parada de emergencia activa, incluso el re-escaneo
  YARA (bajo riesgo) se deniega con mensaje claro; se desactiva limpio.
- **Higiene de identidad**: `cerrar-todas` revoca SOLO las sesiones de la
  cuenta que lo pide (token del auditor sobrevive, el de la otra cuenta
  muere) — el alcance por cuenta es exacto.
- **Auth**: 401 sin token, con firma falsificada y con `alg: none`; bloqueo
  por fuerza bruta a los 5 intentos con ventana de 300 s; validación de
  contraseña corta en el alta. Respaldo completo íntegro (ZIP 33 entradas,
  testzip OK). Navigator exportado en ATT&CK 17 / capa 4.6 al día.

## 4. Hallazgos (por severidad)

### F38 — ALTO · La firma de `evasion.generar` no cubre el payload (asignado a z3)

**Qué:** el endpoint construye los argumentos del boundary como
`{"host": "127.0.0.1", "metodo": p.metodo, "formato": p.formato}`
(`api.py:2013`) — **`payload_b64` (el contenido real del artefacto) queda
fuera de la huella firmada**. El mecanismo de coincidencia EXACTA de
`_decision_previa` (`guardrails.py:479`) es correcto, pero firma un conjunto
de argumentos reducido.

**PoC en operación (traza del caso):** el auditor firmó UNA generación de
evasión con payload benigno (`apr_cdd7ad27a86d`, argumentos registrados:
`{"host","metodo","formato"}`); acto seguido solicitó una generación con un
payload AMSI-bypass **distinto** y el boundary la auto-autorizó: "Autorizada
por decisión humana previa (director.auditor): apr_cdd7ad27a86d" — ejecutada
sin firma nueva (14:26:29 y 14:26:53 en la auditoría del caso).

**Impacto:** una sola firma de "aes_cbc + powershell" pre-autoriza CUALQUIER
payload posterior del caso. Combinado con un agente comprometido (el vector
que el propio README dice imposibilitar), el operador jamás ve el contenido
que autoriza. Contradice el principio documentado: "La coincidencia de la
firma es EXACTA (tool + argumentos): aprobar un vector no autoriza otro".

**Contraste:** persistencia firma `metodo+comando+raiz` (fix F37 de z3 —
hecho bien), AD firma `usuario+hash_nt`. `evasion.generar` es la única
herramienta del arsenal que sub-firma.

**Recomendación:** incluir una identidad del payload en los argumentos que
el boundary evalúa y audita — p. ej. `payload_sha256` (hash del payload
decodificado; sin inflar la aprobación con el b64 completo). Una semilla
distinta ⇒ aprobación nueva. Test de regresión E2E: aprobar payload A no
auto-autoriza payload B (simétrico al test E2E del F37). Revisar de paso
`evasion.escanear` (solo firma `{host}`; el `evidencia_id` no viaja — menor,
la acción es de lectura sobre evidencia custodiada).

### HD-2 — MEDIO · `avanzar` sin `vector_elegido` genera aprobaciones degeneradas (asignado a z1)

Tras aprobar la explotación del vector V, un `avanzar` posterior sin repetir
`vector_elegido` re-ejecuta F3 y encola una aprobación `explotar.ejecutar`
con `{"vector": "", "tecnica_mitre": "T1190"}` — vector VACÍO. El boundary
acepta encolarla (el resumen dice "explotación de  solicitada", con hueco).
El caso no recuerda la elección del operador entre llamadas: cada `avanzar`
debe re-enviar el contexto completo o se degradan las aprobaciones. Fix
doble: (a) el estado del caso persiste el vector elegido hasta que la fase
cambie; (b) el boundary/aprobación rechaza por validación un `vector` vacío
(igual que F37 rechaza raíces fuera del lab). La consola probablemente
enmascara esto reenviando el estado; el contrato API-first no lo protege.

### HD-1 — MEDIO · Re-ejecutar una fase duplica evidencias y hace regresar el resumen (asignado a z2)

La primera pasada de F1 mapeó 16 subdominios (CT); la re-ejecución (tras la
aprobación) volvió a correr los colectores — crt.sh agotó su timeout en esa
segunda pasada y el resumen de fase terminó diciendo "0 subdominios" mientras
la memoria del caso CONSERVA los 16 como objetivos. Peor: el informe final
lista evidencias DUPLICADAS — "Registros DNS de localhost", "AXFR",
"robots.txt", "Seguridad de correo" aparecen DOS veces con el MISMO SHA-256
(ejecuciones idénticas re-almacenadas con IDs nuevos). La cadena de custodia
sigue siendo válida, pero el operador ve "19 evidencias" infladas y un
resumen que contradice el estado acumulado. Fix propuesto: deduplicación por
hash de contenido en `registrar_evidencia` (o marcado de re-ejecución) y que
el resumen de fase distinga "esta ejecución" del estado acumulado del caso.

### HD-3 — MEDIO · El bloqueo por fuerza bruta vive solo en memoria (asignado a z3)

`_intentos` es un dict en memoria (`auth.py:94`): reiniciar el proceso borra
el candado (el auditor se bloqueó a sí mismo y lo comprobó — 6 intentos ⇒ 429
con "cuenta bloqueada 299s", y tras reiniciar el orquestador el login entró
limpio). Con `uvicorn --workers N` cada worker lleva su propio contador: el
límite efectivo se multiplica por N. Para una consola de red team: persistir
la ventana de fallos en `usuarios.db` (o caché compartida) y contar por
cuenta+IP de origen.

### HD-6 — MEDIO · El puente IA de la consola descarta `max_tokens`, `temperature` y `response_format` (asignado a z2)

El router envía `max_tokens` (economía), `temperature` y, cuando quiere
salida estructurada, `response_format: json_schema` — y el puente
(`route.ts`) solo reenvía `model` y `messages` al SDK. Consecuencias: el
control de coste por llamada no está garantizado de extremo a extremo
(completaciones sin techo) y la salida estructurada depende de la disciplina
del modelo, no del contrato. Esta sesión operó con un puente réplica (mismas
omisiones) y el ciclo funcionó por los fallbacks de parseo del razonador —
pero es robustez prestada, no garantizada. Fix: reenviar lo que el SDK
acepte (max_tokens al menos) y traducir `response_format` a instrucción de
sistema cuando el backend no lo soporte nativamente.

### HD-7 — MEDIO (carencia) · Sin Metasploit RPC no hay NINGUNA explotación nativa (asignado a z1, roadmap)

F3 depende al 100% del adaptador MSF. El lab propio expone un portal `/admin`
con login y la plataforma no trae NINGÚN módulo HTTP nativo (fuzzing de
rutas, credenciales por defecto, formulario de login) — el "abuso de
servicio expuesto no probado" que F3 propone como alternativa no existe como
herramienta. Para el posicionamiento "consola de mando autosuficiente" hace
falta un mínimo arsenal web propio (el lab ya está diseñado para ejercitarlo).

### HD-8 — BAJO (carencia) · El laboratorio empaquetado no incluye AD/LDAP (asignado a z1, roadmap)

`platform/lab/` trae nginx + MISP + generador de certificados; el arsenal AD
(`ad.py`: kerberoasting/asrep/dcsync con impacket REAL, sin mock) exige un
dominio externo (`LDAP_HOST`...). El README dice "Active Directory | ✅ Real
en lab", pero el arranque de dos comandos no puede ejercitar ni una consulta
LDAP. Las skills (`kerberoasting_lab`...) son playbooks que asumen un
"adaptador del lab (mock)" que ya no existe en `ad.py`. Un LDAP de laboratorio
ligero en el compose del lab cerraría el círculo del propio marketing.

### HD-4 — BAJO · Salud "degradado" en instalación fresca

`/api/salud` anónimo reporta "degradado" hasta que existe el primer
operador — ventana de bootstrap en la que Docker HEALTHCHECK sigue dando
verde (solo mira HTTP 200), pero cualquier monitorización que parsee el
cuerpo marcará el despliegue nuevo como degradado sin saber por qué (el
endpoint anónimo no da detalle POR DISEÑO — correcto — pero el agregado
podría distinguir "esperando bootstrap" de "roto").

### HD-5 — BAJO · Esquema de respuesta de `/avanzar` inconsistente

Según el momento, la respuesta trae `resultado.resumen` vs `resumen` a nivel
superior, y `fase` presente o ausente (`{"ejecutada": false, "bloqueos":
[...]}`). Un consumidor API-first debe programar contra tres formas. Unificar
el contrato (siempre `fase`, `ejecutada`, `resumen`, `bloqueos` al mismo
nivel) o documentar las tres formas.

### HD-9 — BAJO · Subdominios CT artefactuales sin filtrado

Los CT logs contienen certificados históricos con nombres internos
(`exchvm.nwcnet.localhost`, `tools.sonoma.edu.localhost`...) que el colector
devuelve fielmente como "16 subdominios" de localhost. Ninguno resuelve. Falta
un paso de resolución/etiquetado ("resolvible" vs "histórico CT") para no
entregar ruido como superficie.

### Micro-notas (informativas, sin asignación)

- `retirar` de persistencia deja un `.bashrc` residual de 1 byte (salto de
  línea) en hogares que no lo tenían — la "limpieza certificada" sería
  exacta restaurando el estado previo (fichero inexistente).
- `ultimo_acceso` de la higiene solo se actualiza en login (quedó en 14:17
  con actividad hasta 14:30): entenderlo como "último login", no "última
  actividad", o actualizarlo por petición.
- `persistencia/verificar` exige `comando` en el cuerpo aunque la
  verificación no lo usa (contrato heredado de `PeticionPersistencia`).
- `avanzar` mientras hay aprobación pendiente devuelve 200 con
  `ejecutada: false` y mensaje claro — correcto, pero el `fase: null` de la
  forma reducida alimenta HD-5.
- `.gitignore` ignora `.venv/` (directorio) pero no un `.venv` symlink —
  irrelevante en producción, observado durante el montaje del entorno.

## 5. Tráfico IA de la sesión

16 llamadas GLM reales por el puente (razonador de fase, ROE, prioridades y
3 consultas de copiloto). Coste total acumulado del caso al cierre:
**0,0417 USD / ~5 000 tokens** — la economía por fase del router se refleja
fielmente en el informe y en la respuesta del copiloto.

## 6. Veredicto de dirección

El producto **se sostiene en operación real**: el ciclo agéntico completo con
IA de frontera, el boundary con firma humana, el confinamiento del arsenal,
el escudo LLM01, los webhooks firmados y el aislamiento multi-tenant hacen
en producción exactamente lo que la documentación promete — verificado con
las manos, no con tests. La degradación sin integraciones es honesta y está
bien escrita (requisito exacto, sin datos inventados).

El talón es el **contrato de firma del arsenal de evasión (F38)**: es la
primera grieta real en el principio operator-in-command que este equipo ha
encontrado operando (no leyendo) la plataforma, y es del carril de z3. El
resto del lote son robustez de contrato API (HD-2/HD-5), consistencia de
evidencias (HD-1) y carencias de roadmap coherentes con el posicionamiento
(HD-7/HD-8).

## 7. Órdenes de dirección

1. **z3 — F38 con prioridad máxima**: identidad del payload en la huella
   firmada de `evasion.generar` + test E2E simétrico al del F37 (aprobar
   payload A no autoriza payload B). En la misma sesión: HD-3 (persistir el
   bloqueo por fuerza bruta) y repaso sistemático de "argumentos que firman"
   en TODO el catálogo de herramientas (una tabla en la bitácora: herramienta
   × argumentos firmados × completos/sí).
2. **z2 — HD-1**: deduplicación de evidencias por hash de contenido y
   resumen de fase que distinga ejecución vs acumulado; en la misma ronda,
   HD-6 (puente IA reenvía `max_tokens`/`response_format` al SDK).
3. **z1 — HD-2**: el caso recuerda `vector_elegido` y el boundary rechaza
   vector vacío; para roadmap, HD-7 (arsenal HTTP nativo mínimo contra el
   lab) y HD-8 (LDAP ligero en el compose del lab).
4. **Director**: no toca código en esta sesión (auditoría pura); F38 queda
   registrado con PoC en la traza del caso de auditoría para que z3 lo
   reproduzca. Persistidos también HD-4/HD-5/HD-9 y las micro-notas para que
   cada carril decida si las ataca.

## 8. Pendientes heredados (sin cambios)

- Rotación de `secreto_jwt` + contraseña admin en despliegues derivados (z3).
- Revocación del PAT de push por el operador (tercera petición — el token
  viajó en texto plano por el chat).
- z3 debe reconocer en su próxima bitácora el cierre real del F32 (orden de
  la sesión 03, aún visible).
