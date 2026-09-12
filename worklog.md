# Worklog del proyecto

---
Task ID: 1
Agent: main (Super Z)
Task: Construcción de la plataforma de red team orquestada por IA (núcleo M1 del blueprint) — backend Python + consola Next.js + lab simulado + despliegue

Work Log:
- Leído el blueprint completo (28 págs) y aclarado el alcance con el usuario: núcleo M1, consola web, router híbrido, lab simulado, módulos sensibles como adaptadores MCP sin payload, todo en español, SQLite, Docker Compose.
- Inicializado entorno fullstack (init-fullstack.sh).
- Backend Python en platform/: models.py (dominio + ROE máquina-legible), guardrails.py (boundary con 3 verificaciones: scope, política, riesgo), memory.py (SQLite por caso, auditoría append-only con triggers, cadena de custodia SHA-256+HMAC encadenada), router.py (router semántico local/frontera + presupuestos por fase + compaction), skills.py (SKILL.md con progressive disclosure), graph.py (OrquestadorEngagement con ciclo F0→cierre y bloqueo por aprobaciones), agents/fases.py (agentes F0-F7; F3-F6 vía adaptadores/mock), reporting.py (informe markdown español con ATT&CK), api.py (FastAPI), cli.py (typer), demo_seed.py (escenario ACME).
- Servidores MCP en platform/mcp/: recon (lista blanca de puertos + doble verificación de scope), evidencias (firma HMAC + export), OSINT pasivo (saneado anti-inyección), adaptador C2 MOCK (contrato para Sliver/Mythic).
- Extras: plantilla ROE YAML, skill kerberoasting_lab (educativa, lab-safe), 13 tests pytest, .env.example, pyproject, Dockerfile.
- Corregidos: placeholder roto en memory.py, import hack en guardrails/api, FK estrictas relajadas, placeholders INSERT (hallazgos 12 col, aprobaciones 17 col), verificar_cadena re-hashea contenido (anti-manipulación).
- Consola Next.js: tipos.ts (contrato), demo-engine.ts (motor de simulación con SHA-256 real del navegador, ramas plan B condicionadas a aprobación/rechazo, operator-in-command: el guion espera decisiones), 7 vistas (panel, pipeline, aprobaciones con diálogo de decisión, hallazgos, evidencias con verificación de cadena en vivo, coste IA con recharts, cronología), proxy API live en /api/orchestrator/*.
- Corregido lint (setState en efecto → suscripción zustand).
- Lab simulado (nginx ACME ficticio con robots.txt revelador), docker-compose.yml con perfiles lab/gpu(vLLM), Dockerfile.console, README raíz, docs/ARQUITECTURA.md, LICENSE propietaria.

Stage Summary:
- 13/13 tests del núcleo en verde; seed demo + informe generados correctamente con cadena de custodia válida (7 evidencias firmadas, 1 aprobación pendiente).
- Lint de la consola limpio; dev server 200 en /.
- Estructura: platform/ (núcleo Python cerrado), src/ (consola), docs/, docker-compose.yml, LICENSE.
- Módulos ofensivos: solo interfaces MCP + mocks de lab, sin payload operativo (decisión de seguridad documentada en README/LICENSE).

---
Task ID: 1-verification
Agent: main (Super Z)
Task: Verificación end-to-end con Agent Browser

Work Log:
- Abierta la consola en el navegador: render correcto, sin errores de consola ni runtime.
- Ejecutado el ciclo completo con decisiones mixtas: filtraciones RECHAZADA → F3 explotación web APROBADA (hallazgo crítico) → Kerberoasting RECHAZADA → plan B ruta HELPDESK → implante APROBADO → campaña APROBADA → F7 + cierre → "engagement completado".
- Bug detectado y corregido: los pasos condicionados a aprobaciones nunca creadas (ramas plan B no tomadas) quedaban en espera infinita; ahora se saltan.
- Verificadas vistas: panel (KPIs + feed), pipeline (stepper), aprobaciones (cola + decisiones), evidencias (cadena VÁLIDA, 7 firmas en vivo), coste IA (72% local / 28% frontera, caché 5/11), cronología (actores agente/humano/sistema).
- Responsive 390px verificado (cronología legible, header envuelve correctamente).
- Lint limpio; 13/13 tests del núcleo en verde tras los cambios.

Stage Summary:
- Verificación dorada completa: el ciclo F0→cierre funciona con ambos caminos (aprobado y rechazado) en cada punto de decisión del boundary.
- Capturas de la verificación en download/captura_*.png.

---
Task ID: 2
Agent: main (Super Z)
Task: Rediseño web completo — landing profesional minimalista + consola pulida (solicitud: "web profesional, no muy cargada, minimalista, moderna, animaciones y completa")

Work Log:
- Nuevo sistema de diseño en globals.css: fondo tinta #0a0a0d, superficies panel/raised, hairlines rgba-blanco, acento crimson #e5484d, tokens @theme de Tailwind 4 (ink/panel/raised/line/crimson), scrollbar fina, retícula bg-grid, glow, scanline, dot-live y respeto a prefers-reduced-motion.
- Landing nueva (src/components/landing/): nav fija de cristal con menú móvil (nav.tsx), hero con visual de consola en miniatura animado en bucle (pipeline activo rotativo, tarjeta de aprobación que alterna pendiente↔firmada, feed cíclico) y 4 cifras con contadores animados (hero.tsx), secciones capacidades (6 tarjetas), pipeline F0→F7 interactivo (selección con layoutId y panel de detalle IA/humano/artefacto), operator-in-command con tarjeta de decisión Kerberoasting, arquitectura en 4 capas + router LLM, seguridad (4 garantías) y CTA final (secciones.tsx, pagina.tsx).
- Consola rediseñada (consola/consola.tsx): sidebar fija (escritorio) con indicador activo animado, barra superior con engagement/controles, menú móvil 2 columnas, transiciones AnimatePresence entre vistas; eliminado encabezado.tsx (absorbido por el shell).
- Vistas reestilizadas con micro-animaciones (stagger, barras animadas, hover): panel, pipeline, aprobaciones (diálogos intactos), hallazgos, evidencias, coste (paleta recharts alineada) y cronología (puntos por actor/guardrail).
- Nueva vista "Memoria del caso" (consola/memoria.tsx): resumen compactado del contexto, contadores del almacén, estado de cifrado/custodia/retención, certificado de borrado y barras de presupuesto de tokens por fase.
- page.tsx: conmutador landing↔consola con store zustand + persistencia localStorage (cumple regla lint set-state-in-effect); layout.tsx actualizado a bg-ink.
- Correcciones de lint: import Radio en secciones.tsx; preferencia de vista movida a store externo.
- Verificación Agent Browser: landing completa (hero, capacidades, pipeline interactivo con clic F7 verificado, mando, arquitectura), consola (panel, pipeline, aprobaciones con flujo aprobar Y rechazar verificados con comentarios, hallazgos, evidencias con cadena VÁLIDA, memoria, coste, cronología), menú móvil, viewport 390px y 1440px, persistencia de vista tras reload, sin errores de consola ni runtime; lint limpio.

Stage Summary:
- Entregable: web dual (landing de producto + consola del operador) en la ruta única /, estética dark premium minimalista con acento crimson y animaciones framer-motion.
- El motor de demo ACME no se tocó: toda la lógica operator-in-command sigue verificada (13/13 tests del núcleo Python intactos).
- Capturas en download/verificacion/ (verif_*.png del rediseño + captura_*.png de la ronda anterior).

---
Task ID: 3
Agent: main (Super Z)
Task: Ronda de mejora continua — búsqueda de bugs, pulido de funciones existentes y nuevas funciones red team/pentesting/IA (solicitud: "sigue mejorando lo ya existente, busca bug, comprueba que todo funcione, pule todas las funciones y sigue añadiendo mejoras")

Work Log:
- Auditoría completa del código existente (motor demo, consola, vistas) antes de tocar nada: lint limpio, 13/13 tests Python, servidor 200.
- Bugs corregidos en el motor (demo-engine.ts): (1) `decidir()` ponía el engagement en "activa" aunque quedaran otras aprobaciones pendientes — ahora permanece en "espera_aprobacion" hasta resolver todas; (2) estado inicial del store incompleto tras añadir campos nuevos (error TS detectado con tsc); (3) `analitica.tsx` deducía la clase del modelo con `modelo.startsWith("qwen")` — ahora usa el campo `tipo` real del registro; (4) variable muerta `maxTecho` en memoria.tsx; (5) badge "demo" verde fijo incluso en pausa — ahora refleja pausa (ámbar) y parada (rojo).
- Motor ampliado: nueva capa de SUPERFICIE DE ATAQUE — slice `objetivos` (20 activos poblados a lo largo del guion F1→F6: dominio, subdominios CT logs, rutas robots.txt, host, servicios 443/445/3389, credenciales filtradas, rutas a DA, implante, buzones de campaña) con helper `objetivoActualizar` y `higieneObjetivos()` (al cierre, explotados/credenciales pasan a neutralizado con detalle de higiene).
- Ruido OPSEC acumulado: cada aprobación firmada suma su ruido estimado contra el techo del ROE (metrica nueva en el estado).
- Parada de emergencia (kill switch del ROE): acción `paradaEmergencia()` — detiene el guion, registra feed 🛑 y evento de auditoría con guardrail "denegar"; tras activarla Reanudar queda bloqueado y solo Reiniciar rearranca. AlternarPausa protegida.
- Nueva vista "Objetivos" (consola/objetivos.tsx): grid de activos con icono por tipo (dominio/host/servicio/credencial/ruta/activo_humano), badges de estado (descubierto/confirmado/riesgo/explotado/neutralizado), fase, técnica ATT&CK, filtro segmentado por estado y contador de severidad crítica.
- Exportación del informe (lib/informe.ts): generador Markdown desde el registro (ROE, resumen ejecutivo, hallazgos con MITRE y recomendaciones, superficie observada, decisiones del operador con comentarios, cadena de custodia con hashes, economía del token por modelo/fase, cronología completa) + descarga por Blob; botón "Informe" en la barra superior y acción en la paleta; verificado: descarga de 11,8 KB con 8 secciones (copia de muestra en download/verificacion/).
- Paleta de comandos (consola/paleta.tsx) con cmdk: Ctrl/Cmd+K global, 4 grupos (Navegación 9 vistas, Simulación pausa/turbo/reiniciar, Entregables exportar informe, Seguridad parada de emergencia); accesible también desde botón en sidebar y barra superior.
- Toasts (use-toast ya montado): aviso cuando el boundary crea una aprobación nueva, confirmación de cada decisión y toast final de engagement completado; suscripción zustand (sin setState en efecto, lint limpio).
- Filtros segmentados (ui.tsx `FiltroSegmentado` con pill animada layoutId): hallazgos por severidad, evidencias por tipo, cronología por actor, objetivos por estado — todos con contadores dinámicos.
- Botón copiar SHA-256 en evidencias con feedback Check 1,6 s; panel con barra de progreso del engagement (X de 9 fases) y medidor de ruido OPSEC vs techo con aviso "techo superado"; decisiones registradas ahora muestran fase y hora.
- Verificación Agent Browser (1440px y 390px): ciclo completo F0→cierre en turbo con 5 aprobaciones, higiene de cierre (3 neutralizados), paleta Ctrl+K, parada de emergencia con confirmación, exportación real del informe, filtros, copia de hash, toasts; sin errores de consola; lint y tsc limpios; 13/13 tests Python intactos.
- Capturas en download/verificacion/ (v3_*.png + informe de muestra).

Stage Summary:
- La consola pasa de 8 a 9 vistas (nueva Objetivos), con kill switch ROE, exportación de informe, paleta de comandos, toasts, filtros y métricas OPSEC — manteniendo operator-in-command intacto.
- Tres bugs reales corregidos (estado de fase con múltiples aprobaciones, estado inicial incompleto, clase de modelo por convención frágil) + pulido de UX en 6 vistas.

---
Task ID: 4
Agent: main (Super Z)
Task: "No quiero una página web como publicidad — proyecto serio, real, nada de simulaciones" → eliminación de la landing y del motor de demo; reconexión TOTAL de la consola al backend Python real con herramientas de I/O real.

Work Log:
- DIAGNÓSTICO: la consola funcionaba sobre demo-engine.ts (guion simulado en el navegador) y la raíz era una landing publicitaria; el núcleo Python real existía pero la API no conectaba transportes (fases sin herramientas) y graph.avanzar no respetaba espera_aprobacion.
- BACKEND REAL:
  * transportes.py NUEVO: herramientas reales acotadas al ROE — crt.sh (CT logs), robots.txt real, DNS (dnspython), http_probe (httpx), port_scan (socket, lista blanca), cert_info (SSL), tech_fingerprint, buscar_filtraciones (HIBP v3 con HIBP_API_KEY; sin clave → requisito documentado, sin datos inventados).
  * api.py: transportes_de(roe) conectado a _creador; endpoints nuevos: objetivos, parada_emergencia, roe (actualización auditada), memoria (estadísticas); /estado ampliado (objetivos+memoria+ruido ejecutado); /tokens devuelve registros crudos; PeticionCrear con ventana horaria y técnicas con aprobación.
  * memory.py: tabla objetivos + guardar/listar/actualizar (estado solo avanza), actualizar_roe, estadisticas_memoria, registros de uso de tokens.
  * models.py: Objetivo + TipoObjetivo/EstadoObjetivo; parada_emergencia=False por defecto.
  * fases.py: F1 registra dominios/subdominios DNS/CT/rutas robots como objetivos reales y respeta decisión previa del operador; F2 reordenado como recon real (puertos→servicios→HTTP probe por puerto→fingerprint→cert TLS) con hallazgo por cabeceras ausentes; F3 marca explotado sobre el activo real; cierre neutraliza explotados/riesgo y ya no pide firma vacía sin adaptador C2; fallos de herramienta no rompen la fase; borrador F0 deriva del ROE real.
  * guardrails.py: (0b) kill switch deniega toda tool call; (0c) decisión humana previa por EXACTA (hash tool+argumentos): aprobar el vector A no autoriza el vector B — validado en E2E con un vector duplicado que el boundary rechazó solo.
  * graph.py: avanzar respeta espera_aprobacion (no avanza el puntero; reanuda la fase tras la decisión), kill switch, reintento de fases bloqueadas, persiste certificado_borrado al cierre.
- BUGS DE NÚCLEO CORREGIDOS: fase5/fase6 desempaquetaban Veredicto como tupla (crash de F5 en live); objetivo C2 fuera de scope ("estacion-lab") → ahora propone host del ROE (el boundary lo denegó en vivo y quedó auditado).
- INFRA RESILIENTE: instrumentation.ts arranca uvicorn:8000 + lab:8080 como hijos de Next; proxy con auto-bootstrap y runtime nodejs; sidecar.py + guardián (doble-fork huérfano, lockfile) relanza la consola si el puerto 3000 muere — probado matando el dev server: resurrección automática en ~12 s.
- CONSOLA REAL (sin landing, sin demo): page.tsx = consola; eliminados components/landing y demo-engine; store.ts nuevo: cliente en vivo (sondeo 3 s) con casos/crearCaso/seleccionarCaso/avanzarFase/decidir/paradaEmergencia/informe del backend; 10 vistas; nueva vista Casos (crear engagement con ROE completo + lista); BarraSuperior real (Ejecutar fase con diálogo de contexto F0/F3/F6, Informe del backend, kill switch bidireccional, estado de conexión); Evidencias: verificación independiente REAL en navegador (SHA-256 del contenido + encadenado) + veredicto HMAC del backend (la clave nunca sale del servidor); Panel con cadena desde backend; Memoria con cifrado/tamaño reales.
- E2E VERIFICADO (agente navegador + API): caso "Intrusión externa — Lab ACME" (caso_14f0da440a) F0→cierre completo: crt.sh real (16 subdominios CT), DNS real (127.0.0.1), robots.txt real (/admin /gestion /privado → riesgo), port scan real (8080 abierto), HTTP probe real (cabeceras ausentes → hallazgo), aprobación de filtraciones APROBADA con reanudación correcta, explotación APROBADA + vector duplicado RECHAZADO por coincidencia exacta, kerberoasting RECHAZADO (camino denegado), C2 fuera de scope DENEGADO por el boundary, kill switch ACTIVADO/DESACTIVADO con bloqueo real de avanzar, informe backend 6,3 KB, 13 evidencias cadena VÁLIDA, 4 activos neutralizados en higiene, certificado de borrado persistido.
- VALIDACIÓN: 13/13 pytest, tsc limpio, eslint limpio, móvil 390px sin overflow horizontal, capturas en download/verificacion/real_*.png.

Stage Summary:
- La plataforma es ahora una herramienta operativa real: sin landing publicitaria, sin motor de simulación; consola ↔ backend Python en vivo con I/O real acotada al ROE, operator-in-command exacto y autorreparación del despliegue.
- Los módulos F3-F6 siguen siendo adaptadores de integración (contrato para Sliver/Mythic sin payload): no simulan resultados — sin adaptador conectado documentan el hecho en lugar de inventar éxito.

---
Task ID: 5
Agent: main (Super Z)
Task: Ronda v5 — eliminación del último mock (adaptador C2), integraciones REALES con APIs oficiales (Sliver gRPC, Mythic GraphQL, Metasploit MSG-RPC, LDAP, SMTP), nuevos transportes recon y vista Integraciones en consola.

Work Log:
- AUDITORÍA: detectado el único mock restante (platform/mcp/c2_adapter_server.py con MockTransporte e implantes ficticios) y datos ficticios en fase4_dominio_ad (rutas AD hardcodeadas "usuario.basico -> HELPDESK..."). Ambos violaban el mandato "nada de simulaciones".
- NUEVO PAQUETE platform/integraciones/ con clientes REALES de las APIs oficiales:
  * sliver.py — API gRPC oficial vía sliver-py (config por SLIVER_CONFIG del operador o SLIVER_HOST+SLIVER_TOKEN); estado/sesiones/beacons, tarea shell, retirar, implant_build vía API.
  * mythic.py — GraphQL oficial autenticado por MythicToken (MYTHIC_URL+MYTHIC_TOKEN); callbacks reales, createTask, kill callback, payloads.
  * metasploit.py — MSG-RPC oficial (msgpack sobre HTTP /api/1.1/) con auth.login→token; core.version, session.list, module.execute, shell/meterpreter_write, session.stop.
  * ldap.py — protocolo LDAP v3 (ldap3) contra el DC del alcance; enumeración resumen/usuarios/SPNs/grupos con credenciales bajo ROE.
  * smtp_envio.py — SMTP del equipo (STARTTLS) para envíos REALES de campañas autorizadas F6 con doble firma.
  * Regla de oro: sin configuración devuelven {"conectado": false, "error": "<requisito exacto>"} — jamás datos ficticios.
- TRANSPORTES NUEVOS (I/O real, acotados al ROE): osint.wayback (CDX del Internet Archive), recon.banner_grab (SSH/SMB/RDP), recon.reverse_dns (PTR), recon.http_methods (OPTIONS + métodos peligrosos), recon.dir_index (listados "Index of /"); c2.estado, c2.{sliver,mythic,msf}_{tarea,retirar}, explotar.ejecutar (MSF real con validación de RHOSTS contra el ROE), phishing.enviar_campana. 22 transportes registrados.
- GUARDRAILS: catálogo ampliado — c2.estado baja sin firma; toda tarea/retirada/explotación exige firma humana; ad.enumerar_ldap media con ventana.
- FASES REESCRITAS: F1 añade wayback (rutas históricas → objetivos riesgo); F2 añade banners (vector SSH real por versión), PTR, métodos HTTP peligrosos (hallazgo media) e índices de directorio (hallazgo alta); F3 ejecuta módulos MSF reales con modulo+opciones firmadas y plan B honesto ante error real; F4 SOLO rutas DA derivadas de SPNs reales enumerados por LDAP (sin LDAP → requisito documentado, cero rutas inventadas); F5 consulta C2 real, propone tarea whoami sobre agente activo concreto (firma) y registra la salida real; F6 doble firma (plantilla + envío con destinatarios explícitos) y envío SMTP real; cierre retira agentes reales de cada framework conectado (firma por retirada).
- API: /api/integraciones (estado real sin secretos), /api/integraciones/probar (prueba de conexión real: sliver/mythic/msf/ldap/smtp/crt_sh/wayback/hibp/llm_frontera/llm_local); PeticionAvanzar ampliado (modulo, opciones, destinatarios); router LLM con estado_backends() y probar_backend() (GET /models real).
- MCP: c2_adapter_server.py reescrito de cero como cliente de las integraciones reales (mock eliminado).
- BUGS CORREGIDOS: imports relativos ..integraciones rotos cuando orchestrator corre como paquete top-level (patrón try/except dual en transportes, fases, api); probar_integracion sin handlers para fuentes OSINT (400) → handlers reales crt_sh/wayback/hibp.
- CONSOLA: nueva vista Integraciones (4 grupos: C2, directorio/campañas, router IA, OSINT; tarjetas con estado real, servidor, botón Probar conexión con resultado honesto); store con integraciones + pruebasIntegracion; diálogo de fase ampliado (módulo MSF + RHOSTS en F3, destinatarios en F6); 11 vistas.
- DEPENDENCIAS: msgpack + ldap3 instalados y en requirements/pyproject; sliver-py documentado como opcional oficial.
- E2E VERIFICADO: caso caso_884327f918 "E2E integraciones reales v5" — ciclo F0→cierre completo: F1 wayback + HIBP honesto (sin clave), F2 con PTR real (127.0.0.1 → localhost.) + cabeceras ausentes, F3 aprobado → "sin adaptador de explotación" documentado + plan B, F4 sin LDAP → requisito documentado sin rutas inventadas, F5 sin C2 → requisitos exactos, F6 plantilla firmada + SMTP honesto, cierre con 4 activos neutralizados y certificado; cadena de custodia VÁLIDA (17 evidencias). Vista Integraciones probada en navegador (probar conexión → error real "backend frontera no configurado (falta API_FRONTERA_BASE...)"), móvil 390px sin overflow, navegación limpia de las 11 vistas sin errores de consola; 30/30 pytest; lint y tsc limpios. Capturas en download/verificacion/v5_*.png.

Stage Summary:
- Mandato "cero simulaciones" COMPLETADO al 100%: el último mock del repositorio fue eliminado; todas las capacidades ofensivas son ahora clientes reales de las APIs oficiales de Sliver/Mythic/Metasploit/LDAP/SMTP que el operador conecta a sus instancias autorizadas.
- La plataforma documenta requisitos con precisión en lugar de inventar resultados; sin infraestructura configurada, F3-F6 son honestos y auditables.

---
Task ID: 6
Agent: main (Super Z)
Task: Ronda v6 — "siguientes pasos y continua y actualiza todo y sigue puliendo más los procesos": autenticación real de operadores, eventos SSE en vivo, búsqueda BM25 en memoria, transportes AXFR/nmap, informe HTML y corrección de proceso (tests deterministas).

Work Log:
- CORRECCIÓN DE PROCESO: 2 tests fallaban por dependencia del reloj real (la ventana horaria del ROE denegaba fuera de 08:00-20:00). Añadido `momento` inyectable a MotorGuardrails.evaluar; tests actualizados con reloj fijo (lunes 10:30) y el test dual `test_boundary_enumerar_ldap_en_ventana` ahora verifica DENTRO y FUERA de ventana de forma determinista.
- AUTENTICACIÓN REAL (orchestrator/auth.py NUEVO): cuentas en usuarios.db (SQLite propio) con scrypt (n=2^14,r=8,p=1), roles admin/operador, JWT HS256 RFC 7519 propio (secreto persistido, exp 12h), bloqueo anti fuerza bruta (5 fallos→5min), cambio de contraseña. API middleware deny-by-default: todas las rutas exigen Bearer salvo /api/salud y /api/auth/{estado,login,registrar}. Bootstrap: primera cuenta = admin sin token; después solo admin. Identidad real en auditoría: decidir/parada/roe/crear/avanzar registran el usuario del JWT (el cuerpo ya no puede suplantar). 16 tests nuevos (test_auth.py) incluyendo suplantación bloqueada.
- PROXY (route.ts): reenvía Authorization; streaming SSE sin buffering ni timeout para /eventos.
- CONSOLA: nueva pantalla de acceso (acceso.tsx: bootstrap/login, animada, tema tinta), token en localStorage, api() con Bearer y manejo 401 (SesionExpirada → vuelve al acceso), chip de sesión con logout en la barra, early-return tras TODOS los hooks (reglas de hooks), estado estadoAuth con máquina completa.
- SSE EN VIVO: endpoint /api/engagements/{id}/eventos (deltas de auditoría por rowid, heartbeat, reciclaje 4 min); store consume con fetch+ReadableStream, fusiona eventos y refresca con tope 1,5 s; fallback a sondeo 3 s y reconexión automática; badge sidebar "en vivo · SSE/sondeo"; Pausar detiene SSE.
- BÚSQUEDA DE MEMORIA (orchestrator/busqueda.py NUEVO): BM25 Okapi puro (k1=1.5,b=0.75), tokenizador español tolerante a tildes con stopwords, indexa evidencias/hallazgos/objetivos/auditoría/aprobaciones/resúmenes; embeddings opcionales del backend LOCAL fusionados por RRF (el contenido nunca sale a la frontera); API /memoria/buscar + panel de búsqueda en vista Memoria con resultados animados. 8 tests (test_busqueda.py).
- TRANSPORTES NUEVOS (24 total): osint.zone_transfer (AXFR real con dnspython, hallazgo de exposición DNS si procede) y recon.nmap_servicios (nmap -sV subprocess, lista blanca, sin binario → requisito exacto). Integrados en F1/F2; catálogo boundary clasificado; 6 tests nuevos.
- INFORME HTML: construir_informe_html autocontenido e imprimible (CSS embebido, sin scripts, contenido escapado) con custodia completa y superficie observada; API formato=md|html; botón HTML en barra + paleta.
- BUGS CORREGIDOS: proxy sin Authorization (impedía auth), overflow móvil 78px en barra superior (botones informe ocultos <sm), selector `iniciado` perdido, verificación `alg` del JWT sobre el payload en vez de la cabecera, engagement_id faltante en documentos_de_caso, Insignia tono inválido "gris"→"slate".
- E2E VERIFICADO (navegador): bootstrap de admin real → login → caso "Intrusión externa — ronda v6" (caso_c8cf4f50a4) → F0 completa → F1 real pausa por boundary → aprobación con comentario firmada por identidad JWT → F1 reanudada y completada → F2 completa (hallazgo cabeceras real en localhost:8080) → búsqueda BM25 en vivo ("bm25 · 63 artefactos") → cronología con identidad ("por operador") → logout/login correctos → badge "EN VIVO · SSE" activo → móvil 390px sin overflow tras fix → consola sin errores tras recarga limpia. Smoke script scripts/smoke_v6.sh: 9/9 (bootstrap, 401 credenciales, JWT, caso, F0, BM25, SSE bytes, informe HTML 4,8 KB, 401 sin token).
- VALIDACIÓN FINAL: 59/59 pytest (30→59), eslint limpio, tsc limpio (src), docs/ARQUITECTURA.md §10 v6, README actualizado con flujo de acceso. Capturas v6_*.png en download/verificacion/.

Stage Summary:
- La plataforma gana el ciclo completo de seguridad de acceso: cuentas reales scrypt+JWT, deny-by-default, identidad firma en la auditoría; operador en tiempo real (SSE ~1,5 s) con degradación honesta; memoria del caso ahora RECUPERABLE (BM25+embeddings locales opcionales); dos capacidades de reconocimiento nuevas reales; entregable HTML para el cliente. Cero simulaciones: todo nuevo endpoint/tool genera requisitos exactos ante infraestructura ausente.

---
Task ID: 7
Agent: main (Super Z)
Task: Ronda v7 — "levanta un puerto y dame un enlace para probar; antes revisa qué mejorar, sigue puliendo cada función y añade más funciones, habilidades, mejoras, todo para producción y optimización".

Work Log:
- AUDITORÍA inicial: 59/59 tests, backend sano, consola viva. Detectados: avisos Edge Runtime (cosméticos), métodos duplicados al final de memory.py (bug de mantenimiento corregido), texto residual "lab simulado" en Objetivos (eliminado), y dos bugs funcionales durante E2E (ver abajo).
- PUENTE IA REAL (src/app/api/ia/[[...ruta]]/route.ts NUEVO): endpoint OpenAI-compatible (chat/completions + models) sobre z-ai-web-dev-sdk (GLM-4.6 real). Token interno generado por instrumentation.ts y persistido en db/puente-ia.token (0600, comparación en tiempo constante); instrumentation inyecta API_FRONTERA_BASE/CLAVE/MODELO al uvicorn. El RouterModelos del backend ahora prueba "conectado: true" contra el puente y el copiloto responde con GLM real y contabilidad de tokens (verificado: 987 tokens, $0.0053, 6 fuentes RAG).
- COPILOTO DEL CASO: orchestrator/copiloto.py NUEVO (contexto real del caso: ROE + fase + objetivos + hallazgos + pendientes + RAG BM25 de busqueda.py; tarea "analisis_caso" en router; límites: nunca ejecuta, señala el canal fase+aprobación). Endpoints config (GET/POST, deshabilitado por defecto, habilitación firmada en auditoría como decisión de perímetro) y consulta POST (auditada con pregunta truncada + tokens + modelo). Vista "Copiloto IA" en consola: conversación animada, fuentes citadas, tokens/coste, sugerencias por fase, diálogo de habilitación que explica la implicación de perímetro.
- EQUIPO (ADMIN): auth.py + cambiar_rol/restablecer_contrasena/contar_admins con protección de último admin, auto-bloqueo y desbloqueo por reset; endpoints /api/auth/rol y /api/auth/restablecer; vista "Equipo" (alta con rol, restablecimiento administrativo, baja con confirmaciones; no-admin ve aviso honesto).
- BUG 1 (E2E): /api/auth/registrar era ruta pública del middleware (bootstrap) → request.state sin identidad → alta admin SIEMPRE 403 tras el bootstrap. Corregido verificando el JWT explícito dentro del endpoint + test de regresión (incluye 403 anónimo).
- ENTREGABLES: GET /exportar (orquestart-caso/1 con cadena de custodia verificada y auditoría del evento), GET /hallazgos.csv (CSV real auditado), GET /objetivos/dif (diferencial real de superficie con normalización naive/UTC — bug detectado y corregido en E2E). Consola: botón CSV en Hallazgos, "Exportar custodia (JSON)" en paleta + consola.tsx.
- WEBHOOK REAL: orchestrator/webhook.py NUEVO (POST firmado X-Orquesta-Firma: sha256=HMAC con WEBHOOK_SECRETO, disparo en segundo plano al crear una aprobación, resultado auditable), "Probar conexión" honesto en /integraciones/probar, tarjeta nueva "Notificaciones del equipo" en la vista Integraciones; test con receptor HTTP local que verifica la firma HMAC exacta.
- 3 TRANSPORTES NUEVOS (26 total): recon.correos_seguridad (SPF/DMARC/DKIM por DNS TXT real, hallazgo de postura de correo en F1), osint.sitemap (rutas publicadas del propio objetivo, F1), recon.rutas_sensibles (exposición .git/.env/backups/server-status, hallazgo alto en F2). Clasificados en el catálogo del boundary (ruido/ventana) con doble verificación de scope; tests de scope sin red.
- OPTIMIZACIÓN/PRODUCCIÓN: GZipMiddleware en la API (informes/exportaciones), PRAGMA synchronous=NORMAL + WAL, índice idx_objetivos_descubrimiento, tabla config_caso (KV persistente), cabeceras de seguridad en next.config.ts (X-Frame-Options DENY, nosniff, Referrer-Policy, Permissions-Policy) y poweredByHeader off.
- E2E NAVEGADOR (Agent Browser, cuenta temporal "verificador" creada y eliminada): login → panel con 13 vistas → Copiloto: habilitación, consulta real con respuesta GLM, fuentes, tokens/coste → Equipo: alta real desde UI (falló por BUG 1 → fix → re-verificado ok) → Objetivos: diferencial calculado con 8 activos y desglose por tipo → Hallazgos: CSV descargado (archivo real en ~/Downloads) → Integraciones: puente frontera "conexión real establecida · glm-4.6", webhook con requisito honesto → móvil 390px sin overflow → consola sin errores de runtime. Capturas v7_*.png en download/verificacion/.
- VALIDACIÓN FINAL: 75/75 pytest (59→75), eslint limpio, tsc limpio en src/, smoke scripts/smoke_v7.sh 11/11 (salud, 401, JWT, regresión alta, 403 copiloto honesto, GLM real, custodia con cadena VÁLIDA, dif, CSV, puente conectado). README + docs/ARQUITECTURA.md §11 actualizados.

Stage Summary:
- La plataforma gafa su primer backend de IA REAL sin claves en código (puente GLM OpenAI-compatible con token interno) y con él el Copiloto del caso: análisis conversacional con RAG sobre la memoria del caso, habilitación consciente de perímetro y auditoría completa.
- Gestión admin de operadores completa con protección de último admin; dos bugs reales detectados en E2E (registrar 403 y dif naive/aware) corregidos con tests de regresión.
- Nuevos entregables (custodia JSON, CSV, dif de superficie), webhook firmado real, 3 transportes de recon nuevos y endurecimiento de producción (headers, gzip, pragmas). Cero simulaciones: cada función nueva responde con I/O real o documenta el requisito exacto.

---
Task ID: 8
Agent: main (Super Z)
Task: Ronda v8 — "quiero añadir adaptibilidad, más razonamiento, mejores implementaciones de la IA, razonamiento etc, y sigue buscando bugs y luego detecta implementaciones mejoras en producción que podrías añadir".

Work Log:
- MOTOR DE RAZONAMIENTO ADAPTATIVO (platform/orchestrator/razonador.py NUEVO): tres niveles sobre datos reales del caso. (1) evaluar_cobertura determinista (objetivos por tipo/estado, hallazgos por severidad, transportes aplicados según auditoría, huecos por fase). (2) prioridades_siguientes con reglas puras: rutas en riesgo → recon.rutas_sensibles, hallazgos de cabeceras → fingerprint+métodos, ventana cerrada → pospone intrusivos, credenciales confirmadas → canal F3, críticos sin confirmar → validación (adaptabilidad SIN LLM). (3) planificar_fase y reflexion_fase con IA real: plan con confianza por paso VALIDADO contra catálogo real de 18 transportes (herramientas inventadas se descartan y auditan), reflexión estructurada Observaciones/Huecos/Hipótesis/Siguientes pasos; sin backend → 503 con requisito exacto.
- TRAZAS AUDITABLES: tabla razonamientos (append-only) en memory.py con SHA-256 de entrada y salida, modelo, tokens, coste y confianza; métodos guardar/listar_razonamientos; INSERT con columnas nombradas (no posicional). API: GET/POST razonamiento/{cobertura,prioridades,plan,reflexion} + GET razonamiento (trazas). Vista nueva "Razonamiento" en consola (cobertura animada, prioridades con barras de confianza, plan IA, reflexión, trazas con hash).
- ROUTER RESILIENTE: circuit breaker por backend (3 fallos → abierto 60 s, failover frontera↔local, estado expuesto en /api/salud e integraciones), reintentos con backoff exponencial+jitter solo para 429/5xx/timeout/red, PresupuestoAgotado (techo por caso en config_caso 'presupuesto_caso_tokens' contra consumo REAL en BD), BackendIndisponible con requisitos exactos, temperatura por tarea (razonamiento 0.1–0.2, redacción 0.5–0.6).
- COPILOTO ESTRUCTURADO: secciones obligatorias + bloque JSON de sugerencias accionables (confianza + canal), parseo tolerante con degradación honesta (sin JSON → prose válida, sugerencias vacías); multi-turno real (la consola envía el hilo reciente, servidor sin estado); chips clicables con confianza y canal en la vista Copiloto.
- PRODUCCIÓN: /api/salud con componentes reales (memoria, operadores, router con circuito); limitador de tasa en proceso para login/registro (10/min → 429); X-Request-ID en toda respuesta.
- BUGS REALES DETECTADOS Y CORREGIDOS: (1) NameError 'dominios' en prioridades_siguientes (atrapado por test nuevo); (2) resumen_tokens no tenía 'total_tokens' → el presupuesto de caso NUNCA se habría activado (test lo atrapó; ahora suma por_fase); (3) proxy sin X-Forwarded-For → todos los operadores compartían el cubo del limitador en 127.0.0.1 (detectado en vivo: login de navegador recibió 429 del E2E por IP compartida); (4) copiloto/config POST devolvía solo {habilitado} → la UI mostraba "ninguno configurado" tras alternar (detectado en navegador); (5) overflow móvil 58px en cabeceras de la vista Razonamiento (flex-wrap); (6) icono duplicado Brain en sidebar (memoria→Database); (7) script E2E apuntaba a usuarios.db del raíz en vez de platform/ (USUARIOS_DB).
- VALIDACIÓN: 92/92 pytest (17 nuevos en test_razonador.py: cobertura, prioridades, catálogo, JSON roto, circuito, presupuesto, trazas, 401s). E2E vivo scripts/e2e_v8_razonador.py 14/14: plan GLM real en 4,9 s (6 pasos válidos, 0 descartados), reflexión 4/4 secciones, trazas con hash, 429 real en login. Navegador: login → vista Razonamiento (cobertura 8 objetivos, plan IA con 6 pasos, reflexión, trazas), copiloto con sugerencias (90% · informe / 80% · aprobacion), móvil 390px overflow 0, tsc src limpio, eslint limpio. Capturas v8_*.png en download/verificacion/. Docs §12 v8 y README actualizados; cuenta temporal eliminada.

Stage Summary:
- La plataforma gana el cerebro adaptativo pedido: razona sobre el caso en tres niveles (determinista, reglas, IA), valida todo contra su catálogo real, deja el razonamiento firmado con hashes y NUNCA ejecuta por sí sola — operator-in-command intacto.
- La capa IA es ahora tolerante a fallos (circuito, failover, backoff, presupuesto duro) y el copiloto razona con estructura y sugiere canales correctos.
- Siete bugs corregidos, dos de ellos importantes (presupuesto de caso inerte y cubo compartido del limitador). 92/92 tests, E2E 14/14, consola verificada en vivo.

---
Task ID: 9
Agent: main (Super Z)
Task: Ronda v9 — "continua mejorando y optimizando y puliendo detectando bug y luego pasame el proyecto en un zip": auditoría de concurrencia/seguridad/entrega binaria, ocho correcciones reales con tests de regresión, respaldo ZIP del caso y empaquetado del proyecto.

Work Log:
- AUDITORÍA INICIAL: 92/92 pytest, tsc/eslint limpios, backend sano. TSC de scaffolding ajeno (examples/, skills/) descartado del alcance. Investigación de una "sintaxis rota" en router.py resultó ser artefacto del visor (hexdump: archivo correcto); establecido hexdump como árbitro para futuras sospechas.
- BUG 1 (fuga de recursos): ~15 endpoints abrían MemoriaCaso sin cerrar (FD leak, WAL sin checkpoint, riesgo database is locked); /avanzar tampoco cerraba el pool httpx del router; copiloto/razonamiento fugaban un httpx.Client por petición. Fix sistemático: MemoriaCaso como context manager (commit en __exit__) + with/try-finally en TODA la API.
- BUG 2 (SSE muerto por hilos): logs con sqlite3.ProgrammingError "SQLite objects created in a thread..." — el generador del stream es iterado por hilos worker distintos de anyio. Fix: check_same_thread=False + busy_timeout en la conexión del generador (único propietario). Verificado en vivo: 0 errores de hilo tras reinicio, heartbeats estables.
- BUG 3 (proxy corrompe binarios, detectado en E2E navegador): el proxy hacía r.text()+re-encode de TODAS las respuestas → respaldo.zip llegaba inválido (PK\x03\x04 + U+FFFD, 9631 bytes corruptos vs 5594 válidos). Fix: NextResponse(r.body) stream sin decodificar preservando content-type/content-disposition. Re-verificado en navegador: ZIP válido byte a byte.
- BUG 4 (memoria sin acotar + suplantación): _LimitadorTasa sin poda y clave suplantable vía XFF del primer salto (controlado por el cliente). Fix: poda de caducadas + tope duro 10k claves; proxy usa x-real-ip (Caddy) o ÚLTIMO salto XFF. BUG 5 análogo en auth._intentos (usuarios inexistentes = claves infinitas): poda simétrica.
- BUG 6 (techo de ruido no persistente): MotorGuardrails arrancaba ruido_acumulado=0 en cada petición → el techo del ROE solo vigilaba la fase en curso. Fix: carga inicial = suma de ruido_estimado de aprobaciones APROBADAS del caso.
- BUG 7 (identidad): roe.actualizar auditaba sin identidad y PeticionParada/PeticionRoe traían campo operador muerto editable por cliente. Fix: identidad JWT en el detalle, campos eliminados.
- BUG 8 (higiene): on_event deprecated → lifespan @asynccontextmanager; datetime.utcnow() → now(timezone.utc) (fases.py, reporting.py — el parche masivo estropeó los imports y se reparó a mano con verificación); bucle no-op del CSV eliminado; imports redundantes en crear().
- PRODUCCIÓN: PRAGMA busy_timeout=5000 en memoria de casos, operadores y SSE. NUEVO endpoint GET /api/engagements/{id}/respaldo: ZIP con caso.json (custodia orquestart-caso/1 + cadena verificada) + informe.md + informe.html + MANIFIESTO.txt, auditado como caso.respaldo. Consola: acción "Respaldo de archivo del caso (ZIP)" en paleta + descargarRespaldoCaso en store.
- TESTS: test_v9.py (10 nuevos): poda limitador, poda intentos, context manager con/sin excepción, ruido previo cargado, respaldo ZIP completo (manifiesto+custodia+informes), 404/401, identidad en ROE. Suite 92→102.
- E2E: smoke scripts/smoke_v9.sh 13/13 en vivo (salud, 401, login real, F0 real, ROE con identidad, ZIP validado con Python, informe HTML, custodia VÁLIDA, poda bajo ataque, salud final). Navegador (cuenta temporal verificador_v9 creada y eliminada): login → paleta → respaldo descargado y VALIDADO (4 entradas, cadena True, auditoría 11) → sin errores de consola. Captura download/verificacion/v9_consola_respaldo.png.
- VALIDACIÓN FINAL: 102/102 pytest, tsc limpio (src), eslint limpio, SSE estable. Docs §13 v9 + README actualizados.

Stage Summary:
- La plataforma entra en estado de producción dura: sin fugas de conexiones, SSE inmune al thread-pool, SQLite con encolamiento de escritores, memoria del limitador acotada ante abuso, entregas binarias íntegras y techo de ruido del ROE realmente acumulativo por caso.
- Nuevo entregable operativo (respaldo ZIP de archivo) verificado de extremo a extremo en navegador.
- Proyecto empaquetado en download/ (ZIP sin artefactos locales ni secretos) con guía de arranque incluida.
- PORTABILIDAD (post-empaquetado): eliminadas las rutas absolutas /home/z/my-project de instrumentation.ts (RAIZ = cwd / ORQUESTA_RAIZ), sidecar.py (parents[2]), scripts/{dev-supervisor.sh,smoke_v9.sh,prueba_backend.py} y route.ts del puente IA (PUENTE_IA_TOKEN_RUTA). Puente GLM re-verificado tras el cambio (catálogo real + 401 con token incorrecto).
- ZIP FINAL: download/orquesta-rt-plataforma-v9.zip (154 ficheros, 433 KB) — sin node_modules/.git/runtime/secretos (scanner anti-secretos limpio; los 8 avisos eran falsos positivos verificados: referencias a rutas y patrones del propio scanner). Verificación de extracción en limpio: Python compila, ficheros clave presentes, sin .db/.token/.env. Smoke 13/13 tras todos los cambios.

---
Task ID: 10
Agent: main (Super Z)
Task: Ronda v10 — "intente crear un usuario y me salia error 400, haz un script de instalación fácil de ejecutar y ya, revisa de más problema y sigue puliendo todo".

Work Log:
- DIAGNÓSTICO DEL 400 (mensaje del usuario): tres causas concurrentes identificadas. (1) Fricción de validación: el backend rechazaba guiones en el nombre de usuario y la consola no validaba el formato antes de enviar; el usuario veía un 400 sin explicación útil. (2) Estado residual: usuarios.db conservaba la cuenta admin de mis E2E previos ('operador'), que impedía el bootstrap del usuario real. (3) Tras una alta parcialmente completada (cuenta creada, login automático fallido), reintentar el alta producía 400 "El usuario 'X' ya existe" sin salida clara.
- BUG CRÍTICO ADICIONAL (backend muerto tras reinicio): instrumentation.ts lanzaba "python3" del PATH, que en el proceso Next no tiene uvicorn ("No module named uvicorn" en logs/api.log) → el proxy no podía relanzar el orquestador y la consola quedaba muerta (503). Fix: resolverPython() prueba candidatos en orden (ORQUESTA_PYTHON → <raíz>/.venv → platform/.venv → PATH) ejecutando "import uvicorn, fastapi" en cada uno, con diagnóstico accionable.
- BUG ZOMBIE UVICORN: el apagado elegante de uvicorn sin límite quedaba retenido INDEFINIDAMENTE por una conexión SSE abierta al recibir SIGTERM → proceso zombie solapado con el nuevo (detectado en vivo: 2 uvicorn tras relevo). Fix: --timeout-graceful-shutdown 5 en instrumentation.ts y start.sh; stop.sh con relevo forzado (SIGTERM + drenaje 3s + SIGKILL). Verificado: apagado con SSE abierta ahora 1s.
- BUG START.SH LENTO: el sondeo de salud con curl -m 2 esperaba 2s por intento durante la compilación fría de Next (conexión aceptada, respuesta lenta) → arranque percibido de minutos. Fix: --connect-timeout 1 -m 1 y 240 intentos. Ciclo stop→start verificado en 47s.
- SCRIPTS DE INSTALACIÓN (petición del usuario): install.sh idempotente (prerrequisitos, .venv con requirements+pytest, node_modules, directorios, verificación REAL de imports), start.sh (orquestador con env completa + token de puente, lab, consola, healthchecks, no toca procesos vivos), stop.sh (parada limpia por puerto con relevo forzado). Instalador ejecutado de verdad en este entorno: PyPI real, 104 tests en verde con el .venv nuevo.
- CONSOLA (alta de usuario sin 400): acceso.tsx valida en cliente el patrón exacto del backend (A-Za-z0-9._- {3,32}), contraseñas triviales y coincidencia; pista visible "letras, números y . _ - · sin espacios" en bootstrap; si el alta devuelve "ya existe", conmuta a LOGIN con aviso ámbar claro (recuperación del flujo roto). equipo.tsx: mismas validaciones en el alta de operadores (toasts específicos). Backend auth.py: regla de usuario explícita con regex ASCII y guion permitido, mensaje claro.
- E2E NAVEGADOR VERIFICADO: bootstrap visible con pista → "ana lopez" (espacio) rechazado EN CLIENTE sin tocar el servidor → alta "ana.lopez" OK con entrada directa a la consola (13 vistas) → logout → login OK → Equipo: alta inválida con toast "Usuario inválido", alta válida "luis.martin" OK → móvil 390px overflow 0 → 0 errores de consola. Resiliencia: kill del backend → el proxy lo relanza SOLO con .venv; relevo limpio tras SIGTERM.
- ENTREGA: usuarios.db de pruebas eliminada (bootstrap limpio para el operador real); empaquetar.py v10 (incluye install/start/stop.sh, excluye .venv y *.bak); ZIP download/orquesta-rt-plataforma-v10.zip (156 ficheros, 439 KB) verificado por extracción: sintaxis bash OK, sin .db/.token/.env, código nuevo presente (resolverPython, graceful-shutdown, recuperación ya-existe). Anti-secretos: mismos 8 falsos positivos verificados (rutas y patrones del escáner).
- VALIDACIÓN: 104/104 pytest (2 tests nuevos de regla de usuario), tsc limpio en src, eslint limpio, puente GLM verificado (catálogo con token interno), /api/salud íntegra (circuito cerrado).

Stage Summary:
- El ciclo de acceso queda a prueba de operador: validación preventiva en cliente, mensajes accionables, recuperación automática del alta duplicada y bootstrap limpio garantizado.
- La plataforma es ahora INSTALLABLE de verdad: ./install.sh && ./start.sh desde cero en cualquier máquina con python3+bun/npm; el backend sobrevive a reinicios del sistema (resolución de intérprete) y no deja zombies.
- v10 empaquetada en download/orquesta-rt-plataforma-v10.zip.

---
Task ID: 11
Agent: main (Super Z)
Task: Ronda v11 — "sigue continuando detectando bugs, y puliendo el sistema, no pares": auditoría de seguridad del boundary, validación de alcance del ROE, higiene de tests y empaquetado.

Work Log:
- AUDITORÍA DE SEGURIDAD (con sesión real, contas de auditoría temporales borradas al final): path traversal en engagement_id con %2F y ".." → los IDs se generan en servidor y las rutas solo resuelven ficheros .db DENTRO de casos/ (404 en todos los vectores probados; deny-by-default verificado: 401 sin token). Se añadió igualmente test de regresión.
- BUG 1 (boundary roto por ROE malformado): un CIDR inválido se ACEPTABA al crear el caso y, en el scope check, el ValueError del primer CIDR roto ABORTABA el bucle → los CIDRs válidos posteriores nunca se evaluaban (objetivos legítimos denegados "fuera de alcance" a mitad de engagement). FIX triple: (a) field_validators en ROEPolitica (CIDR, dominio, exclusiones) con mensajes accionables; (b) validate_assignment=True para que CADA mutación del ROE (p. ej. alcance_excluido desde roe.actualizar) pase por validación; (c) bucle del boundary resiliente (CIDR roto se salta, no bloquea a los demás) como defensa en profundidad.
- BUG 2 (500 en lugar de 422): la validación del ROE ocurre dentro del handler → ValidationError de pydantic escapaba como 500. FIX: try/except + _detalle_validacion() que extrae campo/causa/valor en un 422 legible, en crear() y actualizar_roe().
- BUG 3 (formato de informe): ?formato=xml se aceptaba en silencio (caía a markdown). FIX: 422 con "válidos: md, html", precede al 404 de existencia.
- BUG 4 (regresión evitada y testada): "localhost" (objetivo del lab documentado) NO pasa la regex de dominio estricta → habría roto la carga de 4 casos reales ya almacenados. FIX: localhost permitido explícitamente + test de compatibilidad que reabre un ROE almacenado con localhost.
- BUG 5 (higiene de tests, detectado en vivo): el fixture cliente_api de test_v11 creaba 'opv11' en la usuarios.db REAL (el operador habría visto login en vez de bootstrap) y los tests de API creaban casos en el directorio real de casos. FIX: RUTA_DB aislada en tmp con monkeypatch y limpieza del caso creado; suite re-verificada: 0 contaminación (usuarios.db no existe tras pytest; 7 casos reales intactos).
- CONSOLA: el formulario "Nuevo engagement" valida dominios/CIDRs/exclusiones EN CLIENTE con las mismas reglas del backend (IPv4 con octetos/prefijo, IPv6, localhost) → feedback instantáneo, sin 422.
- LIMPIEZA: caso corrupto con CIDR 'banana' (de la ronda de auditoría) y artefactos de prueba eliminados; cuentas de auditoría borradas; usuarios.db reiniciada (bootstrap limpio verificado en navegador: "Alta del primer operador").
- E2E: formulario rechaza "banana" en cliente con mensaje claro; alta válida 200; casos antiguos cargan (compatibilidad localhost); informe 422; móvil 390px overflow 0.
- VALIDACIÓN: 117/117 pytest (13 nuevos en test_v11.py), tsc limpio en src, eslint limpio. ZIP: download/orquesta-rt-plataforma-v11.zip (157 ficheros, 444 KB) verificado por extracción (validadores, helper 422 y formulario presentes; sin secretos ni runtime).

Stage Summary:
- El ROE es ahora infalible por construcción: no se puede firmar un caso con alcance malformado, ninguna mutación del ROE evita la validación, y el boundary sobrevive incluso a un ROE corrupto.
- Errores de la API 422 accionables en lugar de 500/422 genéricos; consola valida en cliente lo mismo que el servidor.
- Suite de tests aislada del despliegue real (sin contaminación de cuentas ni casos).
- Entregable: download/orquesta-rt-plataforma-v11.zip.

---
Task ID: 12
Agent: main (Super Z)
Task: Ronda v12 — "ve mejorando la web las funciones de ia, tecnicas, higiene, pulimiento de todas las funciones existentes, implementaciones para producción etc no pares": biblioteca de TÉCNICAS expuesta al operador, endurecimiento de entrada, mejora del contexto IA y relevo sin carrera.

Work Log:
- AUDITORÍA INICIAL: 117/117 pytest, tsc src 0, eslint limpio, servicios vivos. Línea sospechosa en razonador.py ("por_severidad[\"severidad\"]]") arbitrada con od/AST: bytes correctos `por_severidad[h["severidad"]]` — segundo artefacto del visor documentado (precedente v9).
- TÉCNICAS (hueco principal detectado): la biblioteca de skills era INVISIBLE para el operador (cero endpoints, cero vistas; solo alimentaba prompts de agentes). NUEVO: GET /api/skills (catálogo real con total, distribución por fase/riesgo, contador de aprobación humana), GET /api/skills/{nombre} (playbook completo bajo demanda + hash sha256 verificable del disco, 404 accionable), POST /api/skills/recargar (invalida caché del índice y relee el disco; log del servicio). skills.py: recargar() del índice + higiene en _parsear (UNA lectura de bytes para hash+cuerpo, antes leía el fichero dos veces).
- DECISIÓN DE DISEÑO con test como testigo: el primer intento de /api/skills creaba una instancia nueva por petición (re-parse YAML constante y recargar() convertida en no-op); el test de recarga lo atrapó (esperaba índice obsoleto y encontraba fresco). Fix: caché de módulo _BIBLIOTECA_CATALOGO para el catálogo del operador + recargar reconstruye de cero; los agentes SIGUEN leyendo el disco en cada instanciación de engagement (frescura garantizada donde importa). Fixture resetea la caché (sin contaminación cruzada).
- CONSOLA — VISTA TÉCNICAS (tecnicas.tsx): pestaña nueva (icono Swords) con estadísticas reales (total, con aprobación, fases con cobertura, riesgo alto), buscador por nombre/texto/ATT&CK, filtros por fase y riesgo, tarjetas con MITRE/riesgo/aprobación humana, visor de playbook con fuentes permitidas + sha256 + cuerpo completo, botón "Recargar del disco" con toast, nota operator-in-command. Store: tecnicas/cargarTecnicas/recargarTecnicas + obtenerDetalleTecnica (helper exportado). La paleta genera "Ir a Técnicas" automáticamente.
- PRODUCCIÓN — ENDURECIMIENTO DE ENTRADA (422 en vez de consumo libre): PeticionCrear (dominios/cidrs/excluido ≤100 elementos × ≤253 chars, técnicas ≤50 × ≤24, ventana_dias ≤7×3), PeticionAvanzar (opciones ≤50 claves × 60/500 chars, destinatarios ≤20×254, notas ≤4000), PeticionDecision (comentario ≤2000), PeticionParada (motivo ≤500), PeticionRoe (ventanas ≤5 chars, listas acotadas), PeticionCopiloto.historial (≤20 turnos × 4000 chars — antes ilimitado: un cuerpo gigante consumía memoria/parsing aunque _normalizar_historial solo usara 6).
- IA — COPILOTO: el contexto ahora incluye distribución REAL de severidades de hallazgos (alta=N, media=N...) y estados de objetivos (descubierto=N, sin_explorar=N...) para que el modelo priorice con la forma del riesgo, no solo títulos.
- BUG DE RELEVO (carrera de puerto): arrancarBackend() lanzaba uvicorn inmediatamente tras detectar el backend muerto — si el anterior estaba en graceful shutdown (SSE abierta, hasta 5 s), el nuevo moría con "address already in use" (log mostraba 4 intentos fallidos encadenados). Fix: puertoLibre() espera acotada (8 s) a que el connect TCP sea rechazado ANTES del spawn. Verificado en vivo: relevo con 1 bind, sin errores, 1,27 s.
- BUG DE UI INVESTIGADO (falso positivo): el buscador de Técnicas parecía no restaurar el catálogo al vaciar bajo Playwright; bisecado con onChange directo por fiber + teclas reales: la lógica de estado/filtrado es correcta (tecla real "z" filtra, Ctrl+A+Backspace restaura) — el fill("") sintético no llega al value tracker de React: artefacto del automatismo, no bug de la app.
- E2E NAVEGADOR (cuenta temporal verificador_v12, borrada al final; bootstrap 0 operadores verificado): login → pestaña Técnicas en sidebar → stats reales (1 técnica, 1 aprobación, 1 fase, 1 riesgo alto) → playbook kerberoasting_lab completo (2711 chars, sha256 257a78a4…) → búsqueda filtra y restaura con teclado real → Recargar del disco: POST 200 + refetch → paleta "Ir a Técnicas" → móvil 390px overflow 0 → 0 errores de consola. Capturas: download/verificacion/v12_tecnicas_playbook.png, v12_tecnicas_movil.png.
- LIMPIEZA: cuenta temporal eliminada (la API impide auto-eliminación: correcto; borrado directo en BD y verificado /api/auth/estado hay_operadores=false).
- VALIDACIÓN: 133/133 pytest (16 nuevos en test_v12.py: catálogo, detalle+hash, 404 accionable, 401 deny-by-default en los 3 endpoints nuevos, recarga en caliente con skill añadida al disco, recargar() de BibliotecaSkills, _parsear una lectura, límites de entrada 422 con uso legítimo intacto), tsc src 0, eslint limpio, log del orquestador sin errores nuevos.

Stage Summary:
- El operador ve por fin su arsenal: la biblioteca de técnicas es una vista de primera clase con el mismo progressive disclosure que usa el modelo, custodia sha256 del contenido y recarga en caliente — conocimiento visible, ejecución siempre por el canal humano.
- La superficie de entrada de la API está totalmente acotada (ningún cuerpo puede crecer sin límite) y el copiloto razona con distribuciones reales, no solo títulos.
- El relevo del backend ya no compite con el drain del anterior: cero "address already in use" en el ciclo verificado.
- Entregable: download/orquesta-rt-plataforma-v12.zip.

---
Task ID: 13
Agent: main (Super Z)
Task: Ronda v13 — "sigue implementaciones revisando bugs, limpieza de archivos, e implementaciones de mejoras": limpieza profunda del template (−47 deps npm), modo producción de la consola, rotación de logs, single-flight del bootstrap, copiloto con arsenal/coste/timeline, 2 playbooks nuevos y escáner anti-secretos real.

Work Log:
- AUDITORÍA INICIAL: 133/133 pytest, tsc de src limpio, servicios vivos. Limpieza detectada: logs/dev-restart.log 59 MB + dev.log 46 MB (crecimiento sin límite), consola en modo dev, examples/ roto (tsc global fallaba por el template), db.ts+Prisma huérfanos, 38 componentes ui sin uso, 47 deps npm sin uso.
- LIMPIEZA (con clausura de imports calculada por script, no a ojo): eliminados examples/, tests/ raíz, prisma/, src/lib/db.ts, db/custom.db, 38 ui huérfanos, use-mobile, smoke scripts de rondas viejas (v6/v7/v8/v9), 67 capturas antiguas y ZIPs v9/v11/v12. package.json: 68→19 deps (manteniendo las 6 radix + cmdk + runtime real), scripts sin 'tee' (duplicaban logs), tsconfig excluye skills/scripts/platform → tsc --noEmit GLOBAL en 0 (antes fallaba a nivel raíz). bun.lock sincronizado (−47 paquetes). Tests anti-regresión en test_v13.py impiden que los huérfanos vuelvan.
- BUG 1 (log sin límite): dev-supervisor.sh acumulaba 59 MB/40 min. Reescrito: rotación en caliente (tope 20 MB → conserva 1 MB), modo MODO_CONSOLA=prod con auto-build y fallback, lockfile igual de idempotente. start.sh rota api.log/lab.log/consola.log al arrancar (>20 MB → 1 MB).
- BUG 2 (carrera de bind en relevo del backend): al caer el backend, CADA petición al proxy relanzaba SU uvicorn → "address already in use" (reproducido en vivo: 2 spawns simultáneos). Fix: single-flight en instrumentation.ts (promesa compartida; N peticiones esperan UN arranque; finally libera para reintento). Verificado E2E: backend muerto + 6 peticiones concurrentes → 1 arranque, 0 errores de bind, salud 200.
- BUG 3 (build de producción roto por Turbopack): `next build` abortaba porque Turbopack resolvía los literales ".venv/bin/python3" de instrumentation.ts como referencias de asset y el symlink del venv "sale de la raíz". Fix: segmentos de ruta construidos en runtime (array join), mismo comportamiento. AHORA: bun run build pasa con typescript.ignoreBuildErrors=false (endurecido: el build DEBE fallar con errores de tipos), standalone verificado en :3001 (app 200, proxy 200, asset 200) y detenido limpio.
- MODO PRODUCCIÓN: ./start.sh prod → build standalone + servidor Node (bun run start); ./start.sh (o dev) → dev con recarga en caliente. El guardián se asegura SIEMPRE tras el healthcheck (idempotente por lockfile, cubre consola viva sin guardián).
- IA — COPILOTO (construir_contexto v13): COSTE DEL CASO real (tokens acumulados + % del presupuesto cuando está fijado), ÚLTIMA ACTIVIDAD (últimos eventos de auditoría en orden cronológico, anclaje temporal sin depender del RAG) y ARSENAL (índice real de la biblioteca de técnicas que pasa de api.py al prompt). SISTEMA con reglas 3b (presupuesto: proponer priorizar en vez de más llamadas) y 3c (solo citar técnicas que existen en el arsenal).
- TÉCNICAS — BIBLIOTECA AMPLIADA: 2 playbooks reales lab-safe con el estándar kerberoasting_lab (procedimiento, ruido, aprobación, OPSEC, evidencias, verificación blue team): asrep_roasting_lab (T1558.004, F4_dominio_ad) y llmnr_poisoning_lab (T1557.001, F3_acceso_inicial, con condiciones INNEGOCIABLES de consentimiento y parada si toca activo excluido). Catálogo del operador: 3 técnicas, 2 fases cubiertas, 3 de riesgo alto — verificado en navegador con hash sha256 del disco.
- ANTI-SECRETOS REAL: el escáner del empaquetador ya no adivina por substrings (falsos positivos con "mask-image" y rutas): comprueba que el VALOR del token del puente y claves con forma de API key NO están en el paquete; se auto-excluye. Resultado v13: LIMPIO.
- EMPAQUETADO: empaquetar.py → v13 (sin prisma), ZIP verificado por extracción: 116 ficheros/370 KB (−41 y −74 KB vs v12), scripts bash OK (bash -n), 3 skills, test_v13 dentro, prisma/examples ausentes.
- E2E NAVEGADOR (verificador_v13, borrada al final; bootstrap 0 operadores verificado): alta → consola → Técnicas con stats correctas → playbook llmnr completo con sha256 → vista Copiloto renderiza → móvil 390px overflow 0 → 0 errores de consola. Capturas: download/verificacion/v13_tecnicas_llmnr.png, v13_tecnicas_movil.png.
- VALIDACIÓN FINAL: 149/149 pytest (16 nuevos en test_v13.py), tsc global 0, eslint 0, build de producción OK, servicios 200 tras reinicio completo (stop.sh/start.sh con los scripts nuevos).

Stage Summary:
- El repositorio es por fin "código cerrado": sin un solo fichero o dependencia que la plataforma no use (19 deps npm, 10 ui, cero huérfanos del template), con tests que impiden la regresión de higiene.
- Producción real: build standalone estricto en tipos, ./start.sh prod, guardián con rotación de logs en caliente, relevo del backend sin carreras y logs acotados (de 105 MB de ruido a 8,3 MB y con rotación).
- El copiloto razona ahora con qué acaba de pasar (timeline), cuánto presupuesto queda (coste real) y qué técnicas existen de verdad (arsenal) — y está prohibido citar playbooks que no estén en el despliegue.
- Entregable: download/orquesta-rt-plataforma-v13.zip.

---
Task ID: 14
Agent: main (Super Z)
Task: Ronda v14 — "haz una investigación profunda sobre temas relacionados con nuestra herramienta o proyectos ya existentes, investiga el proyecto en profundidad e implementa nuevas mejoras para producción, uso y más; al terminar investiga bugs": benchmarking del sector (Caldera/Atomic/PlexTrac/ATT&CK Navigator/IA ofensiva), auditoría interna, capa MITRE ATT&CK Navigator end-to-end, regla R9 de arsenal en el razonador, guardia de IDs hostiles (fuzzing) y fix de lockfile zombie.

Work Log:
- INVESTIGACIÓN (web-search, 7 consultas): MITRE Caldera y Atomic Red Team (emulación adversaria, catálogo reproducible ATT&CK), ATT&CK Navigator (capas JSON de cobertura importables), gestión de operaciones RT (PlexTrac/AttackForge: informes con cobertura y verificación blue team), seguridad FastAPI/OWASP (throttling de login, cabeceras), tendencias IA ofensiva 2025-26 (agentes especializados + sugerencia de siguiente acción). Conclusión adoptada: la plataforma ya cumple rate-limit de login, bloqueo por fallos, cabeceras de seguridad, WAL+índices e informe con ATT&CK; los dos huecos de valor real son la CAPA NAVIGATOR exportable y la conexión arsenal↔sugerencias.
- AUDITORÍA PROFUNDA: auth.py (scrypt+JWT+bloqueo OK), api.py (rate limiter con poda OK), memory.py (WAL, synchronous=NORMAL, 6 índices OK), reporting.py (informe md/html con recetas blue team OK), next.config.ts (cabeceras OK). BUG real: /auditoria pasaba `limite` crudo (SQLite LIMIT negativo = SIN LÍMITE; valores enormes = volcado) — acotado a [1,1000] como el resto de endpoints de listado. Tercer artefacto del visor documentado: `criticas = [h for h in hallazgos…]` parecía sintaxis rota; arbitrado con py_compile+tokenize (tokens reales OP '[' + NAME 'h' en col. 15-16) — fichero correcto.
- NUEVO — CAPA ATT&CK NAVIGATOR (benchmarking directo): módulo navigator.py construye la capa layer 4.6 (versions navigator 5.1.0, domain enterprise-attack) SOLO con datos reales: hallazgos.tecnica_mitre → técnica observada con score por severidad MÁXIMA (crítica 100 → informativa 10) y colores del informe; aprobaciones.tecnica_mitre → técnica intentada (incluye rechazadas; sin score si no hay hallazgo — no se vende cobertura); técnicas con formato inválido ignoradas; caso sin hallazgos → capa con 0 técnicas (cero relleno); leyenda de severidades, gradiente, metadata con cadena de custodia. Endpoint GET /api/engagements/{id}/attack-navigator (404 accionable, 401 deny-by-default, Content-Disposition attachment) que queda auditado en el caso (caso.capa_navigator). Consola: descargarCapaNavigator en store.ts, botón "ATT&CK" en la barra superior (junto a Informe/HTML) y comando de paleta "Exportar capa MITRE ATT&CK (Navigator JSON)".
- NUEVO — R9 ARSENAL EN EL RAZONADOR: prioridades_siguientes acepta `arsenal` (portadas reales del catálogo de skills, pasa de api.py) y propone hasta 3 playbooks pertinentes a la fase actual o siguiente (comparación por ORDINAL de fase — los valores del enum llevan sufijo, "F3_acceso_inicial"; el test atrapó este fallo en la 1ª implementación) que aún no tienen huella en el caso (ni hallazgo ni solicitud con esa técnica). Estado "propuesta_arsenal", confianza 0.55, y recuerda que la ejecución exige aprobación humana. Vista Razonamiento ya renderiza prioridades sin cambios.
- FUZZING FINAL EN VIVO (scripts/fuzz_v14.py → research/): 19 pruebas — 8 IDs hostiles en attack-navigator, límites absurdos (auditoría/memoria/razonamiento), 3 cuerpos malformados, 10x attack-navigator concurrentes, token falsificado y vacío. HALLAZGO: id de 10k chars → 500 (Path.exists() lanza OSError ENAMETOOLONG en TODOS los endpoints que resuelven la ruta del caso). FIX de raíz: guardia de ID en _memoria_de y /eventos (≤64 chars, solo [A-Za-z0-9._-]; ids legítimos son caso_<hex>) → 404 sin tocar el FS. Re-fuzzing: LIMPIO 19/19.
- BUG DE PRODUCCIÓN (lockfile del guardián): tras un start.sh muerto a medias quedó un bash <defunct> y el lockfile apuntaba a él; kill -0 prospera sobre zombies → NINGÚN guardián nuevo arrancaba ("ya hay un guardián vivo"). Fix: ps -o stat= para descartar estado Z. Turbopack "reading 'position'": crash transitorio por caché .next a medias del ciclo muerto — rm -rf .next y arranque limpio (no recurrente).
- E2E NAVEGADOR (verificador_v14, borrada al final; bootstrap 0 operadores restaurado): login → botón ATT&CK en barra → capa exportada real ("2 técnicas observadas + intentadas" sobre un caso existente, evento auditado) → paleta muestra el comando → 0 errores de navegador → móvil 390px overflow 0. Capturas: download/verificacion/v14_escritorio.png, v14_movil_390.png. Nota del entorno: el sandbox sega procesos `next` entre llamadas — el E2E se ejecutó autocontenido (consola relanzada + recorrido completo en una sola llamada); el arranque definitivo vía ./start.sh con guardián persiste.
- LIMPIEZA: cuenta temporal y caso de verificación eliminados (usuarios.db con 0 operadores, casos intactos), usuarios.db suelto en la raíz eliminado (falso positivo de CWD), scripts de ronda (e2e/fuzz/patch) movidos a research/ fuera del paquete, ZIP v13 eliminado.
- VALIDACIÓN: 163/163 pytest (14 nuevos en test_v14.py: estructura/scores/dedupe Navigator, intento rechazado sin score, caso vacío sin relleno, 404/401, auditación del endpoint, clamp de auditoría, R9 pertinencia/exclusión/tope-3/compatibilidad, regresión ID hostil), tsc global 0, eslint 0, servicios 200 tras reinicio completo, api.log sin errores nuevos (los binds históricos son del caos 12:39-12:48 ya resuelto).
- EMPAQUETADO: empaquetar.py → v14, ZIP verificado por extracción: 118 ficheros/379 KB (navigator.py, test_v14.py, scripts bash presentes; sin tokens ni artefactos de ronda; anti-secretos LIMPIO).

Stage Summary:
- La plataforma entrega el entregable de referencia del sector: la capa ATT&CK Navigator del caso se exporta con un clic y se importa en el Navigator para cruzar cobertura ofensiva con defensas — construida solo con técnicas realmente observadas o intentadas, auditada y sin relleno.
- El razonador determinista ahora razona también con el arsenal real del despliegue (R9): sugiere playbooks pertinentes por fase que aún no tienen huella, sin ejecutar nunca.
- El fuzzer en vivo elevó la guardia de IDs a toda la API (el 500 de ENAMETOOLONG era sistemático) y el guardián ya no queda bloqueado por un zombie tras un ciclo de arranque interrumpido.
- Entregable: download/orquesta-rt-plataforma-v14.zip.

---
Task ID: 15
Agent: main (Super Z)
Task: Ronda v15 — "sí, continúa": benchmarking del sector (VECTR/purple teaming, Sigma/detection-as-code, VACUUM INTO de SQLite, SSE Last-Event-ID de MDN), implementación de 4 mejoras de producción, limpieza de archivos y caza de bugs.

Work Log:
- INVESTIGACIÓN (web-search, 7 consultas nuevas, research/v15_*.json): VECTR (registro ofensa↔defensa por técnica), Sigma/detection-as-code (reglas versionables desde hallazgos), backup de SQLite en producción (VACUUM INTO + Online Backup API), rotación/expiración JWT (ya correcto: exp 12h + bloqueo por fallos), OWASP LLM/agentic 2025 (saneado anti-inyección ya presente en OSINT), SSE Last-Event-ID (MDN) y gestión de operaciones RT. Conclusión: 4 huecos reales → detección por hallazgo, paquete Sigma, respaldo completo del sistema y reanudación SSE.
- MEJORA 1 — PURPLE TEAMING (patrón VECTR): Hallazgo.deteccion (pendiente/detectado/no_detectado/prevenido) en models.py; migración idempotente por PRAGMA table_info en memory.py (CREATE IF NOT EXISTS no añade columnas); guardar_hallazgo con columnas explícitas y PRESERVACIÓN de la detección ya registrada (una re-guardada desde modelo obsoleto no la resetea — bug atrapado por el test antes de llegar a producción); método marcar_deteccion; endpoint PATCH /hallazgos/{id}/deteccion (422 fuera del Literal, 404, 401, auditado con identidad real); selector en la vista Hallazgos + tira "cobertura de detección"; columna deteccion en el CSV; sección purple team en el informe MD/HTML.
- MEJORA 2 — PAQUETE PURPLE TEAM (detection-as-code): módulo purpleteam.py genera ZIP con informe_purple.md (tabla hallazgo↔detección↔evidencias) + esqueletos Sigma SOLO para técnicas con fuente de logs de conocimiento público (T1558.003→4769, T1558.004→4768, T1557.001→Sysmon 3), con UUID5 estable, tags attack.tXXXX, selección ajustada con el activo real del hallazgo y status experimental; técnicas sin fuente conocida quedan DOCUMENTADAS como pendientes y sin regla (política anti-invención); endpoint /purple-team.zip (409 sin hallazgos, auditado) + botón "Purple" en la barra + comando de paleta.
- MEJORA 3 — RESPALDO COMPLETO (continuidad): módulo respaldo.py con VACUUM INTO (snapshot consistente en caliente, WAL incluido) de usuarios.db + cada caso_*.db, ZIP con manifest.json de SHA-256; endpoint /api/admin/respaldo-completo (403 no-admin, 401 sin token) + auditoría de SISTEMA nueva (tabla auditoria_sistema en usuarios.db, append-only, con endpoint /admin/auditoria-sistema y comando CLI auditoria-sistema); comando CLI respaldo-completo para cron (documentado en el --help) + botón en la vista Equipo.
- MEJORA 4 — SSE Last-Event-ID (MDN): cada evento lleva `id: {rowid}`; el endpoint lee la cabecera Last-Event-ID y reanuda desde el evento siguiente (ids no numéricos/negativos/fuera de rango → cola del flujo); el cliente guarda el último id y lo envía al reconectar (reset al cambiar de caso); el generador se extrajo a función de módulo flujo_eventos_sse + _parse_last_event_id para testear con itertools.islice (el TestClient síncrono se cuelga con streams infinitos — hallazgo de la ronda).
- LIMPIEZA DE ARCHIVOS: 6 casos de prueba residuales de las rondas + -shm/-wal huérfano eliminados; hgigie de git REAL: platform/usuarios.db (¡contenía el secreto JWT!), platform/casos/ (22 ficheros de runtime commiteados), .env, db/puente-ia.token y research/ estaban TRACKED → git rm --cached + .gitignore endurecido (runtime y secretos nunca más en el repo). Commit de higiene incluido.
- CAZA DE BUGS: fuzzing en vivo de 31 comprobaciones (research/fuzz_v15.py) sobre los endpoints nuevos — 401/403/404/422, IDs de 10k, traversal, cuerpos malformados, JSON roto, 10x concurrentes, Last-Event-ID hostil de 5000 dígitos — LIMPIO 31/31. E2E navegador atrapó UN BUG REAL: el proxy Next.js no tenía handler PATCH → 405 en marcarDeteccion (la vista moría en silencio); añadido y verificado end-to-end (BD + auditoría con identidad). El 500 histórico del log en attack-navigator con id 10k era anterior al fix de v14: verificado en vivo → 404 en los 5 endpoints. Labels "Hours Hours" del time picker: quirk del a11y de Chromium con perfil en-US (el documento ya es lang="es"); añadido lang="es" + step=60 a los inputs de hora para formato 24h determinista.
- E2E NAVEGADOR: alta del primer operador → consola → caso nuevo → hallazgo sembrado → selector de detección marca "detectado" (verificado en BD y auditoría) → tira de cobertura renderiza → botón Purple genera paquete (auditoría caso.purple_team) → paleta con comando nuevo → Equipo descarga respaldo completo 200 (auditoría sistema.respaldo: 9 BDs) → móvil 390px overflow 0 → 0 errores de página. Capturas: download/verificacion/v15_escritorio.png, v15_movil_390.png. Limpieza final: cuenta temporal eliminada (0 operadores, bootstrap listo), caso E2E borrado.
- VALIDACIÓN: 179/179 pytest (16 nuevos en test_v15.py: migración BD antigua, preservación de detección, PATCH 404/422/401, Sigma solo con fuente conocida, 409 sin hallazgos, VACUUM INTO + manifiesto, guardia admin, replay SSE con islice), tsc global 0, eslint 0, build de producción OK (advertencia Edge de instrumentation.ts preexistente), servicios 200 tras reinicio completo.
- EMPAQUETADO: versión bumped a v15 en empaquetar.py, ZIP verificado por extracción: 121 ficheros/396 KB (purpleteam.py, respaldo.py, test_v15.py incluidos; bash -n OK en los 3 scripts; sin usuarios.db/casos/token/.env; anti-secretos LIMPIO).

Stage Summary:
- La plataforma cierra el ciclo purple team completo del sector: el operador registra si el blue team detectó, no detectó o previno cada acción (VECTR), la consola muestra la cobertura de detección y el paquete "Purple" entrega informe + esqueletos Sigma solo donde hay conocimiento real de la fuente de logs — nada inventado.
- Continuidad operativa: respaldo completo consistente en caliente (VACUUM INTO) con manifiesto SHA-256, auditable a nivel de despliegue y automatizable por cron con un comando.
- El flujo en vivo ya no pierde eventos entre reconexiones (Last-Event-ID estándar) y el proxy de la consola soporta PATCH (bug de producción atrapado por el E2E).
- Higiene: el repo ya no trackea secretos ni datos de runtime (antes sí: usuarios.db con secreto JWT, 22 ficheros de casos, .env y el token del puente).
- Entregable: download/orquesta-rt-plataforma-v15.zip.

---
Task ID: 16
Agent: main (Super Z)
Task: Ronda v16 — "procede con analítica de cobertura ATT&CK por campaña, webhooks de detección, otra investigación de mejoras y nota de demostración para GitHub con GIFs y fotos del uso real".

Work Log:
- INVESTIGACIÓN (web-search, 4 consultas, research/v16_*.json): gestión de PROGRAMA red team (VECTR/PlexTrac/cobertura multi-campaña), webhooks de producción (Stripe/GitHub/Svix: firma HMAC sobre cuerpo crudo, cabecera de evento, id de entrega, reintento, delivery log), métricas purple team (detected/not detected/prevented + % sobre evaluado), demos GitHub de referencia. Conclusión: 2 mejoras mayores (analítica multi-campaña y webhooks integrados a flujos) + 1 mejora media (registro manual de hallazgos, hueco real descubierto al integrar el evento hallazgo.registrado).
- MEJORA 1 — COBERTURA ATT&CK ENTRE CAMPAÑAS (cobertura_attack.py): agrega TODOS los caso_*.db en modo solo-lectura (sqlite mode=ro): matriz técnica × campaña (observada con severidad máxima / intentada sin hallazgo), técnicas recurrentes (≥2 campañas = debilidad persistente), cobertura de detección por campaña y global (VECTR: (detectado+prevenido)/evaluados), ids inválidos contados sin inferencia, BDs corruptas omitidas y anotadas, orden determinista. Endpoints GET /api/analitica/cobertura-attack + .csv (una fila por celda poblada). Consola: nueva pestaña "Cobertura ATT&CK" (KPIs, heatmap con colores de severidad de Navigator, escudos de detección, recurrentes, tabla por campaña), acción cargarCoberturaAttack en store, botón CSV + comando de paleta "Exportar matriz de cobertura ATT&CK entre campañas (CSV)".
- MEJORA 2 — WEBHOOKS OPERATIVOS (webhook.py v16): receptores persistentes en usuarios.db (tablas webhooks + webhook_entregas, índice y poda a 500 entregas), suscripción por evento (hallazgo.registrado, hallazgo.deteccion, aprobacion.solicitada, aprobacion.decidida, roe.parada_emergencia, webhook.prueba), entrega REAL firmada (X-Orquesta-Firma sha256=HMAC(cuerpo), X-Orquesta-Evento, X-Orquesta-Entrega, X-Orquesta-Id), UN reintento t+2s solo ante 5xx/red (4xx es respuesta firme), delivery log con HTTP real, canal heredado WEBHOOK_URL sigue vivo (sin duplicar URLs), SSRF: scheme+host y veto a metadatos de nube (169.254.0.0/16, metadata.google.internal). Cableado REAL: guardrails (aprobacion.solicitada), api.py (decidida/deteccion/parada), fases.py (registrado). API admin: GET/POST/PATCH/DELETE /api/admin/webhooks, /probar (ping sincrónico), /entregas; auditoría de sistema en cada gestión; secreto generado mostrado UNA sola vez. UI: sección admin en Integraciones (alta con generación de secreto, chips de eventos, probar, pausar, entregas, baja con confirmación).
- MEJORA 3 — REGISTRO MANUAL DE HALLAZGOS: POST /api/engagements/{id}/hallazgos (título, severidad, técnica ATT&CK validada con el regex de Navigator y normalizada a mayúsculas, activo, descripción), auditado como decisión HUMANA (hallazgo.registrar) y dispara hallazgo.registrado por webhook. Formulario en la vista Hallazgos (también en el estado vacío).
- E2E+DEMO REAL: sesión de demostración completa sobre flujos reales — operador demo (bootstrap real), 2 campañas de lab, hallazgos del lab con técnicas válidas, detecciones documentadas vía PATCH real (cada una disparó el webhook de verdad), receptor local :9099 que verificó la firma HMAC del cuerpo capturado, ping de prueba OK, historial de entregas con OK 200 y un FALLO honesto (Connection refused cuando el receptor estaba caído). Capturas reales en docs/demo/ (10 PNG + recorrido.gif 1000px/7,5s ensamblado con ffmpeg palettegen): acceso, casos, panel, cobertura (heatmap+detalle), hallazgos, webhooks (con entregas), paleta, móvil 390. El E2E atrapó y resolvió: record de agent-browser crea contexto nuevo (logout) → frames sucesivos + ffmpeg en su lugar.
- CAZA DE BUGS: fuzzing en vivo 58/58 (research/fuzz_v16.py): 401s deny-by-default, IDs de 10k y traversal en las 3 rutas de webhook, URLs javascript:/file:/metadatos, cuerpos malformados, límites absurdos, 10x cobertura concurrente, token falsificado — cero 500. BUG REAL del repo: el interface EstadoConsola había perdido los campos prioridades/planRazon/reflexion/trazasRazon/razonOcupado/errorRazon (regresión introducida por una edición de esta ronda; tsc la destapó) — restaurados, tsc global 0. Regresiones de tests v7 actualizadas al contrato v16 (firma verificada contra el cuerpo capturado).
- LIMPIEZA: 7 casos residuales de rondas v5-v9 (smoke/E2E, 0 técnicas) eliminados de platform/casos/; sesión de demo borrada (operador demo eliminado por BD tras la protección de auto-baja, 0 operadores, bootstrap listo; 2 casos demo fuera; receptor demo dado de baja vía API con auditoría); tool-results/ y __pycache__ sacados del repo git + .gitignore endurecido; commit de higiene.
- VALIDACIÓN: 196/196 pytest (17 nuevos en test_v16.py: cobertura multi-campaña/recurrentes/CSV/corruptas/determinismo, validar URL/eventos, alta sin secretos, entrega firmada verificada por el receptor local con hmac.compare_digest, reintento 5xx→204 con intentos=2, 4xx sin reintento, filtro de suscripción, evento desconocido, guards admin, ciclo CRUD+auditoría, ping real, POST hallazgo manual auditado+notificado, 401 cobertura), tsc global 0, eslint 0, build de producción OK, servicios 200 tras reinicio (la consola exige relanzamiento limpio tras el build: .next invalidado), api.log sin 500, móvil 390px overflow 0, 0 errores de navegador.
- EMPAQUETADO: versión v16, ZIP verificado por extracción: 137 ficheros/2.5 MB (cobertura_attack.py, test_v16.py, DEMOSTRACION.md + docs/demo/ con GIF y capturas incluidos; bash -n OK; sin usuarios.db/casos/token/.env; anti-secretos LIMPIO). Copia amable de la nota de demo en download/orquesta-rt-demo/.

Stage Summary:
- La plataforma pasa de la cobertura por caso (Navigator v14) a la gestión del PROGRAMA: la matriz técnica × campaña entre todos los casos, las debilidades recurrentes y la cobertura de detección por campaña (VECTR) responden "¿qué se ejercitó, dónde se repite y qué ve el azul?" con la misma disciplina anti-relleno.
- Las notificaciones son de producción: receptores por evento, firma HMAC-SHA256 verificable por el receptor, id de entrega, reintento único, delivery log con el resultado HTTP real (incluye los fallos — nada de éxitos fingidos) y gestión admin auditada.
- El operador puede registrar hallazgos manuales con técnica validada; el webhook hallazgo.registrado cubre también el ciclo del agente.
- Nota de demostración para GitHub con GIF y capturas del uso real (docs/DEMOSTRACION.md), enlazada desde el README y empaquetada en el ZIP.
- Entregables: download/orquesta-rt-plataforma-v16.zip y download/orquesta-rt-demo/.

---
Task ID: 17
Agent: main (Super Z)
Task: Ronda v17 — "menos cargada pero incluyendo todo": despeje de la consola, bucle de pulido, explicación del proyecto para una persona externa.

Work Log:
- DIAGNÓSTICO DE CARGA: 16 pestañas planas en el sidebar + 4 botones de exportación sueltos en la barra (Informe/HTML/ATT&CK/Purple) + custodia y respaldo SOLO en la paleta + cinta de estado de 2 líneas.
- MEJORA 1 — NAVEGACIÓN AGRUPADA: GRUPOS_NAVEGACION (Campaña/Resultados/Inteligencia IA/Sistema) como única fuente de verdad; PESTAÑAS deriva con flatMap (la paleta no cambia). Etiquetas mono de 9px, insignia de aprobaciones conservada; menú móvil con los mismos 4 grupos en rejilla 2 col; componente ElementoNav compartido escritorio/móvil.
- MEJORA 2 — MENÚ EXPORTAR ÚNICO: los 4 botones sueltos → 1 menú desplegable (popover propio: click-fuera + Escape, role=menu/menuitem) con 6 entregables y descripción de cada uno; ahora custodia JSON y respaldo ZIP son visibles en la barra (antes escondidos en la paleta). Barra resultante: paleta, sync, Ejecutar fase, Exportar, Pausar, Parada, sesión — una sola fila.
- MEJORA 3 — CINTA A UNA LÍNEA: "operator-in-command · herramientas reales acotadas al ROE" en un solo mensaje con truncate.
- BUG REAL ATRAPADO POR EL E2E (overflow móvil): a 390px el grupo de controles medía 428px (54px de desbordamiento) — el sello "en vivo" (~60px) y el avatar de sesión. Fix: "en vivo" solo punto en móvil (los estados críticos "sin conexión"/"pausado" SIEMPRE con texto), avatar oculto <sm. Verificado: overflow 0px. El cazador de culpables in-page (eval de rects) localizó el div ofensor en un paso.
- E2E AUTOCONTENIDO (research/e2e_v17.sh): alta bootstrap por UI → consola → 4 grupos presentes (eval DOM: snapshot -i omite texto no interactivo, falsos negativos evitados) → barra con Exportar y sin sueltos → caso creado vía diálogo "Nuevo engagement" → menú Exportar con los 6 items → recorrido Hallazgos/Cobertura/Copiloto/Integraciones → 0 errores de página → móvil 390: grupos y overflow 0 → limpieza: operador temporal fuera por BD (la API protege el auto-baja), caso E2E borrado, 0 operadores (bootstrap listo). 6 iteraciones del guion hasta 100% verde (lecciones: formato de refs del snapshot, login vs bootstrap según existan operadores).
- VALIDACIÓN: tsc global 0, eslint global 0, build producción OK, 196/196 pytest (backend intacto), servicios 200, api.log sin 500 nuevos.
- DOCS: docs/COMO_FUNCIONA.md — explicación en lenguaje llano para alguien de fuera (qué es, problema, para quién, piezas, capacidades, flujo de uso, por qué así, límites); enlazada desde README junto a la demo. Repo git: commit de la ronda.
- EMPAQUETADO: v17 → download/orquesta-rt-plataforma-v17.zip (138 ficheros/2.5 MB, COMO_FUNCIONA.md + demo incluidos, bash -n OK, sin usuarios.db/casos/token, anti-secretos LIMPIO, verificado por extracción). e2e_v17.sh movido a research/.

Stage Summary:
- La consola mantiene sus 16 funciones pero se ve despejada: la navegación se lee en 4 bloques con sentido operativo, la barra cabe en una fila y las exportaciones viven en un menú que además descubre custodia y respaldo.
- El desbordamiento móvil de la barra (regresión silenciosa del menú nuevo) fue atrapado y corregido con verificación numérica en el E2E.
- docs/COMO_FUNCIONA.md da la explicación externa del proyecto dentro del propio repositorio, junto a la demo con GIF.
- Entregables: download/orquesta-rt-plataforma-v17.zip.

---
Task ID: 18
Agent: main (Super Z)
Task: Ronda v18 — "¿lo probaste como un operador? ¿hace OSINT/phishing/pentesting automático, C2, grafo de empleados, AD?": test de operador E2E completo en vivo, pulido de los bugs que destapó, grafo de relaciones del caso y respuesta honesta de capacidades.

Work Log:
- TEST DE OPERADOR E2E EN VIVO (scripts/operador_e2e_v18.py): bootstrap → JWT → estado REAL de integraciones (todas honestamente no configuradas) → caso con ROE (lab 127.0.0.1/32 + dominio .test) → ciclo completo F0→F7 con firma humana de 3 aprobaciones → copiloto GLM-4.6 REAL (respuesta estructurada en 4,4s, secciones Observaciones/Análisis/Riesgos/Siguientes pasos, 2 sugerencias accionables, 1421/415 tokens, $0.009243) → razonador (prioridades deterministas + plan IA 4 pasos) → informe real (5075 caracteres con ATT&CK) → cobertura ATT&CK multi-campaña → auditoría 66 eventos, cadena de custodia VÁLIDA → limpieza total (bootstrap a 0). Resultado final: 19 OK · 0 fallos.
- BUG 1 (dedup de hallazgos): al reanudar una fase tras aprobar, la fase se re-ejecuta completa y duplicaba hallazgos (2× "Postura de correo mejorable" con ids distintos). FIX en memory.guardar_hallazgo: dedup por identidad sustantiva (título, activo, severidad, técnica, descripción) — el primer intento con clave (título, activo) era demasiado agresivo y el test v16 de la matriz ATT&CK lo atrapó (hallazgos distintos de misma técnica/severidad deben convivir); se conserva SIEMPRE el original con su detección.
- BUG 2 (falso positivo DNS): la postura de correo reportaba "mejorable" en dominios sin resolver (un dominio sin DNS no es un dominio sin SPF). FIX en transportes.recon_correos_seguridad: guardia de resolución (A/AAAA/MX/NS) → sin_resolucion=true y sin debilidades. test_v7 actualizado al contrato honesto.
- BUG 3 (higiene de despliegue): la auto-baja estaba vetada SIEMPRE → las cuentas temporales de verificación quedaban huérfanas (encontrados op_verif_v18 + fuzz15adm/fuzz15op residuales + usuarios.db suelto en raíz, todo limpiado). FIX en auth.eliminar_operador: auto-baja permitida si es el ÚNICO operador (reabre bootstrap, entrega limpia); con testigos sigue vetada. Validado EN VIVO: la cuenta E2E se dio de baja por API (200) y el bootstrap reabrió.
- GRAFO DE RELACIONES (src/components/consola/grafo.tsx, nueva capacidad pedida por el usuario): vista en Objetivos con conmutador lista|grafo (sin pestañas nuevas). Nodos por capas (dominios→hosts→servicios/rutas→personas/credenciales), chips de hallazgos con severidad sobre su activo, aislado de vecinos al hacer clic, aristas SOLO por relación observada (subdominio, mismo activo en dos capas, detalle que menciona a otro objetivo), aviso honesto de hallazgos huérfanos y nodos aislados. Pulido tras captura: capas vacías eliminadas, chips por nombre insensible a mayúsculas, conexión de entidad duplicada entre capas.
- E2E NAVEGADOR REAL (scripts/e2e_v18.sh + sesión interactiva): alta bootstrap por UI → caso nuevo (diálogo con Firmar ROE) → F0/F1/F2 con firmas reales desde la cola de Aprobaciones (con diálogo de comentario "Confirmar decisión") → 2 hallazgos manuales por formulario (T1558.003→lab-interno.test, T1595.002→127.0.0.1) → grafo renderiza 4 nodos/3 aristas con chips → escritorio 1440 y móvil 390 sin overflow (0px) → 0 errores de página. Capturas: download/verificacion/v18_grafo_{escritorio,movil}.png + copia en docs/demo/05b-grafo{,-movil}.png.
- VALIDACIÓN: 204/204 pytest (8 nuevos en test_v18.py: dedup×4, guardia DNS×2, auto-baja×2), tsc 0, eslint 0, build producción OK, servicios 200 tras reinicio completo, api.log sin 500.
- DOCS: COMO_FUNCIONA.md ampliado (OSINT real, grafo, integraciones por API oficial y sección "Lo que NO es por diseño": C2 propio, AV evasion, AD completo, métricas fabricadas); DEMOSTRACION.md con sección 4b del grafo.
- EMPAQUETADO: v18 → download/orquesta-rt-plataforma-v18.zip (144 ficheros/2,7 MB, verificado por extracción: grafo.tsx, test_v18.py, docs/demo con grafo; sin usuarios.db/casos/token/.env; anti-secretos LIMPIO).

Stage Summary:
- La plataforma fue ejercitada COMO OPERADOR de punta a punta en vivo: el ciclo ofensivo completo con IA real (GLM-4.6), firmas humanas, custodia válida y coste contabilizado ($0.0092 por consulta de copiloto).
- Tres defectos reales corregidos en la raíz: duplicación de hallazgos al reanudar fases, falso positivo de postura de correo en dominios sin resolver y bloqueo de auto-baja que ensuciaba despliegues.
- Nueva capacidad: grafo de relaciones del caso — derivado solo de lo observado, con honestidad de huérfanos/aislados, en escritorio y móvil.
- docs/COMO_FUNCIONA.md deja por escrito qué es y qué NO es la plataforma (C2, AV evasion, AD): la respuesta honesta forma parte del repositorio.
- Entregable: download/orquesta-rt-plataforma-v18.zip.

---
Task ID: 11
Agent: main (Super Z)
Task: Auditoría honesta de capacidades (respuesta al operador) + implementación de cobertura AD ampliada y grafo de plantilla real (LDAP) + bugs de arranque

Work Log:
- Auditoría del código real con evidencia: LDAP real (ldap3), OSINT real (crt.sh/robots/wayback/HIBP interfaz), phishing SMTP real bajo ROE, C2 = adaptadores a APIs oficiales (Sliver gRPC/Mythic GraphQL/MSF MSG-RPC), purple team VECTR + Sigma anti-invención, webhooks v16 completos, analítica ATT&CK entre campañas v16, Navigator, razonador (cobertura/prioridades/plan/reflexión), copiloto IA.
- Implementado en integraciones/ldap.py: nuevos tipos de lectura real — empleados (displayName/title/department/mail/manager), asrep (UAC extensible 4194304), delegaciones (UAC 524288 + msDS-AllowedToDelegateTo), dcs (UAC 8192), politica (contraseñas/bloqueo con conversión FILETIME→días, hallada y corregida una errata de divisor gracias al test).
- Implementado construir_grafo_empleados(): grafo organizacional SOLO con relaciones declaradas (atributo manager), resolución DN exacto→CN, guardas de autociclo y de ciclos, niveles, departamentos, raíces honestas.
- Nuevo endpoint GET /api/integraciones/ldap/grafo (auth por middleware; requisito exacto si LDAP no configurado).
- Frontend: tipos GrafoPlantilla/NodoPlantilla, acción consultarPlantilla en store, nuevo componente consola/plantilla.tsx (organigrama SVG por niveles, chips de departamentos, estados honestos, sección plegada para no cargar la vista), montado en Integraciones; insignia derivada del estado real del despliegue.
- E2E REAL con servidor LDAP de verdad (ldaptor/Twisted, protocolo LDAP v3 por TCP :1389, scripts/ldap_prueba_e2e.py — fixture de verificación, no se empaqueta): bind+search reales, grafo con 5 personas, cadena jmaria→pgonzal→lortiz/cfdez, niveles 0/1/2, departamentos correctos; capturas en download/capturas/. Estado honesto verificado también (sin LDAP → requisito exacto).
- Bugs v19 hallados y corregidos: (1) carrera start.sh tras stop.sh — bind en uso + falso "en vivo" contra el moribundo → espera de puerto libre + logs/api.pid + verificación de identidad del proceso; (2) start.sh abortaba sin dejar guardián de consola vivo → el guardián se lanza ANTES de esperar y con doble desacoplamiento (subshell+nohup+&), patrón que además es el único que sobrevive al reciclaje del sandbox; (3) vistas globales (Integraciones/Cobertura/Técnicas/Equipo) quedaban bloqueadas sin caso activo → PESTAÑAS_GLOBALES en consola.tsx.
- Verificación estándar completa: 215/215 pytest (11 nuevos en test_v19.py), tsc OK, eslint OK, E2E navegador sin errores, móvil 390px overflow 0px.

Stage Summary:
- La plataforma responde con evidencia a la auditoría de capacidades; el grafo de empleados es real (LDAP del DC bajo ROE), la cobertura AD se amplía a AS-REP/delegaciones/DCs/política; la postura sobre AV evasion y persistencia (arsenal del operador + boundary + purple) se mantiene y se argumenta en la respuesta.
- start.sh/stop.sh ahora son a prueba de carreras y autorreparan la consola.
- Pendiente cola v11: nota demo GitHub con clips, explicación externa del proyecto, más pulido UI, investigación de mejoras.

---
Task ID: 20
Agent: main (Super Z)
Task: Ronda v20 — "debería de tener todo: AD completo, OSINT, phishing, AV evasion, persistencia, sigilo frente al blue team": Arsenal real (evasión verificada + persistencia real + AD ofensivo) bajo ROE, y respuesta a "qué más añadir y mejorar".

Work Log:
- NUEVOS MOTORES REALES: instalados yaram-python 4.5.4 (motor de firmas real del sector AV/EDR) e impacket 0.13.1 (estándar ofensivo Kerberos/SMB/DRSUAPI) en .venv y añadidos a platform/requirements.txt.
- PLATFORM/ORCHESTRATOR/EVASION.PY: generación de artefactos con transformaciones criptográficas REALES (AES-256-CBC con PBKDF2-HMAC-SHA256 100k iter, XOR en cascada, troceado de blobs base64 que rompe la firma de blobs largos, nombres aleatorios y basura controlada) + juego de 8 reglas YARA reales (EICAR, loaders PowerShell, parche AMSI con patrón de bytes B8 57 00 07 80, dumping de credenciales, blobs base64 >500, cabecera MZ, NOP sled, cadenas de persistencia) + escaneo antes/después + ROUND-TRIP REAL (el loader Python generado se ejecuta en subprocess y su SHA-256 reconstruido debe igualar el payload; PowerShell vía decodificador espejo del algoritmo .NET) + entropía de Shannon + IOCs. La "evasión verificada" SOLO se declara si detecciones=0 Y round-trip OK. Fix de primeras pasadas: eliminado generador muerto; el test E2E en vivo confirmó EICAR detectado→0 detecciones→round-trip OK.
- PLATFORM/ORCHESTRATOR/PERSISTENCIA.PY: persistencia REAL en el host del lab con 8 métodos ATT&CK: bashrc T1546.004 (bloque marcado + testigo), python_startup T1546.016 (.pth de UNA línea "import" — un try/except multilínea NO se ejecutaría: falso positivo evitado por diseño), systemd_user T1543.002 (unidad validada con systemd-analyze verify REAL), ssh_authorized_keys T1098.004 (par ed25519 real con cryptography, retirada selectiva que preserva claves ajenas), artefactos cron T1053.003 / Run Key T1547.001 / schtasks XML T1053.005 (generación con hash, honestidad sobre el runtime), c2_framework vía integraciones. Cada implante: implantar → VERIFICAR ACTIVACIÓN REAL (bash -i interactivo; el primer intento con bash -lc era un falso negativo corregido y documentado; arranque de intérprete en venv aislado real) → retirar con verificación de AUSENCIA. El implante es el wrapper completo (comando del operador + testigo): la prueba demuestra que el MECANISMO se ejecutó.
- PLATFORM/ORCHESTRATOR/AD.PY: kerberoasting (TGT→TGS reales por SPN con impacket, formato John para etype 23/17/18), asrep (AS-REQ sin preauth, patrón GetNPUsers), dcsync (DRSUAPI GetNCChanges por pipe SMB), pass_the_hash (SMBConnection.login con hash NT + prueba real listando compartidos), rutas_a_da (SOLO memberOf declarado — misma disciplina anti-inferencia). integraciones/ldap.py ampliado: LAPS (ms-Mcs-AdmPwd), gMSA (principalsAllowedToRetrieve), trusts. Sin DC: requisito exacto, jamás datos inventados.
- BOUNDARY: catálogo ampliado con 13 herramientas del arsenal (evasion.generar media+aprobación; evasion.escanear baja; persistencia.implantar alta ruido 40 con ventana+aprobación; verificar baja; retirar media sin firma — la higiene se fomenta; ad.dcsync crítica ruido 70; ad.pass_the_hash alta ruido 65; laps/gmsa/trusts/rutas_da lecturas) y 16 transportes nuevos registrados. Los endpoints del arsenal usan el MISMO MotorGuardrails: scope del ROE (127.0.0.1 debe estar en alcance), política, ventana, techo, firma humana exacta por hash tool+args, webhook de aprobación y evidencia con cadena de custodia (actor HUMANO con identidad real).
- API: 7 endpoints nuevos (/arsenal estado, /evasion, /evasion/escanear, /persistencia + /verificar + /retirar, /ad) con validación de entrada ANTES del boundary (nunca se crea una aprobación para un payload malformado: hash_nt exige 32 hex, dcsync exige DN).
- CONSOLA: nueva pestaña "Arsenal" en el grupo Campaña (icono Bomb), 3 secciones: Evasión (payload + método + formato → panel con detecciones ANTES/DESPUÉS, entropía, round-trip, descarga del artefacto y visor del loader), Persistencia (8 tarjetas con estado real e implantar/verificar/retirar), AD (8 acciones con host del ROE, resultados reales en JSON) + lista de artefactos custodiados con re-escaneo YARA desde la UI. Store: cargarArsenal/generarEvasion/escanearArtefactoEvasion/accionPersistencia/accionAD integrados con la cola de Aprobaciones (toast "firma requerida" → aprobar → re-invocar).
- TESTS: test_v20.py con 25 pruebas nuevas — evasión (EICAR real detectado, verificación con ejecución de subprocess, re-escaneo independiente, XOR/PS/binario, errores honestos, IOCs), persistencia (activación real de bashrc/.pth en venv aislado/systemd-analyze/SSH con retirada selectiva, idempotencia, estado limpio), AD (requisitos exactos, rutas a DA solo declaradas, scope), catálogo de boundary y API (401, flujo completo de aprobación→evidencia→custodia, persistencia real en raíz temporal con activo:true y ausencia_verificada). BUGS atrapados por los tests y corregidos: ruta de import de ldap (orchestrator.integraciones no existe), _en_scope devuelve bool (3 sitios), namespace Crypto/Cryptodome del venv, nombres del enum Fase, Row.get en arsenal_estado, hash_nt validado antes del boundary. SUITE COMPLETA: 240/240.
- E2E NAVEGADOR REAL (operador de verdad): login → caso "Arsenal v20 — Silencio operativo" (ROE 127.0.0.0/8 + lab.test) → Evasión con EICAR: el boundary pidió firma (insignia 1), aprobada con comentario desde la cola, re-generación → panel "evasión VERIFICADA · Detecciones ANTES (1) DESPUÉS (0) · entropía 4.872→5.855 · round-trip ejecución real del loader (subprocess)" → Persistencia bashrc: firma → implantado con "activo: true, ruta /home/z/.bashrc, prueba bash -i (shell interactivo real)" en UI → Verificar → Retirar con ausencia_verificada:true y "host limpio" → AD trusts/rutas_da: requisitos honestos visibles → auditoría: 10 eventos boundary+arsenal con decisiones correctas, 3 evidencias custodiadas → móvil 390px overflow 0 → 0 errores de página. Capturas: download/verificacion/v20_evasion_verificada.png, v20_arsenal_completo.png, v20_movil_390.png.
- LIMPIEZA: caso E2E borrado, operador e2e.v20 dado de baja firmada por el admin del despliegue (la protección de auto-baja funcionó), .bashrc sin bloques residuales y sin testigos, api.log sin 500.
- VALIDACIÓN: 240/240 pytest, tsc 0, eslint 0, servicios 200 tras reinicio, móvil overflow 0px.
- DOCS: COMO_FUNCIONA.md reescrito — "Lo que NO es por diseño" ya no incluye evasión/persistencia/AD; nueva sección "El arsenal ofensivo (v20)" con las reglas de verificación.
- EMPAQUETADO: v20 → download/orquesta-rt-plataforma-v20.zip (153 ficheros/2,8 MB, verificado por extracción: evasion.py/persistencia.py/ad.py/test_v20.py incluidos, bash -n OK, requirements con yara+impacket, sin usuarios.db/casos/.env, anti-secretos LIMPIO).

Stage Summary:
- La plataforma ya NO responde "No" a persistencia, evasión de AV ni AD completo: las tres capacidades son reales, verificables y quedan bajo el mismo boundary ROE/auditoría/evidencias que el resto — con la honestidad intacta (lo que no puede ejecutarse en el host se reporta como requisito o artefacto, jamás como éxito).
- La evasión dejó de ser una promesa: es una MEDICIÓN contra YARA real con round-trip criptográfico; la persistencia es implantar-verificar-retirar con prueba de activación real; el AD ofensivo usa impacket (kerberoasting/asrep/dcsync/PTH/LAPS/gMSA/trusts/rutas DA).
- OSINT (crt.sh/wayback/DNS/robots), grafo de empleados (LDAP real v19) y phishing (SMTP real con doble firma) ya estaban operativos desde rondas previas.
- Siguientes mejoras candidatas respondidas al operador: planificación threat-led (estilo Atomic Red Team), BloodHound CE, enriquecimiento MISP, RBAC multi-tenant, SSO, despliegue Docker productivo.
- Entregable: download/orquesta-rt-plataforma-v20.zip.

---
Task ID: 21
Agent: main (Super Z)
Task: Ronda v21 — threat-led (Atomic Red Team), RBAC multi-tenant, SSO OIDC, BloodHound CE, MISP, despliegue Docker/K8s productivo, pulido y E2E como operador.

Work Log:
- THREAT-LED (orchestrator/threatled.py): 4 cadenas estilo Atomic Red Team (intrusión AD de extremo a extremo 9 pasos, acceso web+postex 7, phishing guiado 6, evasión y sigilo 6). Regla anti-relleno validada en arranque y tests: cada paso referencia una herramienta REAL del boundary (guardrails._RIESGO_HERRAMIENTAS) o "manual"; el ruido del plan es el MISMO número que exigirá el guardrail. plan_para_caso() contrasta con técnicas ejercitadas del caso (hallazgos + auditoría, ids ATT&CK validados por regex) → estados ejercitado/disponible/manual. API: GET /threatled/cadenas, GET /cadenas/{id}, POST /engagements/{id}/threatled/plan (auditoría + evidencia custodiada con hash HMAC).
- RBAC MULTI-TENANT (auth.py + memory.py + models.py + api.py): roles jerárquicos admin(4)>gestor(3)>operador(2)>lector(1) con NIVEL_ROL; tabla organizaciones + columnas tenant_id/sso_sub con migración idempotente (ALTER guiado por table_info en usuarios.db Y en cada caso). JWT con claim firmado "ten". Middleware: escritura exige nivel ≥2 (deny-by-default: un endpoint nuevo de escritura queda protegido sin tocar su código; única excepción /api/auth/contrasena) + aislamiento de casos por regex de ruta (org distinta → 403; inexistente → 404). Listado de casos filtra por tenant salvo admin; crear asigna tenant del creador (admin puede cross-tenant). Endpoints: organizaciones (GET/POST), /auth/tenant, alta con tenant_id, auditoría de sistema en altas/altas de org/movimientos.
- SSO OIDC (orchestrator/sso.py): flujo authorization-code + PKCE S256, discovery con validación de issuer, canje en el token endpoint REAL, verificación criptográfica del id_token RS256 vía JWKS con stdlib puro (PKCS#1 v1.5: s^e mod n + comparación de padding DigestInfo SHA-256), validación iss/aud/exp/nonce, state de un solo uso con TTL y poda. Resolución de identidad: enlace por sso_sub, por nombre de cuenta local, o alta JIT como lector (hash inalcanzable para login por contraseña). Endpoints públicos: /auth/sso/estado|inicio|callback. La pantalla de acceso muestra el botón "Entrar con SSO" SOLO si el despliegue lo tiene configurado.
- BLOODHOUND CE (integraciones/bloodhound.py): cliente REST oficial real (login secret→session_token, available-domains, search, graph-analysis/shortest-path CE≥6, saved-queries) con httpx; rutas críticas resueltas por el SERVIDOR (la plataforma no recalcula el grafo); errores HTTP reales como requisito honesto.
- MISP (integraciones/misp.py): cliente oficial real (servers/getVersion, attributes/restSearch con limpieza de valores+techo 50, events/restSearch por tag, events/add para exportar hallazgos). Endpoint POST /engagements/{id}/threat-intel/enriquecer con custodia de coincidencias.
- DESPLIEGUE (platform/Dockerfile reescrito + .dockerignore + docker-compose.yml endurecido + deploy/k8s/*.yaml + deploy/README.md): BUG REAL corregido — el Dockerfile anterior NO copiaba integraciones/ (la imagen fallaba al importar ldap/impacket); ahora multi-stage, no-root (orquesta:999), HEALTHCHECK contra /api/salud, USUARIOS_DB=/datos/usuarios.db (antes las cuentas eran efímeras en el contenedor). Compose: no-new-privileges, límites de recursos, healthcheck de consola, CONSOLE_ORIGINS. K8s: namespace/ConfigMap/Secret con placeholders evidentes/PVC/deployments (runAsNonRoot, readOnlyRootFilesystem, drop ALL, sondas /api/salud, Recreate por SQLite RWO)/Services/Ingress TLS con timeouts SSE; README con decisiones (1 réplica orquestador vs 2 consolas, respaldo VACUUM INTO).
- TESTS (test_v21.py, 34 pruebas): threatled (catálogo vs boundary, plan honesto, filtrado de ids), RBAC (niveles, organizaciones, exigencia de org existente, aislamiento end-to-end con dos tokens, lector solo-lectura con su única escritura permitida, auditoría de altas), SSO con IdP fixture REAL sobre TCP (discovery+JWKS+token RS256 firmado con cryptography; flujo completo JIT, vinculación a cuenta local conservando rol, firma con 1 bit volteado detectada, state de un solo uso), BloodHound/MISP contra servidores fixture HTTP reales (protocolo completo, 404 honesto sin graph-analysis, limpieza de valores), plan por API con evidencia y cadena VÁLIDA, validación estructural Docker/K8s, regresión del bug de alta.
- BUGS HALLADOS EN EL PROPIO E2E: (1) entorno: certifi/cacert.pem inexistente en .venv rompía TODO httpx (hasta HTTP plano) — restaurado desde /etc/ssl/certs, documentado; (2) alias de integración: las tarjetas usan claves attack_paths/threat_intel que el backend no despachaba → 400; añadidos alias; (3) REGRESIÓN REAL: auth/registrar ignoraba tenant_id elegido porque la condición miraba el rol DESTINO en vez del peticionario — alta E2E de lector en org-e2e nació en predeterminada; corregido + test de regresión + verificado en vivo (lector.e2b en org-e2e).
- E2E COMO OPERADOR (navegador real): bootstrap → caso con ROE firmado → Cadenas: 4 tarjetas, plan contrastado 0 ejercitados/8 disponibles/1 manual (T1070.001 manual honesto) → hallazgo T1558.003 por API → re-contraste 1 ejercitado → Integraciones: tarjetas BloodHound/MISP/SSO con requisito exacto y prueba con error real → Equipo: organización org-e2e creada desde UI, alta de lector en esa org (chips rol/tenant/SSO) → API con token lector: cadenas 200, caso ajeno 403, escritura 403, listado vacío → móvil 390px overflow 0px en Panel/Cadenas/Integraciones/Equipo → 0 errores de página → limpieza total (caso y cuentas fuera, bootstrap reabierto). Capturas: download/verificacion/v21_{cadenas_plan,equipo_orgs,movil_390}.png.
- VALIDACIÓN: 274/274 pytest (240 previos + 34 v21), tsc 0, eslint 0, build producción OK, servicios 200 tras reinicios, api.log sin 500.
- DOCS: COMO_FUNCIONA.md sección v21; README enlaza deploy/README.md.

Stage Summary:
- La plataforma planifica como un equipo threat-led real: cadenas Atomic Red Team contrastadas contra la evidencia del caso, con el ruido prometido = ruido exigido.
- El control de acceso es de producto multi-tenant: 4 roles jerárquicos firmados en el JWT, organizaciones que aíslan casos en la API (no en el cliente) y SSO OIDC con verificación criptográfica del id_token.
- BloodHound y MISP hablan protocolo oficial con instancias reales del operador; sin ellas, requisito exacto.
- El despliegue Docker/K8s corrige un bug real del Dockerfile (integraciones/ ausente) y persiste las cuentas; manifiestos K8s con sondas y seguridad verificadas estructuralmente en tests.
- 3 bugs de ronda corregidos (certifi roto del entorno, alias de integración, tenant ignorado en alta) — 2 capturados por el E2E en vivo.
- Entregable: download/orquesta-rt-plataforma-v21.zip.

---
Task ID: 22
Agent: main (Super Z)
Task: Ronda v22 (continuación) — SSO federado E2E con Keycloak real, rutas de ataque con Neo4j real, NVD, subida del repo a GitHub privado + devcontainer Codespaces, bugs capturados por pruebas de operador, investigación de mejoras.

Work Log:
- GITHUB: historia nueva limpia (orphan, 215 ficheros) tras detectar .venv trackeada (8.881 ficheros) y binarios; .gitignore endurecido (.venv, lab/keycloak-*/, lab/neo4j-community-*/, lab/*admin.txt, lab/*.pid, lab/logs, lab/downloads, lab/env_laboratorio.sh, /skills/ del entorno, download/*.zip); .devcontainer/devcontainer.json (node 22 + python 3.12 + bun, postCreateCommand ./install.sh, puertos 3000/8000/8080/8081/7474/7687) → repo privado Ruby570bocadito/orquesta-rt creado por API y pusheado (devcontainer verificado en remoto). Advertencia al operador: rotar el PAT publicado en el chat.
- E2E SSO FEDERADO REAL (navegador): acceso → botón "Entrar con SSO del equipo" → redirect a Keycloak :8081 con PKCE S256 → login operador/Operador-Lab-2026 → callback con code → canje + verificación RS256 del id_token vía JWKS → sesión activa en consola como lector (JIT). Captura v22_sso_sesion_federada.png (ronda anterior) + flujo re-verificado tras reinicios.
- RUTAS DE ATAQUE E2E: Integraciones → sección Rutas: motor Neo4j conectado, orígenes reales del grafo (PGONZAL Manager IT, SVC_BACKUP), objetivos alto valor (DOMAIN ADMINS, IT-ADMINS, DC01) → 5 rutas renderizadas con nodos/aristas tal como las devuelve allShortestPaths. Captura v22_rutas_lector_federado.png.
- BUG 1 (capturado por E2E de operador): POST /integraciones/rutas → 403 para lector federado; el middleware RBAC v21 exige nivel ≥2 para TODO POST, pero calcular rutas es consulta pura al motor (sin mutación ni evidencias) → añadido a RUTAS_ESCRITURA_LECTOR + test de regresión (lector consulta rutas 200; crear caso sigue 403).
- BUG 2 (misma clase): POST /integraciones/nvd/enriquecer → 403 para lector; enriquecimiento CVE es LECTURA externa (API pública NVD) → añadido a la lista + test extendido.
- BUG 3 (UX, capturado por E2E): el backend responde {"detail": "..."} y la consola leía cuerpo.detalle → el operador veía "HTTP 403" crudo en vez del mensaje claro; api() de store.ts ahora lee detail/detalle/error. Además: botón "Nuevo engagement" oculto a lectores con nota ámbar "solo lectura" (verificado en vivo).
- BUG 4 (infra del reinicio): el venv quedó destruido por el reset --hard del reordenamiento git (venv trackeada en el histórico viejo) → ./install.sh idempotente la reconstruyó; detectado que matar logs/api.pid + start.sh en ventana de 3s NO reemplaza el proceso (SIGTERM graceful 5s): reinicio quirúrgico kill PID + esperar puerto libre + relanzar → verificado con PID nuevo.
- NVD E2E: "Apache 2.4.49" → CVE-2021-41773 y CVE-2021-42013 REALES del NIST (CRITICAL, CVSS 9.8) renderizados en la consola como lector federado. Captura v22_nvd_cves_reales.png.
- LAB: creado lab/neo4j_arrancar.sh idempotente (password inicial, conf de laboratorio con append único, espera HTTP) y lab/env_laboratorio.ejemplo.sh (plantilla sin secretos para el repo); verificado idempotencia en vivo ("Neo4j ya está en marcha").
- VALIDACIÓN: 290/290 pytest (289 + 2 nuevos, 1 renombrado), tsc 0, eslint 0, móvil 390px overflow 0px, 0 errores de página tras recarga limpia (los errores de Hooks previos eran artefactos del Fast Refresh al añadir hooks con el componente montado).
- LIMPIEZA: cuenta de diagnóstico lect.diag dada de baja; el usuario SSO del lab se conserva (auto-JIT).
- EMPAQUETADO: scripts/empaquetar.py → v22.zip con lab/ en LISTA BLANCA (6 ficheros de laboratorio, jamás env real ni credenciales) + .devcontainer; 175 ficheros/2.891 KB, anti-secretos LIMPIO, verificado por lectura del ZIP.
- INVESTIGACIÓN (web-search): (1) tendencia CTEM/AEV — simulación continua en bucle con delta entre ejecuciones (Picus/SCYTHE/Caldera); (2) agentes de red team IA comprimen semanas→horas (Dreadnode, arxiv 2026) — valida la orquestación existente; (3) BloodHound CE oficial vía docker-compose + Azure paths (AzureHound). Propuestas para siguiente ronda: modo continuo CTEM (programar cadenas, delta de cobertura y detecciones entre corridas), cierre del bucle purple (regla Sigma sugerida por hallazgo y validada contra detecciones), ingestión Azure/híbrido en el motor de rutas.

Stage Summary:
- El repo vive en GitHub privado con devcontainer: abrir en Codespace = ./install.sh + ./start.sh y todo levanta.
- El SSO federado es real de extremo a extremo y las pruebas de operador capturaron 3 bugs de integración RBAC/UI que ningún test unitario veía: los lectores federados ya consultan rutas y CVEs sin 403 falsos, y las denegaciones muestran su mensaje.
- El motor Neo4j del laboratorio sirve rutas de ataque reales con esquema BloodHound y el NVD completa el intel sin MISP.
- Entregables: repo Ruby570bocadito/orquesta-rt (main=c89152a+fixes) y download/orquesta-rt-plataforma-v22.zip.

---
Task ID: 23
Agent: main (Super Z)
Task: Ronda v23 — auditoría de estado + victorias rápidas (README real, CI GitHub Actions) + modo continuo CTEM (corridas con delta real entre corridas).

Work Log:
- AUDITORÍA SOLICITADA ("qué le falta"): verificado en vivo qué existía y qué no → README congelado en v9 (decía "13 tests", "lab simulado MOCK", 0 imágenes incrustadas), sin CI, sin modo continuo CTEM, MISP sin instancia de lab. Prioridades ejecutadas por orden.
- README REESCRITO (v22 real): badges (CI/Python/Next/pytest/licencia), GIF recorrido + 2 capturas incrustadas, capacidades reales en tabla (AD/persistencia/evasión/phishing/threat-led/rutas/SPO/multi-tenant/webhooks/purple/analítica), estructura de repo actualizada (27 módulos orquestador + integraciones + lab + deploy), arranque local/Codespaces/Docker/K8s/lab, seguridad del producto, roadmap honesto.
- CI (nueva): .github/workflows/ci.yml — job backend (pytest completo en Python 3.12 con cache pip) + job consola (bun install --frozen-lockfile, tsc --noEmit, eslint). Sin secretos.
- PUSH GITHUB: d35c7d6 → main en Ruby570bocadito/orquesta-rt con PAT transitorio en memoria (nunca en ficheros); recordatorio de rotación reiterado.
- CTEM (orchestrator/ctem.py nuevo): corrida = instantánea REAL del caso (técnicas ejercitadas de hallazgos+auditoría, detecciones VECTR por estado, hallazgos por severidad, aprobaciones pendientes, acciones boundary:permitir) contrastada con plan_para_caso + delta honesto contra la corrida anterior (nuevas técnicas/hallazgos/detecciones, cobertura antes→después; primera corrida declarada explícitamente). Programas persistentes (ctem_programas, intervalo 1-720 h, reprogramación idempotente), corridas con custodia (evidencia JSON hash+HMAC) y auditoría (Actor HUMANO manual / SISTEMA programada). Planificador del despliegue: bucle asyncio en lifespan (CTEM_SEGUNDOS, 60 s por defecto) ejecuta programas vencidos en TODOS los casos sin tumbar la API; fallo de una BD no detiene las demás.
- API v23: GET /engagements/{id}/ctem (lectura pura), POST .../ctem/programas (RBAC ≥2 automático), POST .../ctem/corridas (dispara webhook ctem.corrida a receptores suscritos), DELETE .../ctem/programas/{pid}; validación 404 cadena con guía, 422 intervalos, 404 caso. EVENTOS webhook ampliado con "ctem.corrida".
- UI: sección compacta "Continuidad (CTEM)" en Cadenas (menos cargada: integrada, no vista nueva) — selector cadena+intervalo, corrida ahora, programar, chips de programas activos con cancelar, delta del último resumen y últimas 5 corridas con evidencia. Store: cargarCtem/corridaCtem/programarCtem/cancelarCtem + tipos DeltaCtem/CorridaCtem/ProgramaCtem/EstadoCtem; toast de import añadido a store.ts (lo necesitaba por primera vez).
- TESTS (test_v23.py, 13): migración idempotente, primera corrida honesta, delta tras hallazgo real (T1558.003), delta de detecciones VECTR, auditoría+custodia con cadena VÁLIDA, validación de intervalos y cadena fantasma, planificador ejecuta SOLO lo vencido y desplaza proxima_corrida_en, cancelar conserva historial, flujo API completo, 404/422, RBAC lector (GET 200; corrida/programar/cancelar 403), evento webhook ctem.corrida en catálogo y validación de eventos inventados.
- BUG CORREGIDO EN CONSTRUCCIÓN: filtro de acciones ejecutadas usaba resultado "aprobado" (inexistente) — el valor real del boundary para ejecución es "permitir"; corregido con comentario que lo documenta.
- VALIDACIÓN: 303/303 pytest (290 + 13 v23), tsc 0, eslint 0, reinicio quirúrgico del orquestador (PID nuevo), /api/salud ok, endpoints CTEM en vivo 401 sin identidad (protección activa), api.log sin 500. E2E de navegador completo NO ejecutado en esta ronda (credenciales del admin no disponibles en contexto); la API está cubierta por la suite completa con TestClient.
- EMPAQUETADO: scripts/empaquetar.py → download/orquesta-rt-plataforma-v23.zip (verificado anti-secretos).

Stage Summary:
- La plataforma ahora compite en el eje que define el sector (CTEM/AEV): la exposición se mide continuamente con delta real entre corridas, no con informes puntuales.
- El escaparate (README) muestra por fin lo que el proyecto ES, con el GIF y capturas reales de la demo; la CI ejecuta 303 tests en cada push.
- Siguiente: instancia MISP de lab (docker-compose.lab.yml), ingestión del dominio real del usuario al motor Neo4j, validación Sigma en vivo.

---
Task ID: z3-sesion-1
Agent: z3 (agente de revisión de código y seguridad)
Task: Auditoría integral de seguridad de orquesta-rt (bug + security review), remediación profesional y documentación en docs/agentes/z3.md

Work Log:
- Revisión completa de la superficie de seguridad: auth.py, sso.py, api.py (2839 líneas), webhook.py, memory.py, transportes.py, guardrails.py, proxy Next.js, puente IA, instrumentation.ts, docker-compose, Caddyfile, .gitignore y BDs del repo. Lo sólido verificado y documentado (JWT HS256, scrypt, PKCE+RS256 del SSO, guardrails de alcance, doble verificación de scope).
- F1 CRÍTICO: usuarios.db (secreto JWT + hash admin) y 10 BDs de casos publicadas en el repo público → .gitignore + git rm --cached; guía de rotación y purge de historial en docs/agentes/z3.md.
- F2 ALTO: Caddyfile :81 era un proxy abierto a cualquier puerto local vía ?XTransformPort= (SSRF a vLLM/orquestador/lab) → handler eliminado.
- F3 ALTO (BOLA): POST /api/aprobaciones/{id}/decision ignoraba el tenant → operador de una organización podía firmar aprobaciones de casos de otra. Ahora filtra por tenant (admin cross-tenant). Verificado E2E (404 cross-tenant / 200 dueño).
- F4 ALTO: JWTs sin revocación (cuenta eliminada/degradada/restablecida seguía viva 12 h) → columna migrada invalidar_antes + auth.sesion_viva() en middleware con caché TTL 15 s; invalidación disparada por cambiar/restablecer contraseña, cambiar rol, mover tenant y baja de cuenta.
- F5 ALTO: CLAVE_CASO hardcodeada en instrumentation.ts (falsificación de cadena de custodia) → clave aleatoria de 256 bits persistida en db/clave-caso (0600) + verificación con claves legadas (CLAVES_CASO_LEGADO) para no invalidar evidencias existentes; las nuevas siempre se firman con la clave vigente.
- F6 MEDIO (SSRF webhook): follow_redirects=False (302 ya no salta la vetación) + vetación por IP literal (ipaddress) de metadatos AWS/GCP/Azure/Alibaba/Oracle + escape WEBHOOK_PERMITIR_METADATOS; loopback se mantiene permitido (test v16 lo exige: n8n on-prem).
- F7 MEDIO: limitador de tasa usaba el PRIMER salto de XFF (controlado por el cliente) → último salto; compose publica 8000 solo en 127.0.0.1.
- F8 MEDIO: inyección de fórmulas CSV en hallazgos.csv y cobertura CSV → sanitización = + - @ \t \r con apóstrofe.
- F9/F10: CORS default * → http://localhost:3000; CSP de refuerzo (object-src/base-uri/frame-ancestors/form-action) en next.config.ts.
- Verificación: 285 passed / 8 skipped (10 fallos preexistentes por deps opcionales ausentes, idénticos con git stash sobre el commit base); script funcional de los fixes 7/7 en verde; TS sin errores de sintaxis.
- Documentación completa en docs/agentes/z3.md (hallazgos, evidencia, soluciones, pendientes de rotación) + recomendaciones P2 sin cambio de código (TLS verify=False configurable, vinculación SSO por nombre, JWT en localStorage, estado en memoria mono-proceso).

Stage Summary:
- 5 hallazgos críticos/altos + 5 medios remediados con backwards-compat (migraciones idempotentes, clave legada de custodia, tests existentes en verde).
- ACCIONES PENDIENTES DEL EQUIPO: rotar secreto_jwt (publicado), tratar datos de casos publicados como brecha, y decidir purge de historial git (filter-repo + force-push).
- Detalle completo en docs/agentes/z3.md.

---
Task ID: z3-sesion-2
Agent: z3 (agente de revisión de código y seguridad)
Task: Profundización de la auditoría (remediación de P2 de la sesión 1 + nuevas superficies), fixes profesionales, tests de regresión y publicación en GitHub

Work Log:
- Superficies revisadas a fondo: platform/integraciones/ (metasploit, bloodhound, mythic, misp, smtp_envio, nvd, rutas), platform/mcp/ (recon, osint, evidencias, c2_adapter), transportes.py completo, respaldo.py, sidecar.py, evasion.py, ad.py, persistencia.py, middleware/RUTAS_PUBLICAS y /api/salud en api.py. Lo sólido verificado y documentado (Cypher parametrizado, SQL del webhook controlado, validador de dominios del ROE, EmailMessage anti header-injection, MCP stdio no expuestos).
- F11 MEDIO: 17 clientes HTTP con verify=False hardcodeado (los de infraestructura propia viajan con credenciales) → integraciones MSF/BloodHound/Mythic verifican POR DEFECTO con escape consciente (*_TLS_VERIFICAR=0); recon/OSINT con política centralizada transportes.verificar_tls()/_cliente_http() + RECON_TLS_ESTRICTO=1; servidores MCP importan la misma política.
- F12 ALTO: secuestro de cuentas vía SSO (preferred_username coincidente heredaba el rol local, p. ej. admin) → vínculo de cuentas gestor/admin exige pre-aprobación explícita (nueva tabla sso_vinculos_preaprobados con caducidad 30 días, comandos CLI sso-preaprobar/sso-vinculos, auditoría sso.preaprobacion/vinculo/alta_jit); OIDC_DOMINIOS_PERMITIDOS exige email federado verificado para altas y vínculos; lector/operador sin variables nuevas: comportamiento intacto.
- F13 MEDIO: /api/salud pública devolvía estado_backends() completo (URLs de backends IA, modelos, rutas de BDs) → anónimo recibe solo {estado, servicio, version}; detalle completo solo con Bearer vivo (HEALTHCHECK y sidecar no se afectan).
- F14 MEDIO: STARTTLS SMTP sin contexto → create_default_context() por defecto, escape SMTP_TLS_SIN_VERIFICAR=1 para labs.
- F15 BAJO: guardia de inyección de argumentos en nmap (objetivo que empieza por '-'); el validador del ROE ya era la defensa primaria, el transporte ahora también.
- F16 BAJO: platform/.env.example era referenciado por README/compose pero nunca existió en el repo → creado SIN secretos con catálogo completo de variables + excepción en .gitignore.
- Tests: platform/tests/test_z3_sesion2.py (17 casos, httpx.Client interceptado para afirmar el verify real, sin red saliente) → 17/17; suite completa 302 passed / 8 skipped con los 10 fallos preexistentes del entorno (yara/ldap3 ausentes), cero regresiones.
- Documentación: sección Sesión 2 en docs/agentes/z3.md (acumulativa, sin tocar la sesión 1) y nueva entrada en este worklog.
- Publicación: commit en rama z3/auditoria-seguridad-sesion1 (incluye sesión 1 + 2), push a origin y fast-forward de main para integrar los fixes.

Stage Summary:
- Sesión 2: 1 hallazgo ALTO (SSO account takeover) + 3 MEDIOS + 2 BAJOS remediados; todas las recomendaciones P2 de la sesión 1 quedan cerradas o mitigadas.
- La plataforma queda con TLS seguro por defecto en integraciones con credenciales, SSO inmune al registro previo de nombres en el IdP y sin fugas de topología en endpoints públicos.
- Siguientes sugeridas por z3: definir OIDC_DOMINIOS_PERMITIDOS en producción, evaluar purge de historial git (BDs publicadas en sesión 1) y mover el JWT de localStorage a cookie httpOnly a medio plazo.

---
Task ID: 24
Agent: z1 (agente colaborador, bitácora en docs/agentes/z1.md)
Task: Ronda v24 — threat intel de laboratorio (servidor MISP compatible con la API real) + validación Sigma en vivo (veredicto estructural antes de entregar reglas).

Work Log:
- AUDITORÍA DE PARTIDA: leído worklog completo (23 rondas) y verificado en vivo lo pendiente de v23: MISP de lab, validación Sigma en vivo, ingestión Neo4j del dominio real. Los dos primeros eran ejecutables end-to-end en esta ronda; el tercero requiere infraestructura del operador.
- INVESTIGACIÓN (opciones MISP de lab): (1) contenedor misp-docker real — descartado por defecto (MySQL+PHP+workers, varios GB, mata la agilidad del lab); (2) mock en el conector — contra la política anti-invención del proyecto; (3) ELEGIDO servidor HTTP que implementa el subconjunto REAL del protocolo MISP que consume el conector (patrón servidor_lab.py): el cliente misp.py no cambia una línea y habla el protocolo completo (auth por cabecera, response.Attribute, filtro timestamp "Nd") sobre sockets de verdad.
- MISP DE LAB (platform/lab/servidor_misp_lab.py, nuevo): getVersion, attributes/restSearch, events/restSearch, events/add; intel semilla ACME coherente con el objetivo nginx del lab; persistencia opcional JSON (--estado); escucha localhost por defecto; docker-compose.lab.yml añade servicio lab-misp (python:3.12-alpine, :8444→9000, volumen de estado) sin Dockerfile nuevo.
- SIGMA VALID (platform/orchestrator/sigma_valid.py, nuevo): validar_regla/validar_lote — validación estructural sin dependencias (YAML parseable, id UUID, logsource con category/product/service, detection con selecciones, condición que solo referencia selecciones existentes incluida sintaxis oficial "1 of selection*" y "all of them") + motor profundo OPCIONAL pySigma (import perezoso, declarado honestamente en motor_profundo). Higiene (tag sin namespace, falta attack.tXXXX, level ausente) como avisos, no errores.
- PURPLE TEAM INTEGRADO: extraído reglas_sigma_caso() como generador compartido (paquete purple y endpoint jamás diverjen); construir_paquete_purple ahora valida las reglas ANTES de entregar, incluye sigma/validacion.md con el veredicto por regla, declara "Validación Sigma (v24): N de M…" en el informe y añade sigma_validas/sigma_invalidas al resumen (contrato extendido; test v15 actualizado en consecuencia).
- API v24: POST /api/engagements/{id}/sigma/validar — veredicto por regla + técnicas sin fuente + motor usado; acción auditable caso.sigma_validar; RBAC nivel ≥2 por el middleware (lector 403, verificado).
- TESTS (test_v24.py, 19): MISP lab E2E real en hilo (versión, coincidencia IOCs semilla, valores inválidos rechazados, eventos por tag, export hallazgo + round-trip de búsqueda, clave errónea 403, persistencia JSON), validador (regla válida, selección fantasma, YAML roto, UUID falso, logsource insuficiente, comodines/cuantificadores, tags inválidos/aviso sin ATT&CK, lote agregado), integración purple (reglas del caso válidas, ZIP con validacion.md, T9999 sin fuente no genera inventos), API (flujo 200, caso vacío total 0, 404 fantasma, RBAC lector).
- BUG DE SUITE DETECTADO Y CORREGIDO: test_v24 corre alfabéticamente ANTES que test_v7 y sus llamadas a /api/auth/registrar contaminaban la ventana deslizante del _LimitadorTasa (429 falso en test_v7). El fixture de v24 sustituye el singleton por una instancia fresca (monkeypatch restaura). Aislamiento por test, espíritu del fix _intentos de v23.
- VALIDACIÓN: pytest 304 passed (285 baseline + 19 v24); baseline pre-existente verificado con git stash + doble pasada (10 fallos de entorno: test_v20 sin yara/ módulos del venv local, ldap/nvd honestos por entorno) y diff de listas de fallos = VACÍO — mis cambios rompen 0 tests. tsc 0, eslint 0. Compose de lab parseable.
- DOCUMENTACIÓN: creada docs/agentes/z1.md (bitácora del agente: misión, auditoría, razonamiento de opciones, implementación, decisiones con fundamento, propuestas) y este registro. README actualizado (threat intel de lab + validación Sigma).

Stage Summary:
- El enriquecimiento threat-intel es ahora ejercitable de extremo a extremo en cualquier laboratorio: `MISP_URL=http://localhost:8444 MISP_KEY=clave-lab-misp` y el conector oficial habla con un servidor real del protocolo MISP.
- Las reglas Sigma del paquete purple llegan con veredicto auditable dentro del ZIP: detection-as-code verificable en el momento de la entrega.
- Siguiente (propuestas en docs/agentes/z1.md): UI de validación en consola, guion E2E del enriquecimiento con el lab, ingestión del dominio real al motor Neo4j y cierre CTEM↔purple↔Sigma.

---
Task ID: 25
Agent: z1 (agente colaborador, bitácora en docs/agentes/z1/)
Task: Ronda v25 — re-implementación y publicación del escudo anti-inyección indirecta OWASP LLM01:2025 en el copiloto (recuperado de una sesión previa no publicada), UI de validación Sigma en la consola, MISP de lab en la plantilla de entorno y reorganización de la bitácora del agente en docs/agentes/z1/ con todas las sesiones.

Work Log:
- AUDITORÍA DE PARTIDA: sincronizado con origin (main @ 11be212, v24 + fixes z3). Verificado en vivo: (a) el escudo LLM01 de la primera sesión NO está en el repo (trabajo no publicado; la revocación de sesión sí quedó cubierta por z3-F4 con otro diseño — se documenta y se descarta la variante propia); (b) el endpoint sigma/validar de v24 no tenía UI; (c) la plantilla de entorno no documentaba el MISP de lab y pySigma no figuraba como opcional.
- ESCUDO LLM01 (copiloto.py): regla 8 del SISTEMA declara el canal <<RAG>>…<</RAG>> como NO CONFIABLE; _FAMILIAS_INYECCION con 8 heurísticas (sobreescritura, cambio de rol, falso sistema <|im_start|>/[INST]/system:, falso JSON con sugerencias, exfiltración verbo+secreto, manipulación ROE/informe, falso cierre de contexto, suplantación de hablante) en español e inglés; _COMBINADO_INYECCION un solo pase (sin re-marcado anidado); _blindar_fragmento marca en línea ⟨dato⟩ SIN borrar evidencia (quitar decoraciones recupera el texto EXACTO, con test que lo exige); construir_contexto delimita cada fragmento y añade línea honesta "ESCUDO LLM01: N patrón(es)" solo si hubo marcas. Truncado antes de marcar para que la marca siempre quede bien formada (riesgo residual del corte documentado).
- UI SIGMA (manejo del usuario web): tipos.ts (VeredictoSigma/ReglaVeredictoSigma), store.ts (validarSigmaCaso vía api<T>), datos.tsx: PanelSigma en Hallazgos junto a la tira purple — botón Validar, resumen N de M + motor + técnicas sin fuente, veredicto por regla con errores (bloquean) y avisos (educan), error inline para RBAC 403 (el lector ve el mensaje del permiso que falta).
- LAB: lab/env_laboratorio.ejemplo.sh con bloque MISP DE LABORATORIO (MISP_URL=http://localhost:8444, clave-lab-misp, MISP_SSL=0 + comando compose); requirements.txt con # pysigma>=0.29 opcional (patrón sliver-py/chromadb).
- TESTS (test_v25.py, 17): 8 familias × (marca única + fidelidad exacta), benigno intacto, multi-familia sin anidamiento, variaciones caso/acentos, falsas coincidencias legítimas sin marcar («ignora el certificado», «excluido del alcance»), delimitadores en contexto, línea ESCUDO solo con marcas, sin coincidencias honesto, regla 8 en SISTEMA.
- VALIDACIÓN: suite completa 338 passed / 8 skipped / 10 failed con diff de fallos contra baseline (git stash + doble pasada) = VACÍO (cero regresiones); tsc 0; eslint 0 en ficheros tocados.
- DOCUMENTACIÓN: README (roadmap v25: escudo LLM01 + UI Sigma + MISP lab), bitácora REORGANIZADA a docs/agentes/z1/ (README + sesion-01-primeras-rondas.md + sesion-02-v25-*.md) con z1.md como índice de rastro, y este registro.
Stage Summary:
- El copiloto queda blindado contra inyección indirecta (LLM01:2025) con la estrategia OWASP de spotlighting: separación de canal + marcado de patrones + anti-invención (la evidencia no se destruye, se anota).
- El operador valida las reglas Sigma desde la consola con veredicto por regla, cerrando la propuesta nº 1 de v24; el lab MISP queda documentado en la puerta de entrada del despliegue.
- Bitácora del agente reorganizada según instrucción del operador: docs/agentes/z1/ contiene TODAS las sesiones (una por fichero).
- Siguiente (propuestas en docs/agentes/z1/sesion-02): endurecer _partir_estructura frente a eco de JSON, ingestión Neo4j del dominio real, bucle CTEM↔purple↔Sigma y panel de sesiones de usuario en la consola.

---
Task ID: 26
Agent: z3 (agente de auditoría de seguridad, bitácora en docs/agentes/agente-z3/)
Task: Sesión 3 — tercera ronda de auditoría sobre main v24 (MISP lab + Sigma), remediación F17-F24, tests de regresión y reorganización documental (carpeta docs/agentes/agente-z3/).

Work Log:
- SINCRONIZACIÓN: main actualizado a 11be212 (v24) y rama z3/auditoria-seguridad-sesion3 creada desde ahí. Leído el worklog completo y docs/agentes/ (z1.md de otro agente NO tocado).
- RONDA 1 (código v24): servidor_misp_lab.py y sigma_valid.py completos, endpoint /sigma/validar (verificado: middleware RBAC nivel 2 + aislamiento tenant via _RE_ENGAGEMENT + auditoría), cambios purpleteam.py y docker-compose.lab.yml.
- RONDA 2 (módulos nunca auditados): copiloto, razonador, ctem, threatled, navigator, busqueda, state, reporting completos + misp.py real. Constancia de lo revisado y OK (SQL parametrizado, catálogo real anti-invención, safe_load, etc.).
- RONDA 3 (transversal): inventario completo de rutas API fuera de /api/engagements (no hay más BOLA), skills.ver_skill sin path traversal (índice en memoria), puertos publicados de ambos compose.
- F17 (MEDIO, bug): reporting.construir_informe usaba h.get("tecnica") en vez de "tecnica_mitre" → el informe markdown perdía SIEMPRE el mapeo MITRE ATT&CK (el HTML sí lo tenía). Corregido + test.
- F18 (MEDIO): servidor_misp_lab leía el cuerpo sin techo → OOM con Content-Length gigante. Techo 5 MB verificado antes de leer + 413; Content-Length no numérica → 400. Test con socket crudo (cabecera sin cuerpo).
- F19 (MEDIO): int() sin capturar (limit/threat_level_id/analysis) mataban la hebra del manejador sin respuesta. _entero_seguro() con rangos oficiales MISP (limit 1-10000, threat 1-4, analysis 0-2) + guardia global 500 JSON. Test: basura → 200 acotado y servidor vivo.
- F20 (BAJO): comparación de clave API en tiempo no constante → hmac.compare_digest. Test 403/200.
- F21 (BAJO): persistencia de estado no atómica → temp + fsync + os.replace. Test: JSON válido y sin .tmp residuales.
- F22 (BAJO, endurecimiento): binds 0.0.0.0 en lab-misp (clave débil por defecto), lab-objetivo y vLLM (SIN auth) → todos a 127.0.0.1 con comentarios de cómo exponer legítimamente. Conectividad backend↔lab/vLLM intacta (red docker o loopback).
- F23 (BAJO, bug): colisión {tecnica}-{slug}.yml en el paquete purple → entradas duplicadas en el ZIP y regla perdida en la validación ("1 de 1" con 2 ficheros). _nombres_sigma_unicos() con sufijo -2/-3 compartido por validación y ZIP. Tests: helper + ZIP E2E con dos hallazgos colisionados.
- F24 (BAJO): _extraer_identificadores devolvía duplicados → errores repetidos en el veredicto Sigma. Dedup con orden. Test.
- TESTS: nuevo test_z3_sesion3.py (8 casos, 8/8 verde). Suite completa: 329 passed, 8 skipped, 10 failed — los 10 fallos son los preexistentes del entorno de auditoría (yara/ldap3 no instalados; mismos nombres confirmados sobre commit base en sesiones 1-2). Cero regresiones. py_compile de los 4 ficheros + yaml.safe_load de ambos compose OK.
- DOCUMENTACIÓN (petición del operador): creada docs/agentes/agente-z3/ con README (índice + metodología + tabla F1-F24), sesion-1, sesion-2 y sesion-3. docs/agentes/z3.md convertido en puntero (sin perder historial, sin tocar z1.md).

Stage Summary:
- 8 hallazgos nuevos remediados con tests (F17-F24); total acumulado z3: 24 fixes de seguridad/robustez en 3 sesiones.
- El servidor MISP de lab ya no puede ser tumbado por volumen (413), basura en parámetros (400/200 acotado) ni muertes silenciosas de hebra; su estado sobrevive a cortes atómicamente.
- vLLM sin auth y el intel del lab ya no quedan a la escucha en todas las interfaces.
- El paquete purple es determinista ante hallazgos homónimos y el informe markdown vuelve a citar ATT&CK como el HTML.
- Documentación del agente reorganizada en docs/agentes/agente-z3/ (todas las auditorías juntas, una por sesión).
---
---
Task ID: 24 (Z2-ronda-1)
Agent: Z2 (pulimiento de funciones y mecánicas)
Task: Misión continua de pulimiento: auditoría de mecánicas del núcleo, corrección de defectos verificados y documentación en docs/agentes/z2.md.

Work Log:
- LECTURA de worklog y docs previos (v1→v23) + suite completa ANTES de tocar nada: 295 passed / 8 skipped.
- AUDITORÍA: barrido del backend (orchestrator/, integraciones/, mcp/) + verificación manual de cada hallazgo. 15 defectos concretos (fail-open, TOCTOU, carreras, contratos incumplidos, TLS con credenciales, env divergente).
- BOUNDARY (guardrails/models/razonador): ventana horaria fail-CLOSED + validación HH:MM/días en el modelo (422 accionable); ventanas que cruzan medianoche soportadas (herencia del día inicial), mismas reglas en _ventana_abierta; techo de ruido sin la exención arbitraria ruido>30 (todo ruido cuenta), margen documentado _MARGEN_TECHO_RUIDO=5 y aviso al cruzar el nivel pactado; condición muerta del motivo "no catalogada" corregida (lee el spec).
- CUSTODIA (memory.py): guardar_evidencia con BEGIN IMMEDIATE (adiós a las "rupturas de encadenamiento" falsas por escritura concurrente); encadenado/verificación por ROWID (el orden creado_en era frágil bajo concurrencia — hallado por el nuevo test de 8 hilos); dedup de hallazgos devuelve la ORIGINAL (adiós a ids fantasma en webhooks); cifrado_reposo → clave_hmac_activa (honesto: CLAVE_CASO firma HMAC, no cifra la BD).
- WEBHOOKS: reintento ante error de red reparado (contrato documentado lo exigía); sin sleep residual; SSRF en 3 capas (nombres de metadatos ampliados + IP directa normalizada + IP resuelta por DNS; receptores del lab en 127.0.0.1 intactos).
- PLANIFICADOR CTEM: TypeError (timestamp naive) capturado — antes mataba TODO el barrido en silencio para siempre; claim atómico del programa (adiós a corridas duplicadas por ticks solapados); cadena desconocida se cancela con warning (antes giraba en falso eterno); logging del bucle en api.py.
- API/AUTH: decidir() con aislamiento multi-tenant y carrera de decisión resuelta (RETURNING; perdedor 404 sin auditoría fantasma); /api/salud usa auth.RUTA_DB (env DB_USUARIOS era errónea: "degradado" falso en producción); /api/auth/operadores solo admin (cross-tenant de metadatos); SSO seguro por defecto (la homonimia ya NO enlaza cuentas: flag SSO_VINCULAR_POR_NOMBRE=1 o endpoint admin POST /api/auth/sso/vincular, auditado) — cierra la toma de cuenta por preferred_username.
- INTEGRACIONES/RESPALDO/HIGIENE: TLS verificado por defecto en metasploit/mythic/bloodhound (opt-out *_TLS_VERIFICAR=0; transportes/MCP intactos: lab sin credenciales); respaldo con glob *.db (las BDs de ids antiguos ya no se pierden); sidecar con with open.
- TESTS (+30): test_v24_z2.py (28) + 2 en test_v21 + ajuste en test_razonador. Cubren cada defecto como contrato, incluida concurrencia real de custodia y claim del planificador.
- VALIDACIÓN: 325 passed / 8 skipped (0 fallos), tsc 0, eslint 0, smoke en vivo /api/salud → ok. Fragilidad detectada y mitigada: limitador de login compartido en el proceso de tests (fixture Z2 con limitador fresco).
- DOCUMENTACIÓN: docs/agentes/z2.md (registro completo de la ronda, notas de despliegue y propuestas para la siguiente ronda).

Stage Summary:
- Las mecánicas que definen el producto (boundary ROE, cadena de custodia, planificador continuo, webhooks firmados, SSO/RBAC) quedan alineadas con sus contratos documentados y libres de las carreras/fail-open hallados; cada corrección lleva su test.
- Despliegue: si usabas vinculación SSO por nombre, activa SSO_VINCULAR_POR_NOMBRE=1 o usa el nuevo endpoint admin; si tus C2/intel van con certificado autofirmado, define la var *_TLS_VERIFICAR=0 correspondiente.
- Siguiente ronda propuesta (en docs/agentes/z2.md): fixture autouse para el limitador de login en tests, re-verificación SSRF en despacho, verificador de cadenas históricas tolerante, SQLCipher y panel del presupuesto de ruido.

---
Task ID: 27
Agent: z1 (agente colaborador, bitácora en docs/agentes/z1/)
Task: Ronda v26 — cierre del eco de JSON en el copiloto (mitad estructural de la regla 8, riesgo residual documentado del escudo LLM01 de v25) y panel de higiene de la propia cuenta en la consola (manejo del usuario web sobre el mecanismo de revocación z3-F4). Todos los commits en main, push continuo.

Work Log:
- AUDITORÍA DE PARTIDA: sincronizado con origin (main @ c9ba451, v25 + rondas 2-3 de z2 + sesión 3 de z3). Re-evaluadas las 4 propuestas de mi sesión 02 contra el código real: (1) eco de JSON sigue abierto (copiloto usa _extraer_json "último que parsea"), (4) higiene de cuenta sigue sin superficie de usuario (invalidar_antes existe pero solo se toca por cambios administrativos). Descartadas por alcance: ingestión Neo4j (requiere operador) y bucle CTEM↔Sigma (ronda propia).
- CIERRE DEL ECO DE JSON (copiloto.py): regla 5b del SISTEMA (el bloque es la ÚLTIMA palabra; los JSON del dato jamás se replican); _CANALES_VALIDOS = fases F0-F7 + aprobacion + informe; _normalizar_bloque (sin marcas ⟦dato⟧⟨⟩ + espacio colapsado); _candidatos_json (cercados en orden + fallback JSON desnudo, inválido jamás fabrica); _es_eco_de_datos (procedencia: bloque ya presente en el contexto entregado = DATO, se descarta); _elegir_bloque_sano (de último a primero, None si no hay sano → sugerencias vacías); _partir_estructura(texto, contexto="") clampa canal desconocido a aprobacion; consultar() entrega datos["contexto"] a la selección. Import _extraer_json retirado. Retrocompatible: contexto vacío = comportamiento clásico.
- HIGIENE DE CUENTA (auth.py + api.py): auth.higiene_cuenta (estado vivo sin material sensible) y auth.revocar_sesiones_propias (corte a ahora SIN tocar credencial + invalidación de caché de sesión); GET /api/auth/higiene (cualquier rol autenticado: estado vivo + identidad del token: iat, exp, segundos restantes, sesion_valida según z3-F4) y POST /api/auth/sesion/cerrar-todas (sign-out-everywhere propio, rate-limited, auditado como sesion.cierre_global). Nota de diseño documentada: corte flotante vs iat truncado → re-login en el MISMO segundo muere (fail-closed, heredado de z3-F4; los tests esperan ~1 s).
- UI (manejo del usuario web): tipos.ts (HigieneToken/HigieneCuenta), store.ts (obtenerHigiene + cerrarSesionesPropias que reutiliza cerrarSesion local), higiene.tsx NUEVO (diálogo con identidad/rol vigentes, alta/último acceso, sesión válida/revocada, caducidad con cuenta atrás, corte de revocación, botón "Cerrar en todos los dispositivos" con AlertDialog que advierte que también muere esta pestaña y que la contraseña no cambia; carga fresca por apertura), consola.tsx (chip de sesión de BarraSuperior clicable; logout ordinario se conserva; estado local de la cabecera).
- TESTS (test_v26.py, 32): copiloto — eco verbatim al final no gana, solo-eco → vacías con prosa intacta, eco con decoraciones descartado, insensible a reformateo, bloque-propio similar sin falso positivo, sin contexto clásico, canal desconocido → aprobacion, 10 canales del contrato, JSON desnudo, JSON inválido, eco partido, regla 5b en prompt, consultar pasa contexto; higiene — estado vivo sin hash, fantasma None, revocación mata token al instante y conserva credencial, 401 sin sesión en ambas rutas, lector consulta la suya, rol vivo ≠ claim congela token, cerrar-todas + re-login OK, auditoría con actor.
- VALIDACIÓN: suite completa 413 passed / 8 skipped / 10 failed con diff de fallos contra worktree del commit pre-v26 (c9ba451) = VACÍO (los 10: yara/ldap3/nvd del entorno; mismos nombres que el baseline de v24/v25/z3). Suites v25+z3 re-ejecutadas juntas: 92 passed. tsc 0; eslint 0 en ficheros tocados.
- DOCUMENTACIÓN: README roadmap "Completado en v26"; docs/agentes/z1/sesion-03-v26-eco-json-higiene-cuenta.md (auditoría, razonamiento, implementación, decisiones, validación, propuestas); índice de docs/agentes/z1/ y puntero z1.md actualizados; este registro.
Stage Summary:
- La inyección indirecta LLM01 queda defendida en AMBOS canales: entrada (spotlighting v25) y salida estructurada (procedencia del bloque + contrato de canales v26). El eco verbatim del dato —el escenario realista— ya no puede aportar sugerencias aunque el modelo desobedezca la regla 8.
- El operador ve y gobierna SU sesión desde la consola: estado vivo frente al middleware de revocación y "cerrar en todos los dispositivos" con un clic, auditado y sin tocar la credencial.
- Siguiente (propuestas en docs/agentes/z1/sesion-03): bucle CTEM↔purple↔Sigma (ronda propia), aviso de caducidad próxima en la higiene, transparencia del escudo en la respuesta del copiloto, ingestión Neo4j con el operador.

---
Task ID: 28 (Z2-ronda-3)
Agent: Z2 (pulimiento de funciones y mecánicas del proyecto orquesta-rt)
Task: Ronda 3 de pulimiento — las 4 propuestas investigadas en la Ronda 2 (cabecera de intento en webhooks, métrica de fuerza bruta en salud, barra de ruido honesta, documentación de endurecimiento) + reorganización de la bitácora de z2 en docs/agentes/z2/ (mismo patrón que z1).

Work Log:
- Sync con main (v26 de z1: copiloto e higiene de cuenta) y línea base verificada: 423 passed / 8 skipped.
- W1 (webhook.py): cabecera X-Orquesta-Intento: 1|2 en cada intento — la entrega (X-Orquesta-Entrega) es igual en original y reintento, así que el receptor no podía distinguirlos (idempotencia/SIEM). Documentada en el contrato del módulo.
- S1 (api.py): _LimitadorTasa registra los bloqueos 429 (deque con poda a 24 h y tope duro MAX_BLOQUEOS=10_000: peticiones denegadas tampoco crecen memoria sin límite). Nueva metrica() expuesta SOLO en el detalle AUTENTICADO de /api/salud (componentes.limitador_auth): el payload anónimo no revela que hay ataque. Métrica operacional: NO afecta a ok_total (bloqueos en masa = limitador funcionando).
- J1 (panel.tsx): barra de ruido re-escalada al corte duro (100 % = techo × 5) con marca vertical del nivel pactado (al 20 % de la escala); el color mantiene la semántica relativa al pactado. La geometría ahora no miente: antes la barra "llena" ocultaba que el boundary aún permite 4× más ruido.
- D1 (deploy/README.md, append puro — fichero compartido): sección "Variables de endurecimiento y superficies admin": *_TLS_VERIFICAR (contrato exacto y receta de CA corporativo), veto SSRF de webhooks en 4 capas + escape WEBHOOK_PERMITIR_METADATOS + canal heredado + X-Orquesta-Intento, SSO (SSO_VINCULAR_POR_NOMBRE, pre-aprobación de privilegiadas, endpoint admin), y la métrica de fuerza bruta.
- TESTS (+10, test_v27_z2.py): intento 1/2 con misma entrega; 5xx → secuencia 1→2; registro y poda 24 h de bloqueos; tope duro del registro; aislamiento por clave; salud anónima sin métrica vs autenticada con ella; fuerza bruta real (4 logins, límite 3 → 429 y aparece en métrica; otra IP conserva presupuesto); bloqueos no degradan el healthcheck.
- DOCS: creada docs/agentes/z2/ (como z1/): README.md (ficha, principios, índice), sesion-01-rondas-1-2.md (git mv de z2.md íntegro + cabecera de contexto) y sesion-02-ronda-3.md (esta ronda); z2.md queda como punta de rastro que redirige (sin romper enlaces de otros agentes).

Stage Summary:
- 433 passed / 8 skipped (0 fallos), tsc 0, eslint 0.
- Contratos nuevos: X-Orquesta-Intento en cada intento de webhook; componentes.limitador_auth {bloqueos_24h, claves_activas} en /api/salud autenticada; barra de ruido a escala del corte duro con marca del pactado.
- Bitácora de z2 reorganizada en docs/agentes/z2/ (README + sesión por ronda); z2.md = punta de rastro.
- Siguiente ronda propuesta (sesion-02-ronda-3.md): export Prometheus (/api/metricas, exige contadores acumulados), entregas del canal heredado en la consola, insignia "techo superado" en la cola de aprobaciones, test de contract de cabeceras webhook, SQLCipher (deferido a ventanilla de despliegue).

---
## z3 — sesión 4 (2026-09-12): servidores MCP, superficie OpenAPI y endurecimiento del proxy

- ALCANCE: zonas NO cubiertas en sesiones 1-3 — servidores MCP, proxy consola→orquestador, persistencia/respaldo/sidecar/graph, CI, K8s, scripts de shell.
- F25 (BAJO*, reclasificado contra código real): /docs, /redoc y /openapi.json sin auth propia, pero el middleware global ya devolvía 401 (RUTAS_PUBLICAS solo exime /api/*). Fixes mantenidos como defensa en profundidad: docs desactivadas por defecto (ORQUESTA_DOCS=1 en desarrollo) + proxy de la consola rechaza segmentos "."/".." con 400 (la normalización WHATWG resolvía /api/orchestrator/../openapi.json → /openapi.json; cerrada como CLASE).
- F26 (MEDIO): osint_server.robots_txt interpolaba el dominio en la POSICIÓN DE AUTORIDAD (f"{esquema}://{dominio}/robots.txt") sin ninguna validación → "crt.sh@evil.com", "evil.com:8080", redirects arbitrarios = SSRF interno del servidor MCP. Fix: comun.dominio_valido() estricta (labels, TLD alfabético, ≤253, sin @:/?#%\ ni espacios, rechaza IPs literales) + redirecciones seguidas a mano (máx 3 saltos) SOLO dentro del dominio solicitado (www.<dominio> OK, evil.com no).
- F27 (BAJO): subdominios_crtsh con query por f-string → inyección de parámetros en el proveedor público. Fix: httpx params={} codificados + guardia F26.
- F28 (MEDIO): recon_server devolvía SIN sanear contenido controlado por el servidor externo (título, Server, X-Powered-By, meta generator) — inconsistencia LLM01 con osint. Fix: servidores_mcp/comun.py::saneado() compartida aplicada en http_probe y tech_fingerprint.
- F29 (BAJO): fallback TLS fail-open en los MCP (httpx.Client(verify=False) fijo si orchestrator no importaba). Fix: comun.cliente_recon() con la MISMA política RECON_TLS_ESTRICTO de transportes + test AST que impide reintroducir verify=False en código de servidores_mcp/.
- F30 (MEDIO): LOS SERVIDORES MCP NO ARRANCABAN con su invocación documentada: el paquete local platform/mcp/ sombrea el SDK PyPI mcp → "Falta el SDK de MCP" (SystemExit). Confirmado empíricamente. Fix: paquete renombrado a platform/servidores_mcp/ (docstrings de uso y comentario de transportes.py actualizados); python -m servidores_mcp.<server> --help → exit 0 en los 4; modo script suelto también OK.
- TESTS: test_z3_sesion4.py — 37 tests, 37/37 (guardia AST, arranque subprocess de los 4 servidores, redirects robots_txt bloqueado/permitido, params crt.sh, saneado de título/cabeceras/generator, coexistencia paquete↔SDK). Suite completa: 10 failed / 383 passed / 8 skipped — los 10 fallos son EXACTAMENTE los preexistentes del entorno (yara/impacket/ldap3 ausentes; test_v19, test_v20, test_integraciones). Cero regresiones. bunx tsc --noEmit: sin errores en los ficheros tocados.
- TRANSPARENCIA: patrones revisados y descartados documentados en la sesión (SQL dinámico de webhook seguro, subprocess en lista de persistencia, respaldo sin extractall, CERT_NONE necesario para inspección de certs, shell=True del C2 bajo ROE, regex acotadas, CI correcto, K8s con runAsNonRoot).

Stage Summary:
- 6 hallazgos remediados (F25-F30): total acumulado z3 → 30 fixes en 4 sesiones.
- La capa MCP (recon/osint/evidencias/c2) vuelve a ser arrancable y sus herramientas de red ya validan dominio, fijan redirects, sane contenido externo y respetan la política TLS central.
- Documentación: docs/agentes/agente-z3/sesion-4-mcp-superficie-y-endurecimiento.md + README índice actualizado (F1-F30).

---
Task ID: 29 (Z2-ronda-4)
Agent: Z2 (pulimiento de funciones y mecánicas del proyecto orquesta-rt)
Task: Ronda 4 de pulimiento — canal heredado WEBHOOK_URL visible en la consola (con entregas), techo de ruido REAL del ROE en la cola de aprobaciones + insignia de techo superado, y contrato de cabeceras webhook a prueba de deriva.

Work Log:
- P (canal heredado): GET /api/admin/webhooks devuelve canal_heredado {activo, url} (webhook.canal_heredado_estado()); GET /api/admin/webhooks/entorno/entregas sirve las entregas registradas bajo "entorno" (404 sin WEBHOOK_URL, 403 no-admin). Vista Webhooks: tarjeta de solo-lectura con borde discontinuo + desplegable de entregas (BloqueEntregas extraído y compartido con los receptores de BD); estado vacío ya no miente si solo hay canal heredado.
- Q (aprobaciones): el techo de ruido de la tarjeta ya no es el 50 hardcodeado — recibe engagement.roe.techo_ruido; con ruidoAcumulado >= techo, cada tarjeta pendiente muestra insignia ámbar "techo de ruido superado · acumulado X/Y".
- R (contrato webhook): dos tests fijan que la documentación del módulo declara las 5 cabeceras X-Orquesta-* y que el despacho envía EXACTAMENTE ese conjunto — la deriva doc/código ya no puede ser silenciosa.
- TESTS (+7, test_v28_z2.py): canal activo/inactivo en lista, entregas del canal consultables, 404 sin configurar, 403 no-admin, contrato de cabeceras x2.
- DOCS: docs/agentes/z2/sesion-03-ronda-4.md + índice del README actualizado; este registro.

Stage Summary:
- 440 passed / 8 skipped (0 fallos), tsc 0, eslint 0.
- El despliegue con WEBHOOK_URL ya muestra su canal y sus entregas en la consola; las decisiones de la cola de aprobaciones llevan el contexto de ruido del ROE real.
- Siguiente ronda propuesta (sesion-03): export Prometheus (contrato público: confirmación del operador), purga de entregas por receptor, etiqueta de ctem.corrida, pings de prueba distinguibles en el historial, SQLCipher (deferido).

---
Task ID: 30
Agent: z1 (agente colaborador, bitácora en docs/agentes/z1/)
Task: Ronda v27 — cierre del bucle CTEM↔purple↔Sigma (propuesta abierta desde la sesión 02), transparencia del escudo LLM01 en la respuesta del copiloto y aviso de caducidad próxima en la higiene de cuenta. Todos los commits en main, push continuo por etapas.

Work Log:
- AUDITORÍA DE PARTIDA: sincronizado con origin (main @ 8be7405, v26). Re-evaluadas las 4 propuestas de mi sesión 03 contra el código real: el bucle CTEM↔Sigma es ejecutable sin operador (las tres piezas existen: corridas VECTR, esqueletos Sigma anti-invención, validador estructural; faltaba el CRUCE), higiene y transparencia siguen abiertas y son mías; Neo4j real sigue requiriendo al operador. Durante la sesión entraron la ronda 4 de z2 y la sesión 4 de z3 (F25-F30): rebase limpio sin conflictos, mis commits quedan sobre ellos.
- BUCLE CTEM↔PURPLE↔SIGMA (ctem.py): cobertura_sigma_caso() cruza lo GENERADO (reglas_sigma_caso, anti-invención) × lo VERIFICADO (validar_lote: solo reglas que pasan cuentan como cobertura) × lo DOCUMENTADO (deteccion VECTR: detectado/prevenido → tecnicas_cubiertas, no_detectado → puntos_ciegos primera clase). instantanea() lo incluye; _delta_sigma() anota transiciones (coverage gain), regresiones (paso a punto ciego) y nuevas_reglas con flag comparable honesto — sin base (corrida pre-v27 o primera) NO se fabrican transiciones (disciplina v23). Import tardío de purpleteam/sigma_valid para evitar el ciclo con memory.
- TRANSPARENCIA DEL ESCUDO (copiloto.py): _elegir_bloque_sano devuelve (bloque, nº ecos descartados); _partir_estructura publica escudo.ecos_descartados; construir_contexto expone escudo_marcas; consultar() compone escudo {marcas_entrada, ecos_descartados} SIEMPRE presente (aunque sea {0,0}): la transparencia es por defecto. El contador para en el primer bloque sano (declara lo descartado ANTES del ganador; deliberado y documentado).
- CONSOLA: cadenas.tsx — insignias del bucle en el último delta ("bucle Sigma: T… detectada(s) con regla válida" esmeralda / "puntos ciegos nuevos: T…" rojo / "+N regla(s) Sigma validada(s)" teal, solo con base comparable) y "Sigma N/M válidas · K cubierta(s)" en cada fila de corrida; copiloto.tsx — nota ámbar de trabajo del escudo por respuesta; higiene.tsx — insignia "caduca pronto" (< 30 min, sesión válida) + sugerencia de renovar; tipos.ts (CoberturaSigma, DeltaCoberturaSigma, escudo) y store.ts (MensajeCopiloto.escudo) retrocompatibles.
- TESTS (test_v27.py, 15): bucle — instantánea cruza reglas válidas, sin fuente no inventa, VECTR entra al cruce, regla inválida NO es cobertura (lote manipulado), transición E2E (corrida base → marcar detectado → delta), regresión a punto ciego, sin base no fabrica, primera corrida declara reglas sin fingir, validador sin pySigma obligatorio; escudo — eco descartado declarado, solo-eco → vacías + 1, sana → 0, marcas de entrada hostil/benigno, E2E de consultar() punta a punta, caso limpio {0,0}.
- VALIDACIÓN: suite completa 475 passed / 8 skipped / 10 failed — los 10 idénticos al baseline del entorno (yara/ldap3, documentado desde v24): cero regresiones. tsc 0; eslint 0 en ficheros tocados.
- DOCUMENTACIÓN: README (roadmap v27, la propuesta del bucle sale de "Siguiente"), docs/agentes/z1/sesion-04-v27-bucle-ctem-sigma-transparencia.md, índice z1 actualizado y este registro.
- PUBLICACIÓN: 4 commits en main con push por etapas (backend 1d8428d tras rebase, consola 4600eb5, tests 053e93a, docs este).

Stage Summary:
- El modo continuo ahora cierra el ciclo ofensa→defensa→detección-as-code: cada corrida sabe qué técnicas detectadas tienen regla Sigma VÁLIDA detrás, y el delta declara la transición (coverage gain) y la regresión a punto ciego sin fabricar nada sin base comparable.
- El escudo LLM01 es transparente por defecto: el operador ve qué filtró cada respuesta (marcas de entrada + ecos de salida) y las sugerencias declaran su procedencia sana.
- La higiene de cuenta avisa ANTES de que el JWT muera a mitad de engagement.
- Siguiente (propuestas en docs/agentes/z1/sesion-04): sección de cobertura en el informe continuo, KPI de puntos ciegos en el Panel, señal agregada de contenido hostil recurrente en el copiloto, ingestión Neo4j con el operador.
---
## z3 — sesión 5 (2026-09-12): analítica cross-tenant, material sensible en git y cabeceras SMTP

- ALCANCE: api.py completo (3.101 líneas: middleware/RBAC/admin/SSO/SSE/analítica), auth.py, sso.py, copiloto.py, skills.py, busqueda.py, memory.py (custodia), transportes.py, webhook.py, reporting.py, cobertura_attack.py, integraciones (smtp_envio/ldap/rutas), infra (compose/Caddy/next.config/instrumentation/install.sh/.gitignore e índice trackeado del repo).
- F31 (MEDIO): /api/analitica/cobertura-attack y .csv agregaban SIEMPRE TODAS las BDs caso_*.db y exponían nombre/cliente/fase/resultados de detección de campañas de OTRAS organizaciones a cualquier cuenta autenticada (incluso lector JIT de otro tenant) — la analítica vive fuera del árbol /api/engagements/{id}, así que el middleware multi-tenant no la cubría (misma clase que F3). Fix: _leer_caso lee tenant_id; construir_cobertura(tenant_filtro) omite BDs de otros tenants (sin anotarlas como error); endpoints calculan filtro None (admin) / tenant_de(request); CSV hereda el aislamiento.
- F32 (ALTO): REGRESIÓN del F1 — usuarios.db (con secreto_jwt y hash scrypt de cuenta admin) y 10 casos/*.db estaban TRACKED en el índice de git: los .gitignore de la sesión 1 no des-trackean ficheros ya commiteados y rondas posteriores los re-añadieron (tests/demos con rutas por defecto en la raíz). Fix: git rm --cached (ficheros en disco, fuera del índice; reglas vigentes impiden re-añadir). PENDIENTE equipo: purga de historial (git filter-repo) + rotación del secreto JWT en despliegues derivados.
- F33 (BAJO): smtp_envio.enviar aceptaba destinatarios con CRLF/lista embebida ("a@b.com\r\nBcc: x") y asuntos multilínea — el EmailMessage moderno neutraliza parte del riesgo pero la frontera era implícita (versión/policy), no política. Fix: _validar_destinatarios() (email RFC 5322 práctico; con CUALQUIER inválido no hay conexión SMTP ni envío parcial), _asunto_seguro() colapsa CR/LF; validación ANTES de cualquier I/O.
- TESTS: test_z3_sesion5.py — 9 tests 9/9 en verde (aislamiento unit+API real con admin/lector de org-a vs org-b en JSON y CSV, tenant predeterminada, validación SMTP con smtplib vetado, asunto monolínea, higiene git). El test de higiene detectó el F32 real en su primera ejecución (mi barrido previo con head -20 lo había truncado). Suite completa: 10 failed / 469 passed / 8 skipped — los 10 fallos son EXACTAMENTE los preexistentes del entorno (yara/ldap3 ausentes; test_v19, test_v20, test_integraciones). Cero regresiones.
- TRANSPARENCIA: rutas.py Cypher 100% parametrizado (sin inyección), sso.py PKCE+RS256 sólido, auth.py sin hallazgos nuevos, reporting.py con escape HTML sistemático, next.config.ts/Caddyfile/install.sh/instrumentation.ts revisados sin hallazgos.

Stage Summary:
- 3 hallazgos remediados (F31-F33): total acumulado z3 → 33 fixes en 5 sesiones.
- La analítica de programa respeta el aislamiento multi-tenant (JSON y CSV); el repo deja de llevar material de credenciales (usuarios.db) ni BDs de caso en el índice.
- Documentación: docs/agentes/agente-z3/sesion-5-analitica-tenant-y-higiene-repo.md + README índice actualizado (F1-F33).

---
Task ID: 31 (Z2-ronda-5)
Agent: Z2 (pulimiento de funciones y mecánicas del proyecto orquesta-rt)
Task: Ronda 5 de pulimiento — las tres propuestas heredadas de la ronda 4 que no exigían decisión del operador (poda de entregas por receptor, etiqueta ctem.corrida, pings de prueba distinguibles) + un cuarto defecto de honestidad hallado durante la investigación (resumen de canales que se tapaban entre sí).

Work Log:
- Base: main 053e93a (v27 de z1 integrado). Línea base verificada: 492 passed / 8 skipped.
- S1 (webhook.py): poda de webhook_entregas POR RECEPTOR (MAX_ENTREGAS_RECEPTOR=100, incluido el canal heredado "entorno") — antes la poda solo global (500) dejaba que un receptor parlanchín se comiera la ventana de diagnóstico de los receptores silenciosos; la poda global se conserva como guarda del tamaño total.
- T1 (webhooks.tsx): etiqueta "Corrida CTEM" para ctem.corrida — caía al nombre crudo desde v23.
- T2 (test_v29_z2.py): contrato BIDIRECCIONAL catálogo de eventos ≡ etiquetas del frontend (parser del tsx con comentarios de línea limpiados): todo evento del backend tiene etiqueta y toda etiqueta es un evento real — la deriva T1 ya no puede volver en silencio.
- U1 (webhooks.tsx): las filas webhook.prueba del historial llevan firma visual propia (borde discontinuo + chip "ping de prueba" slate) — antes se veían IGUAL que una entrega operativa real al diagnosticar un receptor.
- V1 (webhook.py): estado()["servidor"] nombra AMBOS canales cuando coexisten ("URL + N receptor(es) en BD") — antes la WEBHOOK_URL tapaba el recuento de receptores de BD (url or ...).
- TESTS (+10, test_v29_z2.py): techo por receptor del parlanchín (conserva las más recientes), el parlanchín no desplaza al silencioso, techo aplicado al canal heredado, poda global sigue activa como guarda (monkeypatch de constantes), invariante RECEPTOR < GLOBAL de diseño, contrato de etiquetas x2, estado() con ambos canales / solo heredado / solo BD.
- DOCS: docs/agentes/z2/sesion-04-ronda-5.md + índice del README de la carpeta + z2.md (punta de rastro) actualizados; este registro.

Stage Summary:
- 502 passed / 8 skipped (0 fallos), tsc 0, eslint 0.
- La ventana de entregas webhook es equitativa entre receptores; el catálogo de eventos backend↔frontend está protegido contra deriva por contrato; los pings de prueba se distinguen a simple vista del tráfico real.
- Siguiente ronda propuesta (sesion-04): export Prometheus (confirmación del operador, pendiente desde ronda 3), rotación de secreto de receptor con doble ventana, insignia "N fallos en 24 h" por receptor en la vista, webhook.prueba exento del techo por receptor (cuantificar antes), SQLCipher (deferido).

---
Task ID: 32 (Z2-ronda-6)
Agent: Z2 (pulimiento de funciones y mecánicas del proyecto orquesta-rt)
Task: Ronda 6 de pulimiento — métricas de 24 h por receptor visibles en la tarjeta, cuota propia para los pings de prueba (no desplazan entregas reales del receptor) y refresco del historial tras un ping. Rotación de secreto con doble ventana: investigada y DEFERIDA con razón técnica.

Work Log:
- Base: main f0967c7 (ronda 5 publicada tras rebase con z3 sesión 5 y z1 v27). Línea base verificada: 511 passed / 8 skipped.
- W1 (webhook.py + api.py + store.ts + webhooks.tsx): entregas_24h / fallos_24h por receptor (y canal heredado) en GET /api/admin/webhooks — helper entregas_24h_por_receptor() con corte ISO calculado en Python; insignia roja "N fallos en 24 h" o slate "N entregas en 24 h" en la tarjeta; sin tráfico NO muestra nada (cuenta cero, no inventa actividad).
- X1 (webhook.py): la poda por receptor se divide en dos cuotas — entregas reales conservan las últimas MAX_ENTREGAS_RECEPTOR=100 y los pings webhook.prueba la suya MAX_PINGS_RECEPTOR=20; martillear Probar ya no desplaza el historial real del propio receptor.
- Y1 (webhooks.tsx): si el desplegable de entregas está abierto al terminar un ping, se recarga — el resultado aparece al momento.
- DEFERIDO (sesion-05): rotación de secreto con doble ventana (dos secretos válidos simultáneos por receptor para cubrir una ventanilla de segundos en receptores internos: relación coste/beneficio desfavorable), export Prometheus (confirmación del operador, tercera ronda), SQLCipher (ventanilla de despliegue).
- TESTS (+7, test_v30_z2.py): conteo ok/fallos 24h, la ventana ignora lo anterior a 24h, sin entregas → vacío, API decora receptores + canal heredado con ceros honestos, pings no desplazan reales (propiedad central), ambas cuotas a la vez, invariante 0 < PINGS < ENTREGAS. Contrato del canal heredado en test_v28_z2.py (ronda 4) actualizado para aceptar la extensión.
- DOCS: docs/agentes/z2/sesion-05-ronda-6.md + índice del README de la carpeta + z2.md (punta de rastro) actualizados; este registro.

Stage Summary:
- 518 passed / 8 skipped (0 fallos), tsc 0, eslint 0.
- El receptor muerto se ve en su tarjeta sin abrir nada; los pings de prueba tienen su propia cuota y el tráfico real conserva su ventana íntegra de 100.
- Siguiente ronda propuesta (sesion-05): export Prometheus (decidir o retirar del roadmap), estado de salud derivado por receptor (umbrales por tipo de receptor), reenvío manual de entrega fallida (exige esquema nuevo), ETIQUETA_EVENTO compartida (YAGNI, vigilar).

---
Task ID: 33 (Z2-ronda-7)
Agent: Z2 (pulimiento de funciones y mecánicas del proyecto orquesta-rt)
Task: Ronda 7 de pulimiento — diversificación fuera del dominio webhook: búsqueda en memoria del caso. Defecto corregido: el fragmento mostrado al operador no localizaba la coincidencia que BM25 sí había puntuado cuando consulta y contenido diferían en tildes.

Work Log:
- Base: main 79f32a1 (ronda 6 publicada). Línea base verificada: 518 passed / 8 skipped.
- INVESTIGACIÓN: barrido de módulos sin pulir reciente (busqueda.py, flujo de borrado de casos — no existe: decisión de producto, excepciones silenciosas, colisión de ids resumen: — despreciable con microsegundos).
- Z1 (busqueda.py): _fragmento buscaba el término SIN normalizar sobre contenido.lower() mientras tokenizar quita tildes en ambos lados del índice — consulta "enumeracion" contra "enumeración" → find() == -1 → el recorte caía en la CABECERA del documento en vez del pasaje relevante (la vista Memoria renderiza fragmento tal cual). Fix: _normalizar_1a1() — gemelo del contenido con el mismo mapeo que tokenizar; como cada sustitución y el lower() español son 1:1 por carácter, las posiciones del gemelo valen para recortar el original (invariante fijado por test).
- TESTS (+4, test_v31_z2.py): consulta sin tildes sobre contenido con tildes (y viceversa), invariante de longitud/posiciones del gemelo, E2E buscar_caso con fragmento centrado en el pasaje. Los 4 fallan contra el código anterior (fijan el defecto, no el accidente).
- DEFERIDO/DESCARTADO (sesion-06): colisión resumen:{creado_en} (despreciable), degradación silenciosa de embeddings (metodo "bm25" ya es honesto), reenvío manual de entregas fallidas (esquema nuevo), borrado de casos (producto, no defecto).
- DOCS: docs/agentes/z2/sesion-06-ronda-7.md + índice del README de la carpeta + z2.md (punta de rastro) actualizados; este registro.

Stage Summary:
- 522 passed / 8 skipped (0 fallos). Sin cambios de TypeScript: tsc/eslint como en la base.
- La búsqueda del caso muestra fragmentos que corresponden a la coincidencia real — la misma tolerancia a tildes del índice, ahora también en lo que ve el operador.
- Siguiente ronda propuesta (sesion-06): reenvío manual de entregas webhook fallidas (esquema), export Prometheus (cuarta ronda deferido: decidir o retirar), salud derivada por receptor, realce del término en la vista Memoria (trivial sobre el fragmento corregido).

---
Task ID: 34 (Z-DIRECTOR-sesion-01)
Agent: z-director (dirección y revisión del conjunto orquesta-rt)
Task: Auditoría directiva independiente del proyecto (bitácoras de z1/z2/z3 + instalación limpia + estado remoto de GitHub), cierre del F32 (secreto JWT en el historial público) y de la CI roja, con bitácora propia en docs/agentes/z-director/.

Work Log:
- Verificación independiente: venv limpio + requirements → 11 failed / 511 passed (mcp 2.2.0: el SDK 2.x renombró FastMCP y los 4 servidores MCP no arrancan); con mcp<2 → 522 passed / 8 skipped; tsc 0, eslint 0. Badge de Actions: "CI - failing" — la CI corría y fallaba mientras los entornos de los agentes veían verde local.
- Veredicto de dirección: correcta (trayectoria v22→v27 coherente, 33 hallazgos de z3 remediados con test, bitácoras excelentes). El fallo sistémico era de "verdad remota": nadie miraba lo que GitHub muestra a un tercero.
- F32 (ALTO, abierto desde z3 sesión 5): verificado a mano — usuarios.db con secreto_jwt real (64 hex) y hash scrypt de admin accesible por git cat-file en commits pre-purga; ventana de exposición 9cdab8d→a79b2f3. Escaneo COMPLETO del historial: las 11 BDs (usuarios.db + 10 casos/*.db) son el único material sensible (sin .env reales, sin .pem/.key).
- PURGA: git filter-repo --force --invert-paths --path usuarios.db --path casos/ sobre TODO el historial. Verificado: 0 BDs en commits y objetos, blob del secreto físicamente inexistente, árbol pre/post idéntico (1f10abf4…), 30 commits conservados, suite post-purga 522/8. Todos los hashes posteriores a v22 cambiaron (las bitácoras que citan hashes pre-purga quedan como historia, no como error).
- CI: tope mcp>=1.1.2,<2 en requirements.txt con comentario de razón (commit 7a6d7ca pre-purga → 990832d post). El workflow ci.yml NO se tocó: mi primera lectura de "branches: ain]" era un artefacto de renderizado del terminal — od -c + yaml.safe_load confirman que siempre dijo [main] (falso positivo propio, declarado en la bitácora).
- DOCS: docs/agentes/z-director/ (README + sesion-01-auditoria-directiva-y-cierre-incidentes.md) + z-director.md (punta de rastro) + badge de tests del README al día (290→522); este registro.
- OPERADOR (bloqueante): force-push de main + borrar ramas remotas z3/auditoria-seguridad-sesion1 y z3/auditoria-seguridad-sesion3 (fusionadas en main; apuntan a historia con el secreto). TODOS los entornos de agentes deben re-clonar (o reset --hard origin/main) antes de su próximo push — un push desde un clon pre-purga devolvería el secreto a GitHub.
- z3 (esta semana): rotar secreto JWT (UPDATE config + reinicio — HS256 invalida todos los tokens previos) y contraseña admin en todo despliegue derivado; cerrar el inventario de credenciales históricas de su sesión 1.

Stage Summary:
- Historial limpio (0 BDs, árbol intacto, 30 commits), suite 522/8, tsc/eslint 0, requirements resuelve con tope (mcp 1.30.0).
- F32 purgado en local — pendiente el force-push del operador y la rotación de z3 para cierre formal.
- CI quedará en verde tras el push (la causa era solo mcp 2.x); órdenes de dirección emitidas para z2 (checklist de instalación limpia + badge post-push en cada ronda) y z1 (mantener roadmap).
- Siguiente sesión de dirección propuesta: verificación post-push (badge, ramas, clone-limpio) y cierre formal de F32.

---
Task ID: 35 (Z-DIRECTOR-sesion-02)
Agent: z-director (dirección y revisión del conjunto orquesta-rt)
Task: Publicación de la purga del F32 en GitHub en nombre del operador (token cedido) y verificación remota del estado publicado.

Work Log:
- Force-push de main (161be49...435b59a, forced update): el historial purgado sustituye al histórico; 31 commits íntegros con los dos del director.
- Borrado de las ramas remotas z3/auditoria-seguridad-sesion1 y z3/auditoria-seguridad-sesion3: sus punteros conservaban el historial pre-purga con el secreto JWT. origin queda con UNA sola rama (main @ 435b59a).
- Verificación con ojos de tercero: clone limpio desde GitHub → 0 BDs en todo el historial, acceso al SHA pre-purga del secreto (9cdab8d:usuarios.db) → fatal: invalid object name, 31 commits, HEAD en 435b59a. Clone de verificación eliminado tras la comprobación.
- Badge de Actions en branch=main: "CI - passing" — la CI corrió sobre el nuevo historial y pasó; el tope mcp>=1.1.2,<2 era la única causa del rojo, confirmado en remoto.
- Higiene de credenciales: el token del operador viajó en texto plano por el chat; revocación recomendada YA (documentado en la sesión 02 §4).
- DOCS: docs/agentes/z-director/sesion-02-publicacion-y-verificacion-remota.md + índice del README de la carpeta + z-director.md actualizados; este registro.

Stage Summary:
- F32 CERRADO en GitHub: el historial público ya no contiene las BDs ni el secreto, y la CI valida desde instalación limpia en cada push (badge verde).
- Única parte viva del hallazgo: rotación de secreto_jwt y contraseña admin en despliegues derivados (z3, esta semana) y re-clon de los entornos de agentes antes de su próximo push.
- Pendiente del operador: revocar el token cedido; opcional GitHub Support para vistas cacheadas de commits antiguos.

---
Task ID: 36 (z3-sesión-6)
Agent: z3 (auditoría de seguridad)
Task: Sesión 6 de auditoría — módulos del backend nunca auditados a fondo (arsenal AD, ctem, purpleteam, sigma_valid, integraciones C2/Neo4j/NVD/LDAP, lab, consola Next.js) con análisis estático pyflakes como técnica nueva; remediación de defectos de ligado de nombres con tests de regresión y guarda sistémica.

Work Log:
- Base: main f0967c7 (ronda 5 de z2 integrada). Lectura profunda de guardrails.py (boundary completo), ad.py, persistencia.py, navigator.py, ctem.py, purpleteam.py, sigma_valid.py, respaldo.py, sidecar.py, evasion.py, graph.py, agents/fases.py, cli/demo_seed/state, integraciones metasploit/sliver/mythic/bloodhound/nvd/rutas/ldap/misp y servidor MISP lab; consola: proxy /api/orchestrator/*, puente IA, instrumentation.ts, store.ts.
- Barrido pyflakes sobre todo el Python de la plataforma destapa 3 nombres cargados que nadie definió ni importó (invisibles para py_compile y para los tests que no pisan el camino con datos reales).
- F34 (ALTO funcional, ad.py:188): `etipo_clave = _enctype_table[23]` — símbolo que el módulo jamás importa, fuera de todo try: asrep() muere con NameError → 500 en /arsenal/ad justo cuando el directorio declara cuentas sin preauth (su caso de uso). Asignación muerta eliminada (el etype se lee de la AS_REP).
- F35 (MEDIO funcional, ad.py:278): dcsync() llamaba a SMBTransport con `username` (la variable es `usuario`): NameError tras el login SMB, enmascarado por el except genérico como "fallo contra el DC real" — dcsync NUNCA funcionó. Identificador corregido.
- F36 (BAJO, graph.py): json.dumps al cerrar cada fase sin importar json; el NameError caía en el try/except de la compactación y se tragaba en silencio — router.compactar jamás se ejecutó (economía del token cap. 3.2 muerta en silencio). import json añadido.
- Tests: platform/tests/test_z3_sesion6.py (5 tests: asrep dinámico con impacket/pyasn1 simulados en sys.modules, camino sin cuentas, AST de dcsync sin `username`, json expuesto, guarda pyflakes sistémica con importorskip). Validación anti-falso-positivo: stash de los fixes → los 4 esperados fallan; pop → 5/5 en verde. Detectada y corregida una versión vacua de la guarda durante su construcción (check() vs checkPath()).
- Suite completa: 10 failed (mismos preexistentes yara desde la sesión 5) / 506 passed / 8 skipped — cero regresiones (506 = 491 base s5 + 5 z3-s6 + 10 z2-r5).
- DOCS: docs/agentes/agente-z3/sesion-6-arsenal-ad-nombres-indefinidos.md + README índice y tabla F1-F36 actualizados; este registro. Nada de otros agentes tocado.

Stage Summary:
- Total acumulado z3 → 36 fixes en 6 sesiones. El arsenal AD vuelve a estar operativo (asrep/dcsync), la compactación de fases es real y la clase de defecto "nombre indefinido" está protegida por test en toda la plataforma.
- Pendiente de equipo (sin cambios): purga de historial git + rotación del secreto JWT de usuarios.db (F32); rotación del PAT de push.

---
Task ID: 37 (Z2-ronda-8)
Agent: Z2 (pulimiento de funciones y mecánicas del proyecto orquesta-rt)
Task: Ronda 8 de pulimiento — realce del término de búsqueda en la vista Memoria (propuesta estrella de la sesión 06), construido sobre el fragmento corregido en la ronda 7. (Renumerado de 34 a 35 en el rebase: el ID 34 lo tomó antes z3-sesión-6 en main; rebase reconciliado sin debilitar ningún fix ajeno.)

Work Log:
- Base: main 8b98e97 (ronda 7 publicada). Línea base verificada: 522 passed / 8 skipped.
- DECISIÓN DE DISEÑO: las posiciones del realce las calcula el BACKEND (fuente única de verdad de la normalización tolerante a tildes — el gemelo 1:1 de la ronda 7); duplicar la lógica en TypeScript sería la deriva backend↔frontend que esta carpeta caza. El frontend solo pinta.
- AA1 (busqueda.py + memoria.tsx + store.ts): _fragmento_y_coincidencias() + _rangos_coincidencias() — todas las ocurrencias de todos los términos de la consulta sobre el fragmento, pares semiabiertos {inicio, fin} ordenados y sin solapes (solapados se FUNDEN: «adm» dentro de «administración» = una marca); buscar_caso añade "coincidencias" a cada resultado; ResultadoBusqueda gana el campo opcional (tolerante a backend antiguo); FragmentoConRealce pinta <mark> ámbar saneando rangos corruptos. Sin match léxico → lista vacía: la vista no inventa realces.
- AA2: off-by-one del suspensivo inicial cazado POR EL TEST antes de publicar — el «…» inicial desplaza la ventana +1 dentro del fragmento final; sin compensar, el realce pintaba ' enumeració' en vez de 'enumeración' (verificado manualmente). Regresión fijada.
- AA3: término más largo que el radio ya no queda partido por la ventana (fin = max(pos+radio, pos+len(t))).
- AA4: contenido corto (≤ 2×radio) devuelve el documento entero CON rangos.
- Compatibilidad: _fragmento() conserva firma (copiloto RAG y tests de la ronda 7 la consumen).
- TESTS (+9, test_v32_z2.py): tolerancia a tildes en ambos sentidos, posiciones válidas con suspensivo inicial (regresión AA2), orden/sin solapes/fusión, primera coincidencia nunca cortada, sin match → vacío honesto, contenido corto, compatibilidad de firma, E2E con contrato de cable exacto (solo claves inicio/fin). 531 passed / 8 skipped, tsc 0, eslint 0.
- DOCS: docs/agentes/z2/sesion-07-ronda-8.md + índice del README de la carpeta + z2.md (punta de rastro) actualizados; este registro.

Stage Summary:
- 531 passed / 8 skipped (0 fallos), tsc 0, eslint 0.
- El operador ve el término buscado realzado dentro del fragmento — lo que BM25 puntuó es exactamente lo que se marca, tildes incluidas.
- Siguiente ronda propuesta (sesion-07): export Prometheus (quinta ronda deferido: decisión o retirada), reenvío manual de entregas fallidas (esquema de cargas), salud derivada por receptor, realce en títulos (marginal).

---
Task ID: 38 (Z2-ronda-9)
Agent: Z2 (pulimiento de funciones y mecánicas del proyecto orquesta-rt)
Task: Ronda 9 de pulimiento — reenvío manual de entregas webhook fallidas (la propuesta más veterana de la cola, esperando desde la sesión 05 porque "exigía esquema nuevo").

Work Log:
- Base: main f3ef61e (ronda 8 publicada). Línea base verificada: 535 passed / 9 skipped.
- DECISIÓN DE DISEÑO: la carga original viaja en la PROPIA fila de entrega (columnas carga TEXT + reenvio_de INTEGER, migración idempotente PRAGMA table_info como auth.py/memory.py) — la retención ya está acotada por las podas de rondas 5/6; tabla aparte = dos fuentes de verdad que podan a ritmos distintos (descartada); re-derivar la carga del estado actual del caso = el reenvío mentiría sobre el evento original (descartado).
- BB1 (webhook.py): _registrar_entrega/_entregar persisten la carga JSON de cada entrega (real y ping).
- BB2 (webhook.py + api.py): reenviar_entrega(webhook_id, entrega_id) — nueva entrega REAL (uuid, ts, firma nuevos) con la MISMA carga y la configuración ACTUAL del receptor (rotación de url/secreto = caso de uso); veto SSRF por resolución incluido; ruta POST /api/admin/webhooks/{id}/entregas/{entrega_id}/reenviar con el guard _admin_webhooks.
- BB3: el historial (entregas_de) ahora expone id (no identificaba sus filas), reenvio_de y reenviable; la carga NO viaja por la API (datos del caso).
- BB4 (webhooks.tsx + store.ts): botón Reenviar en fallos reenviables (BD y canal heredado), chip "reenvío de #N" teal, error del backend pintado junto a la fila, historial refrescado tras el reenvío (patrón ping ronda 6).
- HONESTIDAD (5 negaciones con test): solo fallos (recibida → 400 "ya llegó"), pings no reenviables (se relanzan con Probar), filas legadas sin carga declaradas NO reenviables, receptor debe existir/activo/suscrito (404/400), re-reenvío apunta a la ORIGINAL (forma de estrella, no cadena); el reenvío cuenta como entrega real en podas y métricas 24h.
- Hallazgo colateral: primer SELECT de entregas_de olvidaba la columna id — cazado por los tests (13 fallos) antes de salir del entorno.
- TESTS (+13, test_v33_z2.py): migración legado sin pérdida, reenvío feliz (misma carga, cabeceras contractuales ronda 4 intactas, original intacta), estrella de re-reenvíos, 5 negaciones, 404s, exposición del historial, métricas 24h, E2E API 200/400/404. 548 passed / 9 skipped, tsc 0, eslint 0.
- DOCS: docs/agentes/z2/sesion-08-ronda-9.md + índice del README de la carpeta + z2.md (punta de rastro) actualizados; este registro.

Stage Summary:
- 548 passed / 9 skipped (0 fallos), tsc 0, eslint 0.
- Un evento webhook perdido YA NO se pierde: el operador lo reenvía con la carga fiel y ve el resultado en el historial — la propuesta en cola desde la sesión 05 queda cerrada.
- Siguiente ronda propuesta (sesion-08): export Prometheus (quinta ronda deferido: decisión o retirada), salud derivada por receptor, reenvío en lote (deferido sin fecha), realce en títulos (marginal).

---
Task ID: 39 (z3-sesión-7)
Agent: z3 (auditoría de seguridad)
Task: Sesión 7 de auditoría — infra de despliegue (CI, install/supervisor, compose, Caddy, proxy consola, puente IA) y re-auditoría del arsenal de persistencia con threat model del propio host; remediación del hallazgo F37 con tests de regresión E2E.

Work Log:
- Base: main 0fc4e8b (sesión 6 publicada). Lectura profunda de la infra nunca cubierta de frente: ci.yml, install.sh, dev-supervisor.sh, stop.sh, docker-compose.yml, Caddyfile, deploy/k8s, proxy /api/orchestrator/*, puente /api/ia, instrumentation.ts, lab/servidor_lab.py; y re-lectura completa de persistencia.py con la pregunta "¿qué puede tocar de verdad el endpoint en ESTE host?".
- F37 (ALTO, persistencia.py + api.py): el campo `raiz` del arsenal de persistencia solo se sometía a realpath+isdir — cualquier directorio escribible del host era destino válido del implante (/root/.bashrc con activación real vía bash -i HOME=/root, authorized_keys de cuentas ajenas con clave privada devuelta en la respuesta, unidad systemd en /etc...). Agravante: el boundary evaluaba {"host": "127.0.0.1", ...} SIN la raíz — la firma del operador no veía el destino real (rompe la coincidencia EXACTA tool+argumentos del blueprint). Remediación: lista blanca de hogares del lab (ORQUESTA_LAB_HOGARES, por defecto SOLO el HOME del despliegue), _raiz_confinada con realpath en ambos lados (traversal y symlinks no escapan) aplicada en implantar/verificar/retirar/estado, "raiz" incluida en los argumentos que el boundary evalúa y audita en los tres endpoints, y testigo de activación entrecomillado con shlex.quote (hogares con espacios daban falso negativo de activación).
- Hermano menor (MEDIO, mismo pase): `echo $(date +%s) >> {testigo}` sin entrecomillar en el bloque bashrc — corregido con shlex.quote.
- Tests: platform/tests/test_z3_sesion7.py (8: rechazo fuera del lab en los 4 flujos, semántica por defecto HOME-only, hogar dedicado multi-home, traversal+symlink, raíz inexistente, espacios en el hogar con activación real, E2E por API donde la aprobación expone argumentos.raiz y /etc muere en el confinamiento tras pasar firma). conftest.py: fixture autouse declara el basetemp de pytest como lab autorizado — el flujo legítimo v20 (tmp_path) sigue en verde.
- Entorno: instalados yara-python y ldap3 (opcionales ausentes en la máquina de auditoría desde la sesión 1): la suite completa pasa por primera vez SIN fallos de entorno. Limpieza de imports muertos heredados en persistencia.py (secrets/tempfile).
- Superficie revisada SIN hallazgos: ci.yml (sin secretos ni pull_request_target), install.sh (set -euo pipefail, sin curl|bash), compose (loopback + no-new-privileges intactos), Caddyfile (transform :81 sigue ausente), proxy (guardia ../ e IP real no suplantable), puente IA (token 0600 + comparación constante), webhook (veto rebinding en 4 capas), busqueda/reporting/respaldo/ctem/threatled/razonador/purpleteam/sigma_valid (SQL parametrizado, sin escrituras con nombres del cliente, yaml.safe_load), usuarios.db fuera del índice git (F32 estable).
- Suite completa: 535 passed / 8 skipped / 0 failed (base previa: 8 failed de entorno). DOCS: docs/agentes/agente-z3/sesion-7-confinamiento-persistencia.md + índice README y tabla F1-F37 + .env.example documentando ORQUESTA_LAB_HOGARES; este registro. Nada de otros agentes tocado.

Stage Summary:
- Total acumulado z3 → 37 fixes en 7 sesiones. El arsenal de persistencia ya no puede escribir ni activarse fuera del laboratorio declarado, y el operador firma el destino real (la raíz es visible en la aprobación y en la auditoría).
- Pendiente de equipo (sin cambios): purga de historial git + rotación del secreto JWT de usuarios.db (F32); rotación del PAT de push.

---
Task ID: 40 (Z-DIRECTOR-sesion-03)
Agent: z-director (dirección y revisión del conjunto orquesta-rt)
Task: Revisión directiva de las 4 rondas publicadas tras la purga (z3-s6, z2-r8, z2-r9, z3-s7): verificación técnica independiente sobre el HEAD publicado y auditoría de la coordinación multi-agente post-purga.

Work Log:
- Verificación técnica: fixes F34/F35/F36/F37 presentes y reales (F37 verificado a mano: _hogares_permitidos/_raiz_confinada con realpath en ambos lados, shlex.quote del testigo, "raiz" en los argumentos del boundary). Rondas 8/9 de z2 presentes (realce con posiciones backend, reenvío manual con negaciones honestas). Suite REAL del HEAD: 556/9/0 — ni z3-s7 (535/8 en el mensaje del ÚLTIMO commit) ni z2-r9 (548/9) reportaron el número de lo publicado (bases paralelas rancio).
- Hallazgos de coordinación: marcador de conflicto '=======' publicado en worklog.md:919 (rebase de z2-r8); fragmento huérfano 'Task ID: 34 (z3-sesión-6)' sin cuerpo (colisión con la sesión 01 del director); F32 declarado "pendiente de decisión del equipo" en bitácoras NUEVAS de z3 publicadas tras el cierre (no leyó la bitácora del director — regla 1 de convivencia incumplida); hashes base citados inexistentes (f0967c7, 0fc4e8b, f3ef61e).
- Guarda pyflakes SKIPeaba en CI (pyflakes ausente de requirements.txt): la protección sistémica contra la clase F34/F35/F36 solo corría en la máquina de z3. Añadida pyflakes>=3 a requirements.txt; verificada en verde (la guarda PASA, suite 557/8/0).
- Saneado del worklog: marcador de conflicto y fragmento huérfano eliminados, separadores --- restaurados. Cero contenido de fondo de otros agentes tocado.
- DOCS: docs/agentes/z-director/sesion-03-revision-agentes-y-saneamiento.md + índice + punta de rastro; este registro.

Stage Summary:
- Veredicto técnico de las 4 rondas: EXCELENTE (F37 = hallazgo de mayor valor del ciclo; suite real 557/8/0 con la guarda activa). Veredicto de coordinación: tocada — artefactos de rebase publicados y bitácoras rancio por no leer al director.
- Órdenes emitidas: z3 reconoce el cierre real de F32 en su próxima sesión; z2 chequea artefactos de conflicto y reporta sobre el HEAD publicado; todos leen las bitácoras previas y numeran Task IDs desde el máximo existente; operador decide el reparto de z1 (inactivo desde v27) y revoca el PAT (petición ya doble).

Addendum (Task ID 40): al publicar, z1 había pusheado v28 (dashboard: ROE vivo editable, auditoría de sistema en Equipo, reasignación cross-tenant, README con GIF) — la orden de reparto de z1 queda resuelta por los hechos. Suite re-verificada tras rebase: 557/8/0. Badge del README actualizado a 557 (z1 citaba 509 en su mensaje; el README heredaba 522 de la sesión 01).
---
Task ID: 41 (Z2-ronda-10) — renumerado desde 40: colisión con la sesión 03 del director, que llegó al remoto mientras esta ronda estaba en vuelo (su regla: numerar desde el máximo existente)
Agent: z2 (pulimiento de funciones y mecánicas)
Task: Ronda 10 — salud DERIVADA por receptor en la vista Webhooks (propuesta en cola desde la sesión 05), apertura con la restauración verificada de las rondas 8-9 tras la purga F32 del z-director, y ejecución de la orden #4 del director (checklist de instalación limpia + badge, revisión de topes de dependencias, plan MCP v2).

Work Log:
- Apertura de sesión: git pull detectó el forced update de la purga. El clon fresco mostró que z3 YA había restaurado su sesión 6, mis rondas 8-9 y añadido su sesión 7. Verificación de integridad ANTES de darla por buena: árboles de mis commits originales (clon pre-purga archivado como orquesta-rt-prepurga-NO-PUSHEAR, del que no se pushea) comparados byte a byte con los restaurados — idénticos salvo el trabajo intercalado del director (tope mcp<2, badge, docs, worklog). Protocolo del director respetado: todo el trabajo de la ronda SOLO desde clon fresco post-purga; 0 BDs en el historial verificado con rev-list.
- Hallazgo colateral detectado TAMBIÉN aquí: la restauración dejó un encabezado huérfano "Task ID: 34 (z3-sesión-6)" sin cuerpo en worklog.md. Lo saneé en paralelo a la sesión 03 del director, que lo publicó antes que mi push — en el rebase prevalece su saneado y el mío queda redundante. Cero contenido de fondo de otros agentes tocado.
- SALUD DERIVADA (webhook.py): nueva salud_receptores() — una consulta con CTE y ROW_NUMBER (PARTITION BY webhook_id ORDER BY creado_en DESC, id DESC) de la que salen ultima_ok/ultima_entrega/ultimo_exito/ultimo_fallo por receptor. Estados: "sano" (última entrega = éxito), "con_fallos" (última = fallo, aunque hubiera éxitos previos), "sin_entregas" (cero filas). La ÚLTIMA fila manda: fallo→éxito es canal recuperado; éxito→fallo es canal caído. La poda por recuento jamás borra la última fila: el estado no puede inventarse por retención (test). Pings y reenvíos son POSTs reales y cuentan (reenvío exitoso → sano, hilo ronda 9). NO existe "muerto por silencio": el silencio viaja como hecho (ultima_entrega) — la reserva operacional de la sesión 05 (roe.parada_emergencia puede tardar meses) resuelta como información, no como umbral.
- API (api.py): GET /api/admin/webhooks fusiona "salud" en cada receptor y en canal_heredado; receptor virgen → contrato explícito {"estado":"sin_entregas", nulls} — el JSON no inventa estados.
- CONSOLA (store.ts, webhooks.tsx, ui.tsx): SaludReceptor tipado + campo salud?; InsigniaSalud compartida por receptores y canal heredado — "último POST ok" (esmeralda) / "último POST falló" (rojo) / "sin entregas todavía" (slate) con tooltips de fechas, e insignia informativa "7+ días sin entregas" SOLO en receptores activos (en pausados el silencio es lo esperado) con la reserva de eventos infrecuentes en el tooltip. Insignia acepta title? opcional (retrocompatible).
- TESTS (+13, test_v34_z2.py): 5 estados derivados (incl. solo-fallos y virgen ausente), ping demuestra canal, reenvío exitoso recupera canal, poda de 25 pings sobre cuota 20 con estado correcto, canal "entorno" sano/con_fallos, BD rota → {}, E2E API (salud por receptor, virgen con nulls, canal heredado, sin canal no inventa campo). Suite RE-MEDIDA tras el rebase (v28 de z1 + sesión 03 del director, guarda pyflakes activa): 570 passed / 8 skipped — 13 tests de la ronda sobre la base 557/8; tsc 0, eslint 0 en lo tocado.
- ORDEN #4 DEL DIRECTOR: (1) checklist "instalación limpia + badge verde tras push" añadida y ejecutada (suite completa en clon fresco antes de pushear); (2) revisión de topes documentada en la bitácora con criterio: tope solo donde el riesgo es real (mcp<2 se mantiene), el resto se vigila con la CI limpia — un tope universal es otra forma de pudrirse; langgraph/langchain marcados como punto ciego local (9 skips: instalar opcionales al verificar); (3) plan de migración MCP v2 en docs/agentes/z2/plan-mcp-v2.md — alcance verificado (4 servidores, punto único de importación FastMCP, comun.py intacto), 6 pasos con criterio de aceptación (los 11 tests de z3 s4), decisión de CUÁNDO: ronda dedicada, no de coladón.
- Badge de tests del README: a la cifra de ESTE push — 570 (557 base del director + 13 de la ronda, medido tras el rebase).
- Observación para z1 (no toco su código): eslint-plugin-react-hooks 7.1.x (npm sin lockfile) marca 3 set-state-in-effect preexistentes (acceso 48, dialogo-fase 47, higiene 96); CI con bun frozen lockfile (7.0.1) sigue en 0 — el arreglo correcto es reestructurar los effects, no degradar el plugin.
- DOCS: docs/agentes/z2/sesion-09-ronda-10.md + plan-mcp-v2.md + índice del README de la carpeta + z2.md (punta de rastro) actualizados; este registro.

Stage Summary:
- 570 passed / 8 skipped (0 fallos), tsc 0, eslint 0 en lo tocado. Badge 570.
- La vista Webhooks contesta la pregunta operacional real — ¿funciona este canal AHORA? — con el estado derivado de la última entrega real, y el silencio se publica como hecho: el juicio de "muerto" lo firma un humano, no un umbral.
- Rondas 8-9 restauradas verificadas íntegras; protocolo post-purga respetado (clon fresco, nada se pushea desde el clon archivado).
- Siguiente ronda propuesta (sesion-10): export Prometheus (sexta ronda deferido: decisión o retirada), refresh manual del desplegable de entregas, migración MCP v2 como ronda dedicada (plan listo), realce en títulos (marginal).

---
Task ID: 42 (Z-DIRECTOR-sesion-04) — renumerado desde 41: la ronda 10 de z2 llegó al remoto durante esta auditoría y tomó el número primero
Agent: z-director (dirección y revisión del conjunto orquesta-rt)
Task: Auditoría dogfood — operar la plataforma como agente de red team en una auditoría real (bootstrap en frío, ciclo completo con IA de frontera real, arsenal, copiloto, webhooks, adversarial) y detectar errores, fallos, mejoras y carencias en operación.

Work Log:
- Entorno propio y reproducible: main 9243d3e, venv de auditoría, BD previa apartada (bootstrap real del primer admin por API), lab :8080, ORQUESTA_LAB_HOGARES dedicado y PUENTE IA réplica fiel del de la consola (GLM real vía SDK; mismas omisiones) — 16 llamadas de frontera durante la sesión.
- Ciclo agéntico F0→F7 completo con razonador y copiloto contra GLM real: F1 OSINT (CT/DNS/robots), F2 recon (fingerprint nginx + vector T1595.002), F3 con plan B honesto, F6 pausado por firma y rechazado deliberadamente, F7 informe con cadena de custodia VÁLIDA y economía de tokens (0,04 USD).
- Boundary: 6 aprobaciones ejercitadas (3 firmadas / 3 rechazadas). Verificación adversarial: 401 sin/falso/none-alg token, 403 cross-tenant en todos los recursos del caso ajeno, kill switch bloquea incluso bajo riesgo, cerrar-todas con alcance por cuenta exacto, anti-SSRF en dos capas (literal + decimal→DNS), HMAC de webhook verificado manualmente con el secreto, F37 verificado EN OPERACIÓN (firma expone raíz; /etc muere tras firma; implantar→retirar con ausencia certificada), escudo LLM01 verificado por canal RAG (marcas_entrada=1) y resistencia del modelo ante inyección directa.
- F38 (ALTO, z3): la firma de evasion.generar NO cubre el payload — api.py:2013 firma solo {host, metodo, formato}; PoC en traza: firma previa con payload benigno auto-autorizó un payload AMSI-bypass distinto ("Autorizada por decisión humana previa"). Rompe la coincidencia EXACTA documentada; recomendación payload_sha256 en la huella + test E2E simétrico al F37.
- HD-2 (z1): avanzar sin vector_elegido encola aprobación degenerada con vector vacío (boundary no la rechaza; el caso no recuerda la elección). HD-1 (z2): re-ejecutar fase duplica evidencias (mismo SHA-256 ×2 en el informe) y el resumen puede regresar (16→0 subdominios) contradiciendo la memoria del caso. HD-3 (z3): bloqueo por fuerza bruta solo en memoria (reiniciar lo limpia; N workers = N×5). HD-6 (z2): el puente IA descarta max_tokens/temperature/response_format — control de coste y salida estructurada sin garantía E2E. HD-7/HD-8 (z1, roadmap): sin MSF no hay explotación HTTP nativa pese al lab con /admin; el lab empaquetado no trae LDAP/AD. HD-4/HD-5/HD-9 y micro-notas documentadas en la bitácora.
- Sin cambios de código de plataforma en esta sesión: auditoría pura con asignación por carril. DOCS: docs/agentes/z-director/sesion-04-auditoria-dogfood-red-team.md + índice README; este registro.

Stage Summary:
- Veredicto: el producto se sostiene en operación real (boundary, confinamiento, LLM01, webhooks, multi-tenant y custodia hacen lo que la documentación promete, verificado con las manos). Primera grieta real del operator-in-command encontrada OPERANDO (no leyendo): F38 — firma del arsenal de evasión sin identidad del payload.
- Órdenes: z3 ataca F38 con prioridad máxima + HD-3 + tabla de "argumentos que firman" para todo el catálogo; z2 ataca HD-1 + HD-6; z1 ataca HD-2 y evalúa HD-7/HD-8 en roadmap.
- Pendientes heredados sin cambios: rotación de secreto_jwt en despliegues derivados, revocación del PAT (tercera petición) y reconocimiento del cierre real de F32 por z3.
