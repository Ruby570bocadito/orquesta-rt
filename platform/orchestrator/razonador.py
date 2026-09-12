"""Motor de razonamiento adaptativo del orquestador.

Este módulo da a la plataforma tres niveles de razonamiento, todos
auditables y todos alimentados EXCLUSIVAMENTE por datos reales del caso
(objetivos, hallazgos, evidencias, ROE, catálogo real de transportes):

1. COBERTURA DETERMINISTA (`evaluar_cobertura`) — análisis puro de la
   superficie real: qué se ha visto, qué está sin explorar, qué huecos
   hay por fase. No necesita LLM: siempre disponible, determinista y
   auditable al céntimo de token.

2. ADAPTABILIDAD SIN MODELO (`prioridades_siguientes`) — motor de reglas
   que reordena las siguientes acciones según lo que el caso ha
   DESCUBIERTO de verdad: si F1 encontró rutas históricas sensibles, la
   prioridad de F2 pasa a verificarlas; si la ventana horaria del ROE
   está cerrada, se prioriza trabajo pasivo. La plataforma se adapta al
   caso aunque no haya ningún LLM configurado.

3. PLANIFICACIÓN Y REFLEXIÓN CON IA (`planificar_fase`,
   `reflexion_fase`) — el modelo (frontera o local, según el router)
   genera un plan de fase propuesto o una autocrítica de la fase
   completada, con confianza por paso. El plan se VALIDA contra el
   catálogo real de transportes: cualquier herramienta inventada por el
   modelo se descarta y se deja constancia. El plan NO ejecuta nada: es
   una propuesta que el operador materializa por el canal de siempre
   (fase + boundary + aprobación humana obligatoria).

Toda traza de razonamiento se persiste con hash criptográfico de entrada
y salida (memoria.guardar_razonamiento): lo que la IA razonó es
evidencia, no humo.
"""
from __future__ import annotations

import json
import re
from datetime import datetime
from typing import Any

try:
    from .models import Fase
except ImportError:  # ejecución como paquete top-level
    from orchestrator.models import Fase  # type: ignore

try:
    from .router import RouterModelos
except ImportError:
    from orchestrator.router import RouterModelos  # type: ignore

# Catálogo REAL de transportes con su fase natural y clasificación de
# ruido (pasivo = no intrusivo; activo = toca la infraestructura objetivo).
# Este catálogo alimenta la validación del plan IA y las prioridades
# mecánicas: una herramienta que no esté aquí NO se propone jamás.
CATALOGO: dict[str, dict[str, str]] = {
    "osint.subdominios_crtsh": {"fase": "F1", "ruido": "pasivo",
        "para": "descubrir subdominios por Certificate Transparency"},
    "osint.robots_txt": {"fase": "F1", "ruido": "pasivo",
        "para": "rutas publicadas y desindexadas del propio objetivo"},
    "osint.wayback": {"fase": "F1", "ruido": "pasivo",
        "para": "rutas históricas del dominio (CDX del Internet Archive)"},
    "osint.sitemap": {"fase": "F1", "ruido": "pasivo",
        "para": "rutas publicadas en sitemap.xml"},
    "osint.buscar_filtraciones": {"fase": "F1", "ruido": "pasivo",
        "para": "credenciales filtradas del dominio (HIBP; requiere API key)"},
    "osint.zone_transfer": {"fase": "F1", "ruido": "pasivo",
        "para": "AXFR contra los NS del dominio (exposición DNS)"},
    "recon.dns_enum": {"fase": "F1", "ruido": "pasivo",
        "para": "resolución A/AAAA/MX/TXT de hosts del alcance"},
    "recon.correos_seguridad": {"fase": "F1", "ruido": "pasivo",
        "para": "postura SPF/DMARC/DKIM del dominio"},
    "recon.port_scan": {"fase": "F2", "ruido": "activo",
        "para": "puertos abiertos del host (lista blanca del ROE)"},
    "recon.nmap_servicios": {"fase": "F2", "ruido": "activo",
        "para": "versiones de servicio con nmap -sV (requiere binario nmap)"},
    "recon.banner_grab": {"fase": "F2", "ruido": "activo",
        "para": "banner SSH/SMB/RDP del puerto expuesto"},
    "recon.http_probe": {"fase": "F2", "ruido": "activo",
        "para": "probe HTTP/S: título, redirecciones, TLS"},
    "recon.cert_info": {"fase": "F2", "ruido": "activo",
        "para": "certificado TLS: emisor, vigencia, SANs"},
    "recon.tech_fingerprint": {"fase": "F2", "ruido": "activo",
        "para": "tecnologías del servidor por cabeceras y HTML"},
    "recon.reverse_dns": {"fase": "F2", "ruido": "pasivo",
        "para": "PTR del host"},
    "recon.http_methods": {"fase": "F2", "ruido": "activo",
        "para": "métodos HTTP peligrosos (OPTIONS)"},
    "recon.dir_index": {"fase": "F2", "ruido": "activo",
        "para": "listados de directorio expuestos"},
    "recon.rutas_sensibles": {"fase": "F2", "ruido": "activo",
        "para": "exposición de .git/.env/backups/server-status"},
}


def _ventana_abierta(roe: dict[str, Any], ahora: datetime | None = None) -> bool:
    """¿Está la ventana activa del ROE abierta ahora mismo?

    MISMAS reglas que el boundary (guardrails._en_ventana_horaria): si el
    razonador y el boundary divergieran, el plan propondría trabajo que el
    boundary denegaría (o al revés). Formato inválido → fail-closed, y las
    ventanas que cruzan medianoche (22:00→06:00) heredan el día del tramo
    inicial en el tramo tras medianoche.
    """
    ventana = roe.get("ventanas_activas") or {}
    dias_cfg = [str(d).lower() for d in (ventana.get("dias") or [])]
    t = ahora or datetime.now()
    nombres = ["lun", "mar", "mie", "jue", "vie", "sab", "dom"]
    try:
        hi = datetime.strptime(str(ventana.get("inicio", "00:00")), "%H:%M").time()
        hf = datetime.strptime(str(ventana.get("fin", "23:59")), "%H:%M").time()
    except ValueError:
        return False  # fail-closed: ventana indeterminada = actividad denegada
    actual = t.time()
    if hi > hf:
        # Ventana nocturna que cruza medianoche.
        if actual >= hi:
            return not dias_cfg or nombres[t.weekday()] in dias_cfg
        if actual < hf:
            return not dias_cfg or nombres[(t.weekday() - 1) % 7] in dias_cfg
        return False
    if dias_cfg and nombres[t.weekday()] not in dias_cfg:
        return False
    return hi <= actual <= hf


# ---------------------------------------------------------------------------
# 1. COBERTURA DETERMINISTA
# ---------------------------------------------------------------------------


def evaluar_cobertura(memoria, engagement_id: str) -> dict[str, Any]:
    """Análisis determinista de la superficie REAL del caso.

    Devuelve el inventario por tipo/estado, hallazgos por severidad y los
    huecos de cobertura por fase (objetivos descubiertos que ninguna
    herramienta ha caracterizado todavía). Sin LLM, sin red: puro SQLite.
    """
    fila = memoria.obtener_engagement(engagement_id)
    if not fila:
        raise ValueError(f"Engagement {engagement_id} no existe")
    objetivos = [dict(o) for o in memoria.listar_objetivos(engagement_id)]
    hallazgos = [dict(h) for h in memoria.listar_hallazgos(engagement_id)]
    evidencias = memoria.listar_evidencias(engagement_id)

    por_tipo: dict[str, dict[str, int]] = {}
    for o in objetivos:
        tipo = o["tipo"]
        por_tipo.setdefault(tipo, {"total": 0, "descubierto": 0, "confirmado": 0,
                                   "riesgo": 0, "explotado": 0, "neutralizado": 0})
        por_tipo[tipo]["total"] += 1
        if o["estado"] in por_tipo[tipo]:
            por_tipo[tipo][o["estado"]] += 1

    por_severidad: dict[str, int] = {}
    for h in hallazgos:
        por_severidad[h["severidad"]] = por_severidad.get(h["severidad"], 0) + 1

    # Huecos: hosts con servicios descubiertos pero sin probe HTTP y
    # dominios sin caracterizar; rutas en riesgo sin verificar en F2.
    hosts = [o["nombre"] for o in objetivos if o["tipo"] == "host"]
    dominios = [o["nombre"] for o in objetivos if o["tipo"] == "dominio"]
    rutas_riesgo = [o for o in objetivos
                    if o["tipo"] == "ruta" and o["estado"] in ("riesgo", "descubierto")]
    servicios = [o["nombre"] for o in objetivos if o["tipo"] == "servicio"]

    # Transportes ya aplicados según auditoría (el detalle registra la
    # herramienta real ejecutada: "transporte X → ...").
    usados: set[str] = set()
    for ev in memoria.listar_auditoria(engagement_id, limite=2000):
        try:
            detalle = ev["detalle"] or ""
        except (KeyError, TypeError, IndexError):
            continue
        for nombre in CATALOGO:
            if nombre in detalle:
                usados.add(nombre)

    huecos: list[dict[str, str]] = []
    if dominios and "recon.dns_enum" not in usados:
        huecos.append({"fase": "F1", "hueco":
                       f"{len(dominios)} dominio(s) sin enumeración DNS"})
    if dominios and "recon.correos_seguridad" not in usados:
        huecos.append({"fase": "F1", "hueco":
                       "postura de correo (SPF/DMARC/DKIM) sin evaluar"})
    if hosts and "recon.port_scan" not in usados:
        huecos.append({"fase": "F2", "hueco":
                       f"{len(hosts)} host(s) sin escaneo de puertos"})
    if hosts and "recon.banner_grab" not in usados:
        huecos.append({"fase": "F2", "hueco":
                       "banners de servicio sin capturar (versiones)"})
    if rutas_riesgo and "recon.rutas_sensibles" not in usados:
        huecos.append({"fase": "F2", "hueco":
                       f"{len(rutas_riesgo)} ruta(s) en riesgo sin verificar "
                       "exposición (.git/.env/backup)"})

    fase_actual = fila["fase_actual"]
    return {
        "fase_actual": fase_actual,
        "estado_fase": fila["estado_fase"],
        "objetivos_total": len(objetivos),
        "objetivos_por_tipo": por_tipo,
        "hallazgos_total": len(hallazgos),
        "hallazgos_por_severidad": por_severidad,
        "evidencias_total": len(evidencias),
        "transportes_aplicados": sorted(usados),
        "huecos": huecos,
        "sin_explorar": {
            "hosts": hosts, "dominios": dominios,
            "servicios": servicios,
            "rutas_en_riesgo": [o["nombre"] for o in rutas_riesgo],
        },
    }


# ---------------------------------------------------------------------------
# 2. ADAPTABILIDAD SIN MODELO (motor de reglas sobre datos reales)
# ---------------------------------------------------------------------------


def prioridades_siguientes(memoria, engagement_id: str,
                           arsenal: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """Reglas de adaptación puras: qué conviene hacer AHORA según lo que
    el caso ha descubierto realmente, el estado de la fase, el ROE
    (ventana/ruido) y lo ya ejecutado. Determinista: mismas entradas,
    misma salida — auditable y explicable línea a línea."""
    fila = memoria.obtener_engagement(engagement_id)
    roe = json.loads(fila["roe_json"])
    cobertura = evaluar_cobertura(memoria, engagement_id)
    objetivos = [dict(o) for o in memoria.listar_objetivos(engagement_id)]
    hallazgos = [dict(h) for h in memoria.listar_hallazgos(engagement_id)]
    fase = cobertura["fase_actual"]
    ventana = _ventana_abierta(roe)
    usados = set(cobertura["transportes_aplicados"])
    excluido = roe.get("alcance_excluido") or []
    dominios = [o["nombre"] for o in objetivos if o["tipo"] == "dominio"]

    propuestas: list[dict[str, Any]] = []

    def _agregar(herramienta: str, objetivo: str, justificacion: str,
                 confianza: float, fase_sugerida: str, intrusivo: bool) -> None:
        bloqueado = intrusivo and not ventana
        propuestas.append({
            "herramienta": herramienta,
            "objetivo": objetivo,
            "justificacion": justificacion,
            "confianza": round(confianza, 2),
            "fase_sugerida": fase_sugerida,
            "estado": "pospuesta_ventana_cerrada" if bloqueado else "propuesta",
        })

    # R1: rutas en riesgo de F1 (robots/wayback) piden verificación en F2.
    for o in objetivos:
        if o["tipo"] == "ruta" and o["estado"] in ("riesgo", "descubierto"):
            _agregar("recon.rutas_sensibles", o["nombre"],
                     f"ruta '{o['nombre']}' marcada {o['estado']} en F1: hay que "
                     "verificar si expone material sensible real", 0.85, "F2",
                     intrusivo=True)

    # R2: hallazgos de cabeceras ausentes → fingerprint + métodos HTTP.
    for h in hallazgos:
        t = h["titulo"].lower()
        if "cabecera" in t and h["activo"]:
            _agregar("recon.tech_fingerprint", h["activo"],
                     f"'{h['titulo']}' en {h['activo']}: el fingerprint aclara "
                     "la pila y refina la recomendación", 0.7, "F2", intrusivo=True)
            _agregar("recon.http_methods", h["activo"],
                     "cabeceras ausentes sugieren higiene HTTP baja: conviene "
                     "comprobar métodos peligrosos", 0.6, "F2", intrusivo=True)

    # R3: dominios sin DNS ni postura de correo.
    for o in objetivos:
        if o["tipo"] == "dominio" and "recon.dns_enum" not in usados:
            _agregar("recon.dns_enum", o["nombre"],
                     "dominio descubierto sin caracterizar: resolución DNS "
                     "básica (A/MX/TXT) barata y pasiva", 0.8, "F1",
                     intrusivo=False)
            break  # una propuesta basta; el resto son variantes del mismo hueco

    # R4: hosts sin escaneo de puertos.
    for o in objetivos:
        if o["tipo"] == "host" and "recon.port_scan" not in usados \
                and o["nombre"] not in excluido:
            _agregar("recon.port_scan", o["nombre"],
                     "host en alcance sin mapa de puertos: primer paso de "
                     "recon activo", 0.75, "F2", intrusivo=True)
            break

    # R5: servicios confirmados sin banner (versiones → vectores reales).
    for o in objetivos:
        if o["tipo"] == "servicio" and "recon.banner_grab" not in usados:
            _agregar("recon.banner_grab", o["nombre"],
                     "servicio abierto sin versión: el banner permite evaluar "
                     "CVEs conocidas sin explotar", 0.7, "F2", intrusivo=True)
            break

    # R6: filtraciones de credenciales no consultadas (pasivo, barato, alto valor).
    if dominios and "osint.buscar_filtraciones" not in usados:
        _agregar("osint.buscar_filtraciones", dominios[0],
                 "sin consulta de filtraciones todavía: credenciales "
                 "expuestas aceleran F3 de forma legítima (requiere HIBP)", 0.65,
                 "F1", intrusivo=False)

    # R7: si hay credenciales confirmadas, F3 es el canal (nunca automático).
    if any(o["tipo"] == "credencial" and o["estado"] in ("confirmado", "riesgo")
           for o in objetivos):
        propuestas.append({
            "herramienta": "(canal de fase F3)",
            "objetivo": "acceso inicial",
            "justificacion": "hay credenciales confirmadas: el operador decide "
                             "vector en F3 con su aprobación obligatoria",
            "confianza": 0.6, "fase_sugerida": "F3", "estado": "canal_fase",
        })

    # R8: hallazgos críticos sin confirmar → prioridad de validación.
    criticas = [h for h in hallazgos
                if h["severidad"] in ("critica", "alta") and h["estado"] == "propuesto"]
    if criticas:
        propuestas.append({
            "herramienta": "(validación de hallazgos)",
            "objetivo": criticas[0]["titulo"],
            "justificacion": f"{len(criticas)} hallazgo(s) alto/crítico en estado "
                             "'propuesto': sin confirmación con evidencia no "
                             "deben llegar al informe final",
            "confianza": 0.9, "fase_sugerida": fase, "estado": "propuesta",
        })

    # R9: playbooks del arsenal (biblioteca de técnicas REAL del despliegue)
    # pertinentes a la fase en curso o a la siguiente, aún sin huella en el
    # caso (ni hallazgo ni solicitud de aprobación con esa técnica ATT&CK).
    # La sugerencia NUNCA ejecuta: el playbook exige su aprobación humana.
    if arsenal:
        trabajadas = {h.get("tecnica_mitre") for h in hallazgos
                      if h.get("tecnica_mitre")}
        trabajadas |= {a.get("tecnica_mitre")
                       for a in (dict(x) for x in
                                 memoria.listar_aprobaciones(engagement_id))
                       if a.get("tecnica_mitre")}
        # Ventana de fases por ORDINAL (los valores del enum llevan sufijo:
        # "F3_acceso_inicial"): pertinentes la fase actual y la siguiente.
        m_fase = re.match(r"^F(\d+)", fase)
        ordinales = {int(m_fase.group(1))} if m_fase else set()
        if m_fase:
            ordinales.add(int(m_fase.group(1)) + 1)

        def _fase_pertinente(fase_skill: str) -> bool:
            m = re.match(r"^F(\d+)", fase_skill or "")
            return bool(m) and int(m.group(1)) in ordinales

        añadidas = 0
        for s in arsenal:
            if añadidas >= 3:
                break
            t = (s.get("tecnica_mitre") or "").strip()
            if not t or t in trabajadas:
                continue
            if not _fase_pertinente(s.get("fase", "")):
                continue
            _agregar(
                f"playbook:{s['nombre']}", t,
                f"el arsenal incluye '{s['nombre']}' para {t} "
                f"({s.get('fase') or 'fase sin fijar'}, riesgo "
                f"{s.get('riesgo', 'media')}): no hay hallazgo ni solicitud "
                "con esa técnica todavía; su ejecución exige aprobación",
                0.55, s.get("fase") or fase, intrusivo=True)
            añadidas += 1

    propuestas.sort(key=lambda p: (-p["confianza"], p["herramienta"]))
    return {
        "fase_actual": fase,
        "ventana_abierta": ventana,
        "cobertura": {k: cobertura[k] for k in
                      ("objetivos_total", "hallazgos_total", "huecos")},
        "prioridades": propuestas[:12],
    }


# ---------------------------------------------------------------------------
# 3. PLANIFICACIÓN Y REFLEXIÓN CON IA
# ---------------------------------------------------------------------------


def _extraer_json(texto: str) -> dict[str, Any] | None:
    """Extrae el último objeto JSON del texto del modelo (soporta bloque
    ```json``` o JSON desnudo). Devuelve None si no hay nada parseable:
    NUNCA se fabrica una estructura de relleno."""
    if "```" in texto:
        bloques = re.findall(r"```(?:json)?\s*(\{.*?\})\s*```", texto, re.DOTALL)
        for bloque in reversed(bloques):
            try:
                return json.loads(bloque)
            except json.JSONDecodeError:
                continue
    m = re.search(r"\{.*\}", texto, re.DOTALL)
    if m:
        try:
            return json.loads(m.group(0))
        except json.JSONDecodeError:
            return None
    return None


def _contexto_para_plan(memoria, engagement_id: str) -> dict[str, Any]:
    fila = memoria.obtener_engagement(engagement_id)
    roe = json.loads(fila["roe_json"])
    prioridades = prioridades_siguientes(memoria, engagement_id)
    return {
        "fase": fila["fase_actual"],
        "roe": {
            "alcance_dominios": roe.get("alcance_dominios", []),
            "alcance_cidrs": roe.get("alcance_cidrs", []),
            "excluido": roe.get("alcance_excluido", []),
            "tecnicas_prohibidas": roe.get("tecnicas_prohibidas", []),
            "techo_ruido": roe.get("techo_ruido", 50),
            "ventana_abierta": _ventana_abierta(roe),
        },
        "cobertura": prioridades["cobertura"],
        "prioridades_mecanicas": prioridades["prioridades"],
    }


SISTEMA_PLAN = (
    "Eres el planificador del orquestador de una plataforma de Red Team. "
    "Genera el plan ADAPTADO de la fase actual a partir de la cobertura real "
    "y las prioridades mecánicas que te entrego. REGLAS:\n"
    "1. SOLO puedes proponer herramientas del CATÁLOGO entregado. Nada fuera "
    "del catálogo. No inventas activos, dominios, IPs ni resultados.\n"
    "2. Cada paso lleva confianza 0-1 y justificación técnica breve.\n"
    "3. Si la ventana del ROE está cerrada, los pasos activos van como "
    "'pospuesta_ventana_cerrada' y priorizas los pasivos.\n"
    "4. Si el alcance no permite más trabajo, dilo: no rellenas por rellenar.\n"
    "5. Máximo 8 pasos, ordenados por prioridad.\n"
    "6. Responde SIEMPRE terminando con un bloque ```json``` exactamente así:\n"
    '```json\n{"pasos": [{"orden": 1, "herramienta": "recon.dns_enum", '
    '"objetivo": "<activo real del caso>", "justificacion": "...", '
    '"confianza": 0.8, "intrusivo": false}]}\n```'
)


def planificar_fase(memoria, router: RouterModelos, engagement_id: str) -> dict[str, Any]:
    """Plan de fase propuesto por IA, validado contra el catálogo REAL.

    - Requiere backend de inferencia: sin él lanza BackendIndisponible
      (no hay plan fingido; el plan mecánico es `prioridades_siguientes`).
    - Descarta pasos con herramientas fuera del catálogo y lo audita.
    - NO ejecuta nada y NO crea aprobaciones: el operador materializa
      cada paso por el canal de fase correspondiente.
    """
    ctx = _contexto_para_plan(memoria, engagement_id)
    fase = Fase(ctx["fase"]) if ctx["fase"] in Fase._value2member_map_ else Fase.F0_SCOPING
    catalogo_txt = "\n".join(
        f"- {nombre} [{v['fase']}|{v['ruido']}]: {v['para']}"
        for nombre, v in sorted(CATALOGO.items()))
    usuario = (
        f"CATÁLOGO DE HERRAMIENTAS REALES:\n{catalogo_txt}\n\n"
        f"ESTADO DEL CASO:\n{json.dumps(ctx, ensure_ascii=False, default=str)}\n\n"
        "Genera el plan adaptado de esta fase.")
    respuesta = router.completar(
        tarea="planificacion_adaptativa", sistema=SISTEMA_PLAN, usuario=usuario,
        fase=fase, max_tokens=1800)
    datos = _extraer_json(respuesta.texto) or {}

    pasos_validos, descartados = [], []
    for paso in datos.get("pasos", [])[:12]:
        if not isinstance(paso, dict):
            continue
        herramienta = str(paso.get("herramienta", "")).strip()
        if herramienta not in CATALOGO:
            descartados.append({"paso": paso, "motivo":
                                "herramienta fuera del catálogo real"})
            continue
        confianza = paso.get("confianza", 0.5)
        try:
            confianza = max(0.0, min(1.0, float(confianza)))
        except (TypeError, ValueError):
            confianza = 0.5
        pasos_validos.append({
            "orden": len(pasos_validos) + 1,
            "herramienta": herramienta,
            "objetivo": str(paso.get("objetivo", ""))[:200],
            "justificacion": str(paso.get("justificacion", ""))[:500],
            "confianza": round(confianza, 2),
            "intrusivo": bool(paso.get("intrusivo", False)),
            "ruido": CATALOGO[herramienta]["ruido"],
        })

    traza = memoria.guardar_razonamiento(
        engagement_id, "plan_fase", fase,
        entrada=ctx, salida={"pasos": pasos_validos, "descartados": descartados,
                             "texto_modelo": respuesta.texto[-2000:]},
        modelo=respuesta.modelo, tipo_modelo=respuesta.tipo.value,
        tokens_entrada=respuesta.tokens_entrada,
        tokens_salida=respuesta.tokens_salida,
        coste_usd=respuesta.coste_usd,
        confianza=(round(sum(p["confianza"] for p in pasos_validos)
                         / len(pasos_validos), 2) if pasos_validos else None))
    return {
        "id": traza["id"],
        "fase": ctx["fase"],
        "pasos": pasos_validos,
        "descartados": descartados,
        "modelo": respuesta.modelo,
        "tipo_modelo": respuesta.tipo.value,
        "tokens": respuesta.tokens_entrada + respuesta.tokens_salida,
        "coste_usd": respuesta.coste_usd,
        "nota": "propuesta del planificador: NO ejecuta nada; cada paso se "
                "materializa por el canal de fase con aprobación humana si "
                "el boundary lo exige",
    }


SISTEMA_REFLEXION = (
    "Eres el crítico de cobertura de una operación de Red Team. Evalúas la "
    "fase que acaba de completarse SOLO con los datos reales entregados. "
    "REGLAS:\n"
    "1. No inventas activos, hallazgos ni resultados que no estén en los datos.\n"
    "2. Estructura OBLIGATORIA con estas secciones exactas:\n"
    "## Observaciones\n(lo que la fase realmente produjo)\n"
    "## Huecos\n(lo que quedó sin cubrir, citando el estado real)\n"
    "## Hipótesis\n(máx. 3, cada una con confianza 0-1 y cómo verificarla "
    "con las herramientas de la plataforma)\n"
    "## Siguientes pasos\n(concretos, accionables, respetando el ROE)\n"
    "3. Sé técnico, directo y honesto: si la fase fue suficiente, dilo.\n"
    "4. Español, máximo 400 palabras."
)


def reflexion_fase(memoria, router: RouterModelos, engagement_id: str) -> dict[str, Any]:
    """Autocrítica de la última fase completada (IA real, datos reales).

    Requiere backend: sin él, BackendIndisponible con el requisito exacto.
    La traza queda persistida con hash y es visible en la consola."""
    fila = memoria.obtener_engagement(engagement_id)
    fase_actual = Fase(fila["fase_actual"]) if fila["fase_actual"] in \
        Fase._value2member_map_ else Fase.F0_SCOPING
    cobertura = evaluar_cobertura(memoria, engagement_id)
    hallazgos = [dict(h) for h in memoria.listar_hallazgos(engagement_id)]
    objetivos = [dict(o) for o in memoria.listar_objetivos(engagement_id)]
    resumenes = memoria.resumen_acumulado(engagement_id)
    datos = {
        "fase_actual": fila["fase_actual"],
        "cobertura": {k: cobertura[k] for k in
                      ("objetivos_por_tipo", "hallazgos_por_severidad",
                       "transportes_aplicados", "huecos", "sin_explorar")},
        "hallazgos": [{"titulo": h["titulo"], "severidad": h["severidad"],
                       "activo": h["activo"], "estado": h["estado"]}
                      for h in hallazgos[:20]],
        "objetivos": [{"nombre": o["nombre"], "tipo": o["tipo"],
                       "estado": o["estado"]} for o in objetivos[:30]],
        "resumenes_previos": resumenes[-3000:] or "(ninguno)",
    }
    usuario = (f"DATOS REALES DEL CASO (fase {fila['fase_actual']}, estado "
               f"'{fila['estado_fase']}'):\n"
               f"{json.dumps(datos, ensure_ascii=False, default=str)}\n\n"
               "Escribe la reflexión de cobertura con la estructura obligatoria.")
    respuesta = router.completar(
        tarea="reflexion_cobertura", sistema=SISTEMA_REFLEXION, usuario=usuario,
        fase=fase_actual, max_tokens=1600)
    confianza = None
    m = re.findall(r"confianza[\"']?\s*[:=]?\s*(0?\.\d+|1\.0|1)\b",
                   respuesta.texto.lower())
    if m:
        try:
            confianza = round(sum(float(x) for x in m) / len(m), 2)
        except (ValueError, ZeroDivisionError):
            confianza = None
    traza = memoria.guardar_razonamiento(
        engagement_id, "reflexion_fase", fase_actual,
        entrada={"fase": fila["fase_actual"], "n_objetivos": len(objetivos),
                 "n_hallazgos": len(hallazgos)},
        salida={"texto": respuesta.texto},
        modelo=respuesta.modelo, tipo_modelo=respuesta.tipo.value,
        tokens_entrada=respuesta.tokens_entrada,
        tokens_salida=respuesta.tokens_salida,
        coste_usd=respuesta.coste_usd, confianza=confianza)
    return {
        "id": traza["id"],
        "fase": fila["fase_actual"],
        "reflexion": respuesta.texto,
        "confianza_media": confianza,
        "modelo": respuesta.modelo,
        "tipo_modelo": respuesta.tipo.value,
        "tokens": respuesta.tokens_entrada + respuesta.tokens_salida,
        "coste_usd": respuesta.coste_usd,
    }
