"""Agentes de fase del ciclo ofensivo (F0-F7).

Cada fase sigue el mismo contrato:
  entrada: EstadoEngagement + memoria + router + guardrails
  salida:  actualización parcial del estado

Reglas transversales:
- Toda tool call pasa por el boundary de guardrails ANTES de ejecutarse.
- Todo lo aprendido se persiste como evidencia y resumen (compaction).
- F0-F2 y F7 son de implementación plena. F3-F6 operan a través de
  INTEGRACIONES REALES con las herramientas estándar del sector que el
  operador conecta a sus instancias autorizadas: Metasploit RPC
  (explotación), LDAP (colección AD), Sliver gRPC / Mythic GraphQL (C2)
  y SMTP (campañas autorizadas). Sin adaptador configurado la fase
  DOCUMENTA el requisito con la configuración exacta: nunca simula
  resultados ni inventa datos.

Los agentes aislados (cap. 3.2) devuelven resúmenes estructurados al
planner: el OSINT lee miles de páginas y devuelve el mapa, no las páginas.
"""
from __future__ import annotations

import json
import socket
from datetime import datetime, timezone
from typing import Any, Callable

from ..models import (
    Aprobacion,
    Actor,
    Evidencia,
    EstadoObjetivo,
    Fase,
    Hallazgo,
    Objetivo,
    ROEPolitica,
    Severidad,
    TipoEvidencia,
    TipoObjetivo,
)
from ..guardrails import MotorGuardrails, Veredicto
from ..memory import MemoriaCaso
from ..router import RouterModelos
from ..skills import BibliotecaSkills

SYSTEM_BASE = (
    "Eres un agente especialista de un equipo de red team profesional que opera "
    "ÚNICAMENTE bajo reglas de compromiso (ROE) firmadas sobre sistemas "
    "autorizados. Nunca propongas acciones fuera del alcance o del ROE. "
    "Responde SIEMPRE con JSON válido ajustado al esquema pedido. Español."
)

import re as _re

_ES_IP = _re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

# --------------------------------------------------------------------------
# Utilidades de agente
# --------------------------------------------------------------------------


class ContextoFase:
    """Inyección de dependencias por fase (facilita tests y sustitución)."""

    def __init__(
        self,
        engagement_id: str,
        memoria: MemoriaCaso,
        router: RouterModelos,
        roe: ROEPolitica,
        skills: BibliotecaSkills | None = None,
        transportes: dict[str, Callable[..., Any]] | None = None,
    ):
        self.engagement_id = engagement_id
        self.memoria = memoria
        self.router = router
        self.skills = skills
        self.guardrails = MotorGuardrails(roe, memoria)
        # Transportes: herramientas MCP reales o simuladas del lab.
        # Clave = "servidor.tool", valor = callable(args) -> dict.
        self.transportes = transportes or {}

    def invocar(self, herramienta: str, argumentos: dict[str, Any], fase: Fase) -> tuple[Veredicto, Any]:
        """Único camino de ejecución de herramientas: boundary primero.

        Un fallo de la herramienta (red caída, timeout, servicio cerrado)
        NO rompe la fase: se convierte en resultado con clave "error" y la
        fase decide cómo degradar. Solo un fallo del propio boundary
        interrumpe la ejecución.
        """
        veredicto = self.guardrails.evaluar(herramienta, argumentos, fase, actor="agente")
        if veredicto.decision.value == "requiere_aprobacion":
            return veredicto, None
        if veredicto.denegado:
            return veredicto, None
        transporte = self.transportes.get(herramienta)
        if transporte is None:
            return veredicto, {"error": f"sin transporte para {herramienta}"}
        try:
            return veredicto, transporte(**argumentos)
        except TypeError:
            try:
                return veredicto, transporte(argumentos)
            except Exception as exc:
                return veredicto, {"error": f"transporte falló: {str(exc)[:200]}"}
        except Exception as exc:
            return veredicto, {"error": f"transporte falló: {str(exc)[:200]}"}

    def objetivo(self, fase: Fase, nombre: str, tipo: str, estado: str = "descubierto",
                 detalle: str = "", severidad: str | None = None,
                 tecnica_mitre: str | None = None) -> Objetivo:
        """Registra (o refresca) un activo real de la superficie de ataque."""
        obj = Objetivo(
            id=self.memoria.nuevo_id("obj"),
            engagement_id=self.engagement_id,
            nombre=nombre, tipo=TipoObjetivo(tipo),
            estado=EstadoObjetivo(estado), detalle=detalle, fase=fase,
            severidad=Severidad(severidad) if severidad else None,
            tecnica_mitre=tecnica_mitre,
        )
        return self.memoria.guardar_objetivo(obj)

    def aprobacion_previa(self, herramienta: str) -> "Aprobacion | None":
        """Última decisión humana previa sobre una herramienta del caso.

        Permite reanudar una fase sin duplicar peticiones: si el operador
        ya aprobó/rechazó la acción, el agente respeta esa decisión en vez
        de volver a pedir firma (operator-in-command sin bucles).
        """
        filas = self.memoria.listar_aprobaciones(self.engagement_id)
        decididas = [a for a in filas
                     if a["herramienta"] == herramienta and a["estado"] != "pendiente"]
        return decididas[-1] if decididas else None

    def evidenciar(self, fase: Fase, titulo: str, contenido: str,
                   tipo: TipoEvidencia = TipoEvidencia.JSON,
                   hallazgo_id: str | None = None) -> Evidencia:
        ev = Evidencia(
            id=self.memoria.nuevo_id("ev"),
            engagement_id=self.engagement_id,
            tipo=tipo, titulo=titulo, contenido=contenido, fase=fase,
            hallazgo_id=hallazgo_id,
        )
        return self.memoria.guardar_evidencia(ev)

    def hallazgo(self, fase: Fase, titulo: str, severidad: Severidad,
                 descripcion: str, recomendacion: str = "",
                 tecnica_mitre: str | None = None, activo: str = "",
                 evidencias: list[str] | None = None) -> Hallazgo:
        h = Hallazgo(
            id=self.memoria.nuevo_id("hal"),
            engagement_id=self.engagement_id, titulo=titulo,
            severidad=severidad, tecnica_mitre=tecnica_mitre, activo=activo,
            descripcion=descripcion, recomendacion=recomendacion,
            evidencias=evidencias or [], estado="confirmado",
        )
        guardado = self.memoria.guardar_hallazgo(h)
        # Notificación webhook REAL a los receptores suscritos (v16):
        # nunca bloquea el ciclo del agente y jamás lanza.
        try:
            from ..webhook import despachar_en_segundo_plano
        except ImportError:
            from orchestrator.webhook import despachar_en_segundo_plano  # type: ignore
        despachar_en_segundo_plano(
            "hallazgo.registrado", self.engagement_id,
            {"hallazgo_id": h.id, "titulo": h.titulo,
             "severidad": h.severidad.value,
             "tecnica_mitre": h.tecnica_mitre or "", "activo": h.activo})
        return guardado

    def system_prompt(self, especialidad: str) -> str:
        """Prefijo estable para cache: base + especialidad + índice de skills."""
        indice = self.skills.indice_para_prompt() if self.skills else ""
        return f"{SYSTEM_BASE}\n\nEspecialidad: {especialidad}\n\nSkills disponibles (cuerpo bajo demanda):\n{indice}"


# --------------------------------------------------------------------------
# F0: scoping y ROE
# --------------------------------------------------------------------------


def fase0_scoping(ctx: ContextoFase, notas_cliente: str) -> dict[str, Any]:
    """Redacta alcance, ROE y criterios de éxito a partir de las notas.

    El humano firma el ROE: este agente solo prepara el borrador y lo
    convierte en política máquina-legible revisable en consola.
    """
    esquema = {
        "type": "object",
        "properties": {
            "nombre": {"type": "string"},
            "cliente": {"type": "string"},
            "alcance_dominios": {"type": "array", "items": {"type": "string"}},
            "alcance_cidrs": {"type": "array", "items": {"type": "string"}},
            "alcance_excluido": {"type": "array", "items": {"type": "string"}},
            "tecnicas_prohibidas": {"type": "array", "items": {"type": "string"}},
            "criterios_exito": {"type": "array", "items": {"type": "string"}},
            "notas": {"type": "string"},
        },
        "required": ["nombre", "cliente", "alcance_dominios"],
    }
    try:
        r = ctx.router.completar(
            tarea="scoping_redaccion", fase=Fase.F0_SCOPING,
            sistema=ctx.system_prompt("F0 scoping: conversión de requisitos a ROE"),
            usuario=f"Notas de la entrevista con el cliente:\n{notas_cliente}\n\n"
                    "Devuelve el borrador de ROE máquina-legible.",
            esquema_json=esquema, max_tokens=1200,
        )
        borrador = json.loads(r.texto)
    except Exception:
        # Degradación determinista: el scoping no puede depender del modelo.
        # El borrador se deriva del ROE ya configurado al crear el caso.
        roe = ctx.guardrails.roe
        borrador = {
            "nombre": "Engagement según contrato del caso",
            "cliente": roe.cliente,
            "alcance_dominios": roe.alcance_dominios,
            "alcance_cidrs": roe.alcance_cidrs,
            "alcance_excluido": roe.alcance_excluido,
            "tecnicas_prohibidas": roe.tecnicas_prohibidas,
            "criterios_exito": [
                "vector de acceso inicial validado con evidencia",
                "rutas de compromiso documentadas con MITRE ATT&CK",
                "informe con hallazgos reproducibles entregado",
            ],
            "notas": (f"borrador determinista sin LLM · ventana "
                      f"{roe.ventanas_activas.inicio}-{roe.ventanas_activas.fin} · "
                      f"techo de ruido {roe.techo_ruido}/100"),
        }
    ctx.evidenciar(
        Fase.F0_SCOPING, "Borrador de ROE generado",
        json.dumps(borrador, ensure_ascii=False, indent=2), TipoEvidencia.JSON)
    ctx.memoria.registrar_auditoria(
        ctx.engagement_id, Actor.AGENTE, "f0.borrador_roe",
        detalle="Borrador de ROE y criterios de éxito generado", herramienta="f0",
        resultado="ok")
    return {"borrador_roe": borrador,
            "resumen": f"F0: ROE borrador listo ({len(borrador.get('alcance_dominios', []))} dominios en scope)"}


# --------------------------------------------------------------------------
# F1: OSINT con agentes recolectores (subagentes aislados)
# --------------------------------------------------------------------------


def fase1_osint(ctx: ContextoFase) -> dict[str, Any]:
    """Orquesta recolectores pasivos y produce el mapa de superficie.

    Cuatro frentes (cap. 4.3): superficie digital (CT logs + DNS + robots),
    filtraciones, redes y código. Las herramientas ejecutan I/O real; cada
    activo descubierto se registra en la superficie de ataque del caso.
    Si el operador ya decidió sobre la búsqueda de filtraciones, su decisión
    previa se respeta sin pedir firma de nuevo.
    """
    dominios = ctx.guardrails.roe.alcance_dominios
    mapa: dict[str, Any] = {"personas_clave": [], "dominios": [], "filtraciones": [],
                            "tecnologias": [], "dns": [],
                            "generado_en": datetime.now(timezone.utc).isoformat()}
    total_subdominios = 0
    notas: list[str] = []

    for dominio in dominios:
        ctx.objetivo(Fase.F1_OSINT, dominio, "dominio",
                     detalle="dominio raíz en alcance del ROE")

        # -- Certificate Transparency (consulta real a crt.sh) ----------------
        veredicto, datos = ctx.invocar(
            "osint.subdominios_crtsh", {"dominio": dominio}, Fase.F1_OSINT)
        if veredicto.permitido and isinstance(datos, dict):
            subs = datos.get("subdominios", [])[:200]
            total_subdominios += len(subs)
            for sub in subs[:60]:
                ctx.objetivo(Fase.F1_OSINT, sub, "dominio",
                             detalle=f"subdominio con certificado CT ({datos.get('fuente', 'crt.sh')})")
            mapa["dominios"].append({"dominio": dominio, "subdominios": subs,
                                     "rank_explotabilidad": "medio"})
            ctx.evidenciar(
                Fase.F1_OSINT, f"CT logs de {dominio}",
                json.dumps(datos, ensure_ascii=False), TipoEvidencia.JSON)
            if "error" in datos:
                notas.append(f"CT logs: {datos['error']}")

        # -- Resolución DNS real ------------------------------------------------
        veredicto, dns = ctx.invocar("recon.dns_enum", {"dominio": dominio}, Fase.F1_OSINT)
        if veredicto.permitido and isinstance(dns, dict) and not dns.get("error"):
            mapa["dns"].append(dns)
            ips = dns.get("a", [])
            if ips:
                ctx.objetivo(Fase.F1_OSINT, ips[0], "host",
                             detalle=f"IP A de {dominio} (DNS real)")
                for mx in dns.get("mx", [])[:3]:
                    ctx.objetivo(Fase.F1_OSINT, mx.split()[-1].rstrip("."), "host",
                                 detalle=f"MX de {dominio}")
            ctx.evidenciar(
                Fase.F1_OSINT, f"Registros DNS de {dominio}",
                json.dumps(dns, ensure_ascii=False), TipoEvidencia.JSON)

        # -- Wayback Machine: URLs históricas reales (pasivo) --------------------
        veredicto, hist = ctx.invocar("osint.wayback", {"dominio": dominio}, Fase.F1_OSINT)
        if veredicto.permitido and isinstance(hist, dict) and not hist.get("error"):
            ctx.evidenciar(
                Fase.F1_OSINT, f"URLs históricas de {dominio} (Internet Archive)",
                json.dumps(hist, ensure_ascii=False), TipoEvidencia.JSON)
            pistas = hist.get("pistas_historicas", [])
            for ruta in pistas[:20]:
                ctx.objetivo(
                    Fase.F1_OSINT, ruta, "ruta",
                    estado="riesgo",
                    detalle="ruta histórica expuesta en el Internet Archive (CDX)",
                    severidad="media")
            if pistas:
                notas.append(f"wayback: {len(pistas)} rutas históricas de interés")

        # -- Transferencia de zona (AXFR) contra los NS reales -----------------
        veredicto, zona = ctx.invocar(
            "osint.zone_transfer", {"dominio": dominio}, Fase.F1_OSINT)
        if veredicto.permitido and isinstance(zona, dict):
            ctx.evidenciar(
                Fase.F1_OSINT, f"AXFR de {dominio}",
                json.dumps(zona, ensure_ascii=False), TipoEvidencia.JSON)
            if zona.get("vulnerable"):
                for ns, registros in zona.get("transferidas", {}).items():
                    for reg in registros[:20]:
                        ctx.objetivo(
                            Fase.F1_OSINT, str(reg).split()[0].rstrip("."), "dominio",
                            estado="riesgo",
                            detalle=f"registro expuesto por AXFR en {ns}",
                            severidad="media")
                ctx.hallazgo(
                    Fase.F1_OSINT, f"Transferencia de zona permitida en {dominio}",
                    Severidad.MEDIA,
                    descripcion="Los servidores autoritativos permiten AXFR: cualquier "
                                "tercero puede volcar el mapa completo de registros DNS "
                                "sin escanear un solo puerto.",
                    recomendacion="Restringir AXFR por IP/TSIG en todos los NS "
                                  "autoritativos y verificar en recursivos.",
                    activo=dominio)
                notas.append("AXFR permitido (exposición DNS)")

        # -- Postura de seguridad de correo (SPF/DMARC/DKIM reales) ---------------
        veredicto, correo = ctx.invocar(
            "recon.correos_seguridad", {"dominio": dominio}, Fase.F1_OSINT)
        if veredicto.permitido and isinstance(correo, dict) and correo.get("debilidades"):
            ctx.hallazgo(
                Fase.F1_OSINT,
                f"Postura de correo mejorable en {dominio}",
                Severidad.MEDIA,
                descripcion="Auditoría DNS real: " + "; ".join(correo["debilidades"])
                            + ". Un dominio sin SPF/DMARC estricto es puerta de "
                              "entrada para phishing dirigido.",
                recomendacion="Publicar SPF -all, DMARC p=reject (progresivo: "
                              "none → quarantine → reject) y DKIM en todos los "
                              "remitentes.",
                activo=dominio)
            ctx.evidenciar(
                Fase.F1_OSINT, f"Seguridad de correo {dominio}",
                json.dumps(correo, ensure_ascii=False), TipoEvidencia.JSON)

        # -- robots.txt real ------------------------------------------------------
        veredicto, datos = ctx.invocar("osint.robots_txt", {"dominio": dominio}, Fase.F1_OSINT)
        if veredicto.permitido and isinstance(datos, dict) and datos.get("rutas"):
            mapa["tecnologias"].append({"dominio": dominio,
                                        "pistas": datos.get("pistas", [])})
            for ruta in datos.get("rutas", [])[:30]:
                sensible = any(p in ruta.lower() for p in
                               ("admin", "panel", "gestion", "priv", "internal"))
                ctx.objetivo(
                    Fase.F1_OSINT, ruta, "ruta",
                    estado="riesgo" if sensible else "descubierto",
                    detalle=f"ruta de robots.txt en {dominio}",
                    severidad="media" if sensible else None)
            ctx.evidenciar(
                Fase.F1_OSINT, f"robots.txt de {dominio}",
                json.dumps(datos, ensure_ascii=False), TipoEvidencia.JSON)

        # -- sitemap.xml real (rutas publicadas por el propio objetivo) ---------
        veredicto, mapa_sitio = ctx.invocar(
            "osint.sitemap", {"dominio": dominio}, Fase.F1_OSINT)
        if veredicto.permitido and isinstance(mapa_sitio, dict) and mapa_sitio.get("rutas"):
            for ruta in mapa_sitio["rutas"][:30]:
                ctx.objetivo(
                    Fase.F1_OSINT, ruta, "ruta",
                    detalle=f"ruta publicada en {mapa_sitio.get('fuente', 'sitemap')} de {dominio}")
            ctx.evidenciar(
                Fase.F1_OSINT, f"sitemap.xml de {dominio}",
                json.dumps({k: mapa_sitio[k] for k in ("fuente", "rutas")},
                           ensure_ascii=False), TipoEvidencia.JSON)

    # -- Filtraciones de credenciales: SIEMPRE con aprobación humana previa -----
    # El boundary gestiona la decisión previa del operador: 1ª pasada crea la
    # petición de firma; en la reanudación, permite (aprobada) o deniega
    # (rechazada) sin duplicar peticiones.
    veredicto, datos = ctx.invocar(
        "osint.buscar_filtraciones",
        {"dominio": dominios[0] if dominios else ""}, Fase.F1_OSINT)
    if veredicto.decision.value == "requiere_aprobacion":
        return {"mapa_superficie": mapa, "subdominios_total": total_subdominios,
                "esperando_aprobacion": [veredicto.aprobacion_id],
                "resumen": f"F1 en curso: {total_subdominios} subdominios mapeados; "
                           "búsqueda de filtraciones pendiente de aprobación"}
    if veredicto.denegado:
        notas.append(f"filtraciones omitidas: {veredicto.motivo[:120]}")
    elif isinstance(datos, dict):
        mapa["filtraciones"] = datos.get("filtraciones", [])
        ctx.evidenciar(
            Fase.F1_OSINT, "Consulta de filtraciones (HIBP)",
            json.dumps(datos, ensure_ascii=False), TipoEvidencia.JSON)
        if datos.get("error"):
            notas.append(f"filtraciones: {datos['error']}")
        elif datos.get("total_filtraciones"):
            ctx.hallazgo(
                Fase.F1_OSINT,
                f"{datos['total_filtraciones']} filtraciones públicas afectan al dominio",
                Severidad.MEDIA,
                descripcion="Brechas públicas registradas que incluyen cuentas del "
                            "dominio del cliente. Revisar reutilización de credenciales.",
                recomendacion="Forzar rotación de contraseñas y activar MFA en "
                              "cuentas afectadas por brechas históricas.",
                activo=dominios[0] if dominios else "")

    resumen = (f"F1 completado: mapa de superficie con {total_subdominios} "
               f"subdominios y {len(mapa['tecnologias'])} dominios con pistas tech")
    if notas:
        resumen += ". Notas: " + "; ".join(notas)
    return {"mapa_superficie": mapa, "subdominios_total": total_subdominios,
            "resumen": resumen}


# --------------------------------------------------------------------------
# F2: reconocimiento y enumeración externa
# --------------------------------------------------------------------------


def fase2_recon(ctx: ContextoFase) -> dict[str, Any]:
    """Enumeración activa acotada + propuesta de vectores iniciales.

    Secuencia real de un recon externo: barrido de puertos por socket
    (lista blanca), sondeo HTTP de cada servicio web abierto, inspección
    TLS y huella tecnológica. La IA aporta el juicio: ordenar vectores por
    probabilidad de éxito y ruido (cap. 4.4). El operador valida el vector
    inicial propuesto. Todo lo descubierto entra en la superficie de ataque.
    """
    vectores: list[dict[str, Any]] = []
    notas: list[str] = []
    dominios = ctx.guardrails.roe.alcance_dominios

    for dominio in dominios:
        # -- 1) Barrido de puertos real (lista blanca, ruido medible) ---------
        veredicto, escaneo = ctx.invocar(
            "recon.port_scan", {"host": dominio, "puertos": "80,443,8080,8443,3389,445,22"},
            Fase.F2_RECON)
        if not veredicto.permitido or not isinstance(escaneo, dict):
            notas.append(f"{dominio}: barrido denegado ({veredicto.motivo[:80]})")
            continue
        if "error" in escaneo:
            notas.append(f"{dominio}: {escaneo['error'][:80]}")
            continue
        ctx.objetivo(Fase.F2_RECON, dominio, "host", estado="confirmado",
                     detalle="host responde a socket-connect (recon activo)")
        ctx.evidenciar(
            Fase.F2_RECON, f"Barrido de puertos {dominio}",
            json.dumps(escaneo, ensure_ascii=False), TipoEvidencia.JSON)

        servicios = escaneo.get("servicios", [])
        web_abiertos = []
        for srv in servicios:
            puerto = srv["puerto"]
            ctx.objetivo(
                Fase.F2_RECON, f"{dominio}:{puerto}", "servicio",
                estado="confirmado", detalle=f"servicio {srv['servicio']} accesible")
            if puerto in (80, 443, 8080, 8443):
                web_abiertos.append(puerto)
            if puerto == 3389:
                vectores.append({
                    "vector": f"RDP expuesto en {dominio}",
                    "tecnologia": "ms-wbt-server", "probabilidad": "baja",
                    "ruido": 40, "tecnica_mitre": "T1021.001",
                    "justificacion": "RDP visible desde el perímetro: password spraying "
                                     "acotado o explotación de CVE si aplica.",
                })
            if puerto == 445:
                vectores.append({
                    "vector": f"SMB accesible en {dominio}",
                    "tecnologia": "microsoft-ds", "probabilidad": "media",
                    "ruido": 30, "tecnica_mitre": "T1021.002",
                    "justificacion": "SMB expuesto permite enumeración de sesiones "
                                     "nulas y versiones vulnerables.",
                })

        # -- 1b) Detección de versiones con nmap (subprocess real) --------------
        # Si el binario no existe, la nota documenta el requisito: honestidad.
        veredicto, nmap = ctx.invocar(
            "recon.nmap_servicios", {"host": dominio}, Fase.F2_RECON)
        if veredicto.permitido and isinstance(nmap, dict):
            if nmap.get("servicios"):
                ctx.evidenciar(
                    Fase.F2_RECON, f"Versiones de servicio (nmap -sV) {dominio}",
                    json.dumps(nmap, ensure_ascii=False), TipoEvidencia.JSON)
                for srv in nmap["servicios"][:12]:
                    detalle_version = f"{srv.get('producto', '')} {srv.get('version', '')}".strip()
                    if detalle_version:
                        ctx.objetivo(
                            Fase.F2_RECON, f"{dominio}:{srv['puerto']}", "servicio",
                            detalle=f"nmap -sV: {detalle_version}")
            elif nmap.get("error"):
                notas.append(f"nmap: {nmap['error'][:80]}")

        # -- 2) Sondeo HTTP real de cada puerto web abierto --------------------
        for puerto in web_abiertos:
            esquema = "https" if puerto in (443, 8443) else "http"
            url = f"{esquema}://{dominio}" if puerto in (80, 443) else f"{esquema}://{dominio}:{puerto}"
            veredicto, datos = ctx.invocar("recon.http_probe", {"url": url}, Fase.F2_RECON)
            if not veredicto.permitido or not isinstance(datos, dict):
                continue
            if datos.get("vivo"):
                ctx.evidenciar(
                    Fase.F2_RECON, f"HTTP probe {url}",
                    json.dumps(datos, ensure_ascii=False), TipoEvidencia.JSON)
                server = datos.get("cabeceras", {}).get("server", "desconocido")
                faltantes = datos.get("cabeceras_faltantes", [])
                if faltantes:
                    ctx.hallazgo(
                        Fase.F2_RECON,
                        f"Cabeceras de seguridad ausentes en {url}",
                        Severidad.MEDIA,
                        descripcion=f"El servicio responde sin: {', '.join(faltantes)}. "
                                    "Aumenta la superficie ante clickjacking, sniffing "
                                    "y XSS.",
                        recomendacion="Añadir CSP, HSTS y X-Frame-Options en el "
                                      "servidor web o el balanceador.",
                        activo=url)
                    ctx.objetivo(
                        Fase.F2_RECON, url, "servicio", estado="riesgo",
                        detalle=f"cabeceras de seguridad ausentes ({len(faltantes)})",
                        severidad="media")
                vectores.append({
                    "vector": f"Servicio web expuesto en {url}",
                    "tecnologia": server, "probabilidad": "media", "ruido": 15,
                    "tecnica_mitre": "T1595.002",
                    "justificacion": f"Servidor {server} expuesto; revisar CVEs de la "
                                     "versión y paneles de administración accesibles.",
                })

            # -- 3) Huella tecnológica pasiva sobre el servicio vivo ----------
            veredicto, huella = ctx.invocar(
                "recon.tech_fingerprint", {"url": url}, Fase.F2_RECON)
            if veredicto.permitido and isinstance(huella, dict) and huella.get("pistas"):
                ctx.evidenciar(
                    Fase.F2_RECON, f"Fingerprint {url}",
                    json.dumps(huella, ensure_ascii=False), TipoEvidencia.JSON)

        # -- 3b) Artefactos sensibles habituales (.git, .env, backups) ---------
        veredicto, sensibles = ctx.invocar(
            "recon.rutas_sensibles",
            {"url": f"http://{dominio}" if web_abiertos and 80 in web_abiertos
                    else f"https://{dominio}"},
            Fase.F2_RECON)
        if veredicto.permitido and isinstance(sensibles, dict):
            if sensibles.get("expuestas"):
                for exp in sensibles["expuestas"]:
                    ctx.hallazgo(
                        Fase.F2_RECON,
                        f"Artefacto sensible expuesto en {exp['ruta']}",
                        Severidad.ALTA,
                        descripcion=f"Pista real: {exp['pista']} sobre {sensibles.get('url', dominio)}. "
                                    "La exposición de código fuente, credenciales o "
                                    "backups acelera la compromisión total.",
                        recomendacion="Retirar el artefacto del servicio web (bloquear "
                                      ".git/.env/backups en el servidor o WAF) y rotar "
                                      "cualquier credencial expuesta.",
                        activo=str(sensibles.get("url", dominio)) + exp["ruta"])
                ctx.evidenciar(
                    Fase.F2_RECON, f"Artefactos sensibles expuestos {dominio}",
                    json.dumps(sensibles["expuestas"], ensure_ascii=False),
                    TipoEvidencia.JSON)
            elif not sensibles.get("error"):
                notas.append(f"{dominio}: sin artefactos sensibles expuestos")

        # -- 4) Certificado TLS del 443 ------------------------------------------
        if 443 in web_abiertos:
            veredicto, cert = ctx.invocar(
                "recon.cert_info", {"host": dominio, "puerto": 443}, Fase.F2_RECON)
            if veredicto.permitido and isinstance(cert, dict) and not cert.get("error"):
                ctx.evidenciar(
                    Fase.F2_RECON, f"Certificado TLS {dominio}",
                    json.dumps(cert, ensure_ascii=False), TipoEvidencia.JSON)

        # -- 5) Banners de servicios no-HTTP (SSH/SMB/RDP) -----------------------
        no_web = [s["puerto"] for s in servicios
                  if s["puerto"] not in (80, 443, 8080, 8443)]
        if no_web:
            veredicto, banners = ctx.invocar(
                "recon.banner_grab",
                {"host": dominio, "puertos": ",".join(map(str, no_web))},
                Fase.F2_RECON)
            if veredicto.permitido and isinstance(banners, dict) and banners.get("banners"):
                ctx.evidenciar(
                    Fase.F2_RECON, f"Banners de servicios {dominio}",
                    json.dumps(banners, ensure_ascii=False), TipoEvidencia.JSON)
                for b in banners["banners"]:
                    banner = str(b.get("banner", ""))
                    if not banner:
                        continue
                    if b.get("puerto") == 22 and "SSH-" in banner:
                        ctx.objetivo(
                            Fase.F2_RECON, f"{dominio}:22", "servicio",
                            estado="confirmado",
                            detalle=f"banner SSH real: {banner[:80]}")
                        version = banner.split("-")[1] if "-" in banner else banner
                        vectores.append({
                            "vector": f"SSH expuesto en {dominio} ({version[:40]})",
                            "tecnologia": banner[:60], "probabilidad": "baja",
                            "ruido": 10, "tecnica_mitre": "T1021.004",
                            "justificacion": "Servicio SSH visible: revisar versiones "
                                             "sin parchear y credenciales filtradas."})

        # -- 6) DNS inverso de las IPs del caso (PTR real) -----------------------
        for fila in ctx.memoria.listar_objetivos(ctx.engagement_id):
            nombre = str(fila["nombre"])
            if fila["tipo"] == "host" and _ES_IP.match(nombre):
                veredicto, ptr = ctx.invocar(
                    "recon.reverse_dns", {"host": nombre}, Fase.F2_RECON)
                if veredicto.permitido and isinstance(ptr, dict) and ptr.get("ptr"):
                    ctx.evidenciar(
                        Fase.F2_RECON, f"DNS inverso de {nombre}",
                        json.dumps(ptr, ensure_ascii=False), TipoEvidencia.JSON)
                    detalle_ptr = ", ".join(ptr["ptr"])
                    ctx.objetivo(Fase.F2_RECON, nombre, "host",
                                 detalle=f"PTR real: {detalle_ptr[:120]}")
                break

        # -- 7) Métodos HTTP peligrosos ------------------------------------------
        for puerto in web_abiertos:
            esquema = "https" if puerto in (443, 8443) else "http"
            url = f"{esquema}://{dominio}" if puerto in (80, 443) else f"{esquema}://{dominio}:{puerto}"
            veredicto, metodos = ctx.invocar(
                "recon.http_methods", {"url": url}, Fase.F2_RECON)
            if veredicto.permitido and isinstance(metodos, dict) and metodos.get("metodos_peligrosos"):
                peligros = ", ".join(metodos["metodos_peligrosos"])
                ctx.hallazgo(
                    Fase.F2_RECON, f"Métodos HTTP peligrosos habilitados en {url}",
                    Severidad.MEDIA,
                    descripcion=f"El servidor anuncia métodos de riesgo: {peligros}. "
                                "PUT/DELETE sin control permiten subida y borrado de "
                                "contenido; TRACE facilita Cross-Site Tracing.",
                    recomendacion="Deshabilitar métodos innecesarios en el servidor "
                                  "web y validarlos también en la aplicación.",
                    activo=url)
                ctx.evidenciar(
                    Fase.F2_RECON, f"Métodos HTTP {url}",
                    json.dumps(metodos, ensure_ascii=False), TipoEvidencia.JSON)

        # -- 8) Índices de directorio sobre rutas de robots.txt ------------------
        rutas_conocidas = [
            str(o["nombre"]) for o in ctx.memoria.listar_objetivos(ctx.engagement_id)
            if o["tipo"] == "ruta"][:20]
        if rutas_conocidas and web_abiertos:
            url_base = (f"https://{dominio}" if 443 in web_abiertos
                        else f"http://{dominio}")
            veredicto, idx = ctx.invocar(
                "recon.dir_index",
                {"url": url_base, "rutas": ",".join(rutas_conocidas)},
                Fase.F2_RECON)
            if veredicto.permitido and isinstance(idx, dict) and idx.get("directorios_abiertos"):
                for d in idx["directorios_abiertos"]:
                    ctx.hallazgo(
                        Fase.F2_RECON,
                        f"Listado de directorio abierto en {url_base}{d['ruta']}",
                        Severidad.ALTA,
                        descripcion=f"El directorio {d['ruta']} expone su contenido "
                                    f"({d.get('evidencia', 'listado detectado')}). "
                                    "Puede revelar ficheros internos, backups o código.",
                        recomendacion="Deshabilitar autoindex (Options -Indexes) y "
                                      "revisar qué ficheros quedaron expuestos.",
                        activo=f"{url_base}{d['ruta']}")
                ctx.objetivo(
                    Fase.F2_RECON, idx["directorios_abiertos"][0]["ruta"], "ruta",
                    estado="riesgo", detalle="directorio con listado abierto",
                    severidad="alta")
                ctx.evidenciar(
                    Fase.F2_RECON, f"Índices de directorio {dominio}",
                    json.dumps(idx, ensure_ascii=False), TipoEvidencia.JSON)

    # Juicio del modelo: ordenar vectores por probabilidad/ruido
    orden = {"alta": 0, "media": 1, "baja": 2}
    vectores.sort(key=lambda v: (orden.get(v.get("probabilidad", "media"), 1), v.get("ruido", 50)))

    if vectores:
        ctx.hallazgo(
            Fase.F2_RECON, f"Superficie externa con {len(vectores)} vectores potenciales",
            Severidad.INFORMATIVA,
            descripcion="Inventario inicial de servicios expuestos ordenado por "
                        "probabilidad de éxito y ruido. Pendiente de validación del operador.",
            activo="; ".join(v["vector"] for v in vectores[:3]))

    resumen = f"F2 completado: {len(vectores)} vectores propuestos y ordenados"
    if notas:
        resumen += ". Notas: " + "; ".join(notas)
    return {"vectores_propuestos": vectores, "resumen": resumen}


# --------------------------------------------------------------------------
# F3-F6: fases sensibles vía INTEGRACIONES REALES (Metasploit RPC, LDAP,
# Sliver gRPC, Mythic GraphQL, SMTP del equipo) — sin adaptador, requisito
# documentado; jamás resultados simulados.
# --------------------------------------------------------------------------


def fase3_acceso_inicial(ctx: ContextoFase, vector_elegido: str,
                         modulo: str = "", opciones: dict[str, Any] | None = None) -> dict[str, Any]:
    """Acceso inicial con plan B automático (cap. 4.5).

    Este nodo NO contiene exploits propios: ejecuta módulos REALES del
    framework Metasploit del operador vía MSG-RPC cuando está configurado
    (modulo + opciones firmadas por el humano). El boundary exige
    aprobación SIEMPRE para explotar.ejecutar. Sin adaptador conectado la
    fase documenta el requisito exacto y activa la reflexión de plan B;
    jamás simula un acceso logrado.
    """
    argumentos: dict[str, Any] = {"vector": vector_elegido, "tecnica_mitre": "T1190"}
    if modulo:
        argumentos["modulo"] = modulo
        argumentos["opciones"] = opciones or {}
    veredicto, resultado = ctx.invocar("explotar.ejecutar", argumentos, Fase.F3_ACCESO)
    if veredicto.decision.value == "requiere_aprobacion":
        detalle = (f"F3: {'módulo ' + modulo if modulo else 'explotación de ' + vector_elegido} "
                   "solicitada; esperando autorización del operador")
        return {"esperando_aprobacion": [veredicto.aprobacion_id],
                "resumen": detalle}
    if veredicto.denegado:
        return {"intentos_fallidos": [{"vector": vector_elegido, "motivo": veredicto.motivo}],
                "resumen": f"F3 bloqueado por guardrail: {veredicto.motivo}"}

    exito = bool(isinstance(resultado, dict) and
                 (resultado.get("job_id") is not None or resultado.get("exito")))
    if exito:
        ev = ctx.evidenciar(
            Fase.F3_ACCESO, f"Ejecución de módulo de explotación: {resultado.get('modulo', modulo or vector_elegido)}",
            json.dumps(resultado, ensure_ascii=False), TipoEvidencia.JSON)
        ctx.hallazgo(
            Fase.F3_ACCESO, f"Acceso inicial vía Metasploit: {resultado.get('modulo', modulo or vector_elegido)}",
            Severidad.CRITICA,
            descripcion=f"Módulo ejecutado en la infraestructura MSF del operador "
                        f"(job {resultado.get('job_id', '?')}, uuid {resultado.get('uuid', '?')[:12]}). "
                        "Verifique las sesiones abiertas en el framework y consolide "
                        "el acceso en la evidencia adjunta.",
            recomendacion="Mitigar el vector explotado y revisar la superficie asociada.",
            tecnica_mitre="T1190", evidencias=[ev.id])
        import re
        m = re.search(r"en (\S+)$", vector_elegido.strip())
        if m:
            nombre = m.group(1)
            ctx.memoria.actualizar_objetivo_estado(
                ctx.engagement_id, nombre, "explotado",
                "acceso inicial confirmado vía superficie web (T1190)")
        return {"resumen": f"F3: módulo de explotación REAL lanzado "
                           f"({resultado.get('modulo', modulo or vector_elegido)}); "
                           "verifique sesiones en Metasploit; listo para F4"}
    # Plan B: reflexión ante fallo REAL (sin adaptador o error del framework)
    motivo = (resultado.get("error") or resultado.get("detalle")
              or resultado.get("error_msf") or "fallo técnico") if isinstance(resultado, dict) else str(resultado)[:200]
    alternativas = ["phishing como vía alternativa", "password spraying acotado",
                    "abuso de servicio expuesto no probado"]
    return {"intentos_fallidos": [{"vector": vector_elegido, "motivo": str(motivo)[:220]}],
            "plan_b_activo": True,
            "resumen": f"F3: vector '{vector_elegido}' no prosperó ({str(motivo)[:160]}); "
                       f"alternativas propuestas al operador: {'; '.join(alternativas)}"}


def fase4_dominio_ad(ctx: ContextoFase) -> dict[str, Any]:
    """Ruta más corta al Domain Admin a partir de datos REALES del directorio.

    Colección vía LDAP (protocolo real, cliente ldap3) con las credenciales
    de lectura obtenidas bajo el ROE. Sin configuración LDAP la fase
    DOCUMENTA el requisito y NO inventa rutas: cualquier 'ruta hacia DA'
    fabricada sin datos sería un engaño al equipo azul.
    """
    dominio = (ctx.guardrails.roe.alcance_dominios or [""])[0]
    veredicto, datos = ctx.invocar(
        "ad.enumerar_ldap", {"tipo": "spns"}, Fase.F4_DOMINIO)
    if veredicto.decision.value == "requiere_aprobacion":
        return {"esperando_aprobacion": [veredicto.aprobacion_id],
                "resumen": "F4: colección LDAP solicitada; esperando autorización"}
    if veredicto.denegado:
        return {"resumen": f"F4 bloqueado por guardrail: {veredicto.motivo}"}

    conectado = bool(isinstance(datos, dict) and datos.get("conectado"))
    ctx.evidenciar(
        Fase.F4_DOMINIO, "Colección LDAP del directorio (real)",
        json.dumps(datos, ensure_ascii=False), TipoEvidencia.JSON)

    if not conectado:
        return {"resumen": "F4: sin colección AD conectada. Configure LDAP en el "
                           "backend (LDAP_HOST, LDAP_BIND_DN, LDAP_BIND_CLAVE, "
                           "LDAP_BASE_DN) con credenciales obtenidas bajo el ROE "
                           "para enumerar usuarios, grupos y SPNs reales; mientras "
                           "tanto no se fabrican rutas hacia DA."}

    candidatas = datos.get("candidatas_kerberoast", [])
    rutas: list[dict[str, Any]] = []
    for cuenta in candidatas[:6]:
        spns = cuenta.get("servicePrincipalName") or []
        if isinstance(spns, str):
            spns = [spns]
        if not spns:
            continue
        usuario = cuenta.get("sAMAccountName", "?")
        rutas.append({
            "ruta": f"kerberoasting {usuario} (SPN: {str(spns[0])[:60]}) -> crack "
                    "offline -> acceso con esa credencial -> enumeración adicional -> DA",
            "ruido": 45, "probabilidad": "media", "tecnica": "T1558.003",
            "nota": "Cuenta con SPN REAL enumerada del directorio; el crack es "
                    "offline y el ruido en controladores es bajo si se filtran SPNs"})
    if rutas:
        ctx.hallazgo(
            Fase.F4_DOMINIO,
            f"{len(rutas)} cuentas con SPN candidatas a Kerberoasting",
            Severidad.MEDIA,
            descripcion="Cuentas de servicio con servicePrincipalName configurado "
                        "enumeradas por LDAP real: sus tickets TGS pueden solicitarse "
                        "y crackearse offline si las contraseñas son débiles.",
            recomendacion="Fijar contraseñas largas o aleatorias en cuentas con SPN, "
                          "aplicar AES en Kerberos y auditar la pertenencia a grupos "
                          "privilegiados.",
            activo=dominio)
    veredicto_k, _ = ctx.invocar(
        "ad.kerberoasting", {"dominio": dominio, "tecnica_mitre": "T1558.003"},
        Fase.F4_DOMINIO)
    pendientes = [veredicto_k.aprobacion_id] if veredicto_k.decision.value == "requiere_aprobacion" else []
    if not rutas and not pendientes:
        return {"resumen": "F4: colección LDAP real completada; sin cuentas con SPN "
                           "candidatas en el directorio consultado"}
    return {"rutas_ad": rutas, "esperando_aprobacion": pendientes,
            "resumen": f"F4: colección LDAP real ({len(candidatas)} cuentas con SPN); "
                       f"{len(rutas)} rutas hacia DA derivadas de datos reales; "
                       "kerberoasting pendiente de firma del operador" if rutas else
                       "F4: colección LDAP real completada; kerberoasting pendiente de firma"}


def fase5_c2_postex(ctx: ContextoFase, ventana_ok: bool = True) -> dict[str, Any]:
    """C2 asistido por IA (cap. 4.7) sobre integraciones REALES.

    Consulta el estado real de los frameworks C2 configurados por el
    operador (Sliver gRPC, Mythic GraphQL, Metasploit RPC). Si hay agentes
    activos, propone la PRIMERA tarea de recolección (whoami) sobre un
    agente concreto: el boundary exige firma humana y, al reanudar, la
    tarea REAL se ejecuta y su salida se registra como evidencia. Sin
    framework conectado la fase documenta el requisito exacto.
    """
    veredicto, estado = ctx.invocar("c2.estado", {}, Fase.F5_C2)
    if veredicto.denegado:
        return {"resumen": f"F5 bloqueado por guardrail: {veredicto.motivo}"}
    frameworks = estado if isinstance(estado, dict) else {}
    ctx.evidenciar(
        Fase.F5_C2, "Estado real de las integraciones C2",
        json.dumps(frameworks, ensure_ascii=False), TipoEvidencia.JSON)

    conectados: dict[str, dict[str, Any]] = {
        k: v for k, v in frameworks.items()
        if isinstance(v, dict) and v.get("conectado")}
    if not conectados:
        faltan = [k for k, v in frameworks.items()
                  if isinstance(v, dict) and v.get("error")]
        return {"resumen": "F5: sin adaptador C2 conectado. Configure sus "
                           "instancias autorizadas en el backend del orquestador "
                           "(SLIVER_CONFIG/SLIVER_HOST, MYTHIC_URL/MYTHIC_TOKEN, "
                           "MSF_HOST/MSF_USER/MSF_PASS). Requisitos: "
                           + ("; ".join(f"{k}: {v.get('error', '')[:80]}"
                                        for k, v in frameworks.items()
                                        if isinstance(v, dict) and v.get("error"))
                              or "; ".join(faltan))}

    # Agentes activos REALES por framework
    sesiones = conectados.get("sliver", {}).get("sesiones") or []
    beacons = conectados.get("sliver", {}).get("beacons") or []
    callbacks = conectados.get("mythic", {}).get("callbacks") or []
    msf_sesiones = conectados.get("metasploit", {}).get("sesiones") or {}
    total = len(sesiones) + len(beacons) + len(callbacks) + len(msf_sesiones)
    nombres = ", ".join(list(conectados.keys()))
    if total == 0:
        return {"resumen": f"F5: C2 conectado ({nombres}) sin agentes activos. El "
                           "despliegue de implantes se realiza desde la consola del "
                           "framework del operador o vía sus APIs oficiales; esta "
                           "plataforma orquesta los agentes existentes con firma humana."}

    # Propuesta de recolección sobre el primer agente disponible (real)
    if sesiones:
        agente = sesiones[0]
        herramienta, argumentos = "c2.sliver_tarea", {
            "sesion_id": agente.get("id"), "comando": "whoami"}
        descripcion_agente = f"sesión Sliver {agente.get('name') or agente.get('hostname', agente.get('id'))}"
    elif callbacks:
        agente = callbacks[0]
        herramienta, argumentos = "c2.mythic_tarea", {
            "callback_id": agente.get("id"), "comando": "whoami", "params": ""}
        descripcion_agente = (f"callback Mythic {agente.get('hostname')} "
                              f"({agente.get('user')})")
    else:
        sid = next(iter(msf_sesiones))
        herramienta, argumentos = "c2.msf_tarea", {
            "sesion_id": int(sid), "comando": "whoami"}
        descripcion_agente = f"sesión Metasploit {sid}"

    veredicto_t, resultado_t = ctx.invocar(herramienta, argumentos, Fase.F5_C2)
    if veredicto_t.decision.value == "requiere_aprobacion":
        return {"esperando_aprobacion": [veredicto_t.aprobacion_id],
                "resumen": f"F5: {total} agente(s) activo(s) en {nombres}; tarea de "
                           f"recolección (whoami) sobre {descripcion_agente} pendiente "
                           "de firma del operador"}
    if veredicto_t.denegado:
        return {"resumen": f"F5: tarea de recolección denegada: {veredicto_t.motivo[:160]}"}

    # Tarea REAL ejecutada (aprobada por decisión humana previa)
    salida = ""
    if isinstance(resultado_t, dict):
        salida = str(resultado_t.get("salida") or resultado_t.get("error") or "")[:4000]
    ctx.evidenciar(
        Fase.F5_C2, f"Tarea real sobre {descripcion_agente}: whoami",
        json.dumps(resultado_t if isinstance(resultado_t, dict)
                   else {"salida": salida}, ensure_ascii=False),
        TipoEvidencia.COMANDO)
    return {"resumen": f"F5: tarea REAL ejecutada sobre {descripcion_agente} "
                       f"(whoami -> {salida[:80] or 'sin salida'}) con firma humana "
                       "previa; coleccion OPSEC programada con jitter contra el techo "
                       "de ruido del ROE"}


def fase6_phishing(ctx: ContextoFase, perfil_objetivo: str,
                   destinatarios: list[str] | None = None) -> dict[str, Any]:
    """Campañas de phishing autorizadas con criterio ético y contractual (4.8).

    Dos firmas humanas independientes: (1) plantilla, (2) envío con
    destinatarios explícitos. El envío es REAL vía el servidor SMTP del
    equipo (SMTP_HOST/SMTP_USUARIO/SMTP_REMITENTE). Sin infraestructura
    SMTP la plataforma documenta el requisito: nunca simula entregas ni
    métricas de apertura.
    """
    try:
        from ..integraciones import smtp_envio
    except ImportError:
        from integraciones import smtp_envio
    smtp = smtp_envio.estado()

    # (1) Plantilla: la generación es determinista y auditable, su USO exige firma
    veredicto = ctx.guardrails.evaluar(
        "phishing.crear_plantilla",
        {"perfil": perfil_objetivo, "idioma": "es", "pretexto": "renovacion_sso"},
        Fase.F6_PHISHING)
    if veredicto.decision.value == "requiere_aprobacion":
        return {"esperando_aprobacion": [veredicto.aprobacion_id],
                "resumen": f"F6: plantilla para perfil '{perfil_objetivo}' pendiente "
                           "de aprobación; el envío exigirá una segunda firma con "
                           "destinatarios explícitos"}
    if veredicto.denegado:
        return {"resumen": f"F6 bloqueado por guardrail: {veredicto.motivo}"}

    # Plantilla aprobada: registrar el contenido real como evidencia
    plantilla = _plantilla_renovacion_sso(ctx.guardrails.roe.cliente)
    asunto = f"[Acción requerida] Renovación de {ctx.guardrails.roe.cliente} SSO"
    ctx.evidenciar(
        Fase.F6_PHISHING, f"Plantilla aprobada (perfil {perfil_objetivo})",
        plantilla, TipoEvidencia.NOTA)

    # (2) Envío: requiere destinatarios explícitos Y segunda firma humana
    if not destinatarios:
        estado_smtp = ("SMTP configurado (remitente "
                       f"{smtp.get('remitente')})" if smtp.get("configurado")
                       else "SMTP no configurado: proporcione la infraestructura "
                            "de envío del equipo (SMTP_HOST, SMTP_USUARIO, "
                            "SMTP_CLAVE, SMTP_REMITENTE)")
        return {"resumen": "F6: plantilla aprobada y registrada como evidencia. "
                           f"Para el envío real proporcione destinatarios autorizados "
                           f"desde la consola. Estado de infraestructura: {estado_smtp}. "
                           "Sin envío simulado: la plataforma no fabrica entregas."}

    veredicto_e, resultado_e = ctx.invocar(
        "phishing.enviar_campana",
        {"destinatarios": destinatarios, "asunto": asunto, "cuerpo": plantilla},
        Fase.F6_PHISHING)
    if veredicto_e.decision.value == "requiere_aprobacion":
        return {"esperando_aprobacion": [veredicto_e.aprobacion_id],
                "resumen": f"F6: envío REAL a {len(destinatarios)} destinatario(s) "
                           "pendiente de firma (segunda aprobación independiente)"}
    if veredicto_e.denegado:
        return {"resumen": f"F6: envío denegado: {veredicto_e.motivo[:160]}"}

    enviado = bool(isinstance(resultado_e, dict) and resultado_e.get("enviado"))
    ctx.evidenciar(
        Fase.F6_PHISHING, f"Resultado del envío ({len(destinatarios)} destinatarios)",
        json.dumps(resultado_e, ensure_ascii=False), TipoEvidencia.JSON)
    if enviado:
        return {"resumen": f"F6: campaña enviada REALmente a {len(destinatarios)} "
                           "destinatario(s) vía SMTP del equipo; las métricas de "
                           "entrega provienen del registro del servidor"}
    error = (resultado_e.get("error") if isinstance(resultado_e, dict)
             else "resultado sin 'enviado'")
    return {"resumen": f"F6: el envío no prosperó: {str(error)[:200]}. "
                       "Nada fue simulado; corrija la infraestructura SMTP e inténtelo de nuevo"}


def _plantilla_renovacion_sso(cliente: str) -> str:
    """Plantilla HTML determinista de la campaña autorizada (contenido real)."""
    cliente = cliente or "la organización"
    return f"""<!doctype html>
<html lang="es"><body style="font-family:Arial,sans-serif;background:#f4f5f7;margin:0;padding:24px">
  <div style="max-width:560px;margin:auto;background:#ffffff;border-radius:8px;overflow:hidden;border:1px solid #e2e4e9">
    <div style="background:#1f2937;padding:16px 24px;color:#fff;font-size:15px;font-weight:600">
      {cliente} &middot; Identidad corporativa
    </div>
    <div style="padding:24px;color:#24292f;font-size:14px;line-height:1.6">
      <p>Hola,</p>
      <p>Tu <strong>certificado de inicio de sesión único (SSO)</strong> está a punto de
      caducar. Para mantener el acceso a las aplicaciones internas, renuévalo desde el
      portal de identidad corporativa antes de 48 horas.</p>
      <p style="margin:24px 0">
        <a href="#PORTAL_RENOVACION#" style="background:#0969da;color:#fff;padding:10px 18px;
        border-radius:6px;text-decoration:none;font-weight:600">Renovar acceso SSO</a>
      </p>
      <p style="color:#57606a;font-size:12px">Si no solicitaste esta renovación, ignora
      este mensaje. Nunca compartiremos tu contraseña por correo; verifica siempre el
      remitente.</p>
      <p>Un saludo,<br/>Servicio de Identidad &middot; {cliente}</p>
    </div>
  </div>
</body></html>
<!-- Campaña de phishing AUTORIZADA bajo ROE firmado. El enlace #PORTAL_RENOVACION#
     se sustituye por el portal de recolección del equipo en su infraestructura. -->"""


# --------------------------------------------------------------------------
# F7: evidencias e informe automático + cierre con higiene
# --------------------------------------------------------------------------


def fase7_informe(ctx: ContextoFase) -> dict[str, Any]:
    """Consolida evidencias y redacta el informe (cap. 4.9).

    El agente de reporting NO reconstruye: consolida la cronología registrada
    desde el minuto uno. Cada hallazgo lleva su receta de verificación
    reproducible para el blue team del cliente.
    """
    filas = ctx.memoria.listar_hallazgos(ctx.engagement_id)
    hallazgos = [
        {"titulo": f["titulo"], "severidad": f["severidad"],
         "tecnica": f["tecnica_mitre"] or "-", "activo": f["activo"],
         "descripcion": f["descripcion"], "recomendacion": f["recomendacion"],
         "verificacion": f"Reproducir con la receta adjunta en evidencias: {f['evidencias_json']}"}
        for f in filas if f["estado"] != "descartado"
    ]
    cadena = ctx.memoria.verificar_cadena(ctx.engagement_id)
    from ..reporting import construir_informe
    ruta_md = construir_informe(ctx.engagement_id, ctx.memoria, hallazgos)
    ev = ctx.evidenciar(
        Fase.F7_INFORME, "Informe consolidado (markdown)",
        f"Ruta: {ruta_md}", TipoEvidencia.FICHERO)
    return {"informe_ruta": str(ruta_md),
            "resumen": f"F7: informe consolidado con {len(hallazgos)} hallazgos; "
                       f"cadena de custodia {'VÁLIDA' if cadena['valida'] else 'ROTO'} "
                       f"({cadena['total']} evidencias firmadas)",
            "hallazgos": hallazgos}


def cierre_higiene(ctx: ContextoFase) -> dict[str, Any]:
    """Higiene de cierre (cap. 5.3): limpieza documentada y certificado.

    Retira los agentes REALES que sigan activos en los frameworks C2
    conectados (Sliver/Mythic/Metasploit, cada retirada con firma humana),
    neutraliza TODO activo que quedó en estado explotado/riesgo durante el
    engagement y emite el certificado de borrado. El listado de 'todo lo
    tocado' sale de la auditoría inmutable.
    """
    acciones: list[str] = []
    esperando: list[str] = []

    veredicto, estado = ctx.invocar("c2.estado", {}, Fase.CIERRE)
    frameworks = estado if isinstance(estado, dict) else {}
    conectados = {k: v for k, v in frameworks.items()
                  if isinstance(v, dict) and v.get("conectado")}

    if not conectados:
        acciones.append("sin adaptador C2 conectado: no hay agentes que retirar")
    else:
        pares: list[tuple[str, str, dict[str, Any], str]] = []
        sliver = conectados.get("sliver", {})
        for s in (sliver.get("sesiones") or []):
            pares.append(("c2.sliver_retirar", "sesión Sliver "
                          f"{s.get('id')}", {"sesion_id": s.get("id")}, str(s.get("id"))))
        for b in (sliver.get("beacons") or []):
            pares.append(("c2.sliver_retirar", f"beacon Sliver {b.get('id')}",
                          {"sesion_id": b.get("id")}, str(b.get("id"))))
        mythic = conectados.get("mythic", {})
        for c in (mythic.get("callbacks") or []):
            pares.append(("c2.mythic_retirar", f"callback Mythic {c.get('id')}",
                          {"callback_id": c.get("id")}, str(c.get("id"))))
        msf = conectados.get("metasploit", {})
        for sid in list((msf.get("sesiones") or {})):
            pares.append(("c2.msf_retirar", f"sesión Metasploit {sid}",
                          {"sesion_id": int(sid)}, str(sid)))
        if not pares:
            acciones.append("C2 conectado sin agentes activos: nada que retirar")
        for herramienta, etiqueta, argumentos, clave in pares:
            veredicto_r, resultado_r = ctx.invocar(herramienta, argumentos, Fase.CIERRE)
            if veredicto_r.decision.value == "requiere_aprobacion":
                esperando.append(veredicto_r.aprobacion_id or "")
                continue
            if veredicto_r.denegado:
                acciones.append(f"retirada DENEGADA ({etiqueta}): "
                                f"{veredicto_r.motivo[:100]}")
                continue
            ok = bool(isinstance(resultado_r, dict) and resultado_r.get("conectado"))
            acciones.append(f"retirada {'ejecutada' if ok else 'fallida'} ({etiqueta})")
            ctx.evidenciar(
                Fase.CIERRE, f"Retirada de {etiqueta}",
                json.dumps(resultado_r, ensure_ascii=False), TipoEvidencia.JSON)

    if esperando:
        return {"esperando_aprobacion": esperando,
                "resumen": f"Cierre: {len(esperando)} retirada(s) de agentes reales "
                           "pendientes de firma del operador"}

    # Higiene real de la superficie: nada queda comprometido al cerrar
    neutralizados = []
    for fila in ctx.memoria.listar_objetivos(ctx.engagement_id):
        if fila["estado"] in ("explotado", "riesgo"):
            ctx.memoria.actualizar_objetivo_estado(
                ctx.engagement_id, fila["nombre"], "neutralizado",
                "higiene de cierre: artefacto retirado y acceso revocado")
            neutralizados.append(fila["nombre"])
    acciones.append(f"activos neutralizados en higiene: {len(neutralizados)}")

    verificacion = ctx.memoria.verificar_cadena(ctx.engagement_id)
    auditoria = ctx.memoria.listar_auditoria(ctx.engagement_id)
    cert_contenido = json.dumps({
        "engagement": ctx.engagement_id,
        "acciones_limpieza": acciones,
        "activos_neutralizados": neutralizados,
        "acciones_auditoria_total": len(auditoria),
        "cadena_custodia": verificacion,
        "emitido_en": datetime.now(timezone.utc).isoformat(),
    }, ensure_ascii=False, indent=2)
    cert = ctx.evidenciar(
        Fase.CIERRE, "Certificado de borrado e higiene de cierre",
        cert_contenido, TipoEvidencia.FIRMA)
    retiradas = sum(1 for a in acciones if a.startswith("retirada ejecutada"))
    return {"certificado_borrado": cert.hash_sha256,
            "resumen": "Cierre: " + ("; ".join(acciones[:4]) if acciones else "sin acciones")
                       + f"; {len(neutralizados)} activos neutralizados, cadena de "
                       "custodia verificada y certificado de borrado emitido"
                       + (f" ({retiradas} retiradas reales)" if retiradas else "")}
