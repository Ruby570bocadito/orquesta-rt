"""Guardrails: control en el límite de la herramienta, no en el prompt.

Principio número uno del blueprint (capítulo 5.1): las instrucciones del
prompt NO son controles de seguridad. La aprobación y el bloqueo viven
FUERA del modelo, como validaciones en el boundary de cada llamada a
herramienta. El modelo propone; el boundary decide; el humano aprueba
lo crítico.

Toda tool call pasa por tres verificaciones independientes:
  1. Permisos de scope (¿el objetivo está en el alcance del ROE?)
  2. Política del ROE (¿técnica prohibida? ¿ventana horaria? ¿techo de ruido?)
  3. Clasificación de riesgo (¿acción destructiva o sensible? -> humano)

La decisión es una de: PERMITIR | REQUIERE_APROBACION | DENEGAR.
Cada decisión se registra en la auditoría inmutable.
"""
from __future__ import annotations

import fnmatch
import hashlib
import ipaddress
import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

from .models import (
    Aprobacion,
    Actor,
    DecisionGuardrail,
    Fase,
    ROEPolitica,
    Severidad,
)

# Margen entre el nivel de ruido PACTADO en el ROE (techo_ruido, escala 0-100,
# visible en la consola con aviso "techo superado") y el corte DURO del
# boundary. El techo del ROE describe el perfil de detección acordado con el
# cliente; el boundary lo traduce a un presupuesto acumulado del caso con
# este margen de seguridad: con techo 50, la denegación dura llega a 250 de
# ruido acumulado — suficiente para un engagement completo sin renegociación,
# nunca infinito. Al cruzar el nivel PACTADO (dentro del margen) el boundary
# sigue operando pero el motivo de cada decisión lo advierte: la auditoría y
# las firmas humanas quedan informadas del exceso sobre lo acordado.
_MARGEN_TECHO_RUIDO = 5


# Catálogo de riesgo por familia de herramienta. Claves = prefijos de tool
# registrados en los servidores MCP. Este mapa es la clasificación de riesgo
# del boundary: no puede ser alterada por el modelo ni por un skill.
_RIESGO_HERRAMIENTAS: dict[str, dict[str, Any]] = {
    # Recon pasivo / enumeración: bajo
    "recon.dns_enum": {"riesgo": "baja", "ruido": 5, "ventana": False},
    "recon.http_probe": {"riesgo": "baja", "ruido": 10, "ventana": False},
    "recon.cert_info": {"riesgo": "baja", "ruido": 5, "ventana": False},
    "recon.tech_fingerprint": {"riesgo": "baja", "ruido": 15, "ventana": True},
    "recon.port_scan": {"riesgo": "media", "ruido": 35, "ventana": True},
    "recon.banner_grab": {"riesgo": "media", "ruido": 15, "ventana": True},
    "recon.reverse_dns": {"riesgo": "baja", "ruido": 5, "ventana": False},
    "recon.http_methods": {"riesgo": "baja", "ruido": 10, "ventana": False},
    "recon.dir_index": {"riesgo": "baja", "ruido": 5, "ventana": False},
    # OSINT pasivo: bajo, sin ventana
    "osint.subdominios_crtsh": {"riesgo": "baja", "ruido": 0, "ventana": False},
    "osint.robots_txt": {"riesgo": "baja", "ruido": 0, "ventana": False},
    "osint.wayback": {"riesgo": "baja", "ruido": 0, "ventana": False},
    "osint.zone_transfer": {"riesgo": "baja", "ruido": 5, "ventana": False},
    "osint.sitemap": {"riesgo": "baja", "ruido": 0, "ventana": False},
    "recon.nmap_servicios": {"riesgo": "media", "ruido": 40, "ventana": True},
    "recon.correos_seguridad": {"riesgo": "baja", "ruido": 0, "ventana": False},
    "recon.rutas_sensibles": {"riesgo": "media", "ruido": 20, "ventana": True},
    "osint.buscar_filtraciones": {"riesgo": "media", "ruido": 0, "ventana": False,
                                   "requiere_aprobacion": True},
    # Evidencias: bajo siempre (escribir en el propio caso)
    "evidencias.guardar": {"riesgo": "baja", "ruido": 0, "ventana": False},
    "evidencias.listar": {"riesgo": "baja", "ruido": 0, "ventana": False},
    "evidencias.verificar": {"riesgo": "baja", "ruido": 0, "ventana": False},
    # C2: integraciones REALES (Sliver gRPC / Mythic GraphQL / Metasploit RPC)
    # configuradas por el operador contra sus instancias autorizadas.
    # c2.estado es lectura del propio framework del operador (baja).
    # Toda TAREA contra objetivos y toda RETIRADA exigen firma humana.
    "c2.estado": {"riesgo": "baja", "ruido": 0, "ventana": False},
    "c2.sliver_tarea": {"riesgo": "alta", "ruido": 55, "ventana": True,
                         "requiere_aprobacion": True},
    "c2.sliver_retirar": {"riesgo": "media", "ruido": 10, "ventana": True,
                           "requiere_aprobacion": True},
    "c2.mythic_tarea": {"riesgo": "alta", "ruido": 55, "ventana": True,
                         "requiere_aprobacion": True},
    "c2.mythic_retirar": {"riesgo": "media", "ruido": 10, "ventana": True,
                           "requiere_aprobacion": True},
    "c2.msf_tarea": {"riesgo": "alta", "ruido": 55, "ventana": True,
                      "requiere_aprobacion": True},
    "c2.msf_retirar": {"riesgo": "media", "ruido": 10, "ventana": True,
                        "requiere_aprobacion": True},
    # Compatibilidad con casos previos al adaptador real
    "c2.registrar_implante": {"riesgo": "alta", "ruido": 60, "ventana": True,
                               "requiere_aprobacion": True},
    "c2.tarea_implante": {"riesgo": "alta", "ruido": 55, "ventana": True,
                           "requiere_aprobacion": True},
    "c2.retirar_implante": {"riesgo": "media", "ruido": 10, "ventana": True,
                             "requiere_aprobacion": True},
    # Explotación y dominio AD: riesgo alto por definición
    "explotar.ejecutar": {"riesgo": "alta", "ruido": 70, "ventana": True,
                           "requiere_aprobacion": True},
    "ad.enumerar_grafo": {"riesgo": "media", "ruido": 25, "ventana": True},
    "ad.enumerar_ldap": {"riesgo": "media", "ruido": 20, "ventana": True},
    "ad.kerberoasting": {"riesgo": "alta", "ruido": 45, "ventana": True,
                          "requiere_aprobacion": True},
    "ad.asrep_roasting": {"riesgo": "alta", "ruido": 30, "ventana": True,
                           "requiere_aprobacion": True},
    "ad.auditar_adcs": {"riesgo": "baja", "ruido": 10, "ventana": True},
    # Phishing: aprobación de plantilla y destinatarios SIEMPRE (cap. 4.8)
    "phishing.crear_plantilla": {"riesgo": "media", "ruido": 0, "ventana": False,
                                  "requiere_aprobacion": True},
    "phishing.enviar_campana": {"riesgo": "alta", "ruido": 0, "ventana": False,
                                 "requiere_aprobacion": True},
    # Arsenal v20 — evasión verificada (YARA real), persistencia real del lab
    # y AD ofensivo (impacket). La generación de artefactos exige firma; el
    # escaneo es lectura local sin ruido; implantar persistencia es de riesgo
    # alto con ventana horaria; retirar es higiene y se fomenta sin firma.
    "evasion.generar": {"riesgo": "media", "ruido": 5, "ventana": False,
                         "requiere_aprobacion": True},
    "evasion.escanear": {"riesgo": "baja", "ruido": 0, "ventana": False},
    "persistencia.implantar": {"riesgo": "alta", "ruido": 40, "ventana": True,
                                "requiere_aprobacion": True},
    "persistencia.verificar": {"riesgo": "baja", "ruido": 5, "ventana": False},
    "persistencia.retirar": {"riesgo": "media", "ruido": 10, "ventana": False},
    "ad.dcsync": {"riesgo": "critica", "ruido": 70, "ventana": True,
                   "requiere_aprobacion": True},
    "ad.pass_the_hash": {"riesgo": "alta", "ruido": 65, "ventana": True,
                          "requiere_aprobacion": True},
    "ad.laps_leer": {"riesgo": "media", "ruido": 10, "ventana": True},
    "ad.gmsa_leer": {"riesgo": "media", "ruido": 10, "ventana": True},
    "ad.trusts": {"riesgo": "baja", "ruido": 5, "ventana": False},
    "ad.rutas_da": {"riesgo": "baja", "ruido": 0, "ventana": False},
    # Acciones destructivas: siempre DENEGADAS salvo firma explícita fuera del
    # ciclo agéntico (jamás ejecutables por el agente). Ejemplo del blueprint:
    # intentar una destructiva y verla bloqueada es la demo de venta.
    "destruir.*": {"riesgo": "critica", "bloqueada": True},
    "wipe.*": {"riesgo": "critica", "bloqueada": True},
    "rm_rf": {"riesgo": "critica", "bloqueada": True},
}


@dataclass
class Veredicto:
    """Resultado de evaluar una tool call en el boundary."""

    decision: DecisionGuardrail
    motivo: str
    riesgo: Severidad = Severidad.BAJA
    ruido_estimado: int = 0
    referencia_roe: str = ""
    aprobacion_id: Optional[str] = None  # si requiere aprobación
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def permitido(self) -> bool:
        return self.decision == DecisionGuardrail.PERMITIR

    @property
    def denegado(self) -> bool:
        return self.decision == DecisionGuardrail.DENEGAR


def _host_en_scope(host: str, roe: ROEPolitica) -> tuple[bool, str]:
    """Comprueba si un host (dominio o IP) está dentro del alcance del ROE."""
    host_limpio = (host or "").strip().lower().replace("*.", "")
    if not host_limpio:
        return False, "objetivo vacío"
    # Exclusiones primero: vetadas aunque parezcan del cliente
    for excl in roe.alcance_excluido:
        if fnmatch.fnmatch(host_limpio, excl.lower()):
            return False, f"'{host_limpio}' está EXCLUIDO explícitamente del ROE ({excl})"
    # CIDRs — cada entrada se evalúa de forma independiente: un CIDR
    # malformado NO aborta el bucle (los válidos posteriores se siguen
    # comprobando). La validación en el modelo ROE hace esto casi
    # inalcanzable; se mantiene como defensa en profundidad.
    try:
        ip = ipaddress.ip_address(host_limpio)
    except ValueError:
        ip = None
    if ip is not None:
        for cidr in roe.alcance_cidrs:
            try:
                red = ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                continue  # CIDR roto: se ignora, no bloquea a los demás
            if ip in red:
                return True, f"IP {host_limpio} dentro de {cidr}"
        return False, f"IP {host_limpio} fuera de los CIDRs del alcance"
    # Dominios (coincidencia de sufijo: sub.dominio.com cubre dominio.com)
    for dom in roe.alcance_dominios:
        dom = dom.lower().lstrip(".")
        if host_limpio == dom or host_limpio.endswith("." + dom):
            return True, f"dominio {host_limpio} dentro de {dom}"
    return False, f"dominio {host_limpio} fuera del alcance del ROE"


def _minutos_hhmm(valor: str) -> Optional[int]:
    """Convierte 'HH:MM' a minutos del día; None si el formato es inválido.

    Estricto a propósito: el boundary no adivina horas. La validación del
    modelo (VentanaHoraria) hace esto casi inalcanzable por API; se mantiene
    como defensa en profundidad para ROE legados en BD. ANTES un formato
    roto devolvía True (fail-open): el engagement quedaba sin control
    horario y sin ningún aviso.
    """
    import re
    if not re.fullmatch(r"\d{1,2}:\d{2}", (valor or "").strip()):
        return None
    h, m = (int(x) for x in valor.split(":"))
    if not (0 <= h <= 23 and 0 <= m <= 59):
        return None
    return h * 60 + m


def _en_ventana_horaria(roe: ROEPolitica, momento: datetime) -> bool:
    """¿Está la ventana horaria del ROE activa en `momento`?

    - Formato inválido: fail-CLOSED (deniega la actividad activa) — el
      control horario nunca se salta por datos malformados.
    - Ventanas que cruzan medianoche (inicio > fin, p. ej. 22:00→06:00):
      válidas y soportadas. El tramo tras medianoche pertenece a la noche
      que arrancó el día anterior (una ventana del viernes 22:00→06:00
      cubre el sábado hasta las 06:00).
    """
    dias = ["lun", "mar", "mie", "jue", "vie", "sab", "dom"]
    inicio = _minutos_hhmm(roe.ventanas_activas.inicio)
    fin = _minutos_hhmm(roe.ventanas_activas.fin)
    if inicio is None or fin is None:
        return False  # fail-closed: ventana indeterminada = actividad denegada
    actual = momento.hour * 60 + momento.minute
    dias_cfg = [d.lower() for d in (roe.ventanas_activas.dias or [])]
    if inicio > fin:
        # Ventana nocturna que cruza medianoche.
        if actual >= inicio:
            return not dias_cfg or dias[momento.weekday()] in dias_cfg
        if actual < fin:
            noche_de_ayer = dias[(momento.weekday() - 1) % 7]
            return not dias_cfg or noche_de_ayer in dias_cfg
        return False
    dia = dias[momento.weekday()]
    if dias_cfg and dia not in dias_cfg:
        return False
    return inicio <= actual < fin


class MotorGuardrails:
    """Evalúa tool calls contra el ROE. Único punto de paso del boundary."""

    def __init__(self, roe: ROEPolitica, memoria=None):
        self.roe = roe
        self.memoria = memoria  # MemoriaCaso para persistir aprobaciones
        # Techo de ruido PERSISTENTE: el ruido ya ejecutado y aprobado en el
        # caso (aprobaciones firmadas) arranca el contador. Antes se creaba a
        # 0 en cada petición y el techo del ROE solo veía el ruido de la fase
        # en curso: el perfil de detección acordado con el cliente podía
        # quedarse sin vigilancia entre fases.
        self.ruido_acumulado = self._ruido_previo()

    def _ruido_previo(self) -> int:
        """Ruido ya autorizado en el caso (suma de aprobaciones aprobadas)."""
        if self.memoria is None:
            return 0
        try:
            filas = self.memoria.listar_aprobaciones(self.roe.engagement_id)
            return sum(int(a["ruido_estimado"] or 0) for a in filas
                       if a["estado"] == "aprobada")
        except Exception:
            return 0  # ante un fallo de lectura, el boundary no se bloquea

    # -- API principal --------------------------------------------------------

    def evaluar(
        self,
        herramienta: str,
        argumentos: dict[str, Any],
        fase: Fase,
        actor: str = "agente",
        momento: Optional[datetime] = None,
    ) -> Veredicto:
        """Único método de entrada del boundary. Idempotente y auditable.

        `momento` permite inyectar el reloj (tests deterministas y replay
        auditado): si es None se usa la hora local actual.
        """
        spec = self._spec_herramienta(herramienta)

        # (0) Herramientas bloqueadas por catálogo (destructivas)
        if spec.get("bloqueada"):
            veredicto = Veredicto(
                decision=DecisionGuardrail.DENEGAR,
                motivo=f"La herramienta '{herramienta}' es de clase destructiva y "
                       "está bloqueada a nivel de boundary: nunca es ejecutable "
                       "por el agente, con o sin aprobación en línea.",
                riesgo=Severidad.CRITICA,
                referencia_roe="catálogo de riesgo (boundary)",
            )
            self._auditar(herramienta, argumentos, fase, veredicto, actor)
            return veredicto

        # (0b) Kill switch del ROE: parada de emergencia activada por el operador
        if self.roe.parada_emergencia:
            veredicto = Veredicto(
                decision=DecisionGuardrail.DENEGAR,
                motivo="PARADA DE EMERGENCIA activa: el operador suspendió toda "
                       "actividad del engagement (kill switch del ROE).",
                riesgo=Severidad.ALTA,
                ruido_estimado=0,
                referencia_roe="parada_emergencia",
            )
            self._auditar(herramienta, argumentos, fase, veredicto, actor)
            return veredicto

        # (0c) Decisión humana previa sobre ESTA acción (mismo tool + args):
        # permite reanudar la fase sin duplicar firmas ni re-pedir la decisión.
        previa = self._decision_previa(herramienta, argumentos)
        riesgo = Severidad(spec.get("riesgo", "media"))
        ruido = int(spec.get("ruido", 40))
        if previa is not None:
            if previa["estado"] == "aprobada":
                self.ruido_acumulado += ruido
                veredicto = Veredicto(
                    decision=DecisionGuardrail.PERMITIR,
                    motivo=f"Autorizada por decisión humana previa "
                           f"({previa['decidida_por'] or 'operador'}): {previa['id']}.",
                    riesgo=riesgo,
                    ruido_estimado=ruido,
                    referencia_roe=f"aprobación previa {previa['id']}",
                )
                self._auditar(herramienta, argumentos, fase, veredicto, actor)
                return veredicto
            veredicto = Veredicto(
                decision=DecisionGuardrail.DENEGAR,
                motivo=f"El operador RECHAZÓ esta acción ({previa['id']})"
                       + (f": \"{previa['comentario_operador']}\""
                          if previa["comentario_operador"] else "") + ".",
                riesgo=riesgo,
                ruido_estimado=0,
                referencia_roe=f"decisión del operador sobre {previa['id']}",
            )
            self._auditar(herramienta, argumentos, fase, veredicto, actor)
            return veredicto

        # (1) Verificación de scope
        objetivo = self._extraer_objetivo(argumentos)
        if objetivo and not self._objetivo_exceptuado(herramienta):
            dentro, motivo_scope = _host_en_scope(objetivo, self.roe)
            if not dentro:
                veredicto = Veredicto(
                    decision=DecisionGuardrail.DENEGAR,
                    motivo=f"Fuera de alcance: {motivo_scope}",
                    riesgo=riesgo,
                    ruido_estimado=ruido,
                    referencia_roe="alcance_dominios / alcance_cidrs / alcance_excluido",
                )
                self._auditar(herramienta, argumentos, fase, veredicto, actor)
                return veredicto

        # (2) Política del ROE: técnicas prohibidas
        tecnica = argumentos.get("tecnica_mitre") or spec.get("tecnica_mitre")
        if tecnica and self._tecnica_prohibida(tecnica):
            veredicto = Veredicto(
                decision=DecisionGuardrail.DENEGAR,
                motivo=f"Técnica {tecnica} prohibida por el ROE del engagement.",
                riesgo=riesgo,
                ruido_estimado=ruido,
                referencia_roe="tecnicas_prohibidas",
            )
            self._auditar(herramienta, argumentos, fase, veredicto, actor)
            return veredicto

        # (2b) Techo de ruido: presupuesto duro del caso. TODO ruido cuenta
        # (también el de herramientas discretas): antes una exención arbitraria
        # ruido>30 dejaba fuera del techo a toda la enumeración silenciosa y
        # el perfil de detección pactado podía violarse sin límite.
        presupuesto = self.roe.techo_ruido * _MARGEN_TECHO_RUIDO
        if self.ruido_acumulado + ruido > presupuesto:
            veredicto = Veredicto(
                decision=DecisionGuardrail.DENEGAR,
                motivo="Techo de ruido del ROE agotado: el perfil de detección "
                       "acordado con el cliente se excedería con esta acción "
                       f"(acumulado {self.ruido_acumulado} + {ruido} > "
                       f"presupuesto {presupuesto}). "
                       "Reduzca actividad o renegocie el ROE.",
                riesgo=riesgo,
                ruido_estimado=ruido,
                referencia_roe=f"techo_ruido={self.roe.techo_ruido} "
                               f"(margen x{_MARGEN_TECHO_RUIDO})",
            )
            self._auditar(herramienta, argumentos, fase, veredicto, actor)
            return veredicto
        # Aviso (no bloqueo) cuando la acción cruza el nivel PACTADO: visible
        # en la auditoría y en el motivo que firma el operador.
        aviso_techo = ""
        if self.ruido_acumulado + ruido > self.roe.techo_ruido:
            aviso_techo = (f" ATENCIÓN: se supera el techo de ruido pactado "
                           f"({self.ruido_acumulado}+{ruido} > "
                           f"{self.roe.techo_ruido}).")

        # (2c) Ventana horaria de actividad activa
        if spec.get("ventana"):
            ahora = momento or datetime.now()
            if not _en_ventana_horaria(self.roe, ahora):
                veredicto = Veredicto(
                    decision=DecisionGuardrail.DENEGAR,
                    motivo=f"Fuera de la ventana horaria autorizada "
                           f"({self.roe.ventanas_activas.inicio}-"
                           f"{self.roe.ventanas_activas.fin} "
                           f"{','.join(self.roe.ventanas_activas.dias)}).",
                    riesgo=riesgo,
                    ruido_estimado=ruido,
                    referencia_roe="ventanas_activas",
                )
                self._auditar(herramienta, argumentos, fase, veredicto, actor)
                return veredicto

        # (3) Clasificación de riesgo: aprobación humana en el boundary
        requiere = spec.get("requiere_aprobacion", False) or (
            self._tecnica_con_aprobacion(tecnica)
        ) or riesgo in (Severidad.ALTA, Severidad.CRITICA)
        if requiere:
            veredicto = Veredicto(
                decision=DecisionGuardrail.REQUIERE_APROBACION,
                motivo=(self._motivo_aprobacion(herramienta, riesgo, ruido, spec)
                        + aviso_techo),
                riesgo=riesgo,
                ruido_estimado=ruido,
                referencia_roe=(
                    "tecnicas_con_aprobacion" if self._tecnica_con_aprobacion(tecnica)
                    else "operator-in-command (umbral de riesgo)"
                ),
            )
            if self.memoria is not None:
                ap = Aprobacion(
                    id=self.memoria.nuevo_id("apr"),
                    engagement_id=self.roe.engagement_id,
                    fase=fase,
                    titulo=f"Aprobación requerida: {herramienta}",
                    descripcion=veredicto.motivo,
                    herramienta=herramienta,
                    argumentos=argumentos,
                    tecnica_mitre=tecnica,
                    riesgo=riesgo,
                    ruido_estimado=ruido,
                    motivo=veredicto.motivo,
                    referencia_roe=veredicto.referencia_roe,
                )
                self.memoria.crear_aprobacion(ap)
                veredicto.aprobacion_id = ap.id
                # Notificación webhook REAL a los receptores suscritos del
                # equipo (v16). Nunca bloquea el boundary ni lanza.
                try:
                    from .webhook import despachar_en_segundo_plano
                except ImportError:
                    from orchestrator.webhook import despachar_en_segundo_plano  # type: ignore
                despachar_en_segundo_plano(
                    "aprobacion.solicitada", self.roe.engagement_id,
                    {"aprobacion_id": ap.id, "fase": fase.value,
                     "titulo": ap.titulo, "riesgo": riesgo.value,
                     "herramienta": herramienta})
            self._auditar(herramienta, argumentos, fase, veredicto, actor)
            return veredicto

        # (4) Permiso normal
        self.ruido_acumulado += ruido
        veredicto = Veredicto(
            decision=DecisionGuardrail.PERMITIR,
            motivo=(f"Dentro de scope y ROE (riesgo {riesgo.value}, ruido {ruido})."
                    + aviso_techo),
            riesgo=riesgo,
            ruido_estimado=ruido,
        )
        self._auditar(herramienta, argumentos, fase, veredicto, actor)
        return veredicto

    # -- helpers ---------------------------------------------------------------

    def _decision_previa(self, herramienta: str, argumentos: dict[str, Any]) -> Optional[dict[str, Any]]:
        """Última decisión humana previa sobre el mismo tool + argumentos.

        La coincidencia es EXACTA (hash de argumentos): aprobar el vector A
        no autoriza el vector B. Devuelve la fila de la aprobación decidida
        o None si nunca se pidió firma para esta acción concreta.
        """
        if self.memoria is None:
            return None
        firma_accion = hashlib.sha256(
            json.dumps({"h": herramienta, "a": argumentos},
                       sort_keys=True, ensure_ascii=False, default=str).encode()
        ).hexdigest()
        for a in self.memoria.listar_aprobaciones(self.roe.engagement_id):
            if a["herramienta"] != herramienta or a["estado"] == "pendiente":
                continue
            try:
                args_guardados = json.loads(a["argumentos_json"])
            except Exception:
                continue
            firma_guardada = hashlib.sha256(
                json.dumps({"h": a["herramienta"], "a": args_guardados},
                           sort_keys=True, ensure_ascii=False, default=str).encode()
            ).hexdigest()
            if firma_guardada == firma_accion:
                return dict(a)
        return None

    @staticmethod
    def _spec_herramienta(herramienta: str) -> dict[str, Any]:
        if herramienta in _RIESGO_HERRAMIENTAS:
            return dict(_RIESGO_HERRAMIENTAS[herramienta])
        for patron, spec in _RIESGO_HERRAMIENTAS.items():
            if "*" in patron and fnmatch.fnmatch(herramienta, patron):
                return dict(spec)
        # Herramienta desconocida: principio de menor privilegio -> aprobación
        return {"riesgo": "media", "ruido": 40, "requiere_aprobacion": True,
                "motivo_extra": "herramienta no catalogada"}

    @staticmethod
    def _extraer_objetivo(argumentos: dict[str, Any]) -> str:
        for clave in ("objetivo", "host", "dominio", "url", "cidr", "ip"):
            if clave in argumentos and argumentos[clave]:
                valor = str(argumentos[clave])
                if valor.startswith(("http://", "https://")):
                    from urllib.parse import urlparse
                    valor = urlparse(valor).hostname or valor
                return valor.split("/")[0].split(":")[0]
        return ""

    @staticmethod
    def _objetivo_exceptuado(herramienta: str) -> bool:
        """Herramientas que no tocan infraestructura del cliente."""
        return herramienta.startswith(("evidencias.", "osint.buscar_filtraciones"))

    def _tecnica_prohibida(self, tecnica: Optional[str]) -> bool:
        if not tecnica:
            return False
        t = tecnica.lower()
        return any(p.lower() in t or t in p.lower()
                   for p in self.roe.tecnicas_prohibidas)

    def _tecnica_con_aprobacion(self, tecnica: Optional[str]) -> bool:
        if not tecnica:
            return False
        t = tecnica.lower()
        return any(p.lower() in t or t in p.lower()
                   for p in self.roe.tecnicas_con_aprobacion)

    @staticmethod
    def _motivo_aprobacion(herramienta: str, riesgo: Severidad, ruido: int,
                           spec: Optional[dict[str, Any]] = None) -> str:
        base = (f"La acción '{herramienta}' (riesgo {riesgo.value}, ruido estimado "
                f"{ruido}) supera el umbral de ejecución autónoma.")
        # El flag vive en el SPEC del boundary (herramienta desconocida →
        # menor privilegio). Antes se comprobaba si el NOMBRE de la
        # herramienta contenía "no catalogada": condición muerta, el aviso
        # jamás aparecía en la firma que ve el operador.
        extra = (" Herramienta no catalogada: se aplica menor privilegio."
                 if spec and spec.get("motivo_extra") else "")
        return base + extra + " El operador debe aprobarla en consola."

    def _auditar(self, herramienta: str, argumentos: dict[str, Any], fase: Fase,
                 veredicto: Veredicto, actor: str) -> None:
        if self.memoria is not None:
            self.memoria.registrar_auditoria(
                engagement_id=self.roe.engagement_id,
                actor=Actor.HUMANO if actor == "humano" else Actor.AGENTE,
                accion=f"boundary:{herramienta}",
                detalle=veredicto.motivo,
                herramienta=herramienta,
                parametros=argumentos,
                resultado=veredicto.decision.value,
                guardrail=veredicto.decision,
            )
