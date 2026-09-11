"""Grafo LangGraph del engagement: máquina de estados F0→cierre.

Arquitectura (cap. 2.6): LangGraph como máquina de estados del engagement,
con nodos por fase y un nodo de CONTROL HUMANO antes de cada transición
crítica. Las aprobaciones vivas en la memoria del caso bloquean el avance:
el grafo se reanuda cuando el operador decide en consola.

El import de langgraph es perezoso: los tests unitarios de dominio
(guardrails, memoria, router) no lo necesitan.
"""
from __future__ import annotations

from typing import Any, Callable, Optional

from .agents.fases import (
    ContextoFase,
    cierre_higiene,
    fase0_scoping,
    fase1_osint,
    fase2_recon,
    fase3_acceso_inicial,
    fase4_dominio_ad,
    fase5_c2_postex,
    fase6_phishing,
    fase7_informe,
)
from .memory import MemoriaCaso
from .models import Actor, EstadoFase, Fase, ROEPolitica
from .router import RouterModelos
from .skills import BibliotecaSkills
from .state import EstadoEngagement

ORDEN_FASES: list[Fase] = [
    Fase.F0_SCOPING, Fase.F1_OSINT, Fase.F2_RECON, Fase.F3_ACCESO,
    Fase.F4_DOMINIO, Fase.F5_C2, Fase.F6_PHISHING, Fase.F7_INFORME, Fase.CIERRE,
]


class OrquestadorEngagement:
    """Ejecuta el ciclo ofensivo fase a fase con control humano explícito.

    Uso típico desde la API / CLI:
        orch = OrquestadorEngagement(engagement_id, memoria, router, roe)
        orch.avanzar()            # ejecuta la fase activa si no hay bloqueos
        orch.avanzar(decisiones)  # reanuda tras aprobar/rechazar en consola
    """

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
        self.roe = roe
        self.ctx = ContextoFase(engagement_id, memoria, router, roe, skills, transportes)
        self._grafo = None  # langgraph opcional; el ciclo también corre secuencial

    # -- construcción del grafo (opcional, si langgraph está instalado) --------

    def construir_grafo(self):
        try:
            from langgraph.graph import END, StateGraph
        except ImportError:
            return None
        g = StateGraph(EstadoEngagement)
        g.add_node("F0", lambda s: self._ejecutar_nodo(s, Fase.F0_SCOPING))
        g.add_node("F1", lambda s: self._ejecutar_nodo(s, Fase.F1_OSINT))
        g.add_node("F2", lambda s: self._ejecutar_nodo(s, Fase.F2_RECON))
        g.add_node("F3", lambda s: self._ejecutar_nodo(s, Fase.F3_ACCESO))
        g.add_node("F4", lambda s: self._ejecutar_nodo(s, Fase.F4_DOMINIO))
        g.add_node("F5", lambda s: self._ejecutar_nodo(s, Fase.F5_C2))
        g.add_node("F6", lambda s: self._ejecutar_nodo(s, Fase.F6_PHISHING))
        g.add_node("F7", lambda s: self._ejecutar_nodo(s, Fase.F7_INFORME))
        g.add_node("cierre", lambda s: self._ejecutar_nodo(s, Fase.CIERRE))
        # Aristas: cadena lineal con cancelación a cierre (parada de emergencia)
        g.add_edge("F0", "F1")
        g.add_edge("F1", "F2")
        g.add_edge("F2", "F3")
        g.add_edge("F3", "F4")
        g.add_edge("F4", "F5")
        g.add_edge("F5", "F6")
        g.add_edge("F6", "F7")
        g.add_edge("F7", "cierre")
        g.add_edge("cierre", END)
        g.set_entry_point("F0")
        # En producción se compila con checkpointer SQLite para reanudar
        # tras fallo: compile(checkpointer=...) según despliegue.
        self._grafo = g
        return g

    # -- ciclo de ejecución ------------------------------------------------------

    def _ejecutar_nodo(self, estado: dict, fase: Fase) -> dict:
        """Despacha la fase activa a su agente y registra la transición."""
        resultado = self.ejecutar_fase(fase)
        self.memoria.actualizar_fase(self.engagement_id, fase, EstadoFase.COMPLETADA.value)
        return {"fase": fase, "resumen": resultado.get("resumen", "")}

    def ejecutar_fase(self, fase: Fase, contexto: dict[str, Any] | None = None) -> dict[str, Any]:
        contexto = contexto or {}
        self.memoria.actualizar_fase(self.engagement_id, fase, EstadoFase.ACTIVA.value)
        self.memoria.registrar_auditoria(
            self.engagement_id, Actor.SISTEMA, f"fase.inicio:{fase.value}",
            herramienta="orquestador", resultado="ok")
        try:
            if fase == Fase.F0_SCOPING:
                res = fase0_scoping(self.ctx, contexto.get("notas_cliente", ""))
            elif fase == Fase.F1_OSINT:
                res = fase1_osint(self.ctx)
            elif fase == Fase.F2_RECON:
                res = fase2_recon(self.ctx)
            elif fase == Fase.F3_ACCESO:
                res = fase3_acceso_inicial(
                    self.ctx, contexto.get("vector_elegido", "servicio web expuesto"),
                    modulo=str(contexto.get("modulo", "") or ""),
                    opciones=contexto.get("opciones") or {})
            elif fase == Fase.F4_DOMINIO:
                res = fase4_dominio_ad(self.ctx)
            elif fase == Fase.F5_C2:
                res = fase5_c2_postex(self.ctx)
            elif fase == Fase.F6_PHISHING:
                res = fase6_phishing(
                    self.ctx, contexto.get("perfil_objetivo", "empleado_generico"),
                    destinatarios=contexto.get("destinatarios") or None)
            elif fase == Fase.F7_INFORME:
                res = fase7_informe(self.ctx)
            elif fase == Fase.CIERRE:
                res = cierre_higiene(self.ctx)
            else:
                res = {"resumen": f"fase {fase.value} sin agente definido"}
        except Exception as exc:  # fallo de fase: auditar y marcar
            self.memoria.registrar_auditoria(
                self.engagement_id, Actor.SISTEMA, f"fase.error:{fase.value}",
                detalle=str(exc), herramienta="orquestador", resultado="error")
            self.memoria.actualizar_fase(self.engagement_id, fase, EstadoFase.BLOQUEADA.value)
            raise

        # Compaction al cerrar la fase (cap. 3.2): resumen denso + presupuesto
        resumen = res.get("resumen", "")
        try:
            compactado = self.router.compactar(
                fase, json.dumps(res, ensure_ascii=False, default=str),
                res.get("hallazgos", []))
        except Exception:
            compactado = resumen
        from .models import ResumenFase
        self.memoria.guardar_resumen_fase(
            ResumenFase(fase=fase, texto=compactado or resumen,
                        hallazgos_clave=[h.get("titulo", "") for h in res.get("hallazgos", [])]),
            self.engagement_id)
        self.memoria.registrar_auditoria(
            self.engagement_id, Actor.SISTEMA, f"fase.fin:{fase.value}",
            detalle=resumen, herramienta="orquestador", resultado="ok")
        return res

    def bloqueos_pendientes(self) -> list:
        """Aprobaciones pendientes: el grafo no avanza mientras existan."""
        return self.memoria.listar_aprobaciones(self.engagement_id, solo_pendientes=True)

    def siguiente_fase(self, actual: Fase) -> Optional[Fase]:
        try:
            i = ORDEN_FASES.index(actual)
        except ValueError:
            return None
        return ORDEN_FASES[i + 1] if i + 1 < len(ORDEN_FASES) else None

    def avanzar(self, contexto: dict[str, Any] | None = None) -> dict[str, Any]:
        """Ejecuta la fase activa si no hay bloqueos y avanza el puntero.

        Contrato operator-in-command:
        - Con aprobaciones pendientes: NO ejecuta nada.
        - Si la fase genera una petición de firma a mitad (esperando_aprobacion):
          queda en espera_aprobacion y el puntero NO avanza; al aprobar, una
          nueva llamada a avanzar() REANUDA la misma fase donde quedó.
        - Si el ROE tiene la parada de emergencia activa: no se ejecuta nada.
        """
        fila = self.memoria.obtener_engagement(self.engagement_id)
        if fila["roe_json"] and ROEPolitica.model_validate_json(fila["roe_json"]).parada_emergencia:
            return {"ejecutada": False, "fase": fila["fase_actual"],
                    "resumen": "PARADA DE EMERGENCIA activa: el ciclo está suspendido "
                               "por decisión del operador.",
                    "bloqueos": [], "parada": True}

        bloqueos = self.bloqueos_pendientes()
        if bloqueos:
            return {"ejecutada": False, "bloqueos": [b["id"] for b in bloqueos],
                    "resumen": f"{len(bloqueos)} aprobación(es) pendientes: el "
                               "principio operator-in-command detiene el avance"}
        fase_actual = Fase(fila["fase_actual"])
        estado_fila = fila["estado_fase"]
        # "bloqueada" admite reintento: el operador decide reintentar una
        # fase que falló (p. ej. por una incidencia de infraestructura).
        if estado_fila in ("pendiente", "activa", "espera_aprobacion", "bloqueada"):
            resultado = self.ejecutar_fase(fase_actual, contexto)
            esperando = resultado.get("esperando_aprobacion") or []
            bloqueos_tras = [b["id"] for b in self.bloqueos_pendientes()]
            if esperando or bloqueos_tras:
                # La fase pide firma humana: se queda aquí, sin avanzar.
                self.memoria.actualizar_fase(
                    self.engagement_id, fase_actual, EstadoFase.ESPERA_APROBACION.value)
                return {"ejecutada": True, "fase": fase_actual.value,
                        "resultado": resultado,
                        "bloqueos": esperando or bloqueos_tras,
                        "espera": True}
            self.memoria.actualizar_fase(
                self.engagement_id, fase_actual, EstadoFase.COMPLETADA.value)
            # El certificado de borrado del cierre se persiste en el caso
            if fase_actual == Fase.CIERRE and resultado.get("certificado_borrado"):
                self.memoria._conn.execute(
                    "UPDATE engagements SET certificado_borrado=?, actualizado_en=? WHERE id=?",
                    (resultado["certificado_borrado"], MemoriaCaso._ts_static(), self.engagement_id),
                )
                self.memoria._conn.commit()
            siguiente = self.siguiente_fase(fase_actual)
            if siguiente:
                self.memoria.actualizar_fase(self.engagement_id, siguiente, EstadoFase.PENDIENTE.value)
            return {"ejecutada": True, "fase": fase_actual.value,
                    "resultado": resultado, "bloqueos": [], "espera": False}
        return {"ejecutada": False, "fase": fase_actual.value,
                "resumen": "fase ya completada; avanza con siguiente_fase()",
                "bloqueos": []}
