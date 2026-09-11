"""Estado compartido del grafo LangGraph (memoria del engagement).

El grafo es la máquina de estados del engagement (capítulo 2.6): cada
transición es auditable, reanudable tras un fallo y aprobable por un
humano. El estado viaja entre nodos por el canal de LangGraph y se
persiste en la memoria del caso.
"""
from __future__ import annotations

from typing import Annotated, Any, Optional

from typing_extensions import TypedDict

from .models import Actor, Fase, Severidad


def _fusionar_listas(actual: list, nuevo: list) -> list:
    """Reductor de LangGraph: acumula listas deduplicando por identidad."""
    return actual + [x for x in nuevo if x not in actual]


class EstadoEngagement(TypedDict, total=False):
    """Estado canónico del engagement mientras avanza por el grafo.

    Campos clave:
    - resumen: compaction acumulada (memoria entre fases, no historia lineal)
    - datos_referenciados: rutas a ficheros del caso, nunca contenidos
    - veredictos_pendientes: aprobaciones esperando al operador
    """

    engagement_id: str
    fase: Fase
    objetivo_general: str

    # Memoria del caso (contexto en ficheros + resumen, cap. 3.2)
    resumen: str
    datos_referenciados: Annotated[list[str], _fusionar_listas]

    # Superficie descubierta (F1/F2)
    mapa_superficie: dict[str, Any]          # personas, dominios, techs priorizadas
    vectores_propuestos: list[dict[str, Any]]  # ordenados por probabilidad/ruido

    # Rutas AD (F4)
    rutas_ad: list[dict[str, Any]]

    # Hallazgos y evidencias (ids en la memoria del caso)
    hallazgos: Annotated[list[str], _fusionar_listas]
    evidencias: Annotated[list[str], _fusionar_listas]

    # Control humano
    veredictos_pendientes: Annotated[list[str], _fusionar_listas]
    decisiones_humanas: Annotated[list[dict[str, Any]], _fusionar_listas]

    # Economía y errores (plan B / reflexión)
    tokens_fase: int
    intentos_fallidos: Annotated[list[dict[str, Any]], _fusionar_listas]
    plan_b_activo: bool

    # Salida final (F7)
    informe_ruta: Optional[str]
    certificado_borrado: Optional[str]
    severidad_maxima: Optional[Severidad]
    actores: list[Actor]
