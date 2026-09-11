"""Capa MITRE ATT&CK Navigator del caso (v14).

El ATT&CK Navigator (https://mitre-attack.github.io/attack-navigator/) es el
estándar del sector para visualizar cobertura de técnicas: las plataformas de
emulación adversaria (MITRE Caldera, Atomic Red Team) y de gestión de
operaciones ofensivas (PlexTrac, AttackForge) entregan una capa JSON que el
equipo azul importa para cruzar cobertura ofensiva con defensas.

Principio no negociable — SOLO datos reales del caso:
- hallazgos.tecnica_mitre     → técnica OBSERVADA con score por severidad.
- aprobaciones.tecnica_mitre  → técnica INTENTADA (solicitud de aprobación;
                                incluye rechazadas, que también son intento).
Si un hallazgo no lleva técnica ATT&CK, no entra en la capa: no se infiere,
no se adivina, no se rellena. El mapeo técnico→táctica lo resuelve el propio
Navigator a partir del ID (la capa no fija táctica: la técnica se pinta en
todas las tácticas donde existe, sin dataset local que mantener).

Formato: layer 4.6 del Navigator (JSON importable por URL o fichero).
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any

# ID ATT&CK válido: técnica T#### o subtécnica T####.###.
_RE_TECNICA = re.compile(r"^T\d{4}(?:\.\d{3})?$")

# Score de la capa por severidad de hallazgo (escala Navigator 0-100).
_SCORE_SEVERIDAD = {
    "critica": 100, "alta": 80, "media": 60, "baja": 40, "informativa": 10,
}

# Mismo lenguaje de color que el informe (consistencia visual de entregables).
_COLOR_SEVERIDAD = {
    "critica": "#b91c1c", "alta": "#c2410c", "media": "#a16207",
    "baja": "#3f6212", "informativa": "#52525b",
}


def construir_capa_navigator(memoria, engagement_id: str) -> dict[str, Any]:
    """Construye la capa Navigator del engagement con técnicas reales.

    Devuelve el dict de la capa (serializable a JSON). Lanza ValueError si
    el engagement no existe (el endpoint lo traduce a 404).
    """
    fila = memoria.obtener_engagement(engagement_id)
    if fila is None:
        raise ValueError(f"Engagement {engagement_id} no existe")

    hallazgos = [dict(h) for h in memoria.listar_hallazgos(engagement_id)]
    aprobaciones = [dict(a) for a in memoria.listar_aprobaciones(engagement_id)]

    # --- técnicas observadas (hallazgos) -------------------------------------
    tecnicas: dict[str, dict[str, Any]] = {}

    def _entrar(tecnica: str) -> dict[str, Any]:
        if tecnica not in tecnicas:
            tecnicas[tecnica] = {
                "techniqueID": tecnica,
                "enabled": True,
                "comment": "",
                "metadata": [],
                "links": [],
            }
        return tecnicas[tecnica]

    por_tecnica: dict[str, list[dict[str, Any]]] = {}
    for h in hallazgos:
        t = (h.get("tecnica_mitre") or "").strip()
        if _RE_TECNICA.fullmatch(t):
            por_tecnica.setdefault(t, []).append(h)

    for t, lista in por_tecnica.items():
        entrada = _entrar(t)
        # Score: la severidad MÁXIMA de los hallazgos de esa técnica.
        orden = {"critica": 4, "alta": 3, "media": 2, "baja": 1, "informativa": 0}
        mejor = max(lista, key=lambda h: orden.get(h.get("severidad", ""), -1))
        sev = mejor.get("severidad", "informativa")
        entrada["score"] = _SCORE_SEVERIDAD.get(sev, 10)
        entrada["color"] = _COLOR_SEVERIDAD.get(sev, _COLOR_SEVERIDAD["informativa"])
        titulos = "; ".join(
            f"[{h.get('severidad', '?')}] {h.get('titulo', 'sin título')} "
            f"({h.get('estado', '?')})" for h in lista)
        entrada["comment"] = f"Observada en {len(lista)} hallazgo(s): {titulos}"
        entrada["metadata"].append({"name": "Hallazgos", "value": str(len(lista))})

    # --- técnicas intentadas (aprobaciones, incluidas las rechazadas) --------
    por_aprob: dict[str, list[dict[str, Any]]] = {}
    for a in aprobaciones:
        t = (a.get("tecnica_mitre") or "").strip()
        if _RE_TECNICA.fullmatch(t):
            por_aprob.setdefault(t, []).append(a)

    for t, lista in por_aprob.items():
        entrada = _entrar(t)
        autorizadas = sum(1 for a in lista if a.get("estado") == "aprobada")
        if "score" not in entrada:
            # Intentada pero sin hallazgo asociado: se marca sin score —
            # el Navigator la muestra como anotada, no como cubierta.
            entrada["comment"] = (
                f"Intentada en {len(lista)} solicitud(es) de aprobación "
                f"({autorizadas} autorizada(s)).")
        else:
            entrada["comment"] += (
                f" Intentada además en {len(lista)} solicitud(es) de "
                f"aprobación ({autorizadas} autorizada(s)).")
        entrada["metadata"].append({"name": "Solicitudes", "value": str(len(lista))})
        entrada["metadata"].append({"name": "Autorizadas", "value": str(autorizadas)})

    tecnicas_ordenadas = [tecnicas[k] for k in sorted(tecnicas)]

    # --- cadena de custodia en el momento de la exportación ------------------
    cadena = memoria.verificar_cadena(engagement_id)

    generados = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    capa: dict[str, Any] = {
        "name": f"OrquestaRT — {fila['nombre']} ({engagement_id})",
        "versions": {"attack": "17", "navigator": "5.1.0", "layer": "4.6"},
        "domain": "enterprise-attack",
        "description": (
            f"Capa de cobertura ofensiva del engagement {engagement_id} "
            f"(cliente: {fila['cliente']}). Técnicas observadas en hallazgos "
            f"y técnicas intentadas vía solicitudes de aprobación. Generada "
            f"por la plataforma OrquestaRT el {generados}. Sin datos de "
            f"relleno: si una técnica no figura, no se observó ni se intentó."),
        "filters": {
            "platforms": ["Windows", "Linux", "macOS", "Network", "IaaS",
                          "SaaS", "Office 365", "Google Workspace",
                          "Containers", "AWS", "GCP", "Azure", "Azure AD"],
            "hasDetections": 0,
        },
        "layout": {
            "layout": "side", "aggregateFunction": "average",
            "showID": True, "showName": True, "viewMode": "graph",
            "toggleTable": False,
        },
        "techniques": tecnicas_ordenadas,
        "gradient": {
            "colors": ["#3f6212", "#a16207", "#b91c1c"],
            "minValue": 0, "maxValue": 100,
        },
        "legendItems": [
            {"label": "Hallazgo crítico", "color": "#b91c1c"},
            {"label": "Hallazgo alto", "color": "#c2410c"},
            {"label": "Hallazgo medio", "color": "#a16207"},
            {"label": "Hallazgo bajo", "color": "#3f6212"},
            {"label": "Informativa / intentada", "color": "#52525b"},
        ],
        "metadata": [
            {"name": "Generado", "value": generados},
            {"name": "OrquestaRT", "value": "capa de engagement red team orquestado por IA"},
            {"name": "Cadena de custodia",
             "value": "VÁLIDA" if cadena.get("valida") else "INVÁLIDA — revisar"},
            {"name": "Evidencias firmadas", "value": str(cadena.get("total", 0))},
        ],
        "links": [],
    }
    return capa


def registrar_capa(memoria, engagement_id: str, capa: dict[str, Any]) -> None:
    """Deja constancia de la exportación en la auditoría del caso."""
    from .models import Actor, DecisionGuardrail

    memoria.registrar_auditoria(
        engagement_id, Actor.SISTEMA, "caso.capa_navigator",
        detalle=(f"capa ATT&CK Navigator exportada: {len(capa['techniques'])} "
                 "técnicas (observadas + intentadas)"),
        guardrail=DecisionGuardrail.PERMITIR)
