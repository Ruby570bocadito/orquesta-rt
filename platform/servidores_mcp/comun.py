"""Utilidades compartidas de los servidores MCP — z3 (sesión de auditoría 4).

Antes, cada servidor MCP duplicaba (con variaciones) tres controles:
  1. La política TLS del cliente de sondeo (verify según RECON_TLS_ESTRICTO),
     con un fallback "fail-open" a verify=False si orchestrator no importaba.
  2. El saneado de contenido externo (mitigación de inyección indirecta de
     prompts, LLM01) — solo lo implementaba el servidor osint, así que el
     recon devolvía títulos/cabeceras/generators SIN sanear.
  3. La validación del formato del dominio objetivo (ninguna herramienta la
     tenía: osint.robots_txt interpolaba el dominio en la posición de
     autoridad de la URL → SSRF a hosts arbitrarios).

Este módulo unifica los tres controles para que NO puedan volver a diverger
entre servidores. No depende del SDK de MCP ni de orchestrator: sirve tanto
en despliegues completos como en despliegues solo-MCP.
"""
from __future__ import annotations

import os
import re

import httpx

# ---------------------------------------------------------------------------
# 1. Política TLS de los sondeos (misma semántica que
#    orchestrator.transportes.RECON_TLS_ESTRICTO, sin importarlo):
#    por defecto el lab usa certificados autofirmados (verify=False) y
#    RECON_TLS_ESTRICTO=1 fuerza la verificación. El valor SIEMPRE se decide
#    aquí: nunca un verify=False hardcoded en un servidor MCP.
# ---------------------------------------------------------------------------


def verificar_tls() -> bool:
    """True si los sondeos https deben verificar el certificado del servidor."""
    return os.environ.get("RECON_TLS_ESTRICTO", "") == "1"


def cliente_recon(**kwargs) -> httpx.Client:
    """Cliente httpx del recon/osint con la política TLS ya aplicada.

    El kwarg `verify` se fuerza desde aquí salvo que el caller lo pase
    explícito (no debería): evita que un verify=False quede hardcoded y
    que un servidor MCP nuevo "olvide" la política.
    """
    kwargs.setdefault("verify", verificar_tls())
    return httpx.Client(**kwargs)


# ---------------------------------------------------------------------------
# 2. Saneado de contenido externo (LLM01 en profundidad)
# ---------------------------------------------------------------------------

_PATRONES_INYECCION = (
    r"(?i)ignora (todas )?(las )?(instrucciones|reglas|roe)",
    r"(?i)system\s*prompt",
    r"(?i)<\|.*?\|>",
    r"(?i)exfiltra|filtra las credenciales",
)


def saneado(texto: str, max_len: int = 200_000) -> str:
    """Trata contenido externo como dato NO CONFIABLE.

    Elimina patrones clásicos de inyección de prompts incrustados en el
    contenido recogido (cabeceras Server/X-Powered-By, <title>, meta
    generator, robots.txt...) antes de que llegue a cualquier modelo.
    Todo servidor MCP que devuelva datos de origen externo DEBE pasarlos
    por aquí.
    """
    texto = (texto or "")[:max_len]
    for p in _PATRONES_INYECCION:
        texto = re.sub(p, "[contenido_saneado]", texto)
    return texto


# ---------------------------------------------------------------------------
# 3. Validación estricta del dominio objetivo
# ---------------------------------------------------------------------------

# Labels alfanuméricas (con guiones interiores), TLD alfabético, longitud
# total ≤ 253. Rechaza: IPs literales (TLD numérico), userinfo (@), puerto
# (:), rutas (/), queries (?), fragments (#), espacios y codificaciones (%).
_RE_DOMINIO = re.compile(
    r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$",
    re.IGNORECASE,
)

_CARACTERES_PROHIBIDOS = "@/?:#% \t\r\n\\"


def dominio_valido(dominio: str) -> bool:
    """Valida el formato estricto de un dominio objetivo de sondeo.

    El dominio se interpola en la posición de autoridad de una URL
    (robots_txt) o en la query de un proveedor público (crt.sh). Sin esta
    guardia, un agente manipulado (LLM01) puede provocar peticiones a hosts
    arbitrarios desde el servidor MCP (SSRF interno) o manipular la query.
    """
    if not dominio or len(dominio) > 253:
        return False
    if any(c in dominio for c in _CARACTERES_PROHIBIDOS):
        return False
    return _RE_DOMINIO.match(dominio) is not None
