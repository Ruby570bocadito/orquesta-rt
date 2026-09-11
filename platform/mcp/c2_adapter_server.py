"""Servidor MCP de C2 y explotación — integraciones REALES.

Este servidor expone las capacidades C2 del orquestador vía Model Context
Protocol. NO contiene simulación alguna: cada herramienta es un cliente de
la API OFICIAL del framework correspondiente, configurado por el operador
contra sus propias instancias en entornos autorizados (ROE firmado):

  sliver        → API gRPC oficial (sliver-py)
  mythic        → API GraphQL oficial
  metasploit    → MSG-RPC oficial (module.execute, session.*)

El guardrail del orquestador exige APROBACIÓN HUMANA para toda tarea y
retirada (cap. 4.7 del blueprint); este servidor es pasivo ante esas
decisiones: las registra y las ejecuta SOLO tras el boundary.

Variables de entorno: SLIVER_CONFIG/SLIVER_HOST/SLIVER_TOKEN,
MYTHIC_URL/MYTHIC_TOKEN, MSF_HOST/MSF_PORT/MSF_USER/MSF_PASS. Sin
configuración, las herramientas devuelven el requisito exacto — jamás
datos ficticios.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

# Permite ejecutar en pie: python -m platform.mcp.c2_adapter_server
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from integraciones import metasploit, mythic, sliver  # noqa: E402

try:
    from mcp.server.fastmcp import FastMCP
except ImportError:  # pragma: no cover
    raise SystemExit("Falta el SDK de MCP: pip install mcp")

mcp = FastMCP("c2_adapter", instructions=(
    "Integraciones C2 y explotación REALES (Sliver gRPC, Mythic GraphQL, "
    "Metasploit MSG-RPC). Toda llamada llegó previamente al guardrail del "
    "orquestador. Sin instancias configuradas devuelve requisitos, no datos."))


def _registro(herramienta: str, args: dict) -> None:
    print(json.dumps({"ts": datetime.now(timezone.utc).isoformat(),
                      "server": "mcp.c2_adapter", "tool": herramienta, "args": args},
                     ensure_ascii=False), flush=True)


@mcp.tool()
def estado_c2() -> dict:
    """Estado REAL de los frameworks C2 configurados: sesiones Sliver,
    callbacks Mythic y sesiones Metasploit. Los no configurados se
    documentan (jamás se inventan agentes)."""
    _registro("estado_c2", {})
    return {"sliver": sliver.estado(), "mythic": mythic.estado(),
            "metasploit": metasploit.estado()}


@mcp.tool()
def tarea_sliver(sesion_id: int, comando: str) -> dict:
    """Ejecuta un comando shell REAL en una sesión Sliver (requiere
    aprobación humana previa del boundary)."""
    _registro("tarea_sliver", {"sesion_id": sesion_id, "comando": comando})
    return sliver.tarea(sesion_id, comando)


@mcp.tool()
def tarea_mythic(callback_id: int, comando: str, params: str = "") -> dict:
    """Crea una tarea REAL en un callback Mythic (requiere aprobación)."""
    _registro("tarea_mythic", {"callback_id": callback_id, "comando": comando})
    return mythic.tarea(callback_id, comando, params)


@mcp.tool()
def tarea_msf(sesion_id: int, comando: str) -> dict:
    """Escribe un comando REAL en una sesión shell/meterpreter de
    Metasploit y devuelve la salida disponible (requiere aprobación)."""
    _registro("tarea_msf", {"sesion_id": sesion_id, "comando": comando})
    return metasploit.tarea_sesion(sesion_id, comando)


@mcp.tool()
def retirar_sliver(sesion_id: int) -> dict:
    """Cierra una sesión/beacon Sliver REAL (higiene de cierre)."""
    _registro("retirar_sliver", {"sesion_id": sesion_id})
    return sliver.retirar(sesion_id)


@mcp.tool()
def retirar_mythic(callback_id: int) -> dict:
    """Bloquea un callback Mythic REAL (higiene de cierre)."""
    _registro("retirar_mythic", {"callback_id": callback_id})
    return mythic.retirar(callback_id)


@mcp.tool()
def retirar_msf(sesion_id: int) -> dict:
    """Detiene una sesión Metasploit REAL (higiene de cierre)."""
    _registro("retirar_msf", {"sesion_id": sesion_id})
    return metasploit.retirar_sesion(sesion_id)


@mcp.tool()
def ejecutar_modulo_msf(modulo: str, opciones: dict | None = None) -> dict:
    """module.execute REAL en Metasploit (exploit/auxiliar). El boundary
    exige aprobación humana SIEMPRE; RHOSTS debe estar en el alcance ROE."""
    _registro("ejecutar_modulo_msf", {"modulo": modulo, "opciones": opciones})
    return metasploit.ejecutar_modulo(
        "exploit" if modulo.startswith("exploit/") else
        "auxiliary" if modulo.startswith("auxiliary/") else "post",
        modulo, opciones or {})


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--transport", default="stdio")
    args = parser.parse_args()
    mcp.run(transport=args.transport)
