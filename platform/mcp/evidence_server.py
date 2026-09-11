"""Servidor MCP de evidencias — cadena de custodia como herramienta.

Toda evidencia del engagement se registra aquí: hash SHA-256, firma HMAC
con la clave del caso y encadenamiento al hash previo (blockchain-lite).
El cliente puede verificar la cadena sin confiar a ciegas en el proveedor
(cap. 5.3 del blueprint: evidencias verificables).

Herramientas:
- guardar:   registra evidencia y devuelve hash+firma
- listar:    índice de evidencias del caso
- verificar: valida la cadena completa del caso
- exportar:  bundle JSON auditable (sin contenidos sensibles si se pide)

Uso:  python -m mcp.evidence_server --caso casos/caso_demo_acme.db
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

try:
    from mcp.server.fastmcp import FastMCP
except ImportError:  # pragma: no cover
    raise SystemExit("Falta el SDK de MCP: pip install mcp")

# La memoria del caso se abre contra la BD del engagement indicado al arrancar.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from orchestrator.memory import MemoriaCaso  # noqa: E402
from orchestrator.models import Evidencia, Fase, TipoEvidencia  # noqa: E402

_memoria: MemoriaCaso | None = None
mcp = FastMCP("evidencias", instructions="Registro de evidencias con cadena de custodia.")


def _m() -> MemoriaCaso:
    if _memoria is None:
        raise RuntimeError("Servidor sin caso: arranque con --caso <ruta.db>")
    return _memoria


@mcp.tool()
def guardar(titulo: str, contenido: str, tipo: str = "json",
            fase: str = "F1_osint", hallazgo_id: str | None = None) -> dict:
    """Registra una evidencia firmada en la cadena de custodia del caso."""
    ev = _m().guardar_evidencia(Evidencia(
        id=_m().nuevo_id("ev"), engagement_id=_engagement_id(),
        tipo=TipoEvidencia(tipo), titulo=titulo, contenido=contenido,
        fase=Fase(fase), hallazgo_id=hallazgo_id))
    return {"id": ev.id, "hash_sha256": ev.hash_sha256,
            "firma_hmac": ev.firma_hmac, "hash_previo": ev.hash_previo}


@mcp.tool()
def listar(limite: int = 100) -> list[dict]:
    """Lista el índice de evidencias del caso."""
    filas = _m().listar_evidencias(_engagement_id())
    return [{"id": f["id"], "tipo": f["tipo"], "titulo": f["titulo"],
             "hash": f["hash_sha256"][:16], "fase": f["fase"], "actor": f["actor"]}
            for f in filas[:limite]]


@mcp.tool()
def verificar() -> dict:
    """Verifica la integridad completa de la cadena de custodia."""
    return _m().verificar_cadena(_engagement_id())


@mcp.tool()
def exportar(con_contenido: bool = False) -> dict:
    """Exporta el bundle auditable del caso (para el informe o el cliente)."""
    filas = _m().listar_evidencias(_engagement_id())
    cadena = _m().verificar_cadena(_engagement_id())
    return {
        "cadena": cadena,
        "evidencias": [dict(f) | ({"contenido": f["contenido"]} if con_contenido else {})
                       for f in filas],
    }


def _engagement_id() -> str:
    return Path(_m().db_path).stem


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--caso", required=True, help="Ruta a la BD del caso")
    parser.add_argument("--transport", default="stdio")
    args = parser.parse_args()
    _memoria = MemoriaCaso(args.caso)
    mcp.run(transport=args.transport)
