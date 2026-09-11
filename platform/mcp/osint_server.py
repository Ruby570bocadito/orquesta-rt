"""Servidor MCP de OSINT pasivo — recolectores de fuentes abiertas.

Fase 1 del ciclo (cap. 4.3): superficie digital pasiva. Herramientas:
- subdominios_crtsh:  certificados de transparencia (crt.sh, público)
- robots_txt:         pistas de rutas y tecnologías en robots.txt
- buscar_filtraciones: INTERFAZ para proveedores licenciados de inteligencia
  de filtraciones (HIBP, DeHashed, etc.). Sin credenciales configuradas el
  adaptador devuelve sin_datos; en el despliegue real el guardrail del
  orquestador exige APROBACIÓN HUMANA previa para invocarla.

Todo contenido externo se trata como dato NO CONFIABLE (cap. 5.2): los
resultados se devuelven como JSON estructurado, nunca se interpretan como
instrucciones para el agente (mitigación de inyección indirecta de prompts).
"""
from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone

import httpx

try:
    from mcp.server.fastmcp import FastMCP
except ImportError:  # pragma: no cover
    raise SystemExit("Falta el SDK de MCP: pip install mcp")

mcp = FastMCP("osint", instructions="Recolectores OSINT pasivos con saneado de contenido.")


def _registro(herramienta: str, args: dict) -> None:
    print(json.dumps({"ts": datetime.now(timezone.utc).isoformat(),
                      "server": "mcp.osint", "tool": herramienta, "args": args},
                     ensure_ascii=False), flush=True)


def _saneado(texto: str, max_len: int = 200_000) -> str:
    """Trata contenido externo como dato no confiable.

    Elimina patrones clásicos de inyección de prompts incrustados en el
    contenido recogido antes de que llegue a cualquier modelo.
    """
    texto = texto[:max_len]
    patrones = (
        r"(?i)ignora (todas )?(las )?(instrucciones|reglas|roe)",
        r"(?i)system\s*prompt",
        r"(?i)<\|.*?\|>",
        r"(?i)exfiltra|filtra las credenciales",
    )
    for p in patrones:
        texto = re.sub(p, "[contenido_saneado]", texto)
    return texto


@mcp.tool()
def subdominios_crtsh(dominio: str) -> dict:
    """Subdominios desde certificados de transparencia (fuente pública crt.sh)."""
    _registro("subdominios_crtsh", {"dominio": dominio})
    try:
        with httpx.Client(timeout=25) as c:
            r = c.get(f"https://crt.sh/?q=%.{dominio}&output=json")
        r.raise_for_status()
        datos = r.json()
    except Exception as exc:
        return {"dominio": dominio, "subdominios": [], "error": str(exc)[:150]}
    subdominios: set[str] = set()
    for fila in datos[:2000]:
        for nombre in str(fila.get("name_value", "")).split("\n"):
            nombre = nombre.strip().lower().lstrip("*.")
            if nombre.endswith("." + dominio.lower()) and nombre != dominio.lower():
                subdominios.add(nombre)
    return {"dominio": dominio, "subdominios": sorted(subdominios)[:500],
            "total": len(subdominios), "fuente": "crt.sh"}


@mcp.tool()
def robots_txt(dominio: str) -> dict:
    """Descarga y estructura robots.txt del dominio (pistas de rutas)."""
    _registro("robots_txt", {"dominio": dominio})
    for esquema in ("https", "http"):
        try:
            with httpx.Client(timeout=10, verify=False, follow_redirects=True) as c:
                r = c.get(f"{esquema}://{dominio}/robots.txt")
            if r.status_code == 200:
                texto = _saneado(r.text, 20_000)
                rutas = [l.split(":", 1)[1].strip() for l in texto.splitlines()
                         if l.lower().startswith(("disallow:", "allow:"))]
                pistas = [r2 for r2 in rutas if any(
                    k in r2.lower() for k in ("admin", "panel", "api", "backup",
                                              "staging", "test", "priv"))]
                return {"dominio": dominio, "rutas": rutas[:100],
                        "pistas": pistas[:30], "saneado": True}
        except Exception:
            continue
    return {"dominio": dominio, "rutas": [], "pistas": [], "nota": "no accesible"}


@mcp.tool()
def buscar_filtraciones(dominio: str) -> dict:
    """INTERFAZ de búsqueda de filtraciones (proveedor licenciado).

    Sin credenciales de proveedor configuradas devuelve sin_datos. El
    guardrail del orquestador exige aprobación humana ANTES de invocar
    esta herramienta (riesgo medio, datos de terceros).
    """
    _registro("buscar_filtraciones", {"dominio": dominio})
    import os
    proveedor = os.environ.get("PROVEEDOR_FILTRACIONES_BASE", "")
    if not proveedor:
        return {"dominio": dominio, "sin_datos": True,
                "nota": "sin proveedor licenciado configurado (HIBP/otro); "
                        "configure PROVEEDOR_FILTRACIONES_* en producción"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--transport", default="stdio")
    args = parser.parse_args()
    mcp.run(transport=args.transport)
