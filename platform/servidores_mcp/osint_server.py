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

z3 (sesión 4): además, el dominio objetivo se valida con formato estricto
(mcp.comun.dominio_valido) ANTES de interpolarse en una URL, y las
redirecciones de robots_txt se siguen manualmente SOLO dentro del dominio
solicitado (anti-SSRF).
"""
from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

import httpx

try:
    from mcp.server.fastmcp import FastMCP
except ImportError:  # pragma: no cover
    raise SystemExit("Falta el SDK de MCP: pip install mcp")

# z3 (auditoría seguridad): política TLS, saneado de contenido y validación
# de dominios unificados en mcp.comun (sesión 4); antes cada herramienta
# decidiría su propio verify=False silencioso.
# RECON_TLS_ESTRICTO=1 hace que los sondeos verifiquen el certificado.
import sys as _sys  # noqa: E402
from pathlib import Path as _Path  # noqa: E402
_sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from servidores_mcp.comun import cliente_recon as _cliente_recon  # noqa: E402
from servidores_mcp.comun import dominio_valido as _dominio_valido  # noqa: E402
from servidores_mcp.comun import saneado as _saneado  # noqa: E402

mcp = FastMCP("osint", instructions="Recolectores OSINT pasivos con saneado de contenido.")


def _registro(herramienta: str, args: dict) -> None:
    print(json.dumps({"ts": datetime.now(timezone.utc).isoformat(),
                      "server": "mcp.osint", "tool": herramienta, "args": args},
                     ensure_ascii=False), flush=True)


# z3 (sesión 4): el saneado de contenido externo vive en mcp.comun.saneado
# y lo comparten TODOS los servidores MCP (antes solo osint lo aplicaba y
# cada uno mantenía su propia copia; recon devolvía títulos y cabeceras sin
# sanear). La función se importa arriba como _saneado.


@mcp.tool()
def subdominios_crtsh(dominio: str) -> dict:
    """Subdominios desde certificados de transparencia (fuente pública crt.sh)."""
    _registro("subdominios_crtsh", {"dominio": dominio})
    # z3 (sesión 4): el dominio se interpola en la query de un proveedor
    # público. Sin validación estricta, un agente manipulado puede inyectar
    # parámetros (&q=...) o fragmentos; con ella, la petición solo sale si el
    # objetivo tiene formato de dominio.
    if not _dominio_valido(dominio):
        return {"dominio": dominio, "subdominios": [],
                "error": "dominio inválido (formato esperado: ejemplo.com)"}
    try:
        # z3 (sesión 4): parámetros codificados por httpx (antes f-string:
        # un dominio con &/# manipulaba la query del proveedor).
        with httpx.Client(timeout=25) as c:
            r = c.get("https://crt.sh/",
                      params={"q": f"%.{dominio}", "output": "json"})
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
    # z3 (sesión 4): el dominio se interpola en la POSICIÓN DE AUTORIDAD de
    # la URL ({esquema}://{dominio}/robots.txt). Sin validación, valores como
    # "crt.sh@evil.com" o "evil.com:8080" redirigían la petición a hosts
    # arbitrarios desde el servidor MCP (SSRF interno).
    if not _dominio_valido(dominio):
        return {"dominio": dominio, "rutas": [], "pistas": [],
                "nota": "dominio inválido (formato esperado: ejemplo.com)"}
    for esquema in ("https", "http"):
        respuesta = _descargar_robots(dominio, esquema)
        if respuesta is None:
            continue
        texto = _saneado(respuesta.text, 20_000)
        rutas = [l.split(":", 1)[1].strip() for l in texto.splitlines()
                 if l.lower().startswith(("disallow:", "allow:"))]
        pistas = [r2 for r2 in rutas if any(
            k in r2.lower() for k in ("admin", "panel", "api", "backup",
                                      "staging", "test", "priv"))]
        return {"dominio": dominio, "rutas": rutas[:100],
                "pistas": pistas[:30], "saneado": True}
    return {"dominio": dominio, "rutas": [], "pistas": [], "nota": "no accesible"}


def _descargar_robots(dominio: str, esquema: str, max_saltos: int = 3):
    """GET de /robots.txt con redirecciones seguidas MANUALMENTE.

    z3 (sesión 4): follow_redirects=True permitía que un 301 del dominio
    solicitado llevase al servidor MCP a un host arbitrario (SSRF ciego por
    redirección). Aquí cada salto se valida: el destino solo puede ser el
    dominio solicitado o un subdominio suyo (p. ej. www.<dominio>).
    Devuelve la Response final si status==200; None en otro caso.
    """
    url = f"{esquema}://{dominio}/robots.txt"
    with _cliente_recon(timeout=10, follow_redirects=False) as c:
        for _ in range(max_saltos + 1):
            r = c.get(url)
            if r.status_code in (301, 302, 303, 307, 308):
                destino = r.headers.get("location", "")
                if not destino:
                    return None
                url = urljoin(url, destino)
                host = urlparse(url).hostname or ""
                if not (host == dominio.lower()
                        or host.endswith("." + dominio.lower())):
                    return None  # redirección fuera del dominio: bloqueada
                continue
            return r if r.status_code == 200 else None
    return None


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
