"""Servidor MCP de reconocimiento — capa de herramientas del lab.

Model Context Protocol: cada dominio ofensivo se encapsula en un servidor
MCP con su propia superficie de permisos (cap. 2.3 del blueprint). Este
servidor expone herramientas de reconocimiento ACTIVO acotado al lab:

- dns_enum:      resolución A/AAAA/MX/TXT (dnspython)
- http_probe:    sondeo de cabeceras HTTP (httpx, sin exploits)
- cert_info:     metadatos de certificado TLS
- tech_fingerprint: huella de tecnologías por cabeceras
- port_scan:     barrido de puertos por socket-connect, SOLO puertos comunes,
                 SOLO contra objetivos dentro del alcance validado por el
                 guardrail del orquestador

POLÍTICA DE SEGURIDAD (cap. 5): todo servidor MCP es superficie de ataque.
Este servidor es PROPIO, de menor privilegio y registra cada llamada. En
despliegue de producción se arranca tras el boundary del orquestador: el
servidor CONFIÓ en que la petición ya pasó guardrails, pero además aplica
una segunda verificación defensiva de scope local (defensa en profundidad).

Uso:  python -m servidores_mcp.recon_server          (stdio)
      python -m servidores_mcp.recon_server --transport sse --port 8001
"""
from __future__ import annotations

import argparse
import json
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

import httpx

try:
    from mcp.server.fastmcp import FastMCP
except ImportError:  # pragma: no cover
    raise SystemExit(
        "Falta el SDK de MCP. Instale requirements.txt: pip install mcp")

# z3 (auditoría seguridad): política TLS centralizada del recon. La sesión 2
# la introdujo vía orchestrator.transportes; la sesión 4 la unifica en
# mcp.comun (sin fallback fail-open a verify=False y sin duplicación).
import sys as _sys  # noqa: E402
from pathlib import Path as _Path  # noqa: E402
_sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from servidores_mcp.comun import cliente_recon as _cliente_recon  # noqa: E402
from servidores_mcp.comun import saneado as _saneado  # noqa: E402

mcp = FastMCP(
    "recon",
    instructions="Herramientas de reconocimiento del lab. Requiere que toda "
                 "llamada haya pasado el boundary de guardrails del orquestador.",
)

# Lista blanca de puertos comunes: el servidor NUNCA barre rangos arbitrarios.
PUERTOS_PERMITIDOS = {80, 443, 8080, 8443, 22, 445, 3389, 8000, 5432, 3306, 53}

# Scope local defensivo (defensa en profundidad). En producción se inyecta
# desde el ROE del engagement al arrancar el servidor.
_SCOPE_DNS: set[str] = set()
_SCOPE_CIDR: set[str] = set()


def configurar_scope(dominios: list[str], cidrs: list[str]) -> None:
    global _SCOPE_DNS, _SCOPE_CIDR
    _SCOPE_DNS = {d.lower() for d in dominios}
    _SCOPE_CIDR = set(cidrs)


def _host_de(objetivo: str) -> str:
    if objetivo.startswith(("http://", "https://")):
        return urlparse(objetivo).hostname or ""
    return objetivo.split("/")[0].split(":")[0]


def _en_scope_local(host: str) -> bool:
    """Segunda verificación local (el guardrail ya validó antes)."""
    host = (host or "").lower()
    if not host:
        return False
    try:
        import ipaddress
        ip = ipaddress.ip_address(host)
        return any(ip in ipaddress.ip_network(c, strict=False) for c in _SCOPE_CIDR)
    except ValueError:
        return any(host == d or host.endswith("." + d) for d in _SCOPE_DNS)


def _registro(herramienta: str, args: dict) -> None:
    print(json.dumps({
        "ts": datetime.now(timezone.utc).isoformat(), "server": "mcp.recon",
        "tool": herramienta, "args": args}, ensure_ascii=False), flush=True)


@mcp.tool()
def dns_enum(dominio: str) -> dict:
    """Resuelve registros A/AAAA/MX/TXT de un dominio del alcance."""
    _registro("dns_enum", {"dominio": dominio})
    host = _host_de(dominio)
    if not _en_scope_local(host):
        return {"error": "fuera de alcance local del servidor", "host": host}
    import dns.resolver
    salida: dict = {"dominio": host}
    for tipo in ("A", "AAAA", "MX", "TXT", "NS"):
        try:
            respuestas = dns.resolver.resolve(host, tipo, lifetime=5)
            salida[tipo.lower()] = [str(r) for r in respuestas][:20]
        except Exception:
            salida[tipo.lower()] = []
    return salida


@mcp.tool()
def http_probe(url: str) -> dict:
    """Sondeo pasivo de cabeceras HTTP(S). No envía payloads de ataque."""
    _registro("http_probe", {"url": url})
    host = _host_de(url)
    if not _en_scope_local(host):
        return {"error": "fuera de alcance local del servidor", "host": host}
    try:
        with _cliente_recon(timeout=8, follow_redirects=False) as c:
            r = c.get(url if url.startswith("http") else f"https://{url}")
        cabeceras = {k.lower(): _saneado(v, 200) for k, v in r.headers.items()
                     if k.lower() in ("server", "x-powered-by", "content-type",
                                      "content-security-policy", "strict-transport-security",
                                      "location", "x-frame-options")}
        # z3 (sesión 4): el título y las cabeceras son CONTENIDO CONTROLADO
        # POR EL SERVIDOR EXTERNO. Igual que el servidor osint, se sanea
        # antes de devolverlo al agente (mitigación LLM01 en profundidad:
        # el escudo del copiloto v25 no cubre otros consumidores).
        return {"vivo": True, "estado": r.status_code, "cabeceras": cabeceras,
                "longitud": len(r.content), "titulo": _saneado(_titulo(r.text), 200)}
    except Exception as exc:
        return {"vivo": False, "error": str(exc)[:200]}


def _titulo(html: str) -> str:
    entre = html.split("<title>", 1)
    if len(entre) > 1:
        return entre[1].split("</title>", 1)[0][:200]
    return ""


@mcp.tool()
def cert_info(host: str, puerto: int = 443) -> dict:
    """Metadatos del certificado TLS (emisor, vigencia, SANs)."""
    _registro("cert_info", {"host": host, "puerto": puerto})
    host = _host_de(host)
    if not _en_scope_local(host):
        return {"error": "fuera de alcance local del servidor"}
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, puerto), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                der = ssock.getpeercert(binary_form=True)
        import hashlib
        return {"host": host, "cert_sha256": hashlib.sha256(der).hexdigest(),
                "nota": "uso de binary_form: detalle completo requiere ssl de contexto verificado"}
    except Exception as exc:
        return {"error": str(exc)[:200]}


@mcp.tool()
def tech_fingerprint(url: str) -> dict:
    """Huella tecnológica básica a partir de cabeceras y cuerpo (pasivo)."""
    _registro("tech_fingerprint", {"url": url})
    host = _host_de(url)
    if not _en_scope_local(host):
        return {"error": "fuera de alcance local del servidor"}
    try:
        with _cliente_recon(timeout=8) as c:
            r = c.get(url if url.startswith("http") else f"https://{url}")
    except Exception as exc:
        return {"error": str(exc)[:200]}
    pistas: dict = {}
    # z3 (sesión 4): cabeceras y meta-generator vienen del servidor externo:
    # se sanea todo valor devuelto (ver mcp.comun.saneado).
    server = r.headers.get("server", "")
    if server:
        pistas["server"] = _saneado(server, 200)
    powered = r.headers.get("x-powered-by", "")
    if powered:
        pistas["framework"] = _saneado(powered, 200)
    cuerpo = r.text[:4000].lower()
    for firma, nombre in (("wp-content", "WordPress"), ("/static/js/vendor.",
                                                       "bundle estático"),
                          ("generator\" content=\"", "meta-generator")):
        if firma in cuerpo:
            pistas.setdefault("cuerpo", []).append(nombre)
    gen = r.text.lower().split('name="generator" content="')
    if len(gen) > 1:
        pistas["generator"] = _saneado(gen[1].split('"')[0][:80], 80)
    return {"url": url, "pistas": pistas}


@mcp.tool()
def port_scan(host: str, puertos: str = "80,443,8080,8443") -> dict:
    """Barrido por socket-connect de la LISTA BLANCA de puertos comunes.

    Limitaciones de diseño (menor privilegio):
    - Solo puertos de PUERTOS_PERMITIDOS; el resto se ignora y se reporta.
    - Sin fragmentación, sin evasión: el lab mide ruido real.
    - Ventana horaria: la aplica el guardrail del orquestador.
    """
    _registro("port_scan", {"host": host, "puertos": puertos})
    host = _host_de(host)
    if not _en_scope_local(host):
        return {"error": "fuera de alcance local del servidor"}
    solicitados = {int(p) for p in puertos.replace(" ", "").split(",") if p.isdigit()}
    invalidos = sorted(solicitados - PUERTOS_PERMITIDOS)
    objetivos = sorted(solicitados & PUERTOS_PERMITIDOS)
    abiertos: list[int] = []
    for puerto in objetivos:
        try:
            with socket.create_connection((host, puerto), timeout=1.5):
                abiertos.append(puerto)
        except OSError:
            continue
    return {"host": host, "puertos_abiertos": abiertos,
            "rechazados_fuera_de_lista_blanca": invalidos,
            "metodo": "socket-connect secuencial (ruido real, sin evasión)"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--transport", default="stdio",
                        choices=["stdio", "sse", "streamable-http"])
    parser.add_argument("--port", type=int, default=8001)
    parser.add_argument("--dominios", default="", help="coma-separados de scope local")
    parser.add_argument("--cidrs", default="", help="coma-separados de scope local")
    args = parser.parse_args()
    if args.dominios or args.cidrs:
        configurar_scope(
            [d for d in args.dominios.split(",") if d],
            [c for c in args.cidrs.split(",") if c])
    else:
        # Por defecto, el lab simulado. Sin scope, las tools deniegan todo.
        configurar_scope(["acme-demo.local", "lab.acme-demo.local"], ["10.30.0.0/24"])
    mcp.run(transport=args.transport)
