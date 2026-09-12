"""Transportes de herramientas REALES del orquestador.

Los agentes de fase no llaman a la red directamente: invocan herramientas
a través del boundary de guardrails, y el boundary ejecuta la función de
este módulo asociada al nombre "servidor.tool".

Son las MISMAS operaciones que exponen los servidores MCP de platform/servidores_mcp/
(recon, osint), aquí enlazadas en proceso para que la API del orquestador
las ejecute sin depender del SDK de MCP en runtime. Cada herramienta:

  1. Verifica el alcance contra el ROE del engagement (defensa en
     profundidad: el guardrail ya lo validó, esto es la segunda barrera).
  2. Devuelve SIEMPRE un dict; los errores operativos se reportan en
     {"error": ...} y nunca propagan excepciones a la fase.
  3. Ejecuta I/O real: sockets, HTTP, DNS, TLS. Sin simulación.
"""
from __future__ import annotations

import ipaddress
import json
import socket
import ssl
from typing import Any, Callable
from urllib.parse import urlparse

from .models import ROEPolitica

# Lista blanca de puertos: el orquestador NUNCA barre rangos arbitrarios.
PUERTOS_PERMITIDOS = {80, 443, 8080, 8443, 22, 445, 3389, 8000, 5432, 3306, 53}

PUERTOS_HTTPS = {443, 8443}


def verificar_tls() -> bool:
    """z3 (auditoría seguridad): verificación TLS de los sondeos de recon.

    Por defecto los clientes HTTP del recon/OSINT no verifican el
    certificado del objetivo (los labs del alcance usan autofirmados y una
    anomalía de certificado es en sí un hallazgo del engagement). Un
    despliegue serio contra infraestructura real puede activar la
    verificación completa:

        RECON_TLS_ESTRICTO=1   →  verify=True en todos los sondeos

    NOTA: esto NO afecta a las integraciones de infraestructura propia
    (metasploit/bloodhound/mythic/misp), que verifican POR DEFECTO con
    escape explícito (ver integraciones/*.py).
    """
    import os
    return os.environ.get("RECON_TLS_ESTRICTO", "") == "1"


def _cliente_http(**kwargs):
    """httpx.Client con la política TLS de recon ya aplicada.

    El valor de `verify` se fuerza desde aquí salvo que el caller lo pase
    explícito (no debería): evita que un verify=False quede hardcoded y
    silencioso en una herramienta nueva.
    """
    import httpx
    kwargs.setdefault("verify", verificar_tls())
    return httpx.Client(**kwargs)

# Banner grab: primera lectura del servicio; puertos que hablan primero.
_BANNER_TAM = 512


def _host_de(objetivo: str) -> str:
    if objetivo.startswith(("http://", "https://")):
        return urlparse(objetivo).hostname or ""
    return objetivo.split("/")[0].split(":")[0]


def _puerto_de(objetivo: str) -> int:
    if objetivo.startswith(("http://", "https://")):
        return urlparse(objetivo).port or (443 if objetivo.startswith("https") else 80)
    partes = objetivo.split(":")
    return int(partes[1]) if len(partes) > 1 and partes[1].isdigit() else 80


def _en_scope(host: str, roe: ROEPolitica) -> bool:
    """Segunda verificación local de alcance (la primera la hace el boundary)."""
    host = (host or "").strip().lower().replace("*.", "")
    if not host:
        return False
    for excl in roe.alcance_excluido:
        import fnmatch
        if fnmatch.fnmatch(host, excl.lower()):
            return False
    try:
        ip = ipaddress.ip_address(host)
        return any(ip in ipaddress.ip_network(c, strict=False) for c in roe.alcance_cidrs)
    except ValueError:
        pass
    for dom in roe.alcance_dominios:
        dom = dom.lower().lstrip(".")
        if host == dom or host.endswith("." + dom):
            return True
    return False


def _url_de(host: str, puerto: int) -> str:
    esquema = "https" if puerto in PUERTOS_HTTPS else "http"
    if puerto in (80, 443):
        return f"{esquema}://{host}"
    return f"{esquema}://{host}:{puerto}"


# ---------------------------------------------------------------------------
# OSINT pasivo
# ---------------------------------------------------------------------------


def osint_subdominios_crtsh(dominio: str, roe: ROEPolitica) -> dict[str, Any]:
    """Subdominios desde Certificate Transparency (crt.sh). Consulta real."""
    host = _host_de(dominio)
    if not _en_scope(host, roe):
        return {"error": "fuera de alcance local del transporte", "host": host}
    try:
        import httpx
        with httpx.Client(timeout=15, follow_redirects=True) as c:
            r = c.get("https://crt.sh/", params={"q": f"%.{host}", "output": "json"})
        if r.status_code != 200:
            return {"dominio": host, "subdominios": [],
                    "nota": f"crt.sh respondió {r.status_code}"}
        entradas = r.json() if isinstance(r.json(), list) else []
        subs: set[str] = set()
        for e in entradas[:2000]:
            for nombre in str(e.get("name_value", "")).split("\n"):
                nombre = nombre.strip().lower().lstrip("*.")
                if nombre.endswith("." + host) and nombre != host:
                    subs.add(nombre)
        return {"dominio": host, "subdominios": sorted(subs)[:400],
                "fuente": "crt.sh (Certificate Transparency)"}
    except Exception as exc:
        return {"dominio": host, "subdominios": [],
                "error": f"crt.sh no disponible: {str(exc)[:160]}"}


def osint_robots_txt(dominio: str, roe: ROEPolitica,
                     puertos: str = "80,443,8080,8443") -> dict[str, Any]:
    """Descarga real de /robots.txt probando los puertos web habituales."""
    host = _host_de(dominio)
    if not _en_scope(host, roe):
        return {"error": "fuera de alcance local del transporte", "host": host}
    solicitados = [int(p) for p in puertos.replace(" ", "").split(",") if p.isdigit()]
    try:
        import httpx
        with _cliente_http(timeout=6, follow_redirects=True) as c:
            for puerto in sorted(set(solicitados) & PUERTOS_PERMITIDOS):
                url = f"{_url_de(host, puerto)}/robots.txt"
                try:
                    r = c.get(url)
                except Exception:
                    continue
                if r.status_code == 200 and "<html" not in r.text[:200].lower():
                    rutas = []
                    pistas: list[str] = []
                    for linea in r.text.splitlines()[:200]:
                        linea = linea.strip()
                        if linea.lower().startswith("disallow:"):
                            ruta = linea.split(":", 1)[1].strip()
                            if ruta and ruta != "/":
                                rutas.append(ruta)
                                if any(p in ruta.lower() for p in
                                       ("admin", "panel", "gestion", "priv", "internal")):
                                    pistas.append(f"ruta sensible expuesta en robots.txt: {ruta}")
                        elif linea.lower().startswith(("user-agent", "sitemap")):
                            pistas.append(linea[:120])
                    return {"dominio": host, "url": url, "rutas": rutas[:60],
                            "pistas": pistas[:20], "crudo": r.text[:4000]}
        return {"dominio": host, "rutas": [], "pistas": [],
                "nota": "sin robots.txt accesible en los puertos web probados"}
    except Exception as exc:
        return {"dominio": host, "rutas": [], "error": str(exc)[:200]}


def osint_buscar_filtraciones(dominio: str, roe: ROEPolitica) -> dict[str, Any]:
    """Filtraciones de credenciales reales vía Have I Been Pwned (v3).

    Requiere HIBP_API_KEY (gratuita para uso legítimo) en el entorno.
    SIN clave NO se inventan resultados: se devuelve el requisito de
    configuración y la fase lo documenta como evidencia.
    """
    import os
    host = _host_de(dominio)
    clave = os.environ.get("HIBP_API_KEY", "")
    if not clave:
        return {"dominio": host, "consultado": False,
                "error": "HIBP_API_KEY no configurada: la consulta de filtraciones "
                         "requiere clave gratuita de haveibeenpwned.com"}
    try:
        import httpx
        with httpx.Client(timeout=15) as c:
            r = c.get("https://haveibeenpwned.com/api/v3/breaches",
                      params={"domain": host},
                      headers={"hibp-api-key": clave, "user-agent": "OrquestaRT"})
        if r.status_code != 200:
            return {"dominio": host, "consultado": True,
                    "error": f"HIBP respondió {r.status_code}"}
        datos = r.json() if isinstance(r.json(), list) else []
        filtraciones = [{
            "nombre": b.get("Name"), "fecha": b.get("BreachDate"),
            "registros": b.get("PwnCount"), "datos": b.get("DataClasses", [])[:8],
        } for b in datos[:40]]
        return {"dominio": host, "consultado": True,
                "total_filtraciones": len(filtraciones),
                "filtraciones": filtraciones,
                "fuente": "Have I Been Pwned v3"}
    except Exception as exc:
        return {"dominio": host, "consultado": False, "error": str(exc)[:200]}


# ---------------------------------------------------------------------------
# Reconocimiento activo acotado
# ---------------------------------------------------------------------------


def recon_dns_enum(dominio: str, roe: ROEPolitica) -> dict[str, Any]:
    """Resolución DNS real A/AAAA/MX/TXT/NS con dnspython."""
    host = _host_de(dominio)
    if not _en_scope(host, roe):
        return {"error": "fuera de alcance local del transporte", "host": host}
    salida: dict[str, Any] = {"dominio": host}
    try:
        import dns.resolver
        for tipo in ("A", "AAAA", "MX", "TXT", "NS"):
            try:
                respuestas = dns.resolver.resolve(host, tipo, lifetime=5)
                salida[tipo.lower()] = [str(r) for r in respuestas][:20]
            except Exception:
                salida[tipo.lower()] = []
    except Exception as exc:
        return {"dominio": host, "error": f"resolver no disponible: {str(exc)[:140]}"}
    return salida


def recon_http_probe(url: str, roe: ROEPolitica) -> dict[str, Any]:
    """Sondeo HTTP(S) real: cabeceras de seguridad, servidor, título."""
    host = _host_de(url)
    if not _en_scope(host, roe):
        return {"error": "fuera de alcance local del transporte", "host": host}
    try:
        import httpx
        destino = url if url.startswith("http") else f"https://{url}"
        with _cliente_http(timeout=8, follow_redirects=False) as c:
            r = c.get(destino)
        cabeceras = {k.lower(): v for k, v in r.headers.items()
                     if k.lower() in ("server", "x-powered-by", "content-type",
                                      "content-security-policy",
                                      "strict-transport-security", "location",
                                      "x-frame-options")}
        faltantes = [h for h in ("content-security-policy",
                                 "strict-transport-security", "x-frame-options")
                     if h not in cabeceras]
        return {"vivo": True, "url": destino, "estado": r.status_code,
                "cabeceras": cabeceras, "cabeceras_faltantes": faltantes,
                "longitud": len(r.content), "titulo": _titulo(r.text)}
    except Exception as exc:
        return {"vivo": False, "url": url, "error": str(exc)[:200]}


def _titulo(html: str) -> str:
    entre = html.split("<title>", 1)
    if len(entre) > 1:
        return entre[1].split("</title>", 1)[0][:200]
    return ""


def recon_cert_info(host: str, roe: ROEPolitica, puerto: int = 443) -> dict[str, Any]:
    """Metadatos reales del certificado TLS (emisor, vigencia, SANs)."""
    host = _host_de(host)
    if not _en_scope(host, roe):
        return {"error": "fuera de alcance local del transporte", "host": host}
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, puerto), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                der = ssock.getpeercert(binary_form=True)
                cert = ssock.getpeercert()
        import hashlib
        return {"host": host, "puerto": puerto,
                "cert_sha256": hashlib.sha256(der).hexdigest(),
                "emisor": dict(x[0] for x in cert.get("issuer", ())).get("organizationName", ""),
                "sujeto": dict(x[0] for x in cert.get("subject", ())).get("commonName", ""),
                "no_despues": cert.get("notAfter", "")}
    except Exception as exc:
        return {"host": host, "error": str(exc)[:200]}


def recon_tech_fingerprint(url: str, roe: ROEPolitica) -> dict[str, Any]:
    """Huella tecnológica real a partir de cabeceras y cuerpo (pasivo)."""
    host = _host_de(url)
    if not _en_scope(host, roe):
        return {"error": "fuera de alcance local del transporte", "host": host}
    try:
        import httpx
        destino = url if url.startswith("http") else f"https://{url}"
        with _cliente_http(timeout=8) as c:
            r = c.get(destino)
    except Exception as exc:
        return {"url": url, "error": str(exc)[:200]}
    pistas: dict[str, Any] = {}
    if r.headers.get("server"):
        pistas["server"] = r.headers["server"]
    if r.headers.get("x-powered-by"):
        pistas["framework"] = r.headers["x-powered-by"]
    cuerpo = r.text[:6000].lower()
    firmas = (("wp-content", "WordPress"), ("generator\" content=\"", "meta-generator"),
              ("/static/js/vendor.", "bundle estático"), ("joomla", "Joomla"),
              ("drupal", "Drupal"), ("next.js", "Next.js"))
    for firma, nombre in firmas:
        if firma in cuerpo:
            pistas.setdefault("cuerpo", []).append(nombre)
    gen = r.text.lower().split('name="generator" content="')
    if len(gen) > 1:
        pistas["generator"] = gen[1].split('"')[0][:80]
    return {"url": destino, "pistas": pistas}


def recon_port_scan(host: str, roe: ROEPolitica,
                    puertos: str = "80,443,8080,8443") -> dict[str, Any]:
    """Barrido real por socket-connect, SOLO lista blanca de puertos comunes.

    Sin evasión ni fragmentación: el ruido es real y lo mide el boundary.
    """
    host = _host_de(host)
    if not _en_scope(host, roe):
        return {"error": "fuera de alcance local del transporte", "host": host}
    solicitados = {int(p) for p in puertos.replace(" ", "").split(",") if p.isdigit()}
    invalidos = sorted(solicitados - PUERTOS_PERMITIDOS)
    objetivos = sorted(solicitados & PUERTOS_PERMITIDOS)
    abiertos: list[dict[str, Any]] = []
    for puerto in objetivos:
        try:
            with socket.create_connection((host, puerto), timeout=1.5):
                servicio = {80: "http", 443: "https", 8080: "http-alt",
                            8443: "https-alt", 22: "ssh", 445: "smb",
                            3389: "rdp", 8000: "http-alt", 5432: "postgres",
                            3306: "mysql", 53: "dns"}.get(puerto, "desconocido")
                abiertos.append({"puerto": puerto, "servicio": servicio})
        except OSError:
            continue
    return {"host": host, "puertos_abiertos": [p["puerto"] for p in abiertos],
            "servicios": abiertos, "rechazados_fuera_de_lista_blanca": invalidos,
            "metodo": "socket-connect secuencial (ruido real, sin evasión)"}


# ---------------------------------------------------------------------------
# OSINT pasivo (adicionales)
# ---------------------------------------------------------------------------


def osint_wayback(dominio: str, roe: ROEPolitica) -> dict[str, Any]:
    """URLs históricas del dominio vía la API CDX pública del Internet
    Archive (consulta real, pasiva). Útil para descubrir rutas antiguas,
    paneles y ficheros que el sitio actual ya no enlaza."""
    host = _host_de(dominio)
    if not _en_scope(host, roe):
        return {"error": "fuera de alcance local del transporte", "host": host}
    try:
        import httpx
        with httpx.Client(timeout=20, follow_redirects=True) as c:
            r = c.get("https://web.archive.org/cdx/search/cdx", params={
                "url": f"{host}/*", "output": "json",
                "collapse": "urlkey", "limit": "800",
                "fl": "original,timestamp,statuscode,mimetype"})
        if r.status_code != 200:
            return {"dominio": host, "urls": [],
                    "nota": f"CDX respondió {r.status_code}"}
        filas = r.json() if isinstance(r.json(), list) else []
        if not filas:
            return {"dominio": host, "urls": [],
                    "nota": "sin capturas históricas en el archivo"}
        cab, cuerpo = filas[0], filas[1:]
        urls: list[dict[str, Any]] = []
        for fila in cuerpo[:800]:
            u = {"url": fila[0] if len(fila) > 0 else "",
                 "captura": fila[1] if len(fila) > 1 else "",
                 "estado": fila[2] if len(fila) > 2 else "",
                 "tipo": fila[3] if len(fila) > 3 else ""}
            urls.append(u)
        # Rutas históricas de interés (paneles, backups, ficheros)
        pistas = [u["url"] for u in urls if any(
            p in u["url"].lower() for p in
            ("admin", "panel", "backup", ".sql", ".zip", ".bak", "login",
             "phpmyadmin", "config", ".old", "intranet"))][:60]
        return {"dominio": host, "total": len(urls), "urls": urls[:400],
                "pistas_historicas": pistas,
                "fuente": "Internet Archive CDX (pasivo)"}
    except Exception as exc:
        return {"dominio": host, "urls": [],
                "error": f"CDX no disponible: {str(exc)[:160]}"}


# ---------------------------------------------------------------------------
# Reconocimiento activo acotado (adicionales)
# ---------------------------------------------------------------------------


def recon_banner_grab(host: str, roe: ROEPolitica,
                      puertos: str = "22,445,3389,8000") -> dict[str, Any]:
    """Captura REAL del banner de servicios no-HTTP abiertos (SSH, SMB, RDP).
    Solo puertos de la lista blanca; socket-connect con lectura única."""
    host_limpio = _host_de(host)
    if not _en_scope(host_limpio, roe):
        return {"error": "fuera de alcance local del transporte", "host": host_limpio}
    solicitados = {int(p) for p in puertos.replace(" ", "").split(",") if p.isdigit()}
    objetivos = sorted(solicitados & PUERTOS_PERMITIDOS)
    banners: list[dict[str, Any]] = []
    for puerto in objetivos:
        try:
            with socket.create_connection((host_limpio, puerto), timeout=2.5) as s:
                s.settimeout(2.0)
                try:
                    bruto = s.recv(_BANNER_TAM)
                    texto = bruto.decode("utf-8", "replace").strip()
                except (socket.timeout, OSError):
                    texto = ""
                banners.append({"puerto": puerto,
                                "banner": texto[:300] if texto else "",
                                "nota": "" if texto else
                                        "sin banner inicial (el cliente debe hablar primero)"})
        except OSError:
            continue
    return {"host": host_limpio, "banners": banners,
            "metodo": "socket-connect + lectura inicial (ruido real, sin evasión)"}


def recon_reverse_dns(host: str, roe: ROEPolitica) -> dict[str, Any]:
    """Resolución PTR REAL (DNS inverso) de una IP dentro del alcance."""
    ip = _host_de(host)
    if not _en_scope(ip, roe):
        return {"error": "fuera de alcance local del transporte", "host": ip}
    try:
        import dns.resolver
        rev = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
        respuestas = dns.resolver.resolve(rev, "PTR", lifetime=5)
        return {"host": ip, "ptr": [str(r) for r in respuestas][:5]}
    except Exception as exc:
        return {"host": ip, "ptr": [], "nota": f"sin PTR o resolver no disponible: {str(exc)[:120]}"}


def recon_http_methods(url: str, roe: ROEPolitica) -> dict[str, Any]:
    """Comprueba REALmente el método OPTIONS y detecta métodos peligrosos."""
    host = _host_de(url)
    if not _en_scope(host, roe):
        return {"error": "fuera de alcance local del transporte", "host": host}
    try:
        import httpx
        destino = url if url.startswith("http") else f"https://{url}"
        with _cliente_http(timeout=8, follow_redirects=False) as c:
            r = c.options(destino)
        permitidos = [m.strip().upper() for m in
                      r.headers.get("allow", r.headers.get("access-control-allow-methods", "")).split(",")
                      if m.strip()]
        peligrosos = [m for m in permitidos
                      if m in ("PUT", "DELETE", "TRACE", "CONNECT", "MOVE", "COPY", "PATCH")]
        return {"url": destino, "estado": r.status_code,
                "metodos_permitidos": permitidos, "metodos_peligrosos": peligrosos}
    except Exception as exc:
        return {"url": url, "error": str(exc)[:200]}


def recon_dir_index(url: str, roe: ROEPolitica, rutas: str = "") -> dict[str, Any]:
    """Detecta listados de directorio REALES ('Index of /') sobre rutas
    descubiertas (p. ej. las expuestas en robots.txt). Consultas GET
    acotadas a las rutas proporcionadas."""
    host = _host_de(url)
    if not _en_scope(host, roe):
        return {"error": "fuera de alcance local del transporte", "host": host}
    lista = [r.strip() for r in rutas.replace("\n", ",").split(",") if r.strip()][:40]
    if not lista:
        return {"url": url, "consultadas": [], "nota": "sin rutas candidatas"}
    try:
        import httpx
        destino_base = url if url.startswith("http") else f"https://{url}"
        abiertos: list[dict[str, Any]] = []
        consultadas: list[str] = []
        with _cliente_http(timeout=6, follow_redirects=False) as c:
            for ruta in lista:
                destino = destino_base.rstrip("/") + ruta
                consultadas.append(destino)
                try:
                    r = c.get(destino)
                except Exception:
                    continue
                cuerpo = r.text[:3000].lower()
                if r.status_code == 200 and "index of /" in cuerpo:
                    abiertos.append({"ruta": ruta, "evidencia": "Index of / detectado"})
                elif r.status_code == 200 and ("<a href=" in cuerpo and "parent directory" in cuerpo):
                    abiertos.append({"ruta": ruta, "evidencia": "listado con enlaces detectado"})
        return {"url": destino_base, "consultadas": consultadas,
                "directorios_abiertos": abiertos}
    except Exception as exc:
        return {"url": url, "error": str(exc)[:200]}


# ---------------------------------------------------------------------------
# C2 y explotación: adaptadores REALES (Sliver / Mythic / Metasploit)
# ---------------------------------------------------------------------------


def recon_correos_seguridad(dominio: str, roe: ROEPolitica) -> dict[str, Any]:
    """Postura REAL de seguridad de correo del dominio (consultas DNS TXT).

    Enumera SPF, DMARC y selectores DKIM comunes. Un dominio sin SPF/DMARC
    estricto es puerta de entrada para phishing dirigido (fase F6): hallazgo
    documentable con evidencia DNS real.
    """
    dominio = _host_de(dominio)
    if dominio and dominio not in (d.lower() for d in roe.alcance_dominios):
        return {"error": "dominio fuera del alcance del ROE", "dominio": dominio}
    try:
        import dns.resolver  # dnspython
    except ImportError:
        return {"error": "dnspython no disponible en el despliegue"}
    resultados: dict[str, Any] = {"dominio": dominio}

    def _txt(nombre: str) -> list[str]:
        try:
            return ["".join(str(x) for x in r.strings)
                    for r in dns.resolver.resolve(nombre, "TXT")]
        except Exception:
            return []

    # Guardia de honestidad: si el dominio NO RESUELVE (no A/AAAA/MX/NS),
    # auditar "postura de correo mejorable" sería un falso positivo — un
    # dominio sin DNS no es un dominio sin SPF. Se reporta el hecho real
    # (sin resolución) y sin debilidades: la fase F1 no fabrica hallazgos.
    resuelve = False
    for tipo in ("A", "AAAA", "MX", "NS"):
        try:
            if list(dns.resolver.resolve(dominio, tipo)):
                resuelve = True
                break
        except Exception:
            continue
    if not resuelve:
        resultados["sin_resolucion"] = True
        resultados["nota"] = ("el dominio no resuelve DNS (A/AAAA/MX/NS): "
                              "no procede auditar postura de correo")
        resultados["debilidades"] = []
        return resultados

    spf = [t for t in _txt(dominio) if t.lower().startswith("v=spf1")]
    dmarc = [t for t in _txt(f"_dmarc.{dominio}") if t.lower().startswith("v=dmarc1")]
    dkim: dict[str, list[str]] = {}
    for selector in ("default", "google", "selector1", "selector2",
                     "k1", "dkim", "mail", "s1", "s2"):
        claves = _txt(f"{selector}._domainkey.{dominio}")
        if claves:
            dkim[selector] = claves
    resultados["spf"] = spf
    resultados["dmarc"] = dmarc
    resultados["dkim_selectores"] = sorted(dkim)
    politicas: list[str] = []
    if not spf:
        politicas.append("sin SPF: cualquier servidor puede suplantar al dominio")
    if not dmarc:
        politicas.append("sin DMARC: sin política contra suplantación directa")
    elif "p=none" in dmarc[0].lower():
        politicas.append("DMARC p=none: no rechaza suplantación, solo monitoriza")
    if not dkim:
        politicas.append("sin DKIM en selectores comunes (verificar selectores privados)")
    resultados["debilidades"] = politicas
    return resultados


def osint_sitemap(dominio: str, roe: ROEPolitica, maximo: int = 100) -> dict[str, Any]:
    """Descubre rutas REALES vía /sitemap.xml (y /sitemap_index.xml).

    Las rutas publicadas por el propio objetivo amplían la superficie a
    probar en F2 sin ruido adicional (un único GET público)."""
    host = _host_de(dominio)
    if not _en_scope(host, roe):
        return {"error": "fuera de alcance local del transporte", "host": host}
    try:
        import httpx
        base = f"https://{host}" if "." in host else f"https://{dominio}"
        for candidato in ("/sitemap.xml", "/sitemap_index.xml"):
            with _cliente_http(timeout=10, follow_redirects=True) as c:
                r = c.get(base + candidato)
            if r.status_code != 200 or "<urlset" not in r.text and "<sitemapindex" not in r.text:
                continue
            import re
            locs = re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", r.text)[:maximo]
            rutas = []
            for loc in locs:
                ruta = "/" + loc.split("://", 1)[-1].split("/", 1)[1] if "/" in loc.split("://", 1)[-1] else "/"
                rutas.append(ruta)
            return {"dominio": str(dominio), "fuente": candidato,
                    "urls": locs, "rutas": rutas}
        return {"dominio": str(dominio), "urls": [], "rutas": [],
                "nota": "sin sitemap.xml publicado"}
    except Exception as exc:
        return {"dominio": dominio, "error": str(exc)[:200]}


_RUTAS_SENSIBLES = (
    "/.git/HEAD", "/.env", "/.env.local", "/.aws/credentials",
    "/server-status", "/server-info", "/.svn/entries", "/web.config",
    "/.htaccess", "/backup.sql", "/dump.sql", "/composer.json",
)


def recon_rutas_sensibles(url: str, roe: ROEPolitica) -> dict[str, Any]:
    """Comprueba exposición REAL de artefactos sensibles habituales
    (.git, .env, backups, server-status) sobre el host del alcance.

    Recon activo estándar y acotado: un GET por ruta candidata, sin
    fuerza bruta. La exposición de .git/.env es hallazgo de severidad
    alta en cualquier test de intrusión externo."""
    host = _host_de(url)
    if not _en_scope(host, roe):
        return {"error": "fuera de alcance local del transporte", "host": host}
    try:
        import httpx
        base = url if url.startswith("http") else f"https://{url}"
        expuestas: list[dict[str, Any]] = []
        probadas: list[str] = []
        with _cliente_http(timeout=6, follow_redirects=False) as c:
            for ruta in _RUTAS_SENSIBLES:
                destino = base.rstrip("/") + ruta
                probadas.append(destino)
                try:
                    r = c.get(destino)
                except Exception:
                    continue
                cuerpo = r.text[:500].lower()
                pista = ""
                if r.status_code == 200:
                    if ruta == "/.git/HEAD" and "ref: refs/" in cuerpo:
                        pista = "repositorio git expuesto"
                    elif ruta == "/.env" and ("=" in cuerpo and "\n" in cuerpo
                                              or "db_" in cuerpo or "key=" in cuerpo):
                        pista = "variables de entorno expuestas"
                    elif ruta == "/server-status" and ("server status" in cuerpo or "apache" in cuerpo):
                        pista = "server-status de Apache público"
                    elif ruta in ("/.aws/credentials",) and "aws_access_key" in cuerpo:
                        pista = "credenciales AWS expuestas"
                    elif ruta in ("/backup.sql", "/dump.sql") and ("create table" in cuerpo or "insert into" in cuerpo):
                        pista = "volcado SQL expuesto"
                    elif ruta in ("/web.config", "/.htaccess") and ("<configuration" in cuerpo or "rewrite" in cuerpo):
                        pista = "configuración de servidor expuesta"
                if pista:
                    expuestas.append({"ruta": ruta, "pista": pista})
        return {"url": base, "probadas": probadas, "expuestas": expuestas}
    except Exception as exc:
        return {"url": url, "error": str(exc)[:200]}


def c2_estado(roe: ROEPolitica) -> dict[str, Any]:
    """Estado real de las integraciones C2 configuradas por el operador.
    Consulta cada framework configurado; los no configurados se documentan."""
    try:
        from ..integraciones import metasploit as msf
        from ..integraciones import mythic
        from ..integraciones import sliver
    except ImportError:  # orchestrator como paquete de nivel superior
        from integraciones import metasploit as msf
        from integraciones import mythic
        from integraciones import sliver
    return {
        "sliver": sliver.estado(),
        "mythic": mythic.estado(),
        "metasploit": msf.estado(),
    }


def c2_sliver_tarea(sesion_id: int, comando: str, roe: ROEPolitica) -> dict[str, Any]:
    try:
        from ..integraciones import sliver
    except ImportError:
        from integraciones import sliver
    return sliver.tarea(int(sesion_id), comando)


def c2_sliver_retirar(sesion_id: int, roe: ROEPolitica) -> dict[str, Any]:
    try:
        from ..integraciones import sliver
    except ImportError:
        from integraciones import sliver
    return sliver.retirar(int(sesion_id))


def c2_mythic_tarea(callback_id: int, comando: str, params: str = "",
                    roe: ROEPolitica = None) -> dict[str, Any]:
    try:
        from ..integraciones import mythic
    except ImportError:
        from integraciones import mythic
    return mythic.tarea(int(callback_id), comando, params)


def c2_mythic_retirar(callback_id: int, roe: ROEPolitica) -> dict[str, Any]:
    try:
        from ..integraciones import mythic
    except ImportError:
        from integraciones import mythic
    return mythic.retirar(int(callback_id))


def c2_msf_tarea(sesion_id: int, comando: str, roe: ROEPolitica) -> dict[str, Any]:
    try:
        from ..integraciones import metasploit
    except ImportError:
        from integraciones import metasploit
    return metasploit.tarea_sesion(int(sesion_id), comando)


def c2_msf_retirar(sesion_id: int, roe: ROEPolitica) -> dict[str, Any]:
    try:
        from ..integraciones import metasploit
    except ImportError:
        from integraciones import metasploit
    return metasploit.retirar_sesion(int(sesion_id))


def explotar_ejecutar(modulo: str, opciones: dict[str, Any] | None = None,
                      roe: ROEPolitica = None) -> dict[str, Any]:
    """Ejecución REAL de un módulo Metasploit (exploit o auxiliar) vía RPC.

    Requiere Metasploit RPC configurado por el operador. El boundary exige
    aprobación humana SIEMPRE para explotar.ejecutar; aquí solo se ejecuta
    lo firmado. Sin adaptador configurado se devuelve el requisito: jamás
    un éxito simulado.
    """
    import os as _os
    if not (_os.environ.get("MSF_HOST") and _os.environ.get("MSF_USER")):
        return {
            "error": "sin adaptador de explotación: Metasploit RPC no configurado "
                     "(MSF_HOST/MSF_PORT/MSF_USER/MSF_PASS). Configure msfrpcd "
                     "en su infraestructura autorizada para ejecutar módulos reales.",
            "exito": False,
        }
    try:
        from ..integraciones import metasploit
    except ImportError:
        from integraciones import metasploit
    tipo, nombre = _split_modulo(modulo)
    if not nombre:
        return {"error": f"módulo no válido: '{modulo}' (use 'exploit/...' o "
                         "'auxiliary/...')", "exito": False}
    # Defensa en profundidad: RHOSTS debe estar dentro del alcance del ROE
    if roe is not None:
        for clave in ("RHOSTS", "RHOST"):
            destino = str((opciones or {}).get(clave, ""))
            if destino and not _en_scope(_host_de(destino), roe):
                return {"error": f"{clave}={destino} fuera del alcance del ROE",
                        "exito": False}
    return metasploit.ejecutar_modulo(tipo, nombre, opciones or {})


def _split_modulo(modulo: str) -> tuple[str, str]:
    texto = (modulo or "").strip().lower()
    if texto.startswith("exploit/"):
        return "exploit", texto
    if texto.startswith("auxiliary/"):
        return "auxiliary", texto
    if texto.startswith("post/"):
        return "post", texto
    return "", ""


def phishing_enviar_campana(destinatarios: list[str], asunto: str, cuerpo: str,
                            roe: ROEPolitica) -> dict[str, Any]:
    """Envío REAL vía la infraestructura SMTP del equipo (F6, con firma)."""
    try:
        from ..integraciones import smtp_envio
    except ImportError:
        from integraciones import smtp_envio
    return smtp_envio.enviar(destinatarios, asunto, cuerpo)


def osint_zone_transfer(dominio: str, roe: ROEPolitica) -> dict[str, Any]:
    """Intento REAL de transferencia de zona (AXFR) contra los NS del dominio.

    Técnica clásica de OSINT activo-ligero: si los servidores autoritativos
    permiten AXFR, se obtiene el mapa completo de registros sin escanear.
    Requiere dnspython (dependencia ya presente).
    """
    host = _host_de(dominio)
    if not _en_scope(host, roe):
        return {"error": "fuera de alcance local del transporte", "host": host}
    try:
        import dns.query
        import dns.resolver
        import dns.zone
    except ImportError:
        return {"host": host, "error": "dnspython no instalado: añádelo al entorno "
                                       "del orquestador (pip install dnspython)"}
    servidores: list[str] = []
    try:
        respuesta = dns.resolver.resolve(host, "NS")
        servidores = [str(r.target).rstrip(".").lower() for r in respuesta]
    except Exception as exc:
        return {"host": host, "servidores_ns": [], "transferidas": {},
                "vulnerable": False,
                "error": f"resolución NS fallida: {str(exc)[:140]}"}
    resultados: dict[str, list[str]] = {}
    for ns in servidores[:4]:
        try:
            zona = dns.zone.from_xfr(dns.query.xfr(ns, host, timeout=6, lifetime=12))
            registros = [str(n) + " " + str(zona[n].to_text(n)) for n in zona.nodes]
            resultados[ns] = registros[:500]
        except Exception:
            resultados[ns] = []  # el NS rechaza AXFR (lo esperable)
    transferidas = {ns: regs for ns, regs in resultados.items() if regs}
    return {
        "host": host,
        "servidores_ns": servidores,
        "transferidas": transferidas,
        "vulnerable": bool(transferidas),
        "nota": ("AXFR permitido: el mapa completo de registros es público para "
                 "el atacante. Hallazgo de exposición DNS." if transferidas
                 else "Ningún servidor autoritativo permite AXFR (configuración correcta)."),
    }


def recon_nmap_servicios(host: str, roe: ROEPolitica,
                         puertos: str = "") -> dict[str, Any]:
    """Detección de servicios REAL con nmap (subprocess -sV) si está instalado.

    - Lista blanca de puertos idéntica al port_scan interno (defensa en
      profundidad: nunca se barre fuera de la lista).
    - Sin binario nmap: devuelve el requisito exacto, jamás un éxito falso.
    """
    import shutil
    destino = _host_de(host)
    if not _en_scope(destino, roe):
        return {"error": "fuera de alcance local del transporte", "host": destino}
    binario = shutil.which("nmap")
    if not binario:
        return {"host": destino, "servicios": [],
                "error": "nmap no está instalado en el host del orquestador: "
                         "instálalo (apt install nmap) para detección de servicios "
                         "profunda; mientras tanto usa recon.port_scan (sockets)"}
    # z3 (auditoría seguridad): inyección de argumentos. `destino` se pasa
    # como último parámetro de nmap; si empezara por '-' nmap lo interpretaría
    # como opción (p. ej. -iL/-oX con fichero arbitrario) en vez de objetivo.
    # El alcance del ROE normalmente lo impide, pero es defensa en profundidad.
    if destino.startswith("-"):
        return {"host": destino, "servicios": [],
                "error": "objetivo inválido para nmap (no puede empezar por '-')"}
    if puertos:
        solicitados = {int(p) for p in puertos.replace(" ", "").split(",") if p.isdigit()}
    else:
        solicitados = set(PUERTOS_PERMITIDOS)
    lista = sorted(solicitados & PUERTOS_PERMITIDOS)
    if not lista:
        return {"host": destino, "servicios": [],
                "error": "ningún puerto solicitado está en la lista blanca del orquestador"}
    args_puertos = ",".join(str(p) for p in lista)
    try:
        import subprocess
        import xml.etree.ElementTree as ET
        proceso = subprocess.run(
            [binario, "-sV", "--version-light", "--open", "-oX", "-",
             "-p", args_puertos, destino],
            capture_output=True, timeout=180)
        raiz = ET.fromstring(proceso.stdout)
        servicios: list[dict[str, Any]] = []
        for host_xml in raiz.findall("host"):
            for puerto in host_xml.iter("port"):
                estado = puerto.find("state")
                if estado is None or estado.get("state") != "open":
                    continue
                servicio = puerto.find("service") or {}
                servicios.append({
                    "puerto": int(puerto.get("portid", "0")),
                    "protocolo": puerto.get("protocol", "tcp"),
                    "nombre": (servicio.get("name") if hasattr(servicio, "get") else None) or "",
                    "producto": (servicio.get("product") if hasattr(servicio, "get") else None) or "",
                    "version": (servicio.get("version") if hasattr(servicio, "get") else None) or "",
                })
        return {"host": destino, "puertos_sondeados": lista, "servicios": servicios,
                "fuente": "nmap -sV (subprocess real)"}
    except subprocess.TimeoutExpired:
        return {"host": destino, "servicios": [], "error": "nmap agotó el tiempo límite (180s)"}
    except Exception as exc:
        return {"host": destino, "servicios": [],
                "error": f"nmap falló: {str(exc)[:160]}"}


# ---------------------------------------------------------------------------
# Arsenal v20: evasión verificada, persistencia real del lab y AD ofensivo
# ---------------------------------------------------------------------------


def _b64_de(payload_b64: str) -> bytes | None:
    try:
        import base64
        return base64.b64decode(payload_b64, validate=True)
    except Exception:
        return None


def evasion_generar(host: str = "", payload_b64: str = "", metodo: str = "aes_cbc",
                    formato: str = "python", roe: ROEPolitica | None = None) -> dict[str, Any]:
    """Artefacto de evasión con verificación YARA real y round-trip."""
    datos = _b64_de(payload_b64)
    if datos is None:
        return {"error": "payload_b64 debe ser base64 válido"}
    if len(datos) > 100_000:
        return {"error": "payload demasiado grande (máximo 100 KB)"}
    from . import evasion
    return evasion.generar(datos, metodo, formato)


def evasion_escanear(host: str = "", payload_b64: str = "",
                     roe: ROEPolitica | None = None) -> dict[str, Any]:
    datos = _b64_de(payload_b64)
    if datos is None:
        return {"error": "payload_b64 debe ser base64 válido"}
    from . import evasion
    return evasion.escanear(datos)


def persistencia_implantar(host: str = "", metodo: str = "", comando: str = "",
                           raiz: str = "", sitio: str = "", interprete: str = "",
                           roe: ROEPolitica | None = None) -> dict[str, Any]:
    if host and roe is not None and not _en_scope(host, roe):
        return {"error": "fuera de alcance local del transporte"}
    from . import persistencia
    return persistencia.implantar(metodo, comando, raiz=raiz or None,
                                  sitio=sitio or None, interprete=interprete or None)


def persistencia_verificar(host: str = "", metodo: str = "", raiz: str = "",
                           sitio: str = "", interprete: str = "",
                           roe: ROEPolitica | None = None) -> dict[str, Any]:
    from . import persistencia
    return persistencia.verificar(metodo, raiz=raiz or None, sitio=sitio or None,
                                  interprete=interprete or None)


def persistencia_retirar(host: str = "", metodo: str = "", raiz: str = "",
                         sitio: str = "", roe: ROEPolitica | None = None) -> dict[str, Any]:
    from . import persistencia
    return persistencia.retirar(metodo, raiz=raiz or None, sitio=sitio or None)


def persistencia_estado(roe: ROEPolitica | None = None) -> dict[str, Any]:
    from . import persistencia
    return persistencia.estado()


def ad_kerberoasting(host: str = "", roe: ROEPolitica | None = None) -> dict[str, Any]:
    from . import ad
    return ad.kerberoasting(host, roe=roe)


def ad_asrep(host: str = "", roe: ROEPolitica | None = None) -> dict[str, Any]:
    from . import ad
    return ad.asrep(host, roe=roe)


def ad_dcsync(host: str = "", dn_objetivo: str = "",
              roe: ROEPolitica | None = None) -> dict[str, Any]:
    from . import ad
    return ad.dcsync(host, dn_objetivo, roe=roe)


def ad_pass_the_hash(host: str = "", usuario: str = "", hash_nt: str = "",
                     roe: ROEPolitica | None = None) -> dict[str, Any]:
    from . import ad
    return ad.pass_the_hash(host, usuario, hash_nt, roe=roe)


def _ad_lectura(tipo: str, host: str, roe: ROEPolitica | None) -> dict[str, Any]:
    if host and roe is not None and not _en_scope(host, roe):
        return {"conectado": False, "error": "fuera de alcance local del transporte"}
    try:
        from .integraciones.ldap import enumerar
    except ImportError:
        from integraciones.ldap import enumerar
    return enumerar(tipo)


def ad_laps(host: str = "", roe: ROEPolitica | None = None) -> dict[str, Any]:
    return _ad_lectura("laps", host, roe)


def ad_gmsa(host: str = "", roe: ROEPolitica | None = None) -> dict[str, Any]:
    return _ad_lectura("gmsa", host, roe)


def ad_trusts(host: str = "", roe: ROEPolitica | None = None) -> dict[str, Any]:
    return _ad_lectura("trusts", host, roe)


def ad_rutas_da(host: str = "", roe: ROEPolitica | None = None) -> dict[str, Any]:
    from . import ad
    return ad.rutas_a_da(host, roe=roe)


# ---------------------------------------------------------------------------
# Registro de transportes por engagement
# ---------------------------------------------------------------------------


def transportes_de(roe: ROEPolitica) -> dict[str, Callable[..., dict[str, Any]]]:
    """Mapa "servidor.tool" -> función real acotada al ROE del engagement."""
    def envolver(fn: Callable[..., dict]) -> Callable[..., dict]:
        def ejecutar(*args: Any, **kwargs: Any) -> dict:
            try:
                return fn(*args, roe=roe, **kwargs)
            except TypeError:
                # llamada posicional desde el boundary
                return fn(*args, roe=roe)
            except Exception as exc:  # última línea de defensa
                return {"error": f"transporte falló: {str(exc)[:200]}"}
        return ejecutar

    return {
        "osint.subdominios_crtsh": envolver(osint_subdominios_crtsh),
        "osint.robots_txt": envolver(osint_robots_txt),
        "osint.buscar_filtraciones": envolver(osint_buscar_filtraciones),
        "osint.wayback": envolver(osint_wayback),
        "osint.zone_transfer": envolver(osint_zone_transfer),
        "osint.sitemap": envolver(osint_sitemap),
        "recon.dns_enum": envolver(recon_dns_enum),
        "recon.http_probe": envolver(recon_http_probe),
        "recon.cert_info": envolver(recon_cert_info),
        "recon.tech_fingerprint": envolver(recon_tech_fingerprint),
        "recon.port_scan": envolver(recon_port_scan),
        "recon.banner_grab": envolver(recon_banner_grab),
        "recon.reverse_dns": envolver(recon_reverse_dns),
        "recon.http_methods": envolver(recon_http_methods),
        "recon.dir_index": envolver(recon_dir_index),
        "recon.nmap_servicios": envolver(recon_nmap_servicios),
        "recon.correos_seguridad": envolver(recon_correos_seguridad),
        "recon.rutas_sensibles": envolver(recon_rutas_sensibles),
        "c2.estado": envolver(c2_estado),
        "c2.sliver_tarea": envolver(c2_sliver_tarea),
        "c2.sliver_retirar": envolver(c2_sliver_retirar),
        "c2.mythic_tarea": envolver(c2_mythic_tarea),
        "c2.mythic_retirar": envolver(c2_mythic_retirar),
        "c2.msf_tarea": envolver(c2_msf_tarea),
        "c2.msf_retirar": envolver(c2_msf_retirar),
        "explotar.ejecutar": envolver(explotar_ejecutar),
        "phishing.enviar_campana": envolver(phishing_enviar_campana),
        "evasion.generar": envolver(evasion_generar),
        "evasion.escanear": envolver(evasion_escanear),
        "persistencia.implantar": envolver(persistencia_implantar),
        "persistencia.verificar": envolver(persistencia_verificar),
        "persistencia.retirar": envolver(persistencia_retirar),
        "persistencia.estado": envolver(persistencia_estado),
        "ad.kerberoasting": envolver(ad_kerberoasting),
        "ad.asrep_roasting": envolver(ad_asrep),
        "ad.dcsync": envolver(ad_dcsync),
        "ad.pass_the_hash": envolver(ad_pass_the_hash),
        "ad.laps_leer": envolver(ad_laps),
        "ad.gmsa_leer": envolver(ad_gmsa),
        "ad.trusts": envolver(ad_trusts),
        "ad.rutas_da": envolver(ad_rutas_da),
    }


def resumen_transportes() -> str:
    return json.dumps(sorted(TRANSPORTE_NOMBRES), ensure_ascii=False)


TRANSPORTE_NOMBRES = (
    "osint.subdominios_crtsh", "osint.robots_txt", "osint.wayback",
    "osint.zone_transfer", "osint.sitemap", "recon.dns_enum",
    "recon.http_probe", "recon.cert_info", "recon.tech_fingerprint",
    "recon.port_scan", "recon.banner_grab", "recon.reverse_dns",
    "recon.http_methods", "recon.dir_index", "recon.nmap_servicios",
    "recon.correos_seguridad", "recon.rutas_sensibles",
    "c2.estado", "c2.sliver_tarea", "c2.sliver_retirar", "c2.mythic_tarea",
    "c2.mythic_retirar", "c2.msf_tarea", "c2.msf_retirar",
    "explotar.ejecutar", "phishing.enviar_campana",
    "evasion.generar", "evasion.escanear",
    "persistencia.implantar", "persistencia.verificar", "persistencia.retirar",
    "persistencia.estado",
    "ad.kerberoasting", "ad.asrep_roasting", "ad.dcsync", "ad.pass_the_hash",
    "ad.laps_leer", "ad.gmsa_leer", "ad.trusts", "ad.rutas_da",
)
