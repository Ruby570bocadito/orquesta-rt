"""Objetivo del laboratorio: servidor HTTP REAL para engagements de prueba.

Sirve una aplicación web deliberada para que las herramientas del
orquestador (http_probe, port_scan, tech_fingerprint, robots_txt) trabajen
contra I/O de verdad: sockets, peticiones y respuestas reales en 127.0.0.1.

Solo escucha en localhost: es un activo del propio operador, nunca un
tercero. En despliegue Docker se sustituye por el contenedor nginx del
lab (platform/lab/docker-compose.lab.yml).

Uso:  python3 lab/servidor_lab.py [--puerto 8080]
"""
from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

INDICE = """<!doctype html>
<html lang="es"><head><meta charset="utf-8">
<title>ACME Corporación — Portal Interno</title>
<meta name="generator" content="PortalACME 2.3.1">
</head><body>
<h1>ACME Corporación</h1>
<p>Portal de empleados. Acceso restringido al personal autorizado.</p>
<ul><li><a href="/admin">Panel de administración</a></li>
<li><a href="/gestion">Gestión de incidencias</a></li></ul>
</body></html>"""

ADMIN = """<!doctype html>
<html lang="es"><head><meta charset="utf-8"><title>ACME — Panel de administración</title>
</head><body><h1>Panel de administración</h1>
<form><label>Usuario</label><input name="usuario"><label>Contraseña</label>
<input type="password" name="clave"><button>Entrar</button></form>
<p>v2.3.1 — build 20260114</p></body></html>"""

ROBOTS = """User-agent: *
Disallow: /admin
Disallow: /gestion
Disallow: /privado
Sitemap: http://localhost:8080/sitemap.xml
"""


class ManejadorLab(BaseHTTPRequestHandler):
    server_version = "nginx/1.24.0"  # cabecera Server deliberadamente visible
    sys_version = ""

    def _responder(self, cuerpo: bytes, tipo: str = "text/html; charset=utf-8") -> None:
        self.send_response(200)
        self.send_header("Content-Type", tipo)
        self.send_header("Content-Length", str(len(cuerpo)))
        # SIN CSP, SIN HSTS, SIN X-Frame-Options: hallazgo real para F2
        self.end_headers()
        self.wfile.write(cuerpo)

    def do_GET(self) -> None:  # noqa: N802 (API stdlib)
        ruta = self.path.split("?")[0]
        if ruta == "/robots.txt":
            self._responder(ROBOTS.encode(), "text/plain; charset=utf-8")
        elif ruta.startswith("/admin"):
            self._responder(ADMIN.encode())
        elif ruta in ("/gestion", "/privado"):
            self._responder(ADMIN.encode())
        elif ruta == "/":
            self._responder(INDICE.encode())
        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

    def log_message(self, formato: str, *args) -> None:
        print(f"[lab] {self.address_string()} {formato % args}", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--puerto", type=int, default=8080)
    args = parser.parse_args()
    servidor = ThreadingHTTPServer(("127.0.0.1", args.puerto), ManejadorLab)
    print(f"[lab] objetivo activo en http://127.0.0.1:{args.puerto}", flush=True)
    servidor.serve_forever()
