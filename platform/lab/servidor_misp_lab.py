"""Threat intel de laboratorio: servidor HTTP REAL compatible con la API de MISP.

El conector de la plataforma (platform/integraciones/misp.py) habla el
protocolo JSON REST de MISP. Este servidor implementa EXACTAMENTE ese
subconjunto sobre sockets reales, para que el operador pueda ejercitar
el enriquecimiento threat intel de extremo a extremo sin desplegar una
instancia MISP completa (que exige MySQL+PHP+worker por ejercicio).

    Uso:  python3 lab/servidor_misp_lab.py [--puerto 9000] [--estado ruta.json]

Endpoints implementados (los que consume el conector):
    GET  /servers/getVersion      → {"version": "2.4.188"}
    POST /attributes/restSearch   → {"response": {"Attribute": [...]}}
    POST /events/restSearch       → {"response": [Event, ...]}
    POST /events/add              → {"Event": {"id": N, ...}}

Autenticación idéntica a la real: cabecera `Authorization: <clave>`.
La clave se fija con --clave o LAB_MISP_KEY (por defecto "clave-lab-misp";
SOLO para laboratorio, jamás use esta clave fuera de un entorno aislado).

Intel semilla: activos del lab "ACME Corporación" (los mismos del
objetivo nginx y del servidor_lab.py), de modo que el enriquecimiento
produce coincidencias REALES de inmediato en un engagement de prueba.
Los eventos que el operador exporta vía /events/add se suman al estado
y, con --estado, sobreviven al reinicio (JSON en disco).

Solo escucha en localhost por defecto: es un servicio del propio
operador, nunca un tercero. En Docker se publica en la red del lab.
"""
from __future__ import annotations

import argparse
import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

# ---------------------------------------------------------------------------
# Estado del intel (atributos y eventos) — en memoria + persistencia opcional
# ---------------------------------------------------------------------------

_CLAVE = os.environ.get("LAB_MISP_KEY", "clave-lab-misp")
_VERSION = "2.4.188"
_RUTA_ESTADO: Path | None = None
_bloqueo = threading.Lock()


def _ahora() -> int:
    return int(time.time())


def _intel_inicial() -> dict:
    """Intel semilla del lab ACME (coincide con el objetivo del laboratorio)."""
    t = _ahora()
    return {
        "siguiente_id": 100,
        "atributos": [
            {"id": "1", "event_id": "1", "type": "domain",
             "category": "Network activity", "to_ids": True,
             "value": "acme-demo.local", "comment": "Dominio del lab ACME",
             "timestamp": t, "Tag": [{"name": "lab"}, {"name": "misp-test"}]},
            {"id": "2", "event_id": "1", "type": "hostname",
             "category": "Network activity", "to_ids": True,
             "value": "portal.acme-demo.local", "comment": "Portal interno",
             "timestamp": t, "Tag": [{"name": "lab"}]},
            {"id": "3", "event_id": "1", "type": "hostname",
             "category": "Network activity", "to_ids": True,
             "value": "vpn.acme-demo.local", "comment": "Gateway VPN del lab",
             "timestamp": t, "Tag": [{"name": "lab"}]},
            {"id": "4", "event_id": "2", "type": "ip-dst",
             "category": "Network activity", "to_ids": True,
             "value": "10.20.0.10", "comment": "Controlador de dominio (lab)",
             "timestamp": t, "Tag": [{"name": "lab"}, {"name": "dir:ad"}]},
            {"id": "5", "event_id": "2", "type": "ip-dst",
             "category": "Network activity", "to_ids": True,
             "value": "10.20.0.25", "comment": "Servidor de archivos (lab)",
             "timestamp": t, "Tag": [{"name": "lab"}]},
        ],
        "eventos": [
            {"id": "1", "info": "Activos del laboratorio ACME (semilla)",
             "threat_level_id": 4, "analysis": 2,
             "date": time.strftime("%Y-%m-%d", time.gmtime(t)),
             "published": True, "timestamp": t,
             "Tag": [{"name": "lab"}, {"name": "misp-test"}]},
            {"id": "2", "info": "Infraestructura interna ACME (semilla)",
             "threat_level_id": 3, "analysis": 1,
             "date": time.strftime("%Y-%m-%d", time.gmtime(t)),
             "published": True, "timestamp": t,
             "Tag": [{"name": "lab"}, {"name": "dir:ad"}]},
        ],
    }


def _cargar_estado(ruta: Path | None) -> dict:
    if ruta and ruta.exists():
        try:
            return json.loads(ruta.read_text(encoding="utf-8"))
        except Exception:
            pass  # estado corrupto: se reinicia con la semilla
    return _intel_inicial()


def _guardar_estado() -> None:
    if _RUTA_ESTADO is None:
        return
    try:
        _RUTA_ESTADO.parent.mkdir(parents=True, exist_ok=True)
        _RUTA_ESTADO.write_text(
            json.dumps(_INTEL, ensure_ascii=False, indent=1), encoding="utf-8")
    except Exception as exc:  # persistencia best-effort, nunca tumba el lab
        print(f"[misp-lab] aviso: no se pudo guardar el estado: {exc}",
              flush=True)


_INTEL = _cargar_estado(_RUTA_ESTADO)


# ---------------------------------------------------------------------------
# Implementación del subconjunto de la API MISP
# ---------------------------------------------------------------------------

def _filtrar_dias(filtro: str | None) -> int | None:
    """Convierte el filtro 'Nd' de MISP (timestamp) en cutoff unix."""
    if isinstance(filtro, str) and filtro.endswith("d"):
        try:
            dias = max(1, int(filtro[:-1]))
        except ValueError:
            return None
        return _ahora() - dias * 86400
    return None


def _attrs_rest(cuerpo: dict) -> dict:
    valores = cuerpo.get("value") or []
    if isinstance(valores, str):
        valores = [valores]
    buscados = {str(v).strip().lower() for v in valores if str(v).strip()}
    cutoff = _filtrar_dias(cuerpo.get("timestamp"))
    limite = int(cuerpo.get("limit") or 500)
    with _bloqueo:
        encontrados = []
        for a in _INTEL["atributos"]:
            if buscados and str(a["value"]).lower() not in buscados:
                continue
            if cutoff and int(a.get("timestamp") or 0) < cutoff:
                continue
            encontrados.append(dict(a))
            if len(encontrados) >= limite:
                break
    return {"response": {"Attribute": encontrados}}


def _events_rest(cuerpo: dict) -> dict:
    tags = cuerpo.get("tag") or []
    if isinstance(tags, str):
        tags = [tags]
    cutoff = _filtrar_dias(cuerpo.get("timestamp"))
    limite = int(cuerpo.get("limit") or 20)
    solo_publicados = bool(cuerpo.get("published"))
    with _bloqueo:
        salida = []
        for e in _INTEL["eventos"]:
            if solo_publicados and not e.get("published"):
                continue
            if cutoff and int(e.get("timestamp") or 0) < cutoff:
                continue
            if tags and not ({t["name"] for t in (e.get("Tag") or [])}
                             & set(tags)):
                continue
            salida.append(dict(e))
            if len(salida) >= limite:
                break
    return {"response": salida}


def _events_add(cuerpo: dict) -> dict:
    evento = (cuerpo or {}).get("Event") or {}
    info = str(evento.get("info") or "").strip()
    attrs = evento.get("Attribute") or []
    if not info:
        return {"name": "El evento necesita info", "message": "info vacía",
                "url": "/events/add"}
    with _bloqueo:
        eid = str(_INTEL["siguiente_id"])
        _INTEL["siguiente_id"] += 1
        t = _ahora()
        _INTEL["eventos"].append({
            "id": eid, "info": info,
            "threat_level_id": int(evento.get("threat_level_id") or 4),
            "analysis": int(evento.get("analysis") or 0),
            "date": time.strftime("%Y-%m-%d", time.gmtime(t)),
            "published": False, "timestamp": t, "Tag": [],
        })
        for i, a in enumerate(attrs, start=1):
            _INTEL["atributos"].append({
                "id": f"{eid}{i}", "event_id": eid,
                "type": str(a.get("type") or "domain")[:30],
                "category": str(a.get("category") or "Network activity")[:60],
                "to_ids": bool(a.get("to_ids", True)),
                "value": str(a.get("value") or "")[:253],
                "comment": str(a.get("comment") or "")[:200],
                "timestamp": t, "Tag": [],
            })
        _guardar_estado()
    return {"Event": {"id": eid, "info": info, "distribution": 0,
                      "threat_level_id": int(evento.get("threat_level_id") or 4),
                      "analysis": int(evento.get("analysis") or 0),
                      "attribute_count": len(attrs)}}


# ---------------------------------------------------------------------------
# Servidor HTTP
# ---------------------------------------------------------------------------

class ManejadorMispLab(BaseHTTPRequestHandler):
    server_version = "MISP/2.4.188"  # cabecera Server como una instancia real

    def _json(self, codigo: int, datos: dict) -> None:
        cuerpo = json.dumps(datos).encode("utf-8")
        self.send_response(codigo)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(cuerpo)))
        self.end_headers()
        self.wfile.write(cuerpo)

    def _autorizado(self) -> bool:
        return self.headers.get("Authorization", "") == _CLAVE

    def do_GET(self) -> None:  # noqa: N802 (API stdlib)
        if not self._autorizado():
            self._json(403, {"name": "Clave API inválida",
                             "message": "Authorization requerida"})
            return
        ruta = self.path.split("?")[0]
        if ruta == "/servers/getVersion":
            self._json(200, {"version": _VERSION})
        else:
            self._json(404, {"name": "No encontrado", "message": ruta})

    def do_POST(self) -> None:  # noqa: N802 (API stdlib)
        if not self._autorizado():
            self._json(403, {"name": "Clave API inválida",
                             "message": "Authorization requerida"})
            return
        try:
            longitud = int(self.headers.get("Content-Length") or 0)
            cuerpo = json.loads(self.rfile.read(longitud) or b"{}")
        except Exception:
            self._json(400, {"name": "Cuerpo inválido",
                             "message": "JSON esperado"})
            return
        ruta = self.path.split("?")[0]
        if ruta == "/attributes/restSearch":
            self._json(200, _attrs_rest(cuerpo))
        elif ruta == "/events/restSearch":
            self._json(200, _events_rest(cuerpo))
        elif ruta == "/events/add":
            self._json(200, _events_add(cuerpo))
        else:
            self._json(404, {"name": "No encontrado", "message": ruta})

    def log_message(self, formato: str, *args) -> None:
        print(f"[misp-lab] {self.address_string()} {formato % args}", flush=True)


def main() -> None:
    global _RUTA_ESTADO, _CLAVE, _INTEL
    parser = argparse.ArgumentParser(
        description="Threat intel de laboratorio compatible con la API MISP")
    parser.add_argument("--puerto", type=int, default=9000)
    parser.add_argument("--clave", default=None,
                        help="Clave API del lab (defecto: LAB_MISP_KEY o "
                             "clave-lab-misp)")
    parser.add_argument("--estado", default=None,
                        help="Ruta JSON para persistir eventos exportados")
    parser.add_argument("--host", default="127.0.0.1",
                        help="Interfaz de escucha (127.0.0.1 salvo Docker)")
    args = parser.parse_args()
    if args.clave:
        _CLAVE = args.clave
    if args.estado:
        _RUTA_ESTADO = Path(args.estado)
        _INTEL = _cargar_estado(_RUTA_ESTADO)
    servidor = ThreadingHTTPServer((args.host, args.puerto), ManejadorMispLab)
    clave_mostrada = "clave-lab-misp (por defecto, SOLO lab)"
    if _CLAVE != "clave-lab-misp":
        clave_mostrada = "***"
    print(f"[misp-lab] API MISP de laboratorio en http://{args.host}:"
          f"{args.puerto} (versión {_VERSION})", flush=True)
    print(f"[misp-lab] clave del lab: {clave_mostrada}", flush=True)
    servidor.serve_forever()


if __name__ == "__main__":
    main()
