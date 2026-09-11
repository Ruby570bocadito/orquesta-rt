"""Cliente REAL de la API REST de MISP (Threat Sharing).

MISP expone una API JSON estable con autenticación por cabecera
`Authorization: <api-key>`. Este módulo la consume directamente con httpx:

  estado()             → versión real del servidor (GET /servers/getVersion)
  buscar_iocs()        → POST /attributes/restSearch por valores (IOC → evento)
  eventos_recientes()  → POST /events/restSearch (filtro por tag/días)
  crear_evento()       → POST /events/add (exportar hallazgo al intel)

Uso principal en la plataforma: ENRIQUECER hallazgos — cada activo
(dominio, IP, hostname) del caso se contrasta contra el intel real del
equipo; las coincidencias (campaña, tags, to_ids) entran como evidencia
custodiada. Sin MISP configurado, el enriquecimiento responde un
requisito exacto: jamás produce "inteligencia" de relleno.

Configuración (variables de entorno del backend):
  MISP_URL      p. ej. https://misp.corp.local
  MISP_KEY      clave API (Automation → Auth Keys en MISP)
  MISP_SSL      "1" (por defecto) verifica TLS; "0" desactiva (solo labs)

Referencias del protocolo (documentación oficial de MISP):
  GET  /servers/getVersion      {"version": "2.4.xxx"}
  POST /attributes/restSearch   {"value": [...], "returnFormat": "json", ...}
  POST /events/restSearch       {"tag": [...], "returnFormat": "json", ...}
  POST /events/add              {"Event": {...}}
"""
from __future__ import annotations

import os
import re
from typing import Any


def _config() -> tuple[str, str, bool]:
    url = os.environ.get("MISP_URL", "")
    clave = os.environ.get("MISP_KEY", "")
    if not url or not clave:
        raise RuntimeError(
            "MISP no configurado: defina MISP_URL (p. ej. https://misp.corp.local) "
            "y MISP_KEY (clave de automatización de su instancia).")
    ssl_ok = os.environ.get("MISP_SSL", "1") != "0"
    return url.rstrip("/"), clave, ssl_ok


def _cliente(timeout: float = 20.0):
    import httpx
    url, clave, ssl_ok = _config()
    return httpx.Client(timeout=timeout, verify=ssl_ok), url, clave


def _cabeceras(clave: str) -> dict[str, str]:
    return {"Authorization": clave,
            "Accept": "application/json",
            "Content-Type": "application/json"}


def estado() -> dict[str, Any]:
    """Versión REAL del servidor MISP (ping autenticado)."""
    try:
        c, url, clave = _cliente()
        try:
            r = c.get(f"{url}/servers/getVersion", headers=_cabeceras(clave))
        finally:
            c.close()
        if r.status_code != 200:
            raise RuntimeError(f"MISP respondió {r.status_code}: {r.text[:200]}")
        return {"conectado": True, "servidor": url,
                "version": r.json().get("version", "desconocida")}
    except RuntimeError as exc:
        return {"conectado": False, "error": str(exc)}
    except Exception as exc:
        return {"conectado": False, "error": f"MISP: {str(exc)[:220]}"}


# Valores razonables de IOC que la plataforma enriquece (acotado anti-abuso):
_PATRON_HOST = re.compile(r"^[a-z0-9]([a-z0-9._-]{1,253})$", re.IGNORECASE)
_PATRON_IP = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3})$")


def _limpiar_valores(valores: list[str]) -> list[str]:
    limpios, vistos = [], set()
    for v in valores or []:
        v = (v or "").strip()
        if not v or len(v) > 253:
            continue
        if not (_PATRON_HOST.fullmatch(v) or _PATRON_IP.fullmatch(v)):
            continue
        v = v.lower()
        if v not in vistos:
            vistos.add(v)
            limpios.append(v)
        if len(limpios) >= 50:
            break  # techo duro: el lote nunca crece sin límite
    return limpios


def buscar_iocs(valores: list[str], dias: int = 365) -> dict[str, Any]:
    """Busca los valores REALES en el intel del equipo (attributes/restSearch).

    Devuelve coincidencias con evento, tags y flag to_ids tal como MISP las
    guarda. Sin coincidencias se informa: "0 atributos" es un resultado
    legítimo (ese activo no está en el intel), no un error.
    """
    limpios = _limpiar_valores(valores)
    if not limpios:
        return {"conectado": False,
                "error": "Sin valores válidos para buscar "
                         "(se aceptan dominios, hostnames e IPv4)"}
    try:
        c, url, clave = _cliente()
        try:
            r = c.post(f"{url}/attributes/restSearch",
                       json={"value": limpios, "returnFormat": "json",
                             "limit": 500,
                             "timestamp": f"{max(1, dias)}d"},
                       headers=_cabeceras(clave))
        finally:
            c.close()
        if r.status_code != 200:
            raise RuntimeError(
                f"MISP attributes/restSearch respondió {r.status_code}: {r.text[:200]}")
        datos = r.json()
        atributos = datos.get("response", {}).get("Attribute", [])
        coincidencias = []
        for a in atributos:
            coincidencias.append({
                "valor": a.get("value"),
                "tipo": a.get("type"),
                "categoria": a.get("category"),
                "to_ids": bool(a.get("to_ids")),
                "evento_id": a.get("event_id"),
                "comentario": (a.get("comment") or "")[:200],
                "tags": [t.get("name") for t in (a.get("Tag") or [])],
            })
        return {"conectado": True, "buscados": limpios,
                "coincidencias": coincidencias,
                "total": len(coincidencias)}
    except RuntimeError as exc:
        return {"conectado": False, "error": str(exc)}
    except Exception as exc:
        return {"conectado": False, "error": f"MISP búsqueda: {str(exc)[:220]}"}


def eventos_recientes(tag: str | None = None, dias: int = 30,
                      limite: int = 20) -> dict[str, Any]:
    """Eventos MISP recientes REALES (para preparar un engagement)."""
    try:
        c, url, clave = _cliente()
        cuerpo: dict[str, Any] = {"returnFormat": "json",
                                  "published": True, "limit": int(limite),
                                  "timestamp": f"{max(1, dias)}d"}
        if tag:
            cuerpo["tag"] = [tag]
        try:
            r = c.post(f"{url}/events/restSearch", json=cuerpo,
                       headers=_cabeceras(clave))
        finally:
            c.close()
        if r.status_code != 200:
            raise RuntimeError(
                f"MISP events/restSearch respondió {r.status_code}: {r.text[:200]}")
        eventos = r.json().get("response", [])
        resumen = [{
            "id": e.get("id"), "info": (e.get("info") or "")[:200],
            "nivel_amenaza": e.get("threat_level_id"),
            "fecha": e.get("date"),
            "tags": [t.get("name") for t in (e.get("Tag") or [])],
        } for e in eventos]
        return {"conectado": True, "eventos": resumen, "total": len(resumen)}
    except RuntimeError as exc:
        return {"conectado": False, "error": str(exc)}
    except Exception as exc:
        return {"conectado": False, "error": f"MISP eventos: {str(exc)[:220]}"}


def crear_evento(info: str, atributos: list[dict[str, str]],
                 distribucion: int = 0, nivel_amenaza: int = 4,
                 analisis: int = 0) -> dict[str, Any]:
    """Crea un evento REAL en MISP (exportar hallazgos del engagement al intel).

    distribucion: 0=organización, 1=comunidad, 2=conectado, 3=todo
    nivel_amenaza: 1=alta, 2=media, 3=baja, 4=indefinido
    analisis: 0=inicial, 1=en curso, 2=completado
    """
    if not info or not atributos:
        return {"conectado": False,
                "error": "Un evento necesita info y al menos un atributo"}
    try:
        c, url, clave = _cliente()
        evento = {
            "Event": {
                "info": info[:200],
                "distribution": int(distribucion),
                "threat_level_id": int(nivel_amenaza),
                "analysis": int(analisis),
                "Attribute": [{
                    "type": (a.get("tipo") or "domain")[:30],
                    "category": (a.get("categoria") or "Network activity")[:60],
                    "to_ids": bool(a.get("to_ids", True)),
                    "distribution": int(distribucion),
                    "value": (a.get("valor") or "")[:253],
                    "comment": (a.get("comentario") or "")[:200],
                } for a in atributos[:100]],  # techo anti-abuso
            }
        }
        try:
            r = c.post(f"{url}/events/add", json=evento, headers=_cabeceras(clave))
        finally:
            c.close()
        if r.status_code not in (200, 201):
            raise RuntimeError(
                f"MISP events/add respondió {r.status_code}: {r.text[:200]}")
        datos = r.json()
        ev = datos.get("Event", datos)
        return {"conectado": True, "evento_id": ev.get("id"),
                "url": f"{url}/events/view/{ev.get('id')}"}
    except RuntimeError as exc:
        return {"conectado": False, "error": str(exc)}
    except Exception as exc:
        return {"conectado": False, "error": f"MISP crear evento: {str(exc)[:220]}"}
