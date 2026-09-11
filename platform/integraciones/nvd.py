"""Enriquecimiento CVE REAL contra la API pública 2.0 del NVD (NIST).

Complemento de intel del laboratorio: cuando no hay MISP en el despliegue
(exige Docker; el conector oficial `integraciones.misp` sigue listo para la
instancia real del operador), los hallazgos con software/versiones pueden
contrastarse contra el NVD — la base de vulnerabilidades autoritativa.

  enriquecer(texto)  → CVEs REALES coincidentes (id, CVSS, descripción)
  estado()           → conectividad real con services.nvd.nist.gov

Protocolo (documentación oficial NVD API 2.0):
  GET https://services.nvd.nist.gov/rest/json/cves/2.0
      ?keywordSearch=<texto>&resultsPerPage=<n>
  (sin clave: 5 peticiones/30 s — el módulo respeta ese techo)

Honestidad: los CVEs devueltos son los que el NVD responde; si el texto no
produce coincidencias, se informa 0 coincidencias — nunca se rellena.
"""
from __future__ import annotations

import os
import re
import time
from typing import Any

_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_PATRON_VERSION = re.compile(
    r"\b([a-z][a-z0-9+#._-]{2,30})\s+v?(\d+\.\d+(?:\.\d+)?(?:p\d+)?)\b",
    re.IGNORECASE)

# Techo de cortesía: la API sin clave permite 5 req / 30 s por IP.
_ULTIMA_PETICION = 0.0
_INTERVALO_S = 7.0


def _esperar_turno() -> None:
    global _ULTIMA_PETICION
    espera = _INTERVALO_S - (time.time() - _ULTIMA_PETICION)
    if espera > 0:
        time.sleep(min(espera, 10.0))
    _ULTIMA_PETICION = time.time()


def estado() -> dict[str, Any]:
    """Ping REAL al NVD (consulta mínima de 1 resultado)."""
    try:
        import httpx
        _esperar_turno()
        with httpx.Client(timeout=20) as c:
            r = c.get(_BASE, params={"resultsPerPage": 1})
        return {"conectado": r.status_code == 200,
                "servicio": "NVD API 2.0 (NIST)",
                "http": r.status_code,
                "error": None if r.status_code == 200 else
                         f"NVD respondió {r.status_code}"}
    except Exception as exc:
        return {"conectado": False, "http": 0,
                "error": f"NVD: {str(exc)[:220]}"}


def _extraer_productos(texto: str) -> list[str]:
    """Candidatos de búsqueda: 'apache 2.4.49' → 'apache 2.4.49'."""
    vistos, candidatos = set(), []
    for producto, version in _PATRON_VERSION.findall(texto or ""):
        consulta = f"{producto} {version}".lower()
        if consulta not in vistos:
            vistos.add(consulta)
            candidatos.append(consulta)
        if len(candidatos) >= 3:  # techo anti-abuso de la API pública
            break
    return candidatos


def enriquecer(texto: str, resultados_por_consulta: int = 5) -> dict[str, Any]:
    """Busca CVEs REALES del NVD para los productos/versiones del texto.

    Devuelve coincidencias con su severidad CVSS real y estado del NVD.
    """
    productos = _extraer_productos(texto)
    if not productos:
        return {"conectado": False,
                "error": "El texto no contiene productos con versión "
                         "reconocibles (p. ej. 'Apache 2.4.49', "
                         "'OpenSSH 8.2p1')"}
    import httpx
    coincidencias: list[dict[str, Any]] = []
    consultas: list[dict[str, Any]] = []
    try:
        with httpx.Client(timeout=25) as c:
            for producto in productos:
                _esperar_turno()
                r = c.get(_BASE, params={
                    "keywordSearch": producto,
                    "resultsPerPage": int(resultados_por_consulta)})
                consultas.append({"consulta": producto, "http": r.status_code})
                if r.status_code != 200:
                    continue
                for item in (r.json().get("vulnerabilities") or [])[:5]:
                    cve = item.get("cve", {})
                    metricas = (cve.get("metrics") or {})
                    severidad, vector, base = None, None, None
                    for clave in ("cvssMetricV31", "cvssMetricV30",
                                  "cvssMetricV2"):
                        if metricas.get(clave):
                            m = metricas[clave][0].get("cvssData", {})
                            base = m.get("baseScore")
                            vector = m.get("vectorString")
                            severidad = (metricas[clave][0].get(
                                "baseSeverity")
                                         or m.get("baseSeverity"))
                            break
                    coincidencias.append({
                        "cve": cve.get("id"),
                        "publicado": cve.get("published", "")[:10],
                        "severidad": severidad,
                        "cvss_base": base,
                        "vector": vector,
                        "descripcion": ((cve.get("descriptions") or
                                         [{}])[0].get("value") or "")[:280],
                        "consulta": producto,
                    })
        # Dedup por CVE (el mismo CVE puede salir en dos consultas)
        vistos, unicos = set(), []
        for x in coincidencias:
            if x["cve"] and x["cve"] not in vistos:
                vistos.add(x["cve"])
                unicos.append(x)
        return {"conectado": True, "servicio": "NVD API 2.0 (NIST)",
                "consultas": consultas, "coincidencias": unicos,
                "total": len(unicos),
                "nota": "CVEs tal como los publica el NVD; sin MISP en el "
                        "despliegue, esta es la intel complementaria real "
                        "disponible en el laboratorio"}
    except RuntimeError as exc:
        return {"conectado": False, "error": str(exc)}
    except Exception as exc:
        return {"conectado": False, "error": f"NVD enriquecer: {str(exc)[:220]}"}
