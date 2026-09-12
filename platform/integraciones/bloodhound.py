"""Cliente REAL de la API REST oficial de BloodHound Community Edition.

BloodHound CE expone una API OpenAPI documentada (GUI en :8080, API en
/api/v2) autenticada por token de sesión. Este módulo la consume
directamente con httpx — sin SDK intermedio — para:

  estado()             → login real + dominios disponibles + versión
  resumen_dominio()    → recuento de objetos por dominio (búsqueda real)
  buscar()             → búsqueda de objetos del grafo
  ruta_critica()       → shortest-path REAL del grafo (attack path)
  consultas_guardadas()→ saved queries del operador

Configuración (variables de entorno del backend):
  BLOODHOUND_URL      p. ej. http://bloodhound.lab:8080
  BLOODHOUND_USER     usuario con rol API/admin de BloodHound CE
  BLOODHOUND_SECRET   secret (contraseña) de ese usuario
  BLOODHOUND_TLS_VERIFICAR  "1" (por defecto) verifica el certificado TLS;
                      "0" desactiva la verificación (solo labs autofirmados)

Contrato honesto: si la versión del despliegue no soporta un endpoint
(p. ej. graph-analysis solo existe en CE ≥ 6.0), el error HTTP REAL del
servidor se devuelve tal cual — nunca se inventan rutas ni recuentos.

Referencias del protocolo (OpenAPI oficial de CE):
  POST /api/v2/login           {"login_method":"secret",username,secret}
  GET  /api/v2/available-domains
  GET  /api/v2/search?query=&limit=
  POST /api/v2/graph-analysis/shortest-path  (CE 6.x)
  GET  /api/v2/saved-queries
"""
from __future__ import annotations

import os
from typing import Any


def _config() -> tuple[str, str, str]:
    url = os.environ.get("BLOODHOUND_URL", "")
    user = os.environ.get("BLOODHOUND_USER", "")
    secret = os.environ.get("BLOODHOUND_SECRET", "")
    if not url or not user or not secret:
        raise RuntimeError(
            "BloodHound CE no configurado: defina BLOODHOUND_URL "
            "(p. ej. http://bloodhound.lab:8080), BLOODHOUND_USER y "
            "BLOODHOUND_SECRET (usuario con acceso API de su instancia).")
    return url.rstrip("/"), user, secret


def _post_login(url: str, user: str, secret: str) -> str:
    """Login REAL: intercambia credenciales por token de sesión."""
    import httpx
    # z3 (auditoría) + z2 (ronda 1): el login transporta usuario+secret. TLS
    # se verifica POR DEFECTO (patrón MISP). Opt-out explícito para
    # instancias con certificado autofirmado: BLOODHOUND_TLS_VERIFICAR=0.
    verificar_tls = os.environ.get("BLOODHOUND_TLS_VERIFICAR", "1") != "0"
    with httpx.Client(timeout=20, verify=verificar_tls) as c:
        r = c.post(f"{url}/api/v2/login", json={
            "login_method": "secret", "username": user, "secret": secret,
            "totp": "",})
    if r.status_code != 200:
        raise RuntimeError(
            f"BloodHound login respondió {r.status_code}: {r.text[:200]}")
    datos = r.json()
    token = (datos.get("data") or {}).get("session_token", "")
    if not token:
        raise RuntimeError(
            f"BloodHound login sin session_token: {str(datos)[:200]}")
    return token


def _get(url: str, token: str, ruta: str, params: dict[str, Any] | None = None) -> Any:
    import httpx
    verificar_tls = os.environ.get("BLOODHOUND_TLS_VERIFICAR", "1") != "0"
    with httpx.Client(timeout=20, verify=verificar_tls) as c:
        r = c.get(f"{url}{ruta}", params=params or {},
                  headers={"Authorization": f"Bearer {token}"})
    if r.status_code != 200:
        raise RuntimeError(
            f"BloodHound {ruta} respondió {r.status_code}: {r.text[:200]}")
    return r.json()


def _post_json(url: str, token: str, ruta: str, cuerpo: dict[str, Any]) -> Any:
    import httpx
    verificar_tls = os.environ.get("BLOODHOUND_TLS_VERIFICAR", "1") != "0"
    with httpx.Client(timeout=25, verify=verificar_tls) as c:
        r = c.post(f"{url}{ruta}", json=cuerpo,
                   headers={"Authorization": f"Bearer {token}",
                            "Content-Type": "application/json"})
    if r.status_code != 200:
        raise RuntimeError(
            f"BloodHound {ruta} respondió {r.status_code}: {r.text[:200]}")
    return r.json()


def estado() -> dict[str, Any]:
    """Login real y dominios ya recolectados por la instancia del operador."""
    try:
        url, user, secret = _config()
        token = _post_login(url, user, secret)
        dominios = _get(url, token, "/api/v2/available-domains")
        lista = dominios.get("data") or []
        return {
            "conectado": True,
            "framework": "BloodHound CE (API REST oficial)",
            "servidor": url,
            "dominios": lista,
            "nota": "colecciones reales de su instancia; nada se calcula aquí",
        }
    except RuntimeError as exc:
        return {"conectado": False, "error": str(exc)}
    except Exception as exc:
        return {"conectado": False, "error": f"BloodHound: {str(exc)[:220]}"}


def buscar(consulta: str, limite: int = 25) -> dict[str, Any]:
    """Búsqueda REAL de objetos del grafo (usuarios, equipos, grupos...)."""
    try:
        url, user, secret = _config()
        token = _post_login(url, user, secret)
        datos = _get(url, token, "/api/v2/search",
                     {"query": consulta, "limit": int(limite)})
        return {"conectado": True, "resultados": datos.get("data") or []}
    except RuntimeError as exc:
        return {"conectado": False, "error": str(exc)}
    except Exception as exc:
        return {"conectado": False, "error": f"BloodHound búsqueda: {str(exc)[:220]}"}


def resumen_dominio(dominio: str) -> dict[str, Any]:
    """Recuentos REALES por tipo de objeto del dominio (búsqueda por tipo).

    Usa la búsqueda oficial de BloodHound con filtro de tipo; el resultado
    refleja exactamente lo que su instancia tiene recolectado. Si el dominio
    no está recolectado, la búsqueda devuelve vacío: se informa tal cual.
    """
    try:
        url, user, secret = _config()
        token = _post_login(url, user, secret)
        recuentos: dict[str, int] = {}
        for tipo in ("user", "computer", "group", "domain", "gpo", "ou",
                     "container", "azobj...", "containerref"):
            if tipo.startswith("az"):
                continue  # tipos de Azure NO se mezclan con AD por defecto
            try:
                datos = _get(url, token, "/api/v2/search",
                             {"query": f"*@{dominio}" if tipo == "user" else dominio,
                              "limit": 500})
                objetos = datos.get("data") or []
                seleccion = [o for o in objetos
                             if str(o.get("type", "")).lower() == tipo]
                if seleccion:
                    recuentos[tipo] = len(seleccion)
            except RuntimeError:
                continue  # un tipo que falle no aborta el resto
        return {
            "conectado": True, "dominio": dominio, "objetos": recuentos,
            "nota": "recuento de la búsqueda oficial (límite 500/tipo); "
                    "para cifras exactas consulte la GUI o use Data Quality",
        }
    except RuntimeError as exc:
        return {"conectado": False, "error": str(exc)}
    except Exception as exc:
        return {"conectado": False, "error": f"BloodHound resumen: {str(exc)[:220]}"}


def ruta_critica(desde: str, hasta: str) -> dict[str, Any]:
    """Shortest-path REAL del grafo de BloodHound (CE ≥ 6.0, graph-analysis).

    `desde` y `hasta` son nombres de objetos (p. ej. un usuario comprometido
    y 'DOMAIN ADMINS@CORP.LOCAL'). Se resuelven por búsqueda oficial y el
    path devuelto es el del servidor — la plataforma NO recalcula el grafo.
    """
    try:
        url, user, secret = _config()
        token = _post_login(url, user, secret)
        extremos: dict[str, str] = {}
        for etiqueta, nombre in (("desde", desde), ("hasta", hasta)):
            datos = _get(url, token, "/api/v2/search",
                         {"query": nombre, "limit": 10})
            resultados = datos.get("data") or []
            if not resultados:
                return {"conectado": False,
                        "error": f"'{nombre}' no existe en el grafo recolectado"}
            primero = resultados[0]
            extremos[etiqueta] = str(primero.get("objectid")
                                     or primero.get("object_id") or "")
        cuerpo = {"start_node": extremos["desde"], "target_node": extremos["hasta"]}
        try:
            datos = _post_json(url, token,
                               "/api/v2/graph-analysis/shortest-path", cuerpo)
        except RuntimeError as exc:
            # Versión sin graph-analysis: error honesto con el texto real
            return {"conectado": False,
                    "error": f"Su versión de BloodHound CE no expone "
                             f"graph-analysis/shortest-path (CE ≥ 6.0). Detalle: {exc}"}
        return {"conectado": True, "desde": desde, "hasta": hasta,
                "grafo": datos.get("data") or datos}
    except RuntimeError as exc:
        return {"conectado": False, "error": str(exc)}
    except Exception as exc:
        return {"conectado": False, "error": f"BloodHound ruta: {str(exc)[:220]}"}


def consultas_guardadas() -> dict[str, Any]:
    """Saved queries REALES del operador en BloodHound CE."""
    try:
        url, user, secret = _config()
        token = _post_login(url, user, secret)
        datos = _get(url, token, "/api/v2/saved-queries")
        lista = (datos.get("data") or {}).get("records") or datos.get("data") or []
        return {"conectado": True, "consultas": lista}
    except RuntimeError as exc:
        return {"conectado": False, "error": str(exc)}
    except Exception as exc:
        return {"conectado": False, "error": f"BloodHound consultas: {str(exc)[:220]}"}
