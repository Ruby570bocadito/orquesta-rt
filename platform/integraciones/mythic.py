"""Cliente REAL de la API GraphQL oficial de Mythic C2.

Mythic expone GraphQL autenticado por token (puerto por defecto 7443,
cabecera `MythicToken`). Este módulo usa ese API documentada directamente
con httpx — sin SDK intermedio — para:

  estado()      → callbacks activos
  tarea()       → creación de tarea (comando de agente) en un callback
  retirar()     → cierre (kill) de un callback
  payload()     → consulta de payloads registrados

Configuración (variables de entorno del backend):
  MYTHIC_URL      p. ej. https://mythic.server:7443
  MYTHIC_TOKEN    token del usuario API de Mythic (Mythic → Create Token)

Los errores de GraphQL se devuelven en "error" tal cual llegan: si una
versión de Mythic cambia un campo, el operador ve el mensaje real y no un
falso éxito.
"""
from __future__ import annotations

import os
from typing import Any

QUERY_CALLBACKS = """
query { callback(order_by: {id: desc}, limit: 100) {
  id host hostname user integrity description os display_ip
  external_ip last_checkin locked active } }
"""

QUERY_PAYLOADS = """
query { payload(order_by: {timestamp: desc}, limit: 20) {
  id uuid filemetum { filename } payloadtype { ptype } operator { username } } }
"""

MUTATION_CREAR_TAREA = """
mutation createTask($callback_display_id: Int!, $command: String!, $params: String) {
  createTask(callback_display_id: $callback_display_id,
             command: $command, params: $params) {
    id display_id status
  }
}
"""

MUTATION_KILL_CALLBACK = """
mutation killCallback($callback_display_id: Int!) {
  updateCallbackField(callback_display_id: $callback_display_id,
                      field: "locked", value: "true") { id }
}
"""


def _config() -> tuple[str, str]:
    url = os.environ.get("MYTHIC_URL", "")
    token = os.environ.get("MYTHIC_TOKEN", "")
    if not url or not token:
        raise RuntimeError(
            "Mythic no configurado: defina MYTHIC_URL (https://servidor:7443) "
            "y MYTHIC_TOKEN (token API generado en la consola de Mythic).")
    return url.rstrip("/"), token


def _gql(consulta: str, variables: dict[str, Any] | None = None) -> dict[str, Any]:
    """POST GraphQL autenticado a la API oficial de Mythic."""
    url, token = _config()
    import httpx
    with httpx.Client(timeout=20, verify=False) as c:
        r = c.post(f"{url}/graphql",
                   json={"query": consulta, "variables": variables or {}},
                   headers={"MythicToken": token,
                            "Content-Type": "application/json"})
    if r.status_code != 200:
        raise RuntimeError(f"Mythic respondió {r.status_code}: {r.text[:200]}")
    datos = r.json()
    if datos.get("errors"):
        raise RuntimeError(f"Mythic GraphQL: {datos['errors'][0].get('message', '')[:200]}")
    return datos.get("data", {})


def estado() -> dict[str, Any]:
    """Callbacks REALES registrados en el servidor Mythic del operador."""
    try:
        data = _gql(QUERY_CALLBACKS)
        callbacks = data.get("callback", [])
        return {"conectado": True,
                "framework": "Mythic (GraphQL oficial)",
                "callbacks": callbacks}
    except RuntimeError as exc:
        return {"conectado": False, "error": str(exc)}
    except Exception as exc:
        return {"conectado": False, "error": f"Mythic: {str(exc)[:220]}"}


def tarea(callback_id: int, comando: str, params: str = "") -> dict[str, Any]:
    """Crea una tarea REAL en un callback Mythic (comando del agente)."""
    try:
        data = _gql(MUTATION_CREAR_TAREA, {
            "callback_display_id": int(callback_id),
            "command": comando, "params": params})
        tarea_creada = data.get("createTask", {})
        return {"conectado": True, "tarea": tarea_creada,
                "nota": "tarea encolada en Mythic; consulte su consola para la respuesta del agente"}
    except RuntimeError as exc:
        return {"conectado": False, "error": str(exc)}
    except Exception as exc:
        return {"conectado": False, "error": f"Mythic tarea: {str(exc)[:220]}"}


def retirar(callback_id: int) -> dict[str, Any]:
    """Bloquea (lock) un callback REAL en Mythic para higiene de cierre."""
    try:
        data = _gql(MUTATION_KILL_CALLBACK, {"callback_display_id": int(callback_id)})
        return {"conectado": True, "retirada": data.get("updateCallbackField", {})}
    except RuntimeError as exc:
        return {"conectado": False, "error": str(exc)}
    except Exception as exc:
        return {"conectado": False, "error": f"Mythic retirar: {str(exc)[:220]}"}


def payloads() -> dict[str, Any]:
    """Payloads registrados en Mythic (producción del propio framework)."""
    try:
        data = _gql(QUERY_PAYLOADS)
        return {"conectado": True, "payloads": data.get("payload", [])}
    except RuntimeError as exc:
        return {"conectado": False, "error": str(exc)}
    except Exception as exc:
        return {"conectado": False, "error": f"Mythic payloads: {str(exc)[:220]}"}
