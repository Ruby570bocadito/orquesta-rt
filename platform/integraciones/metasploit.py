"""Cliente REAL del MSG-RPC oficial de Metasploit Framework.

Metasploit expone su API de operador vía MSG-RPC: msgpack sobre HTTP POST
a `/api/1.1/` (msfrpcd) o vía msfdb (msgrpc). Protocolo estable desde
MSF 4.x y documentado por Rapid7. Implementación directa con msgpack +
httpx, sin dependencias intermedias.

Configuración (variables de entorno del backend):
  MSF_HOST    host de msfrpcd (por defecto 127.0.0.1)
  MSF_PORT    puerto RPC (por defecto 55553)
  MSF_SSL     "1" si msfrpcd corre con TLS
  MSF_TLS_VERIFICAR  "1" (por defecto) verifica el certificado TLS del RPC;
              "0" desactiva la verificación (solo labs con autofirmado)
  MSF_USER    usuario RPC (`msfrpcd -U ...`)
  MSF_PASS    contraseña RPC

Operaciones reales implementadas:
  estado()          → auth + core.version + session.list
  ejecutar_modulo() → module.execute (exploit/auxiliar) sobre el objetivo
  tarea_sesion()    → session.shell_write / meterpreter_write
  retirar_sesion()  → session.stop
"""
from __future__ import annotations

import os
from typing import Any


class RpcMsf:
    """Sesión MSG-RPC con Metasploit: login real y token de sesión."""

    def __init__(self) -> None:
        self.host = os.environ.get("MSF_HOST", "127.0.0.1")
        self.puerto = int(os.environ.get("MSF_PORT", "55553"))
        self.ssl = os.environ.get("MSF_SSL", "") == "1"
        # Verificación TLS por defecto (patrón MISP): por este canal viajan
        # MSF_USER/MSF_PASS y el token RPC. msfrpcd emite un certificado
        # autofirmado: para despliegues con PKI propia o proxy TLS, el
        # opt-out explícito es MSF_TLS_VERIFICAR=0 (jamás silencioso).
        self.verificar_tls = os.environ.get("MSF_TLS_VERIFICAR", "1") != "0"
        self.usuario = os.environ.get("MSF_USER", "")
        self.clave = os.environ.get("MSF_PASS", "")
        # z3 (auditoría seguridad): el RPC transporta el login y el token de
        # sesión de msfrpcd. La verificación del certificado es POR DEFECTO;
        # MSF_TLS_VERIFICAR=0 la desactiva conscientemente (labs autofirmados).
        self.verificar_tls = os.environ.get("MSF_TLS_VERIFICAR", "1") != "0"
        if not self.usuario or not self.clave:
            raise RuntimeError(
                "Metasploit RPC no configurado: defina MSF_HOST, MSF_PORT, "
                "MSF_USER y MSF_PASS. Lance msfrpcd en su infraestructura: "
                "`msfrpcd -U usuario -P clave -S`.")
        esquema = "https" if self.ssl else "http"
        self.url = f"{esquema}://{self.host}:{self.puerto}/api/1.1/"
        self._token: str | None = None

    def _llamar(self, metodo: str, *args: Any) -> Any:
        import httpx
        import msgpack
        if self._token is None:
            self._login()
        mensaje = msgpack.packb([self._token, metodo, *args], use_bin_type=True)
        with httpx.Client(timeout=60, verify=self.verificar_tls) as c:
            r = c.post(self.url, content=mensaje,
                       headers={"Content-Type": "binary/message-pack"})
        r.raise_for_status()
        return msgpack.unpackb(r.content, strict_map_key=False)

    def _login(self) -> None:
        import httpx
        import msgpack
        mensaje = msgpack.packb(
            ["msg", "auth.login", self.usuario, self.clave], use_bin_type=True)
        with httpx.Client(timeout=20, verify=self.verificar_tls) as c:
            r = c.post(self.url, content=mensaje,
                       headers={"Content-Type": "binary/message-pack"})
        r.raise_for_status()
        respuesta = msgpack.unpackb(r.content, strict_map_key=False)
        if isinstance(respuesta, dict) and respuesta.get("token"):
            self._token = str(respuesta["token"])
        elif isinstance(respuesta, list) and len(respuesta) > 1 and respuesta[1]:
            self._token = str(respuesta[1].get("token", ""))
        if not self._token:
            raise RuntimeError(
                f"auth.login de Metasploit RPC falló: {str(respuesta)[:160]}")

    # -- operaciones oficiales -------------------------------------------------

    def version(self) -> dict[str, Any]:
        return dict(self._llamar("core.version") or {})

    def sesiones(self) -> dict[str, Any]:
        return dict(self._llamar("session.list") or {})

    def ejecutar_modulo(self, tipo: str, nombre: str,
                        opciones: dict[str, Any]) -> dict[str, Any]:
        """module.execute REAL: lanza exploit/auxiliar en la infra MSF."""
        return dict(self._llamar("module.execute", tipo, nombre, opciones) or {})

    def escribir_sesion(self, sesion_id: int, comando: str) -> dict[str, Any]:
        tipo = self.sesiones().get(str(sesion_id), {}).get("type", "shell")
        metodo = ("session.meterpreter_write" if "meterpreter" in tipo
                  else "session.shell_write")
        self._llamar(metodo, int(sesion_id), comando)
        return {"enviado": True, "metodo": metodo, "sesion": sesion_id,
                "comando": comando}

    def leer_sesion(self, sesion_id: int) -> dict[str, Any]:
        datos = self._llamar("session.shell_read", int(sesion_id))
        if isinstance(datos, dict) and "data" in datos:
            try:
                datos["salida"] = bytes(datos["data"]).decode("utf-8", "replace")
            except Exception:
                datos["salida"] = str(datos["data"])[:2000]
        return datos

    def detener_sesion(self, sesion_id: int) -> dict[str, Any]:
        return dict(self._llamar("session.stop", int(sesion_id)) or {})


def _con_rpc():
    """Devuelve una sesión RPC ya autenticada (lanza requisito si falta)."""
    return RpcMsf()


def estado() -> dict[str, Any]:
    """Versión de Metasploit y sesiones REALES del operador."""
    try:
        rpc = _con_rpc()
        return {"conectado": True,
                "framework": "Metasploit (MSG-RPC oficial)",
                "version": rpc.version(),
                "sesiones": rpc.sesiones()}
    except RuntimeError as exc:
        return {"conectado": False, "error": str(exc)}
    except Exception as exc:
        return {"conectado": False, "error": f"Metasploit RPC: {str(exc)[:220]}"}


def ejecutar_modulo(tipo: str, nombre: str, opciones: dict[str, Any]) -> dict[str, Any]:
    """Ejecuta un módulo REAL de Metasploit (exploit o auxiliar).

    El operador es responsable de que el módulo y el objetivo estén
    autorizados en el ROE: el boundary del orquestador exige aprobación
    humana para cualquier module.execute.
    """
    try:
        rpc = _con_rpc()
        resultado = rpc.ejecutar_modulo(tipo, nombre, opciones)
        job_id = resultado.get("job_id")
        salida: dict[str, Any] = {"conectado": True, "modulo": nombre,
                                  "uuid": resultado.get("uuid", ""),
                                  "job_id": job_id}
        if job_id is None:
            # module.execute devolvió un error real del framework
            salida["error_msf"] = str(resultado.get("error", ""))[:300]
        return salida
    except RuntimeError as exc:
        return {"conectado": False, "error": str(exc)}
    except Exception as exc:
        return {"conectado": False, "error": f"MSF module.execute: {str(exc)[:220]}"}


def tarea_sesion(sesion_id: int, comando: str) -> dict[str, Any]:
    """Escribe un comando REAL en una sesión shell/meterpreter."""
    try:
        rpc = _con_rpc()
        envio = rpc.escribir_sesion(sesion_id, comando)
        lectura = rpc.leer_sesion(sesion_id)
        return {"conectado": True, **envio, "salida": lectura.get("salida", "")[:8000]}
    except RuntimeError as exc:
        return {"conectado": False, "error": str(exc)}
    except Exception as exc:
        return {"conectado": False, "error": f"MSF sesión: {str(exc)[:220]}"}


def retirar_sesion(sesion_id: int) -> dict[str, Any]:
    """Detiene una sesión REAL (higiene de cierre)."""
    try:
        rpc = _con_rpc()
        rpc.detener_sesion(sesion_id)
        return {"conectado": True, "retirada": sesion_id}
    except RuntimeError as exc:
        return {"conectado": False, "error": str(exc)}
    except Exception as exc:
        return {"conectado": False, "error": f"MSF stop: {str(exc)[:220]}"}
