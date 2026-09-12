"""Envío REAL de correo SMTP para campañas de phishing autorizadas (F6).

Una campaña de phishing de red team autorizado se envía desde la
infraestructura de phishing del PROPIO equipo (servidor SMTP dedicado y
dominio de envío acordado en el ROE). Este módulo es el cliente SMTP
(stdlib) de esa infraestructura. El boundary exige aprobación humana del
envío SIEMPRE (cap. 4.8) y el ROE acota destinatarios y pretextos.

Configuración (variables de entorno del backend):
  SMTP_HOST       servidor SMTP de la infra de phishing del equipo
  SMTP_PUERTO     por defecto 587 (submission con STARTTLS)
  SMTP_USUARIO    usuario SMTP
  SMTP_CLAVE      contraseña SMTP
  SMTP_REMITENTE  dirección de envío acordada con el cliente
  SMTP_TLS        "1" obliga STARTTLS (por defecto) — "0" lo desactiva
  SMTP_TLS_SIN_VERIFICAR  "1" desactiva la verificación del certificado en
                  STARTTLS (solo labs autofirmados); por defecto se verifica

Sin infraestructura SMTP configurada, el envío queda documentado como
requisito: la plataforma nunca simula entregas ni métricas de apertura.
Las métricas reales (entregas, clics) provienen del propio servidor de
phishing del equipo; esta plataforma no fabrica cifras.
"""
from __future__ import annotations

import os
import re
from typing import Any

# z3 (auditoría sesión 5, F33): dirección email EXIGIBLE. La cabecera "To"
# se construye con ", ".join(destinatarios): una entrada con CRLF (o con
# estructura de cabecera tipo "a@b.com, Bcc: victima@x") no debe llegar
# JAMÁS a EmailMessage. Python moderno neutraliza parte del riesgo al
# serializar, pero la política aquí es defense-in-depth explícita: el ROE
# acota los destinatarios y la API solo debe aceptar direcciones válidas.
_RE_DIRECCION = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"       # local-part rfc5322 (práctico)
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"  # label del dominio
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$")  # + tld


def _config() -> dict[str, Any]:
    host = os.environ.get("SMTP_HOST", "")
    usuario = os.environ.get("SMTP_USUARIO", "")
    clave = os.environ.get("SMTP_CLAVE", "")
    remitente = os.environ.get("SMTP_REMITENTE", "")
    if not (host and usuario and clave and remitente):
        raise RuntimeError(
            "SMTP no configurado: defina SMTP_HOST, SMTP_USUARIO, SMTP_CLAVE "
            "y SMTP_REMITENTE con la infraestructura de phishing del equipo "
            "acordada en el ROE.")
    return {"host": host, "puerto": int(os.environ.get("SMTP_PUERTO", "587")),
            "usuario": usuario, "clave": clave, "remitente": remitente,
            "tls": os.environ.get("SMTP_TLS", "1") == "1"}


def _validar_destinatarios(destinatarios: list[str]) -> tuple[list[str], list[str]]:
    """z3 (sesión 5, F33): separa direcciones válidas de inválidas.

    Rechaza: vacías, con CRLF/ángulos/comas (inyección de cabecera o
    lista embebida) y sin formato email verificable. Devuelve
    (validas, invalidas) para poder informar sin enviar NADA si hay
    alguna inválida: una campaña de phishing autorizada no admite
    "envía los buenos y descarta los malos en silencio".
    """
    validas: list[str] = []
    invalidas: list[str] = []
    for d in destinatarios:
        limpio = (d or "").strip()
        if not limpio or _RE_DIRECCION.fullmatch(limpio) is None:
            invalidas.append((d or "")[:80])
            continue
        validas.append(limpio)
    return validas, invalidas


def _asunto_seguro(asunto: str | None) -> str:
    """z3 (sesión 5, F33): el asunto viaja en UNA cabecera — CR/LF fuera
    (colapsados a espacio) para que un asunto hostil no fabrique cabeceras."""
    return " ".join(str(asunto or "").splitlines())


def enviar(destinatarios: list[str], asunto: str, cuerpo: str,
           html: bool = True) -> dict[str, Any]:
    """Envío SMTP real a los destinatarios autorizados en la aprobación."""
    if not destinatarios:
        return {"enviado": False, "error": "lista de destinatarios vacía"}
    # z3 (sesión 5, F33): validación ANTES de cualquier I/O — sin lista
    # válida íntegra no hay conexión SMTP ni envío parcial.
    validas, invalidas = _validar_destinatarios(destinatarios)
    if invalidas:
        return {"enviado": False,
                "error": ("destinatarios inválidos (se exige dirección email "
                          f"válida, sin cabeceras embebidas): {invalidas[:3]}")}
    # El asunto viaja en una cabecera: CR/LF fuera (falsos encabezados).
    asunto = _asunto_seguro(asunto)
    try:
        import smtplib
        from email.message import EmailMessage
        cfg = _config()
        mensaje = EmailMessage()
        mensaje["From"] = cfg["remitente"]
        mensaje["To"] = ", ".join(validas)
        mensaje["Subject"] = asunto
        if html:
            mensaje.set_content("Active HTML para ver esta campaña.")
            mensaje.add_alternative(cuerpo, subtype="html")
        else:
            mensaje.set_content(cuerpo)
        with smtplib.SMTP(cfg["host"], cfg["puerto"], timeout=25) as smtp:
            if cfg["tls"]:
                # z3 (auditoría seguridad): STARTTLS SIN contexto explícito no
                # verifica el certificado del servidor — un MITM activo podría
                # interceptar SMTP_CLAVE y el contenido de la campaña. Se
                # verifica por defecto; SMTP_TLS_SIN_VERIFICAR=1 solo en labs.
                import ssl as _ssl
                if os.environ.get("SMTP_TLS_SIN_VERIFICAR", "") == "1":
                    ctx = _ssl._create_unverified_context()  # noqa: SLF001 - escape documentado
                else:
                    ctx = _ssl.create_default_context()
                smtp.starttls(context=ctx)
            smtp.login(cfg["usuario"], cfg["clave"])
            rechazados = smtp.send_message(mensaje)
        return {"enviado": True, "total": len(validas),
                "remitente": cfg["remitente"],
                "rechazados": list(rechazados or {}),
                "nota": "entrega gestionada por el servidor SMTP del equipo; "
                        "las métricas de la campaña provienen de su registro real"}
    except RuntimeError as exc:
        return {"enviado": False, "error": str(exc)}
    except Exception as exc:
        return {"enviado": False, "error": f"SMTP: {str(exc)[:220]}"}


def estado() -> dict[str, Any]:
    """Estado de la configuración SMTP (sin secretos)."""
    try:
        cfg = _config()
        return {"configurado": True, "host": cfg["host"], "puerto": cfg["puerto"],
                "remitente": cfg["remitente"], "tls": cfg["tls"]}
    except RuntimeError as exc:
        return {"configurado": False, "error": str(exc)}
