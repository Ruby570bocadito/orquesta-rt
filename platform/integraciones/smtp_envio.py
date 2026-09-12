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
from typing import Any


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


def enviar(destinatarios: list[str], asunto: str, cuerpo: str,
           html: bool = True) -> dict[str, Any]:
    """Envío SMTP real a los destinatarios autorizados en la aprobación."""
    if not destinatarios:
        return {"enviado": False, "error": "lista de destinatarios vacía"}
    try:
        import smtplib
        from email.message import EmailMessage
        cfg = _config()
        mensaje = EmailMessage()
        mensaje["From"] = cfg["remitente"]
        mensaje["To"] = ", ".join(destinatarios)
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
        return {"enviado": True, "total": len(destinatarios),
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
