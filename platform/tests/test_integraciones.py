"""Tests de integraciones REALES y transportes ampliados.

Principio: sin infraestructura del operador configurada, las integraciones
devuelven estados honestos (conectado=False + requisito), jamás datos
ficticios. Estos tests verifican ese contrato y la clasificación del
boundary para las nuevas herramientas.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from orchestrator.guardrails import MotorGuardrails  # noqa: E402
from integraciones import ldap, metasploit, mythic, sliver, smtp_envio  # noqa: E402
from orchestrator.models import Fase, ROEPolitica  # noqa: E402
from orchestrator.transportes import transportes_de  # noqa: E402


def _roe() -> ROEPolitica:
    return ROEPolitica(
        engagement_id="test_int", cliente="ACME",
        alcance_dominios=["acme.com"], alcance_cidrs=["10.20.0.0/16"],
        alcance_excluido=["panel.acme.com"])


# ---------------------------------------------------------------------------
# 1) Integraciones sin configurar: honestidad, no simulación
# ---------------------------------------------------------------------------


def test_sliver_sin_configuracion_es_honesto(monkeypatch) -> None:
    for clave in ("SLIVER_CONFIG", "SLIVER_HOST", "SLIVER_TOKEN"):
        monkeypatch.delenv(clave, raising=False)
    estado = sliver.estado()
    assert estado["conectado"] is False
    # Requisito honesto: configuración ausente o dependencia oficial sin instalar
    mensaje = estado["error"]
    assert any(m in mensaje for m in ("SLIVER_CONFIG", "SLIVER_HOST", "sliver-py"))


def test_mythic_sin_configuracion_es_honesto(monkeypatch) -> None:
    monkeypatch.delenv("MYTHIC_URL", raising=False)
    monkeypatch.delenv("MYTHIC_TOKEN", raising=False)
    estado = mythic.estado()
    assert estado["conectado"] is False
    assert "MYTHIC_URL" in estado["error"] and "MYTHIC_TOKEN" in estado["error"]


def test_msf_sin_configuracion_es_honesto(monkeypatch) -> None:
    for clave in ("MSF_HOST", "MSF_USER", "MSF_PASS"):
        monkeypatch.delenv(clave, raising=False)
    estado = metasploit.estado()
    assert estado["conectado"] is False
    assert "MSF_HOST" in estado["error"]


def test_ldap_sin_configuracion_es_honesto(monkeypatch) -> None:
    for clave in ("LDAP_HOST", "LDAP_BIND_DN", "LDAP_BIND_CLAVE", "LDAP_BASE_DN"):
        monkeypatch.delenv(clave, raising=False)
    estado = ldap.enumerar("resumen")
    assert estado["conectado"] is False
    assert "LDAP_HOST" in estado["error"]


def test_smtp_sin_configuracion_es_honesto(monkeypatch) -> None:
    for clave in ("SMTP_HOST", "SMTP_USUARIO", "SMTP_CLAVE", "SMTP_REMITENTE"):
        monkeypatch.delenv(clave, raising=False)
    estado = smtp_envio.estado()
    assert estado["configurado"] is False


def test_explotar_sin_adaptador_no_simula_exito() -> None:
    t = transportes_de(_roe())
    resultado = t["explotar.ejecutar"](modulo="exploit/multi/http/test")
    assert resultado["exito"] is False
    assert "sin adaptador" in resultado["error"]


# ---------------------------------------------------------------------------
# 2) Transportes nuevos: alcance y defensa en profundidad
# ---------------------------------------------------------------------------


def test_wayback_fuera_de_scope_denegado() -> None:
    t = transportes_de(_roe())
    r = t["osint.wayback"](dominio="otro-dominio.net")
    assert "error" in r and "fuera de alcance" in r["error"]


def test_banner_grab_fuera_de_scope_denegado() -> None:
    t = transportes_de(_roe())
    r = t["recon.banner_grab"](host="10.99.99.99")
    assert "error" in r


def test_banner_grab_rechaza_puertos_fuera_de_lista_blanca() -> None:
    t = transportes_de(_roe())
    r = t["recon.banner_grab"](host="10.20.1.1", puertos="9999,12345")
    assert r["banners"] == []  # nada fuera de la lista blanca


def test_explotar_rhosts_fuera_de_roe_bloqueado(monkeypatch) -> None:
    monkeypatch.setenv("MSF_HOST", "127.0.0.1")
    monkeypatch.setenv("MSF_USER", "u")
    monkeypatch.setenv("MSF_PASS", "p")
    t = transportes_de(_roe())
    r = t["explotar.ejecutar"](modulo="exploit/multi/http/x",
                               opciones={"RHOSTS": "172.16.5.5"})
    assert r["exito"] is False
    assert "fuera del alcance" in r["error"]


def test_explotar_modulo_invalido(monkeypatch) -> None:
    for clave in ("MSF_HOST", "MSF_USER", "MSF_PASS"):
        monkeypatch.delenv(clave, raising=False)
    t = transportes_de(_roe())
    r = t["explotar.ejecutar"](modulo="no-es-un-modulo")
    assert r["exito"] is False
    # Honestidad: sin adaptador se reporta el requisito; con adaptador, el
    # nombre inválido. Jamás un éxito simulado.
    assert "sin adaptador" in r["error"] or "no válido" in r["error"]


# ---------------------------------------------------------------------------
# 3) Boundary: clasificación de las nuevas herramientas
# ---------------------------------------------------------------------------


def test_boundary_c2_estado_sin_aprobacion() -> None:
    motor = MotorGuardrails(_roe())
    v = motor.evaluar("c2.estado", {}, Fase.F5_C2)
    assert v.permitido


def test_boundary_c2_tarea_exige_firma() -> None:
    import datetime as _dt
    motor = MotorGuardrails(_roe())
    # Reloj inyectado dentro de la ventana 08:00-20:00 (determinista)
    momento = _dt.datetime(2026, 1, 5, 10, 30)  # lunes 10:30
    v = motor.evaluar("c2.sliver_tarea", {"sesion_id": 1, "comando": "whoami"},
                      Fase.F5_C2, momento=momento)
    assert v.decision.value == "requiere_aprobacion"
    v2 = motor.evaluar("c2.mythic_tarea", {"callback_id": 3, "comando": "ps"},
                       Fase.F5_C2, momento=momento)
    assert v2.decision.value == "requiere_aprobacion"


def test_boundary_wayback_permiso_bajo() -> None:
    motor = MotorGuardrails(_roe())
    v = motor.evaluar("osint.wayback", {"dominio": "acme.com"}, Fase.F1_OSINT)
    assert v.permitido


def test_boundary_envio_campana_exige_firma() -> None:
    motor = MotorGuardrails(_roe())
    v = motor.evaluar("phishing.enviar_campana",
                      {"destinatarios": ["a@acme.com"], "asunto": "t", "cuerpo": "c"},
                      Fase.F6_PHISHING)
    assert v.decision.value == "requiere_aprobacion"


def test_boundary_enumerar_ldap_en_ventana() -> None:
    import datetime as _dt
    motor = MotorGuardrails(_roe())
    # Reloj inyectado dentro de la ventana 08:00-20:00: resultado determinista
    momento = _dt.datetime(2026, 1, 5, 10, 30)  # lunes 10:30
    v = motor.evaluar("ad.enumerar_ldap", {"tipo": "spns"}, Fase.F4_DOMINIO,
                      momento=momento)
    assert v.permitido
    # Y fuera de ventana se deniega con motivo explícito
    fuera = _dt.datetime(2026, 1, 5, 22, 30)  # lunes 22:30
    v2 = motor.evaluar("ad.enumerar_ldap", {"tipo": "grupos"}, Fase.F4_DOMINIO,
                       momento=fuera)
    assert v2.denegado and "ventana horaria" in v2.motivo


def test_transportes_registrados_completos() -> None:
    t = transportes_de(_roe())
    esperadas = {"osint.wayback", "recon.banner_grab", "recon.reverse_dns",
                 "recon.http_methods", "recon.dir_index", "c2.estado",
                 "c2.sliver_tarea", "c2.mythic_tarea", "c2.msf_tarea",
                 "explotar.ejecutar", "phishing.enviar_campana"}
    assert esperadas <= set(t)


# ---------------------------------------------------------------------------
# 4) Transportes v6: AXFR y nmap (reales, honestos, acotados)
# ---------------------------------------------------------------------------


def test_zone_transfer_fuera_de_scope_denegado() -> None:
    t = transportes_de(_roe())
    r = t["osint.zone_transfer"](dominio="otro-dominio.net")
    assert "error" in r and "fuera de alcance" in r["error"]


def test_zone_transfer_resolucion_fallida_honesta() -> None:
    """Dominio del lab sin NS real: error real de resolución, nunca éxito fingido."""
    import dns.resolver  # noqa: F401  (si falta dnspython, el test es irrelevante)
    t = transportes_de(_roe())
    r = t["osint.zone_transfer"](dominio="sub.acme.com")
    assert "vulnerable" in r or "error" in r
    if "error" not in r:
        assert r["vulnerable"] is False and r["transferidas"] == {}


def test_nmap_sin_binario_es_honesto() -> None:
    import shutil
    t = transportes_de(_roe())
    r = t["recon.nmap_servicios"](host="10.20.1.1")
    if shutil.which("nmap"):
        assert "servicios" in r  # con nmap instalado: ejecución real
    else:
        assert "nmap no está instalado" in r["error"]
        assert r["servicios"] == []


def test_boundary_nmap_y_axfr_clasificados() -> None:
    import datetime as _dt
    momento = _dt.datetime(2026, 1, 5, 10, 30)  # lunes 10:30 (dentro de ventana)
    motor = MotorGuardrails(_roe())
    v_axfr = motor.evaluar("osint.zone_transfer", {"dominio": "acme.com"},
                           Fase.F1_OSINT, momento=momento)
    assert v_axfr.permitido  # pasivo-ligero: permiso directo
    v_nmap = motor.evaluar("recon.nmap_servicios", {"host": "10.20.1.1"},
                           Fase.F2_RECON, momento=momento)
    assert v_nmap.permitido  # media riesgo + ventana: permitido en horario
    fuera = _dt.datetime(2026, 1, 5, 22, 30)
    v_nmap2 = motor.evaluar("recon.nmap_servicios", {"host": "10.20.1.1"},
                            Fase.F2_RECON, momento=fuera)
    assert v_nmap2.denegado  # fuera de ventana: denegado


def test_transportes_v6_registrados() -> None:
    t = transportes_de(_roe())
    assert {"osint.zone_transfer", "recon.nmap_servicios"} <= set(t)
