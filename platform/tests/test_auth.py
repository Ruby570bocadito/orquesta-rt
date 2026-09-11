"""Tests de autenticación de operadores: cuentas reales, JWT y acceso.

Verifica el ciclo completo de identidad: alta bootstrap, scrypt, login,
JWT HS256 (firma + expiración), bloqueo anti fuerza bruta y la API
protegida deny-by-default (401 sin token, 200 con token, identidad real
en las decisiones de firma ROE).
"""
from __future__ import annotations

import os
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from orchestrator import auth  # noqa: E402


@pytest.fixture()
def almacen_tmp(tmp_path, monkeypatch):
    """Almacén de operadores aislado por test (USUARIOS_DB temporal)."""
    ruta = tmp_path / "usuarios_test.db"
    monkeypatch.setattr(auth, "RUTA_DB", ruta)
    # Estado limpio de intentos de login entre tests
    monkeypatch.setattr(auth, "_intentos", {})
    return ruta


# ---------------------------------------------------------------------------
# 1) Cuentas y contraseñas (scrypt)
# ---------------------------------------------------------------------------


def test_alta_y_credenciales_validas(almacen_tmp) -> None:
    assert not auth.hay_operadores()
    auth.crear_operador("ana.red", "ClaveSegura2026", rol="admin")
    assert auth.hay_operadores()
    sesion = auth.verificar_credenciales("ana.red", "ClaveSegura2026")
    assert sesion and sesion["usuario"] == "ana.red" and sesion["rol"] == "admin"


def test_credenciales_incorrectas_rechazadas(almacen_tmp) -> None:
    auth.crear_operador("bob", "ClaveSegura2026")
    assert auth.verificar_credenciales("bob", "incorrecta") is None
    assert auth.verificar_credenciales("no_existe", "loquesea1") is None


def test_hash_scrypt_no_guarda_claro(almacen_tmp) -> None:
    import sqlite3
    auth.crear_operador("carla", "ClaveSegura2026")
    conn = sqlite3.connect(str(almacen_tmp))
    fila = conn.execute("SELECT hash FROM operadores WHERE usuario='carla'").fetchone()
    conn.close()
    assert "ClaveSegura2026" not in fila[0]
    assert fila[0].startswith("scrypt$")


def test_contrasena_debil_rechazada(almacen_tmp) -> None:
    with pytest.raises(ValueError):
        auth.crear_operador("dani", "corta")


def test_usuario_duplicado_rechazado(almacen_tmp) -> None:
    auth.crear_operador("eva", "ClaveSegura2026")
    with pytest.raises(ValueError, match="ya existe"):
        auth.crear_operador("eva", "OtraClave2026x")


# v10: regla de usuario explícita — el guion (-) es válido (fricción real
# del alta: antes se rechazaba y producía un 400 incomprensible para el
# operador), y los formatos ambiguos se rechazan con mensaje claro.
def test_usuario_con_guion_aceptado(almacen_tmp) -> None:
    auth.crear_operador("ana-red", "ClaveSegura2026")
    assert auth.verificar_credenciales("ana-red", "ClaveSegura2026")


def test_usuario_formatos_invalidos_rechazados(almacen_tmp) -> None:
    for malo in ("ab", " con espacio", "con espacio", "ána", "a" * 33, ""):
        with pytest.raises(ValueError, match="Usuario inválido"):
            auth.crear_operador(malo, "ClaveSegura2026")


# ---------------------------------------------------------------------------
# 2) JWT HS256
# ---------------------------------------------------------------------------


def test_token_emision_y_verificacion(almacen_tmp) -> None:
    auth.crear_operador("fer", "ClaveSegura2026", rol="operador")
    tok = auth.emitir_token("fer", "operador")
    partes = tok["token"].split(".")
    assert len(partes) == 3  # header.payload.signature (RFC 7519)
    claims = auth.verificar_token(tok["token"])
    assert claims and claims["sub"] == "fer" and claims["rol"] == "operador"
    assert claims["exp"] > time.time()


def test_token_manipulado_rechazado(almacen_tmp) -> None:
    tok = auth.emitir_token("gil", "operador")
    cabecera, cuerpo, firma = tok["token"].split(".")
    # Cambia el payload sin refirmar: la firma deja de cuadrar
    cuerpo_falso = cuerpo[:-2] + ("AA" if cuerpo[-2:] != "AA" else "BB")
    assert auth.verificar_token(f"{cabecera}.{cuerpo_falso}.{firma}") is None
    assert auth.verificar_token("basura.no.es.un.token") is None


def test_token_expirado_rechazado(almacen_tmp, monkeypatch) -> None:
    tok = auth.emitir_token("hugo", "operador")
    # Congela el reloj después de la expiración
    exp = auth.verificar_token(tok["token"])["exp"]
    real_time = time.time
    monkeypatch.setattr(time, "time", lambda: exp + 10)
    try:
        assert auth.verificar_token(tok["token"]) is None
    finally:
        monkeypatch.setattr(time, "time", real_time)


def test_secreto_jwt_persiste_entre_llamadas(almacen_tmp) -> None:
    tok1 = auth.emitir_token("ire", "operador")
    tok2 = auth.emitir_token("ire", "operador")  # otra llamada, misma BD
    assert auth.verificar_token(tok1["token"]) is not None
    assert auth.verificar_token(tok2["token"]) is not None


# ---------------------------------------------------------------------------
# 3) Bloqueo anti fuerza bruta
# ---------------------------------------------------------------------------


def test_bloqueo_tras_fallos_repetidos(almacen_tmp) -> None:
    auth.crear_operador("joa", "ClaveSegura2026")
    for _ in range(auth.MAX_FALLOS):
        assert auth.verificar_credenciales("joa", "malaclave") is None
    # Bloqueado aunque la contraseña sea correcta ahora
    with pytest.raises(ValueError, match="bloqueada"):
        auth.verificar_credenciales("joa", "ClaveSegura2026")


def test_cambiar_contrasena_exige_la_actual(almacen_tmp) -> None:
    auth.crear_operador("kira", "ClaveSegura2026")
    assert not auth.cambiar_contrasena("kira", "malaactual", "NuevaClave2026")
    assert auth.cambiar_contrasena("kira", "ClaveSegura2026", "NuevaClave2026")
    assert auth.verificar_credenciales("kira", "NuevaClave2026")
    assert auth.verificar_credenciales("kira", "ClaveSegura2026") is None


# ---------------------------------------------------------------------------
# 4) API protegida deny-by-default
# ---------------------------------------------------------------------------


@pytest.fixture()
def cliente_api(tmp_path, monkeypatch, almacen_tmp):
    """API de prueba con casos aislados y operador admin dado de alta."""
    from fastapi.testclient import TestClient
    from orchestrator import api as api_mod

    monkeypatch.setattr(api_mod, "RAIZ_CASOS", tmp_path / "casos")
    (tmp_path / "casos").mkdir(exist_ok=True)
    auth.crear_operador("admin", "ClaveSegura2026", rol="admin")
    return TestClient(api_mod.app)


def test_api_sin_token_deniega(cliente_api) -> None:
    r = cliente_api.get("/api/engagements")
    assert r.status_code == 401
    r2 = cliente_api.get("/api/salud")
    assert r2.status_code == 200  # ruta pública


def test_api_login_y_acceso_con_token(cliente_api) -> None:
    r = cliente_api.post("/api/auth/login",
                         json={"usuario": "admin", "contrasena": "ClaveSegura2026"})
    assert r.status_code == 200
    token = r.json()["token"]
    r2 = cliente_api.get("/api/engagements",
                         headers={"Authorization": f"Bearer {token}"})
    assert r2.status_code == 200
    assert r2.json() == []


def test_api_login_incorrecto_401(cliente_api) -> None:
    r = cliente_api.post("/api/auth/login",
                         json={"usuario": "admin", "contrasena": "malaclave"})
    assert r.status_code == 401


def test_bootstrap_registra_primer_operador_y_luego_exige_admin(cliente_api) -> None:
    # Con el almacén ya poblado por el fixture, registrar sin token debe 403
    r = cliente_api.post("/api/auth/registrar",
                         json={"usuario": "intruso", "contrasena": "ClaveSegura2026"})
    assert r.status_code == 403


def test_decision_aprobacion_registra_identidad_real(cliente_api, tmp_path) -> None:
    """La firma ROE queda vinculada al operador autenticado (JWT), no al cuerpo."""
    from orchestrator.memory import MemoriaCaso
    from orchestrator.models import Aprobacion, Fase

    r = cliente_api.post("/api/auth/login",
                         json={"usuario": "admin", "contrasena": "ClaveSegura2026"})
    token = r.json()["token"]
    cabeceras = {"Authorization": f"Bearer {token}"}

    rc = cliente_api.post("/api/engagements", json={
        "nombre": "Caso identidad", "cliente": "ACME",
        "alcance_dominios": ["acme.com"], "ventana_inicio": "00:00",
        "ventana_fin": "23:59"}, headers=cabeceras)
    caso_id = rc.json()["id"]

    memoria = MemoriaCaso(tmp_path / "casos" / f"{caso_id}.db")
    memoria.crear_aprobacion(Aprobacion(
        id="apr_identidad", engagement_id=caso_id, fase=Fase.F3_ACCESO,
        titulo="Prueba de identidad", herramienta="explotar.ejecutar"))
    memoria.cerrar()

    # Intento de suplantación: el cuerpo pide "otro" — el JWT manda
    rd = cliente_api.post("/api/aprobaciones/apr_identidad/decision",
                          json={"decidir": True, "comentario": "ok", "operador": "otro"},
                          headers=cabeceras)
    assert rd.status_code == 200
    memoria = MemoriaCaso(tmp_path / "casos" / f"{caso_id}.db")
    aprobadas = [a for a in memoria.listar_aprobaciones(caso_id)
                 if a["id"] == "apr_identidad"]
    assert aprobadas[0]["decidida_por"] == "admin"  # identidad real del JWT
    # La auditoría inmutable también registra quién decidió
    auditoria = memoria.listar_auditoria(caso_id)
    assert any("por admin" in e["detalle"] for e in auditoria
               if e["accion"] == "aprobacion.decision")
    memoria.cerrar()
