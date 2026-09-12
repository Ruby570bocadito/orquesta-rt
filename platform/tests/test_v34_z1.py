"""Tests v34 (z1, sesión 06): sesiones visibles + SSO administrable.

Dos frentes que cierran las propuestas de la sesión 05 (docs/agentes/z1):

A) Registro de sesiones activas (VISIBILIDAD, no autorización):
   el JWT sigue siendo sin estado y la validez la decide la firma +
   sesion_viva() en cada petición (z3-F4). Esta ronda añade el ESPEJO
   consultable: cada login (local o federado) registra su token
   (jti, UA, IP) y GET /api/auth/sesiones enseña SOLO las sesiones vivas
   del propietario — no expiradas, no revocadas por el corte — marcando
   la pestaña actual. La telemetría de actividad va con throttle (1/min
   por jti) y jamás bloquea una petición válida.

B) Vinculación federada administrable:
   - POST /api/auth/sso/desvincular: operación INVERSA y auditada de
     sso/vincular — sin ella, enlazar era una puerta de una sola vía.
   - GET /api/auth/higiene declara sso_vinculado (booleano) SIN exponer
     el sub del IdP: la presencia del enlace es de la operadora; el sub,
     de la auditoría.
"""
from __future__ import annotations

import sys
import time
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from orchestrator import auth  # noqa: E402

UA_TRABAJO = "Mozilla/5.0 (X11; Linux x86_64) Chrome/126.0 prueba-trabajo"
UA_MOVIL = "Mozilla/5.0 (Android 15) Chrome/126.0 prueba-movil"


@pytest.fixture()
def almacen_tmp(tmp_path, monkeypatch):
    ruta = tmp_path / "usuarios_v34.db"
    monkeypatch.setattr(auth, "RUTA_DB", ruta)
    monkeypatch.setattr(auth, "_intentos", {})
    # v34: el throttle de actividad es estado en proceso — limpio por test
    # (misma filosofía que el reseteo del limitador en conftest).
    monkeypatch.setattr(auth, "_touch_sesiones", {})
    return ruta


def _sesion_nueva(usuario: str, rol: str = "operador",
                  ua: str = UA_TRABAJO, ip: str = "10.0.0.9") -> dict[str, Any]:
    """Emite un token REAL y lo registra: devuelve los claims."""
    token = auth.emitir_token(usuario, rol)["token"]
    auth.registrar_sesion(token, ua, ip)
    claims = auth.verificar_token(token)
    assert claims is not None
    return claims


# ---------------------------------------------------------------------------
# A) Registro de sesiones (unidades)
# ---------------------------------------------------------------------------

def test_registrar_y_listar_sesion_marca_la_actual(almacen_tmp) -> None:
    auth.crear_operador("ana.v34", "ClaveSegura2026")
    claims = _sesion_nueva("ana.v34")
    filas = auth.listar_sesiones("ana.v34", jti_actual=str(claims["jti"]))
    assert len(filas) == 1
    fila = filas[0]
    assert fila["actual"] is True
    # jti resumido: 8 caracteres + elipsis, NUNCA el identificador entero
    assert fila["jti"].endswith("…") and len(fila["jti"]) == 9
    assert fila["user_agent"] == UA_TRABAJO
    assert fila["ip"] == "10.0.0.9"
    assert fila["emitido_en"] == pytest.approx(float(claims["iat"]), abs=1)
    assert fila["expira_en"] > time.time()


def test_otra_consulta_no_marca_actual(almacen_tmp) -> None:
    auth.crear_operador("bruno.v34", "ClaveSegura2026")
    claims = _sesion_nueva("bruno.v34")
    # Consulta SIN jti_actual (o desde otro token): nadie está marcado
    filas = auth.listar_sesiones("bruno.v34")
    assert len(filas) == 1 and filas[0]["actual"] is False
    filas = auth.listar_sesiones("bruno.v34", jti_actual="otrojti")
    assert filas[0]["actual"] is False
    assert str(claims["jti"]) != "otrojti"


def test_listar_sesiones_purga_las_expiradas(almacen_tmp) -> None:
    auth.crear_operador("carla.v34", "ClaveSegura2026")
    # Una fila caducada (era v?): el listado la purga y no la devuelve
    conn = auth._conexion()
    try:
        conn.execute(
            "INSERT INTO sesiones (jti, usuario, emitido_en, expira_en, "
            "ultima_actividad, user_agent, ip) VALUES (?,?,?,?,?,?,?)",
            ("muerto1", "carla.v34", time.time() - 100_000,
             time.time() - 90_000, time.time() - 90_000, "antiguo", "0.0.0.0"))
        conn.commit()
    finally:
        conn.close()
    assert auth.listar_sesiones("carla.v34") == []
    # Y la purga dejó la tabla limpia
    conn = auth._conexion()
    try:
        restantes = conn.execute("SELECT COUNT(*) FROM sesiones").fetchone()[0]
    finally:
        conn.close()
    assert restantes == 0


def test_corte_de_revocacion_vacia_el_listado(almacen_tmp) -> None:
    """La lista es el ESPEJO de sesion_viva: tras el corte de revocación
    (invalidar_antes) las sesiones emitidas antes desaparecen del espejo
    aunque sus tokens no hayan expirado por edad."""
    auth.crear_operador("diana.v34", "ClaveSegura2026")
    _sesion_nueva("diana.v34")
    assert len(auth.listar_sesiones("diana.v34")) == 1
    auth.revocar_sesiones_propias("diana.v34")
    assert auth.listar_sesiones("diana.v34") == []


def test_relogin_tras_corte_aparece(almacen_tmp) -> None:
    """El token emitido DESPUÉS del corte está vivo (sesion_viva) y SU
    sesión aparece en el espejo — el corte no castiga a los nuevos."""
    auth.crear_operador("elena.v34", "ClaveSegura2026")
    _sesion_nueva("elena.v34")
    auth.revocar_sesiones_propias("elena.v34")
    time.sleep(1.05)  # iat truncado a segundo vs corte flotante (v26)
    _sesion_nueva("elena.v34", ua=UA_MOVIL, ip="10.0.0.8")
    filas = auth.listar_sesiones("elena.v34")
    assert len(filas) == 1
    assert filas[0]["user_agent"] == UA_MOVIL and filas[0]["ip"] == "10.0.0.8"


def test_tocar_sesion_actualiza_con_throttle(almacen_tmp, monkeypatch) -> None:
    auth.crear_operador("fer.v34", "ClaveSegura2026")
    claims = _sesion_nueva("fer.v34")
    jti = str(claims["jti"])

    def actividad() -> float:
        conn = auth._conexion()
        try:
            fila = conn.execute(
                "SELECT ultima_actividad FROM sesiones WHERE jti=?",
                (jti,)).fetchone()
        finally:
            conn.close()
        return float(fila["ultima_actividad"])

    auth.tocar_sesion(claims)
    primera = actividad()
    # Inmediatamente después: throttled (1/min por jti) — sin escritura
    auth.tocar_sesion(claims)
    assert actividad() == primera
    # Pasado el minuto: vuelve a volcar (avanzamos el reloj del throttle)
    monkeypatch.setitem(auth._touch_sesiones, jti, time.time() - 61.0)
    auth.tocar_sesion(claims)
    assert actividad() > primera


def test_tocar_sesion_sobrevive_sin_tabla(almacen_tmp, monkeypatch) -> None:
    """La telemetría JAMÁS bloquea: si la BD falla, tocar_sesion se traga
    el error y la petición sigue (la visibilidad es un lujo)."""
    auth.crear_operador("gael.v34", "ClaveSegura2026")
    claims = _sesion_nueva("gael.v34")
    class _BD_Rota:
        def execute(self, *_a: Any, **_k: Any) -> None:
            raise auth.sqlite3.Error("bd rota a propósito")

        def close(self) -> None:
            pass
    monkeypatch.setattr(auth, "_conexion", lambda: _BD_Rota())
    monkeypatch.setitem(auth._touch_sesiones, str(claims["jti"]), 0.0)
    auth.tocar_sesion(claims)  # no levanta


def test_tocar_sesion_sin_jti_no_toca_nada(almacen_tmp) -> None:
    auth.tocar_sesion({"sub": "nadie"})  # sin jti: retorno silencioso
    assert auth.listar_sesiones("nadie") == []


# ---------------------------------------------------------------------------
# B) Desvinculación federada (unidades)
# ---------------------------------------------------------------------------

def test_desvincular_sso_feliz(almacen_tmp) -> None:
    auth.crear_operador("hector.v34", "ClaveSegura2026")
    auth.vincular_sso_manual("hector.v34", "auth0|prueba66")
    assert auth.obtener_por_sso("auth0|prueba66") is not None
    resultado = auth.desvincular_sso("hector.v34")
    assert resultado == {"usuario": "hector.v34", "desvinculado": True}
    assert auth.obtener_por_sso("auth0|prueba66") is None
    # Y puede re-vincularse (puerta de ida y vuelta completa)
    auth.vincular_sso_manual("hector.v34", "auth0|prueba66")
    assert auth.obtener_por_sso("auth0|prueba66") is not None


def test_desvincular_sso_sin_vinculo_y_fantasma(almacen_tmp) -> None:
    auth.crear_operador("irene.v34", "ClaveSegura2026")
    with pytest.raises(ValueError, match="no tiene acceso federado"):
        auth.desvincular_sso("irene.v34")
    with pytest.raises(ValueError, match="no existe"):
        auth.desvincular_sso("fantasma.v34")
    with pytest.raises(ValueError, match="obligatorio"):
        auth.desvincular_sso("")


def test_desvincular_sso_no_toca_otros_vinculos(almacen_tmp) -> None:
    auth.crear_operador("juan.v34", "ClaveSegura2026")
    auth.crear_operador("karla.v34", "ClaveSegura2026")
    auth.vincular_sso_manual("juan.v34", "sub-de-juan")
    auth.vincular_sso_manual("karla.v34", "sub-de-karla")
    auth.desvincular_sso("juan.v34")
    assert auth.obtener_por_sso("sub-de-karla") is not None
    assert auth.obtener_por_sso("sub-de-juan") is None


def test_higiene_unitaria_con_y_sin_vinculo(almacen_tmp) -> None:
    """A nivel auth, higiene_cuenta trae sso_sub en bruto; la conversión a
    booleano (y la omisión del sub) es de la capa API — se prueba en E2E."""
    auth.crear_operador("laura.v34", "ClaveSegura2026")
    assert auth.higiene_cuenta("laura.v34")["sso_sub"] is None
    auth.vincular_sso_manual("laura.v34", "sub-de-laura")
    assert auth.higiene_cuenta("laura.v34")["sso_sub"] == "sub-de-laura"


# ---------------------------------------------------------------------------
# API HTTP
# ---------------------------------------------------------------------------

from fastapi.testclient import TestClient  # noqa: E402

from orchestrator.api import app  # noqa: E402
from orchestrator import sidecar  # noqa: E402


@pytest.fixture()
def cliente_api(almacen_tmp, monkeypatch):
    monkeypatch.setattr(sidecar, "asegurar_consola", lambda: True)
    return TestClient(app)


def _login(cliente: TestClient, usuario: str, contrasena: str,
           ua: str = UA_TRABAJO) -> str:
    r = cliente.post("/api/auth/login",
                     json={"usuario": usuario, "contrasena": contrasena},
                     headers={"User-Agent": ua})
    assert r.status_code == 200, r.text
    return r.json()["token"]


def test_api_sesiones_requieren_sesion(cliente_api: TestClient) -> None:
    assert cliente_api.get("/api/auth/sesiones").status_code == 401


def test_api_login_registra_sesion_con_contexto(cliente_api: TestClient) -> None:
    auth.crear_operador("mar.v34", "ClaveSegura2026")
    token = _login(cliente_api, "mar.v34", "ClaveSegura2026")
    r = cliente_api.get("/api/auth/sesiones",
                        headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200, r.text
    cuerpo = r.json()
    assert cuerpo["total"] == 1
    sesion = cuerpo["sesiones"][0]
    assert sesion["actual"] is True
    assert "prueba-trabajo" in sesion["user_agent"]
    assert sesion["ip"]  # la del TestClient, pero REGISTRADA
    # La higiene de la misma cuenta: federado = False (sin exponer sub)
    h = cliente_api.get("/api/auth/higiene",
                        headers={"Authorization": f"Bearer {token}"}).json()
    assert h["sso_vinculado"] is False
    assert "sso_sub" not in h


def test_api_dos_sesiones_marca_la_actual_de_cada_una(cliente_api: TestClient) -> None:
    auth.crear_operador("nora.v34", "ClaveSegura2026")
    token_trabajo = _login(cliente_api, "nora.v34", "ClaveSegura2026",
                           ua=UA_TRABAJO)
    token_movil = _login(cliente_api, "nora.v34", "ClaveSegura2026",
                         ua=UA_MOVIL)
    for token, ua in ((token_trabajo, "prueba-trabajo"),
                      (token_movil, "prueba-movil")):
        r = cliente_api.get("/api/auth/sesiones",
                            headers={"Authorization": f"Bearer {token}"})
        cuerpo = r.json()
        assert cuerpo["total"] == 2
        marcadas = [s for s in cuerpo["sesiones"] if s["actual"]]
        assert len(marcadas) == 1
        assert ua in marcadas[0]["user_agent"]


def test_api_cerrar_todas_vacia_el_registro_y_relogin_crea_nueva(
        cliente_api: TestClient) -> None:
    """El espejo dice la verdad del corte: «cerrar en todos los
    dispositivos» mata TODAS las sesiones listadas; el re-login (después
    de la espera heredada de v26 por el iat truncado) deja UNA nueva."""
    auth.crear_operador("oscar.v34", "ClaveSegura2026")
    _login(cliente_api, "oscar.v34", "ClaveSegura2026")
    _login(cliente_api, "oscar.v34", "ClaveSegura2026", ua=UA_MOVIL)
    r = cliente_api.post("/api/auth/sesion/cerrar-todas",
                         json={},
                         headers={"Authorization": "Bearer " + _login(
                             cliente_api, "oscar.v34", "ClaveSegura2026")})
    assert r.status_code == 200, r.text
    time.sleep(1.05)  # corte flotante vs iat entero (semántica v26)
    token = _login(cliente_api, "oscar.v34", "ClaveSegura2026")
    r = cliente_api.get("/api/auth/sesiones",
                        headers={"Authorization": f"Bearer {token}"})
    cuerpo = r.json()
    assert cuerpo["total"] == 1
    assert cuerpo["sesiones"][0]["actual"] is True


def _arranque_admin(cliente_api: TestClient) -> str:
    """Bootstrap real: el PRIMER registro sin sesión nace admin (contrato
    del endpoint); después entra por login como cualquiera y devuelve su
    token."""
    r = cliente_api.post("/api/auth/registrar",
                         json={"usuario": "admin.v34",
                               "contrasena": "ClaveAdmin2026"})
    assert r.status_code == 200, r.text
    return _login(cliente_api, "admin.v34", "ClaveAdmin2026")


def test_api_sso_desvincular_flujo_completo_y_auditoria(
        cliente_api: TestClient) -> None:
    """El ciclo COMPLETO de la cuarta brecha: admin vincula el sub del IdP
    a la cuenta de una lectora → su higiene lo declara (sin exponer el
    sub) → el admin lo desvincula → la higiene vuelve a local → todo
    queda en la auditoría del sistema con la identidad del admin."""
    token_admin = _arranque_admin(cliente_api)
    cab_admin = {"Authorization": f"Bearer {token_admin}"}
    r = cliente_api.post("/api/auth/registrar",
                         json={"usuario": "lectora.v34",
                               "contrasena": "ClaveLectora2026",
                               "rol": "lector"},
                         headers=cab_admin)
    assert r.status_code == 200, r.text
    token_lectora = _login(cliente_api, "lectora.v34", "ClaveLectora2026")
    cab_lectora = {"Authorization": f"Bearer {token_lectora}"}

    # La lectora NO toca el canal federado de nadie (ni siquiera el suyo)
    assert cliente_api.post(
        "/api/auth/sso/desvincular", json={"usuario": "lectora.v34"},
        headers=cab_lectora).status_code == 403

    # Vinculación (endpoint v22 que hasta hoy no tenía UI) → higiene lo ve
    r = cliente_api.post("/api/auth/sso/vincular",
                         json={"usuario": "lectora.v34",
                               "sso_sub": "entra|abc123def"},
                         headers=cab_admin)
    assert r.status_code == 200, r.text
    h = cliente_api.get("/api/auth/higiene", headers=cab_lectora).json()
    assert h["sso_vinculado"] is True and "sso_sub" not in h

    # Desvinculación (v34) → higiene vuelve a local; segunda vez, 400
    r = cliente_api.post("/api/auth/sso/desvincular",
                         json={"usuario": "lectora.v34"}, headers=cab_admin)
    assert r.status_code == 200, r.text
    assert r.json() == {"usuario": "lectora.v34", "desvinculado": True}
    h = cliente_api.get("/api/auth/higiene", headers=cab_lectora).json()
    assert h["sso_vinculado"] is False and "sso_sub" not in h
    assert cliente_api.post(
        "/api/auth/sso/desvincular", json={"usuario": "lectora.v34"},
        headers=cab_admin).status_code == 400

    # La auditoría del sistema conserva AMBAS decisiones con su autor
    r = cliente_api.get("/api/admin/auditoria-sistema?limite=100",
                        headers=cab_admin)
    assert r.status_code == 200, r.text
    acciones = {e["accion"] for e in r.json()}
    assert "sso.vincular" in acciones and "sso.desvincular" in acciones
    eventos = [e for e in r.json() if e["accion"] == "sso.desvincular"]
    assert eventos[0]["actor"] == "admin.v34"


def test_api_sso_desvincular_fantasma_400(cliente_api: TestClient) -> None:
    token_admin = _arranque_admin(cliente_api)
    r = cliente_api.post("/api/auth/sso/desvincular",
                         json={"usuario": "nadie.v34"},
                         headers={"Authorization": f"Bearer {token_admin}"})
    assert r.status_code == 400
    assert "no existe" in r.json()["detail"]
