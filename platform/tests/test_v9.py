"""Tests v9: regresión de las correcciones de producción.

Cubre las seis correcciones de esta ronda:
  1. Poda de memoria del limitador de tasa (DoS de claves suplantadas).
  2. Poda del registro de intentos de login en auth.
  3. MemoriaCaso como context manager (cierre garantizado de SQLite).
  4. Techo de ruido PERSISTENTE en el boundary (aprobaciones previas cargadas).
  5. Respaldo ZIP del caso (archivado real con manifiesto y custodia).
  6. Identidad real en la auditoría de roe.actualizar.
"""
from __future__ import annotations

import io
import json
import os
import sys
import time
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from orchestrator import auth  # noqa: E402
from orchestrator.api import _LimitadorTasa, app  # noqa: E402
from orchestrator.guardrails import MotorGuardrails  # noqa: E402
from orchestrator.memory import MemoriaCaso  # noqa: E402
from orchestrator.models import (  # noqa: E402
    Aprobacion,
    Engagement,
    Fase,
    ROEPolitica,
)


# ---------------------------------------------------------------------------
# 1) Limitador de tasa con poda
# ---------------------------------------------------------------------------


def test_limitador_tasa_deniega_al_exceder():
    lim = _LimitadorTasa(maximo=3, ventana_s=60.0)
    for _ in range(3):
        permitido, _ = lim.permitir("1.2.3.4")
        assert permitido
    permitido, reintentar = lim.permitir("1.2.3.4")
    assert not permitido and reintentar >= 1


def test_limitador_tasa_poda_claves_y_acota_memoria():
    lim = _LimitadorTasa(maximo=10, ventana_s=1.0)
    lim.MAX_CLAVES = 20  # aceleramos el umbral de poda para el test
    # Simula un atacante que suplanta cientos de X-Forwarded-For
    for i in range(500):
        lim.permitir(f"10.0.0.{i % 254}.{i % 2}")
    assert len(lim._eventos) <= lim.MAX_CLAVES, (
        "el limitador permite crecimiento de memoria sin límite")


# ---------------------------------------------------------------------------
# 2) Registro de intentos de login con poda
# ---------------------------------------------------------------------------


def test_auth_intentos_poda_usuarios_inexistentes(monkeypatch):
    monkeypatch.setattr(auth, "_intentos", {})
    for i in range(300):
        auth._registrar_intento(f"usuario_inexistente_{i}")
    assert len(auth._intentos) <= auth._INTENTOS_MAX_CLAVES, (
        "el registro de intentos crece sin límite con usuarios inexistentes")
    # El flujo normal sigue registrando
    auth._registrar_intento("operador_real")
    assert "operador_real" in auth._intentos


# ---------------------------------------------------------------------------
# 3) MemoriaCaso como context manager
# ---------------------------------------------------------------------------


@pytest.fixture()
def caso_tmp(tmp_path):
    ruta = tmp_path / "caso_ctx.db"
    eng = Engagement(
        id="caso_ctxtest01", nombre="Caso context manager", cliente="Cliente ACME",
        roe=ROEPolitica(
            engagement_id="caso_ctxtest01", cliente="Cliente ACME",
            alcance_dominios=["acme.test"], alcance_cidrs=[],
            alcance_excluido=[], tecnicas_prohibidas=[],
            tecnicas_con_aprobacion=[], techo_ruido=50),
    )
    memoria = MemoriaCaso(ruta)
    memoria.crear_engagement(eng)
    memoria.cerrar()
    return ruta


def test_memoria_context_manager_cierra_conexion(caso_tmp):
    memoria = MemoriaCaso(caso_tmp)
    with memoria as m:
        assert m.obtener_engagement("caso_ctxtest01") is not None
    # cerrada: nuevas consultas sobre la MISMA instancia fallan con ProgrammingError
    import sqlite3
    with pytest.raises(sqlite3.ProgrammingError):
        memoria.obtener_engagement("caso_ctxtest01")


def test_memoria_context_manager_cierra_incluso_con_excepcion(caso_tmp):
    import sqlite3
    memoria = MemoriaCaso(caso_tmp)
    with pytest.raises(RuntimeError):
        with memoria as m:
            raise RuntimeError("fallo simulado del handler")
    with pytest.raises(sqlite3.ProgrammingError):
        m.obtener_engagement("caso_ctxtest01")


# ---------------------------------------------------------------------------
# 4) Techo de ruido persistente
# ---------------------------------------------------------------------------


def test_boundary_carga_ruido_previo_del_caso(caso_tmp):
    with MemoriaCaso(caso_tmp) as memoria:
        roe = ROEPolitica.model_validate_json(
            memoria.obtener_engagement("caso_ctxtest01")["roe_json"])
        # Firma previa: una acción de ruido 55 aprobada (F3 MSF, por ejemplo)
        ap = Aprobacion(
            id="apr_ruido01", engagement_id="caso_ctxtest01", fase=Fase.F3_ACCESO,
            titulo="Aprobación requerida: explotar.ejecutar",
            descripcion="prueba", herramienta="explotar.ejecutar",
            argumentos={"objetivo": "acme.test", "modulo": "exploit/x"},
            riesgo="alta", ruido_estimado=55, motivo="prueba",
            referencia_roe="operator-in-command")
        memoria.crear_aprobacion(ap)
        memoria.decidir_aprobacion("apr_ruido01", True, "ana.red", "ok")
        motor = MotorGuardrails(roe, memoria)
        # El motor ARRANCA con el ruido ya firmado (antes empezaba en 0)
        assert motor.ruido_acumulado == 55


# ---------------------------------------------------------------------------
# 5) Respaldo ZIP del caso
# ---------------------------------------------------------------------------


@pytest.fixture()
def cliente_api(tmp_path, monkeypatch):
    """API con RAIZ_CASOS aislada y un operador admin real autenticado."""
    casos = tmp_path / "casos"
    casos.mkdir()
    monkeypatch.setattr("orchestrator.api.RAIZ_CASOS", casos)
    ruta_usuarios = tmp_path / "usuarios_api.db"
    monkeypatch.setattr(auth, "RUTA_DB", ruta_usuarios)
    monkeypatch.setattr(auth, "_intentos", {})
    auth.crear_operador("admin.v9", "ClaveSegura2026", rol="admin")
    with TestClient(app) as cliente:
        login = cliente.post("/api/auth/login",
                             json={"usuario": "admin.v9", "contrasena": "ClaveSegura2026"})
        token = login.json()["token"]
        cliente.headers.update({"Authorization": f"Bearer {token}"})
        yield cliente


def test_respaldo_zip_con_custodia_e_informe(cliente_api, tmp_path):
    cliente = cliente_api
    # Caso con contenido real: crear + avanzar F0 (borrador ROE determinista)
    creado = cliente.post("/api/engagements", json={
        "nombre": "Caso respaldo v9", "cliente": "Cliente ACME",
        "alcance_dominios": ["acme.test"], "ventana_inicio": "00:00",
        "ventana_fin": "23:59"}).json()
    assert "id" in creado
    # F0 genera evidencia real (borrador de ROE determinista, sin LLM)
    avanzar = cliente.post(f"/api/engagements/{creado['id']}/avanzar", json={})
    assert avanzar.status_code == 200, avanzar.text
    # Respaldo
    r = cliente.get(f"/api/engagements/{creado['id']}/respaldo")
    assert r.status_code == 200, r.text
    assert r.headers["content-type"].startswith("application/zip")
    archivo = zipfile.ZipFile(io.BytesIO(r.content))
    nombres = archivo.namelist()
    assert f"{creado['id']}/caso.json" in nombres
    assert f"{creado['id']}/MANIFIESTO.txt" in nombres
    assert f"{creado['id']}/informe.md" in nombres
    assert f"{creado['id']}/informe.html" in nombres
    # El caso.json dentro del ZIP es un paquete de custodia válido
    paquete = json.loads(archivo.read(f"{creado['id']}/caso.json"))
    assert paquete["formato"] == "orquestart-caso/1"
    assert len(paquete["evidencias"]) >= 1
    assert paquete["cadena_custodia"]["valida"] is True
    # El manifiesto declara el estado real
    manifiesto = archivo.read(f"{creado['id']}/MANIFIESTO.txt").decode()
    assert "VÁLIDA" in manifiesto and f"caso {creado['id']}" in manifiesto


def test_respaldo_404_caso_inexistente(cliente_api):
    r = cliente_api.get("/api/engagements/caso_noxiste99/respaldo")
    assert r.status_code == 404


def test_respaldo_401_sin_token(cliente_api):
    cliente_nuevo = cliente_api  # TestClient con headers; usamos uno limpio
    from fastapi.testclient import TestClient as _TC
    # Sin cabecera Authorization la petición es anónima: deny-by-default
    import copy
    viejas = dict(cliente_nuevo.headers)
    cliente_nuevo.headers.pop("Authorization")
    try:
        r = cliente_nuevo.get("/api/engagements/caso_loquesea/respaldo")
        assert r.status_code == 401
    finally:
        cliente_nuevo.headers.update(viejas)


# ---------------------------------------------------------------------------
# 6) Identidad real en la auditoría de roe.actualizar
# ---------------------------------------------------------------------------


def test_roe_actualizar_registra_identidad_en_auditoria(cliente_api):
    cliente = cliente_api
    creado = cliente.post("/api/engagements", json={
        "nombre": "Caso ROE identidad", "cliente": "Cliente ACME",
        "alcance_dominios": ["acme.test"]}).json()
    r = cliente.post(f"/api/engagements/{creado['id']}/roe",
                     json={"techo_ruido": 42})
    assert r.status_code == 200
    assert r.json()["roe"]["techo_ruido"] == 42
    eventos = cliente.get(f"/api/engagements/{creado['id']}/auditoria").json()
    roe_evt = [e for e in eventos if e["accion"] == "roe.actualizar"]
    assert roe_evt, "el cambio de ROE no quedó auditado"
    assert "admin.v9" in roe_evt[0]["detalle"], (
        "la auditoría de roe.actualizar no registra la identidad real")
