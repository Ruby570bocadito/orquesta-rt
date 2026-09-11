"""Tests v11: validación de alcance del ROE y robustez del boundary.

Cubre las correcciones de esta ronda:
  1. CIDR malformado RECHAZADO al crear/validar el ROE (antes se almacenaba
     en silencio y rompía el scope check a mitad de engagement).
  2. Dominio inválido rechazado; 'localhost' permitido (objetivo del lab
     documentado y presente en casos ya almacenados).
  3. alcance_excluido: acepta dominio o CIDR válidos, rechaza basura.
  4. Boundary RESILIENTE: un CIDR roto en el ROE ya no aborta la comprobación
     de los demás (defensa en profundidad si un ROE antiguo llega corrupto).
  5. Casos antiguos con dominio 'localhost' SIGUEN cargando (compatibilidad).
  6. /informe rechaza formato inválido con 422 (antes lo aceptaba en silencio).
  7. engagement_id con traversal no abre ficheros fuera de casos/.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from orchestrator.api import app  # noqa: E402
from orchestrator.guardrails import MotorGuardrails, _host_en_scope  # noqa: E402
from orchestrator.models import ROEPolitica  # noqa: E402


# ---------------------------------------------------------------------------
# 1-3) Validadores del modelo ROE
# ---------------------------------------------------------------------------


def roe_base(**kwargs) -> dict:
    datos = {
        "engagement_id": "caso_testv11",
        "cliente": "acme",
        "alcance_dominios": ["cliente.com"],
        "alcance_cidrs": ["192.168.1.0/24"],
    }
    datos.update(kwargs)
    return datos


def test_cidr_malformado_rechazado() -> None:
    with pytest.raises(ValueError, match="CIDR inválido"):
        ROEPolitica.model_validate(roe_base(alcance_cidrs=["banana"]))


def test_cidr_valido_ipv4_ipv6_aceptado() -> None:
    roe = ROEPolitica.model_validate(
        roe_base(alcance_cidrs=["10.0.0.0/8", "2001:db8::/32", "127.0.0.1"])
    )
    assert len(roe.alcance_cidrs) == 3


def test_dominio_invalido_rechazado() -> None:
    with pytest.raises(ValueError, match="Dominio inválido"):
        ROEPolitica.model_validate(
            roe_base(alcance_dominios=["no es un dominio!!"])
        )


def test_localhost_permitido_en_dominios() -> None:
    roe = ROEPolitica.model_validate(
        roe_base(alcance_dominios=["localhost", "cliente.com"])
    )
    assert "localhost" in roe.alcance_dominios


def test_excluido_acepta_dominio_o_cidr_rechaza_basura() -> None:
    ok = ROEPolitica.model_validate(
        roe_base(alcance_excluido=["corp.cliente.com", "10.0.0.0/8"])
    )
    assert len(ok.alcance_excluido) == 2
    with pytest.raises(ValueError, match="exclusión inválida"):
        ROEPolitica.model_validate(roe_base(alcance_excluido=["!!!"]))


# ---------------------------------------------------------------------------
# 4) Boundary resiliente ante CIDR roto (defensa en profundidad)
# ---------------------------------------------------------------------------


def _roe_con_cidr_roto_y_valido() -> ROEPolitica:
    # Se construye con model_construct para SIMULAR un ROE almacenado que
    # llegó corrupto por otra vía (los validadores y validate_assignment
    # del modelo hoy impiden crear uno así por la API: por eso los tests
    # de defensa en profundidad usan esta vía de escape de pydantic).
    base = ROEPolitica.model_validate(roe_base())
    datos = base.model_dump()
    datos["alcance_cidrs"] = ["banana", "127.0.0.0/8"]
    return ROEPolitica.model_construct(**datos)


def test_cidr_roto_no_bloquea_los_validos() -> None:
    motor = MotorGuardrails(_roe_con_cidr_roto_y_valido())
    permitido, motivo = _host_en_scope("127.0.0.1", motor.roe)
    assert permitido, f"el CIDR válido posterior fue ignorado: {motivo}"


def test_ip_fuera_de_cidrs_sigue_denegada() -> None:
    motor = MotorGuardrails(_roe_con_cidr_roto_y_valido())
    permitido, motivo = _host_en_scope("8.8.8.8", motor.roe)
    assert not permitido


# ---------------------------------------------------------------------------
# 5) Compatibilidad: casos antiguos con 'localhost' cargan
# ---------------------------------------------------------------------------


def test_carga_roe_almacenado_localhost(tmp_path) -> None:
    from orchestrator.memory import MemoriaCaso
    from orchestrator.models import Engagement, Fase
    from datetime import datetime, timezone

    ruta = tmp_path / "caso_compat.db"
    roe = ROEPolitica.model_validate(
        roe_base(alcance_dominios=["localhost"], alcance_cidrs=["127.0.0.0/8"])
    )
    eng = Engagement(
        id="caso_compat", nombre="compat", cliente="acme", roe=roe,
        fase_actual=Fase.F0_SCOPING,
        creado_en=datetime.now(timezone.utc),
        actualizado_en=datetime.now(timezone.utc),
    )
    memoria = MemoriaCaso(ruta)
    memoria.crear_engagement(eng)
    memoria.cerrar()
    # Reapertura: el ROE almacenado pasa por los validadores de nuevo
    memoria2 = MemoriaCaso(ruta)
    fila = memoria2.obtener_engagement("caso_compat")
    roe_cargado = ROEPolitica.model_validate_json(fila["roe_json"])
    memoria2.cerrar()
    assert roe_cargado.alcance_dominios == ["localhost"]


# ---------------------------------------------------------------------------
# 6-7) API: formato del informe y traversal de engagement_id
# ---------------------------------------------------------------------------


@pytest.fixture()
def cliente_api(tmp_path, monkeypatch):
    # Aislar el almacén de operadores en tmp: el TestClient apunta a la API
    # real y SIN esto el alta de "opv11" contaminaría usuarios.db del
    # despliegue (el operador vería un login en vez del bootstrap limpio).
    from orchestrator import auth

    monkeypatch.setattr(auth, "RUTA_DB", tmp_path / "usuarios_test_v11.db")
    monkeypatch.setattr(auth, "_intentos", {})
    if not auth.hay_operadores():
        auth.crear_operador("opv11", "ClaveV11segura", rol="admin")
    token = auth.emitir_token("opv11", "admin")["token"]
    cliente = TestClient(app)
    cliente.headers.update({"Authorization": f"Bearer {token}"})
    yield cliente


def test_informe_formato_invalido_422(cliente_api) -> None:
    # Caso inexistente: el 422 de formato debe PRECEDER al 404 de existencia
    r = cliente_api.get("/api/engagements/caso_ninguno/informe?formato=xml")
    assert r.status_code == 422
    assert "formato inválido" in r.json()["detail"]


def test_crear_caso_cidr_invalido_422_con_mensaje(cliente_api) -> None:
    r = cliente_api.post("/api/engagements", json={
        "nombre": "roe roto", "cliente": "acme",
        "alcance_dominios": ["cliente.com"], "alcance_cidrs": ["banana"],
    })
    assert r.status_code == 422, r.text
    assert "CIDR" in r.json()["detail"]


def test_crear_caso_dominio_invalido_422(cliente_api) -> None:
    r = cliente_api.post("/api/engagements", json={
        "nombre": "roe roto 2", "cliente": "acme",
        "alcance_dominios": ["no es dominio!!"],
    })
    assert r.status_code == 422, r.text
    assert "Dominio" in r.json()["detail"]


def test_crear_caso_localhost_ok(cliente_api) -> None:
    from orchestrator.api import RAIZ_CASOS

    r = cliente_api.post("/api/engagements", json={
        "nombre": "lab v11", "cliente": "acme",
        "alcance_dominios": ["localhost"], "alcance_cidrs": ["127.0.0.0/8"],
    })
    assert r.status_code == 200, r.text
    engagement_id = r.json()["id"]
    assert engagement_id.startswith("caso_")
    # El TestClient apunta a la API REAL: limpieza del caso creado para no
    # contaminar el directorio de casos del operador.
    (RAIZ_CASOS / f"{engagement_id}.db").unlink(missing_ok=True)
    import shutil as _shutil
    _shutil.rmtree(RAIZ_CASOS / engagement_id, ignore_errors=True)


def test_engagement_id_traversal_no_fuga(cliente_api) -> None:
    # ".." como id: resuelve a casos/...db, que no existe → 404; jamás abre
    # un fichero fuera del directorio de casos.
    r = cliente_api.get("/api/engagements/../../usuarios/hallazgos")
    assert r.status_code in (404, 400)  # nunca 200
