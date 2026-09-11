"""Tests v14: capa MITRE ATT&CK Navigator, clamp de auditoría y R9 arsenal.

Cubre las mejoras de esta ronda:
  1. Capa ATT&CK Navigator (módulo navigator.py): estructura layer 4.6,
     score/color por severidad (máxima si concurren hallazgos), dedupe de
     técnicas, metadatos de hallazgos y de solicitudes de aprobación,
     técnicas con formato inválido IGNORADAS (sin relleno), caso sin
     hallazgos → capa con cero técnicas (nunca se inventa cobertura).
  2. Endpoint GET /api/engagements/{id}/attack-navigator: 404 accionable,
     Content-Disposition, JSON válido y evento de auditoría del caso.
  3. Clamp de /auditoria: limite negativo u enorme ya no llega crudo a
     SQLite (LIMIT negativo = sin límite); se acota a [1, 1000].
  4. R9 del razonador: playbooks del arsenal real propuestos para la fase
     en curso/siguiente cuando la técnica no tiene huella en el caso, y
     excluidos cuando ya hay hallazgo o solicitud con esa técnica.
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi.testclient import TestClient  # noqa: E402

from orchestrator.api import app, RAIZ_CASOS  # noqa: E402
from orchestrator.memory import MemoriaCaso  # noqa: E402
from orchestrator.models import (  # noqa: E402
    Aprobacion, Engagement, Fase, Hallazgo, ROEPolitica, Severidad,
)
from orchestrator.navigator import construir_capa_navigator  # noqa: E402
from orchestrator.razonador import prioridades_siguientes  # noqa: E402


def _engagement(tmp_path: Path, id_caso: str, fase: Fase = Fase.F3_ACCESO):
    roe = ROEPolitica.model_validate({
        "engagement_id": id_caso, "cliente": "acme",
        "alcance_dominios": ["cliente.com"],
        "alcance_cidrs": ["192.168.1.0/24"],
    })
    ahora = datetime.now(timezone.utc)
    return Engagement(
        id=id_caso, nombre="caso v14", cliente="acme", roe=roe,
        fase_actual=fase, creado_en=ahora, actualizado_en=ahora,
    )


def _memoria_con_caso(tmp_path: Path, id_caso: str,
                      fase: Fase = Fase.F3_ACCESO) -> MemoriaCaso:
    memoria = MemoriaCaso(tmp_path / f"{id_caso}.db")
    memoria.crear_engagement(_engagement(tmp_path, id_caso, fase))
    return memoria


def _hallazgo(id_caso: str, n: int, tecnica: str | None,
              severidad: Severidad = Severidad.ALTA,
              titulo: str = "hallazgo", estado: str = "confirmado") -> Hallazgo:
    return Hallazgo(
        id=f"h{n}", engagement_id=id_caso, titulo=titulo,
        severidad=severidad, tecnica_mitre=tecnica, estado=estado,
    )


def _aprobacion(id_caso: str, n: int, tecnica: str | None,
                estado: str = "aprobada") -> Aprobacion:
    return Aprobacion(
        id=f"a{n}", engagement_id=id_caso, fase=Fase.F3_ACCESO,
        titulo=f"solicitud {n}", tecnica_mitre=tecnica, estado=estado,
    )


# ---------------------------------------------------------------------------
# 1) Capa Navigator: unidad
# ---------------------------------------------------------------------------


def test_capa_navigator_estructura_scores_y_dedupe(tmp_path) -> None:
    id_caso = "caso_nav1"
    memoria = _memoria_con_caso(tmp_path, id_caso)
    memoria.guardar_hallazgo(_hallazgo(id_caso, 1, "T1558.004", Severidad.ALTA,
                                       "AS-REP roasteable", "confirmado"))
    memoria.guardar_hallazgo(_hallazgo(id_caso, 2, "T1557.001", Severidad.CRITICA,
                                       "LLMNR poisoning detectado", "confirmado"))
    memoria.guardar_hallazgo(_hallazgo(id_caso, 3, "T1557.001", Severidad.MEDIA,
                                       "variante", "propuesto"))
    memoria.crear_aprobacion(_aprobacion(id_caso, 1, "T1557.001", "aprobada"))
    memoria.guardar_hallazgo(_hallazgo(id_caso, 4, "banana", Severidad.ALTA,
                                       "técnica malformada"))  # se ignora
    capa = construir_capa_navigator(memoria, id_caso)
    memoria.cerrar()

    assert capa["versions"]["layer"] == "4.6"
    assert capa["domain"] == "enterprise-attack"
    assert capa["name"].startswith("OrquestaRT — caso v14")

    por_id = {t["techniqueID"]: t for t in capa["techniques"]}
    # Dedupe: solo IDs válidos, 'banana' fuera, sin duplicados.
    assert set(por_id) == {"T1558.004", "T1557.001"}
    # Score por severidad MÁXIMA y color coherente con el informe.
    assert por_id["T1558.004"]["score"] == 80
    assert por_id["T1558.004"]["color"] == "#c2410c"
    assert por_id["T1557.001"]["score"] == 100  # crítica manda sobre media
    assert por_id["T1557.001"]["color"] == "#b91c1c"
    # Comentarios combinan hallazgos + solicitud de aprobación.
    assert "2 hallazgo(s)" in por_id["T1557.001"]["comment"]
    assert "Intentada además en 1 solicitud(es)" in por_id["T1557.001"]["comment"]
    meta_vals = {m["name"]: m["value"] for m in por_id["T1557.001"]["metadata"]}
    assert meta_vals["Hallazgos"] == "2"
    assert meta_vals["Solicitudes"] == "1"
    assert meta_vals["Autorizadas"] == "1"
    # Leyenda y gradiente presentes para que la capa sea legible en el Navigator.
    assert len(capa["legendItems"]) == 5
    assert capa["gradient"]["maxValue"] == 100


def test_capa_navigator_intento_rechazado_sin_hallazgo(tmp_path) -> None:
    """Técnica intentada y rechazada: entra como anotación, sin score
    (no se vende como cobertura)."""
    id_caso = "caso_nav2"
    memoria = _memoria_con_caso(tmp_path, id_caso)
    memoria.crear_aprobacion(_aprobacion(id_caso, 1, "T1003.001", "rechazada"))
    capa = construir_capa_navigator(memoria, id_caso)
    memoria.cerrar()

    [t] = capa["techniques"]
    assert t["techniqueID"] == "T1003.001"
    assert "score" not in t  # intentada ≠ observada
    assert "1 solicitud(es)" in t["comment"] and "0 autorizada(s)" in t["comment"]


def test_capa_navigator_caso_sin_hallazgos_sin_relleno(tmp_path) -> None:
    id_caso = "caso_nav3"
    memoria = _memoria_con_caso(tmp_path, id_caso)
    capa = construir_capa_navigator(memoria, id_caso)
    memoria.cerrar()
    assert capa["techniques"] == []  # cero técnicas: cero relleno


def test_capa_navigator_engagement_inexistente(tmp_path) -> None:
    memoria = MemoriaCaso(tmp_path / "caso_nav4.db")
    with pytest.raises(ValueError, match="no existe"):
        construir_capa_navigator(memoria, "caso_nav4")
    memoria.cerrar()


# ---------------------------------------------------------------------------
# 2) Endpoint de la capa Navigator
# ---------------------------------------------------------------------------


@pytest.fixture()
def cliente_api(tmp_path, monkeypatch):
    from orchestrator import auth

    monkeypatch.setattr(auth, "RUTA_DB", tmp_path / "usuarios_test_v14.db")
    monkeypatch.setattr(auth, "_intentos", {})
    if not auth.hay_operadores():
        auth.crear_operador("opv14", "ClaveV14segura", rol="admin")
    token = auth.emitir_token("opv14", "admin")["token"]
    cliente = TestClient(app)
    cliente.headers.update({"Authorization": f"Bearer {token}"})
    yield cliente


def _crear_caso_tmp(cliente) -> str:
    """Crea un caso real por la API; el llamante limpia en su finally."""
    r = cliente.post("/api/engagements", json={
        "nombre": "caso v14 api", "cliente": "acme",
        "alcance_dominios": ["localhost"], "alcance_cidrs": ["127.0.0.0/8"],
    })
    assert r.status_code == 200, r.text
    return r.json()["id"]


def test_endpoint_attack_navigator_404(cliente_api) -> None:
    r = cliente_api.get("/api/engagements/caso_ninguno_v14/attack-navigator")
    assert r.status_code == 404
    assert "no existe" in r.json()["detail"]


def test_endpoint_attack_navigator_401_sin_token() -> None:
    cliente = TestClient(app)
    r = cliente.get("/api/engagements/caso_inexistente/attack-navigator")
    assert r.status_code == 401  # deny-by-default, como el resto de la API


def test_endpoint_attack_navigator_ok_y_auditado(cliente_api) -> None:
    id_caso = _crear_caso_tmp(cliente_api)
    r = cliente_api.get(f"/api/engagements/{id_caso}/attack-navigator")
    assert r.status_code == 200, r.text
    assert "attachment" in r.headers.get("content-disposition", "")
    capa = r.json()
    assert capa["versions"]["layer"] == "4.6"
    assert isinstance(capa["techniques"], list)
    # La exportación queda auditada en el propio caso.
    memoria = MemoriaCaso(RAIZ_CASOS / f"{id_caso}.db")
    eventos = [dict(e) for e in memoria.listar_auditoria(id_caso)]
    memoria.cerrar()
    assert any(e["accion"] == "caso.capa_navigator" for e in eventos)
    (RAIZ_CASOS / f"{id_caso}.db").unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# 3) Clamp de /auditoria
# ---------------------------------------------------------------------------


def test_auditoria_limite_acotado(cliente_api) -> None:
    id_caso = _crear_caso_tmp(cliente_api)
    try:
        # Siembra 3 eventos extra (un caso nuevo solo tiene engagement.crear)
        # para poder verificar el clamp con datos suficientes.
        from orchestrator.models import Actor, DecisionGuardrail
        memoria = MemoriaCaso(RAIZ_CASOS / f"{id_caso}.db")
        for i in range(3):
            memoria.registrar_auditoria(
                id_caso, Actor.SISTEMA, f"prueba.v14.{i}", detalle="test",
                guardrail=DecisionGuardrail.PERMITIR)
        memoria.cerrar()

        r_neg = cliente_api.get(f"/api/engagements/{id_caso}/auditoria?limite=-1")
        assert r_neg.status_code == 200
        # -1 acotado a 1: SQLite con LIMIT -1 habria devuelto TODOS los eventos.
        assert len(r_neg.json()) == 1
        r_2 = cliente_api.get(f"/api/engagements/{id_caso}/auditoria?limite=2")
        assert len(r_2.json()) == 2
        r_huge = cliente_api.get(
            f"/api/engagements/{id_caso}/auditoria?limite=100000000")
        assert r_huge.status_code == 200  # acotado a 1000, sin volcado crudo
        # Con 4 eventos totales el tope 1000 no recorta: vuelven los 4.
        assert len(r_huge.json()) == 4
    finally:
        (RAIZ_CASOS / f"{id_caso}.db").unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# 4) R9: prioridades con arsenal real
# ---------------------------------------------------------------------------

_ARSENAL = [
    {"nombre": "llmnr_poisoning_lab", "fase": "F3_acceso_inicial",
     "tecnica_mitre": "T1557.001", "riesgo": "alta"},
    {"nombre": "asrep_roasting_lab", "fase": "F4_dominio_ad",
     "tecnica_mitre": "T1558.004", "riesgo": "alta"},
    {"nombre": "playbook_otra_fase", "fase": "F7_informe",
     "tecnica_mitre": "T1560.001", "riesgo": "media"},
]


def test_r9_arsenal_propone_playbooks_pertinentes(tmp_path) -> None:
    memoria = _memoria_con_caso(tmp_path, "caso_r9a", fase=Fase.F3_ACCESO)
    res = prioridades_siguientes(memoria, "caso_r9a", arsenal=_ARSENAL)
    memoria.cerrar()
    playbooks = [p["herramienta"] for p in res["prioridades"]
                 if p["herramienta"].startswith("playbook:")]
    # F3 actual + F4 siguiente en ventana: llmnr y asrep; F7 fuera.
    assert "playbook:llmnr_poisoning_lab" in playbooks
    assert "playbook:asrep_roasting_lab" in playbooks
    assert not any("playbook_otra_fase" in p for p in playbooks)


def test_r9_arsenal_excluye_tecnica_con_hallazgo(tmp_path) -> None:
    memoria = _memoria_con_caso(tmp_path, "caso_r9b", fase=Fase.F3_ACCESO)
    memoria.guardar_hallazgo(_hallazgo("caso_r9b", 1, "T1557.001",
                                       Severidad.ALTA, "ya observado"))
    res = prioridades_siguientes(memoria, "caso_r9b", arsenal=_ARSENAL)
    memoria.cerrar()
    playbooks = [p["herramienta"] for p in res["prioridades"]
                 if p["herramienta"].startswith("playbook:")]
    assert "playbook:llmnr_poisoning_lab" not in playbooks  # ya tiene huella
    assert "playbook:asrep_roasting_lab" in playbooks


def test_r9_tope_tres_playbooks(tmp_path) -> None:
    arsenal = [{"nombre": f"pb{i}", "fase": "F3_acceso_inicial",
                "tecnica_mitre": f"T111{i}.001", "riesgo": "media"}
               for i in range(6)]
    memoria = _memoria_con_caso(tmp_path, "caso_r9c", fase=Fase.F3_ACCESO)
    res = prioridades_siguientes(memoria, "caso_r9c", arsenal=arsenal)
    memoria.cerrar()
    playbooks = [p for p in res["prioridades"]
                 if p["herramienta"].startswith("playbook:")]
    assert len(playbooks) == 3  # tope duro: sin inundación de propuestas


def test_r9_sin_arsenal_comportamiento_previo(tmp_path) -> None:
    """Compatibilidad: sin arsenal la función sigue operando igual."""
    memoria = _memoria_con_caso(tmp_path, "caso_r9d", fase=Fase.F3_ACCESO)
    res = prioridades_siguientes(memoria, "caso_r9d")
    memoria.cerrar()
    assert "prioridades" in res and "fase_actual" in res
    assert res["fase_actual"] == "F3_acceso_inicial"


# ---------------------------------------------------------------------------
# 5) Endpoint prioridades con arsenal del despliegue real
# ---------------------------------------------------------------------------


def test_endpoint_prioridades_incluye_arsenal_despliegue(cliente_api) -> None:
    id_caso = _crear_caso_tmp(cliente_api)
    try:
        r = cliente_api.get(
            f"/api/engagements/{id_caso}/razonamiento/prioridades")
        assert r.status_code == 200, r.text
        cuerpo = r.json()
        assert cuerpo["fase_actual"] == "F0_scoping"
        assert isinstance(cuerpo["prioridades"], list)
    finally:
        (RAIZ_CASOS / f"{id_caso}.db").unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# 6) Regresión fuzzing: ID hostil jamás llega al sistema de ficheros
# ---------------------------------------------------------------------------


def test_id_largo_o_hostil_404_sin_500(cliente_api) -> None:
    """Hallado por fuzzing (v14): con un id de 10k caracteres,
    Path.exists() lanza OSError ENAMETOOLONG y la API respondía 500."""
    for id_hostil in ("a" * 10000, "..%2F..%2Fetc%2Fpasswd", "caso_x/../../y"):
        r = cliente_api.get(
            f"/api/engagements/{id_hostil}/hallazgos")
        assert r.status_code in (404, 400, 422), (id_hostil[:30], r.status_code)
        assert r.status_code != 500
    # El endpoint nuevo comparte la guardia vía _memoria_de.
    r = cliente_api.get(f"/api/engagements/{'b' * 10000}/attack-navigator")
    assert r.status_code == 404
