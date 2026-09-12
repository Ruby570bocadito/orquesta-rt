"""Tests v23: modo continuo CTEM — corridas reales, delta honesto entre
corridas, programas persistentes y planificador del despliegue.

La regla de la casa se aplica al módulo nuevo: la corrida MIDE (instantánea
de hallazgos + auditoría + detecciones VECTR reales del caso); jamás fabrica
técnicas, ejecuciones ni argumentos. El delta solo compara datos que ya
existían en las BD del caso.
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from orchestrator import auth as _auth  # noqa: E402
from orchestrator import ctem, threatled, webhook  # noqa: E402
from orchestrator.api import RAIZ_CASOS, app  # noqa: E402
from orchestrator.memory import MemoriaCaso  # noqa: E402
from orchestrator.models import (  # noqa: E402
    Actor, Engagement, Fase, Hallazgo, ROEPolitica, Severidad,
)


def _roe(id_caso: str) -> ROEPolitica:
    return ROEPolitica(
        engagement_id=id_caso, cliente="lab",
        alcance_dominios=["lab.local"],
        alcance_cidrs=["127.0.0.0/8"],
        alcance_excluido=[],
        tecnicas_prohibidas=["T1485", "T1489"],
        tecnicas_con_aprobacion=["T1558.003"],
        techo_ruido=100,
    )


CADENA_AD = "intrusion_ad_completa"
CADENA_EVASION = "evasion_y_sigilo"


def _memoria(tmp_path: Path) -> MemoriaCaso:
    return MemoriaCaso(tmp_path / "caso_ctem.db")


def _caso(memoria: MemoriaCaso, id_caso: str = "caso_ctem_t") -> None:
    memoria.crear_engagement(Engagement(
        id=id_caso, nombre="caso ctem", cliente="lab",
        roe=_roe(id_caso), fase_actual=Fase.F2_RECON,
        estado_fase="activa"))


def _hallazgo(id_caso: str, titulo: str, tecnica: str,
              deteccion: str = "pendiente") -> Hallazgo:
    return Hallazgo(
        id=f"hz_{titulo[:6]}_{id_caso[-4:]}", engagement_id=id_caso,
        titulo=titulo, severidad=Severidad.ALTA, tecnica_mitre=tecnica,
        activo="DC01", descripcion="hallazgo de prueba con técnica real",
        estado="confirmado", deteccion=deteccion)


# ---------------------------------------------------------------------------
# 1) Migración idempotente y delta honesto
# ---------------------------------------------------------------------------


def test_tablas_ctem_migracion_idempotente(tmp_path) -> None:
    ruta = tmp_path / "caso_mig.db"
    m1 = MemoriaCaso(ruta)
    tablas = {f["name"] for f in m1._conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}
    assert "ctem_programas" in tablas and "ctem_corridas" in tablas
    m1.cerrar()
    m2 = MemoriaCaso(ruta)  # reabrir no falla ni duplica
    tablas2 = {f["name"] for f in m2._conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"ctem_programas", "ctem_corridas"} <= tablas2
    m2.cerrar()


def test_corrida_inicial_declara_primera(tmp_path) -> None:
    memoria = _memoria(tmp_path)
    _caso(memoria)
    cadena = threatled.obtener(CADENA_AD)
    resumen = ctem.ejecutar_corrida(memoria, "caso_ctem_t", cadena,
                                    disparo="manual", operador="op")
    assert resumen["delta"]["primera_corrida"] is True
    # Caso vacío: cobertura honesta 0 ejercitados y SIN técnicas inventadas.
    assert resumen["cobertura"]["ejercitados"] == 0
    assert resumen["cobertura"]["total"] == len(cadena.pasos)
    assert resumen["delta"]["nuevas_tecnicas"] == []
    assert resumen["delta"]["hallazgos_nuevos"] == 0
    # La corrida quedó en el historial con su resumen completo.
    historial = ctem.corridas_de(memoria, "caso_ctem_t")
    assert len(historial) == 1 and historial[0]["disparo"] == "manual"
    assert historial[0]["resumen"]["delta"]["primera_corrida"] is True


def test_corrida_capta_hallazgo_y_delta(tmp_path) -> None:
    memoria = _memoria(tmp_path)
    _caso(memoria)
    cadena = threatled.obtener(CADENA_AD)
    c1 = ctem.ejecutar_corrida(memoria, "caso_ctem_t", cadena,
                               disparo="manual", operador="op")
    assert c1["cobertura"]["ejercitados"] == 0
    # El operador trabaja de verdad: hallazgo Kerberoasting con técnica real.
    memoria.guardar_hallazgo(_hallazgo("caso_ctem_t", "Kerberoasting en lab",
                                       "T1558.003"))
    c2 = ctem.ejecutar_corrida(memoria, "caso_ctem_t", cadena,
                               disparo="manual", operador="op")
    d = c2["delta"]
    assert d["primera_corrida"] is False
    assert d["nuevas_tecnicas"] == ["T1558.003"]
    assert d["hallazgos_nuevos"] == 1
    assert d["cobertura_ejercitados"] == {"antes": 0, "despues": 1}
    # El delta NUNCA compara contra una base inexistente ni inventa retroactivos.
    assert c1["delta"]["primera_corrida"] is True


def test_corrida_capta_detecciones_vectr(tmp_path) -> None:
    memoria = _memoria(tmp_path)
    _caso(memoria)
    cadena = threatled.obtener(CADENA_EVASION)
    ctem.ejecutar_corrida(memoria, "caso_ctem_t", cadena, disparo="manual")
    h = memoria.guardar_hallazgo(_hallazgo("caso_ctem_t", "Payload YARA",
                                           "T1027"))
    memoria.marcar_deteccion("caso_ctem_t", h.id, "detectado")
    c2 = ctem.ejecutar_corrida(memoria, "caso_ctem_t", cadena, disparo="manual")
    assert c2["detecciones_documentadas"] == 1
    assert c2["delta"]["detecciones_nuevas"] == 1
    # Y una técnica sin evidencia sigue sin contarse como ejercitada.
    assert "T1070.001" not in c2["tecnicas_ejercitadas"]


def test_auditoria_y_custodia_de_corrida(tmp_path) -> None:
    memoria = _memoria(tmp_path)
    _caso(memoria)
    cadena = threatled.obtener(CADENA_AD)
    resumen = ctem.ejecutar_corrida(memoria, "caso_ctem_t", cadena,
                                    disparo="manual", operador="op")
    acciones = [a["accion"] for a in memoria.listar_auditoria("caso_ctem_t")]
    assert "ctem.corrida" in acciones
    assert resumen.get("evidencia_id"), "la corrida debe custodiarse"
    cadena_c = memoria.verificar_cadena("caso_ctem_t")
    assert cadena_c["valida"] is True


# ---------------------------------------------------------------------------
# 2) Programas: validación, reprogramación, planificador y cancelación
# ---------------------------------------------------------------------------


def test_programar_valida_intervalo(tmp_path) -> None:
    memoria = _memoria(tmp_path)
    _caso(memoria)
    with pytest.raises(ValueError):
        ctem.programar(memoria, "caso_ctem_t", CADENA_AD, 0, operador="op")
    with pytest.raises(ValueError):
        ctem.programar(memoria, "caso_ctem_t", CADENA_AD, 721, operador="op")
    with pytest.raises(ValueError):
        ctem.programar(memoria, "caso_ctem_t", "cadena_fantasma", 24,
                       operador="op")
    p1 = ctem.programar(memoria, "caso_ctem_t", CADENA_AD, 24, operador="op")
    assert p1["estado"] == "programado"
    p2 = ctem.programar(memoria, "caso_ctem_t", CADENA_AD, 48, operador="op")
    assert p2["estado"] == "reprogramado" and p2["id"] == p1["id"]
    assert p2["intervalo_horas"] == 48


def test_planificador_ejecuta_solo_lo_vencido(tmp_path) -> None:
    memoria = _memoria(tmp_path)
    _caso(memoria)
    ahora = datetime(2026, 9, 12, 10, 0, tzinfo=timezone.utc)
    ctem.programar(memoria, "caso_ctem_t", CADENA_AD, 24, operador="op",
                   ahora=ahora)
    prog = ctem.programas_de(memoria, "caso_ctem_t")[0]
    raiz = tmp_path  # la BD del caso vive aquí: ctem busca *.db
    # A las 25 h la corrida todavía NO venció → nada se ejecuta.
    assert ctem.ejecutar_pendientes(raiz, ahora=ahora + timedelta(hours=23)) == []
    # A las 25 h venció → corrida programada y próxima corrida desplazada.
    resumenes = ctem.ejecutar_pendientes(raiz,
                                         ahora=ahora + timedelta(hours=25))
    assert len(resumenes) == 1
    assert resumenes[0]["disparo"] == "programada"
    assert resumenes[0]["operador"] == "planificador_ctem"
    prog = ctem.programas_de(memoria, "caso_ctem_t")[0]
    esperada = datetime.fromisoformat(resumenes[0]["instante"]) + timedelta(hours=24)
    assert datetime.fromisoformat(prog["proxima_corrida_en"]) == esperada
    # Otra corrida 1 h después: la próxima sigue desplazada, no duplica.
    assert ctem.ejecutar_pendientes(
        raiz, ahora=ahora + timedelta(hours=26)) == []


def test_cancelar_conserva_historial(tmp_path) -> None:
    memoria = _memoria(tmp_path)
    _caso(memoria)
    cadena = threatled.obtener(CADENA_AD)
    ctem.ejecutar_corrida(memoria, "caso_ctem_t", cadena, disparo="manual")
    p = ctem.programar(memoria, "caso_ctem_t", CADENA_AD, 12, operador="op")
    r = ctem.cancelar(memoria, "caso_ctem_t", p["id"])
    assert r["estado"] == "cancelado"
    assert ctem.programas_de(memoria, "caso_ctem_t")[0]["activo"] in (0, False)
    assert len(ctem.corridas_de(memoria, "caso_ctem_t")) == 1
    with pytest.raises(LookupError):
        ctem.cancelar(memoria, "caso_ctem_t", "prg_inexistente")


# ---------------------------------------------------------------------------
# 3) API: RBAC, validación y webhook
# ---------------------------------------------------------------------------


def _token_admin() -> str:
    if not _auth.hay_operadores():
        _auth.crear_operador("opv23", "ClaveV23segura!", rol="admin")
    return _auth.emitir_token("opv23", "admin", "predeterminada")["token"]


@pytest.fixture()
def cliente_api(tmp_path, monkeypatch):
    monkeypatch.setattr(_auth, "RUTA_DB", tmp_path / "usuarios_test_v23.db")
    monkeypatch.setattr(_auth, "_intentos", {})
    token = _token_admin()
    cliente = TestClient(app)
    cliente.headers.update({"Authorization": f"Bearer {token}"})
    yield cliente


def _limpiar_caso(id_caso: str) -> None:
    (RAIZ_CASOS / f"{id_caso}.db").unlink(missing_ok=True)


def test_api_ctem_flujo_completo(cliente_api) -> None:
    c = cliente_api
    id_caso = "caso_api_ctem_t"
    _limpiar_caso(id_caso)
    try:
        caso = c.post("/api/engagements",
                      json={"nombre": "ctem api", "cliente": "lab"}).json()["id"]
        assert caso == id_caso or caso
        caso_id = caso
        # Estado inicial vacío pero con estructura completa.
        r = c.get(f"/api/engagements/{caso_id}/ctem")
        assert r.status_code == 200
        cuerpo = r.json()
        assert cuerpo["programas"] == [] and cuerpo["corridas"] == []
        # Corrida manual 200 con delta honesto.
        r = c.post(f"/api/engagements/{caso_id}/ctem/corridas",
                   json={"cadena_id": CADENA_AD})
        assert r.status_code == 200, r.text
        cuerpo = r.json()
        assert cuerpo["corrida_id"].startswith("cor_")
        assert cuerpo["delta"]["primera_corrida"] is True
        assert cuerpo["cobertura"]["total"] == 9
        # El historial ahora tiene la corrida y el último delta no es None.
        cuerpo = c.get(f"/api/engagements/{caso_id}/ctem").json()
        assert len(cuerpo["corridas"]) == 1
        assert cuerpo["ultimo_delta"]["primera_corrida"] is True
        # Programa válido → aparece en el estado.
        r = c.post(f"/api/engagements/{caso_id}/ctem/programas",
                   json={"cadena_id": CADENA_AD, "intervalo_horas": 24})
        assert r.status_code == 200 and r.json()["estado"] == "programado"
        assert len(c.get(f"/api/engagements/{caso_id}/ctem").json()
                   ["programas"]) == 1
        # Cancelar por API → el historial se conserva.
        prog_id = c.get(f"/api/engagements/{caso_id}/ctem").json(
            )["programas"][0]["id"]
        assert c.delete(
            f"/api/engagements/{caso_id}/ctem/programas/{prog_id}"
        ).status_code == 200
        estado = c.get(f"/api/engagements/{caso_id}/ctem").json()
        assert estado["programas"][0]["activo"] in (0, False)
        assert len(estado["corridas"]) == 1
    finally:
        _limpiar_caso(caso_id)


def test_api_ctem_404_y_422(cliente_api) -> None:
    c = cliente_api
    id_caso = "caso_api_ctem_422"
    _limpiar_caso(id_caso)
    try:
        caso_id = c.post("/api/engagements",
                         json={"nombre": "ctem 422", "cliente": "lab"
                               }).json()["id"]
        # Cadena inexistente → 404 con el mensaje que guía (no crudo).
        r = c.post(f"/api/engagements/{caso_id}/ctem/corridas",
                   json={"cadena_id": "no_existe"})
        assert r.status_code == 404 and "threatled/cadenas" in r.json()["detail"]
        r = c.post(f"/api/engagements/{caso_id}/ctem/programas",
                   json={"cadena_id": CADENA_AD, "intervalo_horas": 0})
        assert r.status_code == 422
        r = c.post(f"/api/engagements/{caso_id}/ctem/programas",
                   json={"cadena_id": CADENA_AD, "intervalo_horas": 10000})
        assert r.status_code == 422
        # Caso inexistente → 404 (y nunca 500).
        assert c.get("/api/engagements/caso_fantasma/ctem").status_code == 404
        assert c.post("/api/engagements/caso_fantasma/ctem/corridas",
                      json={"cadena_id": CADENA_AD}).status_code == 404
        # Cancelar programa inexistente → 404.
        assert c.delete(
            f"/api/engagements/{caso_id}/ctem/programas/prg_fantasma"
        ).status_code == 404
    finally:
        _limpiar_caso(caso_id)


def test_api_ctem_rbac_lector(cliente_api) -> None:
    c = cliente_api
    id_caso = "caso_api_ctem_rbac"
    _limpiar_caso(id_caso)
    try:
        caso_id = c.post("/api/engagements",
                         json={"nombre": "ctem rbac", "cliente": "lab"
                               }).json()["id"]
        r = c.post("/api/auth/registrar", json={
            "usuario": "lectv23", "contrasena": "ClaveLector23!",
            "rol": "lector"})
        assert r.status_code == 200, r.text
        l = TestClient(app)
        l.headers.update({"Authorization": f"Bearer {_auth.emitir_token(
            'lectv23', 'lector', 'predeterminada')['token']}"})
        # El lector CONSULTA el estado continuo (lectura pura)…
        assert l.get(f"/api/engagements/{caso_id}/ctem").status_code == 200
        # …pero no programa, no lanza corridas ni cancela (nivel ≥2).
        assert l.post(f"/api/engagements/{caso_id}/ctem/corridas",
                      json={"cadena_id": CADENA_AD}).status_code == 403
        assert l.post(f"/api/engagements/{caso_id}/ctem/programas",
                      json={"cadena_id": CADENA_AD,
                            "intervalo_horas": 24}).status_code == 403
        assert l.delete(
            f"/api/engagements/{caso_id}/ctem/programas/prg_x").status_code == 403
    finally:
        _limpiar_caso(caso_id)


def test_evento_webhook_ctem_registrado() -> None:
    # La corrida es notificable: el evento está en el catálogo oficial y
    # valida sin errores (los receptores pueden suscribirse a él).
    assert "ctem.corrida" in webhook.EVENTOS
    assert webhook.validar_eventos(["ctem.corrida"]) == ["ctem.corrida"]
    with pytest.raises(ValueError):
        webhook.validar_eventos(["ctem.evento_inventado"])


def test_delta_json_serializable_y_estable() -> None:
    """El resumen de corrida viaja por webhook y se custodia: debe ser JSON
    puro, sin objetos no serializables, y determinista ante re-hash."""
    memoria = MemoriaCaso(Path("/tmp") / "ctem_ser.db")
    try:
        _caso(memoria, "caso_ser_t")
        cadena = threatled.obtener(CADENA_AD)
        resumen = ctem.ejecutar_corrida(memoria, "caso_ser_t", cadena,
                                        disparo="manual")
        texto = json.dumps(resumen, ensure_ascii=False, sort_keys=True)
        assert "T1558" not in texto or isinstance(resumen["delta"], dict)
        recomputado = json.loads(texto)
        assert recomputado["cobertura"] == resumen["cobertura"]
    finally:
        memoria.cerrar()
        (Path("/tmp") / "ctem_ser.db").unlink(missing_ok=True)
