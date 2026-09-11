"""Tests del motor de razonamiento adaptativo (razonador.py) y del router
resiliente (circuit breaker, presupuesto, reintentos).

Criterio "cero simulaciones": la cobertura y las prioridades son
deterministas sobre datos reales del caso; el plan IA exige backend real
(sin él → error honesto con requisito exacto) y valida cada paso contra
el catálogo real de transportes.
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi.testclient import TestClient  # noqa: E402

from orchestrator.api import app  # noqa: E402
from orchestrator.memory import MemoriaCaso  # noqa: E402
from orchestrator.models import (  # noqa: E402
    Engagement,
    Fase,
    Hallazgo,
    Objetivo,
    ROEPolitica,
    Severidad,
    TipoObjetivo,
)
from orchestrator import razonador  # noqa: E402
from orchestrator.router import (  # noqa: E402
    PresupuestoAgotado,
    RespuestaRouter,
    RouterModelos,
    TipoModelo,
)


def _caso(tmp_path: Path) -> tuple[MemoriaCaso, str]:
    """Caso real en SQLite temporal con superficie diversa."""
    memoria = MemoriaCaso(tmp_path / "caso_raz.db")
    eid = "caso_raztest01"
    roe = ROEPolitica(
        engagement_id=eid, cliente="Cliente de prueba",
        alcance_dominios=["prueba-lab.local"], alcance_cidrs=["127.0.0.0/8"],
    )
    eng = Engagement(id=eid, nombre="Raz test", cliente="Cliente de prueba", roe=roe)
    memoria.crear_engagement(eng)
    memoria.guardar_objetivo(Objetivo(
        id="obj_d1", engagement_id=eid, nombre="prueba-lab.local",
        tipo=TipoObjetivo.DOMINIO, fase=Fase.F1_OSINT))
    memoria.guardar_objetivo(Objetivo(
        id="obj_h1", engagement_id=eid, nombre="web.prueba-lab.local",
        tipo=TipoObjetivo.HOST, fase=Fase.F1_OSINT))
    memoria.guardar_objetivo(Objetivo(
        id="obj_r1", engagement_id=eid, nombre="/admin", tipo=TipoObjetivo.RUTA,
        estado="riesgo", severidad=Severidad.ALTA, fase=Fase.F1_OSINT))
    memoria.guardar_hallazgo(Hallazgo(
        id="hal_1", engagement_id=eid, titulo="Cabeceras de seguridad ausentes",
        severidad=Severidad.MEDIA, activo="web.prueba-lab.local"))
    return memoria, eid


# ---------------------------------------------------------------------------
# 1) Cobertura determinista
# ---------------------------------------------------------------------------


def test_cobertura_sin_llm_con_datos_reales(tmp_path) -> None:
    memoria, eid = _caso(Path(tmp_path))
    cobertura = razonador.evaluar_cobertura(memoria, eid)
    assert cobertura["objetivos_total"] == 3
    assert cobertura["objetivos_por_tipo"]["dominio"]["total"] == 1
    assert cobertura["hallazgos_por_severidad"]["media"] == 1
    # huecos deterministas: sin DNS ni port_scan ni rutas_sensibles aplicados
    fases_hueco = {h["fase"] for h in cobertura["huecos"]}
    assert "F1" in fases_hueco and "F2" in fases_hueco
    assert cobertura["sin_explorar"]["rutas_en_riesgo"] == ["/admin"]
    memoria.cerrar()


def test_cobertura_detecta_transportes_aplicados(tmp_path) -> None:
    memoria, eid = _caso(Path(tmp_path))
    memoria.registrar_auditoria(
        eid, "sistema", "transporte_ejecutado",
        detalle="transporte recon.dns_enum → prueba-lab.local")
    cobertura = razonador.evaluar_cobertura(memoria, eid)
    assert "recon.dns_enum" in cobertura["transportes_aplicados"]
    # el hueco DNS desaparece de la lista
    assert not any("DNS" in h["hueco"].upper() for h in cobertura["huecos"])
    memoria.cerrar()


def test_cobertura_caso_inexistente(tmp_path) -> None:
    memoria = MemoriaCaso(Path(tmp_path) / "vacío.db")
    try:
        razonador.evaluar_cobertura(memoria, "caso_nadie")
        assert False, "debía fallar"
    except ValueError:
        pass
    memoria.cerrar()


# ---------------------------------------------------------------------------
# 2) Prioridades adaptativas (reglas pures, sin backend)
# ---------------------------------------------------------------------------


def test_prioridades_ruta_en_riesgo_pide_verificacion(tmp_path) -> None:
    memoria, eid = _caso(Path(tmp_path))
    salida = razonador.prioridades_siguientes(memoria, eid)
    herramientas = {p["herramienta"] for p in salida["prioridades"]}
    assert "recon.rutas_sensibles" in herramientas
    top = salida["prioridades"][0]
    assert top["herramienta"] == "recon.rutas_sensibles"  # confianza 0.85 manda
    assert 0 <= top["confianza"] <= 1
    memoria.cerrar()


def test_prioridades_ventana_cerrada_pospone_activos(tmp_path) -> None:
    memoria, eid = _caso(Path(tmp_path))
    # ROE con ventana cerrada TODO el año: el trabajo intrusivo se pospone
    from orchestrator.models import VentanaHoraria
    fila = memoria.obtener_engagement(eid)
    roe = ROEPolitica.model_validate_json(fila["roe_json"])
    roe.ventanas_activas = VentanaHoraria(inicio="03:00", fin="03:01",
                                          dias=["ene"])  # nunca abierta
    memoria.actualizar_roe(eid, roe)
    salida = razonador.prioridades_siguientes(memoria, eid)
    assert salida["ventana_abierta"] is False
    activas = [p for p in salida["prioridades"]
               if p["herramienta"].startswith("recon.port_scan")]
    for p in activas:
        assert p["estado"] == "pospuesta_ventana_cerrada"
    memoria.cerrar()


def test_prioridades_hallazgo_critico_sin_confirmar(tmp_path) -> None:
    memoria, eid = _caso(Path(tmp_path))
    memoria.guardar_hallazgo(Hallazgo(
        id="hal_crit", engagement_id=eid, titulo="Ruta de administración expuesta",
        severidad=Severidad.CRITICA, activo="web.prueba-lab.local",
        estado="propuesto"))
    salida = razonador.prioridades_siguientes(memoria, eid)
    assert any("hallazgo" in p["herramienta"] for p in salida["prioridades"])
    memoria.cerrar()


# ---------------------------------------------------------------------------
# 3) Plan IA: sin backend es honesto; con respuesta valida el catálogo
# ---------------------------------------------------------------------------


def test_planificar_sin_backend_error_honesto(tmp_path) -> None:
    memoria, eid = _caso(Path(tmp_path))
    router = RouterModelos()  # sin API_FRONTERA_BASE ni API_LOCAL_BASE
    try:
        razonador.planificar_fase(memoria, router, eid)
        assert False, "debía exigir backend"
    except RuntimeError as exc:
        assert "API_FRONTERA_BASE" in str(exc) or "API_LOCAL_BASE" in str(exc) \
            or "backend" in str(exc).lower()
    memoria.cerrar()


def test_planificar_valida_catalogo_y_descarta_inventados(tmp_path, monkeypatch) -> None:
    memoria, eid = _caso(Path(tmp_path))
    router = RouterModelos(memoria=memoria, engagement_id=eid)
    router.frontera_base = "http://falso"
    router.frontera_clave = "k"

    def _falso(base, cuerpo):
        contenido = (
            'Plan:\n```json\n{"pasos": ['
            '{"orden": 1, "herramienta": "recon.port_scan", '
            '"objetivo": "web.prueba-lab.local", "justificacion": "mapa", '
            '"confianza": 0.9, "intrusivo": true},'
            '{"orden": 2, "herramienta": "exploit.magico_inventado", '
            '"objetivo": "web.prueba-lab.local", "justificacion": "x", '
            '"confianza": 0.9, "intrusivo": true}'
            ']}\n```')
        return {"choices": [{"message": {"content": contenido}}],
                "usage": {"prompt_tokens": 100, "completion_tokens": 50}}

    monkeypatch.setattr(router, "_post_openai_compat", _falso)
    resultado = razonador.planificar_fase(memoria, router, eid)
    assert len(resultado["pasos"]) == 1
    assert resultado["pasos"][0]["herramienta"] == "recon.port_scan"
    assert resultado["pasos"][0]["ruido"] == "activo"
    assert len(resultado["descartados"]) == 1
    assert "catálogo" in resultado["descartados"][0]["motivo"]
    memoria.cerrar()


def test_planificar_json_roto_no_fabrica_pasos(tmp_path, monkeypatch) -> None:
    memoria, eid = _caso(Path(tmp_path))
    router = RouterModelos(memoria=memoria, engagement_id=eid)
    router.frontera_base = "http://falso"
    router.frontera_clave = "k"

    def _falso(base, cuerpo):
        return {"choices": [{"message": {"content": "lo siento, no puedo"}}],
                "usage": {"prompt_tokens": 10, "completion_tokens": 5}}

    monkeypatch.setattr(router, "_post_openai_compat", _falso)
    resultado = razonador.planificar_fase(memoria, router, eid)
    assert resultado["pasos"] == []
    memoria.cerrar()


def test_reflexion_parsea_confianza(tmp_path, monkeypatch) -> None:
    memoria, eid = _caso(Path(tmp_path))
    router = RouterModelos(memoria=memoria, engagement_id=eid)
    router.frontera_base = "http://falso"
    router.frontera_clave = "k"

    def _falso(base, cuerpo):
        return {"choices": [{"message": {"content":
                "## Observaciones\n3 objetivos.\n"
                "## Huecos\nSin puertos.\n"
                "## Hipótesis\nuna (confianza: 0.7)\n"
                "## Siguientes pasos\nport scan."}}],
                "usage": {"prompt_tokens": 80, "completion_tokens": 40}}

    monkeypatch.setattr(router, "_post_openai_compat", _falso)
    resultado = razonador.reflexion_fase(memoria, router, eid)
    assert resultado["confianza_media"] == 0.7
    assert "## Observaciones" in resultado["reflexion"]
    memoria.cerrar()


# ---------------------------------------------------------------------------
# 4) Router: circuit breaker y presupuesto
# ---------------------------------------------------------------------------


def test_circuito_abierto_enruta_a_local(monkeypatch) -> None:
    router = RouterModelos()
    router.frontera_base = "http://falso"
    router.frontera_clave = "k"
    router.local_base = "http://local-falso"
    for _ in range(3):
        router._registrar_fallo("frontera")
    tipo, modelo, base = router._elegir_modelo("seleccion_exploit")
    assert tipo == TipoModelo.LOCAL
    assert base == "http://local-falso"


def test_circuito_todos_abiertos_error_honesto(monkeypatch) -> None:
    router = RouterModelos()
    router.frontera_base = "http://falso"
    router.frontera_clave = "k"
    router.local_base = "http://local-falso"
    for _ in range(3):
        router._registrar_fallo("frontera")
    for _ in range(3):
        router._registrar_fallo("local")
    try:
        router._elegir_modelo("seleccion_exploit")
        assert False, "debía fallar"
    except RuntimeError as exc:
        assert "circuito abierto" in str(exc)


def test_exito_resetea_circuito() -> None:
    router = RouterModelos()
    router._registrar_fallo("frontera")
    router._registrar_fallo("frontera")
    router._registrar_exito("frontera")
    assert router._circuito_abierto("frontera") is False
    assert router._circuitos["frontera"]["fallos"] == 0


def test_presupuesto_caso_agotado(tmp_path, monkeypatch) -> None:
    memoria, eid = _caso(Path(tmp_path))
    memoria.fijar_config_caso(eid, "presupuesto_caso_tokens", "10")
    # consumo registrado REAL en la BD: 25 tokens ya gastados > techo 10
    from orchestrator.models import UsoTokens, TipoModelo as TM
    memoria.registrar_uso_tokens(eid, UsoTokens(
        fase=Fase.F1_OSINT, modelo="glm-test", tipo=TM.FRONTERA,
        tokens_entrada=20, tokens_salida=5))
    router = RouterModelos(memoria=memoria, engagement_id=eid)
    router.frontera_base = "http://falso"
    router.frontera_clave = "k"
    try:
        router.completar("analisis_caso", "s", "u", Fase.F1_OSINT)
        assert False, "debía bloquear por presupuesto"
    except PresupuestoAgotado:
        pass
    memoria.cerrar()


def test_presupuesto_sin_techo_pasa(tmp_path) -> None:
    memoria, eid = _caso(Path(tmp_path))
    router = RouterModelos(memoria=memoria, engagement_id=eid)
    assert router._presupuesto_caso() == 0  # sin config → sin techo
    memoria.cerrar()


# ---------------------------------------------------------------------------
# 5) API: auth y trazas
# ---------------------------------------------------------------------------


def test_endpoints_razonamiento_exigen_sesion(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("RAIZ_CASOS", str(tmp_path))
    cliente = TestClient(app)
    r = cliente.get("/api/engagements/caso_x/razonamiento/cobertura")
    assert r.status_code == 401
    r = cliente.post("/api/engagements/caso_x/razonamiento/plan")
    assert r.status_code == 401
    r = cliente.get("/api/engagements/caso_x/razonamiento")
    assert r.status_code == 401


def test_trazas_persisten_con_hash(tmp_path) -> None:
    memoria, eid = _caso(Path(tmp_path))
    memoria.guardar_razonamiento(
        eid, "plan_fase", Fase.F1_OSINT, entrada={"a": 1}, salida={"b": 2},
        modelo="glm-test", tipo_modelo="frontera", tokens_entrada=10,
        tokens_salida=5, coste_usd=0.001, confianza=0.8)
    trazas = memoria.listar_razonamientos(eid)
    assert len(trazas) == 1
    t = trazas[0]
    assert t["entrada"]["a"] == 1 and t["salida"]["b"] == 2
    assert len(t["entrada_hash"]) == 64 and len(t["salida_hash"]) == 64
    assert t["confianza"] == 0.8
    # filtro por tipo
    assert len(memoria.listar_razonamientos(eid, tipo="reflexion_fase")) == 0
    memoria.cerrar()
