"""Ronda Z2-6 — métricas por receptor y pings que no ensucian el historial.

Cada test fija el contrato de las mejoras de esta ronda:

1.  Métricas de las últimas 24 h por receptor (`entregas_24h_por_receptor`
    + decorado en GET /api/admin/webhooks): el receptor muerto se ve en la
    tarjeta sin abrir el desplegable del historial — y la ventana cuenta
    CERO cuando no hay entregas: no inventa actividad.
2.  Cuota PROPIA para los pings de prueba (`MAX_PINGS_RECEPTOR`): martillear
    el botón Probar no desplaza las entregas REALES del propio receptor
    (ronda 5 igualó los receptores entre sí; la ronda 6 separa ping de
    tráfico real dentro del mismo receptor).
"""
from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from orchestrator import webhook


@pytest.fixture()
def webhook_db(tmp_path, monkeypatch):
    monkeypatch.setattr(webhook, "_ruta_db", lambda: tmp_path / "wh_z30.db")
    return tmp_path


def _inserta_directo(webhook_id: str, n: int, *, evento: str = "hallazgo.registrado",
                     ok: int = 1, hace_horas: float | None = None) -> None:
    """Inserta n entregas SALTANDO la poda; opcionalmente con fecha antigua
    (para probar la ventana de 24 h)."""
    webhook._conexion().close()  # garantiza el esquema de la BD temporal
    if hace_horas is None:
        creado = datetime.now(timezone.utc).isoformat()
    else:
        creado = (datetime.now(timezone.utc)
                  - timedelta(hours=hace_horas)).isoformat()
    with sqlite3.connect(str(webhook._ruta_db())) as conn:
        conn.executemany(
            "INSERT INTO webhook_entregas (webhook_id, evento, engagement_id,"
            " ok, http, error, intentos, creado_en) VALUES (?,?,?,?,?,?,?,?)",
            [(webhook_id, evento, "caso_z30", ok, 200 if ok else 500, None, 1,
              creado) for _ in range(n)])


# ---------------------------------------------------------------------------
# 1) Métricas de 24 h por receptor
# ---------------------------------------------------------------------------

def test_metricas_24h_cuentan_ok_y_fallos(webhook_db) -> None:
    _inserta_directo("whk_a", 3)
    _inserta_directo("whk_a", 2, ok=0)
    metricas = webhook.entregas_24h_por_receptor()
    assert metricas["whk_a"] == {"entregas_24h": 5, "fallos_24h": 2}


def test_metricas_24h_ignoran_lo_anterior_a_la_ventana(webhook_db) -> None:
    _inserta_directo("whk_viejo", 4, hace_horas=48)
    _inserta_directo("whk_viejo", 1, hace_horas=1)
    metricas = webhook.entregas_24h_por_receptor()
    # Solo la entrega de la última hora entra en la ventana de 24 h.
    assert metricas["whk_viejo"] == {"entregas_24h": 1, "fallos_24h": 0}


def test_metricas_24h_sin_entregas_devuelve_vacio(webhook_db) -> None:
    assert webhook.entregas_24h_por_receptor() == {}


@pytest.fixture()
def cliente_z30(tmp_path, monkeypatch):
    """API aislada con admin + BD de webhooks temporal."""
    from fastapi.testclient import TestClient

    from orchestrator import api as api_mod
    from orchestrator import auth as _auth

    monkeypatch.setattr(api_mod, "RAIZ_CASOS", tmp_path / "casos")
    (tmp_path / "casos").mkdir(exist_ok=True)
    monkeypatch.setattr(webhook, "_ruta_db", lambda: tmp_path / "wh_z30.db")
    monkeypatch.setattr(_auth, "RUTA_DB", tmp_path / "usuarios_z30.db")
    monkeypatch.setattr(_auth, "_intentos", {})
    _auth.crear_operador("adminz30", "ClaveZ30segura1", rol="admin")
    cliente = TestClient(api_mod.app)

    def _token(usuario: str, clave: str) -> dict[str, str]:
        r = cliente.post("/api/auth/login",
                         json={"usuario": usuario, "contrasena": clave})
        assert r.status_code == 200, r.text
        return {"Authorization": f"Bearer {r.json()['token']}"}

    cliente.token_de = _token  # type: ignore[attr-defined]
    return cliente


def test_lista_api_decora_metricas_y_canal_heredado(cliente_z30,
                                                    monkeypatch) -> None:
    monkeypatch.setenv("WEBHOOK_URL", "https://n8n.legacy/hook")
    alta = webhook.crear_webhook("https://mattermost.lab/hook",
                                 ["hallazgo.registrado"], secreto="s" * 20)
    webhook.crear_webhook("https://silencio.lab/hook", ["webhook.prueba"],
                          secreto="s" * 20)
    _inserta_directo(alta["id"], 2, ok=0)          # receptor con fallos
    _inserta_directo("entorno", 3)                  # canal heredado sano
    cabeceras = cliente_z30.token_de("adminz30", "ClaveZ30segura1")
    r = cliente_z30.get("/api/admin/webhooks", headers=cabeceras)
    assert r.status_code == 200
    cuerpo = r.json()
    por_id = {w["id"]: w for w in cuerpo["receptores"]}
    assert por_id[alta["id"]]["fallos_24h"] == 2
    assert por_id[alta["id"]]["entregas_24h"] == 2
    # Receptor sin entregas en la ventana: CEROS (no inventa actividad).
    sin = [w for w in cuerpo["receptores"] if w["id"] != alta["id"]][0]
    assert sin["entregas_24h"] == 0 and sin["fallos_24h"] == 0
    # El canal heredado también lleva sus métricas (registradas como "entorno").
    assert cuerpo["canal_heredado"]["entregas_24h"] == 3
    assert cuerpo["canal_heredado"]["fallos_24h"] == 0


# ---------------------------------------------------------------------------
# 2) Cuota propia de los pings de prueba
# ---------------------------------------------------------------------------

def test_los_pings_no_desplazan_las_entregas_reales(webhook_db) -> None:
    """La propiedad central de la ronda: martillear Probar (30 pings) deja
    INTACTO el historial de entregas reales del propio receptor."""
    _inserta_directo("whk_a", 10)  # entregas reales previas
    _inserta_directo("whk_a", 30, evento="webhook.prueba")
    webhook._registrar_entrega("whk_a", "webhook.prueba", "prueba",
                               True, 200, None, 1)
    reales = [e for e in webhook.entregas_de("whk_a", limite=100)
              if e["evento"] != "webhook.prueba"]
    assert len(reales) == 10, \
        "los pings de prueba no pueden desplazar las entregas reales"
    pings = [e for e in webhook.entregas_de("whk_a", limite=100)
             if e["evento"] == "webhook.prueba"]
    assert len(pings) == webhook.MAX_PINGS_RECEPTOR, \
        "los pings tienen su propia cuota (no crecen sin límite)"


def test_ambas_cuotas_se_aplican_a_la_vez(webhook_db) -> None:
    _inserta_directo("whk_a", webhook.MAX_ENTREGAS_RECEPTOR + 30)
    _inserta_directo("whk_a", webhook.MAX_PINGS_RECEPTOR + 30,
                     evento="webhook.prueba")
    webhook._registrar_entrega("whk_a", "hallazgo.registrado", "caso_z30",
                               True, 200, None, 1)
    # El CONTRATO vive en la BD: cada cuota se respeta por separado.
    with sqlite3.connect(str(webhook._ruta_db())) as conn:
        conn.row_factory = sqlite3.Row
        fila = conn.execute(
            "SELECT SUM(CASE WHEN evento != 'webhook.prueba' THEN 1 ELSE 0 END) r,"
            " SUM(CASE WHEN evento = 'webhook.prueba' THEN 1 ELSE 0 END) p"
            " FROM webhook_entregas WHERE webhook_id='whk_a'").fetchone()
    assert fila["r"] == webhook.MAX_ENTREGAS_RECEPTOR, \
        "el techo de entregas reales se respeta con pings presentes"
    assert fila["p"] == webhook.MAX_PINGS_RECEPTOR, \
        "la cuota de pings se respeta con entregas reales presentes"
    # Y la vista sigue acotada a su límite (100 filas en la ventana).
    assert len(webhook.entregas_de("whk_a", limite=100)) == 100


def test_cuota_de_pings_es_menor_que_la_de_entregas() -> None:
    """Invariante de diseño: la cuota de pings es una FRACCIÓN del techo de
    entregas reales (el historial útil de pings es corto)."""
    assert 0 < webhook.MAX_PINGS_RECEPTOR < webhook.MAX_ENTREGAS_RECEPTOR
