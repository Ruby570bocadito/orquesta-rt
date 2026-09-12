"""Ronda Z2-10 — salud DERIVADA por receptor en la vista Webhooks.

Propuesta heredada de la sesión 05 (cinco rondas en cola): con
entregas_24h/fallos_24h el admin veía ACTIVIDAD, pero no la pregunta
operacional de verdad: ¿este canal funciona AHORA?

1.  El estado se deriva del RESULTADO DE LA ÚLTIMA entrega retenida:
    "sano" (última = éxito), "con_fallos" (última = fallo) o
    "sin_entregas" (cero entregas registradas). La última fila manda:
    un fallo seguido de éxito es un canal recuperado; un éxito seguido
    de fallo es un canal caído aunque el día tuviera éxitos.
2.  La poda JAMÁS borra la última fila (conserva las últimas N): el
    estado no puede inventarse por retención.
3.  Pings de prueba y reenvíos manuales son POSTs reales: cuentan como
    última entrega (un ping que responde demuestra el canal; un reenvío
    exitoso lo recupera — hilo con la ronda 9).
4.  NO existe el estado "muerto por silencio": el silencio se publica
    como HECHO (ultima_entrega) y la vista lo presenta como información.
    Un receptor suscrito solo a roe.parada_emergencia puede estar meses
    sin tráfico y seguir estando PERFECTAMENTE sano — el juicio de
    "esto está muerto" lo firma un humano, no un umbral.
5.  El canal heredado "entorno" sale del mismo GROUP BY: mismo registro,
    misma salud.
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from orchestrator import webhook


@pytest.fixture()
def webhook_db(tmp_path, monkeypatch):
    monkeypatch.setattr(webhook, "_ruta_db", lambda: tmp_path / "wh_z34.db")
    return tmp_path


def _post_ok(url, cuerpo, cabeceras):
    return {"ok": True, "http": 200, "error": None}


def _post_500(url, cuerpo, cabeceras):
    return {"ok": False, "http": 500, "error": None}


def _entrega(webhook_id: str, ok: bool, carga: dict | None = None) -> None:
    """Despacha una entrega real (única suscripción: hallazgo.registrado)."""
    orig = webhook._post
    webhook._post = _post_ok if ok else _post_500  # type: ignore[assignment]
    try:
        webhook.despachar("hallazgo.registrado", "caso_z34",
                          carga if carga is not None else {"hallazgo_id": "h1"})
    finally:
        webhook._post = orig  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# 1) Estados derivados: la ÚLTIMA fila manda
# ---------------------------------------------------------------------------

def test_salud_sano_tras_exito(webhook_db) -> None:
    alta = webhook.crear_webhook("https://receptor.lab/hook",
                                 ["hallazgo.registrado"], secreto="s" * 20)
    _entrega(alta["id"], ok=True)
    s = webhook.salud_receptores()[alta["id"]]
    assert s["estado"] == "sano"
    assert s["ultima_entrega"] == s["ultimo_exito"]
    assert s["ultimo_fallo"] is None
    # timestamp ISO parseable
    datetime.fromisoformat(s["ultima_entrega"])


def test_salud_con_fallos_tras_fallo_final(webhook_db) -> None:
    alta = webhook.crear_webhook("https://receptor.lab/hook",
                                 ["hallazgo.registrado"], secreto="s" * 20)
    _entrega(alta["id"], ok=True)
    _entrega(alta["id"], ok=False)
    s = webhook.salud_receptores()[alta["id"]]
    assert s["estado"] == "con_fallos"
    # el éxito PREVIO no disimula el estado actual: canal caído ahora
    assert s["ultimo_exito"] is not None
    assert s["ultimo_fallo"] == s["ultima_entrega"]
    datetime.fromisoformat(s["ultimo_fallo"])


def test_salud_recuperado_fallo_luego_exito(webhook_db) -> None:
    alta = webhook.crear_webhook("https://receptor.lab/hook",
                                 ["hallazgo.registrado"], secreto="s" * 20)
    _entrega(alta["id"], ok=False)
    _entrega(alta["id"], ok=True)
    s = webhook.salud_receptores()[alta["id"]]
    assert s["estado"] == "sano"
    # el fallo histórico queda como hecho (útil para el tooltip de la vista)
    assert s["ultimo_fallo"] is not None
    assert s["ultimo_exito"] == s["ultima_entrega"]


def test_salud_solo_fallos_ultimo_exito_ninguno(webhook_db) -> None:
    alta = webhook.crear_webhook("https://receptor.lab/hook",
                                 ["hallazgo.registrado"], secreto="s" * 20)
    _entrega(alta["id"], ok=False)
    s = webhook.salud_receptores()[alta["id"]]
    assert s["estado"] == "con_fallos"
    assert s["ultimo_exito"] is None


def test_salud_sin_entregas_no_aparece(webhook_db) -> None:
    webhook.crear_webhook("https://receptor.lab/hook",
                          ["hallazgo.registrado"], secreto="s" * 20)
    # receptor creado y jamás probado: el backend NO inventa estado
    assert webhook.salud_receptores() == {}


# ---------------------------------------------------------------------------
# 2) Pings y reenvíos: POSTs reales que cuentan como última entrega
# ---------------------------------------------------------------------------

def test_salud_ping_de_prueba_demuestra_canal(webhook_db) -> None:
    alta = webhook.crear_webhook("https://receptor.lab/hook",
                                 ["hallazgo.registrado"], secreto="s" * 20)
    orig = webhook._post
    webhook._post = _post_ok  # type: ignore[assignment]
    try:
        r = webhook.probar_webhook(alta["id"])
        assert r["enviado"] is True
    finally:
        webhook._post = orig  # type: ignore[assignment]
    s = webhook.salud_receptores()[alta["id"]]
    assert s["estado"] == "sano"
    # la fila es un ping (webhook.prueba): la salud no distingue, es un POST real
    historial = webhook.entregas_de(alta["id"])
    assert historial[0]["evento"] == "webhook.prueba"


def test_salud_reenvio_exitoso_recupera_canal(webhook_db, monkeypatch) -> None:
    """Hilo ronda 9→10: arreglar el receptor y reenviar reflja la salud."""
    alta = webhook.crear_webhook("https://receptor.lab/hook",
                                 ["hallazgo.registrado"], secreto="s" * 20)
    _entrega(alta["id"], ok=False, carga={"hallazgo_id": "h-roto"})
    assert webhook.salud_receptores()[alta["id"]]["estado"] == "con_fallos"
    id_fallo = webhook.entregas_de(alta["id"])[0]["id"]
    monkeypatch.setattr(webhook, "_post", _post_ok)
    monkeypatch.setattr(webhook.time, "sleep", lambda s: None)
    webhook.reenviar_entrega(alta["id"], id_fallo)
    s = webhook.salud_receptores()[alta["id"]]
    assert s["estado"] == "sano"
    assert s["ultimo_exito"] == s["ultima_entrega"]


# ---------------------------------------------------------------------------
# 3) La poda jamás borra la última fila: el estado no se inventa
# ---------------------------------------------------------------------------

def test_salud_sobrevive_a_la_poda_de_pings(webhook_db) -> None:
    alta = webhook.crear_webhook("https://receptor.lab/hook",
                                 ["hallazgo.registrado"], secreto="s" * 20)
    orig = webhook._post
    webhook._post = _post_ok  # type: ignore[assignment]
    try:
        for _ in range(webhook.MAX_PINGS_RECEPTOR + 5):
            webhook.probar_webhook(alta["id"])
    finally:
        webhook._post = orig  # type: ignore[assignment]
    # la poda recorta los pings a la cuota, PERO la última fila sigue:
    historial = webhook.entregas_de(alta["id"])
    assert len(historial) <= webhook.MAX_PINGS_RECEPTOR
    s = webhook.salud_receptores()[alta["id"]]
    assert s["estado"] == "sano"
    assert s["ultima_entrega"] == historial[0]["creado_en"]


# ---------------------------------------------------------------------------
# 4) Canal heredado "entorno": mismo registro, misma salud
# ---------------------------------------------------------------------------

def test_salud_canal_heredado_entorno(webhook_db, monkeypatch) -> None:
    monkeypatch.setenv("WEBHOOK_URL", "https://heredado.lab/hook")
    _entrega("entorno", ok=True)
    s = webhook.salud_receptores()["entorno"]
    assert s["estado"] == "sano"
    _entrega("entorno", ok=False)
    assert webhook.salud_receptores()["entorno"]["estado"] == "con_fallos"


def test_salud_bd_rota_devuelve_vacio(webhook_db, monkeypatch) -> None:
    monkeypatch.setattr(webhook, "_ruta_db",
                        lambda: webhook_db / "no_existe.db")
    # la BD no existe hasta la primera _conexion con CREATE TABLE: forzamos
    # una ruta inválida (fichero-directorio) para provocar sqlite3.Error
    webhook_db.mkdir(exist_ok=True)
    ruta_dir = webhook_db / "como_directorio"
    ruta_dir.mkdir(exist_ok=True)
    monkeypatch.setattr(webhook, "_ruta_db", lambda: ruta_dir)
    assert webhook.salud_receptores() == {}


# ---------------------------------------------------------------------------
# 5) Contrato E2E: /api/admin/webhooks expone la salud
# ---------------------------------------------------------------------------

@pytest.fixture()
def cliente_z34(tmp_path, monkeypatch):
    """API aislada con admin + BD de webhooks temporal (patrón rondas 6 y 9)."""
    from fastapi.testclient import TestClient

    from orchestrator import api as api_mod
    from orchestrator import auth as _auth

    monkeypatch.setattr(api_mod, "RAIZ_CASOS", tmp_path / "casos")
    (tmp_path / "casos").mkdir(exist_ok=True)
    monkeypatch.setattr(webhook, "_ruta_db", lambda: tmp_path / "wh_z34_api.db")
    monkeypatch.setattr(_auth, "RUTA_DB", tmp_path / "usuarios_z34.db")
    monkeypatch.setattr(_auth, "_intentos", {})
    _auth.crear_operador("adminz34", "ClaveZ34segura1", rol="admin")
    cliente = TestClient(api_mod.app)

    def _token(usuario: str, clave: str) -> dict[str, str]:
        r = cliente.post("/api/auth/login",
                         json={"usuario": usuario, "contrasena": clave})
        assert r.status_code == 200, r.text
        return {"Authorization": f"Bearer {r.json()['token']}"}

    cliente.token_de = _token  # type: ignore[attr-defined]
    return cliente


def test_api_lista_expone_salud_por_receptor(cliente_z34, monkeypatch) -> None:
    alta = webhook.crear_webhook("https://receptor.lab/hook",
                                 ["hallazgo.registrado"], secreto="s" * 20)
    webhook.crear_webhook("https://virgen.lab/hook",
                          ["aprobacion.solicitada"], secreto="s" * 20)
    _entrega(alta["id"], ok=True)
    _entrega(alta["id"], ok=False)
    r = cliente_z34.get("/api/admin/webhooks",
                        headers=cliente_z34.token_de("adminz34", "ClaveZ34segura1"))
    assert r.status_code == 200, r.text
    receptores = {w["id"]: w for w in r.json()["receptores"]}
    # receptor con tráfico: salud derivada de la ÚLTIMA entrega (falló)
    s = receptores[alta["id"]]["salud"]
    assert s["estado"] == "con_fallos"
    assert s["ultimo_exito"] is not None
    assert s["ultimo_fallo"] == s["ultima_entrega"]
    # receptor virgen: el contrato NO inventa estado — sin_entregas y nulls
    sv = receptores[[i for i in receptores if i != alta["id"]][0]]["salud"]
    assert sv == {"estado": "sin_entregas", "ultima_entrega": None,
                  "ultimo_exito": None, "ultimo_fallo": None}


def test_api_canal_heredado_expone_salud(cliente_z34, monkeypatch) -> None:
    monkeypatch.setenv("WEBHOOK_URL", "https://heredado.lab/hook")
    _entrega("entorno", ok=True)
    r = cliente_z34.get("/api/admin/webhooks",
                        headers=cliente_z34.token_de("adminz34", "ClaveZ34segura1"))
    assert r.status_code == 200, r.text
    canal = r.json()["canal_heredado"]
    assert canal["activo"] is True
    assert canal["salud"]["estado"] == "sano"
    assert canal["salud"]["ultima_entrega"] is not None


def test_api_sin_canal_heredado_no_inventa_salud(cliente_z34, monkeypatch) -> None:
    monkeypatch.delenv("WEBHOOK_URL", raising=False)
    r = cliente_z34.get("/api/admin/webhooks",
                        headers=cliente_z34.token_de("adminz34", "ClaveZ34segura1"))
    assert r.status_code == 200, r.text
    assert r.json()["canal_heredado"] == {"activo": False, "url": ""}
