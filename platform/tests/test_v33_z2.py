"""Ronda Z2-9 — reenvío MANUAL de entregas webhook fallidas.

Propuesta heredada desde la sesión 05 (tres rondas en cola): hasta ahora
una entrega perdida solo quedaba como FALLO en el historial y el evento se
perdía para siempre para ese receptor. Ahora:

1.  La CARGA ORIGINAL viaja en la propia fila de entrega (columna `carga`,
    migración idempotente guiada por table_info) — sin tabla nueva y con
    la MISMA retención acotada (podas por receptor y global).
2.  `reenviar_entrega` dispara una entrega REAL nueva (uuid, ts y firma
    nuevos) con la MISMA carga y la configuración ACTUAL del receptor
    (rotación de URL/secreto tras arreglarlo = caso de uso principal).
3.  Honestidad: solo fallos reales con carga registrada; los pings no se
    reenvían (se relanzan con Probar); las filas anteriores a la ronda
    (sin carga) se declaran NO reenviables en vez de inventarse contenido;
    el receptor debe existir, estar activo y seguir suscrito; el reenvío
    se registra como fila propia (`reenvio_de` → la ORIGINAL, forma de
    estrella) y entra en las mismas podas y métricas 24 h que cualquier
    entrega real. La carga NO sale por la API del historial.
"""
from __future__ import annotations

import json
import sqlite3

import pytest

from orchestrator import webhook


@pytest.fixture()
def webhook_db(tmp_path, monkeypatch):
    monkeypatch.setattr(webhook, "_ruta_db", lambda: tmp_path / "wh_z33.db")
    return tmp_path


def _fila_cruda(entrega_id: int) -> dict:
    with sqlite3.connect(str(webhook._ruta_db())) as conn:
        conn.row_factory = sqlite3.Row
        f = conn.execute(
            "SELECT * FROM webhook_entregas WHERE id=?", (entrega_id,)).fetchone()
    return dict(f)


def _despacha_con_fallo(webhook_id: str, carga: dict) -> int:
    """Deja una entrega REAL fallida (500 firme) y devuelve su id."""
    def _post_500(url, cuerpo, cabeceras):
        return {"ok": False, "http": 500, "error": None}

    orig_post, orig_sleep = webhook._post, webhook.time.sleep
    webhook._post = _post_500                    # type: ignore[assignment]
    webhook.time.sleep = lambda s: None
    try:
        webhook.despachar("hallazgo.registrado", "caso_z33", carga)
    finally:
        webhook._post, webhook.time.sleep = orig_post, orig_sleep  # type: ignore[assignment]
    return webhook.entregas_de(webhook_id)[0]["id"]


# ---------------------------------------------------------------------------
# 1) Migración idempotente: BDs anteriores a la ronda ganan columnas sin perder datos
# ---------------------------------------------------------------------------

def test_migracion_gana_columnas_sin_perder_datos(tmp_path, monkeypatch) -> None:
    ruta = tmp_path / "wh_legado.db"
    conn = sqlite3.connect(str(ruta))
    conn.executescript("""
        CREATE TABLE webhooks (
            id TEXT PRIMARY KEY, url TEXT NOT NULL,
            secreto TEXT NOT NULL DEFAULT '', eventos TEXT NOT NULL DEFAULT '[]',
            activo INTEGER NOT NULL DEFAULT 1, descripcion TEXT NOT NULL DEFAULT '',
            creado_en TEXT NOT NULL, actualizado_en TEXT NOT NULL);
        CREATE TABLE webhook_entregas (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            webhook_id TEXT NOT NULL, evento TEXT NOT NULL,
            engagement_id TEXT NOT NULL DEFAULT '', ok INTEGER NOT NULL,
            http INTEGER, error TEXT, intentos INTEGER NOT NULL DEFAULT 1,
            creado_en TEXT NOT NULL);
        INSERT INTO webhook_entregas (webhook_id, evento, engagement_id, ok,
            http, error, intentos, creado_en)
            VALUES ('whk_legado', 'hallazgo.registrado', 'caso', 0, 500,
                    NULL, 2, '2026-01-01T00:00:00+00:00');
    """)
    conn.commit()
    conn.close()
    monkeypatch.setattr(webhook, "_ruta_db", lambda: ruta)
    webhook._conexion().close()  # dispara la migración
    with sqlite3.connect(str(ruta)) as c:
        cols = {f[1] for f in c.execute("PRAGMA table_info(webhook_entregas)")}
        assert {"carga", "reenvio_de"} <= cols
        f = c.execute("SELECT webhook_id, ok, carga, reenvio_de"
                      " FROM webhook_entregas").fetchone()
        assert f == ("whk_legado", 0, None, None), "datos legado intactos"


# ---------------------------------------------------------------------------
# 2) El reenvío: nueva entrega real, misma carga, marcada con reenvio_de
# ---------------------------------------------------------------------------

def test_reenvio_de_fallo_real_nueva_entrega_misma_carga(webhook_db, monkeypatch) -> None:
    alta = webhook.crear_webhook("https://receptor.lab/hook",
                                 ["hallazgo.registrado"], secreto="s" * 20)
    carga = {"hallazgo_id": "h1", "titulo": "Enum SMB", "severidad": "alta"}
    id_fallo = _despacha_con_fallo(alta["id"], carga)

    vistas: list[dict[str, str]] = []

    def _post_ok(url, cuerpo, cabeceras):
        vistas.append(dict(cabeceras))
        return {"ok": True, "http": 200, "error": None}

    monkeypatch.setattr(webhook, "_post", _post_ok)
    r = webhook.reenviar_entrega(alta["id"], id_fallo)
    assert r == {"enviado": True, "http": 200, "error": None}

    original = _fila_cruda(id_fallo)
    nuevo = _fila_cruda(webhook.entregas_de(alta["id"])[0]["id"])
    assert original["ok"] == 0, "la fila original sigue mostrando el fallo"
    assert nuevo["id"] != original["id"] and nuevo["ok"] == 1
    assert nuevo["reenvio_de"] == original["id"]
    assert json.loads(nuevo["carga"]) == carga, "misma carga del evento original"
    assert json.loads(original["carga"]) == carga, "la original también la guarda"
    # Misma cabecera contractual (ronda 4) que cualquier entrega: firma,
    # evento e id — con entrega uuid NUEVA y intento 1 (no es un reintento).
    assert vistas and vistas[0]["X-Orquesta-Evento"] == "hallazgo.registrado"
    assert vistas[0]["X-Orquesta-Firma"]
    assert vistas[0]["X-Orquesta-Intento"] == "1"
    assert vistas[0]["X-Orquesta-Id"] == "caso_z33"


def test_re_reenvio_apunta_siempre_a_la_original(webhook_db, monkeypatch) -> None:
    alta = webhook.crear_webhook("https://receptor.lab/hook",
                                 ["hallazgo.registrado"], secreto="s" * 20)
    id_fallo = _despacha_con_fallo(alta["id"], {"hallazgo_id": "h2"})

    def _post_mal(url, cuerpo, cabeceras):
        return {"ok": False, "http": 502, "error": None}

    monkeypatch.setattr(webhook, "_post", _post_mal)
    monkeypatch.setattr(webhook.time, "sleep", lambda s: None)
    r1 = webhook.reenviar_entrega(alta["id"], id_fallo)
    assert r1["enviado"] is False
    id_reenvio1 = webhook.entregas_de(alta["id"])[0]["id"]
    r2 = webhook.reenviar_entrega(alta["id"], id_reenvio1)  # re-reenvío
    assert r2["enviado"] is False
    filas = webhook.entregas_de(alta["id"])
    assert filas[0]["reenvio_de"] == id_fallo and filas[1]["reenvio_de"] == id_fallo, \
        "forma de estrella: los reenvíos apuntan a la ORIGINAL, no en cadena"


# ---------------------------------------------------------------------------
# 3) Honestidad: lo que NO se reenvía y por qué (400 con razón legible)
# ---------------------------------------------------------------------------

def test_reenvio_deniega_entrega_ya_recibida(webhook_db, monkeypatch) -> None:
    alta = webhook.crear_webhook("https://receptor.lab/hook",
                                 ["hallazgo.registrado"], secreto="s" * 20)
    monkeypatch.setattr(webhook, "_post",
                        lambda u, c, h: {"ok": True, "http": 200, "error": None})
    webhook.despachar("hallazgo.registrado", "caso_z33", {"hallazgo_id": "h3"})
    id_ok = webhook.entregas_de(alta["id"])[0]["id"]
    with pytest.raises(ValueError, match="ya llegó"):
        webhook.reenviar_entrega(alta["id"], id_ok)


def test_reenvio_deniega_ping_de_prueba(webhook_db, monkeypatch) -> None:
    alta = webhook.crear_webhook("https://receptor.lab/hook", ["webhook.prueba"],
                                 secreto="s" * 20)
    monkeypatch.setattr(webhook, "_post",
                        lambda u, c, h: {"ok": False, "http": 500, "error": None})
    monkeypatch.setattr(webhook.time, "sleep", lambda s: None)
    webhook.probar_webhook(alta["id"])
    id_ping = webhook.entregas_de(alta["id"])[0]["id"]
    with pytest.raises(ValueError, match="ping"):
        webhook.reenviar_entrega(alta["id"], id_ping)


def test_reenvio_entrega_inexistente(webhook_db) -> None:
    alta = webhook.crear_webhook("https://receptor.lab/hook",
                                 ["hallazgo.registrado"], secreto="s" * 20)
    with pytest.raises(LookupError):
        webhook.reenviar_entrega(alta["id"], 9999)


def test_reenvio_receptor_eliminado(webhook_db) -> None:
    alta = webhook.crear_webhook("https://receptor.lab/hook",
                                 ["hallazgo.registrado"], secreto="s" * 20)
    id_fallo = _despacha_con_fallo(alta["id"], {"hallazgo_id": "h4"})
    webhook.eliminar_webhook(alta["id"])
    with pytest.raises(LookupError):
        webhook.reenviar_entrega(alta["id"], id_fallo)


def test_reenvio_receptor_desactivado(webhook_db) -> None:
    alta = webhook.crear_webhook("https://receptor.lab/hook",
                                 ["hallazgo.registrado"], secreto="s" * 20)
    id_fallo = _despacha_con_fallo(alta["id"], {"hallazgo_id": "h5"})
    webhook.actualizar_webhook(alta["id"], activo=False)
    with pytest.raises(ValueError, match="desactivado"):
        webhook.reenviar_entrega(alta["id"], id_fallo)


def test_reenvio_receptor_desuscrito_del_evento(webhook_db) -> None:
    alta = webhook.crear_webhook("https://receptor.lab/hook",
                                 ["hallazgo.registrado"], secreto="s" * 20)
    id_fallo = _despacha_con_fallo(alta["id"], {"hallazgo_id": "h6"})
    webhook.actualizar_webhook(alta["id"], eventos=["aprobacion.solicitada"])
    with pytest.raises(ValueError, match="suscrito"):
        webhook.reenviar_entrega(alta["id"], id_fallo)


def test_reenvio_fila_legado_sin_carga(webhook_db) -> None:
    """Filas anteriores a la ronda (sin carga): NO reenviables — se declara
    en vez de inventarse un contenido que nunca existió."""
    alta = webhook.crear_webhook("https://receptor.lab/hook",
                                 ["hallazgo.registrado"], secreto="s" * 20)
    id_fallo = _despacha_con_fallo(alta["id"], {"hallazgo_id": "h7"})
    with sqlite3.connect(str(webhook._ruta_db())) as conn:
        conn.execute("UPDATE webhook_entregas SET carga=NULL WHERE id=?",
                     (id_fallo,))
    with pytest.raises(ValueError, match="sin carga"):
        webhook.reenviar_entrega(alta["id"], id_fallo)


# ---------------------------------------------------------------------------
# 4) El historial expone reenvio_de / reenviable; la carga NO viaja
# ---------------------------------------------------------------------------

def test_entregas_de_expone_reenviable_y_reenvio_de(webhook_db, monkeypatch) -> None:
    alta = webhook.crear_webhook("https://receptor.lab/hook",
                                 ["hallazgo.registrado", "webhook.prueba"],
                                 secreto="s" * 20)
    # Fallo real con carga → reenviable.
    id_fallo = _despacha_con_fallo(alta["id"], {"hallazgo_id": "h8"})
    historial = {f["id"]: f for f in webhook.entregas_de(alta["id"])}
    assert historial[id_fallo]["reenviable"] is True
    assert historial[id_fallo]["reenvio_de"] is None
    assert historial[id_fallo]["carga"] is None, "la carga no sale por la API"
    # Ping fallido → NO reenviable (se relanza con Probar).
    monkeypatch.setattr(webhook, "_post",
                        lambda u, c, h: {"ok": False, "http": 500, "error": None})
    monkeypatch.setattr(webhook.time, "sleep", lambda s: None)
    webhook.probar_webhook(alta["id"])
    historial = {f["id"]: f for f in webhook.entregas_de(alta["id"])}
    ping = [f for f in historial.values() if f["evento"] == "webhook.prueba"][0]
    assert ping["reenviable"] is False


def test_reenvio_cuenta_como_entrega_real_en_metricas(webhook_db, monkeypatch) -> None:
    alta = webhook.crear_webhook("https://receptor.lab/hook",
                                 ["hallazgo.registrado"], secreto="s" * 20)
    id_fallo = _despacha_con_fallo(alta["id"], {"hallazgo_id": "h9"})
    monkeypatch.setattr(webhook, "_post",
                        lambda u, c, h: {"ok": True, "http": 200, "error": None})
    webhook.reenviar_entrega(alta["id"], id_fallo)
    metricas = webhook.entregas_24h_por_receptor()
    assert metricas[alta["id"]] == {"entregas_24h": 2, "fallos_24h": 1}, \
        "el reenvío es una entrega real: entra en la misma ventana de 24 h"


# ---------------------------------------------------------------------------
# 5) API: POST /admin/webhooks/{id}/entregas/{eid}/reenviar
# ---------------------------------------------------------------------------

@pytest.fixture()
def cliente_z33(tmp_path, monkeypatch):
    """API aislada con admin + BD de webhooks temporal (patrón ronda 6)."""
    from fastapi.testclient import TestClient

    from orchestrator import api as api_mod
    from orchestrator import auth as _auth

    monkeypatch.setattr(api_mod, "RAIZ_CASOS", tmp_path / "casos")
    (tmp_path / "casos").mkdir(exist_ok=True)
    monkeypatch.setattr(webhook, "_ruta_db", lambda: tmp_path / "wh_z33_api.db")
    monkeypatch.setattr(_auth, "RUTA_DB", tmp_path / "usuarios_z33.db")
    monkeypatch.setattr(_auth, "_intentos", {})
    _auth.crear_operador("adminz33", "ClaveZ33segura1", rol="admin")
    cliente = TestClient(api_mod.app)

    def _token(usuario: str, clave: str) -> dict[str, str]:
        r = cliente.post("/api/auth/login",
                         json={"usuario": usuario, "contrasena": clave})
        assert r.status_code == 200, r.text
        return {"Authorization": f"Bearer {r.json()['token']}"}

    cliente.token_de = _token  # type: ignore[attr-defined]
    return cliente


def test_api_reenvio_flujo_completo_200_400_404(cliente_z33, monkeypatch) -> None:
    alta = webhook.crear_webhook("https://receptor.lab/hook",
                                 ["hallazgo.registrado"], secreto="s" * 20)
    id_fallo = _despacha_con_fallo(alta["id"], {"hallazgo_id": "h10"})
    cabeceras = cliente_z33.token_de("adminz33", "ClaveZ33segura1")

    monkeypatch.setattr(webhook, "_post",
                        lambda u, c, h: {"ok": True, "http": 200, "error": None})
    r = cliente_z33.post(
        f"/api/admin/webhooks/{alta['id']}/entregas/{id_fallo}/reenviar",
        headers=cabeceras)
    assert r.status_code == 200, r.text
    assert r.json() == {"enviado": True, "http": 200, "error": None}

    id_ok = webhook.entregas_de(alta["id"])[0]["id"]
    r400 = cliente_z33.post(
        f"/api/admin/webhooks/{alta['id']}/entregas/{id_ok}/reenviar",
        headers=cabeceras)
    assert r400.status_code == 400 and "ya llegó" in r400.json()["detail"]

    r404 = cliente_z33.post(
        f"/api/admin/webhooks/{alta['id']}/entregas/424242/reenviar",
        headers=cabeceras)
    assert r404.status_code == 404
