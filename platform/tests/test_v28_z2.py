"""Ronda Z2-4 — canal heredado visible y contrato de cabeceras.

Cada test fija el contrato de las mejoras de esta ronda:

1.  Contrato de cabeceras webhook: la documentación del módulo declara las
    cinco cabeceras X-Orquesta-* y el despacho no envía NINGUNA más — una
    cabecera nueva exige pasar por la documentación (y por este test).
2.  Canal heredado WEBHOOK_URL: visible en la lista de webhooks (admin) y
    sus entregas consultables bajo el identificador "entorno" — antes un
    despliegue con canal heredado parecía "sin notificaciones".
3.  Cola de aprobaciones: el techo de ruido mostrado es el ROE REAL del
    caso (el 50 hardcodeado mentía con cualquier otro ROE).
"""
from __future__ import annotations

import pytest

from orchestrator import webhook


# ---------------------------------------------------------------------------
# 1) Contrato de cabeceras (documentación ≡ despacho)
# ---------------------------------------------------------------------------

_CABECERAS_CONTRATO = {
    "X-Orquesta-Firma",
    "X-Orquesta-Evento",
    "X-Orquesta-Entrega",
    "X-Orquesta-Intento",
    "X-Orquesta-Id",
}


def test_contrato_cabeceras_documentado_en_el_modulo() -> None:
    doc = webhook.__doc__ or ""
    for cabecera in _CABECERAS_CONTRATO:
        assert cabecera in doc, \
            f"{cabecera} falta en la documentación del módulo webhook: " \
            "el contrato se documenta Y se envía, nunca solo una de las dos"


@pytest.fixture()
def webhook_db(tmp_path, monkeypatch):
    monkeypatch.setattr(webhook, "_ruta_db", lambda: tmp_path / "wh_z28.db")
    return tmp_path


def test_despacho_envia_exactamente_las_cabeceras_del_contrato(
        webhook_db, monkeypatch) -> None:
    alta = webhook.crear_webhook("https://receptor.lab/hook",
                                 ["hallazgo.registrado"], secreto="s" * 20)
    vistas: list[dict[str, str]] = []

    def _post_ok(url, cuerpo, cabeceras):
        vistas.append(dict(cabeceras))
        return {"ok": True, "http": 200, "error": None}

    monkeypatch.setattr(webhook, "_post", _post_ok)
    assert webhook.despachar("hallazgo.registrado", "caso_z28", {}) == 1
    assert set(vistas[0]) == _CABECERAS_CONTRATO, \
        "el despacho no puede añadir cabeceras fuera del contrato documentado"
    assert alta["id"]  # el receptor existe; el test es sobre las cabeceras


# ---------------------------------------------------------------------------
# 2) Canal heredado WEBHOOK_URL: visible y con entregas
# ---------------------------------------------------------------------------


@pytest.fixture()
def cliente_z28(tmp_path, monkeypatch):
    """API aislada con admin + BD de webhooks temporal."""
    from fastapi.testclient import TestClient

    from orchestrator import api as api_mod
    from orchestrator import auth as _auth

    monkeypatch.setattr(api_mod, "RAIZ_CASOS", tmp_path / "casos")
    (tmp_path / "casos").mkdir(exist_ok=True)
    monkeypatch.setattr(webhook, "_ruta_db", lambda: tmp_path / "wh_z28.db")
    monkeypatch.setattr(_auth, "RUTA_DB", tmp_path / "usuarios_z28.db")
    monkeypatch.setattr(_auth, "_intentos", {})
    _auth.crear_operador("adminz28", "ClaveZ28segura1", rol="admin")
    cliente = TestClient(api_mod.app)

    def _token(usuario: str, clave: str) -> dict[str, str]:
        r = cliente.post("/api/auth/login",
                         json={"usuario": usuario, "contrasena": clave})
        assert r.status_code == 200, r.text
        return {"Authorization": f"Bearer {r.json()['token']}"}

    cliente.token_de = _token  # type: ignore[attr-defined]
    return cliente


def test_canal_heredado_activo_aparece_en_la_lista(
        cliente_z28, monkeypatch) -> None:
    monkeypatch.setenv("WEBHOOK_URL", "https://n8n.legacy/hook")
    cabeceras = cliente_z28.token_de("adminz28", "ClaveZ28segura1")
    r = cliente_z28.get("/api/admin/webhooks", headers=cabeceras)
    assert r.status_code == 200
    canal = r.json()["canal_heredado"]
    assert canal["activo"] is True
    assert canal["url"] == "https://n8n.legacy/hook"
    # z2 (ronda 6): el canal heredado lleva también sus métricas de 24 h —
    # sin entregas registradas la ventana cuenta CERO (no inventa actividad).
    assert canal["entregas_24h"] == 0
    assert canal["fallos_24h"] == 0


def test_canal_heredado_inactivo_en_la_lista(cliente_z28, monkeypatch) -> None:
    monkeypatch.delenv("WEBHOOK_URL", raising=False)
    cabeceras = cliente_z28.token_de("adminz28", "ClaveZ28segura1")
    r = cliente_z28.get("/api/admin/webhooks", headers=cabeceras)
    assert r.json()["canal_heredado"] == {"activo": False, "url": ""}


def test_entregas_del_canal_heredado_consultables(
        cliente_z28, monkeypatch) -> None:
    """Las entregas registradas bajo el id "entorno" (canal heredado) son
    consultables por el admin — antes daban 404: el receptor no está en BD."""
    monkeypatch.setenv("WEBHOOK_URL", "https://n8n.legacy/hook")
    # Una entrega real del canal heredado (lo que _receptores_de registra)
    webhook._registrar_entrega("entorno", "hallazgo.registrado", "caso_z28",
                               True, 200, None, 1)
    cabeceras = cliente_z28.token_de("adminz28", "ClaveZ28segura1")
    r = cliente_z28.get("/api/admin/webhooks/entorno/entregas",
                        headers=cabeceras)
    assert r.status_code == 200
    entregas = r.json()
    assert len(entregas) == 1
    assert entregas[0]["ok"] is True and entregas[0]["http"] == 200


def test_entregas_del_canal_heredado_sin_configurar_404(
        cliente_z28, monkeypatch) -> None:
    monkeypatch.delenv("WEBHOOK_URL", raising=False)
    cabeceras = cliente_z28.token_de("adminz28", "ClaveZ28segura1")
    r = cliente_z28.get("/api/admin/webhooks/entorno/entregas",
                        headers=cabeceras)
    assert r.status_code == 404, \
        "sin WEBHOOK_URL el canal heredado no existe (no hay receptor)"


def test_entregas_del_canal_heredado_solo_admin(cliente_z28) -> None:
    # La gestión de webhooks es admin; el canal heredado no es una excepción.
    from orchestrator import auth as _auth
    _auth.crear_operador("lectorz28", "ClaveZ28lectura1", rol="lector")
    r_login = cliente_z28.post("/api/auth/login", json={
        "usuario": "lectorz28", "contrasena": "ClaveZ28lectura1"})
    lector = {"Authorization": f"Bearer {r_login.json()['token']}"}
    r = cliente_z28.get("/api/admin/webhooks/entorno/entregas", headers=lector)
    assert r.status_code == 403
