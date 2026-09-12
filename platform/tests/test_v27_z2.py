"""Ronda Z2-3 — visibilidad e idempotencia (pulimiento).

Cada test fija el contrato de las mejoras de esta ronda:

1.  Webhook: cada intento de entrega lleva `X-Orquesta-Intento: 1|2`.
    El identificador de entrega (`X-Orquesta-Entrega`) es IGUAL en el
    original y en el reintento — sin la cabecera nueva, el receptor con
    idempotencia no puede distinguirlos y su SIEM puede duplicar la alerta.
2.  Limitador de autenticación: los bloqueos (429) se registran con tope
    duro de memoria y se exponen como métrica operacional en el detalle
    AUTENTICADO de /api/salud (el payload anónimo no revela actividad de
    ataque). Métrica ≠ salud: bloqueos en masa es el limitador funcionando.
"""
from __future__ import annotations

import time

import pytest

from orchestrator import webhook
from orchestrator.api import _LimitadorTasa


# ---------------------------------------------------------------------------
# 1) Webhook: X-Orquesta-Intento (original vs reintento)
# ---------------------------------------------------------------------------


@pytest.fixture()
def webhook_db(tmp_path, monkeypatch):
    monkeypatch.setattr(webhook, "_ruta_db", lambda: tmp_path / "wh_z27.db")
    return tmp_path


class TestCabeceraIntentoZ2:
    def test_intento_1_en_envio_exitoso(self, webhook_db, monkeypatch) -> None:
        alta = webhook.crear_webhook("https://receptor.lab/hook",
                                     ["hallazgo.registrado"], secreto="s" * 20)
        vistas: list[dict[str, str]] = []

        def _post_ok(url, cuerpo, cabeceras):
            vistas.append(dict(cabeceras))
            return {"ok": True, "http": 200, "error": None}

        monkeypatch.setattr(webhook, "_post", _post_ok)
        assert webhook.despachar("hallazgo.registrado", "caso_z27", {}) == 1
        assert len(vistas) == 1
        assert vistas[0]["X-Orquesta-Intento"] == "1"
        assert vistas[0]["X-Orquesta-Evento"] == "hallazgo.registrado"

    def test_reintento_lleva_intento_2_y_misma_entrega(
            self, webhook_db, monkeypatch) -> None:
        """El original y el reintento comparten X-Orquesta-Entrega (mismo
        evento lógico) y se distinguen SOLO por X-Orquesta-Intento."""
        alta = webhook.crear_webhook("https://receptor.lab/hook",
                                     ["hallazgo.registrado"], secreto="s" * 20)
        vistas: list[dict[str, str]] = []

        def _post_falso(url, cuerpo, cabeceras):
            vistas.append(dict(cabeceras))
            if len(vistas) == 1:
                return {"ok": False, "http": None, "error": "red caída"}
            return {"ok": True, "http": 200, "error": None}

        monkeypatch.setattr(webhook, "_post", _post_falso)
        monkeypatch.setattr(webhook.time, "sleep", lambda s: None)
        assert webhook.despachar("hallazgo.registrado", "caso_z27", {}) == 1
        assert len(vistas) == 2, "el error de red debe reintentarse"
        assert vistas[0]["X-Orquesta-Intento"] == "1"
        assert vistas[1]["X-Orquesta-Intento"] == "2"
        assert (vistas[0]["X-Orquesta-Entrega"]
                == vistas[1]["X-Orquesta-Entrega"]), \
            "la entrega es la misma: el reintento se distingue por INTENTO"

    def test_5xx_tambien_es_reintento_2(self, webhook_db, monkeypatch) -> None:
        alta = webhook.crear_webhook("https://receptor.lab/hook",
                                     ["hallazgo.registrado"], secreto="s" * 20)
        intentos_vistos: list[str] = []

        def _post_503(url, cuerpo, cabeceras):
            intentos_vistos.append(cabeceras["X-Orquesta-Intento"])
            return {"ok": False, "http": 503, "error": None}

        monkeypatch.setattr(webhook, "_post", _post_503)
        monkeypatch.setattr(webhook.time, "sleep", lambda s: None)
        assert webhook.despachar("hallazgo.registrado", "caso_z27", {}) == 0
        assert intentos_vistos == ["1", "2"]
        historial = webhook.entregas_de(alta["id"])
        assert historial[0]["intentos"] == 2


# ---------------------------------------------------------------------------
# 2) Limitador de auth: métrica de bloqueos (429) con tope de memoria
# ---------------------------------------------------------------------------


class TestMetricaLimitadorZ2:
    def test_bloqueos_se_registran(self) -> None:
        lim = _LimitadorTasa(maximo=2, ventana_s=60.0)
        assert lim.permitir("ip")[0] is True
        assert lim.permitir("ip")[0] is True
        permitido, reintentar = lim.permitir("ip")
        assert permitido is False and reintentar >= 1
        m = lim.metrica()
        assert m["bloqueos_24h"] == 1, "el 429 debe quedar registrado"
        assert m["claves_activas"] == 1

    def test_la_poda_de_24h_no_cuenta_bloqueos_antiguos(self) -> None:
        lim = _LimitadorTasa(maximo=1, ventana_s=60.0)
        lim.permitir("a")
        lim.permitir("a")  # bloqueo
        lim.permitir("b")  # otra clave
        lim.permitir("b")  # bloqueo
        assert lim.metrica()["bloqueos_24h"] == 2
        # Simula bloqueos de hace 25 h: la métrica los poda al leer.
        viejo = time.time() - 90_000
        lim._bloqueos.clear()
        lim._bloqueos.append(viejo)
        lim._bloqueos.append(time.time())
        assert lim.metrica()["bloqueos_24h"] == 1, \
            "solo cuentan los bloqueos de las últimas 24 h"

    def test_tope_duro_de_memoria_del_registro(self) -> None:
        """Peticiones DENEGADAS tampoco pueden crecer la memoria sin límite
        (un atacante sí genera bloqueos en masa, aunque no controle las
        claves)."""
        lim = _LimitadorTasa(maximo=1, ventana_s=60.0)
        lim.MAX_BLOQUEOS = 5
        for n in range(20):
            lim.permitir(f"atacante-{n}")          # primero: permitido
            lim.permitir(f"atacante-{n}")          # segundo: bloqueado
        assert len(lim._bloqueos) <= 5, \
            "el registro de bloqueos respeta su tope duro (popleft)"

    def test_metrica_no_afecta_a_otras_claves(self) -> None:
        lim = _LimitadorTasa(maximo=1, ventana_s=60.0)
        lim.permitir("normal")
        permitido, _ = lim.permitir("normal")
        assert permitido is False
        # La actividad bloqueada de "normal" no contamina a otras claves...
        assert lim.metrica()["claves_activas"] == 1
        # ...y una clave nueva sigue teniendo presupuesto completo.
        assert lim.permitir("otra")[0] is True


# ---------------------------------------------------------------------------
# 3) /api/salud: métrica SOLO autenticada, y los 429 reales se ven
# ---------------------------------------------------------------------------


@pytest.fixture()
def cliente_z27(tmp_path, monkeypatch):
    """API aislada con limitador REAL (max 3) para provocar 429 de verdad."""
    from fastapi.testclient import TestClient

    from orchestrator import api as api_mod
    from orchestrator import auth as _auth

    monkeypatch.setattr(api_mod, "RAIZ_CASOS", tmp_path / "casos")
    (tmp_path / "casos").mkdir(exist_ok=True)
    monkeypatch.setattr(api_mod, "_limitador_auth",
                        api_mod._LimitadorTasa(maximo=3, ventana_s=60.0))
    monkeypatch.setattr(_auth, "RUTA_DB", tmp_path / "usuarios_z27.db")
    monkeypatch.setattr(_auth, "_intentos", {})
    _auth.crear_operador("adminz27", "ClaveZ27segura1", rol="admin")
    cliente = TestClient(api_mod.app)

    def _token(usuario: str, clave: str) -> dict[str, str]:
        r = cliente.post("/api/auth/login",
                         json={"usuario": usuario, "contrasena": clave})
        assert r.status_code == 200, r.text
        return {"Authorization": f"Bearer {r.json()['token']}"}

    cliente.token_de = _token  # type: ignore[attr-defined]
    return cliente


def test_salud_autenticada_expone_la_metrica_y_anonima_no(cliente_z27) -> None:
    r_anon = cliente_z27.get("/api/salud")
    assert r_anon.status_code == 200
    assert "componentes" not in r_anon.json(), \
        "el payload anónimo no revela nada (z3): ni métrica de bloqueos"
    cabeceras = cliente_z27.token_de("adminz27", "ClaveZ27segura1")
    r_auth = cliente_z27.get("/api/salud", headers=cabeceras)
    assert r_auth.status_code == 200
    componentes = r_auth.json()["componentes"]
    assert "limitador_auth" in componentes, \
        "el detalle autenticado incluye la métrica del limitador"
    metrica = componentes["limitador_auth"]
    assert set(metrica) == {"bloqueos_24h", "claves_activas"}
    assert metrica["bloqueos_24h"] == 0  # solo 1 login correcto: sin bloqueos


def test_429_real_se_refleja_en_la_metrica(cliente_z27) -> None:
    """Fuerza bruta simulada: 4 logins fallidos contra un límite de 3 —
    el cuarto recibe 429 y queda contado en /api/salud autenticada."""
    codigos = [cliente_z27.post(
        "/api/auth/login",
        json={"usuario": "adminz27", "contrasena": "mala"}).status_code
        for _ in range(4)]
    assert codigos[:3] == [401, 401, 401], "fallos de credencial son 401"
    assert codigos[3] == 429, "el cuarto intento agota el presupuesto"
    # La clave del limitador es el último salto de X-Forwarded-For (z3):
    # un cliente legítimo con OTRA IP conserva su presupuesto completo.
    legitimo = cliente_z27.post("/api/auth/login", json={
        "usuario": "adminz27", "contrasena": "ClaveZ27segura1"},
        headers={"X-Forwarded-For": "10.0.0.99, 10.0.0.1"})
    assert legitimo.status_code == 200, legitimo.text
    r = cliente_z27.get("/api/salud", headers={
        "Authorization": f"Bearer {legitimo.json()['token']}",
        "X-Forwarded-For": "10.0.0.99, 10.0.0.1"})
    metrica = r.json()["componentes"]["limitador_auth"]
    assert metrica["bloqueos_24h"] == 1, "el 429 aparece en la métrica"


def test_metrica_no_afecta_al_estado_del_healthcheck(cliente_z27) -> None:
    """La métrica es OPERACIONAL: bloqueos en masa no degradan el estado —
    al contrario, es la defensa funcionando (los sondas de Docker no deben
    marcar el pod como unhealthy porque esté bajo ataque)."""
    for _ in range(5):
        cliente_z27.post("/api/auth/login",
                         json={"usuario": "x", "contrasena": "y"})
    r = cliente_z27.get("/api/salud")
    assert r.status_code == 200
    assert r.json()["estado"] == "ok", \
        "bloqueos de fuerza bruta NO degradan el healthcheck"
