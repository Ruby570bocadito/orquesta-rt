"""Ronda Z2-5 — ventana de entregas equitativa y catálogo sin deriva.

Cada test fija el contrato de las mejoras de esta ronda:

1.  Poda de entregas POR RECEPTOR (`MAX_ENTREGAS_RECEPTOR`): un receptor
    muy activo ya no desplaza el historial de los demás — antes la poda
    global a MAX_ENTREGAS dejaba que un solo receptor parlanchín se comiera
    la ventana de diagnóstico de los receptores silenciosos.
2.  Poda GLOBAL: se conserva como guarda del tamaño total del registro.
3.  Catálogo de eventos ≡ etiquetas del frontend: todo evento del backend
    tiene etiqueta en la vista Webhooks y toda etiqueta del frontend es un
    evento real (bidireccional) — `ctem.corrida` llevaba desde v23 cayendo
    al nombre crudo en los chips de suscripción y en las filas de entregas.
4.  Resumen de canales en `estado()`: cuando coexisten el canal heredado
    WEBHOOK_URL y receptores de BD, el resumen nombra AMBOS — antes la URL
    del entorno tapaba el recuento de receptores (`url or ...`).
"""
from __future__ import annotations

import re
import sqlite3
from pathlib import Path

import pytest

from orchestrator import webhook


@pytest.fixture()
def webhook_db(tmp_path, monkeypatch):
    monkeypatch.setattr(webhook, "_ruta_db", lambda: tmp_path / "wh_z29.db")
    return tmp_path


def _inserta_directo(webhook_id: str, n: int) -> None:
    """Inserta n entregas SALTANDO la poda (así el test controla el punto de
    partida y ejercita la poda con UNA sola llamada a _registrar_entrega)."""
    webhook._conexion().close()  # garantiza el esquema de la BD temporal
    with sqlite3.connect(str(webhook._ruta_db())) as conn:
        conn.executemany(
            "INSERT INTO webhook_entregas (webhook_id, evento, engagement_id,"
            " ok, http, error, intentos, creado_en) VALUES (?,?,?,?,?,?,?,?)",
            [(webhook_id, "hallazgo.registrado", "caso_z29", 1, 200, None, 1,
              f"2026-09-12T00:{i // 60:02d}:{i % 60:02d}")
             for i in range(n)])


# ---------------------------------------------------------------------------
# 1) Poda POR RECEPTOR: la ventana de diagnóstico es equitativa
# ---------------------------------------------------------------------------

def test_techo_por_receptor_limita_el_historial_del_parlanchin(
        webhook_db) -> None:
    _inserta_directo("whk_parlanchin", webhook.MAX_ENTREGAS_RECEPTOR + 20)
    webhook._registrar_entrega("whk_parlanchin", "hallazgo.registrado",
                               "caso_z29", True, 200, None, 1)
    entregas = webhook.entregas_de("whk_parlanchin", limite=100)
    assert len(entregas) == webhook.MAX_ENTREGAS_RECEPTOR, \
        "un receptor no puede acumular más de su techo de entregas"
    # Se conservan las MÁS RECIENTES: la entrega recién registrada está y la
    # más antigua del bloque inicial ya no.
    assert entregas[0]["engagement_id"] == "caso_z29"


def test_el_parlanchin_no_desplaza_al_silencioso(webhook_db) -> None:
    """El defecto de fondo de la ronda: con la poda solo global, un receptor
    muy activo comía la ventana de los demás y el admin dejaba de ver por qué
    el receptor silencioso no recibía nada."""
    _inserta_directo("whk_parlanchin", webhook.MAX_ENTREGAS_RECEPTOR + 20)
    _inserta_directo("whk_silencioso", 3)
    webhook._registrar_entrega("whk_parlanchin", "hallazgo.registrado",
                               "caso_z29", True, 200, None, 1)
    assert len(webhook.entregas_de("whk_silencioso", limite=100)) == 3, \
        "el historial del receptor silencioso debe sobrevivir íntegro al " \
        "tráfico del parlanchín"


def test_techo_por_receptor_aplica_al_canal_heredado(webhook_db) -> None:
    """El canal heredado registra bajo el id "entorno" (sin fila en la tabla
    webhooks): el techo por receptor también es suyo."""
    _inserta_directo("entorno", webhook.MAX_ENTREGAS_RECEPTOR + 20)
    webhook._registrar_entrega("entorno", "hallazgo.registrado",
                               "caso_z29", True, 200, None, 1)
    assert len(webhook.entregas_de("entorno", limite=100)) == \
        webhook.MAX_ENTREGAS_RECEPTOR


def test_poda_global_sigue_activa_como_guarda(webhook_db, monkeypatch) -> None:
    """Con techos por receptor grandes, la poda GLOBAL sigue limitando el
    tamaño total del registro (guarda del despliegue)."""
    monkeypatch.setattr(webhook, "MAX_ENTREGAS", 25)
    monkeypatch.setattr(webhook, "MAX_ENTREGAS_RECEPTOR", 100)
    _inserta_directo("whk_a", 20)
    _inserta_directo("whk_b", 20)
    webhook._registrar_entrega("whk_a", "hallazgo.registrado",
                               "caso_z29", True, 200, None, 1)
    with sqlite3.connect(str(webhook._ruta_db())) as conn:
        total = conn.execute(
            "SELECT COUNT(*) c FROM webhook_entregas").fetchone()[0]
    assert total <= 25, "la guarda global del tamaño total debe seguir activa"


def test_relacion_entre_techos_es_invariante_de_diseno() -> None:
    """El techo por receptor debe ser estrictamente menor que la poda global:
    si no, un receptor puede llegar a comerse hasta la ventana completa."""
    assert webhook.MAX_ENTREGAS_RECEPTOR < webhook.MAX_ENTREGAS


# ---------------------------------------------------------------------------
# 2) Catálogo de eventos ≡ etiquetas del frontend (contrato bidireccional)
# ---------------------------------------------------------------------------

_RAIZ_REPO = Path(__file__).resolve().parents[2]
_RUTA_TSX = _RAIZ_REPO / "src" / "components" / "consola" / "webhooks.tsx"


def _etiquetas_frontend() -> dict[str, str]:
    """Extrae el catálogo ETIQUETA_EVENTO del componente webhooks.tsx.

    Quita los comentarios de línea (//) antes de buscar claves para que un
    comentario que mencione un evento no se cuele como etiqueta fantasma.
    """
    lineas = _RUTA_TSX.read_text(encoding="utf-8").splitlines()
    bloque: list[str] = []
    dentro = False
    for linea in lineas:
        if linea.strip().startswith("const ETIQUETA_EVENTO"):
            dentro = True
            continue
        if dentro and linea.strip() == "};":
            break
        if dentro:
            bloque.append(linea.split("//")[0])
    return dict(re.findall(r'"([^"]+)"\s*:\s*"([^"]*)"', "\n".join(bloque)))


def test_todo_evento_del_backend_tiene_etiqueta_en_el_frontend() -> None:
    etiquetas = _etiquetas_frontend()
    faltan = [e for e in webhook.EVENTOS if e not in etiquetas]
    assert not faltan, \
        f"eventos sin etiqueta en webhooks.tsx (caen al nombre crudo): {faltan}"


def test_toda_etiqueta_del_frontend_es_un_evento_real() -> None:
    """Dirección inversa: una etiqueta de un evento eliminado del backend es
    basura que confunde al operador (nunca se disparará)."""
    etiquetas = _etiquetas_frontend()
    muertas = [k for k in etiquetas if k not in webhook.EVENTOS]
    assert not muertas, f"etiquetas de eventos inexistentes: {muertas}"


# ---------------------------------------------------------------------------
# 3) Resumen de canales en estado() honesto con ambos canales
# ---------------------------------------------------------------------------

def test_estado_nombra_ambos_canales_cuando_coexisten(webhook_db,
                                                      monkeypatch) -> None:
    monkeypatch.setenv("WEBHOOK_URL", "https://n8n.legacy/hook")
    webhook.crear_webhook("https://mattermost.lab/hook",
                          ["hallazgo.registrado"], secreto="s" * 20)
    webhook.crear_webhook("https://n8n.lab/hook", ["webhook.prueba"],
                          secreto="s" * 20)
    estado = webhook.estado()
    assert estado["servidor"] == \
        "https://n8n.legacy/hook + 2 receptor(es) en BD", \
        "la URL del entorno no puede tapar el recuento de receptores de BD"
    assert estado["configurado"] is True
    assert estado["canal_heredado"] is True


def test_estado_con_solo_canal_heredado(webhook_db, monkeypatch) -> None:
    monkeypatch.setenv("WEBHOOK_URL", "https://n8n.legacy/hook")
    assert webhook.estado()["servidor"] == "https://n8n.legacy/hook"


def test_estado_con_solo_receptores_de_bd(webhook_db, monkeypatch) -> None:
    monkeypatch.delenv("WEBHOOK_URL", raising=False)
    webhook.crear_webhook("https://mattermost.lab/hook",
                          ["hallazgo.registrado"], secreto="s" * 20)
    assert webhook.estado()["servidor"] == "1 receptor(es) en BD"
