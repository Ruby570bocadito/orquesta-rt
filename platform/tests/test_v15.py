"""Tests v15: purple teaming (detección por hallazgo), paquete Sigma,
respaldo completo VACUUM INTO y reanudación SSE Last-Event-ID.

Cubre las mejoras de esta ronda:
  1. Hallazgo.deteccion (patrón VECTR): columna nueva con migración
     idempotente para BDs antiguas, valor por defecto 'pendiente',
     método marcar_deteccion y endpoint PATCH auditado.
  2. Paquete purple team (purpleteam.py): informe + esqueletos Sigma SOLO
     para técnicas con fuente de logs conocida; técnicas sin fuente
     documentadas como pendientes (política anti-invención); 409 sin
     hallazgos.
  3. Respaldo completo (respaldo.py): VACUUM INTO de usuarios.db + casos
     con manifiesto SHA-256; endpoint solo admin (403 para operador) con
     auditoría de sistema.
  4. SSE: cada evento lleva id: y Last-Event-ID reanuda el flujo desde
     el evento siguiente (sin pérdida del hueco entre reconexiones).
"""
from __future__ import annotations

import io
import itertools
import json
import sqlite3
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi.testclient import TestClient  # noqa: E402

from orchestrator.api import (  # noqa: E402
    app, RAIZ_CASOS, _parse_last_event_id, flujo_eventos_sse,
)
from orchestrator.memory import MemoriaCaso  # noqa: E402
from orchestrator.models import (  # noqa: E402
    Actor, Engagement, Fase, Hallazgo, ROEPolitica, Severidad,
)
from orchestrator.purpleteam import construir_paquete_purple  # noqa: E402
from orchestrator.respaldo import construir_respaldo_completo  # noqa: E402


def _engagement(id_caso: str, fase: Fase = Fase.F3_ACCESO) -> Engagement:
    roe = ROEPolitica.model_validate({
        "engagement_id": id_caso, "cliente": "acme",
        "alcance_dominios": ["cliente.com"],
        "alcance_cidrs": ["192.168.1.0/24"],
    })
    ahora = datetime.now(timezone.utc)
    return Engagement(
        id=id_caso, nombre="caso v15", cliente="acme", roe=roe,
        fase_actual=fase, creado_en=ahora, actualizado_en=ahora,
    )


def _hallazgo(id_caso: str, n: int, tecnica: str | None = None,
              severidad: Severidad = Severidad.ALTA,
              titulo: str = "hallazgo v15", activo: str = "") -> Hallazgo:
    return Hallazgo(
        id=f"h{n}", engagement_id=id_caso, titulo=titulo,
        severidad=severidad, tecnica_mitre=tecnica, estado="confirmado",
        activo=activo,
    )


# ---------------------------------------------------------------------------
# 1) detección por hallazgo: migración + persistencia
# ---------------------------------------------------------------------------


def test_migracion_deteccion_en_bd_antigua(tmp_path) -> None:
    """BD creada con el esquema ANTIGUO (sin columna deteccion): al abrir
    MemoriaCaso la migración añade la columna con 'pendiente' y los
    hallazgos existentes siguen accesibles."""
    ruta = tmp_path / "caso_viejo.db"
    conn = sqlite3.connect(str(ruta))
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS hallazgos (
            id TEXT PRIMARY KEY,
            engagement_id TEXT NOT NULL,
            titulo TEXT NOT NULL,
            severidad TEXT NOT NULL,
            tecnica_mitre TEXT,
            activo TEXT DEFAULT '',
            descripcion TEXT DEFAULT '',
            recomendacion TEXT DEFAULT '',
            estado TEXT NOT NULL DEFAULT 'propuesto',
            evidencias_json TEXT NOT NULL DEFAULT '[]',
            creado_por TEXT NOT NULL,
            creado_en TEXT NOT NULL
        );
    """)
    conn.execute(
        "INSERT INTO hallazgos VALUES ('h9','caso_viejo','antiguo','alta',"
        "NULL,'','','','confirmado','[]','agente','2026-01-01T00:00:00+00:00')")
    conn.commit()
    conn.close()

    memoria = MemoriaCaso(ruta)
    filas = memoria.listar_hallazgos("caso_viejo")
    assert len(filas) == 1
    assert filas[0]["deteccion"] == "pendiente"  # migrada sin inventar resultado
    memoria.cerrar()


def test_guardar_hallazgo_preserva_deteccion(tmp_path) -> None:
    """Re-guardar un hallazgo que ya tiene detección NO la resetea a
    pendiente (columnas explícitas en el INSERT)."""
    id_caso = "caso_det1"
    memoria = MemoriaCaso(tmp_path / f"{id_caso}.db")
    memoria.crear_engagement(_engagement(id_caso))
    h = _hallazgo(id_caso, 1, "T1558.003", activo="svc-sqlprod")
    memoria.guardar_hallazgo(h)
    memoria.marcar_deteccion(id_caso, "h1", "detectado")

    h2 = h.model_copy(update={"descripcion": "actualizado"})
    memoria.guardar_hallazgo(h2)

    filas = memoria.listar_hallazgos(id_caso)
    assert filas[0]["deteccion"] == "detectado"
    assert filas[0]["descripcion"] == "actualizado"
    memoria.cerrar()


def test_marcar_deteccion_inexistente_lanza_keyerror(tmp_path) -> None:
    id_caso = "caso_det2"
    memoria = MemoriaCaso(tmp_path / f"{id_caso}.db")
    memoria.crear_engagement(_engagement(id_caso))
    with pytest.raises(KeyError):
        memoria.marcar_deteccion(id_caso, "h_fantasma", "detectado")
    memoria.cerrar()


# ---------------------------------------------------------------------------
# 2) Endpoint PATCH de detección
# ---------------------------------------------------------------------------


@pytest.fixture()
def cliente_api(tmp_path, monkeypatch):
    from orchestrator import auth

    monkeypatch.setattr(auth, "RUTA_DB", tmp_path / "usuarios_test_v15.db")
    monkeypatch.setattr(auth, "_intentos", {})
    if not auth.hay_operadores():
        auth.crear_operador("opv15", "ClaveV15segura", rol="admin")
    token = auth.emitir_token("opv15", "admin")["token"]
    cliente = TestClient(app)
    cliente.headers.update({"Authorization": f"Bearer {token}"})
    yield cliente


def _crear_caso_tmp(cliente) -> str:
    r = cliente.post("/api/engagements", json={
        "nombre": "caso v15 api", "cliente": "acme",
        "alcance_dominios": ["localhost"], "alcance_cidrs": ["127.0.0.0/8"],
    })
    assert r.status_code == 200, r.text
    return r.json()["id"]


def test_patch_deteccion_ok_auditado_y_en_listado(cliente_api) -> None:
    id_caso = _crear_caso_tmp(cliente_api)
    try:
        memoria = MemoriaCaso(RAIZ_CASOS / f"{id_caso}.db")
        memoria.guardar_hallazgo(_hallazgo(id_caso, 1, "T1558.003"))
        memoria.cerrar()

        r = cliente_api.patch(
            f"/api/engagements/{id_caso}/hallazgos/h1/deteccion",
            json={"deteccion": "no_detectado"})
        assert r.status_code == 200, r.text
        assert r.json() == {"id": "h1", "deteccion": "no_detectado"}

        lista = cliente_api.get(f"/api/engagements/{id_caso}/hallazgos").json()
        assert lista[0]["deteccion"] == "no_detectado"

        # El CSV real incluye la columna nueva (esquema derivado de filas).
        csv_txt = cliente_api.get(
            f"/api/engagements/{id_caso}/hallazgos.csv").text
        assert "deteccion" in csv_txt.splitlines()[0]
        assert "no_detectado" in csv_txt

        memoria = MemoriaCaso(RAIZ_CASOS / f"{id_caso}.db")
        eventos = [dict(e) for e in memoria.listar_auditoria(id_caso)]
        memoria.cerrar()
        assert any(e["accion"] == "hallazgo.deteccion" for e in eventos)
    finally:
        (RAIZ_CASOS / f"{id_caso}.db").unlink(missing_ok=True)


def test_patch_deteccion_404_y_422(cliente_api) -> None:
    id_caso = _crear_caso_tmp(cliente_api)
    try:
        r = cliente_api.patch(
            f"/api/engagements/{id_caso}/hallazgos/h_fantasma/deteccion",
            json={"deteccion": "detectado"})
        assert r.status_code == 404
        r = cliente_api.patch(
            f"/api/engagements/{id_caso}/hallazgos/h1/deteccion",
            json={"deteccion": "inventado"})
        assert r.status_code == 422  # valor fuera del Literal: nunca entra
    finally:
        (RAIZ_CASOS / f"{id_caso}.db").unlink(missing_ok=True)


def test_patch_deteccion_401_sin_token() -> None:
    cliente = TestClient(app)
    r = cliente.patch(
        "/api/engagements/caso_x/hallazgos/h1/deteccion",
        json={"deteccion": "detectado"})
    assert r.status_code == 401


# ---------------------------------------------------------------------------
# 3) Paquete purple team + esqueletos Sigma
# ---------------------------------------------------------------------------


def test_paquete_sigma_solo_tecnicas_conocidas(tmp_path) -> None:
    id_caso = "caso_pt1"
    memoria = MemoriaCaso(tmp_path / f"{id_caso}.db")
    memoria.crear_engagement(_engagement(id_caso))
    memoria.guardar_hallazgo(_hallazgo(id_caso, 1, "T1558.003",
                                       titulo="Kerberoasting", activo="svc-sql"))
    memoria.guardar_hallazgo(_hallazgo(id_caso, 2, "T9999.001",
                                        titulo="técnica sin mapa"))
    memoria.marcar_deteccion(id_caso, "h1", "detectado")
    contenido, resumen = construir_paquete_purple(id_caso, memoria)
    memoria.cerrar()

    zf = zipfile.ZipFile(io.BytesIO(contenido))
    nombres = zf.namelist()
    assert "informe_purple.md" in nombres
    sigma = [n for n in nombres if n.startswith("sigma/") and n.endswith(".yml")]
    assert len(sigma) == 1  # solo la técnica con fuente conocida

    yml = zf.read(sigma[0]).decode()
    assert "EventID: 4769" in yml
    assert "TargetUserName|endswith: 'svc-sql'" in yml
    assert "- attack.t1558.003" in yml
    assert "status: experimental" in yml

    informe = zf.read("informe_purple.md").decode()
    assert "Kerberoasting" in informe
    assert "Detectado" in informe  # resultado registrado por el operador
    assert "T9999.001" in informe  # documentada, no silenciada
    assert resumen == {"hallazgos": 2, "reglas": 1, "sin_fuente": 1}


def test_paquete_purple_409_sin_hallazgos(tmp_path) -> None:
    id_caso = "caso_pt2"
    memoria = MemoriaCaso(tmp_path / f"{id_caso}.db")
    memoria.crear_engagement(_engagement(id_caso))
    with pytest.raises(ValueError, match="sin hallazgos"):
        construir_paquete_purple(id_caso, memoria)
    memoria.cerrar()


def test_endpoint_purple_team_ok_auditado(cliente_api) -> None:
    id_caso = _crear_caso_tmp(cliente_api)
    try:
        memoria = MemoriaCaso(RAIZ_CASOS / f"{id_caso}.db")
        memoria.guardar_hallazgo(_hallazgo(id_caso, 1, "T1558.004",
                                            titulo="AS-REP", activo="asrepcat"))
        memoria.cerrar()

        r = cliente_api.get(f"/api/engagements/{id_caso}/purple-team.zip")
        assert r.status_code == 200, r.text
        assert "attachment" in r.headers.get("content-disposition", "")
        zf = zipfile.ZipFile(io.BytesIO(r.content))
        assert "informe_purple.md" in zf.namelist()
        assert any(n.endswith(".yml") for n in zf.namelist())

        memoria = MemoriaCaso(RAIZ_CASOS / f"{id_caso}.db")
        eventos = [dict(e) for e in memoria.listar_auditoria(id_caso)]
        memoria.cerrar()
        assert any(e["accion"] == "caso.purple_team" for e in eventos)
    finally:
        (RAIZ_CASOS / f"{id_caso}.db").unlink(missing_ok=True)


def test_endpoint_purple_team_409_sin_hallazgos(cliente_api) -> None:
    id_caso = _crear_caso_tmp(cliente_api)
    try:
        r = cliente_api.get(f"/api/engagements/{id_caso}/purple-team.zip")
        assert r.status_code == 409
    finally:
        (RAIZ_CASOS / f"{id_caso}.db").unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# 4) Respaldo completo: VACUUM INTO + manifiesto + guardia admin
# ---------------------------------------------------------------------------


def test_respaldo_completo_zip_y_manifiesto(tmp_path) -> None:
    from orchestrator import auth as _auth

    ruta_usuarios = tmp_path / "usuarios.db"
    conn = sqlite3.connect(str(ruta_usuarios))
    conn.execute("CREATE TABLE t (a INTEGER)")
    conn.commit()
    conn.close()

    casos = tmp_path / "casos"
    casos.mkdir()
    memoria = MemoriaCaso(casos / "caso_bk1.db")
    memoria.crear_engagement(_engagement("caso_bk1"))
    memoria.cerrar()

    zip_bytes, manifiesto = construir_respaldo_completo(casos, ruta_usuarios)
    assert manifiesto["total_bases"] == 2
    nombres = [f["nombre"] for f in manifiesto["ficheros"]]
    assert "usuarios.db" in nombres and "caso_bk1.db" in nombres

    zf = zipfile.ZipFile(io.BytesIO(zip_bytes))
    assert "manifest.json" in zf.namelist()
    for f in manifiesto["ficheros"]:
        assert len(f["sha256"]) == 64
        # Cada snapshot es una BD SQLite válida y verificable.
        cabecera = zf.read(f["nombre"])[:16]
        assert cabecera.startswith(b"SQLite format 3")


def test_endpoint_respaldo_completo_guardia_admin(cliente_api, tmp_path,
                                                  monkeypatch) -> None:
    from orchestrator import auth

    id_caso = _crear_caso_tmp(cliente_api)
    try:
        # Un operador NO admin queda fuera (403).
        auth.crear_operador("opv15op", "ClaveV15operador", rol="operador")
        token_op = auth.emitir_token("opv15op", "operador")["token"]
        cliente_op = TestClient(app)
        cliente_op.headers.update({"Authorization": f"Bearer {token_op}"})
        assert cliente_op.get("/api/admin/respaldo-completo").status_code == 403
        assert cliente_op.get("/api/admin/auditoria-sistema").status_code == 403

        r = cliente_api.get("/api/admin/respaldo-completo")
        assert r.status_code == 200, r.text
        assert "attachment" in r.headers.get("content-disposition", "")
        zf = zipfile.ZipFile(io.BytesIO(r.content))
        assert "manifest.json" in zf.namelist()

        # La acción queda en la auditoría de SISTEMA (nivel despliegue).
        eventos = auth.listar_auditoria_sistema(10)
        assert any(e["accion"] == "sistema.respaldo" for e in eventos)
        r2 = cliente_api.get("/api/admin/auditoria-sistema")
        assert r2.status_code == 200
        assert any(e["accion"] == "sistema.respaldo" for e in r2.json())
    finally:
        (RAIZ_CASOS / f"{id_caso}.db").unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# 5) SSE: id por evento + reanudación con Last-Event-ID
#
# Nota: el TestClient síncrono espera a que la respuesta TERMINE, y el
# flujo SSE es infinito por diseño (reciclado a los 240 s): un GET por
# HTTP colgaría el test. El generador es función de módulo precisamente
# para poder testearlo acotado con itertools.islice + close().
# ---------------------------------------------------------------------------


def _sembrar_eventos(id_caso: str, n: int) -> None:
    memoria = MemoriaCaso(RAIZ_CASOS / f"{id_caso}.db")
    for i in range(n):
        memoria.registrar_auditoria(id_caso, Actor.SISTEMA,
                                     f"prueba.v15.{i}", detalle="sse")
    memoria.cerrar()


def test_parse_last_event_id_seguro() -> None:
    """Cabecera hostil o vacía nunca produce un punto de partida loco."""
    assert _parse_last_event_id(None) is None
    assert _parse_last_event_id("") is None
    assert _parse_last_event_id("banana") is None
    assert _parse_last_event_id("-3") is None
    assert _parse_last_event_id("0x2") is None
    assert _parse_last_event_id("  5  ") == 5
    assert _parse_last_event_id("0") == 0


def test_sse_reanuda_desde_last_event_id(cliente_api) -> None:
    """Con Last-Event-ID el flujo replayea el hueco; con id imposible,
    no. Cada evento lleva su id: estándar SSE."""
    id_caso = _crear_caso_tmp(cliente_api)
    ruta = RAIZ_CASOS / f"{id_caso}.db"
    try:
        _sembrar_eventos(id_caso, 5)
        # El POST de creación ya dejó el evento engagement.crear (rowid 1);
        # los sembrados ocupan los rowids 2..6.

        # Replay completo desde 1: conectado + 5 sembrados + ping.
        gen = flujo_eventos_sse(ruta, id_caso, 1)
        items = list(itertools.islice(gen, 7))
        gen.close()
        assert items[0].startswith('data: {"tipo": "conectado"')
        for n in range(5):
            bloque = items[1 + n]
            assert bloque.startswith(f"id: {2 + n}\n")  # id: estándar SSE
            assert f'prueba.v15.{n}' in bloque
        assert items[6] == ": ping\n\n"  # sin saltos ni duplicados

        # Replay parcial desde el id 3: SOLO rowids 4..6 (sin duplicados).
        gen = flujo_eventos_sse(ruta, id_caso, 3)
        items = list(itertools.islice(gen, 2))
        gen.close()
        assert 'prueba.v15.1' not in items[1]
        assert 'prueba.v15.2' in items[1]
        assert 'prueba.v15.3' not in items[1]

        # Sin Last-Event-ID (conexión nueva): arranca en la cola.
        gen = flujo_eventos_sse(ruta, id_caso, None)
        items = list(itertools.islice(gen, 2))
        gen.close()
        assert "conectado" in items[0]
        assert "prueba.v15." not in items[1]

        # Id imposible (más allá de la cola): cae al final, sin error.
        gen = flujo_eventos_sse(ruta, id_caso, 99999999)
        items = list(itertools.islice(gen, 2))
        gen.close()
        assert "prueba.v15." not in items[1]
    finally:
        ruta.unlink(missing_ok=True)


def test_sse_guias_endpoint_404_y_401(cliente_api) -> None:
    """Los guardias del endpoint devuelven ANTES de abrir el stream
    (seguro para TestClient): 404 caso inexistente y 401 sin token."""
    r = cliente_api.get("/api/engagements/caso_ninguno_v15/eventos",
                        headers={"Last-Event-ID": "3"})
    assert r.status_code == 404
    cliente = TestClient(app)
    r = cliente.get("/api/engagements/caso_x/eventos")
    assert r.status_code == 401


# ---------------------------------------------------------------------------
# 6) Regresión: informe con sección purple team
# ---------------------------------------------------------------------------


def test_informe_incluye_resultado_deteccion(tmp_path) -> None:
    from orchestrator.reporting import construir_informe

    id_caso = "caso_inf15"
    memoria = MemoriaCaso(tmp_path / f"{id_caso}.db")
    memoria.crear_engagement(_engagement(id_caso))
    memoria.guardar_hallazgo(_hallazgo(id_caso, 1, "T1558.003",
                                        titulo="Kerberoasting"))
    memoria.marcar_deteccion(id_caso, "h1", "detectado")
    ruta = construir_informe(id_caso, memoria, carpeta_salida=tmp_path)
    memoria.cerrar()

    texto = ruta.read_text(encoding="utf-8")
    assert "Detección (blue team):" in texto
    assert "Detectado" in texto
    assert "Resultados de detección registrados (purple team)" in texto
