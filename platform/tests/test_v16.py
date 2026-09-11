"""Tests v16: analítica de cobertura ATT&CK entre campañas y webhooks de
notificación operativa.

Cubre las mejoras de esta ronda:
  1. Cobertura ATT&CK multi-campaña (cobertura_attack.py): matriz técnica ×
     campaña agregada de todos los casos (solo lectura, solo IDs ATT&CK
     válidos), técnicas recurrentes (≥ 2 campañas), cobertura de detección
     por campaña (patrón VECTR), tolerancia a BDs corruptas y CSV.
  2. Webhooks persistentes (webhook.py v16): receptores en BD del
     despliegue con suscripción por evento, entrega real firmada
     (HMAC-SHA256 sobre el cuerpo crudo, cabecera X-Orquesta-Evento),
     registro de entregas, UN reintento ante 5xx y guards admin en la API.
     La entrega se prueba contra un servidor HTTP local real: el receptor
     verifica la firma con hmac.compare_digest.
"""
from __future__ import annotations

import hashlib
import hmac as hmac_mod
import http.server
import json
import sqlite3
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi.testclient import TestClient  # noqa: E402

from orchestrator import auth  # noqa: E402
from orchestrator.api import app, RAIZ_CASOS  # noqa: E402
from orchestrator.cobertura_attack import (  # noqa: E402
    construir_cobertura, csv_cobertura,
)
from orchestrator import webhook  # noqa: E402
from orchestrator.models import (  # noqa: E402
    Aprobacion, Engagement, Fase, Hallazgo, ROEPolitica, Severidad,
)

# ---------------------------------------------------------------------------
# utilidades de montaje
# ---------------------------------------------------------------------------


def _memoria_tmp(ruta: Path, id_caso: str) -> "object":
    from orchestrator.memory import MemoriaCaso

    m = MemoriaCaso(ruta)
    roe = ROEPolitica.model_validate({
        "engagement_id": id_caso, "cliente": "acme",
        "alcance_dominios": ["cliente.com"], "alcance_cidrs": ["192.168.1.0/24"],
    })
    from datetime import datetime, timezone

    ahora = datetime.now(timezone.utc)
    m.crear_engagement(Engagement(
        id=id_caso, nombre=f"caso {id_caso}", cliente="acme", roe=roe,
        fase_actual=Fase.F4_DOMINIO, creado_en=ahora, actualizado_en=ahora))
    return m


def _hal(m, id_caso: str, n: int, tecnica: str | None, sev: Severidad,
         deteccion: str = "pendiente", titulo: str = "hallazgo v16") -> None:
    h = Hallazgo(
        id=f"hal_{n}", engagement_id=id_caso, titulo=titulo, severidad=sev,
        tecnica_mitre=tecnica, estado="confirmado", activo="host01")
    m.guardar_hallazgo(h)
    if deteccion != "pendiente":
        m.marcar_deteccion(id_caso, h.id, deteccion)


def _apr(m, id_caso: str, n: int, tecnica: str) -> None:
    m.crear_aprobacion(Aprobacion(
        id=f"apr_{n}", engagement_id=id_caso, fase=Fase.F3_ACCESO,
        titulo="solicitud", herramienta="mcp.recon", tecnica_mitre=tecnica))


# ---------------------------------------------------------------------------
# 1) cobertura ATT&CK entre campañas
# ---------------------------------------------------------------------------


def test_cobertura_sin_casos(tmp_path) -> None:
    """Sin BDs de caso: estructura vacía honesta, sin relleno ni error."""
    c = construir_cobertura(tmp_path)
    assert c["campañas"] == [] and c["matriz"] == [] and c["recurrentes"] == []
    assert c["totales"]["campañas"] == 0
    assert c["totales"]["cobertura_deteccion_global_pct"] is None


def test_cobertura_multi_campaña_completa(tmp_path) -> None:
    """Dos campañas: matriz técnica × campaña, recurrentes, severidad máxima
    y cobertura de detección por campaña (VECTR)."""
    raiz = tmp_path
    a = _memoria_tmp(raiz / "caso_aaa.db", "caso_aaa")
    _hal(a, "caso_aaa", 1, "T1558.003", Severidad.ALTA, "detectado")
    _hal(a, "caso_aaa", 2, "T1110.001", Severidad.CRITICA, "prevenido")
    _hal(a, "caso_aaa", 3, "T1110.001", Severidad.MEDIA, "no_detectado")
    _hal(a, "caso_aaa", 4, "bananapk", Severidad.ALTA)  # ID inválido: ignorado
    _apr(a, "caso_aaa", 1, "T1566.001")  # intentada sin hallazgo
    a.cerrar()

    b = _memoria_tmp(raiz / "caso_bbb.db", "caso_bbb")
    _hal(b, "caso_bbb", 1, "T1558.003", Severidad.MEDIA, "no_detectado")
    b.cerrar()

    c = construir_cobertura(raiz)
    ids = [x["id"] for x in c["campañas"]]
    assert ids == ["caso_aaa", "caso_bbb"]

    # recurrentes: T1558.003 observada en las DOS campañas
    assert len(c["recurrentes"]) == 1
    assert c["recurrentes"][0]["tecnica"] == "T1558.003"
    assert {x["id"] for x in c["recurrentes"][0]["campanas"]} == {"caso_aaa", "caso_bbb"}

    # matriz: filas ordenadas; T1110.001 con severidad máxima CRITICA en aaa
    filas = {f["tecnica"]: f for f in c["matriz"]}
    assert set(filas) == {"T1110.001", "T1558.003", "T1566.001"}
    celda1110 = filas["T1110.001"]["celdas"]["caso_aaa"]
    assert celda1110["estado"] == "observada"
    assert celda1110["hallazgos"] == 2
    assert celda1110["severidad_max"] == "critica"
    assert celda1110["deteccion"]["prevenido"] == 1
    assert celda1110["deteccion"]["no_detectado"] == 1
    assert celda1110["cobertura_pct"] == 50
    # T1566.001: solo intentada → sin score, sin cobertura
    celda1566 = filas["T1566.001"]["celdas"]["caso_aaa"]
    assert celda1566["estado"] == "intentada"
    assert celda1566["severidad_max"] is None
    assert celda1566["cobertura_pct"] is None
    assert filas["T1110.001"]["celdas"]["caso_bbb"] is None

    # cobertura de detección por campaña: aaa evaluados=3 (det+no+prev)
    camp_a = next(x for x in c["campañas"] if x["id"] == "caso_aaa")
    assert camp_a["deteccion"]["detectado"] == 1
    assert camp_a["deteccion"]["prevenido"] == 1
    assert camp_a["deteccion"]["no_detectado"] == 1
    assert camp_a["cobertura_deteccion_pct"] == 67  # 2/3 redondeo
    assert camp_a["ids_invalidos"] == 1

    # totales globales
    assert c["totales"]["campañas"] == 2
    assert c["totales"]["tecnicas_distintas"] == 3
    assert c["totales"]["ids_invalidos"] == 1
    assert c["totales"]["cobertura_deteccion_global_pct"] == 50  # 2/4 evaluados
    assert c["totales"]["por_severidad"]["alta"] == 1


def test_cobertura_bd_corrupta_omitida(tmp_path) -> None:
    """Un fichero ilegible no rompe la analítica: se anota y se continúa."""
    (tmp_path / "caso_roto.db").write_bytes(b"no es una base de datos")
    m = _memoria_tmp(tmp_path / "caso_ok.db", "caso_ok")
    _hal(m, "caso_ok", 1, "T1003.001", Severidad.BAJA, "detectado")
    m.cerrar()

    c = construir_cobertura(tmp_path)
    assert [x["id"] for x in c["campañas"]] == ["caso_ok"]
    assert len(c["errores"]) == 1 and c["errores"][0]["bd"] == "caso_roto.db"
    assert c["totales"]["tecnicas_distintas"] == 1


def test_csv_cobertura(tmp_path) -> None:
    raiz = tmp_path
    a = _memoria_tmp(raiz / "caso_x1.db", "caso_x1")
    _hal(a, "caso_x1", 1, "T1059.001", Severidad.ALTA, "detectado")
    a.cerrar()
    c = construir_cobertura(raiz)
    texto = csv_cobertura(c)
    lineas = texto.strip().splitlines()
    assert lineas[0] == ("tecnica,campana_id,campana_nombre,estado,hallazgos,"
                         "severidad_max,detectado,no_detectado,prevenido,pendiente")
    partes = lineas[1].split(",")
    assert partes[0] == "T1059.001" and partes[2] == "caso caso_x1"
    assert partes[3] == "observada" and partes[5] == "alta"
    assert partes[6] == "1"  # detectado


def test_cobertura_orden_determinista(tmp_path) -> None:
    """Campañas ordenadas por creación; filas de matriz por ID de técnica."""
    from datetime import datetime, timedelta, timezone

    m2 = _memoria_tmp(tmp_path / "caso_zz2.db", "caso_zz2")
    m2.cerrar()
    m1 = _memoria_tmp(tmp_path / "caso_aa1.db", "caso_aa1")
    # reescribir creado_en para forzar orden: zz2 más antiguo
    conn = sqlite3.connect(str(tmp_path / "caso_zz2.db"))
    viejo = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    conn.execute("UPDATE engagements SET creado_en=? WHERE id='caso_zz2'", (viejo,))
    conn.commit()
    conn.close()
    m1.cerrar()
    c = construir_cobertura(tmp_path)
    assert [x["id"] for x in c["campañas"]] == ["caso_zz2", "caso_aa1"]
    tecnicas = [f["tecnica"] for f in c["matriz"]]
    assert tecnicas == sorted(tecnicas)


# ---------------------------------------------------------------------------
# 2) webhooks de notificación operativa
# ---------------------------------------------------------------------------


class _ReceptorHandler(http.server.BaseHTTPRequestHandler):
    """Receptor HTTP local REAL: captura cabeceras/cuerpo y responde según
    una lista de estados configurada por el test."""
    estados: list[int] = []
    recibidos: list[dict] = []
    lock = threading.Lock()

    def do_POST(self):  # noqa: N802
        longitud = int(self.headers.get("Content-Length", "0"))
        cuerpo = self.rfile.read(longitud)
        with _ReceptorHandler.lock:
            _ReceptorHandler.recibidos.append({
                "cabeceras": dict(self.headers),
                "cuerpo": cuerpo,
            })
            estado = (_ReceptorHandler.estados.pop(0)
                      if _ReceptorHandler.estados else 204)
        self.send_response(estado)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *args):  # silencio en los tests
        pass


@pytest.fixture()
def receptor():
    _ReceptorHandler.estados = []
    _ReceptorHandler.recibidos = []
    servidor = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _ReceptorHandler)
    hilo = threading.Thread(target=servidor.serve_forever, daemon=True)
    hilo.start()
    yield f"http://127.0.0.1:{servidor.server_address[1]}/hook"
    servidor.shutdown()


@pytest.fixture()
def webhooks_tmp(tmp_path, monkeypatch):
    monkeypatch.setattr(webhook, "_ruta_db", lambda: tmp_path / "usuarios_wh_test.db")
    yield


def test_validar_url_y_eventos() -> None:
    with pytest.raises(ValueError):
        webhook.validar_url("ftp://n8n.interno/hook")
    with pytest.raises(ValueError):
        webhook.validar_url("no es una url")
    with pytest.raises(ValueError):
        webhook.validar_url("https://169.254.169.254/latest/meta-data")
    with pytest.raises(ValueError):
        webhook.validar_url("https://metadata.google.internal/computeMetadata")
    assert webhook.validar_url(" http://127.0.0.1:8080/hook ") == "http://127.0.0.1:8080/hook"

    with pytest.raises(ValueError):
        webhook.validar_eventos([])
    with pytest.raises(ValueError):
        webhook.validar_eventos(["evento_inexistente"])
    assert webhook.validar_eventos(["hallazgo.deteccion", "hallazgo.deteccion"]) == \
        ["hallazgo.deteccion"]


def test_crear_y_listar_sin_secretos(webhooks_tmp) -> None:
    creado = webhook.crear_webhook("https://n8n.interno/hook",
                                   ["hallazgo.deteccion"], "", "canal equipo")
    assert creado["secreto_generado"] and len(creado["secreto_generado"]) >= 32
    lista = webhook.listar_webhooks()
    assert len(lista) == 1
    fila = lista[0]
    assert "secreto" not in fila and "secreto_generado" not in fila
    assert fila["tiene_secreto"] is True
    assert fila["eventos"] == ["hallazgo.deteccion"]
    # un secreto explícito corto se rechaza
    with pytest.raises(ValueError):
        webhook.crear_webhook("https://n8n.interno/hook2", ["webhook.prueba"],
                              "corto", "")


def test_entrega_real_firmada_y_registrada(webhooks_tmp, receptor) -> None:
    _ReceptorHandler.estados = [200]
    secreto = "secreto-compartido-de-prueba-32ch"
    creado = webhook.crear_webhook(receptor, ["hallazgo.deteccion"], secreto, "")
    r = webhook.despachar("hallazgo.deteccion", "caso_wh", {"hallazgo_id": "hal_9"})
    assert r == 1

    assert len(_ReceptorHandler.recibidos) == 1
    rec = _ReceptorHandler.recibidos[0]
    cuerpo = rec["cuerpo"]
    firma = rec["cabeceras"].get("X-Orquesta-Firma", "")
    esperada = "sha256=" + hmac_mod.new(secreto.encode(), cuerpo,
                                        hashlib.sha256).hexdigest()
    assert hmac_mod.compare_digest(firma, esperada)  # firma REAL verificada
    assert rec["cabeceras"]["X-Orquesta-Evento"] == "hallazgo.deteccion"
    assert rec["cabeceras"].get("X-Orquesta-Id") == "caso_wh"
    carga = json.loads(cuerpo)
    assert carga["evento"] == "hallazgo.deteccion"
    assert carga["engagement_id"] == "caso_wh"
    assert carga["hallazgo_id"] == "hal_9"

    entregas = webhook.entregas_de(creado["id"])
    assert len(entregas) == 1
    assert entregas[0]["ok"] is True and entregas[0]["http"] == 200
    assert entregas[0]["intentos"] == 1


def test_reintento_ante_5xx_luego_exito(webhooks_tmp, receptor) -> None:
    _ReceptorHandler.estados = [500, 204]
    creado = webhook.crear_webhook(receptor, ["webhook.prueba"], "secreto-32-caracteres-ok!", "")
    r = webhook.probar_webhook(creado["id"])
    assert r["enviado"] is True
    assert len(_ReceptorHandler.recibidos) == 2  # 1er intento falló, 2º OK
    entregas = webhook.entregas_de(creado["id"])
    assert entregas[0]["intentos"] == 2 and entregas[0]["ok"] is True


def test_4xx_no_reintenta(webhooks_tmp, receptor) -> None:
    _ReceptorHandler.estados = [422]
    creado = webhook.crear_webhook(receptor, ["webhook.prueba"], "secreto-32-caracteres-ok!", "")
    r = webhook.probar_webhook(creado["id"])
    assert r["enviado"] is False and r["http"] == 422
    assert len(_ReceptorHandler.recibidos) == 1  # un 4xx es respuesta firme


def test_suscripcion_filtra_eventos(webhooks_tmp, receptor) -> None:
    """Un receptor suscrito a un evento NO recibe los demás."""
    _ReceptorHandler.estados = [200, 200]
    creado = webhook.crear_webhook(receptor, ["webhook.prueba"],
                                   "secreto-32-caracteres-ok!", "")
    webhook.despachar("hallazgo.deteccion", "caso_x", {})
    assert len(_ReceptorHandler.recibidos) == 0  # evento no suscrito: silencio
    webhook.despachar("webhook.prueba", "caso_x", {})
    assert len(_ReceptorHandler.recibidos) == 1
    webhook.eliminar_webhook(creado["id"])
    assert webhook.listar_webhooks() == []
    assert webhook.entregas_de(creado["id"]) == []  # entregas borradas con él


def test_evento_desconocido_no_entrega(webhooks_tmp) -> None:
    assert webhook.despachar("banana.evento", "caso_x", {}) == 0


# ---------------------------------------------------------------------------
# 3) API: guards admin y endpoints de webhooks / cobertura
# ---------------------------------------------------------------------------


@pytest.fixture()
def cliente_api(tmp_path, monkeypatch):
    monkeypatch.setattr(auth, "RUTA_DB", tmp_path / "usuarios_test_v16.db")
    monkeypatch.setattr(auth, "_intentos", {})
    monkeypatch.setattr(webhook, "_ruta_db", lambda: tmp_path / "usuarios_test_v16.db")
    if not auth.hay_operadores():
        auth.crear_operador("opv16", "ClaveV16segura", rol="admin")
    token = auth.emitir_token("opv16", "admin")["token"]
    cliente = TestClient(app)
    cliente.headers.update({"Authorization": f"Bearer {token}"})
    yield cliente


def _operador_normal() -> TestClient:
    if not auth.hay_operadores():
        auth.crear_operador("opv16", "ClaveV16segura", rol="admin")
    auth.crear_operador("operador16", "ClaveOp16segura", rol="operador")
    token = auth.emitir_token("operador16", "operador")["token"]
    cliente = TestClient(app)
    cliente.headers.update({"Authorization": f"Bearer {token}"})
    return cliente


def test_api_webhooks_guards_y_ciclo(cliente_api) -> None:
    # un operador sin rol admin NO gestiona webhooks
    op = _operador_normal()
    assert op.get("/api/admin/webhooks").status_code == 403
    assert op.post("/api/admin/webhooks", json={
        "url": "https://x.interno/h", "eventos": ["webhook.prueba"],
    }).status_code == 403

    # alta admin: URL inválida → 422 accionable
    r = cliente_api.post("/api/admin/webhooks", json={
        "url": "ftp://mal", "eventos": ["webhook.prueba"]})
    assert r.status_code == 422 and "http://" in r.json()["detail"]

    # ciclo completo admin
    r = cliente_api.post("/api/admin/webhooks", json={
        "url": "https://n8n.interno/hook", "eventos": ["hallazgo.deteccion"],
        "descripcion": "canal equipo"})
    assert r.status_code == 200, r.text
    creado = r.json()
    assert creado["secreto_generado"]
    wid = creado["id"]

    lista = cliente_api.get("/api/admin/webhooks").json()
    assert lista["eventos"] and len(lista["receptores"]) == 1
    assert all("secreto" not in w for w in lista["receptores"])

    # PATCH: pausar y resuscribir
    r = cliente_api.patch(f"/api/admin/webhooks/{wid}",
                          json={"activo": False, "eventos": ["webhook.prueba"]})
    assert r.status_code == 200 and r.json()["activo"] is False
    assert r.json()["eventos"] == ["webhook.prueba"]

    # entregas de un id desconocido → 404
    assert cliente_api.get(
        "/api/admin/webhooks/whk_inexistente/entregas").status_code == 404

    # baja
    assert cliente_api.delete(f"/api/admin/webhooks/{wid}").status_code == 200
    assert cliente_api.delete(f"/api/admin/webhooks/{wid}").status_code == 404

    # la gestión quedó en la auditoría de sistema
    audit = cliente_api.get("/api/admin/auditoria-sistema").json()
    acciones = [a["accion"] for a in audit]
    assert "webhook.alta" in acciones and "webhook.baja" in acciones


def _crear_caso_tmp(cliente) -> str:
    r = cliente.post("/api/engagements", json={
        "nombre": "caso v16", "cliente": "acme",
        "alcance_dominios": ["localhost"], "alcance_cidrs": ["127.0.0.0/8"],
    })
    assert r.status_code == 200, r.text
    return r.json()["id"]


def test_post_hallazgo_manual_auditado_y_notificado(cliente_api, receptor) -> None:
    """v16: alta manual de hallazgo (POST) con técnica válida, 422 en
    técnica malformada y 404 en caso inexistente. Auditado como humano y
    notificado de verdad vía el receptor local."""
    _ReceptorHandler.estados = [200, 200, 200]
    r = cliente_api.post("/api/admin/webhooks", json={
        "url": receptor, "eventos": ["hallazgo.registrado", "hallazgo.deteccion"],
        "secreto": "secreto-32-caracteres-ok!"})
    assert r.status_code == 200, r.text
    id_caso = _crear_caso_tmp(cliente_api)
    try:
        # alta válida con técnica (minúsculas: se normaliza)
        r = cliente_api.post(f"/api/engagements/{id_caso}/hallazgos", json={
            "titulo": "Brecha vista en verificación manual",
            "severidad": "alta", "tecnica_mitre": "t1190",
            "activo": "127.0.0.1:8080", "descripcion": "d"})
        assert r.status_code == 200, r.text
        hal = r.json()
        assert hal["tecnica_mitre"] == "T1190"

        # técnica malformada → 422 accionable
        r = cliente_api.post(f"/api/engagements/{id_caso}/hallazgos", json={
            "titulo": "Otra brecha", "severidad": "baja",
            "tecnica_mitre": "sin formato"})
        assert r.status_code == 422 and "T####" in r.json()["detail"]

        # sin técnica es válido (opcional)
        r = cliente_api.post(f"/api/engagements/{id_caso}/hallazgos", json={
            "titulo": "Sin técnica mapeada", "severidad": "informativa"})
        assert r.status_code == 200 and r.json()["tecnica_mitre"] is None

        # el hallazgo está en el listado y la auditoría lo atribuye al operador
        lista = cliente_api.get(f"/api/engagements/{id_caso}/hallazgos").json()
        assert any(h["id"] == hal["id"] for h in lista)
        audit = cliente_api.get(f"/api/engagements/{id_caso}/auditoria").json()
        assert any(ev["accion"] == "hallazgo.registrar" and ev["actor"] == "humano"
                   for ev in audit)

        # caso inexistente → 404
        assert cliente_api.post("/api/engagements/caso_nadie/hallazgos", json={
            "titulo": "El caso no existe", "severidad": "alta"}).status_code == 404

        # el webhook de hallazgo.registrado salió de verdad al receptor
        import time as _time
        for _ in range(25):
            if any(json.loads(e["cuerpo"])["evento"] == "hallazgo.registrado"
                   for e in _ReceptorHandler.recibidos):
                break
            _time.sleep(0.2)
        eventos = [json.loads(e["cuerpo"])["evento"]
                   for e in _ReceptorHandler.recibidos]
        assert "hallazgo.registrado" in eventos
    finally:
        (RAIZ_CASOS / f"{id_caso}.db").unlink(missing_ok=True)


def test_api_webhook_probar_con_receptor_real(cliente_api, receptor) -> None:
    _ReceptorHandler.estados = [200]
    r = cliente_api.post("/api/admin/webhooks", json={
        "url": receptor, "eventos": ["webhook.prueba"], "secreto": "secreto-32-caracteres-ok!"})
    assert r.status_code == 200, r.text
    wid = r.json()["id"]
    r = cliente_api.post(f"/api/admin/webhooks/{wid}/probar")
    assert r.status_code == 200 and r.json()["enviado"] is True
    # el receptor recibió la firma y el ping
    rec = _ReceptorHandler.recibidos[0]
    assert rec["cabeceras"]["X-Orquesta-Evento"] == "webhook.prueba"
    firma = rec["cabeceras"]["X-Orquesta-Firma"]
    esperada = "sha256=" + hmac_mod.new(
        b"secreto-32-caracteres-ok!", rec["cuerpo"], hashlib.sha256).hexdigest()
    assert hmac_mod.compare_digest(firma, esperada)


def test_api_cobertura_attack_estructura_y_csv(cliente_api) -> None:
    r = cliente_api.get("/api/analitica/cobertura-attack")
    assert r.status_code == 200, r.text
    cuerpo = r.json()
    for clave in ("generado", "campañas", "matriz", "recurrentes", "totales", "fuente"):
        assert clave in cuerpo
    assert isinstance(cuerpo["matriz"], list)
    assert "cobertura_deteccion_global_pct" in cuerpo["totales"]

    rc = cliente_api.get("/api/analitica/cobertura-attack.csv")
    assert rc.status_code == 200
    assert "text/csv" in rc.headers["content-type"]
    assert "attachment" in rc.headers["content-disposition"]
    primera = rc.text.strip().splitlines()[0]
    assert primera.startswith("tecnica,campana_id,campana_nombre")


def test_api_cobertura_401_sin_token() -> None:
    cliente = TestClient(app)
    assert cliente.get("/api/analitica/cobertura-attack").status_code == 401
    assert cliente.get("/api/analitica/cobertura-attack.csv").status_code == 401
