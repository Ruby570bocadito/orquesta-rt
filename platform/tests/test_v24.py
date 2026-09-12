"""Tests v24 — threat intel de laboratorio (MISP) + validación Sigma.

Principio de la plataforma: TODO sobre I/O y protocolos reales. El
servidor MISP de laboratorio se levanta en un hilo con sockets de
verdad y el conector oficial (integraciones/misp.py) habla con él de
extremo a extremo. La validación Sigma verifica las reglas que la
plataforma entrega, no "espera que compilen".
"""
from __future__ import annotations

import io
import json
import sys
import threading
import zipfile
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lab"))

from orchestrator import auth as _auth  # noqa: E402
from orchestrator.api import RAIZ_CASOS, app  # noqa: E402
from orchestrator.memory import MemoriaCaso  # noqa: E402
from orchestrator.models import (  # noqa: E402
    Actor, Engagement, Fase, Hallazgo, ROEPolitica, Severidad,
)
from orchestrator.purpleteam import (  # noqa: E402
    construir_paquete_purple, reglas_sigma_caso,
)
from orchestrator.sigma_valid import validar_lote, validar_regla  # noqa: E402
from integraciones import misp  # noqa: E402
import servidor_misp_lab  # noqa: E402

# ---------------------------------------------------------------------------
# Utilidades de caso (mismos patrones que v23)
# ---------------------------------------------------------------------------


def _roe(id_caso: str) -> ROEPolitica:
    return ROEPolitica(
        engagement_id=id_caso, cliente="lab",
        alcance_dominios=["lab.local"],
        alcance_cidrs=["127.0.0.0/8"],
        alcance_excluido=[], techo_ruido=100)


def _caso_con_hallazgo(tmp_path: Path, id_caso: str = "caso_v24_t",
                       tecnica: str = "T1558.003") -> MemoriaCaso:
    memoria = MemoriaCaso(tmp_path / f"{id_caso}.db")
    memoria.crear_engagement(Engagement(
        id=id_caso, nombre="caso v24", cliente="lab",
        roe=_roe(id_caso), fase_actual=Fase.F2_RECON, estado_fase="activa"))
    memoria.guardar_hallazgo(Hallazgo(
        id=f"hz_v24_{id_caso[-4:]}", engagement_id=id_caso,
        titulo="Kerberoasting sin detección", severidad=Severidad.ALTA,
        tecnica_mitre=tecnica, activo="svc-backup",
        descripcion="Solicitudes de tickets RC4 masivas contra el SPN",
        estado="confirmado", deteccion="no_detectado"))
    return memoria


# ---------------------------------------------------------------------------
# 1) Servidor MISP de laboratorio: protocolo REAL sobre sockets reales
# ---------------------------------------------------------------------------

_CLAVE_LAB = "clave-lab-misp"


@pytest.fixture(scope="module")
def servidor_misp():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0),
                                servidor_misp_lab.ManejadorMispLab)
    hilo = threading.Thread(target=httpd.serve_forever, daemon=True)
    hilo.start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()


@pytest.fixture(autouse=True)
def _intel_limpio(monkeypatch):
    # Estado semilla fresco por test: los eventos creados en un test no
    # contaminan al siguiente.
    servidor_misp_lab._INTEL.clear()
    servidor_misp_lab._INTEL.update(servidor_misp_lab._intel_inicial())


@pytest.fixture()
def misp_lab(servidor_misp, monkeypatch):
    monkeypatch.setenv("MISP_URL", servidor_misp)
    monkeypatch.setenv("MISP_KEY", _CLAVE_LAB)
    monkeypatch.setenv("MISP_SSL", "0")
    return servidor_misp


def test_misp_lab_estado_version_real(misp_lab) -> None:
    estado = misp.estado()
    assert estado["conectado"] is True
    assert estado["version"].startswith("2.4")
    assert estado["servidor"] == misp_lab


def test_misp_lab_coincidencia_ioc_semilla(misp_lab) -> None:
    r = misp.buscar_iocs(["acme-demo.local", "10.20.0.10"])
    assert r["conectado"] is True and r["total"] == 2
    valores = {c["valor"] for c in r["coincidencias"]}
    assert "acme-demo.local" in valores and "10.20.0.10" in valores
    for c in r["coincidencias"]:
        assert c["to_ids"] is True
        assert "lab" in c["tags"]


def test_misp_lab_valores_invalidos_rechazados(misp_lab) -> None:
    r = misp.buscar_iocs(["<script>alert(1)</script>", ""])
    assert r["conectado"] is False
    assert "Sin valores válidos" in r["error"]


def test_misp_lab_eventos_recientes_por_tag(misp_lab) -> None:
    r = misp.eventos_recientes(tag="dir:ad", dias=30)
    assert r["conectado"] is True and r["total"] == 1
    assert "Infraestructura interna ACME" in r["eventos"][0]["info"]


def test_misp_lab_exportar_hallazgo_roundtrip(misp_lab) -> None:
    # Exportar un hallazgo del engagement al intel…
    r = misp.crear_evento(
        "Hallazgo Kerberoasting caso v24",
        [{"tipo": "hostname", "valor": "dc01.lab.local",
          "categoria": "Network activity", "comentario": "exportado"}])
    assert r["conectado"] is True and r["evento_id"]
    # …y el IOC exportado ya es buscable (round-trip completo).
    b = misp.buscar_iocs(["dc01.lab.local"])
    assert b["conectado"] is True and b["total"] == 1
    assert b["coincidencias"][0]["evento_id"] == r["evento_id"]


def test_misp_lab_clave_incorrecta_rechazada(servidor_misp,
                                             monkeypatch) -> None:
    monkeypatch.setenv("MISP_URL", servidor_misp)
    monkeypatch.setenv("MISP_KEY", "clave-erronea")
    monkeypatch.setenv("MISP_SSL", "0")
    estado = misp.estado()
    assert estado["conectado"] is False


def test_misp_lab_persistencia_estado(misp_lab, tmp_path) -> None:
    ruta = tmp_path / "misp_lab.json"
    servidor_misp_lab._RUTA_ESTADO = ruta
    try:
        misp.crear_evento("evento persistente",
                          [{"tipo": "domain", "valor": "persistente.local"}])
        assert ruta.exists()
        datos = json.loads(ruta.read_text(encoding="utf-8"))
        assert any(e["info"] == "evento persistente"
                   for e in datos["eventos"])
    finally:
        servidor_misp_lab._RUTA_ESTADO = None


# ---------------------------------------------------------------------------
# 2) Validación Sigma: veredicto estructural, no "esperamos que compile"
# ---------------------------------------------------------------------------

_REGLA_OK = """
title: Kerberoasting - cuenta de servicio
id: 12345678-1234-5678-1234-567812345678
status: experimental
description: |
    Solicitudes de tickets Kerberos RC4 contra un SPN de servicio.
author: Operador OrquestaRT
date: 2026-09-12
logsource:
    product: windows
    service: security
detection:
    selection_evento:
        EventID: 4769
    selection_entorno:
        TargetUserName|endswith: 'svc-backup'
    condition: selection_evento and selection_entorno
tags:
    - attack.t1558.003
level: high
"""


def test_sigma_regla_valida() -> None:
    r = validar_regla(_REGLA_OK)
    assert r["valida"] is True, r["errores"]
    assert r["logsource"] == {"product": "windows", "service": "security"}
    assert "attack.t1558.003" in r["tags"]
    assert r["motor_profundo"]  # siempre informa el motor usado


def test_sigma_condicion_referencia_inexistente() -> None:
    rota = _REGLA_OK.replace("condition: selection_evento and selection_entorno",
                             "condition: selection_evento and selection_fantasma")
    r = validar_regla(rota)
    assert r["valida"] is False
    assert any("selection_fantasma" in e for e in r["errores"])


def test_sigma_yaml_roto_y_campos_obligatorios() -> None:
    r = validar_regla("title: [esto no es yaml válido")
    assert r["valida"] is False and any("yaml" in e for e in r["errores"])
    # id no-UUID
    r2 = validar_regla(_REGLA_OK.replace(
        "id: 12345678-1234-5678-1234-567812345678", "id: identificador-falso"))
    assert r2["valida"] is False and any("UUID" in e for e in r2["errores"])
    # logsource sin ninguna clave válida (solo definition, que no basta)
    r3 = validar_regla(_REGLA_OK.replace(
        "logsource:\n    product: windows\n    service: security\n",
        "logsource:\n    definition: sin category/product/service\n"))
    assert r3["valida"] is False and any("logsource" in e for e in r3["errores"])


def test_sigma_condicion_comodin_y_cuantificadores() -> None:
    # "1 of selection_*" es sintaxis oficial: debe resolver el comodín.
    r = validar_regla(_REGLA_OK.replace(
        "condition: selection_evento and selection_entorno",
        "condition: 1 of selection_*"))
    assert r["valida"] is True, r["errores"]
    # "all of them" no referencia ninguna selección: válido.
    r2 = validar_regla(_REGLA_OK.replace(
        "condition: selection_evento and selection_entorno",
        "condition: all of them"))
    assert r2["valida"] is True, r2["errores"]


def test_sigma_tags_y_avisos() -> None:
    # Tag con caracteres inválidos → error estructural.
    r = validar_regla(_REGLA_OK.replace("- attack.t1558.003",
                                        "- tecnicas!raras"))
    assert r["valida"] is False
    assert any("namespace" in e for e in r["errores"])
    # Tag sin namespace.category → aviso de higiene (no error).
    r0 = validar_regla(_REGLA_OK.replace("- attack.t1558.003",
                                         "- etiqueta_simple"))
    assert r0["valida"] is True
    assert any("namespace" in a for a in r0["avisos"])
    # Sin tag ATT&CK → aviso (no error): la regla puede ser genérica.
    r2 = validar_regla(_REGLA_OK.replace("    - attack.t1558.003\n", ""))
    assert r2["valida"] is True
    assert any("attack.t" in a for a in r2["avisos"])


def test_sigma_lote_resumen_agregado() -> None:
    lote = validar_lote({"ok.yml": _REGLA_OK,
                         "rota.yml": "title: [x",
                         "fantasma.yml": _REGLA_OK.replace(
                             "condition: selection_evento and selection_entorno",
                             "condition: fantasma")})
    assert lote["total"] == 3
    assert lote["validas"] == 1 and lote["invalidas"] == 2
    assert [d["nombre"] for d in lote["reglas"]] == ["ok.yml", "rota.yml",
                                                     "fantasma.yml"]


# ---------------------------------------------------------------------------
# 3) Integración con el paquete purple team: mismas reglas, veredicto real
# ---------------------------------------------------------------------------


def test_purple_reglas_sigma_del_caso_validas(tmp_path) -> None:
    memoria = _caso_con_hallazgo(tmp_path)
    reglas, sin_fuente = reglas_sigma_caso("caso_v24_t", memoria)
    assert len(reglas) == 1 and not sin_fuente
    assert reglas[0]["tecnica"] == "T1558.003"
    lote = validar_lote({f"{r['tecnica']}-{r['id']}.yml": r["yml"]
                         for r in reglas})
    assert lote["validas"] == lote["total"] == 1, \
        [d["errores"] for d in lote["reglas"]]
    memoria.cerrar()


def test_purple_zip_incluye_validacion(tmp_path) -> None:
    memoria = _caso_con_hallazgo(tmp_path)
    contenido, resumen = construir_paquete_purple("caso_v24_t", memoria)
    assert resumen["reglas"] == 1
    assert resumen["sigma_validas"] == 1 and resumen["sigma_invalidas"] == 0
    with zipfile.ZipFile(io.BytesIO(contenido)) as z:
        nombres = z.namelist()
        assert "sigma/validacion.md" in nombres
        validacion = z.read("sigma/validacion.md").decode("utf-8")
        assert "VÁLIDA" in validacion
        # El informe declara el resultado de la validación, no lo oculta.
        informe = z.read("informe_purple.md").decode("utf-8")
        assert "Validación Sigma (v24): 1 de 1" in informe
    memoria.cerrar()


def test_purple_tecnicas_sin_fuente_no_validan_inventos(tmp_path) -> None:
    memoria = _caso_con_hallazgo(tmp_path, tecnica="T9999.999")
    reglas, sin_fuente = reglas_sigma_caso("caso_v24_t", memoria)
    assert reglas == [] and sin_fuente == ["T9999.999"]
    memoria.cerrar()


# ---------------------------------------------------------------------------
# 4) API: endpoint de validación Sigma con RBAC real
# ---------------------------------------------------------------------------


def _token_admin() -> str:
    if not _auth.hay_operadores():
        _auth.crear_operador("opv24", "ClaveV24segura!", rol="admin")
    return _auth.emitir_token("opv24", "admin", "predeterminada")["token"]


@pytest.fixture()
def cliente_api(tmp_path, monkeypatch):
    monkeypatch.setattr(_auth, "RUTA_DB", tmp_path / "usuarios_test_v24.db")
    monkeypatch.setattr(_auth, "_intentos", {})
    # Limitador de tasa fresco por test: las llamadas de autenticación de
    # ESTA suite no contaminan al resto (y viceversa) — el orden de
    # ejecución de la suite no puede decidir qué tests pasan.
    import orchestrator.api as _api
    monkeypatch.setattr(_api, "_limitador_auth",
                        _api._LimitadorTasa(maximo=10, ventana_s=60.0))
    token = _token_admin()
    cliente = TestClient(app)
    cliente.headers.update({"Authorization": f"Bearer {token}"})
    yield cliente


def _limpiar_caso(id_caso: str) -> None:
    (RAIZ_CASOS / f"{id_caso}.db").unlink(missing_ok=True)


def test_api_sigma_validar_caso_con_regla(cliente_api) -> None:
    c = cliente_api
    try:
        id_caso = c.post("/api/engagements",
                         json={"nombre": "sigma", "cliente": "lab"
                               }).json()["id"]
        memoria = MemoriaCaso(RAIZ_CASOS / f"{id_caso}.db")
        memoria.guardar_hallazgo(Hallazgo(
            id="hz_api_sigma", engagement_id=id_caso,
            titulo="Kerberoasting detectado tarde",
            severidad=Severidad.ALTA, tecnica_mitre="T1558.003",
            activo="svc-sql", descripcion="ticket RC4 anómalo",
            estado="confirmado", deteccion="detectado"))
        memoria.cerrar()
        r = c.post(f"/api/engagements/{id_caso}/sigma/validar")
        assert r.status_code == 200, r.text
        cuerpo = r.json()
        assert cuerpo["total"] == 1 and cuerpo["validas"] == 1
        assert cuerpo["invalidas"] == 0 and cuerpo["sin_fuente"] == []
        assert cuerpo["reglas"][0]["valida"] is True
    finally:
        _limpiar_caso(id_caso)


def test_api_sigma_validar_caso_vacio_y_404(cliente_api) -> None:
    c = cliente_api
    try:
        id_caso = c.post("/api/engagements",
                         json={"nombre": "vacio", "cliente": "lab"
                               }).json()["id"]
        r = c.post(f"/api/engagements/{id_caso}/sigma/validar")
        assert r.status_code == 200
        cuerpo = r.json()
        assert cuerpo["total"] == 0
        assert cuerpo["motor"] == "sin reglas que validar"
    finally:
        _limpiar_caso(id_caso)
    # Caso inexistente → 404 del middleware multi-tenant.
    assert c.post("/api/engagements/caso_fantasma_v24/sigma/validar"
                  ).status_code == 404


def test_api_sigma_validar_lector_no_ejecuta(cliente_api) -> None:
    c = cliente_api
    try:
        id_caso = c.post("/api/engagements",
                         json={"nombre": "rbac", "cliente": "lab"
                               }).json()["id"]
        r = c.post("/api/auth/registrar",
                   json={"usuario": "lectv24",
                         "contrasena": "ClaveLectorV24!",
                         "rol": "lector"})
        assert r.status_code == 200, r.text
        l = TestClient(app)
        l.headers.update({"Authorization": f"Bearer {_auth.emitir_token(
            'lectv24', 'lector', 'predeterminada')['token']}"})
        # Validar es una acción del operador (nivel ≥2): el lector, no.
        assert l.post(f"/api/engagements/{id_caso}/sigma/validar"
                      ).status_code == 403
    finally:
        _limpiar_caso(id_caso)
