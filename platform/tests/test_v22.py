"""Pruebas v22 — rutas de ataque reales (Neo4j + esquema BloodHound),
enriquecimiento CVE real (NVD) y SSO contra el IdP real del laboratorio.

Honestidad de la suite: los tests que exigen servicios de laboratorio vivos
(Keycloak :8081, Neo4j :7474) se saltan con un mensaje preciso si no están
en marcha — nunca falsifican una verificación.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from integraciones import nvd, rutas  # noqa: E402

NEO4J = (
    os.environ.get("NEO4J_URL", "http://localhost:7474"),
    os.environ.get("NEO4J_USER", "neo4j"),
    os.environ.get("NEO4J_PASS", "orquesta-lab-2026"),
)
KC_BASE = os.environ.get("OIDC_ISSUER", "http://localhost:8081/realms/orquesta")


def _neo4j_vivo() -> bool:
    try:
        os.environ.update({"NEO4J_URL": NEO4J[0], "NEO4J_USER": NEO4J[1],
                           "NEO4J_PASS": NEO4J[2]})
        return bool(rutas.estado().get("conectado"))
    except Exception:
        return False


NEO4J_OK = _neo4j_vivo()


# ---------------------------------------------------------------- rutas: honestidad

def test_rutas_sin_config_requisito_exacto(monkeypatch):
    for k in ("NEO4J_URL", "NEO4J_USER", "NEO4J_PASS"):
        monkeypatch.delenv(k, raising=False)
    e = rutas.estado()
    assert e["conectado"] is False
    assert "NEO4J_URL" in e["error"] and "NEO4J_USER" in e["error"]


def test_rutas_limite_validado():
    r = rutas.rutas("X", 0)
    assert r["conectado"] is False and "limite" in r["error"]
    r = rutas.rutas("X", 21)
    assert r["conectado"] is False and "limite" in r["error"]


@pytest.mark.skipif(not NEO4J_OK, reason="Neo4j de laboratorio no disponible")
def test_rutas_estado_recuento_real():
    os.environ.update({"NEO4J_URL": NEO4J[0], "NEO4J_USER": NEO4J[1],
                       "NEO4J_PASS": NEO4J[2]})
    e = rutas.estado()
    assert e["conectado"] is True and e["cargado"] is True
    assert e["objetos"].get("User", 0) >= 7
    assert e["objetos"].get("Domain", 0) == 1
    assert "MemberOf" in e["aristas"]


@pytest.mark.skipif(not NEO4J_OK, reason="Neo4j de laboratorio no disponible")
def test_rutas_camino_canonico_cfdez():
    """La ruta CFDEZ→DOMAIN ADMINS existe en la colección y el MOTOR la
    devuelve con la cadena canónica (AddMember→GenericAll→...→MemberOf)."""
    os.environ.update({"NEO4J_URL": NEO4J[0], "NEO4J_USER": NEO4J[1],
                       "NEO4J_PASS": NEO4J[2]})
    r = rutas.rutas("CFDEZ@TEST.LOCAL", 5)
    assert r["conectado"] is True and r["total"] >= 1
    ruta_da = [x for x in r["rutas"]
               if x["nodos"][-1]["nombre"] == "DOMAIN ADMINS@TEST.LOCAL"]
    assert ruta_da, "debe existir ruta hacia DOMAIN ADMINS"
    aristas = ruta_da[0]["aristas"]
    assert "AddMember" in aristas and "HasSession" in aristas
    # dirigido: MemberOf solo puede ir de usuario a grupo; el path no puede
    # empezar por el destino ni contener el origen en medio
    nombres = [n["nombre"] for n in ruta_da[0]["nodos"]]
    assert nombres[0] == "CFDEZ@TEST.LOCAL"
    assert nombres.count("CFDEZ@TEST.LOCAL") == 1


@pytest.mark.skipif(not NEO4J_OK, reason="Neo4j de laboratorio no disponible")
def test_rutas_origen_sin_camino_honesto():
    """MSANZ no conecta con los objetivos: 0 rutas es un RESULTADO, no un error."""
    os.environ.update({"NEO4J_URL": NEO4J[0], "NEO4J_USER": NEO4J[1],
                       "NEO4J_PASS": NEO4J[2]})
    r = rutas.rutas("MSANZ@TEST.LOCAL", 5)
    assert r["conectado"] is True and r["total"] == 0


@pytest.mark.skipif(not NEO4J_OK, reason="Neo4j de laboratorio no disponible")
def test_rutas_objetivos_alto_valor():
    os.environ.update({"NEO4J_URL": NEO4J[0], "NEO4J_USER": NEO4J[1],
                       "NEO4J_PASS": NEO4J[2]})
    o = rutas.objetivos()
    nombres = {x["nombre"] for x in o["objetivos"]}
    assert "DOMAIN ADMINS@TEST.LOCAL" in nombres
    assert "DC01.TEST.LOCAL" in nombres


@pytest.mark.skipif(not NEO4J_OK, reason="Neo4j de laboratorio no disponible")
def test_rutas_origen_inexistente_devuelve_vacio_honesto():
    os.environ.update({"NEO4J_URL": NEO4J[0], "NEO4J_USER": NEO4J[1],
                       "NEO4J_PASS": NEO4J[2]})
    r = rutas.rutas("NOEXISTE@TEST.LOCAL", 5)
    assert r["conectado"] is True and r["total"] == 0


# ---------------------------------------------------------------- NVD: real

def test_nvd_sin_productos_requisito():
    r = nvd.enriquecer("el servidor parece vulnerable")
    assert r["conectado"] is False and "productos" in r["error"]


def test_nvd_extraccion_productos():
    p = nvd._extraer_productos("Apache 2.4.49 expuesto y OpenSSH 8.2p1")
    assert p == ["apache 2.4.49", "openssh 8.2p1"]
    assert nvd._extraer_productos("sin versiones aquí") == []


def test_nvd_cves_reales_apache():
    """Consulta REAL al NVD: Apache 2.4.49 debe traer CVE-2021-41773."""
    r = nvd.enriquecer("Apache 2.4.49 sin parchear")
    if not r.get("conectado") and r.get("error") and "NVD" in r.get("error", ""):
        pytest.skip("NVD no accesible desde este entorno")
    assert r["total"] >= 1
    ids = {c["cve"] for c in r["coincidencias"]}
    assert "CVE-2021-41773" in ids
    cve = next(c for c in r["coincidencias"] if c["cve"] == "CVE-2021-41773")
    assert cve["severidad"] in ("CRITICAL", "HIGH")
    assert cve["cvss_base"] is not None and cve["cvss_base"] >= 9.0


# ---------------------------------------------------------------- API HTTP

@pytest.fixture(scope="module")
def _api():
    from fastapi.testclient import TestClient
    os.environ.update({"NEO4J_URL": NEO4J[0], "NEO4J_USER": NEO4J[1],
                       "NEO4J_PASS": NEO4J[2]})
    from orchestrator import api as api_mod
    with TestClient(api_mod.app) as c:
        yield c


def test_api_rutas_exige_token(_api):
    assert _api.get("/api/integraciones/rutas").status_code == 401
    assert _api.post("/api/integraciones/rutas", json={}).status_code == 401
    assert _api.post("/api/integraciones/nvd/enriquecer",
                     json={"texto": "Apache 2.4.49"}).status_code == 401


def test_api_estado_integra_motor_rutas_y_nvd(_api, token_admin):
    r = _api.get("/api/integraciones",
                 headers={"Authorization": f"Bearer {token_admin}"}).json()
    assert "motor_rutas" in r and "nvd" in r
    assert r["motor_rutas"]["configurado"] is True
    assert r["nvd"]["configurado"] is True


def test_api_probar_alias_neo4j(_api, token_admin):
    r = _api.post("/api/integraciones/probar",
                  headers={"Authorization": f"Bearer {token_admin}"},
                  json={"nombre": "neo4j"}).json()
    assert r.get("conectado") is True


@pytest.mark.skipif(not NEO4J_OK, reason="Neo4j de laboratorio no disponible")
def test_api_rutas_flujo_completo(_api, token_admin):
    cab = {"Authorization": f"Bearer {token_admin}"}
    vista = _api.get("/api/integraciones/rutas", headers=cab).json()
    assert vista["motor"]["conectado"] is True
    assert vista["origenes"]["total"] >= 7
    rutas_res = _api.post("/api/integraciones/rutas", headers=cab,
                          json={"origen": "CFDEZ@TEST.LOCAL",
                                "limite": 3}).json()
    assert rutas_res["conectado"] is True and rutas_res["total"] >= 1
    assert rutas_res["rutas"][0]["nodos"][0]["nombre"] == "CFDEZ@TEST.LOCAL"


def test_lector_puede_consultar_rutas_regresion_403(_api, token_admin):
    """Regresión del E2E real (v22): el POST de rutas es una consulta pura
    al motor y el middleware RBAC no debe bloquearla a un lector (antes
    respondía 403 por ser POST). Sin motor configurado, el endpoint sigue
    respondiendo 200 con el requisito exacto — jamás 403."""
    from fastapi.testclient import TestClient
    import time as _time
    from orchestrator import auth as auth_mod
    cab = {"Authorization": f"Bearer {token_admin}"}
    usuario = f"lect.rutas{int(_time.time()) % 1000000}"
    r = _api.post("/api/auth/registrar", headers=cab, json={
        "usuario": usuario, "contrasena": "ClaveLectora1!",
        "rol": "lector"})
    assert r.status_code == 200, r.text
    token = auth_mod.emitir_token(usuario, "lector",
                                  "predeterminada")["token"]
    l = TestClient(_api.app)
    l.headers.update({"Authorization": f"Bearer {token}"})
    resp = l.post("/api/integraciones/rutas",
                  json={"origen": "", "limite": 3})
    assert resp.status_code == 200, resp.text
    # Y el enriquecimiento NVD (también consulta pura): 200, no 403.
    r2 = l.post("/api/integraciones/nvd/enriquecer",
                json={"texto": "OpenSSH 8.2p1"})
    assert r2.status_code == 200, r2.text
    # Pero una escritura real del caso SIGUE prohibida (RBAC intacto).
    assert l.post("/api/engagements", json={
        "nombre": "x", "cliente": "y"}).status_code == 403
    cuerpo = resp.json()
    # Con el motor del lab disponible: rutas reales; sin él: requisito
    # honesto. En NINGÚN caso un lector recibe 403 por consultar.
    if cuerpo.get("conectado"):
        assert isinstance(cuerpo.get("rutas"), list)
    else:
        assert "error" in cuerpo
    auth_mod.eliminar_operador(usuario, peticionario="test-lector-rutas")


# ---------------------------------------------------------------- SSO: IdP real

def test_sso_estado_con_idp_real(monkeypatch):
    """Con el laboratorio levantado, el SSO se anuncia configurado y apunta
    al issuer REAL de Keycloak; el flujo genera la URL contra ESE issuer."""
    import httpx
    try:
        r = httpx.get(f"{KC_BASE}/.well-known/openid-configuration", timeout=5)
    except Exception:
        pytest.skip("Keycloak de laboratorio no disponible")
    assert r.status_code == 200
    doc = r.json()
    assert doc["issuer"] == KC_BASE
    assert "S256" in str(doc["code_challenge_methods_supported"])
    # Entorno OIDC del laboratorio en el proceso de test (descubrimiento real)
    monkeypatch.setenv("OIDC_ISSUER", KC_BASE)
    monkeypatch.setenv("OIDC_CLIENT_ID", "orquesta-rt")
    monkeypatch.setenv("OIDC_CLIENT_SECRET", "orquesta-rt-lab-secret")
    monkeypatch.setenv("OIDC_REDIRECT_URI", "http://localhost:3000/acceso?sso=1")
    from orchestrator import sso
    sso.descubrir(force=True)
    url = sso.url_autorizacion()["url"]
    assert url.startswith(f"{KC_BASE}/protocol/openid-connect/auth")
    assert "code_challenge_method=S256" in url


# ---------------------------------------------------------------- fixture auth

@pytest.fixture(scope="module")
def token_admin(_api):
    """Token de una cuenta admin de prueba creada directamente en auth.

    Nombre único por ejecución para no chocar con despliegues ya arrancados;
    se da de baja al terminar (higiene del despliegue).
    """
    import time
    from orchestrator import auth
    usuario = f"opv22t{int(time.time()) % 1000000}"
    auth.crear_operador(usuario, "ClaveV22segura!", rol="admin")
    tok = auth.emitir_token(usuario, "admin", auth.TENANT_PREDETERMINADA)["token"]
    yield tok
    try:
        auth.eliminar_operador(usuario, peticionario=f"admin-{usuario}")
    except Exception:
        pass
