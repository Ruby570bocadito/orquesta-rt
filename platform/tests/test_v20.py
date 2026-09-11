"""Tests v20: Arsenal real — evasión verificada, persistencia real y AD.

Nada simulado: la evasión se mide contra YARA real (motor de firmas) con
round-trip por ejecución real del loader; la persistencia se activa de
verdad (shell interactivo, intérprete real en venv aislado) y se retira con
verificación de ausencia; el módulo AD devuelve requisito exacto sin DC y
calcula rutas a DA solo sobre datos declarados.
"""
from __future__ import annotations

import base64
import os
import subprocess
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from integraciones import ldap  # noqa: E402
from orchestrator import auth as _auth  # noqa: E402
from orchestrator import ad, evasion, persistencia  # noqa: E402
from orchestrator.api import RAIZ_CASOS, app  # noqa: E402
from orchestrator.guardrails import MotorGuardrails, _RIESGO_HERRAMIENTAS  # noqa: E402
from orchestrator.models import Fase, ROEPolitica  # noqa: E402

# EICAR por concatenación: el fichero de pruebas NO debe ser detectable.
EICAR = (b"X5O!P%@AP[4\\PZX54(P^)7CC)7}" + b"$EICAR-STANDARD-"
         b"ANTIVIRUS-TEST-FILE!$H+H*")

_CLAVES_LDAP = ("LDAP_HOST", "LDAP_BIND_DN", "LDAP_BIND_CLAVE", "LDAP_BASE_DN")


def _roe(tmp: Path) -> ROEPolitica:
    return ROEPolitica(
        engagement_id="caso_t20", cliente="t20",
        alcance_cidrs=["127.0.0.0/8"], alcance_dominios=["lab.test"],
        tecnicas_prohibidas=["T1485"],
        ventanas_activas={"inicio": "00:00", "fin": "23:59",
                          "dias": ["lun", "mar", "mie", "jue", "vie", "sab", "dom"]},
        techo_ruido=90,
    )


# ---------------------------------------------------------------------------
# 1) Evasión: YARA real + round-trip real
# ---------------------------------------------------------------------------


def test_yara_detecta_eicar_real() -> None:
    escaneo = evasion.escanear(EICAR)
    assert escaneo["limpio"] is False
    assert "EICAR_Test_File" in [d["regla"] for d in escaneo["detecciones"]]


def test_texto_inofensivo_no_detecta() -> None:
    assert evasion.escanear(b"holamundo normalista 123")["limpio"] is True


def test_evasion_aes_python_verificada_con_ejecucion_real(tmp_path) -> None:
    r = evasion.generar(EICAR, "aes_cbc", "python")
    assert "error" not in r
    assert [d["regla"] for d in r["detecciones_antes"]] == ["EICAR_Test_File"]
    assert r["detecciones_despues"] == []
    assert r["roundtrip_ok"] is True
    assert r["roundtrip"]["rc"] == 0
    # el hash del payload original es el EICAR real (verificable externamente)
    assert r["hash_payload"] == evasion.sha256(EICAR)
    assert r["evasion_verificada"] is True
    # el artefacto escaneado por terceros (re-escaneo independiente) es limpio
    artefacto = base64.b64decode(r["artefacto_b64"])
    assert evasion.escanear(artefacto)["limpio"] is True
    # entropía calculada de verdad en ambos lados
    assert 0.0 < r["entropia_antes"] <= 8.0
    assert 0.0 < r["entropia_despues"] <= 8.0


def test_evasion_xor_powershell_roundtrip_espejo() -> None:
    r = evasion.generar(EICAR, "xor_cascada", "powershell")
    assert "error" not in r
    assert r["roundtrip_ok"] is True
    assert "PBKDF2" in r["roundtrip"]["tipo"] or "espejo" in r["roundtrip"]["tipo"]
    # el loader PowerShell nunca contiene el payload en claro
    artefacto = base64.b64decode(r["artefacto_b64"]).decode("utf-8", "replace")
    assert "EICAR-STANDARD" not in artefacto


def test_evasion_binario_y_errores_honestos() -> None:
    r = evasion.generar(b"\x90" * 64, "base64_dividido", "binario")
    assert "error" not in r and r["roundtrip_ok"] is True
    assert evasion.generar(b"x", "banana", "python")["error"]
    assert evasion.generar(b"", "aes_cbc", "python")["error"]
    assert evasion.generar(b"x" * 8, "aes_cbc", "banana")["error"]


def test_iocs_reales() -> None:
    i = evasion.iocs(EICAR)
    assert i["sha256"] == evasion.sha256(EICAR)
    assert i["tamano"] == len(EICAR)
    assert any("EICAR" in c for c in i["cadenas_notables"])


# ---------------------------------------------------------------------------
# 2) Persistencia real: implantar → activar → retirar sin rastro
# ---------------------------------------------------------------------------


def test_bashrc_activacion_real_y_limpieza(tmp_path) -> None:
    r = persistencia.implantar("bashrc", "echo hola", raiz=str(tmp_path))
    assert r["implantado"] is True and r["activo"] is True
    v = persistencia.verificar("bashrc", raiz=str(tmp_path))
    assert v["verificado"] is True and v["activo"] is True
    # la segunda implantación se niega (idempotente, sin duplicar bloque)
    r2 = persistencia.implantar("bashrc", "echo hola", raiz=str(tmp_path))
    assert r2["implantado"] is False
    ret = persistencia.retirar("bashrc", raiz=str(tmp_path))
    assert ret["retirado"] is True and ret["ausencia_verificada"] is True
    assert ".orquesta_beacon" not in os.listdir(tmp_path)


def test_python_startup_activa_intérprete_real(tmp_path) -> None:
    venv = tmp_path / "venv"
    subprocess.run([sys.executable, "-m", "venv", str(venv)], check=True,
                   capture_output=True, timeout=120)
    py = str(venv / "bin" / "python3")
    sitio = str(venv / "lib" / f"python{sys.version_info.major}.{sys.version_info.minor}" / "site-packages")
    r = persistencia.implantar("python_startup", "pass", raiz=str(tmp_path),
                               sitio=sitio, interprete=py)
    assert r["implantado"] is True and r["activo"] is True
    assert os.path.exists(os.path.join(sitio, "zzz_orquesta_lab_persist.pth"))
    ret = persistencia.retirar("python_startup", raiz=str(tmp_path), sitio=sitio)
    assert ret["retirado"] is True and ret["ausencia_verificada"] is True


def test_systemd_unidad_validada_y_retirada(tmp_path) -> None:
    r = persistencia.implantar("systemd_user", "id -u", raiz=str(tmp_path))
    assert r["implantado"] is True
    if "error" not in r["prueba"]:
        assert r["prueba"]["rc"] == 0  # systemd-analyze verify real
    v = persistencia.verificar("systemd_user", raiz=str(tmp_path))
    assert v["verificado"] is True
    assert persistencia.retirar("systemd_user", raiz=str(tmp_path))["ausencia_verificada"] is True


def test_ssh_clave_real_y_retirada_selectiva(tmp_path) -> None:
    auth_dir = tmp_path / ".ssh"
    auth_dir.mkdir()
    (auth_dir / "authorized_keys").write_text("ssh-ed25519 AAAAclavedeotro usuario@otro\n")
    r = persistencia.implantar("ssh_authorized_keys", "pass", raiz=str(tmp_path))
    assert r["implantado"] is True and r.get("huella", "").startswith("SHA256:")
    contenido = (auth_dir / "authorized_keys").read_text()
    assert "usuario@otro" in contenido  # la clave ajena NO se toca
    assert "orquesta-lab-persist" in contenido
    ret = persistencia.retirar("ssh_authorized_keys", raiz=str(tmp_path))
    assert ret["ausencia_verificada"] is True
    assert "usuario@otro" in (auth_dir / "authorized_keys").read_text()


def test_artefactos_y_estado_honestos(tmp_path) -> None:
    for metodo in ("cron_artefacto", "windows_run_key", "windows_tarea_programada"):
        r = persistencia.implantar(metodo, "cmd.exe", raiz=str(tmp_path))
        assert r.get("generado") is True and r.get("hash"), metodo
        assert r.get("implantado") in (False, None)  # jamás se dice implantado
    est = persistencia.estado(raiz=str(tmp_path))
    assert est["limpio_total"] is True  # artefactos no cuentan como implante
    assert persistencia.implantar("banana", "x", raiz=str(tmp_path))["error"]
    assert persistencia.implantar("bashrc", "", raiz=str(tmp_path))["error"]


def test_metodos_disponibles_contracto() -> None:
    metodos = {m["metodo"]: m for m in persistencia.metodos_disponibles()}
    esperados = {"bashrc": "T1546.004", "python_startup": "T1546.016",
                 "systemd_user": "T1543.002", "ssh_authorized_keys": "T1098.004",
                 "cron_artefacto": "T1053.003", "windows_run_key": "T1547.001",
                 "windows_tarea_programada": "T1053.005"}
    for nombre, tecnica in esperados.items():
        assert metodos[nombre]["tecnica"] == tecnica
        assert metodos[nombre]["detalle"]


# ---------------------------------------------------------------------------
# 3) AD: honestidad sin DC + rutas a DA con datos reales (sustituidos)
# ---------------------------------------------------------------------------


def test_ad_sin_credenciales_devuelve_requisito_exacto(monkeypatch) -> None:
    for clave in _CLAVES_LDAP:
        monkeypatch.delenv(clave, raising=False)
    for r in (ad.kerberoasting("127.0.0.1"), ad.asrep("127.0.0.1"),
              ad.dcsync("127.0.0.1", "CN=x")):
        assert r["conectado"] is False
        assert "LDAP_HOST" in r["error"]


def test_pth_valida_formato_hash() -> None:
    assert "32 hex" in ad.pass_the_hash("127.0.0.1", "u", "ZZ")["error"]
    # host HTTP (no SMB) → error real de conexión, jamás "éxito"
    r = ad.pass_the_hash("127.0.0.1", "admin", "a" * 32)
    assert r["conectado"] is False and "error" in r


def test_kerberoasting_fuera_de_scope(monkeypatch) -> None:
    for clave in _CLAVES_LDAP:
        monkeypatch.delenv(clave, raising=False)
    roe = _roe(Path("."))
    r = ad.kerberoasting("10.99.99.5", roe=roe)
    assert r["conectado"] is False and "fuera de alcance local" in r["error"]


def test_rutas_a_da_solo_relaciones_declaradas(monkeypatch) -> None:
    datos = {
        "usuarios": {"conectado": True, "usuarios": [
            {"sAMAccountName": "jmaria",
             "memberOf": ["CN=Domain Admins,CN=Users,DC=test,DC=local"]},
            {"sAMAccountName": "sinrol", "memberOf": []},
            {"sAMAccountName": "pgonzal",
             "memberOf": ["CN=Helpdesk,DC=test,DC=local"]},
        ]},
        "grupos": {"conectado": True, "grupos_interes": [
            {"cn": "Domain Admins",
             "distinguishedName": "CN=Domain Admins,CN=Users,DC=test,DC=local",
             "member": ["CN=Domain Admins,CN=Users,DC=test,DC=local"]},
            {"cn": "Helpdesk", "distinguishedName": "CN=Helpdesk,DC=test,DC=local",
             "member": []},
        ]},
    }
    monkeypatch.setattr(ldap, "enumerar", lambda tipo="resumen": datos[tipo])
    r = ad.rutas_a_da()
    assert r["conectado"] is True
    assert r["total"] == 1
    assert r["rutas"][0]["usuario"] == "jmaria"
    assert "Domain Admins" in r["rutas"][0]["via"]


def test_rutas_da_sin_grupo_da_es_honesto(monkeypatch) -> None:
    datos = {
        "usuarios": {"conectado": True, "usuarios": []},
        "grupos": {"conectado": True, "grupos_interes": []},
    }
    monkeypatch.setattr(ldap, "enumerar", lambda tipo="resumen": datos[tipo])
    r = ad.rutas_a_da()
    assert r["conectado"] is True and r["rutas"] == []


# ---------------------------------------------------------------------------
# 4) Boundary: el arsenal queda clasificado por el mismo catálogo
# ---------------------------------------------------------------------------


def test_catalogo_arsenal_completo() -> None:
    esperados = {
        "evasion.generar": ("media", True), "evasion.escanear": ("baja", False),
        "persistencia.implantar": ("alta", True), "persistencia.verificar": ("baja", False),
        "persistencia.retirar": ("media", False), "ad.dcsync": ("critica", True),
        "ad.pass_the_hash": ("alta", True), "ad.trusts": ("baja", False),
        "ad.rutas_da": ("baja", False),
    }
    for herramienta, (riesgo, aprobacion) in esperados.items():
        spec = _RIESGO_HERRAMIENTAS[herramienta]
        assert spec["riesgo"] == riesgo, herramienta
        assert spec.get("requiere_aprobacion", False) == aprobacion, herramienta


def test_boundary_arsenal_decisiones(tmp_path) -> None:
    from orchestrator.memory import MemoriaCaso
    from orchestrator.models import Engagement, EstadoFase
    memoria = MemoriaCaso(tmp_path / "caso_t20.db")
    try:
        memoria.crear_engagement(Engagement(
            id="caso_t20", nombre="t20", cliente="acme", roe=_roe(tmp_path),
            fase_actual=Fase.F5_C2, estado_fase=EstadoFase.ACTIVA))
        motor = MotorGuardrails(_roe(tmp_path), memoria)
        args_generar = {"host": "127.0.0.1", "metodo": "aes_cbc", "formato": "python"}
        v = motor.evaluar("evasion.generar", args_generar, Fase.F5_C2)
        assert v.decision.value == "requiere_aprobacion"
        v2 = motor.evaluar("evasion.escanear", {"host": "127.0.0.1"}, Fase.F5_C2)
        assert v2.decision.value == "permitir"
        v3 = motor.evaluar("persistencia.implantar",
                           {"host": "127.0.0.1", "metodo": "bashrc",
                            "comando": "id"}, Fase.F5_C2)
        assert v3.decision.value == "requiere_aprobacion"
        v4 = motor.evaluar("ad.dcsync",
                           {"host": "127.0.0.1", "dn_objetivo": "CN=krbtgt"},
                           Fase.F4_DOMINIO)
        assert v4.decision.value == "requiere_aprobacion"
        v5 = motor.evaluar("ad.rutas_da", {"host": "127.0.0.1"}, Fase.F4_DOMINIO)
        assert v5.decision.value == "permitir"
    finally:
        memoria.cerrar()
        (tmp_path / "caso_t20.db").unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# 5) API del arsenal: 401, flujo de aprobación y evidencia con custodia
# ---------------------------------------------------------------------------


@pytest.fixture()
def cliente_api(tmp_path, monkeypatch):
    monkeypatch.setattr(_auth, "RUTA_DB", tmp_path / "usuarios_test_v20.db")
    monkeypatch.setattr(_auth, "_intentos", {})
    if not _auth.hay_operadores():
        _auth.crear_operador("opv20", "ClaveV20segura!", rol="admin")
    token = _auth.emitir_token("opv20", "admin")["token"]
    cliente = TestClient(app)
    cliente.headers.update({"Authorization": f"Bearer {token}"})
    yield cliente


def _crear_caso(cliente: TestClient) -> str:
    r = cliente.post("/api/engagements", json={
        "nombre": "caso arsenal v20", "cliente": "acme",
        "alcance_dominios": ["lab.test"], "alcance_cidrs": ["127.0.0.0/8"],
    })
    assert r.status_code == 200, r.text
    return r.json()["id"]


def test_api_arsenal_401_sin_token() -> None:
    cliente = TestClient(app)
    assert cliente.get("/api/engagements/caso_x/arsenal").status_code == 401
    assert cliente.post("/api/engagements/caso_x/arsenal/evasion",
                        json={}).status_code == 401


def test_api_arsenal_estado(cliente_api) -> None:
    id_caso = _crear_caso(cliente_api)
    try:
        r = cliente_api.get(f"/api/engagements/{id_caso}/arsenal")
        assert r.status_code == 200
        datos = r.json()
        assert "EICAR_Test_File" in datos["reglas_deteccion"]
        assert datos["persistencia"]["limpio_total"] is True
        assert "bashrc" in datos["persistencia"]["metodos"]
    finally:
        (RAIZ_CASOS / f"{id_caso}.db").unlink(missing_ok=True)


def test_api_evasion_flujo_aprobacion_y_evidencia(cliente_api) -> None:
    id_caso = _crear_caso(cliente_api)
    try:
        cuerpo = {"payload_b64": base64.b64encode(EICAR).decode(),
                  "metodo": "aes_cbc", "formato": "python"}
        r1 = cliente_api.post(f"/api/engagements/{id_caso}/arsenal/evasion",
                              json=cuerpo)
        assert r1.status_code == 200
        assert r1.json()["estado"] == "espera_aprobacion"
        apr_id = r1.json()["aprobacion_id"]
        # 404 y 422 saneados
        assert cliente_api.post("/api/engagements/caso_nadie/arsenal/evasion",
                                json=cuerpo).status_code == 404
        assert cliente_api.post(f"/api/engagements/{id_caso}/arsenal/evasion",
                                json={"payload_b64": "###", "metodo": "aes_cbc",
                                      "formato": "python"}).status_code in (422, 500)
        # aprobación humana real en la cola
        rd = cliente_api.post(f"/api/aprobaciones/{apr_id}/decision",
                              json={"decidir": True, "comentario": "ROE lo cubre"})
        assert rd.status_code == 200, rd.text
        # re-invocación idéntica → el boundary autoriza con la decisión previa
        r2 = cliente_api.post(f"/api/engagements/{id_caso}/arsenal/evasion",
                              json=cuerpo)
        assert r2.status_code == 200
        datos = r2.json()
        assert datos["estado"] == "ejecutado"
        resultado = datos["resultado"]
        assert resultado["evasion_verificada"] is True
        assert resultado["roundtrip_ok"] is True
        # evidencia con custodia + re-escaneo real del artefacto
        r3 = cliente_api.post(f"/api/engagements/{id_caso}/arsenal/evasion/escanear",
                              json={"evidencia_id": datos["evidencia_id"]})
        assert r3.status_code == 200
        assert r3.json()["escaneo"]["limpio"] is True
        evs = cliente_api.get(f"/api/engagements/{id_caso}/evidencias").json()
        assert any("[Arsenal][Evasion]" in e["titulo"] for e in evs["evidencias"])
    finally:
        (RAIZ_CASOS / f"{id_caso}.db").unlink(missing_ok=True)


def test_api_persistencia_flujo_completo_real(cliente_api, tmp_path) -> None:
    """Implanta en un raíz temporal REAL, verifica activación y retira.
    El flujo pasa por la cola de aprobaciones del boundary."""
    id_caso = _crear_caso(cliente_api)
    raiz = str(tmp_path / "home_lab")
    os.makedirs(raiz, exist_ok=True)
    try:
        cuerpo = {"metodo": "bashrc", "comando": "echo beacon", "raiz": raiz}
        r1 = cliente_api.post(f"/api/engagements/{id_caso}/arsenal/persistencia",
                              json=cuerpo)
        assert r1.status_code == 200
        assert r1.json()["estado"] == "espera_aprobacion"
        rd = cliente_api.post(f"/api/aprobaciones/{r1.json()['aprobacion_id']}/decision",
                              json={"decidir": True, "comentario": ""})
        assert rd.status_code == 200
        r2 = cliente_api.post(f"/api/engagements/{id_caso}/arsenal/persistencia",
                              json=cuerpo)
        assert r2.status_code == 200
        datos = r2.json()
        assert datos["estado"] == "ejecutado"
        assert datos["resultado"]["activo"] is True  # shell interactivo real
        # verificar sin firma (bajo riesgo)
        r3 = cliente_api.post(
            f"/api/engagements/{id_caso}/arsenal/persistencia/verificar",
            json={"metodo": "bashrc", "raiz": raiz})
        assert r3.status_code == 200
        assert r3.json()["resultado"]["activo"] is True
        # retirar sin firma (higiene) y verificación de ausencia
        r4 = cliente_api.post(
            f"/api/engagements/{id_caso}/arsenal/persistencia/retirar",
            json={"metodo": "bashrc", "raiz": raiz})
        assert r4.status_code == 200
        assert r4.json()["resultado"]["ausencia_verificada"] is True
        # estado del host vuelve a limpio
        r5 = cliente_api.get(f"/api/engagements/{id_caso}/arsenal").json()
        assert r5["persistencia"]["limpio_total"] is True
    finally:
        (RAIZ_CASOS / f"{id_caso}.db").unlink(missing_ok=True)


def test_api_ad_honesto_sin_dc_y_con_aprobacion(cliente_api, monkeypatch) -> None:
    for clave in _CLAVES_LDAP:
        monkeypatch.delenv(clave, raising=False)
    id_caso = _crear_caso(cliente_api)
    try:
        # kerberoasting: alta → espera de firma
        r1 = cliente_api.post(f"/api/engagements/{id_caso}/arsenal/ad",
                              json={"accion": "kerberoasting", "host": "127.0.0.1"})
        assert r1.status_code == 200
        assert r1.json()["estado"] == "espera_aprobacion"
        apr_id = r1.json()["aprobacion_id"]
        rd = cliente_api.post(f"/api/aprobaciones/{apr_id}/decision",
                              json={"decidir": True, "comentario": ""})
        assert rd.status_code == 200
        r2 = cliente_api.post(f"/api/engagements/{id_caso}/arsenal/ad",
                              json={"accion": "kerberoasting", "host": "127.0.0.1"})
        assert r2.status_code == 200
        datos = r2.json()
        # sin LDAP configurado el módulo reporta el requisito real
        assert datos["estado"] == "sin_resultado"
        assert "LDAP_HOST" in datos["resultado"]["error"]
        # lecturas bajas (trusts) pasan sin firma y también son honestas
        r3 = cliente_api.post(f"/api/engagements/{id_caso}/arsenal/ad",
                              json={"accion": "trusts", "host": "127.0.0.1"})
        assert r3.status_code == 200
        assert r3.json()["estado"] in ("ejecutado", "sin_resultado")
        # dcsync sin dn_objetivo → 422 accionable
        r4 = cliente_api.post(f"/api/engagements/{id_caso}/arsenal/ad",
                              json={"accion": "dcsync", "host": "127.0.0.1"})
        assert r4.status_code == 422
        # pth con hash malformado → 422
        r5 = cliente_api.post(f"/api/engagements/{id_caso}/arsenal/ad",
                              json={"accion": "pass_the_hash", "host": "127.0.0.1",
                                    "usuario": "u", "hash_nt": "zz"})
        assert r5.status_code == 422
    finally:
        (RAIZ_CASOS / f"{id_caso}.db").unlink(missing_ok=True)


def test_transportes_arsenal_registrados() -> None:
    from orchestrator.transportes import TRANSPORTE_NOMBRES, transportes_de
    roe = _roe(Path("."))
    mapa = transportes_de(roe)
    for nombre in ("evasion.generar", "evasion.escanear", "persistencia.implantar",
                   "persistencia.verificar", "persistencia.retirar",
                   "ad.kerberoasting", "ad.asrep_roasting", "ad.dcsync",
                   "ad.pass_the_hash", "ad.laps_leer", "ad.gmsa_leer",
                   "ad.trusts", "ad.rutas_da"):
        assert nombre in mapa, nombre
        assert nombre in TRANSPORTE_NOMBRES
