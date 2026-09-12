"""Tests z3 — sesión 7: confinamiento del arsenal de persistencia (F37).

Hallazgo (auditoría del código v27): el endpoint
`/api/engagements/{id}/arsenal/persistencia` aceptaba un campo `raiz`
libre y `persistencia.implantar()` solo comprobaba que el directorio
EXISTIERA (`os.path.realpath` + `os.path.isdir`). Consecuencia:

  - Escritura + activación de ejecución en CUALQUIER ruta del host donde
    el proceso tuviera permiso (`raiz=/root` → implante en /root/.bashrc
    + shell interactivo con HOME=/root; `raiz=/home/ajeno` → clave SSH
    propia en authorized_keys ajeno).
  - El boundary jamás lo vio: los argumentos evaluados eran
    `{"host": "127.0.0.1", ...}` — el destino real (`raiz`) viajaba
    FUERA de la evaluación y del registro de aprobación.

Remediación probada aquí:
  F37a Lista blanca de hogares del lab (`ORQUESTA_LAB_HOGARES`, separada
       por ":"; por defecto SOLO el HOME del despliegue). implantar,
       verificar, retirar y estado la aplican con realpath en ambos
       lados: `..`, symlinks y rutas alternativas no escapan.
  F37b El testigo de activación va entrecomillado (shlex.quote): hogares
       con espacios dejaban un testigo intacto (falso negativo).
  F37c La raíz viaja en los argumentos que el boundary evalúa y audita:
       la aprobación muestra el destino real.
"""
from __future__ import annotations

import os
import shutil
import sys
import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from orchestrator import persistencia  # noqa: E402
from orchestrator.api import RAIZ_CASOS, app  # noqa: E402

FUERA_DEL_LAB = "/etc"


# ---------------------------------------------------------------------------
# F37a — la lista blanca gobierna implantar / verificar / retirar / estado
# ---------------------------------------------------------------------------

def test_implantar_rechaza_raiz_fuera_del_lab(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("ORQUESTA_LAB_HOGARES", str(tmp_path))
    r = persistencia.implantar("bashrc", "id", raiz=FUERA_DEL_LAB)
    assert r["implantado"] is False
    assert "fuera del laboratorio autorizado" in r["error"]
    # ni rastro en la raíz vetada
    assert not os.path.exists(os.path.join(FUERA_DEL_LAB, ".orquesta_beacon"))


def test_verificar_retirar_estado_rechazan_raiz_fuera(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("ORQUESTA_LAB_HOGARES", str(tmp_path))
    v = persistencia.verificar("bashrc", raiz=FUERA_DEL_LAB)
    assert v["verificado"] is False and "fuera del laboratorio" in v["error"]
    r = persistencia.retirar("bashrc", raiz=FUERA_DEL_LAB)
    assert r["retirado"] is False and "fuera del laboratorio" in r["error"]
    e = persistencia.estado(raiz=FUERA_DEL_LAB)
    assert "error" in e and e["metodos"] == {}


def test_por_defecto_solo_el_home_del_despliegue(monkeypatch) -> None:
    """Sin ORQUESTA_LAB_HOGARES: el HOME del despliegue es el único lab."""
    monkeypatch.delenv("ORQUESTA_LAB_HOGARES", raising=False)
    hogar = os.path.expanduser("~")
    raiz, error = persistencia._raiz_confinada(None)
    assert error is None and raiz == hogar
    # una ruta ajena al hogar se rechaza aunque exista en el host
    _, error = persistencia._raiz_confinada(FUERA_DEL_LAB)
    assert error and "fuera del laboratorio autorizado" in error


def test_hogar_dedicado_del_lab_permitido(monkeypatch, tmp_path) -> None:
    """Despliegue con usuario de lab dedicado: su hogar va en la lista."""
    hogar_lab = tmp_path / "hogar_lab"
    hogar_lab.mkdir()
    monkeypatch.setenv("ORQUESTA_LAB_HOGARES", f"{hogar_lab}:{FUERA_DEL_LAB}")
    r = persistencia.implantar("bashrc", "echo beacon", raiz=str(hogar_lab))
    assert r["implantado"] is True
    ret = persistencia.retirar("bashrc", raiz=str(hogar_lab))
    assert ret["retirado"] is True and ret["ausencia_verificada"] is True


def test_traversal_y_symlink_no_escapan(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("ORQUESTA_LAB_HOGARES", str(tmp_path))
    # ../ hasta salir del lab: el destino EXISTE (abuelo de tmp_path) y
    # aun así se rechaza por la lista blanca, no por inexistencia
    fuera = (tmp_path / ".." / "..").resolve()
    assert fuera.is_dir() and not fuera.samefile(tmp_path)
    r = persistencia.implantar("bashrc", "id", raiz=str(fuera))
    assert r["implantado"] is False and "fuera del laboratorio" in r["error"]
    # symlink DENTRO del lab que apunta a un directorio de fuera
    externo = tempfile.mkdtemp(prefix="f37-fuera-")
    try:
        enlace = tmp_path / "enlace"
        os.symlink(externo, enlace)
        r2 = persistencia.implantar("bashrc", "id", raiz=str(enlace))
        assert r2["implantado"] is False and "fuera del laboratorio" in r2["error"]
        assert not os.path.exists(os.path.join(externo, ".orquesta_beacon"))
    finally:
        shutil.rmtree(externo, ignore_errors=True)


def test_raiz_inexistente_sigue_dando_error_claro(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("ORQUESTA_LAB_HOGARES", str(tmp_path))
    r = persistencia.implantar("bashrc", "id", raiz=str(tmp_path / "no_existe"))
    assert r["implantado"] is False and "no existe en el host" in r["error"]


# ---------------------------------------------------------------------------
# F37b — testigo entrecomillado: hogares con espacios activan de verdad
# ---------------------------------------------------------------------------

def test_hogar_con_espacios_activa_testigo(monkeypatch, tmp_path) -> None:
    hogar = tmp_path / "usuario del lab (con espacios)"
    hogar.mkdir()
    monkeypatch.setenv("ORQUESTA_LAB_HOGARES", str(tmp_path))
    r = persistencia.implantar("bashrc", "echo beacon", raiz=str(hogar))
    assert r["implantado"] is True and r["activo"] is True
    # el bloque escribe el testigo en la ruta correcta ENTRECOMILLADA
    bashrc = (hogar / ".bashrc").read_text()
    assert f">> '{hogar / '.orquesta_beacon'}'" in bashrc
    ret = persistencia.retirar("bashrc", raiz=str(hogar))
    assert ret["ausencia_verificada"] is True


# ---------------------------------------------------------------------------
# F37c — la raíz viaja en los argumentos del boundary (aprobación honesta)
# ---------------------------------------------------------------------------

@pytest.fixture()
def cliente_api(tmp_path, monkeypatch):
    from orchestrator import auth

    monkeypatch.setattr(auth, "RUTA_DB", tmp_path / "usuarios_test_z3s7.db")
    monkeypatch.setattr(auth, "_intentos", {})
    if not auth.hay_operadores():
        auth.crear_operador("opz3s7", "ClaveZ3s7segura", rol="admin")
    token = auth.emitir_token("opz3s7", "admin")["token"]
    cliente = TestClient(app)
    cliente.headers.update({"Authorization": f"Bearer {token}"})
    yield cliente


def test_aprobacion_muestra_la_raiz_real(cliente_api, tmp_path) -> None:
    id_caso = cliente_api.post("/api/engagements", json={
        "nombre": "caso z3 sesion 7", "cliente": "acme",
        "alcance_dominios": ["lab.test"], "alcance_cidrs": ["127.0.0.0/8"],
    }).json()["id"]
    hogar_lab = tmp_path / "home_lab_f37"
    hogar_lab.mkdir()
    try:
        cuerpo = {"metodo": "bashrc", "comando": "echo beacon",
                  "raiz": str(hogar_lab)}
        r1 = cliente_api.post(
            f"/api/engagements/{id_caso}/arsenal/persistencia", json=cuerpo)
        assert r1.status_code == 200
        assert r1.json()["estado"] == "espera_aprobacion"
        # la cola de aprobaciones muestra el DESTINO REAL del implante
        estado = cliente_api.get(f"/api/engagements/{id_caso}/estado").json()
        pendientes = estado["aprobaciones_pendientes"]
        args = next(a["argumentos"] for a in pendientes
                    if a["herramienta"] == "persistencia.implantar")
        assert args["raiz"] == str(hogar_lab)
        # aprobación → ejecución en el lab permitido
        cliente_api.post(
            f"/api/aprobaciones/{r1.json()['aprobacion_id']}/decision",
            json={"decidir": True, "comentario": ""})
        r2 = cliente_api.post(
            f"/api/engagements/{id_caso}/arsenal/persistencia", json=cuerpo)
        assert r2.status_code == 200
        datos = r2.json()
        assert datos["estado"] == "ejecutado"
        assert datos["resultado"]["activo"] is True
        # y la raíz FUERA del lab se rechaza también por la vía del API
        r3 = cliente_api.post(
            f"/api/engagements/{id_caso}/arsenal/persistencia",
            json={"metodo": "bashrc", "comando": "id", "raiz": FUERA_DEL_LAB})
        assert r3.status_code == 200
        cliente_api.post(
            f"/api/aprobaciones/{r3.json()['aprobacion_id']}/decision",
            json={"decidir": True, "comentario": ""})
        r4 = cliente_api.post(
            f"/api/engagements/{id_caso}/arsenal/persistencia",
            json={"metodo": "bashrc", "comando": "id", "raiz": FUERA_DEL_LAB})
        assert r4.json()["estado"] == "fallo"
        assert "fuera del laboratorio" in r4.json()["error"]
        assert not os.path.exists(os.path.join(FUERA_DEL_LAB, ".orquesta_beacon"))
    finally:
        persistencia.retirar("bashrc", raiz=str(hogar_lab))
        (RAIZ_CASOS / f"{id_caso}.db").unlink(missing_ok=True)
