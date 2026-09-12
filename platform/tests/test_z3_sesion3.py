"""Tests z3 sesión 3 — regresión de los fixes F17-F24.

F17  reporting: el informe markdown incluye el mapeo MITRE ATT&CK
     (clave correcta `tecnica_mitre`, no la inexistente `tecnica`).
F18  servidor MISP lab: techo duro del cuerpo (413 con Content-Length
     desbordada) — probado con socket crudo, sin enviar el cuerpo.
F19  servidor MISP lab: parámetros basura (limit/threat_level_id/analysis
     no numéricos) devuelven 200 acotado, nunca una hebra muerta.
F20  servidor MISP lab: clave errónea → 403 (comparación tiempo constante).
F21  servidor MISP lab: persistencia atómica del estado (JSON válido en
     disco y sin temporales residuales).
F23  purpleteam: dos hallazgos con misma técnica y slug → nombres únicos
     en el ZIP y veredicto de validación por cada regla emitida.
F24  sigma_valid: condición "sel and sel" produce UN solo error, no dos.
"""
from __future__ import annotations

import io
import json
import socket
import sys
import threading
import time
import zipfile
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lab"))

from orchestrator.memory import MemoriaCaso  # noqa: E402
from orchestrator.models import (  # noqa: E402
    Engagement, Fase, Hallazgo, ROEPolitica, Severidad,
)
from orchestrator.purpleteam import (  # noqa: E402
    _nombres_sigma_unicos, construir_paquete_purple,
)
from orchestrator.reporting import construir_informe  # noqa: E402
from orchestrator.sigma_valid import validar_regla  # noqa: E402
import servidor_misp_lab  # noqa: E402

# ---------------------------------------------------------------------------
# Utilidades de caso (mismos patrones que v24)
# ---------------------------------------------------------------------------


def _roe(id_caso: str) -> ROEPolitica:
    return ROEPolitica(
        engagement_id=id_caso, cliente="lab",
        alcance_dominios=["lab.local"],
        alcance_cidrs=["127.0.0.0/8"],
        alcance_excluido=[], techo_ruido=100)


def _caso_base(tmp_path: Path, id_caso: str) -> MemoriaCaso:
    memoria = MemoriaCaso(tmp_path / f"{id_caso}.db")
    memoria.crear_engagement(Engagement(
        id=id_caso, nombre="caso z3 s3", cliente="lab",
        roe=_roe(id_caso), fase_actual=Fase.F2_RECON, estado_fase="activa"))
    return memoria


# ---------------------------------------------------------------------------
# F17 · informe markdown con mapeo MITRE ATT&CK
# ---------------------------------------------------------------------------

def test_f17_informe_markdown_incluye_mitre(tmp_path: Path) -> None:
    memoria = _caso_base(tmp_path, "caso_z3_f17")
    memoria.guardar_hallazgo(Hallazgo(
        id="hz_z3_f17", engagement_id="caso_z3_f17",
        titulo="Kerberoasting documentado", severidad=Severidad.ALTA,
        tecnica_mitre="T1558.003", activo="svc-backup",
        descripcion="Tickets RC4 masivos", estado="confirmado"))
    ruta = construir_informe("caso_z3_f17", memoria,
                             carpeta_salida=tmp_path / "salidas")
    texto = ruta.read_text(encoding="utf-8")
    assert "**MITRE ATT&CK:** `T1558.003`" in texto, (
        "el informe markdown debe citar la técnica ATT&CK del hallazgo")


# ---------------------------------------------------------------------------
# Servidor MISP lab (F18-F21)
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
    servidor_misp_lab._INTEL.clear()
    servidor_misp_lab._INTEL.update(servidor_misp_lab._intel_inicial())


def _peticion_cruda(puerto: int, peticion: bytes) -> bytes:
    """Petición HTTP/1.1 cruda por socket (para probar cabeceras sin cuerpo)."""
    with socket.create_connection(("127.0.0.1", puerto), timeout=5) as s:
        s.sendall(peticion)
        s.settimeout(5)
        trozos = []
        while True:
            try:
                trozo = s.recv(65536)
            except socket.timeout:
                break
            if not trozo:
                break
            trozos.append(trozo)
            if b"\r\n\r\n" in b"".join(trozos) and b"Content-Length" in b"".join(trozos):
                cuerpo = b"".join(trozos).split(b"\r\n\r\n", 1)[1]
                cabeceras = b"".join(trozos).split(b"\r\n\r\n", 1)[0]
                esperado = 0
                for linea in cabeceras.split(b"\r\n"):
                    if linea.lower().startswith(b"content-length:"):
                        esperado = int(linea.split(b":")[1].strip())
                if len(cuerpo) >= esperado:
                    break
    return b"".join(trozos)


def test_f18_cuerpo_desbordado_responde_413(servidor_misp) -> None:
    puerto = int(servidor_misp.rsplit(":", 1)[1])
    peticion = (
        f"POST /events/add HTTP/1.1\r\n"
        f"Host: 127.0.0.1:{puerto}\r\n"
        f"Authorization: {_CLAVE_LAB}\r\n"
        f"Content-Length: {servidor_misp_lab.MAX_CUERPO_BYTES + 1}\r\n"
        f"Connection: close\r\n\r\n").encode()
    respuesta = _peticion_cruda(puerto, peticion)
    primera = respuesta.split(b"\r\n", 1)[0]
    assert b"413" in primera, (
        "Content-Length sobre el techo debe responder 413 sin leer el cuerpo")


def test_f19_parametros_basura_no_matan_la_hebra(servidor_misp) -> None:
    import httpx
    cuerpo_basura = {"limit": "diezmil", "timestamp": "Ndn"}
    r = httpx.post(f"{servidor_misp}/attributes/restSearch",
                   json=cuerpo_basura,
                   headers={"Authorization": _CLAVE_LAB}, timeout=5)
    assert r.status_code == 200
    assert "Attribute" in r.json()["response"]

    r2 = httpx.post(f"{servidor_misp}/events/add",
                    json={"Event": {"info": "prueba z3",
                                    "threat_level_id": "alta",
                                    "analysis": "si"}},
                    headers={"Authorization": _CLAVE_LAB}, timeout=5)
    assert r2.status_code == 200
    ev = r2.json()["Event"]
    assert ev["threat_level_id"] == 4  # defecto ante basura, dentro de 1-4
    assert ev["analysis"] == 0

    # el servidor sigue vivo para peticiones normales
    r3 = httpx.post(f"{servidor_misp}/events/restSearch", json={},
                    headers={"Authorization": _CLAVE_LAB}, timeout=5)
    assert r3.status_code == 200


def test_f20_clave_incorrecta_403_y_valida_200(servidor_misp) -> None:
    import httpx
    r = httpx.post(f"{servidor_misp}/events/restSearch", json={},
                   headers={"Authorization": "clave-que-no-es"}, timeout=5)
    assert r.status_code == 403
    r2 = httpx.post(f"{servidor_misp}/events/restSearch", json={},
                    headers={"Authorization": _CLAVE_LAB}, timeout=5)
    assert r2.status_code == 200


def test_f21_guardado_estado_atomico(tmp_path: Path, monkeypatch) -> None:
    ruta = tmp_path / "estado" / "misp_lab.json"
    monkeypatch.setattr(servidor_misp_lab, "_RUTA_ESTADO", ruta)
    servidor_misp_lab._guardar_estado()
    assert ruta.exists()
    datos = json.loads(ruta.read_text(encoding="utf-8"))
    assert "atributos" in datos and "eventos" in datos
    residuales = [p for p in ruta.parent.iterdir() if p.suffix == ".tmp"]
    assert residuales == [], "no deben quedar temporales tras el replace"


# ---------------------------------------------------------------------------
# F23 · nombres Sigma únicos ante colisiones técnica+slug
# ---------------------------------------------------------------------------

def test_f23_nombres_unicos() -> None:
    generadas = [
        {"id": "hz_a", "titulo": "Acceso inicial", "tecnica": "T1190",
         "yml": "title: a\nid: 11111111-1111-1111-1111-111111111111\n"},
        {"id": "hz_b", "titulo": "Acceso inicial", "tecnica": "T1190",
         "yml": "title: b\nid: 22222222-2222-2222-2222-222222222222\n"},
    ]
    nombres = _nombres_sigma_unicos(generadas)
    assert len(nombres) == 2
    valores = list(nombres)
    assert len(set(valores)) == 2, "los nombres deben ser únicos"
    assert valores[0].startswith("T1190-") and valores[0].endswith(".yml")
    assert valores[1].startswith("T1190-") and "-2.yml" in valores[1]


def test_f23_zip_sin_duplicados_y_validacion_completa(tmp_path: Path) -> None:
    memoria = _caso_base(tmp_path, "caso_z3_f23")
    # Dos hallazgos con MISMO título (mismo slug) y MISMA técnica con fuente
    # conocida: activo distinto evita el dedup de memoria — exactamente el
    # caso que antes producía dos entradas ZIP con el mismo nombre.
    for i, activo in enumerate(("svc-backup", "svc-archivos"), 1):
        memoria.guardar_hallazgo(Hallazgo(
            id=f"hz_z3_f23_{i}", engagement_id="caso_z3_f23",
            titulo="Kerberoasting sin detección", severidad=Severidad.ALTA,
            tecnica_mitre="T1558.003", activo=activo,
            descripcion=f"Solicitudes RC4 contra {activo}",
            estado="confirmado", deteccion="no_detectado"))
    contenido, resumen = construir_paquete_purple("caso_z3_f23", memoria)
    with zipfile.ZipFile(io.BytesIO(contenido)) as zf:
        nombres_sigma = [n for n in zf.namelist()
                         if n.startswith("sigma/") and n.endswith(".yml")]
    assert len(nombres_sigma) == len(set(nombres_sigma)), (
        "el ZIP no debe contener entradas duplicadas")
    assert resumen["reglas"] == 2
    assert len(nombres_sigma) == 2, (
        "cada hallazgo con fuente conocida emite SU fichero, sin perder ninguno")
    assert resumen["sigma_validas"] == 2 and resumen["sigma_invalidas"] == 0


# ---------------------------------------------------------------------------
# F24 · sin errores duplicados en el veredicto Sigma
# ---------------------------------------------------------------------------

def test_f24_condicion_repetida_un_solo_error() -> None:
    regla = """title: prueba
id: 33333333-3333-3333-3333-333333333333
logsource:
  product: windows
  service: security
detection:
  sel:
    EventID: 4769
  condition: falta and falta
"""
    r = validar_regla(regla)
    errores_falta = [e for e in r["errores"] if "'falta'" in e]
    assert len(errores_falta) == 1, (
        f"'falta and falta' debe producir UN error, no {len(errores_falta)}")
