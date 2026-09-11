"""Tests v12: biblioteca de técnicas expuesta + endurecimiento de entrada.

Cubre las mejoras de esta ronda:
  1. GET /api/skills: catálogo REAL desde disco (total, distribución por
     fase/riesgo, contador de aprobación humana, campos de la portada).
  2. GET /api/skills/{nombre}: playbook completo bajo demanda con hash
     sha256 verificable del contenido.
  3. 404 accionable para técnica inexistente; 401 sin sesión (deny-by-default
     se mantiene en los endpoints nuevos).
  4. POST /api/skills/recargar: una skill AÑADIDA al disco aparece tras
     recargar SIN reiniciar (hot reload real, no simulado).
  5. skills.recargar(): índice reconstruido; _parsear de UNA lectura
     (hash correcto + portada YAML + cuerpo).
  6. Endurecimiento de producción: listas/dicts/textos sin límite ahora
     acotados (dominios ≤100, historial copiloto ≤20 turnos, opciones ≤50,
     elemento de alcance ≤253 chars) → 422 en lugar de consumo libre.
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from orchestrator.api import (  # noqa: E402
    PeticionAvanzar,
    PeticionCopiloto,
    PeticionCrear,
    PeticionRecargar,
    app,
)
from orchestrator.skills import BibliotecaSkills  # noqa: E402

SKILL_MD = """---
nombre: tecnica_prueba_v12
descripcion: "Playbook de prueba para la ronda v12: validación del catálogo expuesto al operador."
fase: "F2_recon"
tecnica_mitre: "T1046"
riesgo: "media"
requiere_aprobacion: true
fuentes_permitidas:
  - "lab (mock)"
---

# Skill: técnica de prueba v12

Procedimiento de prueba del catálogo de técnicas.
"""


@pytest.fixture()
def biblioteca_tmp(tmp_path):
    """Biblioteca de skills aislada en tmp con UNA técnica real."""
    carpeta = tmp_path / "tecnica_prueba_v12"
    carpeta.mkdir()
    (carpeta / "SKILL.md").write_text(SKILL_MD, encoding="utf-8")
    return tmp_path


@pytest.fixture()
def cliente_api(tmp_path, monkeypatch, biblioteca_tmp):
    """Cliente autenticado con skills apuntando al tmp (sin tocar el disco
    real del despliegue y sin contaminar usuarios.db). Resetea también la
    caché del catálogo para que cada test arranque con índice limpio."""
    from orchestrator import auth

    monkeypatch.setattr(auth, "RUTA_DB", tmp_path / "usuarios_test_v12.db")
    monkeypatch.setattr(auth, "_intentos", {})
    if not auth.hay_operadores():
        auth.crear_operador("opv12", "ClaveV12segura", rol="admin")
    token = auth.emitir_token("opv12", "admin")["token"]
    monkeypatch.setattr("orchestrator.api.RAIZ_SKILLS", biblioteca_tmp)
    monkeypatch.setattr("orchestrator.api._BIBLIOTECA_CATALOGO", None)
    cliente = TestClient(app)
    cliente.headers.update({"Authorization": f"Bearer {token}"})
    yield cliente


# ---------------------------------------------------------------------------
# 1-3) Catálogo y detalle de técnicas
# ---------------------------------------------------------------------------


def test_skills_catalogo_real(cliente_api) -> None:
    r = cliente_api.get("/api/skills")
    assert r.status_code == 200
    datos = r.json()
    assert datos["total"] == 1
    assert datos["por_fase"]["F2_recon"] == 1
    assert datos["por_riesgo"]["media"] == 1
    assert datos["con_aprobacion"] == 1
    t = datos["tecnicas"][0]
    assert t["nombre"] == "tecnica_prueba_v12"
    assert t["tecnica_mitre"] == "T1046"
    assert t["requiere_aprobacion"] is True
    assert t["fuentes_permitidas"] == ["lab (mock)"]


def test_skills_detalle_con_hash_verificable(cliente_api, biblioteca_tmp) -> None:
    r = cliente_api.get("/api/skills/tecnica_prueba_v12")
    assert r.status_code == 200
    datos = r.json()
    assert "# Skill: técnica de prueba v12" in datos["cuerpo"]
    esperado = hashlib.sha256(
        (biblioteca_tmp / "tecnica_prueba_v12" / "SKILL.md").read_bytes()
    ).hexdigest()
    assert datos["hash_contenido"] == esperado


def test_skill_inexistente_404_accionable(cliente_api) -> None:
    r = cliente_api.get("/api/skills/no_existe_v12")
    assert r.status_code == 404
    assert "1 disponibles" in r.json()["detail"]


def test_skills_requieren_sesion() -> None:
    # Deny-by-default se mantiene en TODOS los endpoints nuevos
    anonimo = TestClient(app)
    assert anonimo.get("/api/skills").status_code == 401
    assert anonimo.get("/api/skills/tecnica_prueba_v12").status_code == 401
    assert anonimo.post("/api/skills/recargar", json={}).status_code == 401


# ---------------------------------------------------------------------------
# 4-5) Recarga en caliente y biblioteca
# ---------------------------------------------------------------------------


def test_recargar_detecta_skill_nueva_sin_reiniciar(
    cliente_api, biblioteca_tmp
) -> None:
    # Antes de añadir: 1 técnica
    assert cliente_api.get("/api/skills").json()["total"] == 1
    # El operador añade una skill nueva al disco del despliegue
    nueva = biblioteca_tmp / "tecnica_segunda_v12"
    nueva.mkdir()
    (nueva / "SKILL.md").write_text(
        "---\nnombre: tecnica_segunda_v12\ndescripcion: \"segunda\"\n"
        "riesgo: \"baja\"\n---\n# Segunda\n", encoding="utf-8")
    # El índice EN MEMORIA de la API sigue obsoleto hasta recargar
    assert cliente_api.get("/api/skills").json()["total"] == 1
    # Recarga en caliente: sin reiniciar, el catálogo se actualiza
    r = cliente_api.post("/api/skills/recargar", json={"motivo": "test v12"})
    assert r.status_code == 200
    assert r.json()["total"] == 2
    assert cliente_api.get("/api/skills").json()["total"] == 2
    assert cliente_api.get("/api/skills/tecnica_segunda_v12").status_code == 200


def test_recargar_motivo_tambien_funciona_vacio(cliente_api) -> None:
    r = cliente_api.post("/api/skills/recargar", json={})
    assert r.status_code == 200
    assert r.json()["total"] == 1


def test_biblioteca_recargar_reconstruye_indice(tmp_path) -> None:
    biblio = BibliotecaSkills(tmp_path)
    assert biblio.listar() == []
    carpeta = tmp_path / "algo"
    carpeta.mkdir()
    (carpeta / "SKILL.md").write_text(
        "---\nnombre: algo\ndescripcion: \"x\"\n---\ncuerpo", encoding="utf-8")
    assert biblio.recargar() == 1
    assert biblio.obtener("algo") is not None


def test_parsear_una_lectura_hash_y_cuerpo(tmp_path) -> None:
    carpeta = tmp_path / "tecnica_prueba_v12"
    carpeta.mkdir()
    (carpeta / "SKILL.md").write_text(SKILL_MD, encoding="utf-8")
    biblio = BibliotecaSkills(tmp_path)
    skill = biblio.obtener("tecnica_prueba_v12")
    assert skill is not None
    contenido = SKILL_MD.encode("utf-8")
    assert skill.hash_contenido == hashlib.sha256(contenido).hexdigest()
    # el cuerpo conserva el playbook completo (sin la portada YAML)
    assert "# Skill: técnica de prueba v12" in skill.cargar_cuerpo()
    assert skill.portada.fase == "F2_recon"


def test_peticion_recargar_motivo_acotado() -> None:
    with pytest.raises(Exception):
        PeticionRecargar(motivo="x" * 500)


# ---------------------------------------------------------------------------
# 6) Endurecimiento de entrada (422, no consumo libre)
# ---------------------------------------------------------------------------


def test_crear_rechaza_mas_de_100_dominios() -> None:
    with pytest.raises(Exception):
        PeticionCrear.model_validate({
            "nombre": "caso", "cliente": "acme",
            "alcance_dominios": [f"d{i}.example.com" for i in range(101)],
        })


def test_crear_rechaza_elemento_de_alcance_gigante() -> None:
    with pytest.raises(Exception):
        PeticionCrear.model_validate({
            "nombre": "caso", "cliente": "acme",
            "alcance_dominios": ["a" * 300 + ".com"],
        })


def test_avanzar_rechaza_mas_de_50_opciones() -> None:
    with pytest.raises(Exception):
        PeticionAvanzar.model_validate({
            "opciones": {f"k{i}": "v" for i in range(51)},
        })


def test_avanzar_rechaza_valor_de_opcion_gigante() -> None:
    with pytest.raises(Exception):
        PeticionAvanzar.model_validate({"opciones": {"RHOSTS": "x" * 600}})


def test_copiloto_rechaza_historial_de_mas_de_20_turnos() -> None:
    turnos = [{"rol": "operador", "texto": "hola"} for _ in range(21)]
    with pytest.raises(Exception):
        PeticionCopiloto.model_validate({"pregunta": "estado del caso", "historial": turnos})


def test_copiloto_acepta_historial_limite() -> None:
    turnos = [{"rol": "operador", "texto": "hola"} for _ in range(20)]
    p = PeticionCopiloto.model_validate({"pregunta": "estado del caso", "historial": turnos})
    assert len(p.historial) == 20


def test_crear_acepta_carga_normal_intacta() -> None:
    # El endurecimiento NO rompe el uso legítimo de la consola
    p = PeticionCrear.model_validate({
        "nombre": "caso legítimo", "cliente": "acme",
        "alcance_dominios": ["cliente.com", "otro.com"],
        "alcance_cidrs": ["10.0.0.0/8"],
        "tecnicas_prohibidas": ["T1485", "T1489"],
        "ventana_dias": ["lun", "vie"],
    })
    assert len(p.alcance_dominios) == 2
    assert p.tecnicas_prohibidas == ["T1485", "T1489"]
