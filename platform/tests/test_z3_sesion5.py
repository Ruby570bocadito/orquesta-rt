"""Tests z3 — sesión 5: aislamiento multi-tenant en analítica, higiene de
repositorio y validación SMTP (cabeceras de correo).

Cubre los fixes de esta ronda:
  F31  /api/analitica/cobertura-attack y .csv agregaban SIEMPRE todas las
       BDs del despliegue y exponían nombre/cliente/fase/resultados de
       campañas de OTRAS organizaciones a cualquier cuenta autenticada.
       Ahora el no-admin solo agrega los casos de SU tenant (unit + API).
  F32  Las BDs de caso (casos/*.db) estaban TRACKED en git (regresión de la
       política F1 de la sesión 1: los .gitignore no des-trackean ficheros
       ya commiteados). Test de higiene: git no lleva ninguna BD.
  F33  smtp_envio.enviar aceptaba destinatarios con CRLF / estructura de
       cabecera ("a@b.com, Bcc: x") y asuntos con saltos de línea — el
       EmailMessage moderno neutraliza parte del riesgo, pero la frontera
       ahora es explícita: solo direcciones email válidas y asunto
       monolínea; con CUALQUIER destinatario inválido no se envía nada.
"""
from __future__ import annotations

import sqlite3
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fastapi.testclient import TestClient  # noqa: E402

from orchestrator import auth  # noqa: E402
from orchestrator.api import app  # noqa: E402
from orchestrator.cobertura_attack import (  # noqa: E402
    construir_cobertura, csv_cobertura,
)
from orchestrator.models import (  # noqa: E402
    Engagement, Fase, Hallazgo, ROEPolitica, Severidad,
)
from integraciones import smtp_envio  # noqa: E402

RAIZ_REPO = Path(__file__).resolve().parents[2]


# ---------------------------------------------------------------------------
# utilidades de montaje
# ---------------------------------------------------------------------------


def _memoria_tenant(ruta: Path, id_caso: str, tenant: str = "predeterminada"):
    from orchestrator.memory import MemoriaCaso

    m = MemoriaCaso(ruta)
    roe = ROEPolitica.model_validate({
        "engagement_id": id_caso, "cliente": "acme",
        "alcance_dominios": ["cliente.com"],
        "alcance_cidrs": ["192.168.1.0/24"],
    })
    ahora = datetime.now(timezone.utc)
    m.crear_engagement(Engagement(
        id=id_caso, nombre=f"caso {id_caso}", cliente="acme", roe=roe,
        fase_actual=Fase.F4_DOMINIO, tenant_id=tenant,
        creado_en=ahora, actualizado_en=ahora))
    return m


def _hal(m, id_caso: str, n: int, tecnica: str, sev: Severidad,
         deteccion: str) -> None:
    h = Hallazgo(
        id=f"hal_{n}", engagement_id=id_caso, titulo=f"hallazgo {n}",
        severidad=sev, tecnica_mitre=tecnica, estado="confirmado",
        activo="host01")
    m.guardar_hallazgo(h)
    m.marcar_deteccion(id_caso, h.id, deteccion)


# ---------------------------------------------------------------------------
# F31 — aislamiento multi-tenant en la analítica (unit)
# ---------------------------------------------------------------------------


def test_cobertura_filtro_tenant_aisla_campañas(tmp_path) -> None:
    """Con tenant_filtro, la agregación SOLO incluye campañas de ese tenant;
    sin filtro (admin) ve las dos. Sin filtro NO cambió el contrato."""
    a = _memoria_tenant(tmp_path / "caso_aaa.db", "caso_aaa", tenant="org-a")
    _hal(a, "caso_aaa", 1, "T1558.003", Severidad.ALTA, "detectado")
    a.cerrar()
    b = _memoria_tenant(tmp_path / "caso_bbb.db", "caso_bbb", tenant="org-b")
    _hal(b, "caso_bbb", 1, "T1110.001", Severidad.CRITICA, "no_detectado")
    b.cerrar()

    # admin (filtro None): despliegue completo
    completo = construir_cobertura(tmp_path)
    assert {x["id"] for x in completo["campañas"]} == {"caso_aaa", "caso_bbb"}
    assert completo["totales"]["campañas"] == 2

    # lector de org-a: solo SU campaña; ni el nombre ni el cliente de la otra
    solo_a = construir_cobertura(tmp_path, tenant_filtro="org-a")
    assert [x["id"] for x in solo_a["campañas"]] == ["caso_aaa"]
    assert solo_a["totales"]["campañas"] == 1
    assert all("caso_bbb" not in fila["celdas"] or fila["celdas"]["caso_bbb"] is None
               for fila in solo_a["matriz"])
    # la BD omitida NO es un "error": es un caso de otro tenant
    assert solo_a["errores"] == []

    solo_b = construir_cobertura(tmp_path, tenant_filtro="org-b")
    assert [x["id"] for x in solo_b["campañas"]] == ["caso_bbb"]


def test_cobertura_tenant_por_defecto_y_csv_filtrado(tmp_path) -> None:
    """Los casos creados antes de la migración de tenants llevan
    'predeterminada': el filtro debe encontrarlos igualmente, y el CSV
    hereda el mismo aislamiento."""
    m = _memoria_tenant(tmp_path / "caso_x1.db", "caso_x1",
                        tenant="predeterminada")
    _hal(m, "caso_x1", 1, "T1059.001", Severidad.ALTA, "detectado")
    m.cerrar()
    otro = _memoria_tenant(tmp_path / "caso_x2.db", "caso_x2", tenant="org-z")
    otro.cerrar()

    solo_pred = construir_cobertura(tmp_path, tenant_filtro="predeterminada")
    assert [x["id"] for x in solo_pred["campañas"]] == ["caso_x1"]

    texto = csv_cobertura(solo_pred)
    assert "caso_x1" in texto and "caso_x2" not in texto


# ---------------------------------------------------------------------------
# F31 — aislamiento multi-tenant en la analítica (API real)
# ---------------------------------------------------------------------------


@pytest.fixture()
def api_tenant(tmp_path, monkeypatch):
    """API con dos tenants (org-a/org-b), admin global y lector de org-a."""
    monkeypatch.setattr(auth, "RUTA_DB", tmp_path / "usuarios_s5.db")
    monkeypatch.setattr(auth, "_intentos", {})
    auth.crear_organizacion("org-a", "Organización A")
    auth.crear_organizacion("org-b", "Organización B")
    auth.crear_operador("admin5", "ClaveAdmin5segura", rol="admin")
    auth.crear_operador("lectorA", "ClaveLector5segura", rol="lector",
                        tenant_id="org-a")

    # casos: uno por organización (los .db viven en la raíz temporal)
    monkeypatch.setattr("orchestrator.api.RAIZ_CASOS", tmp_path)
    a = _memoria_tenant(tmp_path / "caso_aaa.db", "caso_aaa", tenant="org-a")
    _hal(a, "caso_aaa", 1, "T1558.003", Severidad.ALTA, "detectado")
    a.cerrar()
    b = _memoria_tenant(tmp_path / "caso_bbb.db", "caso_bbb", tenant="org-b")
    _hal(b, "caso_bbb", 1, "T1110.001", Severidad.CRITICA, "detectado")
    b.cerrar()

    def _cliente(usuario: str, rol: str, tenant: str = "predeterminada"):
        token = auth.emitir_token(usuario, rol, tenant)["token"]
        c = TestClient(app)
        c.headers.update({"Authorization": f"Bearer {token}"})
        return c

    yield _cliente


def test_api_cobertura_admin_ve_todo(api_tenant) -> None:
    r = api_tenant("admin5", "admin").get("/api/analitica/cobertura-attack")
    assert r.status_code == 200, r.text
    assert {x["id"] for x in r.json()["campañas"]} == {"caso_aaa", "caso_bbb"}


def test_api_cobertura_lector_otros_tenant_aislado(api_tenant) -> None:
    """REGRESIÓN F31: el lector de org-a antes recibía la campaña de org-b
    con su nombre, cliente y cobertura de detección."""
    r = api_tenant("lectorA", "lector", "org-a").get(
        "/api/analitica/cobertura-attack")
    assert r.status_code == 200, r.text
    campañas = r.json()["campañas"]
    assert [x["id"] for x in campañas] == ["caso_aaa"]
    crudo = r.text
    assert "caso_bbb" not in crudo and "caso caso_bbb" not in crudo

    # el CSV hereda el mismo aislamiento
    csv = api_tenant("lectorA", "lector", "org-a").get(
        "/api/analitica/cobertura-attack.csv")
    assert csv.status_code == 200
    assert "caso_aaa" in csv.text and "caso_bbb" not in csv.text


# ---------------------------------------------------------------------------
# F33 — validación de cabeceras SMTP
# ---------------------------------------------------------------------------


def test_smtp_destinatarios_validos_unitarios() -> None:
    validas, invalidas = smtp_envio._validar_destinatarios([
        " usuario@cliente.com ", "op2@equipo.local",
    ])
    assert validas == ["usuario@cliente.com", "op2@equipo.local"]
    assert invalidas == []


def test_smtp_destinatario_crlf_rechazado() -> None:
    """REGRESIÓN F33: CRLF/cabecera embebida jamás llega a EmailMessage."""
    _, invalidas = smtp_envio._validar_destinatarios([
        "a@b.com\r\nBcc: victima@ex.com",
        "a@b.com\nSubject: falsificado",
        "a@b.com, c@d.com",          # lista embebida en una entrada
        "Fulano <a@b.com>",          # ángulos: no son una dirección plana
        "", "sin-arroba",
    ])
    assert len(invalidas) == 6


def test_smtp_enviar_no_envia_con_invalidos(monkeypatch) -> None:
    """Con CUALQUIER destinatario inválido no hay conexión SMTP (ni envío
    parcial de los 'buenos'): la campaña autorizada se rechaza entera."""
    conectado = {"veces": 0}

    class _Prohibido:  # cualquier uso de smtplib aquí es un fallo del test
        def __getattr__(self, nombre):
            raise AssertionError("smtplib no debe tocarse con destinatarios inválidos")

    monkeypatch.setitem(sys.modules, "smtplib", _Prohibido())
    resultado = smtp_envio.enviar(
        ["jefe@cliente.com", "x@y.com\r\nBcc: robo@ex.com"],
        "Asunto legítimo", "<p>hola</p>")
    assert resultado["enviado"] is False
    assert "destinatarios inválidos" in resultado["error"]
    del conectado  # silencio de linting: la guarda real es _Prohibido


def test_smtp_asunto_monolinea() -> None:
    """El asunto viaja en una cabecera: los saltos de línea se colapsan."""
    sucio = "Informe F6\r\nBcc: victima@ex.com\nsegunda línea"
    assert "\r" not in smtp_envio._asunto_seguro(sucio)
    assert "\n" not in smtp_envio._asunto_seguro(sucio)
    assert smtp_envio._asunto_seguro(None) == ""


# ---------------------------------------------------------------------------
# F32 — higiene del repositorio: ninguna BD de runtime en git
# ---------------------------------------------------------------------------


def test_repo_sin_bds_trackeadas() -> None:
    """REGRESIÓN F32: `casos/*.db` estaban TRACKED (el .gitignore no
    des-trackea). `git ls-files` no debe contener ninguna BD de datos."""
    if not (RAIZ_REPO / ".git").exists():
        pytest.skip("sin .git (distribución empaquetada)")
    tracked = subprocess.run(
        ["git", "ls-files"], cwd=RAIZ_REPO, capture_output=True, text=True,
        timeout=30).stdout.splitlines()
    bds = [f for f in tracked if f.endswith((".db", ".db-wal", ".db-shm"))]
    assert bds == [], (
        "BDs de runtime de vuelta en el índice de git: "
        + ", ".join(bds))
    # y la política de .gitignore sigue escrita (defensa de superficie)
    gitignore = (RAIZ_REPO / ".gitignore").read_text(encoding="utf-8")
    for regla in ("usuarios.db", "/casos/", "*.db"):
        assert regla in gitignore
