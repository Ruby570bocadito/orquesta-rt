"""Tests v13: copiloto con contexto ampliado, biblioteca ampliada e higiene.

Cubre las mejoras de esta ronda:
  1. Copiloto: el contexto incluye COSTE DEL CASO (tokens + presupuesto
     cuando existe), ÚLTIMA ACTIVIDAD (timeline real de auditoría) y
     ARSENAL (índice de técnicas del despliegue). Sin arsenal dice
     explícitamente que la biblioteca está vacía: nunca lo inventa.
  2. copiloto.consultar(): el arsenal llega al prompt del modelo (stub de
     router, sin llamada real).
  3. Biblioteca ampliada: los dos playbooks nuevos (asrep_roasting_lab,
     llmnr_poisoning_lab) se parsean del disco real con portada completa
     (fase/ATT&CK/riesgo/aprobación) y hash verificable.
  4. Higiene estructural (anti-regresión): los huérfanos del template
     (examples/, tests/, prisma/, db.ts, componentes ui no usados) NO
     vuelven al repositorio, y package.json no vuelve a arrastrar
     dependencias muertas.
  5. Scripts de arranque sintácticamente válidos (start.sh, stop.sh,
     dev-supervisor.sh) y con rotación de logs presente.
"""
from __future__ import annotations

import hashlib
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from orchestrator import copiloto  # noqa: E402
from orchestrator.skills import BibliotecaSkills  # noqa: E402

RAIZ_PROYECTO = Path(__file__).resolve().parents[2]
RAIZ_SKILLS_REALES = Path(__file__).resolve().parents[1] / "skills"


# ---------------------------------------------------------------------------
# 1-2. Copiloto: contexto ampliado (stubs, sin llamadas de red ni BD)
# ---------------------------------------------------------------------------

class _FilaEngagement(dict):
    """Fila de engagement con acceso tipo sqlite3.Row (dict ya lo da)."""


class _MemoriaStub:
    """Memoria mínima para construir_contexto: datos reales en memoria.

    El RAG (busqueda.documentos_de_caso) itera evidencias, hallazgos,
    objetivos, aprobaciones y auditoría con columnas completas; se
    aportan con la forma de fila del SQL real. resumenes_fase se sirve
    de una sqlite en memoria.
    """

    def __init__(self, con_presupuesto: bool = True):
        self.con_presupuesto = con_presupuesto
        import sqlite3
        self._conn = sqlite3.connect(":memory:")
        self._conn.row_factory = sqlite3.Row
        self._conn.execute(
            "CREATE TABLE resumenes_fase (id INTEGER PRIMARY KEY, "
            "engagement_id TEXT, fase TEXT, texto TEXT, creado_en TEXT)")
        self._conn.execute(
            "INSERT INTO resumenes_fase (engagement_id, fase, texto, creado_en) "
            "VALUES ('caso_x', 'F4_dominio_ad', "
            "'Resumen de prueba de la fase', '2026-09-11T10:00:00Z')")

    def obtener_engagement(self, _id: str) -> dict[str, Any]:
        return _FilaEngagement(
            nombre="Caso Prueba", cliente="Cliente Prueba",
            fase_actual="F4_dominio_ad", estado_fase="en_curso",
            roe_json=('{"alcance": {"dominios": ["lab.local"], "cidrs": '
                      '["127.0.0.0/8"], "excluido": []}, '
                      '"ventana_horaria": {"inicio": "09:00", "fin": "17:00"}, '
                      '"techo_ruido": 40, "tecnicas_prohibidas": []}'),
            coste_acumulado_usd=0.1234, tokens_acumulados=2500,
        )

    def listar_objetivos(self, _id: str) -> list[dict[str, Any]]:
        return [{"id": 1, "nombre": "dc01", "tipo": "host",
                 "estado": "descubierto", "detalle": "controlador de dominio del lab",
                 "fase": "F2_recon", "descubierto_en": "2026-09-11T09:00:00Z"}]

    def listar_hallazgos(self, _id: str) -> list[dict[str, Any]]:
        return [{"id": 1, "titulo": "Cuenta sin preauth", "severidad": "alta",
                 "descripcion": "cuenta sin preautenticación Kerberos",
                 "recomendacion": "habilitar preauth", "activo": "cuenta_svc",
                 "tecnica_mitre": "T1558.004",
                 "creado_en": "2026-09-11T10:30:00Z"}]

    def listar_aprobaciones(self, _id: str, solo_pendientes: bool = False) -> list[dict[str, Any]]:
        if not solo_pendientes:
            return []
        return [{"id": 1, "titulo": "Aprobación pendiente de prueba",
                 "motivo": "evaluar técnica", "descripcion": "detalle",
                 "herramienta": "ad.asrep", "estado": "pendiente",
                 "decidida_por": None, "fase": "F4_dominio_ad",
                 "creada_en": "2026-09-11T10:35:00Z"}]

    def listar_auditoria(self, _id: str, limite: int = 500) -> list[dict[str, Any]]:
        # orden DESC (más reciente primero), como el SQL real
        return [
            {"id": 2, "accion": "copiloto_consulta", "actor": "humano",
             "detalle": "consulta de prueba", "resultado": "ok",
             "creado_en": "2026-09-11T11:00:00Z"},
            {"id": 1, "accion": "roe_firmado", "actor": "humano",
             "detalle": "ROE firmado", "resultado": "ok",
             "creado_en": "2026-09-11T09:30:00Z"},
        ]

    def listar_evidencias(self, _id: str) -> list[dict[str, Any]]:
        return []

    def listar_resumenes(self, _id: str) -> list[dict[str, Any]]:  # noqa: N802
        return []

    def config_caso(self, _id: str, clave: str) -> str | None:
        if clave == "presupuesto_caso_tokens":
            return "10000" if self.con_presupuesto else None
        return None


ARSenal_PRUEBA = (
    "- kerberoasting_lab: auditar cuentas de servicio con SPN "
    "[fase=F4_dominio_ad | ATT&CK=T1558.003 | riesgo=alta]"
)


def test_contexto_incluye_coste_con_presupuesto() -> None:
    datos = copiloto.construir_contexto(
        _MemoriaStub(), "caso_x", "¿qué sigue?", arsenal=ARSenal_PRUEBA)
    assert "COSTE DEL CASO: 0.1234 USD · 2500 tokens" in datos["contexto"]
    assert "de un presupuesto de 10000 (25% consumido)" in datos["contexto"]


def test_contexto_coste_sin_presupuesto_no_miente() -> None:
    datos = copiloto.construir_contexto(
        _MemoriaStub(con_presupuesto=False), "caso_x", "¿qué sigue?",
        arsenal=ARSenal_PRUEBA)
    assert "sin presupuesto fijado para el caso" in datos["contexto"]
    assert "%" not in datos["contexto"].split("COSTE DEL CASO:")[1].split("\n")[0]


def test_contexto_incluye_ultima_actividad_orden_cronologico() -> None:
    datos = copiloto.construir_contexto(
        _MemoriaStub(), "caso_x", "¿qué sigue?", arsenal=ARSenal_PRUEBA)
    linea = [l for l in datos["contexto"].splitlines()
             if l.startswith("ÚLTIMA ACTIVIDAD")][0]
    # más reciente al final: roe_firmado (antiguo) antes que copiloto_consulta
    assert linea.index("roe_firmado") < linea.index("copiloto_consulta")


def test_contexto_incluye_arsenal_y_no_lo_inventa_si_vacio() -> None:
    con_arsenal = copiloto.construir_contexto(
        _MemoriaStub(), "caso_x", "q", arsenal=ARSenal_PRUEBA)
    assert "kerberoasting_lab" in con_arsenal["contexto"]
    sin_arsenal = copiloto.construir_contexto(_MemoriaStub(), "caso_x", "q")
    assert "biblioteca de técnicas vacía" in sin_arsenal["contexto"]
    assert "kerberoasting_lab" not in sin_arsenal["contexto"]


def test_consultar_pasaba_el_arsenal_al_prompt() -> None:
    """Stub de router: captura el prompt y verifica que el arsenal viaja."""
    capturado: dict[str, str] = {}

    class _Respuesta:
        texto = "## Observaciones\nok"
        modelo = "stub"
        tipo = type("T", (), {"value": "local"})()
        tokens_entrada = 1
        tokens_salida = 1
        coste_usd = 0.0

    class _RouterStub:
        def completar(self, **kwargs):
            capturado["usuario"] = kwargs["usuario"]
            return _Respuesta()

    copiloto.consultar(_MemoriaStub(), _RouterStub(), "caso_x", "¿y ahora?",
                       arsenal=ARSenal_PRUEBA)
    assert "kerberoasting_lab" in capturado["usuario"]


# ---------------------------------------------------------------------------
# 3. Biblioteca ampliada: playbooks nuevos parsean del disco real
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("nombre,fase,mitre", [
    ("asrep_roasting_lab", "F4_dominio_ad", "T1558.004"),
    ("llmnr_poisoning_lab", "F3_acceso_inicial", "T1557.001"),
])
def test_playbook_nuevo_parsea_completo(nombre: str, fase: str, mitre: str) -> None:
    biblioteca = BibliotecaSkills(RAIZ_SKILLS_REALES)
    skill = biblioteca.obtener(nombre)
    assert skill is not None, f"{nombre} debe existir en la biblioteca real"
    assert skill.portada.fase == fase
    assert skill.portada.tecnica_mitre == mitre
    assert skill.portada.riesgo == "alta"
    assert skill.portada.requiere_aprobacion is True
    assert skill.portada.fuentes_permitidas, "el playbook declara fuentes"
    # cuerpo sustancial y hash verificable contra el disco
    cuerpo = skill.cargar_cuerpo()
    assert len(cuerpo) > 1500, "playbook real, no una ficha vacía"
    assert "Propósito" in cuerpo and "blue team" in cuerpo.lower()
    hash_disco = hashlib.sha256(skill.ruta.read_bytes()).hexdigest()
    assert skill.hash_contenido == hash_disco


def test_biblioteca_real_tiene_tres_playbooks() -> None:
    biblioteca = BibliotecaSkills(RAIZ_SKILLS_REALES)
    nombres = {s.nombre for s in biblioteca.listar()}
    assert {"kerberoasting_lab", "asrep_roasting_lab",
            "llmnr_poisoning_lab"} <= nombres


def test_arsenal_para_copiloto_cita_fase_y_attack() -> None:
    """El índice que recibe el copiloto incluye fase y ATT&CK por técnica."""
    indice = BibliotecaSkills(RAIZ_SKILLS_REALES).indice_para_prompt()
    assert "T1558.004" in indice and "T1557.001" in indice
    assert "fase=" in indice and "riesgo=" in indice


# ---------------------------------------------------------------------------
# 4. Higiene estructural: los huérfanos del template no vuelven
# ---------------------------------------------------------------------------

def test_no_quedan_huerfanos_del_template() -> None:
    for huérfano in ("examples", "tests", "prisma"):
        assert not (RAIZ_PROYECTO / huérfano).exists(), \
            f"{huérfano}/ del template no debe existir"
    assert not (RAIZ_PROYECTO / "src" / "lib" / "db.ts").exists()
    assert not (RAIZ_PROYECTO / "db" / "custom.db").exists()
    # componentes ui no usados por la consola (los 10 usados se conservan)
    for ui in ("sidebar.tsx", "calendar.tsx", "form.tsx", "carousel.tsx",
               "drawer.tsx", "sonner.tsx", "table.tsx"):
        assert not (RAIZ_PROYECTO / "src" / "components" / "ui" / ui).exists()


def test_package_json_sin_dependencias_muertas() -> None:
    import json
    paquete = json.loads((RAIZ_PROYECTO / "package.json").read_text())
    deps = paquete["dependencies"]
    for muerta in ("@prisma/client", "prisma", "next-auth", "zod", "uuid",
                   "sharp", "date-fns", "react-hook-form", "embla-carousel-react",
                   "@dnd-kit/core", "@tanstack/react-query", "sonner"):
        assert muerta not in deps, f"dependencia muerta: {muerta}"
    # y las que SUSTENTAN la consola siguen presentes
    for viva in ("next", "react", "zustand", "z-ai-web-dev-sdk", "recharts",
                 "framer-motion", "cmdk"):
        assert viva in deps, f"falta dependencia estructural: {viva}"
    # scripts sin 'tee' (los logs los gestionan el guardián y start.sh)
    for guion in paquete["scripts"].values():
        assert "tee " not in guion, "el tee duplica logs sin límite"


def test_ui_usados_intactos() -> None:
    for ui in ("alert-dialog", "button", "command", "dialog", "input",
               "label", "select", "textarea", "toast", "toaster"):
        assert (RAIZ_PROYECTO / "src" / "components" / "ui" / f"{ui}.tsx").exists()


# ---------------------------------------------------------------------------
# 5. Scripts de arranque: sintaxis y rotación de logs
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("script", ["start.sh", "stop.sh",
                                    "scripts/dev-supervisor.sh"])
def test_scripts_bash_sintaxis_valida(script: str) -> None:
    ruta = RAIZ_PROYECTO / script
    assert ruta.exists(), f"{script} debe existir"
    resultado = subprocess.run(["bash", "-n", str(ruta)], capture_output=True)
    assert resultado.returncode == 0, resultado.stderr.decode()


def test_rotacion_de_logs_presente() -> None:
    supervisor = (RAIZ_PROYECTO / "scripts" / "dev-supervisor.sh").read_text()
    assert "rotar_log" in supervisor, "el guardián rota su log en caliente"
    assert "MODO_CONSOLA" in supervisor, "el guardián soporta modo producción"
    arranque = (RAIZ_PROYECTO / "start.sh").read_text()
    assert "rotar_log" in arranque, "start.sh rota api.log/lab.log al arrancar"
    assert "MODO_CONSOLA" in arranque, "start.sh selecciona dev/prod"
