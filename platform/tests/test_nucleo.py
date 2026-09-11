"""Tests del núcleo de dominio: guardrails, memoria y cadena de custodia.

Estos tests NO requieren langgraph ni backends de LLM: validan la parte
que hace vendible la plataforma (cap. 5): el boundary no negocia.

Ejecutar:  cd platform && python -m pytest tests/ -v
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from orchestrator.guardrails import MotorGuardrails, Veredicto  # noqa: E402
from orchestrator.memory import MemoriaCaso  # noqa: E402
from orchestrator.models import (  # noqa: E402
    Actor,
    DecisionGuardrail,
    Evidencia,
    Fase,
    ROEPolitica,
    Severidad,
    TipoEvidencia,
    UsoTokens,
)
from orchestrator.demo_seed import sembrar_demo  # noqa: E402


def _roe(tmp_path: Path) -> ROEPolitica:
    return ROEPolitica(
        engagement_id="caso_test",
        cliente="Cliente de prueba",
        alcance_dominios=["cliente.com", "lab.cliente.com"],
        alcance_cidrs=["10.30.0.0/24"],
        alcance_excluido=["10.30.0.1"],
        tecnicas_prohibidas=["T1485", "T1489"],
        tecnicas_con_aprobacion=["T1558.003"],
        techo_ruido=50,
    )


# ---------------------------------------------------------------------------
# Guardrails: el boundary no negocia
# ---------------------------------------------------------------------------


class TestGuardrails:
    def _motor(self, tmp_path):
        memoria = MemoriaCaso(tmp_path / "test.db")
        return MotorGuardrails(_roe(tmp_path), memoria), memoria

    def test_fuera_de_scope_deniega(self, tmp_path):
        motor, _ = self._motor(tmp_path)
        v = motor.evaluar("recon.port_scan", {"host": "vecino-malvado.net"}, Fase.F2_RECON)
        assert v.denegado
        assert "fuera de alcance" in v.motivo.lower() or "fuera del alcance" in v.motivo.lower()

    def test_excluido_deniega_incluso_en_scope(self, tmp_path):
        motor, _ = self._motor(tmp_path)
        v = motor.evaluar("recon.http_probe", {"url": "https://10.30.0.1/"}, Fase.F2_RECON)
        assert v.denegado
        assert "excluido" in v.motivo.lower()

    def test_dentro_de_scope_permitido(self, tmp_path):
        motor, _ = self._motor(tmp_path)
        v = motor.evaluar("recon.dns_enum", {"dominio": "lab.cliente.com"}, Fase.F1_OSINT)
        assert v.permitido

    def test_tecnica_prohibida_deniega(self, tmp_path):
        motor, _ = self._motor(tmp_path)
        v = motor.evaluar("destruir.ejecutar_test",
                          {"objetivo": "lab.cliente.com", "tecnica_mitre": "T1485"},
                          Fase.F5_C2)
        # Destructivas: denegadas por catálogo aunque no esté catalogada
        assert v.denegado

    def test_kerberoasting_requiere_aprobacion(self, tmp_path):
        motor, memoria = self._motor(tmp_path)
        # Reloj inyectado DENTRO de la ventana 08:00-20:00: el boundary es
        # determinista y el test no depende de la hora del entorno.
        import datetime as _dt
        momento = _dt.datetime(2026, 1, 5, 10, 30)  # lunes 10:30
        v = motor.evaluar("ad.kerberoasting",
                          {"dominio": "lab.cliente.com", "tecnica_mitre": "T1558.003"},
                          Fase.F4_DOMINIO, momento=momento)
        assert v.decision == DecisionGuardrail.REQUIERE_APROBACION
        # Y la petición quedó persistida para la consola
        pendientes = memoria.listar_aprobaciones("caso_test", solo_pendientes=True)
        assert any(p["tecnica_mitre"] == "T1558.003" for p in pendientes)

    def test_herramienta_destructiva_bloqueada_siempre(self, tmp_path):
        motor, _ = self._motor(tmp_path)
        v = motor.evaluar("wipe.discos", {"objetivo": "lab.cliente.com"}, Fase.F5_C2)
        assert v.denegado
        assert "destructiva" in v.motivo.lower()

    def test_herramienta_desconocida_menor_privilegio(self, tmp_path):
        motor, _ = self._motor(tmp_path)
        v = motor.evaluar("mcp.desconocida.hacer_algo", {}, Fase.F2_RECON)
        assert v.decision == DecisionGuardrail.REQUIERE_APROBACION

    def test_decision_auditable(self, tmp_path):
        motor, memoria = self._motor(tmp_path)
        motor.evaluar("recon.dns_enum", {"dominio": "cliente.com"}, Fase.F1_OSINT)
        registros = memoria.listar_auditoria("caso_test")
        assert any(r["accion"] == "boundary:recon.dns_enum" for r in registros)


# ---------------------------------------------------------------------------
# Memoria: auditoría append-only y cadena de custodia
# ---------------------------------------------------------------------------


class TestMemoria:
    def _memoria(self, tmp_path) -> MemoriaCaso:
        return MemoriaCaso(tmp_path / "caso.db")

    def test_auditoria_es_append_only(self, tmp_path):
        memoria = self._memoria(tmp_path)
        memoria.registrar_auditoria("caso_x", Actor.AGENTE, "prueba", detalle="hola")
        with pytest.raises(Exception):
            memoria._conn.execute(
                "UPDATE auditoria SET detalle='manipulado' WHERE accion='prueba'")

    def test_cadena_custodia_valida(self, tmp_path):
        memoria = self._memoria(tmp_path)
        for i in range(5):
            memoria.guardar_evidencia(Evidencia(
                id=f"ev_{i}", engagement_id="caso_x", tipo=TipoEvidencia.JSON,
                titulo=f"Evidencia {i}", contenido=f"contenido-{i}",
                fase=Fase.F1_OSINT))
        assert memoria.verificar_cadena("caso_x")["valida"] is True

    def test_cadena_detecta_manipulacion(self, tmp_path):
        memoria = self._memoria(tmp_path)
        memoria.guardar_evidencia(Evidencia(
            id="ev_a", engagement_id="caso_x", tipo=TipoEvidencia.NOTA,
            titulo="A", contenido="original", fase=Fase.F1_OSINT))
        memoria.guardar_evidencia(Evidencia(
            id="ev_b", engagement_id="caso_x", tipo=TipoEvidencia.NOTA,
            titulo="B", contenido="b", fase=Fase.F1_OSINT))
        # Manipulación directa en BD: el hash deja de coincidir con la firma
        memoria._conn.execute(
            "UPDATE evidencias SET contenido='manipulado' WHERE id='ev_a'")
        memoria._conn.commit()
        resultado = memoria.verificar_cadena("caso_x")
        assert resultado["valida"] is False

    def test_economia_tokens_acumulada(self, tmp_path):
        memoria = self._memoria(tmp_path)
        from orchestrator.models import Engagement
        eng = Engagement(id="caso_t", nombre="t", cliente="c",
                         roe=_roe(tmp_path))
        memoria.crear_engagement(eng)
        memoria.registrar_uso_tokens("caso_t", UsoTokens(
            fase=Fase.F1_OSINT, modelo="local-1", tipo="local",
            tokens_entrada=1000, tokens_salida=200))
        memoria.registrar_uso_tokens("caso_t", UsoTokens(
            fase=Fase.F1_OSINT, modelo="local-1", tipo="local",
            tokens_entrada=500, tokens_salida=100, coste_usd=0.5))
        resumen = memoria.resumen_tokens("caso_t")
        assert resumen["por_fase"][0]["tokens"] == 1800
        fila = memoria.obtener_engagement("caso_t")
        assert fila["tokens_acumulados"] == 1800
        assert abs(fila["coste_acumulado_usd"] - 0.5) < 1e-9


# ---------------------------------------------------------------------------
# Seeder de demo: recorre las rutas reales
# ---------------------------------------------------------------------------


def test_demo_seed_integro(tmp_path):
    eid = sembrar_demo(tmp_path)
    memoria = MemoriaCaso(tmp_path / f"{eid}.db")
    assert memoria.verificar_cadena(eid)["valida"]
    assert len(memoria.listar_aprobaciones(eid)) >= 2
    pendientes = memoria.listar_aprobaciones(eid, solo_pendientes=True)
    assert any("T1558.003" in (p["tecnica_mitre"] or "") for p in pendientes)
    hallazgos = memoria.listar_hallazgos(eid)
    assert any(h["severidad"] == "critica" for h in hallazgos)
