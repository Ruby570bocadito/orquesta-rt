"""Tests v18: dedup de hallazgos al reanudar fase + guardia de resolución
DNS en la postura de correo (anti falso positivo en dominios sin resolver).

Ambos hallazgos salieron del test de operador E2E en vivo: al reanudar F1
tras aprobar la búsqueda de filtraciones, la fase se re-ejecutaba y
duplicaba el hallazgo de postura de correo sobre un dominio que ni
siquiera resolvía.
"""
from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from orchestrator.memory import MemoriaCaso
from orchestrator.models import Actor, Hallazgo, Severidad
from orchestrator import transportes


def _hallazgo(titulo: str, activo: str, id_h: str = "hal_1",
              engagement: str = "caso_test") -> Hallazgo:
    return Hallazgo(
        id=id_h, engagement_id=engagement, titulo=titulo,
        severidad=Severidad.MEDIA, activo=activo,
        descripcion="descripción de prueba", recomendacion="recomendación de prueba",
        creado_por=Actor.AGENTE)


# ---------------------------------------------------------------- dedup

def test_reguardar_mismo_id_no_duplica():
    """La re-guardada con el MISMO id (contrato v15) sigue funcionando."""
    with tempfile.TemporaryDirectory() as tmp:
        mem = MemoriaCaso(Path(tmp) / "caso_test.db")
        h = _hallazgo("Postura de correo mejorable en X", "X")
        mem.guardar_hallazgo(h)
        mem.guardar_hallazgo(h)  # mismo id → REPLACE, una sola fila
        assert mem.listar_hallazgos("caso_test").__len__() == 1


def test_reanudacion_fase_con_nuevo_id_dedupe():
    """Al reanudar una fase se genera un Hallazgo NUEVO (otro id) con el
    mismo título y activo: debe conservarse el original y NO duplicarse."""
    with tempfile.TemporaryDirectory() as tmp:
        mem = MemoriaCaso(Path(tmp) / "caso_test.db")
        original = _hallazgo("Postura de correo mejorable en X", "X", id_h="hal_orig")
        mem.guardar_hallazgo(original)
        # firma humana registra detección sobre el original...
        mem.marcar_deteccion("caso_test", "hal_orig", "detectado")
        # ...luego la fase se reanuda y la herramienta re-observa lo mismo
        copia = _hallazgo("Postura de correo mejorable en X", "X",
                          id_h="hal_copia_reanudada")
        mem.guardar_hallazgo(copia)
        filas = [dict(h) for h in mem.listar_hallazgos("caso_test")]
        assert len(filas) == 1, f"duplicado: {len(filas)} filas"
        assert filas[0]["id"] == "hal_orig", "debe conservarse el original"
        assert filas[0]["deteccion"] == "detectado", "la detección no se pierde"


def test_mismo_titulo_en_activo_distinto_no_dedupe():
    """'Postura de correo mejorable en X' y '... en Y' son hallazgos
    distintos: ambos sobreviven (el dedup exige mismo activo)."""
    with tempfile.TemporaryDirectory() as tmp:
        mem = MemoriaCaso(Path(tmp) / "caso_test.db")
        mem.guardar_hallazgo(_hallazgo("Postura de correo mejorable en X", "X", id_h="h1"))
        mem.guardar_hallazgo(_hallazgo("Postura de correo mejorable en Y", "Y", id_h="h2"))
        assert len(mem.listar_hallazgos("caso_test")) == 2


def test_dedupe_insensible_a_mayusculas():
    """El mismo hecho con distinta capitalización del título no duplica."""
    with tempfile.TemporaryDirectory() as tmp:
        mem = MemoriaCaso(Path(tmp) / "caso_test.db")
        mem.guardar_hallazgo(_hallazgo("Postura de correo mejorable", "X", id_h="h1"))
        mem.guardar_hallazgo(_hallazgo("postura de correo mejorable", "X", id_h="h2"))
        assert len(mem.listar_hallazgos("caso_test")) == 1


# ------------------------------------------------- postura de correo

class _SinResolucion:
    """Resolver.resolve que falla siempre (dominio inexistente)."""

    def __call__(self, nombre, tipo, *a, **k):
        raise Exception("NXDOMAIN")


def _roe():
    from orchestrator.models import ROEPolitica
    return ROEPolitica(
        engagement_id="caso_test", cliente="ACME",
        alcance_dominios=["lab-interno.test"])


def test_correo_dominio_sin_resolucion_no_fabrica_debilidades():
    """Un dominio que no resuelve no puede tener 'postura mejorable':
    se reporta sin_resolucion y debilidades vacías (fase F1 no crea hallazgo)."""
    roe = _roe()
    with patch("dns.resolver.resolve", side_effect=Exception("NXDOMAIN")):
        r = transportes.recon_correos_seguridad("lab-interno.test", roe)
    assert r.get("sin_resolucion") is True
    assert r.get("debilidades") == []
    assert "nota" in r


def test_correo_dominio_resoluble_con_debilidades_reales():
    """Un dominio que SÍ resuelve y sin SPF/DMARC sigue reportando
    debilidades reales (la guardia no oculta hallazgos legítimos)."""
    roe = _roe()
    registros = {
        ("lab-interno.test", "A"): ["93.184.216.34"],
        ("lab-interno.test", "TXT"): [],
        ("_dmarc.lab-interno.test", "TXT"): [],
    }

    def _resolver(nombre, tipo, *a, **k):
        class _R:
            strings = [bytes(v, "utf-8") for v in registros.get((nombre, tipo), [])]
        if (nombre, tipo) not in registros:
            raise Exception("NXDOMAIN")
        return [_R()]

    with patch("dns.resolver.resolve", side_effect=_resolver):
        r = transportes.recon_correos_seguridad("lab-interno.test", roe)
    assert r.get("sin_resolucion") is None
    assert any("sin SPF" in d for d in r.get("debilidades", []))


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-q"]))


# ---------------------------------------------- política de auto-baja v18

def test_auto_baja_unica_cuenta_reabre_bootstrap(tmp_path, monkeypatch):
    """Un operador único puede darse de baja por API: cierre limpio de
    cuentas temporales y reapertura del bootstrap (entrega del despliegue)."""
    from orchestrator import auth
    ruta = tmp_path / "usuarios.db"
    monkeypatch.setattr(auth, "RUTA_DB", ruta)
    monkeypatch.setattr(auth, "_intentos", {})
    auth.crear_operador("solo_op", "Clave-Test-2026!", rol="admin")
    auth.eliminar_operador("solo_op", "solo_op")  # auto-baja: permitida
    assert not auth.hay_operadores()


def test_auto_baja_con_mas_operadores_bloqueada(tmp_path, monkeypatch):
    """Con testigos administrativos, nadie se borra a sí mismo: la salida
    la firma otro admin (la auditoría queda con autoridad coherente)."""
    from orchestrator import auth
    ruta = tmp_path / "usuarios.db"
    monkeypatch.setattr(auth, "RUTA_DB", ruta)
    monkeypatch.setattr(auth, "_intentos", {})
    auth.crear_operador("admin_a", "Clave-Test-2026!", rol="admin")
    auth.crear_operador("admin_b", "Clave-Test-2026!", rol="admin")
    with pytest.raises(ValueError, match="no puede eliminar su propia cuenta"):
        auth.eliminar_operador("admin_a", "admin_a")
    # otro admin sí puede darlo de baja (contrato histórico)
    auth.eliminar_operador("admin_a", "admin_b")
    assert auth.hay_operadores()
