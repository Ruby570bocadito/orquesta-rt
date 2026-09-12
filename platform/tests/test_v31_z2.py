"""Ronda Z2-7 — el fragmento de búsqueda localiza lo que BM25 puntuó.

Defecto corregido: `_fragmento` buscaba el término SIN normalizar sobre el
contenido crudo, pero el índice (tokenizar) quita tildes en AMBOS lados —
una consulta acentuada (o un contenido con tildes y consulta sin ellas)
no encontraba la posición y el recorte caía en la cabecera del documento
en vez de en la coincidencia que BM25 sí había encontrado y puntuado.
El operador veía un fragmento que no correspondía al resultado.
"""
from __future__ import annotations

from orchestrator.busqueda import (
    _fragmento,
    _normalizar_1a1,
    buscar_caso,
)
from orchestrator.memory import MemoriaCaso
from orchestrator.models import (
    Actor,
    Evidencia,
    Engagement,
    Fase,
    ROEPolitica,
    TipoEvidencia,
)

_RELLENO_A = "Relleno inicial para desplazar la coincidencia fuera de la cabecera. " * 8
_RELLENO_B = " Relleno final para que el recorte lleve suspensivos por la derecha." * 8


# ---------------------------------------------------------------------------
# 1) El fragmento entiende de tildes igual que el índice
# ---------------------------------------------------------------------------

def test_fragmento_localiza_consulta_sin_tildes_sobre_contenido_con_tildes() -> None:
    contenido = _RELLENO_A + "La enumeración SMB reveló un usuario sin bloqueo." + _RELLENO_B
    frag = _fragmento(contenido, "enumeracion")
    assert "enumeración SMB reveló" in frag, \
        "el fragmento debe caer sobre la coincidencia aunque las tildes " \
        "difieran entre consulta y contenido"
    assert frag.startswith("…") and frag.endswith("…")


def test_fragmento_localiza_consulta_con_tildes_sobre_contenido_sin_tildes() -> None:
    contenido = _RELLENO_A + "El kerberoasting es viable contra la cuenta de servicio." + _RELLENO_B
    frag = _fragmento(contenido, "kerberoasting viable")
    assert "kerberoasting es viable" in frag


def test_normalizacion_1a1_conserva_longitud_y_posiciones() -> None:
    """Invariante que sostiene la corrección: el gemelo normalizado mide lo
    mismo que el original (sustituciones 1:1 por carácter en español), así
    que sus posiciones valen para recortar el texto real."""
    original = "Explotación ÜLTIMA de la enumeración ñandú íntegra"
    gemelo = _normalizar_1a1(original)
    assert len(gemelo) == len(original)
    pos = gemelo.find("enumeracion")
    assert pos >= 0
    assert original[pos:pos + len("enumeracion")].lower() == "enumeración"


# ---------------------------------------------------------------------------
# 2) E2E: la vista de memoria muestra el fragmento alrededor del hallazgo
# ---------------------------------------------------------------------------

def test_buscar_caso_fragmento_apunta_a_la_coincidencia_acento(tmp_path) -> None:
    from datetime import datetime, timezone

    memoria = MemoriaCaso(tmp_path / "caso_z31.db")
    eid = "caso_z31"
    memoria.crear_engagement(Engagement(
        id=eid, nombre="Caso z31", cliente="ACME",
        roe=ROEPolitica(engagement_id=eid, cliente="ACME",
                        alcance_dominios=["acme.com"]),
        creado_en=datetime.now(timezone.utc),
        actualizado_en=datetime.now(timezone.utc)))
    memoria.guardar_evidencia(Evidencia(
        id="ev_z31", engagement_id=eid, tipo=TipoEvidencia.COMANDO,
        titulo="Salida de rpcclient",
        contenido=_RELLENO_A + "La enumeración SMB detectó backup_adm sin "
                               "bloqueo de cuenta." + _RELLENO_B,
        fase=Fase.F2_RECON, actor=Actor.AGENTE))
    r = buscar_caso(memoria, eid, "enumeracion backup_adm", limite=5)
    assert r["resultados"], "BM25 debe encontrar la evidencia (ya lo hacía)"
    frag = r["resultados"][0]["fragmento"]
    assert "enumeración SMB detectó" in frag, \
        "el fragmento mostrado al operador debe centrarse en la " \
        "coincidencia, no en la cabecera del documento"
    memoria.cerrar()
