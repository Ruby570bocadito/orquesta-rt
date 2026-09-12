"""Ronda Z2-8 — el término buscado se REALZA sobre el fragmento mostrado.

Extensión natural de la ronda 7: el fragmento ya cae sobre la coincidencia
que BM25 puntuó (gemelo normalizado 1:1); ahora el backend entrega también
las POSICIONES exactas (coincidencias: [{inicio, fin}]) para que la vista
Memoria pinte el término con realce. Contrato fijado aquí:

  · Posiciones SEMIABIERTAS [inicio, fin) sobre el fragmento DEVUELTO —
    válidas con `fragmento.slice(inicio, fin)` en el frontend, suspensivos
    («…») incluidos en la cuenta pero JAMÁS dentro de un rango.
  · La normalización es la MISMA que la del índice (tolerancia a tildes):
    lo que BM25 puntuó es exactamente lo que se realza.
  · Sin coincidencia léxica en el fragmento (resultado solo-semántico,
    cabecera por ausencia de match) → lista VACÍA: la vista no inventa
    realces que el índice no sostiene.
  · Rangos ordenados, sin solapes (los solapados se funden: «adm» dentro
    de «administración» pinta una sola marca continua).
"""
from __future__ import annotations

from orchestrator.busqueda import (
    _fragmento,
    _fragmento_y_coincidencias,
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


def _en_rango(frag: str, c: dict) -> bool:
    return 0 <= c["inicio"] < c["fin"] <= len(frag)


def _trozo_normalizado(frag: str, c: dict) -> str:
    return _normalizar_1a1(frag[c["inicio"]:c["fin"]])


# ---------------------------------------------------------------------------
# 1) El realce entiende de tildes igual que el índice (herencia de la ronda 7)
# ---------------------------------------------------------------------------

def test_coincidencias_consulta_sin_tildes_sobre_contenido_con_tildes() -> None:
    contenido = _RELLENO_A + "La enumeración SMB reveló un usuario sin bloqueo." + _RELLENO_B
    frag, cs = _fragmento_y_coincidencias(contenido, "enumeracion")
    assert cs, "debe haber al menos un rango de realce"
    assert all(_en_rango(frag, c) for c in cs), "rangos dentro del fragmento"
    assert any(_trozo_normalizado(frag, c) == "enumeracion" for c in cs), \
        "el trozo realzado debe SER el término (con la tolerancia del índice)"
    assert frag.startswith("…"), "el caso sigue llevando suspensivo inicial"


def test_coincidencias_consulta_con_tildes_sobre_contenido_sin_tildes() -> None:
    contenido = _RELLENO_A + "El kerberoasting es viable contra la cuenta de servicio." + _RELLENO_B
    frag, cs = _fragmento_y_coincidencias(contenido, "kerberoásting viable")
    assert cs
    trozos = {_trozo_normalizado(frag, c) for c in cs}
    assert {"kerberoasting", "viable"} <= trozos, \
        "cada término de la consulta queda realzado donde aparece"


# ---------------------------------------------------------------------------
# 2) Contrato de posiciones: suspensivos, orden, solapes, límites
# ---------------------------------------------------------------------------

def test_coincidencias_posiciones_valen_con_suspensivo_inicial() -> None:
    """El «…» inicial DESPLAZA la ventana dentro del fragmento: los rangos
    deben venir ya desplazados (regresión de la primera implementación de
    la ronda 8, que devolvía posiciones de la ventana sin el +1)."""
    contenido = _RELLENO_A + "La enumeración SMB detectó backup_adm sin bloqueo." + _RELLENO_B
    frag, cs = _fragmento_y_coincidencias(contenido, "enumeracion")
    assert frag.startswith("…")
    assert cs and all(_en_rango(frag, c) for c in cs), \
        "con suspensivo inicial los rangos siguen apuntando al texto real"
    assert any(_trozo_normalizado(frag, c) == "enumeracion" for c in cs), \
        "el +1 del suspensivo está incluido: el trozo realzado es el término"


def test_coincidencias_ordenadas_y_sin_solapes_con_fusion() -> None:
    """«adm» dentro de «administración» se FUNDE en una sola marca; los
    rangos resultantes llegan ordenados y sin solapes al frontend."""
    contenido = "La administración del dominio admite admisión y respaldo." * 4
    assert len(contenido) > 180  # fuerza la ruta de ventana
    frag, cs = _fragmento_y_coincidencias(contenido, "adm administracion")
    assert len(cs) >= 2
    for a, b in zip(cs, cs[1:]):
        assert a["fin"] <= b["inicio"], "sin solapes tras la fusión"
    trozos = [_trozo_normalizado(frag, c) for c in cs]
    assert "administracion" in trozos, \
        "«adm» + «administracion» solapados deben fundirse en una marca continua"


def test_coincidencias_primera_coincidencia_nunca_cortada() -> None:
    """Un término más largo que el radio no queda partido por la ventana
    (antes el recorte podía partirlo a la mitad)."""
    largo = "supercalifragilisticoespialidosamente"
    contenido = "El término " + largo + " sigue aquí con más texto de relleno."
    frag, cs = _fragmento_y_coincidencias(contenido, largo, radio=10)
    assert cs, "el término largo debe salir realzado COMPLETO"
    assert any(_trozo_normalizado(frag, c) == largo for c in cs), \
        "el rango cubre el término entero, no un cacho"


# ---------------------------------------------------------------------------
# 3) Honestidad: sin match no hay realce; contenido corto muestra todo
# ---------------------------------------------------------------------------

def test_coincidencias_vacias_cuando_no_hay_match() -> None:
    contenido = "Relleno sin ninguna coincidencia utilizable. " * 10
    frag, cs = _fragmento_y_coincidencias(contenido, "zzzinexistente")
    assert cs == [], "sin match NO se inventan realces"
    assert frag.endswith("…"), "cabecera honesta del documento"


def test_coincidencias_contenido_corto_todo_visible() -> None:
    contenido = "Evidencia breve con kerberoasting confirmado en el dominio."
    frag, cs = _fragmento_y_coincidencias(contenido, "kerberoasting")
    assert frag == contenido, "contenido corto: el fragmento es el documento entero"
    assert len(cs) == 1 and _trozo_normalizado(frag, cs[0]) == "kerberoasting"


def test_fragmento_mantiene_firma_anterior() -> None:
    """Compatibilidad: _fragmento sigue devolviendo SOLO texto (el copiloto
    RAG y los tests de la ronda 7 lo consumen así)."""
    contenido = _RELLENO_A + "La enumeración SMB reveló el acceso." + _RELLENO_B
    solo = _fragmento(contenido, "enumeracion")
    tupla = _fragmento_y_coincidencias(contenido, "enumeracion")[0]
    assert isinstance(solo, str) and solo == tupla


# ---------------------------------------------------------------------------
# 4) E2E: la respuesta de buscar_caso trae el contrato completo de la vista
# ---------------------------------------------------------------------------

def test_buscar_caso_devuelve_coincidencias_para_la_vista(tmp_path) -> None:
    from datetime import datetime, timezone

    memoria = MemoriaCaso(tmp_path / "caso_z32.db")
    eid = "caso_z32"
    memoria.crear_engagement(Engagement(
        id=eid, nombre="Caso z32", cliente="ACME",
        roe=ROEPolitica(engagement_id=eid, cliente="ACME",
                        alcance_dominios=["acme.com"]),
        creado_en=datetime.now(timezone.utc),
        actualizado_en=datetime.now(timezone.utc)))
    memoria.guardar_evidencia(Evidencia(
        id="ev_z32", engagement_id=eid, tipo=TipoEvidencia.COMANDO,
        titulo="Salida de rpcclient",
        contenido=_RELLENO_A + "La enumeración SMB detectó backup_adm sin "
                               "bloqueo de cuenta." + _RELLENO_B,
        fase=Fase.F2_RECON, actor=Actor.AGENTE))
    r = buscar_caso(memoria, eid, "enumeracion backup_adm", limite=5)
    assert r["resultados"], "BM25 encuentra la evidencia (ya lo hacía)"

    primero = r["resultados"][0]
    frag = primero["fragmento"]
    cs = primero["coincidencias"]
    assert isinstance(cs, list) and cs, "el resultado trae rangos de realce"
    for c in cs:
        # Contrato de cable EXACTO: solo inicio/fin, semiabiertos, en rango.
        assert set(c.keys()) == {"inicio", "fin"}
        assert _en_rango(frag, c)
    trozos = {_trozo_normalizado(frag, c) for c in cs}
    assert "enumeracion" in trozos, \
        "el término acentuado del documento se realza desde una consulta sin tildes"
    assert {"backup", "adm"} <= trozos, \
        "backup_adm se realza por sus dos tokens (el guion bajo separa)"
    memoria.cerrar()
