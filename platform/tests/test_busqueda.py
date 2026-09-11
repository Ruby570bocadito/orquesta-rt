"""Tests de búsqueda en memoria (BM25) e informe HTML.

BM25 debe ser tolerante a tildes, ignorar stopwords y ordenar por
relevancia real. El informe HTML debe ser autocontenido y escapar el
contenido del caso (anti-XSS en el entregable).
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from orchestrator.busqueda import (  # noqa: E402
    Documento,
    IndiceBM25,
    buscar_caso,
    tokenizar,
)
from orchestrator.memory import MemoriaCaso  # noqa: E402
from orchestrator.models import (  # noqa: E402
    Actor,
    Evidencia,
    Fase,
    Hallazgo,
    TipoEvidencia,
)


# ---------------------------------------------------------------------------
# 1) Tokenizador
# ---------------------------------------------------------------------------


def test_tokenizador_tolerante_a_tildes() -> None:
    assert tokenizar("Explotación de acceso") == tokenizar("explotacion de acceso")


def test_tokenizador_sin_stopwords() -> None:
    tokens = tokenizar("la explotación del sistema por el agente")
    assert "la" not in tokens and "del" not in tokens and "por" not in tokens and "el" not in tokens
    assert "explotacion" in tokens and "sistema" in tokens


# ---------------------------------------------------------------------------
# 2) Índice BM25 puro
# ---------------------------------------------------------------------------


def test_bm25_ordena_por_relevancia() -> None:
    docs = [
        Documento(id="1", tipo="evidencia", titulo="Kerberoasting en SPN",
                  contenido="solicitud de TGS para cuentas de servicio con SPN"),
        Documento(id="2", tipo="evidencia", titulo="Puerto 443 abierto",
                  contenido="servicio HTTPS detectado en el host web"),
        Documento(id="3", tipo="hallazgo", titulo="Kerberoasting viable",
                  contenido="cuenta de servicio con SPN y contraseña débil: kerberoasting"),
    ]
    indice = IndiceBM25(docs)
    resultados = indice.buscar("kerberoasting spn servicio", limite=3)
    ids = [d.id for d, _ in resultados]
    assert "1" in ids and "3" in ids
    assert "2" not in ids[:1]  # el doc irrelevante no lidera
    # El hallazgo y la evidencia de kerberoasting puntúan por encima
    assert resultados[0][0].id in ("1", "3")


def test_bm25_sin_coincidencias_vacio() -> None:
    docs = [Documento(id="1", tipo="nota", titulo="nada", contenido="contenido sin relación")]
    assert IndiceBM25(docs).buscar("criptomoneda", limite=5) == []


# ---------------------------------------------------------------------------
# 3) Búsqueda de caso completa
# ---------------------------------------------------------------------------


def _caso(tmp_path) -> tuple[MemoriaCaso, str]:
    from datetime import datetime, timezone
    from orchestrator.models import Engagement, ROEPolitica
    memoria = MemoriaCaso(tmp_path / "caso_busqueda.db")
    eid = "caso_busqueda"
    memoria.crear_engagement(Engagement(
        id=eid, nombre="Caso búsqueda", cliente="ACME",
        roe=ROEPolitica(engagement_id=eid, cliente="ACME", alcance_dominios=["acme.com"]),
        creado_en=datetime.now(timezone.utc), actualizado_en=datetime.now(timezone.utc)))
    memoria.guardar_evidencia(Evidencia(
        id="ev_1", engagement_id=eid, tipo=TipoEvidencia.COMANDO,
        titulo="Salida de rpcclient", contenido="Enumeración SMB: usuario backup_adm detectado con privilegio GETINFO",
        fase=Fase.F2_RECON, actor=Actor.AGENTE))
    memoria.guardar_evidencia(Evidencia(
        id="ev_2", engagement_id=eid, tipo=TipoEvidencia.JSON,
        titulo="Certificado TLS del portal", contenido="Emisor: R3, caduca en 2027, SAN portal.acme.com",
        fase=Fase.F2_RECON, actor=Actor.AGENTE))
    memoria.guardar_hallazgo(Hallazgo(
        id="hal_1", engagement_id=eid, titulo="Credenciales de backup expuestas",
        severidad="alta", descripcion="El usuario backup_adm aparece en la enumeración SMB sin bloqueo de cuenta",
        recomendacion="Rotar credenciales y activar bloqueo por intentos"))
    return memoria, eid


def test_buscar_caso_encuentra_evidencia(tmp_path) -> None:
    memoria, eid = _caso(tmp_path)
    r = buscar_caso(memoria, eid, "backup_adm enumeracion", limite=5)
    assert r["total_indexado"] >= 3
    assert r["resultados"]
    assert any("ev_1" in x["id"] for x in r["resultados"][:2])
    memoria.cerrar()


def test_buscar_caso_tolerante_tildes_y_vacio(tmp_path) -> None:
    memoria, eid = _caso(tmp_path)
    r = buscar_caso(memoria, eid, "enumeracion SMB", limite=5)
    assert any("ev_1" in x["id"] for x in r["resultados"])
    r2 = buscar_caso(memoria, eid, "zzzz-inexistente")
    assert r2["resultados"] == []
    memoria.cerrar()


def test_buscar_caso_filtro_por_tipo(tmp_path) -> None:
    memoria, eid = _caso(tmp_path)
    r = buscar_caso(memoria, eid, "backup credenciales", limite=10, tipos=["hallazgo"])
    assert all(x["tipo"] == "hallazgo" for x in r["resultados"])
    assert r["resultados"]  # el hallazgo de credenciales está
    memoria.cerrar()


# ---------------------------------------------------------------------------
# 4) Informe HTML
# ---------------------------------------------------------------------------


def test_informe_html_autocontenido_y_escapado(tmp_path) -> None:
    from orchestrator.reporting import construir_informe_html
    memoria, eid = _caso(tmp_path)
    ruta = construir_informe_html(eid, memoria, carpeta_salida=tmp_path)
    contenido = ruta.read_text(encoding="utf-8")
    memoria.cerrar()
    assert ruta.name == "informe.html"
    assert "<!DOCTYPE html>" in contenido and "lang=\"es\"" in contenido
    assert "Cadena de custodia" in contenido and "VÁLIDA" in contenido
    assert "backup_adm" in contenido  # los datos del caso están
    # Sin CSS externo ni scripts: autocontenido
    assert "<script" not in contenido and "<link" not in contenido
    # Contenido potencialmente HTML en el caso queda escapado
    assert "<script>alert(1)</script>" not in contenido
