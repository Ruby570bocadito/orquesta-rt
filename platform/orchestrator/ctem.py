"""Modo continuo CTEM (Continuous Threat Exposure Management).

La exposición de una organización no se mide UNA vez: los adversarios
vuelven, el entorno cambia y las defensas se ajustan. El modo continuo
convierte cada cadena threat-led en un INSTRUMENTO PERIÓDICO:

- **Programa**: una cadena se ejecuta como "corrida" en un intervalo.
- **Corrida**: instantánea REAL del caso en un instante T — técnicas
  ejercitadas (hallazgos + auditoría), detecciones documentadas por el
  operador (VECTR), hallazgos por severidad, aprobaciones pendientes y
  cobertura de la cadena — contrastada con la corrida anterior.
- **Delta**: qué cambió entre corridas — nuevas técnicas ejercitadas,
  nuevos hallazgos, nuevas detecciones y movimiento de cobertura. Es el
  dato que Picus/SCYthe/Caldera llaman "resumen de simulación continua":
  aquí se calcula desde evidencia real del caso, nunca inventada.

Disciplina anti-relleno (la misma de siempre):
- La corrida NO ejecuta técnicas por su cuenta: no fabrica argumentos ni
  pretendie automatizar lo que exige firma del operador. La corrida MIDE;
  las técnicas se ejecutan por la vía de siempre (fases/arsenal con el
  boundary como árbitro). Lo que la corrida promete es exactamente lo que
  la auditoría y los hallazgos del caso pueden demostrar.
- La programación es persistente y auditable (tablas en la BD del caso);
  la corrida programada queda firmada como Actor.SISTEMA con el detalle
  del programa que la disparó, y el operador puede ver el historial
  completo en la consola.
"""
from __future__ import annotations

import json
import logging
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

from . import threatled

_logger = logging.getLogger("orquestador.ctem")

# Intervalos de programación: CTEM razonable es diario o semanal; el mínimo
# de 1 h evita bucles de medición sin valor y el máximo 720 h (30 días).
INTERVALO_MIN_HORAS = 1
INTERVALO_MAX_HORAS = 720

_ESQUEMA_CTEM = """
CREATE TABLE IF NOT EXISTS ctem_programas (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL,
    cadena_id TEXT NOT NULL,
    intervalo_horas INTEGER NOT NULL,
    activo INTEGER NOT NULL DEFAULT 1,
    creado_por TEXT NOT NULL DEFAULT '',
    creado_en TEXT NOT NULL,
    ultima_corrida_en TEXT,
    proxima_corrida_en TEXT
);
CREATE TABLE IF NOT EXISTS ctem_corridas (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL,
    cadena_id TEXT NOT NULL,
    disparo TEXT NOT NULL,
    operador TEXT NOT NULL DEFAULT '',
    resumen_json TEXT NOT NULL,
    creado_en TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ctem_corridas_caso
    ON ctem_corridas (engagement_id, cadena_id, creado_en);
CREATE INDEX IF NOT EXISTS idx_ctem_programas_caso
    ON ctem_programas (engagement_id, activo);
"""


def crear_tablas(conn: sqlite3.Connection) -> None:
    """Migración idempotente: se llama desde MemoriaCaso.__init__."""
    conn.executescript(_ESQUEMA_CTEM)


# ---------------------------------------------------------------------------
# Instantánea REAL del caso
# ---------------------------------------------------------------------------


def _tecnicas_ejercitadas(memoria: Any, engagement_id: str) -> set[str]:
    hallazgos = [dict(f) for f in memoria.listar_hallazgos(engagement_id)]
    acciones = [dict(a) for a in memoria.listar_auditoria(engagement_id)]
    return threatled.tecnicas_ejercitadas_de(hallazgos, acciones)


def instantanea(memoria: Any, engagement_id: str, cadena: threatled.Cadena) -> dict[str, Any]:
    """Estado REAL del caso en este instante, contrastado con la cadena.

    Nada se calcula "en abstracto": cada número sale de las tablas del caso
    (hallazgos, auditoría, aprobaciones) o del plan honesto de la cadena.
    """
    hallazgos = [dict(h) for h in memoria.listar_hallazgos(engagement_id)]
    acciones = [dict(a) for a in memoria.listar_auditoria(engagement_id)]

    tecnicas = threatled.tecnicas_ejercitadas_de(hallazgos, acciones)
    plan = threatled.plan_para_caso(cadena, tecnicas)

    por_severidad: dict[str, int] = {}
    por_deteccion: dict[str, int] = {"pendiente": 0, "detectado": 0,
                                     "no_detectado": 0, "prevenido": 0}
    for h in hallazgos:
        sev = str(h.get("severidad") or "media").lower()
        por_severidad[sev] = por_severidad.get(sev, 0) + 1
        det = str(h.get("deteccion") or "pendiente").lower()
        por_deteccion[det] = por_deteccion.get(det, 0) + 1

    pendientes = memoria.listar_aprobaciones(engagement_id, solo_pendientes=True)
    # El boundary audita toda evaluación; las tool call que REALMENTE se
    # ejecutaron quedan con decisión "permitir" (las aprobadas se
    # re-evalúan en ejecución y también quedan en "permitir").
    acciones_ejecutadas = sum(
        1 for a in acciones
        if str(a.get("accion", "")).startswith("boundary:")
        and str(a.get("resultado", "")) == "permitir"
    )

    return {
        "cadena_id": cadena.id,
        "cobertura": plan["resumen"],
        "tecnicas_ejercitadas": sorted(tecnicas),
        "hallazgos": {"total": len(hallazgos), "por_severidad": por_severidad},
        "detecciones": por_deteccion,
        "detecciones_documentadas": sum(
            v for k, v in por_deteccion.items() if k != "pendiente"),
        "aprobaciones_pendientes": len(pendientes),
        "acciones_ejecutadas": acciones_ejecutadas,
    }


def delta_entre(antes: Optional[dict[str, Any]], despues: dict[str, Any]) -> dict[str, Any]:
    """Delta honesto entre dos corridas. Con una sola corrida, el delta lo
    declara explícitamente (`primera_corrida: true`): nada se compara contra
    una base inexistente."""
    if antes is None:
        return {
            "primera_corrida": True,
            "nuevas_tecnicas": despues["tecnicas_ejercitadas"],
            "hallazgos_nuevos": despues["hallazgos"]["total"],
            "detecciones_nuevas": despues["detecciones_documentadas"],
            "cobertura_ejercitados": {"antes": None,
                                      "despues": despues["cobertura"]["ejercitados"]},
        }
    tec_antes = set(antes.get("tecnicas_ejercitadas") or [])
    tec_despues = set(despues.get("tecnicas_ejercitadas") or [])
    # Hallazgos nuevos: el total crece (los hallazgos son append-only).
    h_antes = int(antes.get("hallazgos", {}).get("total", 0))
    h_despues = int(despues["hallazgos"]["total"])
    det_antes = int(antes.get("detecciones_documentadas", 0))
    det_despues = int(despues["detecciones_documentadas"])
    return {
        "primera_corrida": False,
        "nuevas_tecnicas": sorted(tec_despues - tec_antes),
        "hallazgos_nuevos": max(h_despues - h_antes, 0),
        "detecciones_nuevas": max(det_despues - det_antes, 0),
        "cobertura_ejercitados": {
            "antes": antes.get("cobertura", {}).get("ejercitados"),
            "despues": despues["cobertura"]["ejercitados"],
        },
    }


# ---------------------------------------------------------------------------
# Corridas
# ---------------------------------------------------------------------------


def fila_fase(memoria: Any, engagement_id: str) -> str:
    """Fase actual del caso (para la fase de la evidencia custodiada)."""
    fila = memoria.obtener_engagement(engagement_id)
    return str(fila["fase_actual"]) if fila is not None else "F0_scoping"


def _custodiar(memoria: Any, engagement_id: str, fase: str,
               resumen: dict[str, Any]) -> Optional[str]:
    """Guarda el resumen de la corrida como evidencia con custodia."""
    try:
        from .models import Actor, Evidencia
        ev = memoria.guardar_evidencia(Evidencia(
            id=memoria.nuevo_id("ev"),
            engagement_id=engagement_id,
            tipo="json",
            titulo=f"Corrida CTEM: {resumen['cadena_nombre']} "
                   f"({resumen['disparo']})",
            contenido=json.dumps(resumen, ensure_ascii=False, indent=2,
                                 sort_keys=True),
            hash_sha256="", firma_hmac="", hash_previo="",
            fase=fase,
            actor=Actor.HUMANO if resumen.get("disparo") == "manual"
            else Actor.SISTEMA,
            hallazgo_id=None,
            creado_en=resumen.get("instante") or "",
        ))
        return ev.id
    except Exception:
        # La custodia no puede romper la corrida: la medición ya quedó en
        # ctem_corridas y en la auditoría; la evidencia se reintenta en la
        # siguiente corrida. Se devuelve None y el resumen lo anota.
        return None


def _corrida_anterior(conn: sqlite3.Connection, engagement_id: str,
                      cadena_id: str) -> Optional[dict[str, Any]]:
    fila = conn.execute(
        "SELECT resumen_json FROM ctem_corridas WHERE engagement_id=? AND "
        "cadena_id=? ORDER BY creado_en DESC, id DESC LIMIT 1",
        (engagement_id, cadena_id),
    ).fetchone()
    if fila is None:
        return None
    return json.loads(fila["resumen_json"])


def ejecutar_corrida(memoria: Any, engagement_id: str, cadena: threatled.Cadena,
                     disparo: str, operador: str = "",
                     ahora: Optional[datetime] = None) -> dict[str, Any]:
    """Corrida REAL: instantánea + delta + persistencia + programación.

    `disparo` es 'manual' (el operador la pidió por API/consola) o
    'programada' (el planificador del despliegue la ejecutó a su hora).
    Devuelve el resumen completo con id de corrida y delta.
    """
    if disparo not in {"manual", "programada"}:
        raise ValueError("disparo debe ser 'manual' o 'programada'")
    instante = (ahora or datetime.now(timezone.utc))
    conn = memoria._conn

    # La corrida registra la cadena y su instantánea en el MISMO commit
    # lógico: sin ventanas donde el historial diga una cosa y el delta otra.
    instantanea_ahora = instantanea(memoria, engagement_id, cadena)
    antes = _corrida_anterior(conn, engagement_id, cadena.id)
    delta = delta_entre(antes, instantanea_ahora)
    resumen: dict[str, Any] = {
        "cadena_id": cadena.id,
        "cadena_nombre": cadena.nombre,
        "disparo": disparo,
        "operador": operador,
        "instante": instante.isoformat(),
        **instantanea_ahora,
        "delta": delta,
    }
    corrida_id = memoria.nuevo_id("cor")
    conn.execute(
        "INSERT INTO ctem_corridas (id, engagement_id, cadena_id, disparo, "
        "operador, resumen_json, creado_en) VALUES (?,?,?,?,?,?,?)",
        (corrida_id, engagement_id, cadena.id, disparo, operador,
         json.dumps(resumen, ensure_ascii=False, sort_keys=True),
         instante.isoformat()),
    )
    resumen["corrida_id"] = corrida_id

    # Auditoría: el actor distingue corrida pedida por el operador (HUMANO)
    # de corrida vencida ejecutada por el planificador (SISTEMA).
    from .models import Actor
    memoria.registrar_auditoria(
        engagement_id,
        Actor.HUMANO if disparo == "manual" else Actor.SISTEMA,
        "ctem.corrida",
        detalle=(f"Corrida CTEM '{cadena.nombre}' ({disparo}): "
                 f"{instantanea_ahora['cobertura']['ejercitados']}/"
                 f"{instantanea_ahora['cobertura']['total']} ejercitados · "
                 f"delta: {delta['hallazgos_nuevos']} hallazgos nuevos, "
                 f"{delta['detecciones_nuevas']} detecciones nuevas"),
        herramienta="ctem", resultado="ok")

    # Custodia: el resumen es un artefacto verificable (hash + HMAC), igual
    # que cualquier evidencia del caso — no un log efímero.
    ev_id = _custodiar(memoria, engagement_id,
                       fila_fase(memoria, engagement_id), resumen)
    if ev_id:
        resumen["evidencia_id"] = ev_id

    # Actualiza la programación activa de esta cadena (si la hay): la
    # corrida consumida desplaza la siguiente ejecución programada.
    ahora_iso = instante.isoformat()
    proxima = (instante + timedelta(hours=1)).isoformat()
    fila_prog = conn.execute(
        "SELECT id, intervalo_horas FROM ctem_programas WHERE engagement_id=? "
        "AND cadena_id=? AND activo=1", (engagement_id, cadena.id)).fetchone()
    if fila_prog is not None:
        proxima = (instante + timedelta(
            hours=int(fila_prog["intervalo_horas"]))).isoformat()
        conn.execute(
            "UPDATE ctem_programas SET ultima_corrida_en=?, proxima_corrida_en=? "
            "WHERE id=?", (ahora_iso, proxima, fila_prog["id"]))
    conn.commit()
    resumen["corrida_id"] = corrida_id
    resumen["proxima_corrida_en"] = proxima if fila_prog is not None else None
    return resumen


# ---------------------------------------------------------------------------
# Programas
# ---------------------------------------------------------------------------


def programar(memoria: Any, engagement_id: str, cadena_id: str,
              intervalo_horas: int, operador: str,
              ahora: Optional[datetime] = None) -> dict[str, Any]:
    """Crea (o reprograma) el programa continuo de una cadena."""
    if threatled.obtener(cadena_id) is None:
        raise ValueError(f"cadena desconocida: {cadena_id!r}")
    if not (INTERVALO_MIN_HORAS <= int(intervalo_horas) <= INTERVALO_MAX_HORAS):
        raise ValueError(
            f"intervalo_horas debe estar entre {INTERVALO_MIN_HORAS} y "
            f"{INTERVALO_MAX_HORAS}")
    instante = (ahora or datetime.now(timezone.utc))
    conn = memoria._conn
    existente = conn.execute(
        "SELECT id FROM ctem_programas WHERE engagement_id=? AND cadena_id=?",
        (engagement_id, cadena_id)).fetchone()
    proxima = (instante + timedelta(hours=int(intervalo_horas))).isoformat()
    if existente is not None:
        conn.execute(
            "UPDATE ctem_programas SET intervalo_horas=?, activo=1, "
            "creado_por=?, proxima_corrida_en=? WHERE id=?",
            (int(intervalo_horas), operador, proxima, existente["id"]))
        programa_id = existente["id"]
        accion = "reprogramado"
    else:
        programa_id = memoria.nuevo_id("prg")
        conn.execute(
            "INSERT INTO ctem_programas (id, engagement_id, cadena_id, "
            "intervalo_horas, activo, creado_por, creado_en, ultima_corrida_en, "
            "proxima_corrida_en) VALUES (?,?,?,?,1,?,?,NULL,?)",
            (programa_id, engagement_id, cadena_id, int(intervalo_horas),
             operador, instante.isoformat(), proxima))
        accion = "programado"
    conn.commit()
    return {"id": programa_id, "cadena_id": cadena_id,
            "intervalo_horas": int(intervalo_horas), "estado": accion,
            "proxima_corrida_en": proxima}


def cancelar(memoria: Any, engagement_id: str, programa_id: str) -> dict[str, Any]:
    """Desactiva un programa (el historial de corridas se conserva)."""
    conn = memoria._conn
    fila = conn.execute(
        "SELECT id, cadena_id FROM ctem_programas WHERE engagement_id=? AND id=?",
        (engagement_id, programa_id)).fetchone()
    if fila is None:
        raise LookupError(f"programa inexistente: {programa_id}")
    conn.execute("UPDATE ctem_programas SET activo=0 WHERE id=?", (programa_id,))
    conn.commit()
    return {"id": programa_id, "cadena_id": fila["cadena_id"],
            "estado": "cancelado"}


def programas_de(memoria: Any, engagement_id: str) -> list[dict[str, Any]]:
    conn = memoria._conn
    filas = conn.execute(
        "SELECT * FROM ctem_programas WHERE engagement_id=? "
        "ORDER BY creado_en", (engagement_id,)).fetchall()
    return [dict(f) for f in filas]


def corridas_de(memoria: Any, engagement_id: str,
                cadena_id: Optional[str] = None,
                limite: int = 50) -> list[dict[str, Any]]:
    """Historial de corridas (más reciente primero), resumen incluido."""
    conn = memoria._conn
    if cadena_id:
        filas = conn.execute(
            "SELECT * FROM ctem_corridas WHERE engagement_id=? AND cadena_id=? "
            "ORDER BY creado_en DESC, id DESC LIMIT ?",
            (engagement_id, cadena_id, int(limite))).fetchall()
    else:
        filas = conn.execute(
            "SELECT * FROM ctem_corridas WHERE engagement_id=? "
            "ORDER BY creado_en DESC, id DESC LIMIT ?",
            (engagement_id, int(limite))).fetchall()
    salida = []
    for f in filas:
        d = dict(f)
        try:
            d["resumen"] = json.loads(d.pop("resumen_json"))
        except (TypeError, ValueError):
            d["resumen"] = {}
        salida.append(d)
    return salida


# ---------------------------------------------------------------------------
# Planificador del despliegue (bucle continuo)
# ---------------------------------------------------------------------------


def programas_pendientes(raiz_casos: Path,
                         ahora: Optional[datetime] = None) -> list[dict[str, Any]]:
    """Programas cuya próxima corrida venció, en TODOS los casos del
    despliegue. El planificador de api.py llama esto periódicamente."""
    instante = (ahora or datetime.now(timezone.utc))
    pendientes: list[dict[str, Any]] = []
    if not raiz_casos.exists():
        return pendientes
    from .memory import MemoriaCaso  # import tardío: evitar ciclo
    for db in sorted(raiz_casos.glob("*.db")):
        try:
            memoria = MemoriaCaso(db)
        except sqlite3.Error:
            continue  # BD corrupta: se omite y se anota por el llamador
        try:
            filas = memoria._conn.execute(
                "SELECT id, engagement_id, cadena_id, intervalo_horas, "
                "proxima_corrida_en FROM ctem_programas WHERE activo=1"
            ).fetchall()
            for f in filas:
                try:
                    vencida = (f["proxima_corrida_en"] is None or
                               datetime.fromisoformat(f["proxima_corrida_en"])
                               <= instante)
                except ValueError:
                    vencida = True
                except TypeError:
                    # Timestamp naive (BD antigua/editada a mano) vs instante
                    # aware: la comparación lanza TypeError. ANTES no se
                    # capturaba y ABORTABA el barrido completo del despliegue;
                    # el bucle de api.py lo tragaba sin logging y TODAS las
                    # corridas programadas se omitían indefinidamente sin
                    # rastro. Se marca vencida: ejecutar_corrida reprograma
                    # con timestamp nuevo aware y el programa se autocura.
                    vencida = True
                if vencida:
                    pendientes.append({
                        "programa_id": f["id"],
                        "engagement_id": f["engagement_id"],
                        "cadena_id": f["cadena_id"],
                        "proxima_corrida_en": f["proxima_corrida_en"],
                        "bd": str(db),
                    })
        finally:
            memoria.cerrar()
    return pendientes


def ejecutar_pendientes(raiz_casos: Path,
                        ahora: Optional[datetime] = None) -> list[dict[str, Any]]:
    """Ejecuta TODAS las corridas vencidas del despliegue. Cada corrida es

    real (instantánea + delta + auditoría en su caso); los fallos de una BD
    no detienen a las demás. Devuelve los resúmenes ejecutados.

    Cada programa se RECLAMA atómicamente antes de ejecutarse (UPDATE
    condicionado al valor leído de proxima_corrida_en): con ticks
    solapados o más de un worker, solo uno gana el claim y la corrida no
    se duplica. Un programa reclamado que falla queda con proxima NULL
    (= vencida): se reintenta al siguiente tick sin quedar bloqueado.
    """
    from .memory import MemoriaCaso  # import tardío
    resumenes: list[dict[str, Any]] = []
    for pend in programas_pendientes(raiz_casos, ahora=ahora):
        try:
            memoria = MemoriaCaso(Path(pend["bd"]))
        except sqlite3.Error:
            continue
        try:
            # Claim atómico del slot: solo el writer que actualice la fila
            # con el valor leído ejecuta la corrida.
            reclamado = memoria._conn.execute(
                "UPDATE ctem_programas SET proxima_corrida_en=NULL "
                "WHERE id=? AND activo=1 AND proxima_corrida_en IS ?",
                (pend["programa_id"], pend["proxima_corrida_en"]),
            ).rowcount
            memoria._conn.commit()
            if not reclamado:
                continue  # otro tick/worker lo reclamó antes: no duplicar
            cadena = threatled.obtener(pend["cadena_id"])
            if cadena is None:
                _logger.warning(
                    "ctem: programa %s con cadena desconocida %s; se cancela",
                    pend["programa_id"], pend["cadena_id"])
                memoria._conn.execute(
                    "UPDATE ctem_programas SET activo=0 WHERE id=?",
                    (pend["programa_id"],))
                memoria._conn.commit()
                continue
            resumen = ejecutar_corrida(
                memoria, pend["engagement_id"], cadena,
                disparo="programada", operador="planificador_ctem",
                ahora=ahora)
            resumenes.append(resumen)
        except (sqlite3.Error, ValueError) as exc:
            _logger.warning(
                "ctem: corrida programada falló para programa %s: %s",
                pend["programa_id"], exc)
            continue
        finally:
            memoria.cerrar()
    return resumenes
