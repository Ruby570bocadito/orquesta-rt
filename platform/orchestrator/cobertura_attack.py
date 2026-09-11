"""Analítica de cobertura MITRE ATT&CK entre campañas (v16).

El Navigator (v14) exporta la capa de UN caso. La gestión de un PROGRAMA de
red team (VECTR, reportes de programa) va un paso más allá: compara la
cobertura de técnicas ENTRE campañas para responder tres preguntas que un
informe individual no contesta:

  1. ¿Qué técnicas ya se han ejercitado y en qué campaña? (matriz
     técnica × campaña, el heatmap estándar de los gestores de cobertura)
  2. ¿Qué debilidades se REPITEN entre campañas? (técnicas recurrentes:
     el mismo hueco que el rojo vuelve a explotar cada engagement)
  3. ¿Cómo de bien detectó el equipo azul lo que el rojo ejecutó?
     (cobertura de detección por campaña, patrón VECTR: detectado /
     no detectado / prevenido, con el porcentaje sobre lo evaluado)

Principio no negociable — SOLO datos reales:
- hallazgos.tecnica_mitre     → técnica OBSERVADA en esa campaña.
- aprobaciones.tecnica_mitre  → técnica INTENTADA en esa campaña.
- hallazgos.deteccion         → resultado defensivo REAL documentado.
Los IDs que no cumplen el formato ATT&CK (T#### o T####.###) se ignoran
con contador público; nunca se adivinan ni se rellenan. Sin campañas con
técnicas, la estructura queda vacía: cero relleno.
"""
from __future__ import annotations

import sqlite3
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Mismo validador que la capa Navigator: una sola definición de "ID ATT&CK
# válido" en toda la plataforma (navigator._RE_TECNICA).
from .navigator import _RE_TECNICA

# Orden canónico de severidad (mayor primero).
_ORDEN_SEV = {"critica": 4, "alta": 3, "media": 2, "baja": 1, "informativa": 0}


def _leer_caso(db_path: Path) -> dict[str, Any] | None:
    """Lee de una BD de caso SOLO lo que la analítica necesita.

    Devuelve {campaña, observadas: {tec: {...}}, intentadas: {tec: n},
    deteccion: Counter}. Un fichero corrupto o huérfano no rompe la
    analítica: se anota en `errores` y se continúa con el resto.
    """
    try:
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=5)
        conn.row_factory = sqlite3.Row
    except sqlite3.Error:
        return None
    try:
        eng = conn.execute(
            "SELECT id, nombre, cliente, fase_actual, estado_fase, creado_en "
            "FROM engagements WHERE id=?", (db_path.stem,)).fetchone()
        if eng is None:
            return None

        observadas: dict[str, dict[str, Any]] = {}
        deteccion = Counter()
        severidades = Counter()
        hallazgos_con_tecnica = 0
        invalidos = 0
        for h in conn.execute(
                "SELECT tecnica_mitre, severidad, deteccion FROM hallazgos"):
            t = (h["tecnica_mitre"] or "").strip()
            if not _RE_TECNICA.fullmatch(t):
                if t:
                    invalidos += 1
                continue
            hallazgos_con_tecnica += 1
            det = h["deteccion"] or "pendiente"
            deteccion[det] += 1
            severidades[h["severidad"] or "informativa"] += 1
            celda = observadas.setdefault(t, {
                "hallazgos": 0, "severidad_max": None, "deteccion": Counter()})
            celda["hallazgos"] += 1
            sev = h["severidad"] or "informativa"
            if celda["severidad_max"] is None or _ORDEN_SEV.get(
                    sev, 0) > _ORDEN_SEV.get(celda["severidad_max"], 0):
                celda["severidad_max"] = sev
            celda["deteccion"][det] += 1

        intentadas: dict[str, int] = {}
        for a in conn.execute("SELECT tecnica_mitre FROM aprobaciones"):
            t = (a["tecnica_mitre"] or "").strip()
            if _RE_TECNICA.fullmatch(t):
                intentadas[t] = intentadas.get(t, 0) + 1

        return {
            "campaña": {
                "id": eng["id"], "nombre": eng["nombre"],
                "cliente": eng["cliente"], "fase": eng["fase_actual"],
                "estado_fase": eng["estado_fase"], "creado_en": eng["creado_en"],
            },
            "observadas": observadas,
            "intentadas": intentadas,
            "deteccion": deteccion,
            "severidades": severidades,
            "hallazgos_con_tecnica": hallazgos_con_tecnica,
            "ids_invalidos": invalidos,
        }
    except sqlite3.Error:
        return None
    finally:
        conn.close()


def construir_cobertura(raiz_casos: Path) -> dict[str, Any]:
    """Agrega la cobertura ATT&CK de TODAS las campañas del despliegue.

    Solo lectura (SQLite mode=ro): la analítica nunca escribe en los casos.
    """
    generados = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    resultado: dict[str, Any] = {
        "generado": generados,
        "fuente": "hallazgos.tecnica_mitre + aprobaciones.tecnica_mitre + "
                  "hallazgos.deteccion (solo IDs ATT&CK válidos)",
        "campañas": [],
        "matriz": [],
        "recurrentes": [],
        "totales": {},
        "errores": [],
    }

    bdss = sorted(raiz_casos.glob("caso_*.db")) if raiz_casos.exists() else []
    if not bdss:
        resultado["totales"] = {
            "campañas": 0, "tecnicas_distintas": 0, "tecnicas_observadas": 0,
            "tecnicas_intentadas": 0, "hallazgos_con_tecnica": 0,
            "ids_invalidos": 0, "por_severidad": {}, "deteccion": {},
            "cobertura_deteccion_media_pct": None,
            "cobertura_deteccion_global_pct": None,
        }
        return resultado

    campanas: list[dict[str, Any]] = []
    matriz: dict[str, dict[str, dict[str, Any]]] = {}
    observacion_por_tecnica: dict[str, list[dict[str, Any]]] = {}
    tot_deteccion = Counter()
    tot_sev = Counter()
    tot_observadas = 0
    tot_intentadas = 0
    tot_hallazgos = 0
    tot_invalidos = 0
    pct_por_campaña: list[int] = []

    for bd in bdss:
        datos = _leer_caso(bd)
        if datos is None:
            resultado["errores"].append(
                {"bd": bd.name, "motivo": "ilegible u huérfana: omitida"})
            continue
        cam = datos["campaña"]
        det = datos["deteccion"]
        evaluados = det["detectado"] + det["no_detectado"] + det["prevenido"]
        cobertura_pct = (
            round((det["detectado"] + det["prevenido"]) * 100 / evaluados)
            if evaluados else None)

        campanas.append({
            **cam,
            "hallazgos_con_tecnica": datos["hallazgos_con_tecnica"],
            "tecnicas_observadas": len(datos["observadas"]),
            "tecnicas_intentadas": len(datos["intentadas"]),
            "deteccion": {
                "detectado": det.get("detectado", 0),
                "no_detectado": det.get("no_detectado", 0),
                "prevenido": det.get("prevenido", 0),
                "pendiente": det.get("pendiente", 0),
            },
            "cobertura_deteccion_pct": cobertura_pct,
            "ids_invalidos": datos["ids_invalidos"],
        })
        if cobertura_pct is not None:
            pct_por_campaña.append(cobertura_pct)
        tot_deteccion.update(det)
        tot_sev.update(datos["severidades"])
        tot_hallazgos += datos["hallazgos_con_tecnica"]
        tot_invalidos += datos["ids_invalidos"]
        tot_observadas += len(datos["observadas"])
        tot_intentadas += len(datos["intentadas"])

        for t, celda in datos["observadas"].items():
            matriz.setdefault(t, {}).setdefault(cam["id"], {
                "estado": "observada", "hallazgos": 0, "severidad_max": None,
                "deteccion": {"detectado": 0, "no_detectado": 0,
                              "prevenido": 0, "pendiente": 0},
            })
            m = matriz[t][cam["id"]]
            m["hallazgos"] += celda["hallazgos"]
            if (celda["severidad_max"] and
                    (m["severidad_max"] is None or _ORDEN_SEV.get(
                        celda["severidad_max"], 0) > _ORDEN_SEV.get(
                        m["severidad_max"], 0))):
                m["severidad_max"] = celda["severidad_max"]
            for k, v in celda["deteccion"].items():
                m["deteccion"][k] = m["deteccion"].get(k, 0) + v
            observacion_por_tecnica.setdefault(t, []).append(cam)

        for t in datos["intentadas"]:
            matriz.setdefault(t, {}).setdefault(cam["id"], {
                "estado": "intentada", "hallazgos": 0, "severidad_max": None,
                "deteccion": {"detectado": 0, "no_detectado": 0,
                              "prevenido": 0, "pendiente": 0},
            })

    # --- filas de la matriz -------------------------------------------------
    campanas.sort(key=lambda c: (c["creado_en"] or "", c["id"]))
    ids_campañas = [c["id"] for c in campanas]
    filas: list[dict[str, Any]] = []
    for t in sorted(matriz):
        fila: dict[str, Any] = {"tecnica": t, "celdas": {}, "campanas": 0}
        n_cam = 0
        for cid in ids_campañas:
            celda = matriz[t].get(cid)
            if not celda:
                fila["celdas"][cid] = None
                continue
            n_cam += 1
            det = celda["deteccion"]
            evaluados = det["detectado"] + det["no_detectado"] + det["prevenido"]
            fila["celdas"][cid] = {
                "estado": "observada" if celda["hallazgos"] else "intentada",
                "hallazgos": celda["hallazgos"],
                "severidad_max": celda["severidad_max"],
                "deteccion": det,
                "cobertura_pct": (
                    round((det["detectado"] + det["prevenido"]) * 100 / evaluados)
                    if evaluados else None),
            }
        fila["campanas"] = n_cam
        filas.append(fila)

    # --- técnicas recurrentes (observadas en ≥2 campañas) -------------------
    recurrentes: list[dict[str, Any]] = []
    for t, camps in observacion_por_tecnica.items():
        if len(camps) >= 2:
            recurrentes.append({
                "tecnica": t,
                "campanas": [{"id": c["id"], "nombre": c["nombre"]} for c in camps],
            })
    recurrentes.sort(key=lambda r: (-len(r["campanas"]), r["tecnica"]))

    evaluados_tot = (tot_deteccion["detectado"] + tot_deteccion["no_detectado"]
                     + tot_deteccion["prevenido"])
    resultado["campañas"] = campanas
    resultado["matriz"] = filas
    resultado["recurrentes"] = recurrentes
    resultado["totales"] = {
        "campañas": len(campanas),
        "tecnicas_distintas": len(matriz),
        "tecnicas_observadas": tot_observadas,
        "tecnicas_intentadas": tot_intentadas,
        "hallazgos_con_tecnica": tot_hallazgos,
        "ids_invalidos": tot_invalidos,
        "por_severidad": {k: v for k, v in
                          sorted(tot_sev.items(), key=lambda kv: -_ORDEN_SEV.get(kv[0], 0))},
        "deteccion": {k: tot_deteccion.get(k, 0) for k in
                      ("detectado", "no_detectado", "prevenido", "pendiente")},
        "cobertura_deteccion_media_pct": (
            round(sum(pct_por_campaña) / len(pct_por_campaña))
            if pct_por_campaña else None),
        "cobertura_deteccion_global_pct": (
            round((tot_deteccion["detectado"] + tot_deteccion["prevenido"])
                  * 100 / evaluados_tot) if evaluados_tot else None),
    }
    return resultado


def csv_cobertura(cobertura: dict[str, Any]) -> str:
    """Matriz técnica × campaña en CSV (una fila por celda poblada).

    Columnas: tecnica, campana_id, campana_nombre, estado, hallazgos,
    severidad_max, detectado, no_detectado, prevenido, pendiente.
    """
    import csv
    import io

    nombres = {c["id"]: c["nombre"] for c in cobertura["campañas"]}
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["tecnica", "campana_id", "campana_nombre", "estado",
                "hallazgos", "severidad_max", "detectado", "no_detectado",
                "prevenido", "pendiente"])
    for fila in cobertura["matriz"]:
        for cid in nombres:
            celda = fila["celdas"].get(cid)
            if not celda:
                continue
            det = celda["deteccion"]
            w.writerow([
                fila["tecnica"], cid, nombres[cid], celda["estado"],
                celda["hallazgos"], celda["severidad_max"] or "",
                det.get("detectado", 0), det.get("no_detectado", 0),
                det.get("prevenido", 0), det.get("pendiente", 0),
            ])
    return buf.getvalue()
