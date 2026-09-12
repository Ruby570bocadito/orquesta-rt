"""Validación de reglas Sigma del caso (detection-as-code verificable).

El paquete purple team genera esqueletos Sigma desde hallazgos reales.
Hasta ahora esos esqueletos salían sin verificación estructural: un
error de sintaxis (condición que referencia una selección inexistente,
YAML roto, id no-UUID) solo se descubría cuando el operador lo cargaba
en su pipeline — o peor, en su SIEM.

Este módulo valida ANTES de entregar:

  validar_regla(texto)   → dict {valida, errores, avisos, logsource, tags}
  validar_lote(dict)     → resumen {total, validas, invalidas, reglas: [...]}

Dos niveles:
  1. Estructural (siempre, sin dependencias): YAML parseable, campos
     obligatorios (title, id UUID, logsource, detection con selections
     y condition), la condición solo referencia selecciones existentes
     (incluida sintaxis "1 of selection*"), tags con namespace conocido
     y al menos un attack.tXXXX.
  2. Profunda (opcional): si pySigma está instalado se construye la
     SigmaRule oficial — cualquier error del parser real se añade como
     error. Nunca es requisito: sin pySigma la validación estructural
     sigue siendo completa y honesta (lo declara en el resultado).

Política de la plataforma: lo que entrega el paquete purple debe ser
verificable en el momento de la entrega, no "esperamos que compile".
"""
from __future__ import annotations

import re
import uuid
from typing import Any

import yaml

# Estados oficiales de la especificación Sigma
_ESTADOS = {"stable", "test", "experimental", "deprecated", "unsupported"}

# Namespaces de tags con significado declarado en la especificación
_RE_TAG = re.compile(r"^[a-z0-9_\-]+(\.[a-z0-9_\-]+)*$")
_RE_TAG_TECNICA = re.compile(r"^attack\.t\d{4}(?:\.\d{3})?$")

# Identificadores reservados de la gramática de condiciones Sigma
_PALABRAS_CONDICION = {
    "and", "or", "not", "of", "them", "all", "any", "one", "count",
    "by", "min", "max", "avg", "sum", "near", "in", "within",
}


def _extraer_identificadores(condicion: str) -> list[str]:
    """Identificadores de selecciones usados por una condición Sigma.

    Tolerante: entiende "sel", "sel1 and sel2", "1 of sel*", "all of them"
    y cuantificadores "x of y". Devuelve los nombres (con comodines tal
    cual, p. ej. "sel*") que deben existir en detection.
    """
    tokens = re.findall(r"[A-Za-z_][A-Za-z0-9_\*\[\]]*", condicion or "")
    nombres: list[str] = []
    vistos: set[str] = set()  # z3 (F24): sin duplicados — "sel and sel"
    # no debe producir dos errores idénticos en el veredicto.

    def _apuntar(nombre: str) -> None:
        if nombre not in vistos:
            vistos.add(nombre)
            nombres.append(nombre)

    # "N of patron*" / "1 of them" / "all of sel"
    patron_of = re.findall(
        r"(?:\b\d+|\ball\b|\bany\b|\bone\b)\s+of\s+([A-Za-z_][A-Za-z0-9_\*]*)",
        condicion or "", re.IGNORECASE)
    for patron in patron_of:
        bajo = patron.lower()
        if bajo in _PALABRAS_CONDICION:
            continue  # "them"/"all"/"any": cuantificador, no una selección
        _apuntar(bajo)
    for t in tokens:
        bajo = t.lower()
        if bajo in _PALABRAS_CONDICION:
            continue
        # omitir los que ya capturó el patrón "of" (evita duplicar sel*)
        if any(p.rstrip("*") in bajo for p in patron_of):
            continue
        if re.fullmatch(r"\d+", bajo):
            continue
        _apuntar(bajo)
    return nombres


def validar_regla(texto: str) -> dict[str, Any]:
    """Valida una regla Sigma (YAML) y devuelve un veredicto detallado.

    Nunca lanza: los problemas de parseo SON el resultado (errores).
    """
    errores: list[str] = []
    avisos: list[str] = []
    resultado: dict[str, Any] = {"valida": True, "errores": errores,
                                 "avisos": avisos, "logsource": None,
                                 "tags": [], "motor_profundo": None}

    try:
        datos = yaml.safe_load(texto or "")
    except Exception as exc:
        resultado["valida"] = False
        errores.append(f"yaml: no parseable ({str(exc)[:160]})")
        return resultado

    if not isinstance(datos, dict):
        resultado["valida"] = False
        errores.append("yaml: la regla debe ser un mapa clave-valor")
        return resultado

    # --- title -----------------------------------------------------------
    titulo = datos.get("title")
    if not isinstance(titulo, str) or not titulo.strip():
        errores.append("title: ausente o vacío (obligatorio)")
    elif len(titulo) > 256:
        errores.append("title: excede 256 caracteres")

    # --- id: UUID ----------------------------------------------------------
    rid = datos.get("id")
    if not rid:
        errores.append("id: ausente (obligatorio, UUID)")
    else:
        try:
            uuid.UUID(str(rid))
        except (ValueError, AttributeError):
            errores.append(f"id: '{rid}' no es un UUID válido")

    # --- status ----------------------------------------------------------
    estado = datos.get("status")
    if estado is not None and estado not in _ESTADOS:
        avisos.append(f"status: '{estado}' no es un estado oficial "
                      f"({', '.join(sorted(_ESTADOS))})")

    # --- logsource ---------------------------------------------------------
    fuente = datos.get("logsource")
    if not isinstance(fuente, dict) or not fuente:
        errores.append("logsource: ausente o vacío (obligatorio)")
    else:
        claves_validas = [k for k in ("category", "product", "service",
                                      "definition") if fuente.get(k)]
        if not any(k in claves_validas for k in ("category", "product",
                                                 "service")):
            errores.append("logsource: necesita al menos category, product "
                           "o service")
        resultado["logsource"] = {k: fuente[k] for k in
                                  ("category", "product", "service")
                                  if fuente.get(k)}

    # --- detection ---------------------------------------------------------
    deteccion = datos.get("detection")
    if not isinstance(deteccion, dict) or not deteccion:
        errores.append("detection: ausente o vacío (obligatorio)")
    else:
        selecciones = {k.lower() for k in deteccion
                       if k.lower() != "condition"}
        condicion = deteccion.get("condition")
        if not condicion:
            errores.append("detection: falta 'condition' (obligatorio)")
        elif not isinstance(condicion, (str, list)):
            errores.append("detection.condition: debe ser texto o lista")
        else:
            if not selecciones:
                errores.append("detection: no hay ninguna selección "
                               "además de 'condition'")
            condiciones = ([condicion] if isinstance(condicion, str)
                           else [str(c) for c in condicion])
            for c in condiciones:
                for nombre in _extraer_identificadores(c):
                    if nombre.endswith("*"):
                        prefijo = nombre.rstrip("*")
                        if not any(s.startswith(prefijo)
                                   for s in selecciones):
                            errores.append(
                                f"detection.condition: '{nombre}' no "
                                f"coincide con ninguna selección "
                                f"(prefijo '{prefijo}*')")
                    elif nombre not in selecciones:
                        errores.append(
                            f"detection.condition: referencia "
                            f"'{nombre}' inexistente en detection")
        # selecciones vacías ({}): aviso, la regla matchearía demasiado
        for k, v in deteccion.items():
            if k.lower() != "condition" and isinstance(v, dict) and not v:
                avisos.append(f"detection.{k}: selección vacía "
                              f"(matchearía cualquier evento)")
                break

    # --- tags --------------------------------------------------------------
    tags = datos.get("tags") or []
    if not isinstance(tags, list):
        errores.append("tags: debe ser una lista")
        tags = []
    tags_limpios: list[str] = []
    for t in tags:
        tag = str(t).strip().lower()
        if not _RE_TAG.match(tag):
            errores.append(f"tags: '{t}' no es un tag con namespace válido")
            continue
        if "." not in tag:
            avisos.append(f"tags: '{tag}' sin namespace.category (higiene "
                          f"Sigma: p. ej. attack.t1558.003)")
        tags_limpios.append(tag)
    if not any(_RE_TAG_TECNICA.match(t) for t in tags_limpios):
        avisos.append("tags: falta attack.tXXXX (la regla no se vincula a "
                      "una técnica ATT&CK)")

    # --- nivel -------------------------------------------------------------
    nivel = datos.get("level")
    if nivel is None:
        avisos.append("level: ausente (recomendado: informational a critical)")

    # --- validación profunda opcional (pySigma) ----------------------------
    try:
        from sigma.rule import SigmaRule  # type: ignore
        try:
            SigmaRule.from_yaml(texto or "")
            resultado["motor_profundo"] = "pysigma: ok"
        except Exception as exc:
            resultado["valida"] = False
            errores.append(f"pysigma: {str(exc)[:200]}")
            resultado["motor_profundo"] = "pysigma: error"
    except ImportError:
        resultado["motor_profundo"] = ("pysigma no instalado "
                                       "(validación estructural completa)")

    resultado["tags"] = tags_limpios
    resultado["valida"] = resultado["valida"] and not errores
    return resultado


def validar_lote(reglas: dict[str, str]) -> dict[str, Any]:
    """Valida un lote {nombre: yaml} y devuelve el resumen agregado.

    El orden del resultado sigue el orden de inserción (estable) para
    que el informe purple sea determinista entre corridas.
    """
    detalles: list[dict[str, Any]] = []
    validas = 0
    for nombre, texto in (reglas or {}).items():
        r = validar_regla(texto)
        detalles.append({"nombre": nombre, **r})
        if r["valida"]:
            validas += 1
    return {"total": len(detalles), "validas": validas,
            "invalidas": len(detalles) - validas,
            "con_motor_profundo": sum(
                1 for d in detalles
                if str(d.get("motor_profundo", "")).startswith("pysigma")),
            "reglas": detalles}
