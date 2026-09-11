"""Rutas de ataque REALES sobre el motor Neo4j del despliegue.

La plataforma consulta el grafo con Cypher (allShortestPaths DIRIGIDOS,
esquema de BloodHound) a través de la API transaccional HTTP de Neo4j y
devuelve las rutas que el MOTOR calcula — la plataforma no recalcula ni
inventa rutas.

Dos fuentes posibles y SIEMPRE etiquetadas:
  1. Motor de laboratorio (NEO4J_URL configurado): grafo cargado con la
     colección declarada del dominio de laboratorio (lab/coleccion_dominio.py).
  2. BloodHound CE del operador (BLOODHOUND_URL configurado): las rutas las
     sirve el servidor CE vía su API oficial (integraciones.bloodhound).

Sin ninguna de las dos configuradas, el endpoint responde el requisito
exacto: jamás se fabrican rutas.

Variables de entorno:
  NEO4J_URL    p. ej. http://localhost:7474
  NEO4J_USER   usuario de Neo4j
  NEO4J_PASS   contraseña de Neo4j

Referencia del protocolo (API transaccional HTTP de Neo4j 5):
  POST /db/neo4j/tx/commit
       {"statements":[{"statement":"...","parameters":{...}}]}
       (cabecera basic auth; los resultados vienen en data[*].row)
"""
from __future__ import annotations

import os
from typing import Any

# Objetivos de alto valor: grupos con admincount y controladores de dominio.
_CYPHER_RUTAS = """
MATCH p = allShortestPaths((o)-[*1..10]->(t))
WHERE ($origen IS NULL OR o.name = $origen)
  AND ((t:Group AND coalesce(t.admincount, false))
    OR (t:Computer AND EXISTS { ()-[:DCFor]->(d:Domain) WHERE d = t }
        OR EXISTS { (t)-[:DCFor]->(:Domain) })
    OR (t:Domain AND EXISTS { (o)-[:GetChangesAll|AllExtendedRights*1..2]->(t) }))
  AND o <> t
WITH p, t, length(p) AS saltos
RETURN [n IN nodes(p) | {nombre: n.name, tipo: head([l IN labels(n)
         WHERE l IN ['User','Group','Computer','Domain']]),
         asreproastable: coalesce(n.dontreqpreauth, false),
         kerberoasteable: size(coalesce(n.serviceprincipalnames, [])) > 0}]
       AS nodos,
       [r IN relationships(p) | type(r)] AS aristas,
       saltos
ORDER BY saltos ASC
LIMIT $limite
"""

_CYPHER_OBJETIVOS = """
MATCH (t)
WHERE (t:Group AND coalesce(t.admincount, false))
   OR (t:Computer AND EXISTS { (t)-[:DCFor]->(:Domain) })
RETURN t.name AS nombre, head([l IN labels(t)
       WHERE l IN ['Group','Computer','Domain']]) AS tipo
ORDER BY nombre
LIMIT 50
"""

_CYPHER_ORIGENES = """
MATCH (u:User)
RETURN u.name AS nombre,
       coalesce(u.admincount, false) AS admincount,
       coalesce(u.dontreqpreauth, false) AS asreproastable,
       coalesce(u.displayname, '') AS displayname,
       coalesce(u.title, '') AS cargo
ORDER BY nombre
LIMIT 100
"""

_CYPHER_RECUENTO = """
MATCH (n) WITH labels(n) AS ls, count(*) AS c
UNWIND ls AS l
WITH l, c WHERE l IN ['User','Group','Computer','Domain']
RETURN l AS tipo, sum(c) AS total
ORDER BY tipo
"""

_CYPHER_ARISTAS = """
MATCH ()-[r]->()
RETURN type(r) AS tipo, count(*) AS total
ORDER BY total DESC
"""


def _config() -> tuple[str, str, str]:
    url = os.environ.get("NEO4J_URL", "")
    usuario = os.environ.get("NEO4J_USER", "")
    clave = os.environ.get("NEO4J_PASS", "")
    if not url or not usuario or not clave:
        raise RuntimeError(
            "Motor de rutas no configurado: defina NEO4J_URL, NEO4J_USER y "
            "NEO4J_PASS (p. ej. la instancia de laboratorio arrancada con "
            "lab/neo4j_arrancar.sh y cargada con lab/coleccion_dominio.py) o "
            "apunte a su Neo4j de producción con la colección de BloodHound.")
    return url.rstrip("/"), usuario, clave


def _consultar(consulta: str, parametros: dict[str, Any] | None = None) -> list[list[Any]]:
    """Ejecuta Cypher REAL contra la API transaccional HTTP de Neo4j."""
    import httpx
    url, usuario, clave = _config()
    cuerpo = {"statements": [{"statement": consulta,
                              "parameters": parametros or {}}]}
    try:
        with httpx.Client(timeout=20) as c:
            r = c.post(f"{url}/db/neo4j/tx/commit", json=cuerpo,
                       auth=(usuario, clave))
    except Exception as exc:
        raise RuntimeError(f"Neo4j inaccesible ({url}): {str(exc)[:200]}")
    if r.status_code != 200:
        raise RuntimeError(f"Neo4j respondió {r.status_code}: {r.text[:200]}")
    datos = r.json()
    errores = datos.get("errors") or []
    if errores:
        raise RuntimeError(f"Cypher rechazado: {str(errores[0])[:200]}")
    return [fila.get("row", []) for fila in datos.get("results",
           [{}])[0].get("data", [])]


def estado() -> dict[str, Any]:
    """Estado REAL del motor: conectividad y recuento del grafo cargado."""
    try:
        url, _, _ = _config()
        filas = _consultar(_CYPHER_RECUENTO)
        recuento = {fila[0]: fila[1] for fila in filas}
        aristas = {fila[0]: fila[1] for fila in _consultar(_CYPHER_ARISTAS)}
        total = sum(recuento.values())
        if total == 0:
            return {"conectado": True, "motor": url, "objetos": {},
                    "cargado": False,
                    "nota": "Neo4j accesible pero SIN colección cargada: "
                            "ejecute lab/coleccion_dominio.py o cargue su "
                            "recolección de BloodHound"}
        return {"conectado": True, "motor": url, "objetos": recuento,
                "aristas": aristas, "cargado": True,
                "esquema": "BloodHound (Base/User/Group/Computer/Domain)",
                "nota": "las rutas las calcula el MOTOR Neo4j con Cypher "
                        "dirigido (allShortestPaths) sobre la colección "
                        "cargada; nada se inventa en la plataforma"}
    except RuntimeError as exc:
        return {"conectado": False, "error": str(exc)}
    except Exception as exc:
        return {"conectado": False, "error": f"Neo4j: {str(exc)[:220]}"}


def origenes() -> dict[str, Any]:
    """Usuarios REALES del grafo (puntos de partida de rutas)."""
    try:
        filas = _consultar(_CYPHER_ORIGENES)
        usuarios = [{"nombre": f[0], "admincount": bool(f[1]),
                     "asreproastable": bool(f[2]), "displayname": f[3],
                     "cargo": f[4]} for f in filas]
        return {"conectado": True, "usuarios": usuarios,
                "total": len(usuarios)}
    except RuntimeError as exc:
        return {"conectado": False, "error": str(exc)}
    except Exception as exc:
        return {"conectado": False, "error": f"Neo4j orígenes: {str(exc)[:220]}"}


def objetivos() -> dict[str, Any]:
    """Objetivos de alto valor REALES del grafo (grupos admin, DCs)."""
    try:
        filas = _consultar(_CYPHER_OBJETIVOS)
        lista = [{"nombre": f[0], "tipo": f[1]} for f in filas]
        return {"conectado": True, "objetivos": lista, "total": len(lista)}
    except RuntimeError as exc:
        return {"conectado": False, "error": str(exc)}
    except Exception as exc:
        return {"conectado": False, "error": f"Neo4j objetivos: {str(exc)[:220]}"}


def rutas(origen: str | None = None, limite: int = 5) -> dict[str, Any]:
    """Rutas de ataque REALES calculadas por Neo4j (Cypher dirigido).

    Con `origen` (nombre de un usuario del grafo) calcula los caminos más
    cortos hacia objetivos de alto valor. Sin origen, las rutas desde
    CUALQUIER nodo del grafo hacia objetivos de alto valor.
    """
    if limite < 1 or limite > 20:
        return {"conectado": False, "error": "limite debe estar entre 1 y 20"}
    try:
        filas = _consultar(_CYPHER_RUTAS,
                           {"origen": (origen or "").strip().upper() or None,
                            "limite": int(limite)})
        rutas_lista = [{"nodos": f[0], "aristas": f[1], "saltos": f[2]}
                       for f in filas]
        return {"conectado": True,
                "origen": origen or "(todo el grafo)",
                "rutas": rutas_lista, "total": len(rutas_lista),
                "nota": "paths calculados por el motor Neo4j con "
                        "allShortestPaths dirigido; la colección es la "
                        "cargada en la instancia (lab o su producción)"}
    except RuntimeError as exc:
        return {"conectado": False, "error": str(exc)}
    except Exception as exc:
        return {"conectado": False, "error": f"Neo4j rutas: {str(exc)[:220]}"}
