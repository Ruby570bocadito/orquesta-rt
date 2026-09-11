#!/usr/bin/env python3
"""Colección de dominio de laboratorio en esquema BloodHound → Neo4j REAL.

Qué es:
  Una colección DECLARADA del dominio de laboratorio `test.local` (la misma
  plantilla que sirve el LDAP real del lab v19: jmaria/pgonzal/lortiz/cfdez/
  msanz) cargada en una instancia Neo4j REAL con el esquema de grafo de
  BloodHound (labels Base/User/Group/Computer/Domain y tipos de relación
  MemberOf, AdminTo, GenericAll, AddMember, AllExtendedRights, HasSession,
  GetChangesAll, DCFor).

Qué NO es:
  No es un BloodHound CE (eso exige Docker+Postgres+Neo4j) ni sustituye al
  conector CE del orquestador, que habla el protocolo REST oficial cuando el
  operador tiene su instancia. Las rutas de ataque que se sirvan desde aquí
  las calcula el MOTOR Neo4j REAL con Cypher (allShortestPaths) sobre esta
  colección — y la plataforma lo etiqueta honestamente como "colección de
  laboratorio".

Uso:  .venv/bin/python3 lab/coleccion_dominio.py
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
CYPHER = RAIZ / "lab" / "coleccion.cypher"
SHELL = RAIZ / "lab" / "neo4j-community-5.26.12" / "bin" / "cypher-shell"
USUARIO, CLAVE = "neo4j", "orquesta-lab-2026"

# ---------------------------------------------------------------------------
# Colección declarada del dominio de laboratorio
# ---------------------------------------------------------------------------
NODOS = [
    # (labels_extra, name, props)
    ("Domain", "TEST.LOCAL", {}),
    # Usuarios derivados de la plantilla real del LDAP de laboratorio (v19)
    ("User", "JMARIA@TEST.LOCAL", {"displayname": "Juan María", "title": "CEO",
                                   "department": "Dirección", "enabled": True}),
    ("User", "PGONZAL@TEST.LOCAL", {"displayname": "Paula González",
                                    "title": "Manager IT", "department": "IT",
                                    "admincount": True, "enabled": True}),
    ("User", "LORTIZ@TEST.LOCAL", {"displayname": "Luis Ortiz",
                                   "title": "Developer", "department": "IT",
                                   "dontreqpreauth": True, "enabled": True}),
    ("User", "CFDEZ@TEST.LOCAL", {"displayname": "Carla Fernández",
                                  "title": "Developer", "department": "IT",
                                  "enabled": True}),
    ("User", "MSANZ@TEST.LOCAL", {"displayname": "Marta Sanz",
                                  "title": "Account Exec", "department": "Ventas",
                                  "enabled": True}),
    # Cuentas de servicio típicas de una colección real
    ("User", "SVC_BACKUP@TEST.LOCAL", {"displayname": "svc-backup",
                                       "serviceprincipalnames":
                                       ["CIFS/WKS-FP-01.test.local",
                                        "CIFS/SRV-ARCHIVE.test.local"],
                                       "admincount": True, "enabled": True}),
    ("User", "SVC_HELPDESK@TEST.LOCAL", {"displayname": "svc-helpdesk",
                                         "enabled": True}),
    # Grupos
    ("Group", "DOMAIN ADMINS@TEST.LOCAL", {"admincount": True}),
    ("Group", "IT-ADMINS@TEST.LOCAL", {"admincount": True}),
    ("Group", "HELPDESK@TEST.LOCAL", {}),
    ("Group", "ALL-STAFF@TEST.LOCAL", {}),
    # Equipos
    ("Computer", "DC01.TEST.LOCAL", {"operatingsystem":
                                     "Windows Server 2022"}),
    ("Computer", "WKS-FP-01.TEST.LOCAL", {"operatingsystem":
                                          "Windows 11 Pro"}),
    ("Computer", "WKS-FP-02.TEST.LOCAL", {"operatingsystem":
                                          "Windows 11 Pro"}),
    ("Computer", "SRV-ARCHIVE.TEST.LOCAL", {"operatingsystem":
                                            "Windows Server 2019"}),
]

# (tipo, origen, destino)  — solo relaciones DECLARADAS de la colección
ARISTAS = [
    ("MemberOf", "PGONZAL@TEST.LOCAL", "IT-ADMINS@TEST.LOCAL"),
    ("MemberOf", "SVC_HELPDESK@TEST.LOCAL", "HELPDESK@TEST.LOCAL"),
    ("MemberOf", "SVC_HELPDESK@TEST.LOCAL", "IT-ADMINS@TEST.LOCAL"),
    ("MemberOf", "SVC_BACKUP@TEST.LOCAL", "DOMAIN ADMINS@TEST.LOCAL"),
    ("MemberOf", "JMARIA@TEST.LOCAL", "ALL-STAFF@TEST.LOCAL"),
    ("MemberOf", "LORTIZ@TEST.LOCAL", "ALL-STAFF@TEST.LOCAL"),
    ("MemberOf", "CFDEZ@TEST.LOCAL", "ALL-STAFF@TEST.LOCAL"),
    ("MemberOf", "MSANZ@TEST.LOCAL", "ALL-STAFF@TEST.LOCAL"),
    ("AddMember", "CFDEZ@TEST.LOCAL", "HELPDESK@TEST.LOCAL"),
    ("GenericAll", "HELPDESK@TEST.LOCAL", "SVC_HELPDESK@TEST.LOCAL"),
    ("AllExtendedRights", "PGONZAL@TEST.LOCAL", "JMARIA@TEST.LOCAL"),
    ("AdminTo", "IT-ADMINS@TEST.LOCAL", "WKS-FP-01.TEST.LOCAL"),
    ("AdminTo", "IT-ADMINS@TEST.LOCAL", "WKS-FP-02.TEST.LOCAL"),
    ("AdminTo", "SVC_BACKUP@TEST.LOCAL", "SRV-ARCHIVE.TEST.LOCAL"),
    # Esquema oficial BH: (Computer)-[:HasSession]->(User) — controlar el
    # equipo permite robar las credenciales del usuario en sesión.
    ("HasSession", "WKS-FP-01.TEST.LOCAL", "SVC_BACKUP@TEST.LOCAL"),
    ("HasSession", "WKS-FP-02.TEST.LOCAL", "JMARIA@TEST.LOCAL"),
    ("GetChangesAll", "SVC_BACKUP@TEST.LOCAL", "TEST.LOCAL"),
    ("DCFor", "DC01.TEST.LOCAL", "TEST.LOCAL"),
    ("AllExtendedRights", "DOMAIN ADMINS@TEST.LOCAL", "DC01.TEST.LOCAL"),
]

ETIQUETAS = {"Domain": ":Base:Domain", "User": ":Base:User",
             "Group": ":Base:Group", "Computer": ":Base:Computer"}


def _serializar(v: object) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    if isinstance(v, list):
        return "[" + ", ".join(f"'{x}'" for x in v) + "]"
    return f"'{v}'"


def generar() -> str:
    lineas = ["MATCH (n) DETACH DELETE n;"]
    for labels, name, props in NODOS:
        p = {"name": name, "domain": "TEST.LOCAL", **props}
        cuerpo = ", ".join(f"{k}: {_serializar(v)}" for k, v in p.items())
        lineas.append(f"CREATE (n{ETIQUETAS[labels]} {{{cuerpo}}});")
    for tipo, origen, destino in ARISTAS:
        lineas.append(
            f"MATCH (a {{name: '{origen}'}}), (b {{name: '{destino}'}}) "
            f"CREATE (a)-[:{tipo}]->(b);")
    lineas.append("CREATE INDEX usuario_nombre IF NOT EXISTS "
                  "FOR (u:User) ON (u.name);")
    lineas.append("CREATE INDEX grupo_nombre IF NOT EXISTS "
                  "FOR (g:Group) ON (g.name);")
    lineas.append("CREATE INDEX equipo_nombre IF NOT EXISTS "
                  "FOR (c:Computer) ON (c.name);")
    return "\n".join(lineas) + "\n"


def main() -> int:
    CYPHER.write_text(generar(), encoding="utf-8")
    cmd = [str(SHELL), "-a", "127.0.0.1:7687", "-u", USUARIO, "-p", CLAVE,
           "--format", "plain", "-f", str(CYPHER)]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    if r.returncode != 0:
        print("ERROR cargando colección:", r.stderr[-800:], file=sys.stderr)
        return 1
    # Verificación REAL del contenido cargado
    ver = subprocess.run(
        [str(SHELL), "-a", "127.0.0.1:7687", "-u", USUARIO, "-p", CLAVE,
         "--format", "plain",
         "MATCH (n) RETURN labels(n)[1] AS t, count(*) AS c ORDER BY t;"],
        capture_output=True, text=True, timeout=60)
    print("Colección cargada. Recuento real en Neo4j:")
    print(ver.stdout.strip() or ver.stderr[-400:])
    return 0


if __name__ == "__main__":
    sys.exit(main())
