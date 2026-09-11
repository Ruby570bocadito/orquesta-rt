"""Servidor LDAP REAL de prueba (ldaptor/Twisted) para la E2E del grafo.

HABLA EL PROTOCOLO LDAP v3 de verdad por TCP (:1389): el cliente ldap3 del
orquestador conecta, hace BIND con credenciales y SEARCH sin saber que al
otro lado hay ldaptor. Es un fixture de VERIFICACIÓN E2E del despliegue de
pruebas — no forma parte del producto ni se empaqueta.

Árbol de prueba (organización reducida, cargado vía LDIF):
  dc=test,dc=local
  ├── cn=consulta              (usuario de bind, userPassword=clave-e2e)
  └── ou=people
      ├── jmaria  CEO / Dirección            (raíz: sin manager)
      ├── pgonzal Manager IT / IT            (manager=jmaria)
      ├── lortiz  Developer / IT             (manager=pgonzal)
      ├── cfdez   Developer / IT             (manager=pgonzal)
      └── msanz   Account Exec / Ventas      (manager=jmaria)

Uso: python scripts/ldap_prueba_e2e.py [puerto]
"""
from __future__ import annotations

import io
import sys

from ldaptor import interfaces
from ldaptor.inmemory import fromLDIFFile
from ldaptor.protocols.ldap.ldapserver import LDAPServer
from twisted.internet import protocol, reactor
from twisted.internet.defer import maybeDeferred
from twisted.python.components import registerAdapter
from zope.interface import implementer

PUERTO = int(sys.argv[1]) if len(sys.argv) > 1 else 1389

PEOPLE = [
    # (cn, sn, displayName, title, department, mail, manager_cn)
    ("jmaria", "María", "Juan María", "CEO", "Dirección",
     "jmaria@test.local", ""),
    ("pgonzal", "González", "Paula González", "Manager IT", "IT",
     "pgonzal@test.local", "jmaria"),
    ("lortiz", "Ortiz", "Luis Ortiz", "Developer", "IT",
     "lortiz@test.local", "pgonzal"),
    ("cfdez", "Fernández", "Carla Fernández", "Developer", "IT",
     "cfdez@test.local", "pgonzal"),
    ("msanz", "Sanz", "Miguel Sanz", "Account Exec", "Ventas",
     "msanz@test.local", "jmaria"),
]

_LIFNEA = []
_LIFNEA += [
    "dn: dc=test,dc=local",
    "objectClass: dcObject", "objectClass: organization",
    "dc: test", "o: ACME Prueba", "",
    "dn: cn=consulta,dc=test,dc=local",
    "objectClass: person", "objectClass: organizationalPerson",
    "cn: consulta", "sn: bind", "userPassword: clave-e2e", "",
    "dn: ou=people,dc=test,dc=local",
    "objectClass: organizationalUnit", "ou: people", "",
]
for cn, sn, nombre, cargo, depto, correo, manager in PEOPLE:
    _LIFNEA += [
        f"dn: cn={cn},ou=people,dc=test,dc=local",
        "objectClass: inetOrgPerson",
        f"cn: {cn}", f"sn: {sn}", f"displayName: {nombre}",
        f"title: {cargo}", f"department: {depto}", f"mail: {correo}",
        f"sAMAccountName: {cn}", "sAMAccountType: 805306368",
    ]
    if manager:
        _LIFNEA.append(f"manager: cn={manager},ou=people,dc=test,dc=local")
    _LIFNEA.append("")
_LIFNEA.append("")  # terminación LDIF del último registro

LDIF = "\n".join(_LIFNEA).encode()


@implementer(interfaces.IConnectedLDAPEntry)
class FabricaLDAP(protocol.ServerFactory):
    """Fábrica oficial ldaptor: el servidor resuelve DNs vía la raíz."""

    protocol = LDAPServer

    def __init__(self, root) -> None:
        self.root = root
        self.debug = False

    def buildProtocol(self, addr):  # noqa: ANN001, ANN201
        proto = self.protocol()
        proto.debug = self.debug
        proto.factory = self
        return proto

    def lookup(self, dn):  # noqa: ANN001, ANN201
        return maybeDeferred(self.root.lookup, dn)


registerAdapter(lambda x: x, FabricaLDAP,
                interfaces.IConnectedLDAPEntry)


def _servir(raiz) -> None:
    reactor.listenTCP(PUERTO, FabricaLDAP(raiz), interface="127.0.0.1")
    print(f"LDAP de prueba escuchando en 127.0.0.1:{PUERTO}", flush=True)

if __name__ == "__main__":
    d = fromLDIFFile(io.BytesIO(LDIF))
    d.addCallback(_servir)
    d.addErrback(lambda fallo: (print(fallo, flush=True),
                                reactor.stop()))
    reactor.run()
