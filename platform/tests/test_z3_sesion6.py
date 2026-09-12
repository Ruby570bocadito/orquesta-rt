"""Tests z3 — sesión 6: defectos de nombres indefinidos en el arsenal AD y
en el grafo de fases (detectados con análisis estático pyflakes + verificación
dinámica), y guarda sistémica contra regresiones del mismo tipo.

Cubre los fixes de esta ronda:
  F34  ad.asrep(): `etipo_clave = _enctype_table[23]` — resto de una versión
       anterior que referenciaba un símbolo que el módulo JAMÁS importa.
       NameError garantizado justo cuando el directorio SÍ declara cuentas
       sin preautenticación (el caso de uso de la herramienta), fuera de todo
       try: 500 vía /api/engagements/{id}/arsenal/ad. La asignación era además
       muerta (el etype se lee de la AS_REP recibida). Test dinámico: con los
       módulos impacket/pyasn1 simulados y LDAP enumerando cuentas, asrep()
       debe completar sin excepción.
  F35  ad.dcsync(): la llamada a SMBTransport usaba `username` (inexistente;
       la variable del ámbito es `usuario`): NameError tras el login SMB,
       capturado por el except genérico con un error engañoso ("DCSync falló
       contra el DC real"). dcsync NUNCA funcionó. Test estático: el AST de
       dcsync no carga ningún nombre `username`.
  F36  graph.py usaba json.dumps al cerrar CADA fase sin importar json; el
       NameError caía dentro del try/except de la compactación y se tragaba
       en silencio: la compactación de resúmenes (economía del token, cap.
       3.2 del blueprint) jamás se ejecutó. Test: el módulo expone json y el
       NameError ya no es posible.
  Guarda sistémica: pyflakes (si está instalado) no reporta NINGÚN
  "undefined name" en el código Python de la plataforma.
"""
from __future__ import annotations

import ast
import io
import sys
import types
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from integraciones import ldap as ldap_mod  # noqa: E402
from orchestrator import ad as ad_mod  # noqa: E402
from orchestrator import graph as graph_mod  # noqa: E402
from orchestrator.models import ROEPolitica  # noqa: E402

RAIZ_PLATAFORMA = Path(__file__).resolve().parents[1]


# ---------------------------------------------------------------------------
# utilidades: ROE mínimo y módulos simulados para ejercitar asrep sin red
# ---------------------------------------------------------------------------

def _roe() -> ROEPolitica:
    return ROEPolitica.model_validate({
        "engagement_id": "caso_z3_s6", "cliente": "acme",
        "alcance_dominios": ["cliente.com"],
        "alcance_cidrs": ["10.20.0.0/24"],
    })


class _PrincipalFalso:
    def __init__(self, nombre: str, type: int = 0):  # noqa: A002 (API impacket)
        self.nombre = nombre
        self.components = (nombre,)


class _KerberosErrorFalso(Exception):
    def getErrorCode(self) -> int:  # noqa: N802 (API impacket)
        return 0


class _AS_REQ_Falso:
    """Suficiente para el flujo de asrep(): req-body dict-able."""

    def __init__(self) -> None:
        self._campos: dict = {"req-body": {}}

    def __getitem__(self, clave):
        return self._campos[clave]

    def __setitem__(self, clave, valor) -> None:
        self._campos[clave] = valor


def _montar_modulos_simulados() -> None:
    """Inyecta un árbol impacket/pyasn1 mínimo en sys.modules.

    Objetivo: que los imports DENTRO de asrep() resuelvan y el flujo llegue
    a la línea del bug F34 y al bucle de cuentas. sendReceive falso eleva
    RuntimeError (genérico) → cada cuenta cae en errores_honestos, que es
    exactamente el comportamiento honesto sin un KDC real.
    La limpieza la hace el fixture `modulos_simulados` (yield + finally).
    """
    def _modulo(nombre: str, **atributos):
        mod = types.ModuleType(nombre)
        for clave, valor in atributos.items():
            setattr(mod, clave, valor)
        sys.modules[nombre] = mod
        return mod

    constants = _modulo(
        "impacket.krb5.constants",
        PrincipalNameType=types.SimpleNamespace(
            NT_PRINCIPAL=1, NT_SRV_INST=2),
        encodeFlags=lambda banderas: list(banderas),
        KDC_OPT_FORWARDABLE=0x40000000, KDC_OPT_RENEWABLE=0x08000000,
        KDC_OPT_CAN_POSTDATE=0x00000010, KDC_ERR_PREAUTH_REQUIRED=25,
    )
    krb5 = _modulo("impacket.krb5")
    krb5.constants = constants
    impacket = _modulo("impacket")
    impacket.krb5 = krb5

    _modulo("impacket.krb5.asn1", AS_REQ=_AS_REQ_Falso, AS_REP=type("AS_REP", (), {}))
    _modulo("impacket.krb5.kerberosv5",
            sendReceive=lambda *a, **k: (_ for _ in ()).throw(
                RuntimeError("sin KDC real en la auditoría")),
            KerberosError=_KerberosErrorFalso)
    _modulo("impacket.krb5.types",
            Principal=_PrincipalFalso,
            KerberosTime=types.SimpleNamespace(
                to_asn1=lambda dt: dt.isoformat()))
    _modulo("pyasn1.codec.ber",
            decoder=types.SimpleNamespace(decode=lambda *a, **k: (None, None)),
            encoder=types.SimpleNamespace(encode=lambda *a, **k: b""))
    sys.modules.setdefault("pyasn1.codec", types.ModuleType("pyasn1.codec"))
    sys.modules.setdefault("pyasn1", types.ModuleType("pyasn1"))


@pytest.fixture
def modulos_simulados():
    _montar_modulos_simulados()
    try:
        yield
    finally:
        for nombre in list(sys.modules):
            if nombre == "impacket" or nombre.startswith(("impacket.", "pyasn1")):
                sys.modules.pop(nombre, None)


@pytest.fixture
def entorno_asrep(monkeypatch, modulos_simulados):
    monkeypatch.setenv("LDAP_HOST", "10.20.0.10")
    monkeypatch.setenv("LDAP_BIND_DN", "ORQUESTA\\consulta")
    monkeypatch.setenv("LDAP_BIND_CLAVE", "clave-de-lectura-ro")
    monkeypatch.setenv("LDAP_BASE_DN", "DC=acme,DC=local")
    # El DC responde con UNA cuenta sin preauth: el flujo debe llegar al
    # bucle de roasting (donde vivía el NameError de F34).
    monkeypatch.setattr(
        ldap_mod, "enumerar",
        lambda modo: {"conectado": True,
                      "cuentas_sin_preautenticacion": [
                          {"sAMAccountName": "svc-backup"}]},
    )


# ---------------------------------------------------------------------------
# F34 — asrep() completa sin NameError aunque haya cuentas roastables
# ---------------------------------------------------------------------------

def test_f34_asrep_sin_nameerror_con_cuentas(entorno_asrep):
    """Con cuentas sin preauth el flujo alcanzaba _enctype_table (F34) y
    moría con NameError fuera de todo try. Ahora la corrida completa:
    conectado=True y cada cuenta termina en errores_honestos (KDC simulado
    caído) — jamás una excepción."""
    resultado = ad_mod.asrep("10.20.0.10", roe=_roe())
    assert resultado["conectado"] is True
    assert resultado["total"] == 0  # KDC simulado no entregó AS_REP válidos
    assert "svc-backup" in " ".join(resultado["errores_honestos"])


def test_f34_asrep_sin_cuentas_sigue_siendo_honesto(monkeypatch, modulos_simulados):
    """Sin cuentas sin preauth la herramienta sigue devolviendo el resultado
    honesto (regresión de guarda: el fix F34 no debe alterar ese camino)."""
    monkeypatch.setenv("LDAP_HOST", "10.20.0.10")
    monkeypatch.setenv("LDAP_BIND_DN", "ORQUESTA\\consulta")
    monkeypatch.setenv("LDAP_BIND_CLAVE", "clave-de-lectura-ro")
    monkeypatch.setenv("LDAP_BASE_DN", "DC=acme,DC=local")
    monkeypatch.setattr(ldap_mod, "enumerar",
                        lambda modo: {"conectado": True,
                                      "cuentas_sin_preautenticacion": []})
    resultado = ad_mod.asrep("10.20.0.10", roe=_roe())
    assert resultado["conectado"] is True
    assert resultado["hashes"] == []
    assert "sin preautenticaci" in resultado["nota"] or "sin preautenticación" in resultado["nota"]


# ---------------------------------------------------------------------------
# F35 — el AST de dcsync no carga ningún nombre `username`
# ---------------------------------------------------------------------------

def test_f35_dcsync_sin_nombre_username_en_ast():
    """dcsync() usaba `username` (inexistente) en la llamada SMBTransport:
    NameError tras el login SMB, enmascarado por el except genérico. El AST
    excluye comentarios por diseño: cualquier carga del nombre `username`
    dentro de la función hace fallar este test."""
    arbol = ast.parse((RAIZ_PLATAFORMA / "orchestrator" / "ad.py")
                      .read_text(encoding="utf-8"))
    dcsync = next(
        nodo for nodo in ast.walk(arbol)
        if isinstance(nodo, ast.FunctionDef) and nodo.name == "dcsync")
    cargas = [n.id for n in ast.walk(dcsync)
              if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)]
    assert "username" not in cargas, (
        "dcsync() vuelve a referenciar un nombre inexistente: la variable "
        "del ámbito es `usuario` (F35)")


# ---------------------------------------------------------------------------
# F36 — graph.py expone json (la compactación de fases puede ejecutarse)
# ---------------------------------------------------------------------------

def test_f36_graph_expone_json():
    """graph.py llamaba json.dumps al cerrar cada fase sin importar json:
    el NameError caía en el try/except de la compactación y se tragaba en
    silencio (la compactación jamás se ejecutó). El módulo debe exponer el
    propio módulo json."""
    import json as json_real
    assert graph_mod.json is json_real


# ---------------------------------------------------------------------------
# Guarda sistémica — pyflakes: cero "undefined name" en la plataforma
# ---------------------------------------------------------------------------

def test_pyflakes_sin_nombres_indefinidos():
    """F34/F35/F36 comparten raíz: nombres cargados que nadie definió ni
    importó. Esta guarda sistémica corre pyflakes (si está instalado en el
    entorno de test) sobre TODO el Python de la plataforma y falla ante
    cualquier 'undefined name'. Las variables asignadas y no usadas son
    avisos de estilo y NO fallan (hay sondas estructurales deliberadas)."""
    pyflakes = pytest.importorskip("pyflakes.api")
    from pyflakes.reporter import Reporter

    objetivos = sorted(
        list((RAIZ_PLATAFORMA / "orchestrator").glob("*.py"))
        + list((RAIZ_PLATAFORMA / "orchestrator" / "agents").glob("*.py"))
        + list((RAIZ_PLATAFORMA / "integraciones").glob("*.py"))
        + list((RAIZ_PLATAFORMA / "servidores_mcp").glob("*.py"))
        + list((RAIZ_PLATAFORMA / "lab").glob("*.py"))
    )
    assert objetivos, "el barrido pyflakes no encontró ficheros"

    salida = io.StringIO()
    reportero = Reporter(salida, salida)
    # checkPath(fichero, reporter): check() espera CÓDIGO como primer
    # parámetro, no una ruta (pasar la ruta producía un análisis vacuo).
    for fichero in objetivos:
        pyflakes.checkPath(str(fichero), reportero)
    indefinidos = [linea for linea in salida.getvalue().splitlines()
                   if "undefined name" in linea]
    assert indefinidos == [], (
        "pyflakes detectó nombres indefinidos (clase de defecto F34/F35/F36): "
        + "; ".join(indefinidos))
