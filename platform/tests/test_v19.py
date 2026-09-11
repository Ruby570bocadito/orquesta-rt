"""Tests v19: grafo de plantilla REAL (LDAP) + cobertura AD ampliada.

Cubre dos huecos declarados en la auditoría de capacidades:
1. Grafo organizacional construido SOLO con relaciones que el directorio
   declara (atributo `manager`), con guardas de ciclos y honestidad sobre
   nodos raíz (manager no recogido ≠ sin manager).
2. Nuevas lecturas AD de solo lectura: empleados, AS-REP (DONT_REQ_PREAUTH),
   delegaciones, controladores de dominio y política de contraseñas. Sin
   LDAP configurado, todas devuelven requisito — jamás datos inventados.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from integraciones import ldap  # noqa: E402


_CLAVES_LDAP = ("LDAP_HOST", "LDAP_BIND_DN", "LDAP_BIND_CLAVE", "LDAP_BASE_DN")


def _sin_ldap(monkeypatch) -> None:
    for clave in _CLAVES_LDAP:
        monkeypatch.delenv(clave, raising=False)


# ---------------------------------------------------------------- honestidad


def test_nuevos_tipos_sin_configuracion_son_honestos(monkeypatch) -> None:
    """Sin credenciales LDAP: requisito exacto, cero plantilla inventada."""
    _sin_ldap(monkeypatch)
    for tipo in ("empleados", "asrep", "delegaciones", "dcs", "politica"):
        r = ldap.enumerar(tipo)
        assert r["conectado"] is False, tipo
        assert "LDAP" in r["error"], tipo
        assert "LDAP_HOST" in r["error"], tipo


def _conexion_falsa(monkeypatch, entradas=None):
    """Sustituye la conexión por una que registra consultas (sin red)."""
    consultas: list[tuple[str, str, list[str]]] = []

    class _Conn:
        entries: list = entradas or []

        def search(self, base, filtro, attributes=None):  # noqa: ANN001
            consultas.append((base, filtro, list(attributes or [])))

        def unbind(self):
            pass

    conn = _Conn()
    monkeypatch.setattr(ldap, "_conexion", lambda: (conn, "DC=test,DC=local"))
    return conn, consultas


def test_asrep_delegaciones_dcs_usan_filtro_extensible_uac(monkeypatch) -> None:
    """Las lecturas UAC emplean el match extensible estándar de AD (1.2.840
    .113556.1.4.803) — contrato de solo lectura contra el DC real."""
    for tipo, bit in (("asrep", "4194304"), ("delegaciones", "524288"),
                      ("dcs", "8192")):
        _, consultas = _conexion_falsa(monkeypatch)
        r = ldap.enumerar(tipo)
        assert r["conectado"] is True, tipo
        assert consultas, tipo
        assert any(
            f"1.2.840.113556.1.4.803:={bit}" in filtro
            for _, filtro, _ in consultas
        ), (tipo, consultas)


def test_empleados_pide_atributos_de_persona(monkeypatch) -> None:
    """La consulta de plantilla pide manager/cargo/departamento explícitos."""
    _, consultas = _conexion_falsa(monkeypatch)
    r = ldap.enumerar("empleados")
    assert r["conectado"] is True
    _, _, atributos = consultas[0]
    for esperado in ("sAMAccountName", "displayName", "mail", "title",
                     "department", "manager", "distinguishedName"):
        assert esperado in atributos, esperado


def test_politica_dominio_sin_filas_devuelve_estructura_honesta(monkeypatch) -> None:
    conn, _ = _conexion_falsa(monkeypatch)
    r = ldap.enumerar("politica")
    assert r["conectado"] is True
    assert r["politica"]["longitud_minima"] is None
    assert r["politica"]["umbral_bloqueo"] is None


# ------------------------------------------------------- grafo de plantilla


def _fila(cuenta, dn, manager="", nombre="", cargo="", depto="", correo=""):
    return {"sAMAccountName": cuenta, "distinguishedName": dn,
            "manager": manager, "displayName": nombre or cuenta,
            "title": cargo, "department": depto, "mail": correo}


def test_grafo_resuelve_cadena_de_mando_por_dn() -> None:
    filas = [
        _fila("jefe", "CN=jefe,OU=Dire,DC=test,DC=local",
              cargo="CEO", depto="Dirección"),
        _fila("mm1", "CN=mm1,OU=IT,DC=test,DC=local",
              manager="CN=jefe,OU=Dire,DC=test,DC=local",
              cargo="Manager IT", depto="IT"),
        _fila("dev1", "CN=dev1,OU=IT,DC=test,DC=local",
              manager="CN=mm1,OU=IT,DC=test,DC=local",
              cargo="Developer", depto="IT"),
    ]
    g = ldap.construir_grafo_empleados(filas)
    assert g["resumen"]["total"] == 3
    assert g["resumen"]["con_manager"] == 2
    assert g["resumen"]["raices"] == 1
    assert g["resumen"]["profundidad"] == 3
    niveles = {n["cuenta"]: n["nivel"] for n in g["nodos"]}
    assert niveles == {"jefe": 0, "mm1": 1, "dev1": 2}
    assert {"de": "jefe", "a": "mm1"} in g["aristas"]
    assert {"de": "mm1", "a": "dev1"} in g["aristas"]
    assert g["departamentos"] == {"IT": 2, "Dirección": 1}


def test_grafo_manager_fuera_de_conjunto_es_raiz_honesto() -> None:
    filas = [
        _fila("a", "CN=a,DC=test,DC=local",
              manager="CN=no_recogido,DC=otro,DC=local"),
        _fila("b", "CN=b,DC=test,DC=local"),
    ]
    g = ldap.construir_grafo_empleados(filas)
    assert g["resumen"]["con_manager"] == 0
    assert g["resumen"]["raices"] == 2
    assert g["aristas"] == []


def test_grafo_ciclo_no_cuelga_y_corta_honesto() -> None:
    filas = [
        _fila("a", "CN=a,DC=t,DC=l", manager="CN=b,DC=t,DC=l"),
        _fila("b", "CN=b,DC=t,DC=l", manager="CN=a,DC=t,DC=l"),
        _fila("c", "CN=c,DC=t,DC=l", manager="CN=b,DC=t,DC=l"),
    ]
    g = ldap.construir_grafo_empleados(filas)  # no debe recursar infinito
    assert g["resumen"]["total"] == 3
    # la cadena c→b→a se corta en el ciclo: niveles acotados, sin crash
    niveles = {n["cuenta"]: n["nivel"] for n in g["nodos"]}
    assert set(niveles) == {"a", "b", "c"}


def test_grafo_autociclo_se_ignora() -> None:
    filas = [_fila("a", "CN=a,DC=t,DC=l", manager="CN=a,DC=t,DC=l")]
    g = ldap.construir_grafo_empleados(filas)
    assert g["nodos"][0]["manager"] is None
    assert g["aristas"] == []


def test_grafo_vacio_y_objetos_sin_cuenta_son_honestos() -> None:
    g = ldap.construir_grafo_empleados([])
    assert g["resumen"]["total"] == 0
    assert g["resumen"]["profundidad"] == 0
    assert g["nodos"] == [] and g["aristas"] == []
    # objetos sin sAMAccountName se descartan (no son personas)
    g2 = ldap.construir_grafo_empleados(
        [{"distinguishedName": "CN=Equipo,OU=Grupos,DC=t,DC=l"}])
    assert g2["resumen"]["total"] == 0


def test_grafo_respaldo_cn_para_manager_sin_dn_exacto() -> None:
    # el DN del manager llega con formato distinto al DN devuelto del nodo:
    # el respaldo por CN debe seguir resolviendo la relación declarada
    filas = [
        _fila("jefe", "CN=jefe,OU=Dire,DC=test,DC=local"),
        _fila("sub", "CN=sub,OU=IT,DC=test,DC=local",
              manager="CN=Jefe,OU=Dire,DC=OTRO,DC=local"),
    ]
    g = ldap.construir_grafo_empleados(filas)
    assert g["nodos"][1]["manager"] == "jefe"
    assert g["aristas"] == [{"de": "jefe", "a": "sub"}]


# ------------------------------------------------------------- conversión


def test_filetime_a_dias() -> None:
    # -8.64e12 (100 ns) = 10 días exactos de caducidad de contraseña
    assert ldap._filetime_a_dias(-8_640_000_000_000) == 10.0
    assert ldap._filetime_a_dias(-864_000_000_000) == 1.0
    assert ldap._filetime_a_dias("no-numérico") is None
    assert ldap._filetime_a_dias(None) is None
