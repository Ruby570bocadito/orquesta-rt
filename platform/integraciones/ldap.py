"""Cliente REAL de LDAP / Active Directory (protocolo LDAP v3).

Fase F4 (rutas hacia Domain Admin) necesita datos REALES del directorio:
usuarios, grupos, SPNs, delegaciones. Este módulo consulta el controlador
de dominio dentro del alcance del ROE con `ldap3` (cliente LDAP estándar).
El operador aporta credenciales de lectura — obtenidas en fases previas
del engagement autorizado — y el boundary clasifica cada consulta.

Configuración (variables de entorno del backend):
  LDAP_HOST      host del DC (debe estar dentro del alcance del ROE)
  LDAP_PUERTO    389 (ldap) o 636 (ldaps) — por defecto 389
  LDAP_SSL       "1" para ldaps
  LDAP_BIND_DN   usuario de bind (p. ej. ORQUESTA\\consulta o DN completo)
  LDAP_BIND_CLAVE  contraseña del bind
  LDAP_BASE_DN   base de búsqueda (p. ej. DC=acme,DC=local)

Sin credenciales NO se inventan rutas AD: se documenta el requisito.
"""
from __future__ import annotations

import os
import re
from collections import Counter
from typing import Any


def _config() -> dict[str, Any]:
    host = os.environ.get("LDAP_HOST", "")
    bind_dn = os.environ.get("LDAP_BIND_DN", "")
    clave = os.environ.get("LDAP_BIND_CLAVE", "")
    base = os.environ.get("LDAP_BASE_DN", "")
    if not (host and bind_dn and clave and base):
        raise RuntimeError(
            "LDAP no configurado: defina LDAP_HOST, LDAP_BIND_DN, "
            "LDAP_BIND_CLAVE y LDAP_BASE_DN con credenciales de lectura "
            "obtenidas bajo el ROE del engagement.")
    return {"host": host, "puerto": int(os.environ.get("LDAP_PUERTO", "389")),
            "ssl": os.environ.get("LDAP_SSL", "") == "1",
            "bind_dn": bind_dn, "clave": clave, "base": base}


def _conexion():
    from ldap3 import Connection, Server
    cfg = _config()
    servidor = Server(cfg["host"], port=cfg["puerto"], use_ssl=cfg["ssl"],
                      connect_timeout=8)
    conn = Connection(servidor, user=cfg["bind_dn"], password=cfg["clave"],
                      auto_bind=True, receive_timeout=15)
    return conn, cfg["base"]


def _filtrar_filas(entradas) -> list[dict[str, Any]]:
    salida: list[dict[str, Any]] = []
    for e in entradas:
        fila: dict[str, Any] = {}
        for atributo in e.entry_attributes:
            valor = e[atributo].value
            fila[atributo] = (valor if isinstance(valor, (str, int, list))
                              else str(valor))
        salida.append(fila)
    return salida


def _filetime_a_dias(valor: Any) -> float | None:
    """Convierte un intervalo FILETIME (100 ns, firmado negativo) a días."""
    try:
        n = int(str(valor))
    except (TypeError, ValueError):
        return None
    return round(abs(n) / 864_000_000_000, 2)


def construir_grafo_empleados(filas: list[dict[str, Any]]) -> dict[str, Any]:
    """Grafo organizacional REAL a partir de filas LDAP de personas.

    Solo relaciones que el directorio realmente declara (atributo `manager`);
    ninguna arista se deduce por heurística de nombres. Un empleado cuyo
    manager no está en el conjunto recogido queda como raíz: también es
    información honesta (la relación existe, pero no fue leída del DC).
    """
    nodos: list[dict[str, Any]] = []
    por_dn: dict[str, dict[str, Any]] = {}
    for f in filas:
        cuenta = str(f.get("sAMAccountName") or "").strip()
        if not cuenta:
            continue  # objeto sin cuenta: no es una persona del directorio
        dn = str(f.get("distinguishedName") or "").strip()
        nodo: dict[str, Any] = {
            "cuenta": cuenta,
            "nombre": str(f.get("displayName") or cuenta).strip(),
            "cargo": str(f.get("title") or "").strip(),
            "departamento": str(f.get("department") or "").strip()
                            or "sin departamento",
            "correo": str(f.get("mail") or "").strip(),
            "manager_dn": str(f.get("manager") or "").strip(),
        }
        nodos.append(nodo)
        if dn:
            por_dn[dn.lower()] = nodo

    def _resolver(dn: str) -> str | None:
        """DN del manager → cuenta. DN exacto primero, CN como respaldo."""
        if not dn:
            return None
        hit = por_dn.get(dn.lower())
        if hit:
            return hit["cuenta"]
        m = re.match(r"^CN=([^,]+)", dn, re.IGNORECASE)
        if m:
            cn = m.group(1).strip().lower()
            for n in nodos:
                if n["cuenta"].lower() == cn or n["nombre"].lower() == cn:
                    return n["cuenta"]
        return None

    for n in nodos:
        n["manager"] = _resolver(n.pop("manager_dn"))
        if n["manager"] == n["cuenta"]:
            n["manager"] = None  # autociclo del directorio: se ignora

    # Nivel = profundidad desde una raíz (sin manager resuelto). La guarda
    # de ciclos corta cadenas corruptas del directorio en lugar de colgar.
    nivel_de: dict[str, int] = {}

    def _nivel(cuenta: str, vistos: frozenset[str] = frozenset()) -> int:
        if cuenta in nivel_de:
            return nivel_de[cuenta]
        if cuenta in vistos or len(vistos) > 64:
            return 0
        nodo = next((n for n in nodos if n["cuenta"] == cuenta), None)
        if nodo is None or not nodo["manager"]:
            return 0
        return 1 + _nivel(nodo["manager"], vistos | {cuenta})

    for n in nodos:
        n["nivel"] = _nivel(n["cuenta"])
        nivel_de[n["cuenta"]] = n["nivel"]

    departamentos = Counter(n["departamento"] for n in nodos)
    con_manager = sum(1 for n in nodos if n["manager"])
    return {
        "nodos": nodos,
        "aristas": [{"de": n["manager"], "a": n["cuenta"]}
                    for n in nodos if n["manager"]],
        "departamentos": dict(departamentos.most_common()),
        "resumen": {
            "total": len(nodos),
            "con_manager": con_manager,
            "raices": len(nodos) - con_manager,
            "profundidad": (max(nivel_de.values()) + 1) if nivel_de else 0,
        },
    }


def enumerar(tipo: str = "resumen") -> dict[str, Any]:
    """Consulta REAL al directorio: personas, cuentas, SPNs y configuración.

    tipo:
      resumen      → dominio, unidades organizativas y contadores
      empleados    → plantilla real (cargo, departamento, manager) + grafo
      usuarios     → cuentas (sAMAccountName, memberOf, pwdLastSet)
      spns         → cuentas con servicePrincipalName (candidatas a Kerberoasting)
      asrep        → cuentas sin preautenticación Kerberos (DONT_REQ_PREAUTH)
      delegaciones → delegación sin restricción y restringida (msDS-AllowedToDelegateTo)
      dcs          → controladores de dominio (SERVER_TRUST_ACCOUNT)
      politica     → política de contraseñas y bloqueo del dominio
      grupos       → grupos y miembros de interés (DA, admins)
      laps         → contraseñas locales de máquina (ms-Mcs-AdmPwd)
      gmsa         → cuentas de servicio gestionadas por grupo
      trusts       → relaciones de confianza del dominio
    """
    try:
        conn, base = _conexion()
        try:
            if tipo == "usuarios":
                conn.search(base, "(sAMAccountType=805306368)",
                            attributes=["sAMAccountName", "displayName",
                                        "memberOf", "pwdLastSet",
                                        "lastLogonTimestamp", "description"])
                return {"conectado": True, "tipo": "usuarios",
                        "usuarios": _filtrar_filas(conn.entries)[:400]}
            if tipo == "spns":
                conn.search(base, "(servicePrincipalName=*)",
                            attributes=["sAMAccountName",
                                        "servicePrincipalName", "memberOf"])
                return {"conectado": True, "tipo": "spns",
                        "candidatas_kerberoast": _filtrar_filas(conn.entries)[:200]}
            if tipo == "empleados":
                conn.search(base, "(sAMAccountType=805306368)",
                            attributes=["sAMAccountName", "displayName",
                                        "mail", "title", "department",
                                        "manager", "distinguishedName"])
                filas = _filtrar_filas(conn.entries)[:600]
                return {"conectado": True, "tipo": "empleados",
                        "base_dn": base, **construir_grafo_empleados(filas)}
            if tipo == "asrep":
                conn.search(base,
                            "(&(sAMAccountType=805306368)"
                            "(userAccountControl:1.2.840.113556.1.4.803:=4194304))",
                            attributes=["sAMAccountName", "description"])
                return {"conectado": True, "tipo": "asrep", "base_dn": base,
                        "cuentas_sin_preautenticacion":
                            _filtrar_filas(conn.entries)[:200],
                        "nota": "cuentas con DONT_REQ_PREAUTH leídas del DC: "
                                "hallazgo estándar de auditoría de directorio"}
            if tipo == "delegaciones":
                conn.search(base,
                            "(userAccountControl:1.2.840.113556.1.4.803:=524288)",
                            attributes=["sAMAccountName"])
                sin_restriccion = _filtrar_filas(conn.entries)[:100]
                conn.search(base, "(msDS-AllowedToDelegateTo=*)",
                            attributes=["sAMAccountName",
                                        "msDS-AllowedToDelegateTo"])
                return {"conectado": True, "tipo": "delegaciones",
                        "base_dn": base,
                        "delegacion_sin_restriccion": sin_restriccion,
                        "delegacion_restringida":
                            _filtrar_filas(conn.entries)[:100],
                        "nota": "delegaciones activas declaradas por el "
                                "directorio: superficie de escalada a auditar"}
            if tipo == "dcs":
                conn.search(base,
                            "(userAccountControl:1.2.840.113556.1.4.803:=8192)",
                            attributes=["sAMAccountName", "dNSHostName",
                                        "operatingSystem"])
                return {"conectado": True, "tipo": "dcs", "base_dn": base,
                        "controladores": _filtrar_filas(conn.entries)[:50]}
            if tipo == "politica":
                conn.search(base, "(objectClass=domain)",
                            attributes=["maxPwdAge", "minPwdAge", "minPwdLength",
                                        "pwdHistoryLength", "pwdProperties",
                                        "lockoutThreshold", "lockoutDuration",
                                        "lockoutObservedWindow"])
                filas_pol = _filtrar_filas(conn.entries)
                dominio = filas_pol[0] if filas_pol else {}

                def _minutos(clave: str) -> float | None:
                    dias = _filetime_a_dias(dominio.get(clave))
                    return round(dias * 1440, 1) if dias is not None else None

                politica = {
                    "duracion_maxima_contrasena_dias":
                        _filetime_a_dias(dominio.get("maxPwdAge")),
                    "duracion_minima_contrasena_dias":
                        _filetime_a_dias(dominio.get("minPwdAge")),
                    "longitud_minima": dominio.get("minPwdLength"),
                    "historial": dominio.get("pwdHistoryLength"),
                    "umbral_bloqueo": dominio.get("lockoutThreshold"),
                    "duracion_bloqueo_min": _minutos("lockoutDuration"),
                    "ventana_bloqueo_min": _minutos("lockoutObservedWindow"),
                }
                return {"conectado": True, "tipo": "politica", "base_dn": base,
                        "politica": politica}
            if tipo == "grupos":
                conn.search(base, "(objectCategory=group)",
                            attributes=["cn", "member", "description"])
                grupos = _filtrar_filas(conn.entries)
                interes = [g for g in grupos if any(
                    k in str(g.get("cn", "")).lower()
                    for k in ("admin", "da-", "domain admins", "helpdesk",
                              "operators", "schema"))][:100]
                return {"conectado": True, "tipo": "grupos",
                        "total_grupos": len(grupos), "grupos_interes": interes}
            if tipo == "laps":
                # LAPS: contraseñas locales de máquina gestionadas por el
                # dominio. Leer ms-Mcs-AdmPwd exige que el bind tenga permiso:
                # si el DC lo deniega se reporta el hecho, no un vacío falso.
                conn.search(base, "(ms-Mcs-AdmPwd=*)",
                            attributes=["sAMAccountName", "ms-Mcs-AdmPwd",
                                        "ms-Mcs-AdmPwdExpirationTime"])
                filas = _filtrar_filas(conn.entries)
                return {"conectado": True, "tipo": "laps", "base_dn": base,
                        "equipos_con_laps": [
                            {**f, "ms-Mcs-AdmPwd": f.get("ms-Mcs-AdmPwd", ""),
                             "nota": "contraseña local leída del DC bajo ROE"}
                            for f in filas[:200]],
                        "total": len(filas),
                        "nota": "lectura real de ms-Mcs-AdmPwd; sin LAPS "
                                "desplegado el resultado es 0 y el hallazgo "
                                "es 'sin gestión de contraseñas locales'"}
            if tipo == "gmsa":
                conn.search(base, "(objectClass=msDS-GroupManagedServiceAccount)",
                            attributes=["sAMAccountName", "description",
                                        "msDS-ManagedPasswordInterval",
                                        "principalsAllowedToRetrieveManagedPassword"])
                filas = _filtrar_filas(conn.entries)
                return {"conectado": True, "tipo": "gmsa", "base_dn": base,
                        "cuentas_gmsa": filas[:100], "total": len(filas),
                        "nota": "lectura real de gMSA; quién puede recuperar "
                                "la contraseña es superficie de escalada "
                                "(principalsAllowedToRetrieve)"}
            if tipo == "trusts":
                conn.search(base, "(objectClass=trustedDomain)",
                            attributes=["cn", "flatName", "trustDirection",
                                        "trustType", "trustAttributes"])
                filas = _filtrar_filas(conn.entries)
                return {"conectado": True, "tipo": "trusts", "base_dn": base,
                        "confianzas": filas[:50], "total": len(filas),
                        "nota": "trusts declarados por el DC; dirección y "
                                "atributos leídos del objeto trustedDomain"}
            # resumen
            conn.search(base, "(objectClass=organizationalUnit)",
                        attributes=["ou"])
            ous = [str(e.ou) for e in conn.entries][:100]
            conn.search(base, "(sAMAccountType=805306368)", attributes=["sAMAccountName"])
            n_usuarios = len(conn.entries)
            return {"conectado": True, "tipo": "resumen", "base_dn": base,
                    "unidades_organizativas": ous,
                    "usuarios_total": n_usuarios}
        finally:
            conn.unbind()
    except RuntimeError as exc:
        return {"conectado": False, "error": str(exc)}
    except Exception as exc:
        return {"conectado": False, "error": f"LDAP: {str(exc)[:220]}"}
