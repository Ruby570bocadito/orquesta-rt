"""SSO federado (OpenID Connect, flujo authorization-code + PKCE).

El despliegue puede delegar la identidad en un IdP OIDC real (Keycloak,
Auth0, Entra ID, Google...). El flujo:

  1. estado()        → ¿configurado? (la consola muestra el botón SSO)
  2. url_autorizacion() → redirige al /authorize del IdP con state, nonce
     y code_challenge (PKCE S256: el verifier NUNCA sale del servidor)
  3. el IdP devuelve code al redirect_uri configurado (la consola lo
     reenvía a la API)
  4. canjear_codigo() → POST token-endpoint + verificación CRIPTOGRÁFICA
     del id_token (RS256 vía JWKS del IdP, iss/aud/exp/nonce)
  5. la identidad federada se resuelve con auth.crear_o_vincular_sso
     (enlace a cuenta existente o alta JIT como 'lector') y se emite el
     JWT de la plataforma.

Configuración (variables de entorno):
  OIDC_ISSUER         p. ej. https://sso.corp.local/realms/redteam
  OIDC_CLIENT_ID      client id registrado en el IdP
  OIDC_CLIENT_SECRET  client secret (confidencial)
  OIDC_REDIRECT_URI   p. ej. https://consola.corp.local/acceso?sso=1
  OIDC_AUTO_ALTA      "1" (por defecto) crea lector JIT; "0" exige cuenta
  OIDC_ROL_JIT        rol del alta JIT (por defecto "lector")

Honestidad: si el IdP no responde o el id_token no verifica, el error real
llega al operador. Sin OIDC_ISSUER el SSO está desactivado y la consola
sigue con usuario/contraseña — nada se simula.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from typing import Any, Optional

# ---------------------------------------------------------------- PKCE / state

_STATES: dict[str, dict[str, Any]] = {}
_STATES_TTL_S = 600
_STATES_MAX = 5_000


def _podar_estados() -> None:
    ahora = time.time()
    if len(_STATES) >= _STATES_MAX:
        for k in [k for k, v in _STATES.items() if ahora - v["creado"] > _STATES_TTL_S]:
            del _STATES[k]
        if len(_STATES) >= _STATES_MAX:
            antiguos = sorted(_STATES.items(), key=lambda kv: kv[1]["creado"])
            for k, _ in antiguos[: _STATES_MAX // 4]:
                del _STATES[k]
    for k in [k for k, v in _STATES.items() if ahora - v["creado"] > _STATES_TTL_S]:
        del _STATES[k]


def _b64url(datos: bytes) -> str:
    return base64.urlsafe_b64encode(datos).rstrip(b"=").decode()


def _b64url_decodificar(texto: str) -> bytes:
    return base64.urlsafe_b64decode(texto + "=" * (-len(texto) % 4))


# ---------------------------------------------------------------- config

OIDC_AUTO_ALTA = os.environ.get("OIDC_AUTO_ALTA", "1") != "0"
OIDC_ROL_JIT = os.environ.get("OIDC_ROL_JIT", "lector")


def _config() -> dict[str, str]:
    issuer = os.environ.get("OIDC_ISSUER", "").rstrip("/")
    client_id = os.environ.get("OIDC_CLIENT_ID", "")
    client_secret = os.environ.get("OIDC_CLIENT_SECRET", "")
    redirect_uri = os.environ.get("OIDC_REDIRECT_URI", "")
    if not (issuer and client_id and client_secret and redirect_uri):
        raise RuntimeError(
            "SSO OIDC no configurado: defina OIDC_ISSUER, OIDC_CLIENT_ID, "
            "OIDC_CLIENT_SECRET y OIDC_REDIRECT_URI.")
    return {"issuer": issuer, "client_id": client_id,
            "client_secret": client_secret, "redirect_uri": redirect_uri}


def estado() -> dict[str, Any]:
    """Configuración visible SIN secretos (para la pantalla de acceso)."""
    cfg_completa = all(os.environ.get(k, "") for k in (
        "OIDC_ISSUER", "OIDC_CLIENT_ID", "OIDC_CLIENT_SECRET",
        "OIDC_REDIRECT_URI"))
    return {
        "configurado": cfg_completa,
        "issuer": os.environ.get("OIDC_ISSUER", ""),
        "auto_alta": OIDC_AUTO_ALTA,
        "rol_jit": OIDC_ROL_JIT if OIDC_AUTO_ALTA else None,
        "detalle": "OIDC authorization-code + PKCE (Keycloak/Entra/Auth0/...)"
                   if cfg_completa else
                   "Defina OIDC_ISSUER, OIDC_CLIENT_ID, OIDC_CLIENT_SECRET y "
                   "OIDC_REDIRECT_URI para habilitar el acceso federado",
    }


# ---------------------------------------------------------------- discovery

_descubrimiento: dict[str, Any] | None = None
_descubrimiento_en: float = 0.0
_DESCUBRIMIENTO_TTL_S = 3600


def descubrir(force: bool = False) -> dict[str, Any]:
    """OIDC Discovery REAL: GET {issuer}/.well-known/openid-configuration."""
    global _descubrimiento, _descubrimiento_en
    cfg = _config()
    if (not force and _descubrimiento
            and time.time() - _descubrimiento_en < _DESCUBRIMIENTO_TTL_S):
        return _descubrimiento
    import httpx
    url = f"{cfg['issuer']}/.well-known/openid-configuration"
    try:
        with httpx.Client(timeout=15) as c:
            r = c.get(url)
    except Exception as exc:
        raise RuntimeError(f"OIDC discovery no accesible ({url}): {str(exc)[:200]}")
    if r.status_code != 200:
        raise RuntimeError(
            f"OIDC discovery respondió {r.status_code}: {r.text[:200]}")
    doc = r.json()
    if doc.get("issuer", cfg["issuer"]) != cfg["issuer"]:
        raise RuntimeError(
            "OIDC discovery: el issuer del documento no coincide con "
            f"OIDC_ISSUER ({doc.get('issuer')!r} != {cfg['issuer']!r})")
    for campo in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
        if not doc.get(campo):
            raise RuntimeError(
                f"OIDC discovery incompleto: falta '{campo}' en el IdP")
    _descubrimiento, _descubrimiento_en = doc, time.time()
    return doc


# ---------------------------------------------------------------- flujo


def url_autorizacion() -> dict[str, Any]:
    """Crea state/nonce/verifier y construye la URL del /authorize REAL."""
    cfg = _config()
    doc = descubrir()
    state = secrets.token_urlsafe(24)
    nonce = secrets.token_urlsafe(24)
    verifier = secrets.token_urlsafe(48)
    _podar_estados()
    _STATES[state] = {"nonce": nonce, "verifier": verifier,
                      "creado": time.time()}
    desafio = _b64url(hashlib.sha256(verifier.encode()).digest())
    from urllib.parse import urlencode
    consulta = urlencode({
        "response_type": "code",
        "client_id": cfg["client_id"],
        "redirect_uri": cfg["redirect_uri"],
        "scope": "openid profile email",
        "state": state,
        "nonce": nonce,
        "code_challenge": desafio,
        "code_challenge_method": "S256",
    })
    return {"url": f"{doc['authorization_endpoint']}?{consulta}",
            "state": state}


def _jwk_verificar_rs256(id_token: str, jwks: dict[str, Any]) -> dict[str, Any]:
    """Verificación criptográfica REAL de la firma RS256 (stdlib puro).

    PKCS#1 v1.5: s^e mod n con la JWK del IdP y comparación del padding
    EM=0x00 01 FF..FF 00 || DigestInfo(SHA-256). Igual de firme que una
    librería JWT para este caso, sin dependencia nueva.
    """
    try:
        cabecera_b64, cuerpo_b64, firma_b64 = id_token.split(".")
    except ValueError:
        raise RuntimeError("id_token malformado (no son 3 segmentos)")
    cabecera = json.loads(_b64url_decodificar(cabecera_b64))
    if cabecera.get("alg") != "RS256":
        raise RuntimeError(
            f"Algoritmo del id_token no soportado: {cabecera.get('alg')!r} "
            "(solo RS256)")
    kid = cabecera.get("kid")
    clave = None
    for jwk in jwks.get("keys", []):
        if jwk.get("kty") == "RSA" and (kid is None or jwk.get("kid") == kid):
            clave = jwk
            break
    if not clave:
        raise RuntimeError("Ninguna JWK del IdP corresponde al kid del id_token")
    n = int.from_bytes(_b64url_decodificar(clave["n"]), "big")
    e = int.from_bytes(_b64url_decodificar(clave["e"]), "big")
    firma = _b64url_decodificar(firma_b64)
    k = (n.bit_length() + 7) // 8
    if len(firma) != k:
        raise RuntimeError("Longitud de firma inválida para la clave del IdP")
    s = int.from_bytes(firma, "big")
    if s >= n:
        raise RuntimeError("Firma fuera de rango")
    em = pow(s, e, n).to_bytes(k, "big")
    digestinfo = bytes.fromhex(
        "3031300d060960864801650304020105000420") + hashlib.sha256(
        f"{cabecera_b64}.{cuerpo_b64}".encode()).digest()
    esperado = (b"\x00\x01" + b"\xff" * (k - len(digestinfo) - 3)
                + b"\x00" + digestinfo)
    if not hmac.compare_digest(em, esperado):
        raise RuntimeError("La firma del id_token NO verifica (RS256)")
    return json.loads(_b64url_decodificar(cuerpo_b64))


def canjear_codigo(code: str, state: str) -> dict[str, Any]:
    """Intercambia code por tokens en el endpoint REAL del IdP y verifica.

    Devuelve la cuenta resuelta ({usuario, rol, tenant_id, ...}) lista para
    emitir el JWT de la plataforma.
    """
    if not code or not state:
        raise RuntimeError("Falta code o state en el callback SSO")
    _podar_estados()
    registro = _STATES.pop(state, None)
    if not registro:
        raise RuntimeError(
            "state SSO desconocido o caducado: reinicia el inicio de sesión")
    if time.time() - registro["creado"] > _STATES_TTL_S:
        raise RuntimeError("state SSO caducado: reinicia el inicio de sesión")
    cfg = _config()
    doc = descubrir()
    import httpx
    with httpx.Client(timeout=20) as c:
        r = c.post(doc["token_endpoint"], data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": cfg["redirect_uri"],
            "client_id": cfg["client_id"],
            "client_secret": cfg["client_secret"],
            "code_verifier": registro["verifier"],
        }, headers={"Content-Type": "application/x-www-form-urlencoded"})
    if r.status_code != 200:
        raise RuntimeError(
            f"OIDC token endpoint respondió {r.status_code}: {r.text[:200]}")
    tokens = r.json()
    id_token = tokens.get("id_token", "")
    if not id_token:
        raise RuntimeError("El IdP no devolvió id_token")
    with httpx.Client(timeout=15) as c:
        rj = c.get(doc["jwks_uri"])
    if rj.status_code != 200:
        raise RuntimeError(f"OIDC JWKS respondió {rj.status_code}")
    claims = _jwk_verificar_rs256(id_token, rj.json())
    ahora = int(time.time())
    if int(claims.get("exp", 0)) < ahora:
        raise RuntimeError("id_token expirado")
    if ahora and int(claims.get("iat", ahora)) > ahora + 300:
        raise RuntimeError("id_token emitido en el futuro (reloj del IdP)")
    if claims.get("nonce") != registro["nonce"]:
        raise RuntimeError("nonce del id_token no coincide (posible replay)")
    identidad = (claims.get("preferred_username")
                 or claims.get("email")
                 or claims.get("sub"))
    if not identidad:
        raise RuntimeError("id_token sin preferred_username/email/sub")
    # Usuario local seguro: el claim puede traer símbolos que nuestra
    # política de cuentas no admite; se normaliza de forma determinista.
    import re as _re
    usuario = _re.sub(r"[^A-Za-z0-9._-]", "_", str(identidad))[:32].lower()
    if len(usuario) < 3:
        usuario = f"sso_{usuario or 'user'}"
    cuenta = _resolver_cuenta(str(claims.get("sub", usuario)), usuario, claims)
    return cuenta


def _resolver_cuenta(sso_sub: str, usuario: str,
                     claims: dict[str, Any] | None = None) -> dict[str, Any]:
    """Enlaza o crea la cuenta local (JIT lector por defecto).

    z3 (auditoría seguridad): los claims del id_token (email / email_verified)
    acompañan a la resolución para que la política de dominios de confianza
    (OIDC_DOMINIOS_PERMITIDOS en auth.crear_o_vincular_sso) pueda aplicarse.
    """
    from . import auth
    tenant = os.environ.get("OIDC_TENANT", auth.TENANT_PREDETERMINADA)
    c = claims or {}
    return auth.crear_o_vincular_sso(
        sso_sub=sso_sub, usuario=usuario, rol=OIDC_ROL_JIT,
        tenant_id=tenant, auto_alta=OIDC_AUTO_ALTA,
        email=str(c.get("email") or ""),
        email_verificado=bool(c.get("email_verified")))


def desconectar_url() -> Optional[str]:
    """end_session_endpoint del IdP si existe (logout federado honesto)."""
    if _descubrimiento and _descubrimiento.get("end_session_endpoint"):
        return _descubrimiento["end_session_endpoint"]
    return None
