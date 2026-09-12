"""Autenticación de operadores: cuentas reales, JWT y control de acceso.

La consola gestiona acciones con consecuencias legales (aprobaciones ROE,
paradas de emergencia, ejecución de fases): el "operador" de cada decisión
debe ser una IDENTIDAD REAL autenticada, no un campo de formulario editable.

Diseño (sin dependencias externas, todo stdlib):
- Contraseñas con scrypt (OWASP: n=2^14, r=8, p=1, dklen=32) y salt único.
- Token JWT HS256 (RFC 7519) con expiración; secreto persistido en el
  almacén de operadores (sobrevive a reinicios del servicio).
- Almacén SQLite propio (USUARIOS_DB), separado de la memoria por caso.
- Bloqueo temporal tras fallos repetidos de login (anti fuerza bruta).
- Roles: admin (gestión del despliegue), gestor (gestión de caso en su
  organización), operador (trabajo de caso) y lector (solo lectura).
- Multi-tenant: cada cuenta pertenece a una ORGANIZACIÓN (tenant); los
  casos llevan tenant y el aislamiento se aplica en la API.
- Vinculación SSO OIDC opcional (sso_sub) para login federado.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

RUTA_DB = Path(os.environ.get("USUARIOS_DB", "usuarios.db"))

SCHEMA = """
CREATE TABLE IF NOT EXISTS operadores (
    usuario TEXT PRIMARY KEY,
    hash TEXT NOT NULL,
    rol TEXT NOT NULL DEFAULT 'operador',
    tenant_id TEXT NOT NULL DEFAULT 'predeterminada',
    sso_sub TEXT,
    creado_en TEXT NOT NULL,
    ultimo_acceso TEXT
);
CREATE TABLE IF NOT EXISTS organizaciones (
    id TEXT PRIMARY KEY,
    nombre TEXT NOT NULL,
    creado_en TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS config (
    clave TEXT PRIMARY KEY,
    valor TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS auditoria_sistema (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor TEXT NOT NULL,
    accion TEXT NOT NULL,
    detalle TEXT DEFAULT '',
    creado_en TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sso_vinculos_preaprobados (
    usuario TEXT PRIMARY KEY,
    sso_sub TEXT NOT NULL,
    creado_por TEXT NOT NULL,
    creado_en TEXT NOT NULL
);
-- v34: registro de sesiones emitidas (visibilidad de higiene, NO
-- autorización — la validez la sigue decidiendo la firma + sesion_viva).
CREATE TABLE IF NOT EXISTS sesiones (
    jti TEXT PRIMARY KEY,
    usuario TEXT NOT NULL,
    emitido_en REAL NOT NULL,
    expira_en REAL NOT NULL,
    ultima_actividad REAL NOT NULL,
    user_agent TEXT DEFAULT '',
    ip TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_sesiones_usuario ON sesiones(usuario);
"""

SCRYPT_N, SCRYPT_R, SCRYPT_P, DKLEN = 2 ** 14, 8, 1, 32
TOKEN_HORAS = float(os.environ.get("TOKEN_HORAS", "12"))
MAX_FALLOS, VENTANA_FALLOS_S, BLOQUEO_S = 5, 600, 300

TENANT_PREDETERMINADA = "predeterminada"
# Jerarquía de roles (mayor número = más privilegios):
#   lector    (1)  consulta el caso: hallazgos, evidencias, informes
#   operador  (2)  trabaja el caso: fases, arsenal, hallazgos, aprobaciones
#   gestor    (3)  gestiona el caso en su organización: crear/editar ROE
#   admin     (4)  despliegue completo: organizaciones, cuentas, cross-tenant
ROLES = ("admin", "gestor", "operador", "lector")
NIVEL_ROL = {"lector": 1, "operador": 2, "gestor": 3, "admin": 4}


def rol_nivel(rol: str) -> int:
    return NIVEL_ROL.get((rol or "").strip().lower(), 0)


def tiene_nivel(rol: str, minimo: int) -> bool:
    return rol_nivel(rol) >= minimo

# Registro en memoria de intentos fallidos: {usuario: [timestamps]}
# Con PODA: un atacante que pruebe usuarios inexistentes no puede hacer
# crecer el diccionario sin límite (las entradas caducadas se eliminan).
_intentos: dict[str, list[float]] = {}
_INTENTOS_MAX_CLAVES = 5_000


def _registrar_intento(usuario: str) -> None:
    ahora = time.time()
    if len(_intentos) >= _INTENTOS_MAX_CLAVES:
        for k in [k for k, v in _intentos.items()
                  if not v or ahora - v[-1] >= VENTANA_FALLOS_S]:
            del _intentos[k]
        if len(_intentos) >= _INTENTOS_MAX_CLAVES:
            antiguas = sorted(_intentos.items(), key=lambda kv: kv[1][-1])
            for k, _ in antiguas[: _INTENTOS_MAX_CLAVES // 4]:
                del _intentos[k]
    _intentos.setdefault(usuario, []).append(ahora)


# ---------------------------------------------------------------------------
# Almacén
# ---------------------------------------------------------------------------


def _conexion() -> sqlite3.Connection:
    conn = sqlite3.connect(str(RUTA_DB), timeout=10)
    conn.row_factory = sqlite3.Row
    # Concurrencia: la API atiende peticiones en paralelo (threadpool) y el
    # proxy relanza el backend bajo demanda; busy_timeout encola escritores
    # en vez de fallar el login con "database is locked".
    conn.execute("PRAGMA busy_timeout=5000")
    conn.executescript(SCHEMA)
    _migrar(conn)
    conn.commit()
    return conn


def _migrar(conn: sqlite3.Connection) -> None:
    """Migraciones idempotentes para despliegues previos a la v21:
    columnas tenant_id/sso_sub y organización por defecto.
    Un ALTER que ya se aplicó levanta OperationalError y se ignora."""
    columnas = {f[1] for f in conn.execute("PRAGMA table_info(operadores)")}
    if "tenant_id" not in columnas:
        conn.execute(
            "ALTER TABLE operadores ADD COLUMN tenant_id TEXT NOT NULL "
            "DEFAULT 'predeterminada'")
    if "sso_sub" not in columnas:
        conn.execute("ALTER TABLE operadores ADD COLUMN sso_sub TEXT")
    # z3 (auditoría seguridad): instante (epoch) a partir del cual los tokens
    # emitidos ANTES ya no valen para esta cuenta (revocación de sesiones).
    if "invalidar_antes" not in columnas:
        conn.execute(
            "ALTER TABLE operadores ADD COLUMN invalidar_antes REAL NOT NULL "
            "DEFAULT 0")
    if not conn.execute(
            "SELECT 1 FROM organizaciones WHERE id=?",
            (TENANT_PREDETERMINADA,)).fetchone():
        conn.execute(
            "INSERT OR IGNORE INTO organizaciones (id, nombre, creado_en) "
            "VALUES (?,?,?)",
            (TENANT_PREDETERMINADA, "Organización por defecto", _ts()))


def _secreto_jwt(conn: sqlite3.Connection) -> bytes:
    """Secreto HS256 persistido: se genera una única vez por despliegue."""
    fila = conn.execute("SELECT valor FROM config WHERE clave='secreto_jwt'").fetchone()
    if fila:
        return fila["valor"].encode()
    secreto = secrets.token_hex(32)
    conn.execute(
        "INSERT OR REPLACE INTO config (clave, valor) VALUES ('secreto_jwt', ?)",
        (secreto,))
    conn.commit()
    return secreto.encode()


def _ts(dt: datetime | None = None) -> str:
    return (dt or datetime.now(timezone.utc)).isoformat()


# ---------------------------------------------------------------------------
# Contraseñas (scrypt)
# ---------------------------------------------------------------------------


def _hash_contrasena(contrasena: str) -> str:
    salt = secrets.token_bytes(16)
    derivada = hashlib.scrypt(contrasena.encode(), salt=salt,
                              n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=DKLEN)
    return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${salt.hex()}${derivada.hex()}"


def _verificar_contrasena(contrasena: str, guardada: str) -> bool:
    try:
        esquema, n, r, p, salt_hex, hash_hex = guardada.split("$")
        if esquema != "scrypt":
            return False
        derivada = hashlib.scrypt(contrasena.encode(), salt=bytes.fromhex(salt_hex),
                                  n=int(n), r=int(r), p=int(p), dklen=DKLEN)
        return hmac.compare_digest(derivada.hex(), hash_hex)
    except (ValueError, TypeError):
        return False


# ---------------------------------------------------------------------------
# JWT HS256 (RFC 7519, implementación estándar sin dependencias)
# ---------------------------------------------------------------------------


def _b64url(datos: bytes) -> str:
    return base64.urlsafe_b64encode(datos).rstrip(b"=").decode()


def _b64url_decodificar(texto: str) -> bytes:
    relleno = "=" * (-len(texto) % 4)
    return base64.urlsafe_b64decode(texto + relleno)


def emitir_token(usuario: str, rol: str,
                 tenant: str = TENANT_PREDETERMINADA) -> dict[str, Any]:
    """Emite un JWT firmado. Devuelve {token, expira_en}.

    El claim `ten` (tenant/organización) viaja FIRMADO: un cliente no puede
    cambiar de organización editando el token.
    """
    conn = _conexion()
    try:
        secreto = _secreto_jwt(conn)
    finally:
        conn.close()
    ahora = int(time.time())
    expira = ahora + int(TOKEN_HORAS * 3600)
    cabecera = _b64url(json.dumps(
        {"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    cuerpo = _b64url(json.dumps(
        {"sub": usuario, "rol": rol, "ten": tenant,
         "iat": ahora, "exp": expira,
         "jti": secrets.token_hex(8)},
        separators=(",", ":")).encode())
    firma = _b64url(hmac.new(secreto, f"{cabecera}.{cuerpo}".encode(),
                             hashlib.sha256).digest())
    return {"token": f"{cabecera}.{cuerpo}.{firma}", "expira_en": expira}


def verificar_token(token: str) -> Optional[dict[str, Any]]:
    """Verifica firma y expiración del JWT. Devuelve claims o None."""
    try:
        cabecera_b64, cuerpo_b64, firma_b64 = token.split(".")
        conn = _conexion()
        try:
            secreto = _secreto_jwt(conn)
        finally:
            conn.close()
        firma_esperada = hmac.new(
            secreto, f"{cabecera_b64}.{cuerpo_b64}".encode(), hashlib.sha256).digest()
        if not hmac.compare_digest(_b64url(firma_esperada), firma_b64):
            return None
        cabecera = json.loads(_b64url_decodificar(cabecera_b64))
        claims = json.loads(_b64url_decodificar(cuerpo_b64))
        if cabecera.get("alg") != "HS256" or int(claims.get("exp", 0)) < time.time():
            return None
        return claims
    except Exception:
        return None


# ---------------------------------------------------------------------------
# z3 (auditoría seguridad): REVOCACIÓN de sesiones. Un JWT no puede
# invalidarse por sí solo: sin este chequeo, una cuenta ELIMINADA, DEGRADADA
# o con credencial restablecida seguía operativa hasta 12 h (TOKEN_HORAS)
# con su token robado/copiado. `invalidar_antes` (epoch por cuenta) se fija
# en cada cambio administrativo; el middleware comprueba que el token fue
# emitido DESPUÉS y que rol/tenant del claim siguen vigentes en la BD.
# El coste (1 SELECT por petición) se amortiza con una caché TTL corta.
# ---------------------------------------------------------------------------

_CACHE_SESION_TTL_S = 15.0
_sesiones_cache: dict[tuple[str, str], tuple[float, Optional[dict[str, Any]]]] = {}
_SESIONES_CACHE_MAX = 5_000


def _invalidar_cache_sesion(usuario: str) -> None:
    for k in [k for k in _sesiones_cache if k[1] == usuario]:
        del _sesiones_cache[k]


def estado_actual(usuario: str) -> Optional[dict[str, Any]]:
    """Estado vivo de la cuenta: (existe, rol, tenant_id, invalidar_antes).
    None si la cuenta ya no existe. Con caché TTL de 15 s (clave incluye la
    BD activa: despliegues y tests aíslan por RUTA_DB)."""
    clave = (str(RUTA_DB), usuario)
    ahora = time.time()
    if len(_sesiones_cache) > _SESIONES_CACHE_MAX:
        for k in [k for k, v in _sesiones_cache.items()
                  if ahora - v[0] > _CACHE_SESION_TTL_S]:
            del _sesiones_cache[k]
    hit = _sesiones_cache.get(clave)
    if hit and ahora - hit[0] < _CACHE_SESION_TTL_S:
        return hit[1]
    conn = _conexion()
    try:
        fila = conn.execute(
            "SELECT rol, tenant_id, invalidar_antes FROM operadores "
            "WHERE usuario=?", (usuario,)).fetchone()
        estado = (dict(fila) if fila else None)
    finally:
        conn.close()
    _sesiones_cache[clave] = (ahora, estado)
    return estado


def sesion_viva(claims: dict[str, Any]) -> bool:
    """¿El token sigue siendo VÁLIDO para la cuenta actual?
    Comprueba existencia, rol y tenant vigentes y el corte `invalidar_antes`
    contra el `iat` del token. Los tokens sin `iat` legible se rechazan."""
    usuario = str(claims.get("sub") or "")
    if not usuario:
        return False
    try:
        iat = int(claims.get("iat") or 0)
    except (TypeError, ValueError):
        return False
    if iat <= 0:
        return False
    estado = estado_actual(usuario)
    if estado is None:
        return False  # cuenta eliminada: token muerto
    if estado["rol"] != claims.get("rol"):
        return False  # rol cambiado (degradación o promoción): re-login
    if estado["tenant_id"] != claims.get("ten"):
        return False  # cuenta movida de organización: re-login
    if iat < float(estado["invalidar_antes"] or 0):
        return False  # credencial/rol alterado tras la emisión
    return True


def higiene_cuenta(usuario: str) -> Optional[dict[str, Any]]:
    """Estado de higiene de la PROPIA cuenta (v26, panel de la consola).

    Lo que un usuario puede ver de sí mismo sin material sensible: rol y
    organización VIGENTES (los del middleware de revocación, no los del
    token), fechas de alta/último acceso y el corte `invalidar_antes`.
    v34: incluye `sso_sub` (presencia del enlace federado) — la API lo
    convierte al booleano `sso_vinculado` y NUNCA expone el sub entero.
    Los claims del token se añaden en la API (capa de presentación)."""
    conn = _conexion()
    try:
        fila = conn.execute(
            "SELECT usuario, rol, tenant_id, creado_en, ultimo_acceso, "
            "invalidar_antes, sso_sub FROM operadores WHERE usuario=?",
            (usuario,)).fetchone()
        return dict(fila) if fila else None
    finally:
        conn.close()


# --- Registro de sesiones activas (v34) -------------------------------------
# El JWT es sin estado por diseño (z3-F4 fija el corte de revocación), pero
# la HIGIENE del operador necesita saber qué sesiones suyas están vivas y
# desde dónde. Esta tabla es el ESPEJO consultable de los tokens emitidos:
# nunca decide validez — la decide la firma + sesion_viva() en cada petición.

# Throttle de actividad: jti → último volcado a BD (1/min evita una
# escritura por petición; la granularidad minuto basta para higiene).
_touch_sesiones: dict[str, float] = {}


def registrar_sesion(token: str, user_agent: str = "", ip: str = "") -> dict[str, Any]:
    """Registra una sesión recién emitida (login local o federado).

    Se llama en los dos únicos puntos donde nace un token (POST /auth/login
    y el callback SSO). Extrae los claims del propio token para no duplicar
    la verdad: jti, emisión y caducidad son los del JWT real. Las filas de
    sesiones expiradas se purgan aquí para mantener la tabla acotada."""
    claims = verificar_token(token)
    if not claims:
        return {}
    jti = str(claims.get("jti") or "")
    if not jti:
        return {}  # token sin jti (emitido antes de v?): sin registro
    ahora = time.time()
    expira = int(claims.get("exp") or 0)
    conn = _conexion()
    try:
        conn.execute("DELETE FROM sesiones WHERE expira_en < ?", (ahora,))
        conn.execute(
            "INSERT OR REPLACE INTO sesiones "
            "(jti, usuario, emitido_en, expira_en, ultima_actividad, "
            " user_agent, ip) VALUES (?,?,?,?,?,?,?)",
            (jti, str(claims.get("sub")), float(claims.get("iat") or ahora),
             float(expira or ahora), ahora,
             (user_agent or "")[:200], (ip or "")[:64]))
        conn.commit()
    finally:
        conn.close()
    return {"jti": f"{jti[:8]}…", "expira_en": expira}


def tocar_sesion(claims: dict[str, Any], user_agent: str = "", ip: str = "") -> None:
    """Actualiza la última actividad de la sesión autenticada.

    Se llama desde el middleware en CADA petición: el throttle en memoria
    (1/min por jti) evita convertir la tabla en cuello de botella. La
    telemetría nunca bloquea una petición válida: cualquier fallo de BD
    se traga (la visibilidad es un lujo, la sesión un derecho)."""
    jti = str(claims.get("jti") or "")
    if not jti:
        return
    ahora = time.time()
    if ahora - _touch_sesiones.get(jti, 0.0) < 60.0:
        return
    if len(_touch_sesiones) > 10_000:
        for k in [k for k, v in _touch_sesiones.items()
                  if ahora - v > 3600.0]:
            del _touch_sesiones[k]
    _touch_sesiones[jti] = ahora
    try:
        conn = _conexion()
        try:
            conn.execute(
                "UPDATE sesiones SET ultima_actividad=? WHERE jti=?",
                (ahora, jti))
            conn.commit()
        finally:
            conn.close()
    except sqlite3.Error:
        pass


def listar_sesiones(usuario: str, jti_actual: str = "") -> list[dict[str, Any]]:
    """Sesiones VIVAS de la cuenta: token no expirado Y emitido después
    del último corte de revocación (invalidar_antes) — exactamente lo que
    el middleware acepta hoy. Sin material sensible: el jti viaja resumido
    (8 primeros caracteres) para que el operador reconozca SU pestaña."""
    ahora = time.time()
    conn = _conexion()
    try:
        conn.execute("DELETE FROM sesiones WHERE expira_en < ?", (ahora,))
        conn.commit()
        filas = conn.execute(
            "SELECT s.jti, s.emitido_en, s.expira_en, s.ultima_actividad, "
            "       s.user_agent, s.ip "
            "FROM sesiones s JOIN operadores o ON o.usuario = s.usuario "
            "WHERE s.usuario = ? AND s.expira_en > ? "
            "      AND s.emitido_en >= COALESCE(o.invalidar_antes, 0) "
            "ORDER BY s.emitido_en DESC",
            (usuario, ahora)).fetchall()
    finally:
        conn.close()
    return [{
        "jti": f"{f['jti'][:8]}…",
        "actual": bool(jti_actual) and f["jti"] == jti_actual,
        "emitido_en": f["emitido_en"],
        "expira_en": f["expira_en"],
        "ultima_actividad": f["ultima_actividad"],
        "user_agent": f["user_agent"],
        "ip": f["ip"],
    } for f in filas]


def desvincular_sso(usuario: str) -> dict[str, Any]:
    """Retira el enlace federado de una cuenta (decisión explícita del
    admin, auditada): la cuenta vuelve a autenticarse SOLO con credencial
    local. Operación inversa de vincular_sso_manual — sin ella, enlazar
    sería una puerta de una sola vía."""
    usuario = (usuario or "").strip()
    if not usuario:
        raise ValueError("usuario es obligatorio")
    conn = _conexion()
    try:
        fila = conn.execute(
            "SELECT sso_sub FROM operadores WHERE usuario=?",
            (usuario,)).fetchone()
        if fila is None:
            raise ValueError(f"El usuario '{usuario}' no existe")
        if not fila["sso_sub"]:
            raise ValueError(
                f"La cuenta '{usuario}' no tiene acceso federado vinculado")
        conn.execute(
            "UPDATE operadores SET sso_sub=NULL WHERE usuario=?", (usuario,))
        conn.commit()
    finally:
        conn.close()
    return {"usuario": usuario, "desvinculado": True}


def revocar_sesiones_propias(usuario: str) -> dict[str, Any]:
    """«Cerrar sesión en TODOS los dispositivos» de la propia cuenta (v26).

    Fija `invalidar_antes` al instante actual SIN tocar la credencial:
    todos los JWT emitidos antes mueren — INCLUIDO el de quien lo pide
    (semántica estándar de sign-out-everywhere; el cliente limpia su
    sesión local al recibir el 200 y vuelve a entrar con credenciales).
    La credencial sigue siendo válida: esto NO es un restablecimiento.
    """
    corte = time.time()
    conn = _conexion()
    try:
        cur = conn.execute(
            "UPDATE operadores SET invalidar_antes=? WHERE usuario=?",
            (corte, usuario))
        conn.commit()
        if cur.rowcount == 0:
            raise ValueError(f"El usuario '{usuario}' no existe")
    finally:
        conn.close()
    _invalidar_cache_sesion(usuario)
    return {"usuario": usuario, "corte": corte}


# ---------------------------------------------------------------------------
# Cuentas de operador
# ---------------------------------------------------------------------------


def _validar_contrasena(contrasena: str) -> None:
    if len(contrasena) < 8:
        raise ValueError("La contraseña debe tener al menos 8 caracteres")
    if contrasena.lower() in ("password", "contrasena", "12345678", "changeme"):
        raise ValueError("Contraseña trivial: elige una credencial real")


def hay_operadores() -> bool:
    conn = _conexion()
    try:
        return conn.execute("SELECT COUNT(*) FROM operadores").fetchone()[0] > 0
    finally:
        conn.close()


def crear_operador(usuario: str, contrasena: str, rol: str = "operador",
                   tenant_id: str = TENANT_PREDETERMINADA,
                   sso_sub: str | None = None) -> dict[str, Any]:
    """Alta de operador. Validación de credencial, rol y organización."""
    usuario = (usuario or "").strip()
    # Regla explícita y amable: letras/números ASCII + . _ - (sin espacios).
    # Antes se rechazaba el guion (-), un fallo fricción habitual al alta.
    if not re.fullmatch(r"[A-Za-z0-9._-]{3,32}", usuario):
        raise ValueError(
            "Usuario inválido: usa de 3 a 32 caracteres (letras, números, "
            "punto, guion y guion bajo; sin espacios ni tildes)"
        )
    if rol not in ROLES:
        raise ValueError("Rol inválido")
    _validar_contrasena(contrasena)
    tenant_id = (tenant_id or TENANT_PREDETERMINADA).strip().lower()
    conn = _conexion()
    try:
        if not conn.execute("SELECT 1 FROM organizaciones WHERE id=?",
                            (tenant_id,)).fetchone():
            raise ValueError(
                f"La organización '{tenant_id}' no existe (créala antes de "
                "dar de alta cuentas en ella)")
        conn.execute(
            "INSERT INTO operadores (usuario, hash, rol, tenant_id, sso_sub, "
            "creado_en) VALUES (?,?,?,?,?,?)",
            (usuario, _hash_contrasena(contrasena), rol, tenant_id, sso_sub, _ts()))
        conn.commit()
    except sqlite3.IntegrityError as exc:
        raise ValueError(f"El usuario '{usuario}' ya existe") from exc
    finally:
        conn.close()
    return {"usuario": usuario, "rol": rol, "tenant_id": tenant_id,
            "creado_en": _ts()}


def verificar_credenciales(usuario: str, contrasena: str) -> Optional[dict[str, Any]]:
    """Autenticación con bloqueo temporal tras fallos repetidos."""
    usuario = (usuario or "").strip()
    ahora = time.time()
    fallos = [t for t in _intentos.get(usuario, []) if ahora - t < VENTANA_FALLOS_S]
    if len(fallos) >= MAX_FALLOS and ahora - fallos[-1] < BLOQUEO_S:
        restante = int(BLOQUEO_S - (ahora - fallos[-1]))
        raise ValueError(f"Demasiados intentos fallidos: cuenta bloqueada {restante}s")
    conn = _conexion()
    try:
        fila = conn.execute(
            "SELECT usuario, hash, rol, tenant_id FROM operadores WHERE usuario=?",
            (usuario,)).fetchone()
        if fila and _verificar_contrasena(contrasena, fila["hash"]):
            _intentos.pop(usuario, None)
            conn.execute("UPDATE operadores SET ultimo_acceso=? WHERE usuario=?",
                         (_ts(), usuario))
            conn.commit()
            return {"usuario": fila["usuario"], "rol": fila["rol"],
                    "tenant_id": fila["tenant_id"]}
    finally:
        conn.close()
    _registrar_intento(usuario)
    return None


def cambiar_contrasena(usuario: str, actual: str, nueva: str) -> bool:
    if not verificar_credenciales(usuario, actual):
        return False
    _validar_contrasena(nueva)
    conn = _conexion()
    try:
        # z3 (revocación de sesiones): el cambio de credencial mata los tokens
        # emitidos antes de ahora (robo de sesión / cambio tras compromiso).
        conn.execute(
            "UPDATE operadores SET hash=?, invalidar_antes=? WHERE usuario=?",
            (_hash_contrasena(nueva), time.time(), usuario))
        conn.commit()
        _invalidar_cache_sesion(usuario)
        return True
    finally:
        conn.close()


def listar_operadores() -> list[dict[str, Any]]:
    """Lista de cuentas (sin material sensible de credenciales)."""
    conn = _conexion()
    try:
        filas = conn.execute(
            "SELECT usuario, rol, tenant_id, sso_sub, creado_en, ultimo_acceso "
            "FROM operadores ORDER BY creado_en").fetchall()
        return [dict(f) for f in filas]
    finally:
        conn.close()


def obtener_operador(usuario: str) -> Optional[dict[str, Any]]:
    """Datos de una cuenta concreta (sin hash de credencial)."""
    conn = _conexion()
    try:
        fila = conn.execute(
            "SELECT usuario, rol, tenant_id, sso_sub, creado_en, ultimo_acceso "
            "FROM operadores WHERE usuario=?", (usuario,)).fetchone()
        return dict(fila) if fila else None
    finally:
        conn.close()


def eliminar_operador(usuario: str, peticionario: str) -> None:
    """Baja de cuenta (solo admin).

    Auto-baja: permitida SOLO cuando el peticionario es el ÚNICO operador
    del despliegue — el cierre limpio de una cuenta temporal o la entrega
    del despliegue reabren el bootstrap para el siguiente responsable. Si
    quedan más operadores, la salida la firma otro admin: nunca se borra
    a sí mismo sin testigo administrativo.
    """
    if usuario == peticionario:
        conn = _conexion()
        try:
            total = conn.execute("SELECT COUNT(*) FROM operadores").fetchone()[0]
        finally:
            conn.close()
        if total > 1:
            raise ValueError(
                "Un operador no puede eliminar su propia cuenta con más "
                "operadores activos: la baja la firma otro admin")
        # Único operador: la auto-baja reabre el bootstrap (entrega limpia).
    else:
        conn = _conexion()
        try:
            fila = conn.execute(
                "SELECT rol FROM operadores WHERE usuario=?", (usuario,)).fetchone()
            if not fila:
                raise ValueError(f"El usuario '{usuario}' no existe")
            if fila["rol"] == "admin" and contar_admins() <= 1:
                raise ValueError(
                    "No se puede eliminar al último admin: el despliegue quedaría sin "
                    "forma de gestionar operadores")
        finally:
            conn.close()
    conn = _conexion()
    try:
        conn.execute("DELETE FROM operadores WHERE usuario=?", (usuario,))
        conn.commit()
    finally:
        conn.close()
    # z3 (revocación de sesiones): el token de la cuenta eliminada muere en
    # la próxima petición (estado_actual → None) sin esperar a la caché.
    _invalidar_cache_sesion(usuario)


def contar_admins() -> int:
    conn = _conexion()
    try:
        return conn.execute(
            "SELECT COUNT(*) FROM operadores WHERE rol='admin'").fetchone()[0]
    finally:
        conn.close()


def restablecer_contrasena(usuario: str, nueva: str) -> dict[str, Any]:
    """Restablecimiento ADMINISTRATIVO de credencial (usuario afectado fuera
    de sesión): fuerza una nueva contraseña sin conocer la anterior.

    Herramienta de respuesta a incidentes de acceso; queda registrada la
    fecha de última gestión en la propia cuenta."""
    _validar_contrasena(nueva)
    conn = _conexion()
    try:
        # z3 (revocación de sesiones): el restablecimiento administrativo
        # responde a un INCIDENTE: mata también las sesiones vivas de la
        # cuenta afectada, no solo la contraseña.
        cur = conn.execute(
            "UPDATE operadores SET hash=?, invalidar_antes=? WHERE usuario=?",
            (_hash_contrasena(nueva), time.time(), usuario))
        conn.commit()
        if cur.rowcount == 0:
            raise ValueError(f"El usuario '{usuario}' no existe")
    finally:
        conn.close()
    _invalidar_cache_sesion(usuario)
    _intentos.pop(usuario, None)  # desbloquea la cuenta tras el reset
    return {"usuario": usuario, "restablecida": True}


def cambiar_rol(usuario: str, rol: str, peticionario: str) -> dict[str, Any]:
    """Cambio de rol (solo admin). Protege el acceso administrativo:
    nadie puede quitarse admin a sí mismo ni degradar al último admin."""
    if rol not in ROLES:
        raise ValueError("Rol inválido")
    if usuario == peticionario:
        raise ValueError("Un admin no puede cambiar su propio rol (protección de bloqueo)")
    conn = _conexion()
    try:
        fila = conn.execute(
            "SELECT rol FROM operadores WHERE usuario=?", (usuario,)).fetchone()
        if not fila:
            raise ValueError(f"El usuario '{usuario}' no existe")
        if fila["rol"] == "admin" and rol != "admin" and contar_admins() <= 1:
            raise ValueError("No se puede degradar al último admin del despliegue")
        # z3 (revocación de sesiones): el rol vigente debe ser el del token.
        conn.execute(
            "UPDATE operadores SET rol=?, invalidar_antes=? WHERE usuario=?",
            (rol, time.time(), usuario))
        conn.commit()
    finally:
        conn.close()
    _invalidar_cache_sesion(usuario)
    return {"usuario": usuario, "rol": rol}


# ---------------------------------------------------------------------------
# Auditoría de sistema (nivel despliegue, distinta de la auditoría por caso):
# acciones administrativas que no viven dentro de un engagement concreto —
# respaldos completos, gestión de cuentas. Append-only como la del caso.
# ---------------------------------------------------------------------------

def registrar_auditoria_sistema(actor: str, accion: str, detalle: str = "") -> None:
    conn = _conexion()
    try:
        conn.execute(
            "INSERT INTO auditoria_sistema (actor, accion, detalle, creado_en) "
            "VALUES (?,?,?,?)",
            (actor, accion, detalle, _ts()))
        conn.commit()
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Organizaciones (multi-tenant v21): los casos y las cuentas viven en una
# organización; el aislamiento lo aplica la API. 'predeterminada' existe
# siempre para despliegues mono-equipo.
# ---------------------------------------------------------------------------


_ID_ORG = re.compile(r"^[a-z0-9][a-z0-9._-]{1,40}$")


def crear_organizacion(org_id: str, nombre: str) -> dict[str, Any]:
    """Alta de organización (tenant). id: slug minúscula [a-z0-9._-]."""
    org_id = (org_id or "").strip().lower()
    nombre = (nombre or "").strip()
    if not _ID_ORG.fullmatch(org_id):
        raise ValueError(
            "Id de organización inválido: 2-41 caracteres en minúscula "
            "(letras, números, punto, guion y guion bajo)")
    if not (2 <= len(nombre) <= 120):
        raise ValueError("El nombre de la organización debe tener 2-120 caracteres")
    conn = _conexion()
    try:
        conn.execute(
            "INSERT INTO organizaciones (id, nombre, creado_en) VALUES (?,?,?)",
            (org_id, nombre, _ts()))
        conn.commit()
    except sqlite3.IntegrityError as exc:
        raise ValueError(f"La organización '{org_id}' ya existe") from exc
    finally:
        conn.close()
    return {"id": org_id, "nombre": nombre, "creado_en": _ts()}


def listar_organizaciones() -> list[dict[str, Any]]:
    conn = _conexion()
    try:
        filas = conn.execute(
            "SELECT o.id, o.nombre, o.creado_en, "
            "(SELECT COUNT(*) FROM operadores op WHERE op.tenant_id=o.id) "
            "AS operadores "
            "FROM organizaciones o ORDER BY o.creado_en").fetchall()
        return [dict(f) for f in filas]
    finally:
        conn.close()


def organizacion_existe(org_id: str) -> bool:
    conn = _conexion()
    try:
        return conn.execute("SELECT 1 FROM organizaciones WHERE id=?",
                            (org_id,)).fetchone() is not None
    finally:
        conn.close()


def asignar_tenant(usuario: str, tenant_id: str) -> dict[str, Any]:
    """Mueve una cuenta de organización (admin, cross-tenant)."""
    tenant_id = (tenant_id or "").strip().lower()
    conn = _conexion()
    try:
        if not conn.execute("SELECT 1 FROM organizaciones WHERE id=?",
                            (tenant_id,)).fetchone():
            raise ValueError(f"La organización '{tenant_id}' no existe")
        cur = conn.execute(
            "UPDATE operadores SET tenant_id=?, invalidar_antes=? WHERE usuario=?",
            (tenant_id, time.time(), usuario))
        conn.commit()
        if cur.rowcount == 0:
            raise ValueError(f"El usuario '{usuario}' no existe")
    finally:
        conn.close()
    _invalidar_cache_sesion(usuario)
    return {"usuario": usuario, "tenant_id": tenant_id}


# ---------------------------------------------------------------------------
# Vinculación SSO (OIDC): la identidad federada (claim `sub` del IdP) se
# enlaza a una cuenta local. JIT (just-in-time): si llega un sub nuevo con
# auto-alta activado se crea una cuenta LEATOR (mínimo privilegio) enlazada.
# ---------------------------------------------------------------------------


def obtener_por_sso(sso_sub: str) -> Optional[dict[str, Any]]:
    conn = _conexion()
    try:
        fila = conn.execute(
            "SELECT usuario, rol, tenant_id, sso_sub FROM operadores "
            "WHERE sso_sub=?", (sso_sub,)).fetchone()
        return dict(fila) if fila else None
    finally:
        conn.close()


def crear_o_vincular_sso(sso_sub: str, usuario: str, rol: str = "lector",
                         tenant_id: str = TENANT_PREDETERMINADA,
                         auto_alta: bool = True,
                         email: str = "",
                         email_verificado: bool = False) -> dict[str, Any]:
    """Resuelve el login SSO REAL: cuenta ya enlazada → devolverla;
    usuario local existente sin enlace → enlazarlo SOLO si la política lo
    permite (z3: cuentas privilegiadas exigen pre-aprobación explícita y,
    si hay dominio de confianza configurado, email federado verificado;
    z2: la homonimia exige además SSO_VINCULAR_POR_NOMBRE=1 o vínculo
    pre-aprobado);
    cuenta nueva → alta JIT como 'lector' (o el rol indicado) si auto_alta.

    Vinculación por nombre DESACTIVADA por defecto (segura por defecto):
    enlazar una cuenta local homónima solo porque el claim
    preferred_username coincide permitía a un usuario federado que
    eligiera ese nombre APROPIARSE de la cuenta (p. ej. 'admin'): el login
    SSO devolvía el rol y la organización de la cuenta ajena. Ahora la
    vinculación de una identidad federada a una cuenta local existente es
    una decisión EXPLÍCITA del admin:

      - via env SSO_VINCULAR_POR_NOMBRE=1 (despliegues que confían en el
        IdP corporativo y su política de nombres), o
      - via endpoint admin POST /api/auth/sso/vincular (enlace puntual,
        auditado).

    Con el flag desactivado, si la identidad federada colisiona con una
    cuenta local se lanza ValueError accionable (ni JIT silencioso ni
    enlace: el admin decide).

    El hash guardado para cuentas JIT es UNREACHABLE (el acceso federado
    no usa contraseña local); se guarda un token imposible de reproducir
    para que un intento de login con contraseña directa no coincida jamás.
    """
    existente = obtener_por_sso(sso_sub)
    if existente:
        return existente
    # z3 (auditoría seguridad): si el despliegue declara dominios de email
    # de confianza (OIDC_DOMINIOS_PERMITIDOS), cualquier alta o vínculo
    # automático exige un email federado VERIFICADO de uno de esos dominios.
    # Sin esa comprobación, un IdP con autorregistro abierto podría crear
    # 'admin' y heredar la cuenta local del mismo nombre (secuestro de
    # cuenta vía SSO).
    dominios = _dominios_sso_permitidos()
    if dominios:
        dominio_email = (email.split("@")[-1].lower().strip()
                         if "@" in email else "")
        if not email_verificado or dominio_email not in dominios:
            raise ValueError(
                "SSO: se exige un email federado verificado de los dominios "
                f"autorizados ({', '.join(sorted(dominios))}) para "
                "vincular o dar de alta la identidad")
    # z2 (ronda 1): la vinculación por homonimia está DESACTIVADA por
    # defecto; el flag la abre solo en IdPs de confianza. Un vínculo
    # PRE-APROBADO por admin (z3) es una decisión explícita y basta por sí
    # mismo (se comprueba por cuenta, abajo).
    vinculacion_por_nombre = os.environ.get("SSO_VINCULAR_POR_NOMBRE", "") == "1"
    conn = _conexion()
    try:
        fila = conn.execute(
            "SELECT usuario, rol, tenant_id FROM operadores WHERE usuario=?",
            (usuario,)).fetchone()
        if fila:
            preaprobado = _vinculo_preaprobado(conn, fila["usuario"], sso_sub)
            if rol_nivel(fila["rol"]) >= 3 and not preaprobado:
                # z3: cuentas gestor/admin — el nombre federado que coincide
                # NO basta. Un admin debe pre-aprobar el vínculo
                # explícitamente (CLI: orquesta sso-preaprobar).
                raise ValueError(
                    f"SSO: la cuenta local privilegiada '{usuario}' exige "
                    "pre-aprobación explícita de un admin antes de enlazar "
                    "una identidad federada (orquesta sso-preaprobar)")
            if not preaprobado and not vinculacion_por_nombre:
                # z2: para el resto de cuentas la homonimia tampoco basta
                # por sí sola (toma de cuenta de menor rol): hace falta el
                # flag de IdP de confianza o un vínculo pre-aprobado.
                raise ValueError(
                    f"La identidad federada '{usuario}' coincide con una cuenta "
                    "local existente y la vinculación por nombre está "
                    "desactivada. Un administrador debe enlazarla de forma "
                    "explícita (orquesta sso-preaprobar o "
                    "POST /api/auth/sso/vincular) o activar "
                    "SSO_VINCULAR_POR_NOMBRE=1 si su IdP garantiza la "
                    "única propiedad de los nombres de usuario.")
            conn.execute("UPDATE operadores SET sso_sub=? WHERE usuario=?",
                         (sso_sub, usuario))
            conn.commit()
            registrar_auditoria_sistema(
                f"sso:{sso_sub}", "sso.vinculo",
                f"identidad federada enlazada a la cuenta local "
                f"'{usuario}' (rol {fila['rol']})")
            return {"usuario": fila["usuario"], "rol": fila["rol"],
                    "tenant_id": fila["tenant_id"], "sso_sub": sso_sub}
        if not auto_alta:
            raise ValueError(
                f"La identidad federada '{usuario}' no tiene cuenta en este "
                "despliegue y el auto-alta SSO está desactivado")
        conn.execute(
            "INSERT INTO operadores (usuario, hash, rol, tenant_id, sso_sub, "
            "creado_en) VALUES (?,?,?,?,?,?)",
            (usuario,
             "sso$federado$" + secrets.token_hex(32),  # inalcanzable por login
             rol if rol in ROLES else "lector",
             tenant_id if organizacion_existe(tenant_id) else TENANT_PREDETERMINADA,
             sso_sub, _ts()))
        conn.commit()
        registrar_auditoria_sistema(
            f"sso:{sso_sub}", "sso.alta_jit",
            f"alta JIT federada '{usuario}' (rol {rol if rol in ROLES else 'lector'}, "
            f"tenant {tenant_id if organizacion_existe(tenant_id) else TENANT_PREDETERMINADA})")
    except sqlite3.IntegrityError as exc:
        raise ValueError(f"El usuario '{usuario}' ya existe") from exc
    finally:
        conn.close()
    return obtener_por_sso(sso_sub) or obtener_operador(usuario) or {
        "usuario": usuario, "rol": rol, "tenant_id": tenant_id, "sso_sub": sso_sub}


def _dominios_sso_permitidos() -> set[str]:
    """Dominios de email federado de confianza (OIDC_DOMINIOS_PERMITIDOS).

    Vacío = sin restricción de dominio (comportamiento previo); con valor,
    'a.com, b.com' restringe altas y vínculos SSO a emails verificados de
    esos dominios.
    """
    bruto = os.environ.get("OIDC_DOMINIOS_PERMITIDOS", "")
    return {d.strip().lower().lstrip("@.") for d in bruto.split(",")
            if d.strip()} - {""}


def _vinculo_preaprobado(conn: sqlite3.Connection, usuario: str,
                         sso_sub: str) -> bool:
    conn.execute("DELETE FROM sso_vinculos_preaprobados WHERE creado_en<?",
                 (_ts_gracia_vinculos(),))
    return conn.execute(
        "SELECT 1 FROM sso_vinculos_preaprobados WHERE usuario=? AND sso_sub=?",
        (usuario, sso_sub)).fetchone() is not None


def _ts_gracia_vinculos() -> str:
    """Los pre-aprobados no usados caducan a los 30 días (higiene)."""
    from datetime import datetime, timedelta, timezone
    return (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()


def preaprobar_vinculo_sso(actor: str, usuario: str, sso_sub: str) -> dict[str, Any]:
    """Autorización EXPLÍCITA de un admin para enlazar una identidad
    federada (sub del IdP) con una cuenta local existente. Obligatorio
    para cuentas gestor/admin; recomendado para cualquier vínculo.
    Caduca a los 30 días si no se consume."""
    conn = _conexion()
    try:
        fila = conn.execute("SELECT rol FROM operadores WHERE usuario=?",
                            (usuario,)).fetchone()
        if not fila:
            raise ValueError(f"El usuario '{usuario}' no existe")
        conn.execute(
            "INSERT OR REPLACE INTO sso_vinculos_preaprobados "
            "(usuario, sso_sub, creado_por, creado_en) VALUES (?,?,?,?)",
            (usuario, sso_sub, actor, _ts()))
        conn.commit()
    finally:
        conn.close()
    registrar_auditoria_sistema(
        actor, "sso.preaprobacion",
        f"vínculo federado pre-aprobado: cuenta '{usuario}' ← sub '{sso_sub}'")
    return {"usuario": usuario, "sso_sub": sso_sub}


def listar_vinculos_preaprobados() -> list[dict[str, Any]]:
    conn = _conexion()
    try:
        filas = conn.execute(
            "SELECT usuario, sso_sub, creado_por, creado_en "
            "FROM sso_vinculos_preaprobados ORDER BY creado_en").fetchall()
        return [dict(f) for f in filas]
    finally:
        conn.close()


def eliminar_vinculo_preaprobado(actor: str, usuario: str) -> int:
    conn = _conexion()
    try:
        cur = conn.execute(
            "DELETE FROM sso_vinculos_preaprobados WHERE usuario=?", (usuario,))
        conn.commit()
        eliminados = cur.rowcount
    finally:
        conn.close()
    if eliminados:
        registrar_auditoria_sistema(
            actor, "sso.preaprobacion_baja",
            f"pre-aprobación de vínculo federado retirada: '{usuario}'")
    return eliminados


def vincular_sso_manual(usuario: str, sso_sub: str) -> dict[str, Any]:
    """Enlaza una identidad federada (sub del IdP) a una cuenta local EXISTENTE
    como decisión explícita del admin (endpoint auditado, no flujo de login).

    Reemplaza el auto-enlace por homonimia: la confianza del claim
    preferred_username la fija el admin, no el usuario federado.
    """
    usuario = (usuario or "").strip()
    sso_sub = (sso_sub or "").strip()
    if not usuario or not sso_sub:
        raise ValueError("usuario y sso_sub son obligatorios")
    if len(sso_sub) > 256:
        raise ValueError("sso_sub demasiado largo")
    conn = _conexion()
    try:
        fila = conn.execute(
            "SELECT usuario, rol, tenant_id FROM operadores WHERE usuario=?",
            (usuario,)).fetchone()
        if fila is None:
            raise ValueError(f"El usuario '{usuario}' no existe")
        previo = conn.execute(
            "SELECT usuario FROM operadores WHERE sso_sub=? AND usuario<>?",
            (sso_sub, usuario)).fetchone()
        if previo is not None:
            raise ValueError(
                f"El sub federado ya está enlazado a otra cuenta ({previo['usuario']})")
        conn.execute("UPDATE operadores SET sso_sub=? WHERE usuario=?",
                     (sso_sub, usuario))
        conn.commit()
    finally:
        conn.close()
    return {"usuario": usuario, "sso_sub": sso_sub,
            "rol": obtener_operador(usuario)["rol"],
            "tenant_id": obtener_operador(usuario)["tenant_id"],
            "vinculado": True}


def listar_auditoria_sistema(limite: int = 200) -> list[dict[str, Any]]:
    acotado = min(max(limite, 1), 1000)
    conn = _conexion()
    try:
        filas = conn.execute(
            "SELECT id, actor, accion, detalle, creado_en FROM auditoria_sistema "
            "ORDER BY id DESC LIMIT ?", (acotado,)).fetchall()
        return [dict(f) for f in filas]
    finally:
        conn.close()
