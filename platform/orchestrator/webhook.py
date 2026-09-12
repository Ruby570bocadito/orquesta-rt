"""Notificación webhook REAL de eventos operativos (v16).

Los receptores los configura el admin en la consola (BD del despliegue,
tabla `webhooks`): cada receptor se suscribe a los eventos que le interesen
y el orquestador le entrega un POST HTTP real firmado, con registro de
entregas y un reintento ante fallo transitorio:

    X-Orquesta-Firma:   sha256=<HMAC-SHA256(cuerpo, secreto_del_receptor)>
    X-Orquesta-Evento:  hallazgo.registrado | ...
    X-Orquesta-Entrega: id único de entrega (cabecera de idempotencia)
    X-Orquesta-Intento: 1 | 2 — nº de intento dentro de la entrega (z2, ronda 3)
    X-Orquesta-Id:      engagement al que pertenece el evento

Prácticas del sector (Stripe/GitHub/Svix): firma HMAC-SHA256 sobre el
cuerpo crudo, cabecera de tipo de evento, identificador de entrega y
registro de resultados. El reintento es UNO (t+2 s) solo ante 5xx o error
de red: un webhook operacional avisa, no bloquea nunca al orquestador.

z2 (ronda 3): cada intento lleva `X-Orquesta-Intento: 1|2`. El identificador
de entrega es igual en ambos intentos (mismo evento lógico) — el receptor
con idempotencia por `X-Orquesta-Entrega` no distingue original de reintento
sin esta cabecera (p. ej. para no duplicar alertas en su SIEM).

Eventos emitidos por los flujos REALES del orquestador:
    hallazgo.registrado     el agente registró un hallazgo (fases.py)
    hallazgo.deteccion      el operador documentó el resultado defensivo
    aprobacion.solicitada   el boundary pide firma humana (guardrails.py)
    aprobacion.decidida     el operador aprobó o rechazó (api.py)
    roe.parada_emergencia   kill switch activado/desactivado (api.py)
    webhook.prueba          ping de prueba desde la consola

Compatibilidad: si el entorno define WEBHOOK_URL, esa dirección recibe
TODOS los eventos como canal heredado (a menos que coincida con un
receptor ya dado de alta, para no duplicar). Sin receptores no hay envío:
no se inventa ninguna entrega.
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import os
import secrets
import socket
import sqlite3
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

# --- catálogo de eventos ----------------------------------------------------

EVENTOS: tuple[str, ...] = (
    "hallazgo.registrado",
    "hallazgo.deteccion",
    "aprobacion.solicitada",
    "aprobacion.decidida",
    "roe.parada_emergencia",
    "ctem.corrida",
    "webhook.prueba",
)

# Redes de metadatos de nube vetadas como receptor (SSRF): el webhook es
# una configuración de admin, pero el límite link-local es defense-in-depth.
# z3 (auditoría): vetado por IP LITERAL (ipaddress), no por prefijo de texto
# — "169.254." no atrapaba 0xA9.0xFE..., ni los metadatos de Alibaba
# (100.100.100.200) u Oracle (192.0.0.192). El loopback se PERMITE (receptor
# n8n/lab en el mismo host es uso legítimo on-prem). Escape documentado para
# despliegues excepcionales con receptores en redes de metadatos (no debería
# existir): WEBHOOK_PERMITIR_METADATOS=1.
# z2 (ronda 1-2): el veto se aplica en CUATRO capas — nombre textual, IP
# directa en formas alternativas (decimal 2852039166, hex 0xA9FEA9FE, IPv6
# mapeado ::ffff:169.254.169.254), IP RESUELTA por DNS en el ALTA y de nuevo
# en el DESPACHO (el DNS pudo cambiar entre alta y entrega: rebinding — y el
# canal heredado WEBHOOK_URL nunca pasó por validar_url).
_HOSTS_VETADOS = {
    "metadata.google.internal",
    "metadata.goog",
    "metadata.azure.internal",
    "metadata.oraclecloud.com",
}
_REDES_VETADAS = tuple(
    ipaddress.ip_network(r) for r in (
        "169.254.0.0/16",       # link-local: AWS/GCP/Azure IMDS
        "fe80::/10",            # link-local IPv6
        "fd00:ec2::254/128",    # AWS IMDS IPv6
        "100.100.100.200/32",   # Alibaba Cloud IMDS
        "192.0.0.192/32",       # Oracle Cloud IMDS
    )
)


def _ip_vetada(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """True si la IP es link-local o de metadatos de nube."""
    if ip.version == 6 and ip.ipv4_mapped:  # ::ffff:a9fe:a9fe → 169.254.169.254
        ip = ip.ipv4_mapped
    return ip.is_link_local or any(ip in red for red in _REDES_VETADAS)


def _veto_metadatos_activo() -> bool:
    """Escape documentado (z3): WEBHOOK_PERMITIR_METADATOS=1 desactiva el
    veto para despliegues excepcionales. Por defecto el veto está ON."""
    return os.environ.get("WEBHOOK_PERMITIR_METADATOS", "") != "1"


MAX_ENTREGAS = 500  # poda global del registro de entregas por despliegue

# z2 (ronda 5): techo de entregas POR RECEPTOR. La poda global POR SÍ SOLA
# dejaba
# que un receptor muy activo (p. ej. suscrito a todo en un despliegue con
# mucho tráfico) desplazase el historial de los demás: la ventana de
# diagnóstico de 500 líneas se la comía un solo receptor y el admin dejaba
# de ver por qué el receptor silencioso no recibía nada. Con el techo por
# receptor (aplicado también al canal heredado "entorno") la ventana es
# equitativa; la poda global se conserva como guarda del tamaño total.
MAX_ENTREGAS_RECEPTOR = 100

# z2 (ronda 6): los pings de prueba (webhook.prueba) tienen CUOTA PROPIA
# dentro del techo por receptor: el botón Probar es manual y un operador
# que lo martillea no debe desplazar (dentro de su techo de 100) las
# entregas REALES del propio receptor — que son justo lo que se necesita
# diagnosticar cuando se usa el ping. Cuota menor y separada: el historial
# de pings útil es corto (¿responde? ¿con qué HTTP?).
MAX_PINGS_RECEPTOR = 20


def _ruta_db() -> Path:
    """Misma BD de despliegue que la autenticación (usuarios.db)."""
    from .auth import RUTA_DB

    return Path(RUTA_DB)


def _conexion() -> sqlite3.Connection:
    conn = sqlite3.connect(str(_ruta_db()), timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=5000")
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS webhooks (
            id TEXT PRIMARY KEY,
            url TEXT NOT NULL,
            secreto TEXT NOT NULL DEFAULT '',
            eventos TEXT NOT NULL DEFAULT '[]',
            activo INTEGER NOT NULL DEFAULT 1,
            descripcion TEXT NOT NULL DEFAULT '',
            creado_en TEXT NOT NULL,
            actualizado_en TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS webhook_entregas (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            webhook_id TEXT NOT NULL,
            evento TEXT NOT NULL,
            engagement_id TEXT NOT NULL DEFAULT '',
            ok INTEGER NOT NULL,
            http INTEGER,
            error TEXT,
            intentos INTEGER NOT NULL DEFAULT 1,
            creado_en TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_webhook_entregas_wh
            ON webhook_entregas(webhook_id, id DESC);
    """)
    conn.commit()
    return conn


# --- validación -------------------------------------------------------------

def _veto_por_resolucion(host: str) -> None:
    """Veto anti-SSRF por IP (directa o resuelta). Lanza ValueError.

    Capas compartidas por el ALTA (validar_url) y el DESPACHO (_entregar):
    1. nombre textual de metadatos (rápido, sin red);
    2. el host ES una IP vetada en forma alternativa (decimal, hex, octal,
       IPv6 mapeada — urlparse NO la normaliza; la resolución sí);
    3. resolución DNS real — el nombre podía ocultar una IP link-local.
    Un host aún no resoluble se admite: no puede alcanzar metadatos y la
    entrega fallará de forma natural (registrada en el historial).
    Escape documentado (z3): WEBHOOK_PERMITIR_METADATOS=1 desactiva el veto.
    """
    if not _veto_metadatos_activo():
        return
    host_l = (host or "").lower().rstrip(".")
    if host_l in _HOSTS_VETADOS:
        raise ValueError("receptor no permitido: endpoints de metadatos de nube vetados")
    try:
        ip_directa = ipaddress.ip_address(host_l)
    except ValueError:
        ip_directa = None
    if ip_directa is not None and _ip_vetada(ip_directa):
        raise ValueError("receptor no permitido: endpoints de metadatos de nube vetados")
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return
    for info in infos:
        try:
            ip = ipaddress.ip_address(info[4][0])
        except ValueError:
            continue
        if _ip_vetada(ip):
            raise ValueError(
                "receptor no permitido: el host resuelve a una IP de "
                "metadatos de nube (link-local vetada)")


def validar_url(url: str) -> str:
    """Valida la URL del receptor y la devuelve normalizada (str.strip).

    Exige http/https y host; veta los endpoints de metadatos de nube por
    nombre Y por IP directa y resuelta (un chequeo solo textual era
    saltable con formas alternativas de la misma IP). Lanza ValueError
    con mensaje accionable (el endpoint lo traduce a 422).
    """
    limpio = (url or "").strip()
    partes = urlparse(limpio)
    if partes.scheme not in ("http", "https"):
        raise ValueError("la URL debe usar http:// o https://")
    host = partes.hostname or ""
    if not host:
        raise ValueError("la URL necesita un host (p. ej. https://n8n.interno/webhook)")
    _veto_por_resolucion(host)
    return limpio


def validar_eventos(eventos: list[str]) -> list[str]:
    """Valida la suscripción: lista no vacía de eventos conocidos, sin duplicados."""
    limpios = [e.strip() for e in eventos if e and e.strip()]
    if not limpios:
        raise ValueError("selecciona al menos un evento")
    desconocidos = [e for e in limpios if e not in EVENTOS]
    if desconocidos:
        raise ValueError(f"eventos desconocidos: {', '.join(desconocidos)}")
    return list(dict.fromkeys(limpios))


# --- CRUD de receptores (sin secretos en las lecturas) ----------------------

def _fila_publica(f: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": f["id"],
        "url": f["url"],
        "eventos": json.loads(f["eventos"]),
        "activo": bool(f["activo"]),
        "descripcion": f["descripcion"],
        "tiene_secreto": bool(f["secreto"]),
        "creado_en": f["creado_en"],
        "actualizado_en": f["actualizado_en"],
    }


def listar_webhooks() -> list[dict[str, Any]]:
    with _conexion() as conn:
        filas = conn.execute("SELECT * FROM webhooks ORDER BY creado_en").fetchall()
    return [_fila_publica(f) for f in filas]


def crear_webhook(url: str, eventos: list[str], secreto: str = "",
                  descripcion: str = "") -> dict[str, Any]:
    """Alta de receptor. Si el secreto llega vacío se genera uno fuerte y se
    devuelve UNA VEZ (nunca vuelve a salir de la BD)."""
    url_ok = validar_url(url)
    eventos_ok = validar_eventos(eventos)
    if secreto and len(secreto) < 16:
        raise ValueError("el secreto debe tener al menos 16 caracteres")
    nuevo = {
        "id": f"whk_{uuid.uuid4().hex[:12]}",
        "url": url_ok,
        "secreto": secreto.strip() or secrets.token_hex(32),
        "eventos": eventos_ok,
        "activo": 1,
        "descripcion": (descripcion or "").strip()[:200],
        "creado_en": datetime.now(timezone.utc).isoformat(),
        "actualizado_en": datetime.now(timezone.utc).isoformat(),
    }
    with _conexion() as conn:
        conn.execute(
            "INSERT INTO webhooks (id, url, secreto, eventos, activo, descripcion,"
            " creado_en, actualizado_en) VALUES (?,?,?,?,?,?,?,?)",
            (nuevo["id"], nuevo["url"], nuevo["secreto"],
             json.dumps(nuevo["eventos"]), nuevo["activo"],
             nuevo["descripcion"], nuevo["creado_en"], nuevo["actualizado_en"]))
    publico = {k: v for k, v in nuevo.items() if k != "secreto"}
    publico["tiene_secreto"] = True
    publico["secreto_generado"] = nuevo["secreto"]  # SOLO en la respuesta de alta
    return publico


def actualizar_webhook(webhook_id: str, url: str | None = None,
                       eventos: list[str] | None = None,
                       activo: bool | None = None,
                       descripcion: str | None = None,
                       secreto: str | None = None) -> dict[str, Any]:
    """Actualización parcial. Un secreto nuevo sustituye al anterior."""
    cambios: dict[str, Any] = {}
    if url is not None:
        cambios["url"] = validar_url(url)
    if eventos is not None:
        cambios["eventos"] = json.dumps(validar_eventos(eventos))
    if activo is not None:
        cambios["activo"] = 1 if activo else 0
    if descripcion is not None:
        cambios["descripcion"] = descripcion.strip()[:200]
    if secreto is not None and secreto.strip():
        if len(secreto.strip()) < 16:
            raise ValueError("el secreto debe tener al menos 16 caracteres")
        cambios["secreto"] = secreto.strip()
    if not cambios:
        raise ValueError("nada que actualizar")
    cambios["actualizado_en"] = datetime.now(timezone.utc).isoformat()
    with _conexion() as conn:
        cur = conn.execute(
            f"UPDATE webhooks SET {', '.join(k + '=?' for k in cambios)} WHERE id=?",
            (*cambios.values(), webhook_id))
        if cur.rowcount != 1:
            raise LookupError(f"webhook {webhook_id} no existe")
        fila = conn.execute("SELECT * FROM webhooks WHERE id=?",
                            (webhook_id,)).fetchone()
    return _fila_publica(fila)


def eliminar_webhook(webhook_id: str) -> None:
    """Baja del receptor y de su registro de entregas (higiene de datos)."""
    with _conexion() as conn:
        cur = conn.execute("DELETE FROM webhooks WHERE id=?", (webhook_id,))
        if cur.rowcount != 1:
            raise LookupError(f"webhook {webhook_id} no existe")
        conn.execute("DELETE FROM webhook_entregas WHERE webhook_id=?",
                     (webhook_id,))


# --- entrega real -----------------------------------------------------------

def firmar(cuerpo: bytes, secreto: str) -> str:
    return "sha256=" + hmac.new(secreto.encode(), cuerpo, hashlib.sha256).hexdigest()


def _cuerpo(evento: str, engagement_id: str, entrega: str, carga: dict[str, Any]) -> bytes:
    return json.dumps(
        {"evento": evento, "engagement_id": engagement_id,
         "entrega": entrega, "ts": datetime.now(timezone.utc).isoformat(),
         **carga},
        ensure_ascii=False, default=str).encode()


def _post(url: str, cuerpo: bytes, cabeceras_extra: dict[str, str]) -> dict[str, Any]:
    try:
        import httpx
        cabeceras = {"Content-Type": "application/json",
                     "User-Agent": "OrquestaRT-Webhook/1", **cabeceras_extra}
        # z3 (auditoría) + z2 (ronda 2): follow_redirects DESACTIVADO. Con
        # redirecciones activas, un receptor comprometido hacía 302 hacia
        # http://169.254.169.254/... y saltaba la vetación de validar_url
        # (el cliente HTTP resolvía la redirección sin revalidar) — el POST
        # FIRMADO viajaba al destino tras el salto. Un 3xx se reporta como
        # fallo de entrega con diagnóstico claro y SIN reintento. Si tu
        # receptor redirige http→https, da de alta la URL https directa.
        with httpx.Client(timeout=5.0, follow_redirects=False) as cliente:
            r = cliente.post(url, content=cuerpo, headers=cabeceras)
        if 300 <= r.status_code < 400:
            return {"ok": False, "http": r.status_code,
                    "error": "el receptor redirige: los webhooks deben "
                             "apuntar al endpoint final (sin 3xx)"}
        return {"ok": 200 <= r.status_code < 300, "http": r.status_code, "error": None}
    except Exception as exc:
        return {"ok": False, "http": None, "error": str(exc)[:200]}


def _entregar(webhook_id: str, url: str, secreto: str, evento: str,
              engagement_id: str, carga: dict[str, Any]) -> dict[str, Any]:
    """Entrega con UN reintento (t+2 s) ante 5xx o error de red. Cada intento
    usa un cuerpo NUEVO (ts distinto) y por tanto firma nueva.

    Antes de conectar se re-verifica el veto SSRF (capa de despacho): el
    alta pudo ser hace días y el DNS puede haber cambiado (rebinding), y
    el canal heredado WEBHOOK_URL nunca pasó por validar_url. Un receptor
    vetado no consume ni un intento y queda registrado en el historial.
    """
    entrega = uuid.uuid4().hex
    intentos = 0
    resultado: dict[str, Any] = {"ok": False, "http": None, "error": None}
    try:
        _veto_por_resolucion(urlparse(url).hostname or "")
    except ValueError as exc:
        error = str(exc)[:200]
        _registrar_entrega(webhook_id, evento, engagement_id,
                           False, None, error, 0)
        return {"ok": False, "http": None, "error": error}
    for intento in (1, 2):
        intentos = intento
        cuerpo = _cuerpo(evento, engagement_id, entrega, carga)
        cabeceras = {
            "X-Orquesta-Firma": firmar(cuerpo, secreto) if secreto else "",
            "X-Orquesta-Evento": evento,
            "X-Orquesta-Entrega": entrega,
            # z2 (ronda 3): nº de intento dentro de la MISMA entrega — la
            # entrega (uuid) es idéntica en el reintento; sin esta cabecera el
            # receptor no puede distinguir un reintento de un envío original
            # y su idempotencia (o su SIEM) puede duplicar la alerta.
            "X-Orquesta-Intento": str(intento),
            "X-Orquesta-Id": engagement_id,
        }
        cabeceras = {k: v for k, v in cabeceras.items() if v}
        resultado = _post(url, cuerpo, cabeceras)
        # Contrato documentado: reintentar UNA vez ante 5xx O ERROR DE RED.
        # Antes, un error de red (http=None) entraba por (None or 0) < 500
        # y se ROMPIA el bucle: el reintento estaba muerto y un blip de red
        # perdía el evento en silencio (incluido aprobacion.solicitada).
        reintentable = (resultado["http"] is None
                        or (resultado["http"] or 0) >= 500)
        if resultado["ok"] or not reintentable:
            break  # éxito o respuesta firme del receptor (4xx): no reintentar
        if intento < 2:
            time.sleep(2.0)  # solo si queda un intento: no dormir en balde
    _registrar_entrega(webhook_id, evento, engagement_id,
                       resultado["ok"], resultado["http"],
                       resultado["error"], intentos)
    return resultado


def _registrar_entrega(webhook_id: str, evento: str, engagement_id: str,
                       ok: bool, http: int | None, error: str | None,
                       intentos: int) -> None:
    try:
        with _conexion() as conn:
            conn.execute(
                "INSERT INTO webhook_entregas (webhook_id, evento, engagement_id,"
                " ok, http, error, intentos, creado_en) VALUES (?,?,?,?,?,?,?,?)",
                (webhook_id, evento, engagement_id, 1 if ok else 0, http,
                 error, intentos, datetime.now(timezone.utc).isoformat()))
            # Poda por RECEPTOR (z2, ronda 5) en dos cuotas separadas
            # (z2, ronda 6): las entregas REALES conservan las últimas
            # MAX_ENTREGAS_RECEPTOR y los pings de prueba la suya
            # (MAX_PINGS_RECEPTOR) — martillear el botón Probar no desplaza
            # el historial real del propio receptor. Aplica también al
            # canal heredado ("entorno"), que no tiene fila en la tabla
            # webhooks pero sí entregas con su id.
            conn.execute(
                "DELETE FROM webhook_entregas WHERE webhook_id=?"
                " AND evento != 'webhook.prueba' AND id NOT IN "
                "(SELECT id FROM webhook_entregas WHERE webhook_id=?"
                " AND evento != 'webhook.prueba' ORDER BY id DESC LIMIT ?)",
                (webhook_id, webhook_id, MAX_ENTREGAS_RECEPTOR))
            conn.execute(
                "DELETE FROM webhook_entregas WHERE webhook_id=?"
                " AND evento = 'webhook.prueba' AND id NOT IN "
                "(SELECT id FROM webhook_entregas WHERE webhook_id=?"
                " AND evento = 'webhook.prueba' ORDER BY id DESC LIMIT ?)",
                (webhook_id, webhook_id, MAX_PINGS_RECEPTOR))
            # Poda GLOBAL: guarda del tamaño total del registro (despliegue).
            conn.execute(
                "DELETE FROM webhook_entregas WHERE id NOT IN "
                "(SELECT id FROM webhook_entregas ORDER BY id DESC LIMIT ?)",
                (MAX_ENTREGAS,))
    except sqlite3.Error:
        pass  # el registro de entregas nunca rompe el flujo operacional


def _receptores_de(evento: str) -> list[tuple[str, str, str]]:
    """(id, url, secreto) de los receptores activos suscritos al evento,
    más el canal heredado del entorno si aplica (sin duplicar URLs)."""
    try:
        with _conexion() as conn:
            filas = conn.execute(
                "SELECT id, url, secreto, eventos FROM webhooks WHERE activo=1"
            ).fetchall()
    except sqlite3.Error:
        filas = []
    receptores: list[tuple[str, str, str]] = []
    urls = set()
    for f in filas:
        if evento in json.loads(f["eventos"]):
            receptores.append((f["id"], f["url"], f["secreto"]))
            urls.add(f["url"])
    heredado = os.environ.get("WEBHOOK_URL", "").strip()
    if heredado and heredado not in urls:
        receptores.append(("entorno", heredado, os.environ.get("WEBHOOK_SECRETO", "")))
    return receptores


def despachar(evento: str, engagement_id: str, carga: dict[str, Any]) -> int:
    """Entrega el evento a todos los receptores suscritos (bloqueante).
    Devuelve el número de entregas realizadas. Nunca lanza."""
    if evento not in EVENTOS:
        return 0
    entregas = 0
    for webhook_id, url, secreto in _receptores_de(evento):
        try:
            r = _entregar(webhook_id, url, secreto, evento, engagement_id, carga)
            if r["ok"]:
                entregas += 1
        except Exception:
            continue
    return entregas


def despachar_en_segundo_plano(evento: str, engagement_id: str,
                               carga: dict[str, Any]) -> None:
    """Dispara la notificación sin bloquear el ciclo del orquestador.
    El receptor lento jamás retrasa la operación del caso."""
    threading.Thread(target=despachar, args=(evento, engagement_id, carga),
                     daemon=True).start()


def entregas_de(webhook_id: str, limite: int = 20) -> list[dict[str, Any]]:
    """Últimas entregas del receptor (más reciente primero), acotadas [1, 100]."""
    acotado = min(max(limite, 1), 100)
    with _conexion() as conn:
        filas = conn.execute(
            "SELECT webhook_id, evento, engagement_id, ok, http, error, intentos,"
            " creado_en FROM webhook_entregas WHERE webhook_id=?"
            " ORDER BY id DESC LIMIT ?", (webhook_id, acotado)).fetchall()
    return [dict(f) | {"ok": bool(f["ok"])} for f in filas]


def entregas_24h_por_receptor() -> dict[str, dict[str, int]]:
    """z2 (ronda 6): entregas y fallos de las últimas 24 h por receptor.

    Fuente: `webhook_entregas` (la misma que pinta el desplegable del
    historial). Los receptores SIN entregas en la ventana no aparecen en
    el resultado: quien decora (api.py) pone ceros — el JSON nunca miente
    pero tampoco inventa actividad.
    """
    corte = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
    try:
        with _conexion() as conn:
            filas = conn.execute(
                "SELECT webhook_id, COUNT(*) AS total, "
                "SUM(CASE WHEN ok=0 THEN 1 ELSE 0 END) AS fallos "
                "FROM webhook_entregas WHERE creado_en >= ? "
                "GROUP BY webhook_id", (corte,)).fetchall()
    except sqlite3.Error:
        return {}
    return {f["webhook_id"]: {"entregas_24h": f["total"],
                              "fallos_24h": f["fallos"] or 0}
            for f in filas}


def probar_webhook(webhook_id: str) -> dict[str, Any]:
    """Ping REAL de prueba (sincrónico: el operador ve el resultado ahora)."""
    with _conexion() as conn:
        f = conn.execute("SELECT id, url, secreto FROM webhooks WHERE id=?",
                         (webhook_id,)).fetchone()
    if f is None:
        raise LookupError(f"webhook {webhook_id} no existe")
    r = _entregar(f["id"], f["url"], f["secreto"], "webhook.prueba",
                  "prueba", {"mensaje": "Ping de prueba del orquestador — "
                                        "si lees esto, el receptor funciona"})
    return {"enviado": r["ok"], "http": r["http"], "error": r["error"]}


# --- estado y compatibilidad con el canal heredado --------------------------

def configurado() -> bool:
    """¿Hay algún canal de notificación (receptores en BD o entorno)?"""
    try:
        with _conexion() as conn:
            n = conn.execute("SELECT COUNT(*) c FROM webhooks WHERE activo=1").fetchone()["c"]
    except sqlite3.Error:
        n = 0
    return bool(n) or bool(os.environ.get("WEBHOOK_URL", ""))


def estado() -> dict[str, Any]:
    """Estado visible en la consola (sin secretos)."""
    try:
        with _conexion() as conn:
            activos = conn.execute(
                "SELECT COUNT(*) c FROM webhooks WHERE activo=1").fetchone()["c"]
    except sqlite3.Error:
        activos = 0
    url = os.environ.get("WEBHOOK_URL", "")
    # z2 (ronda 5): resumen honesto cuando coexisten los dos canales — antes
    # la URL del entorno TAPABA el recuento de receptores de BD (`url or ...`)
    # y un despliegue con ambos parecía tener solo el canal heredado.
    canales = ([url] if url else []) \
        + ([f"{activos} receptor(es) en BD"] if activos else [])
    return {
        "configurado": bool(activos) or bool(url),
        "detalle": "POST real firmado (HMAC-SHA256) con registro de entregas · "
                   "receptores configurables en Integraciones (admin)",
        "servidor": " + ".join(canales),
        "firmado": True,
        "receptores_activos": activos,
        "canal_heredado": bool(url),
        "eventos": list(EVENTOS),
    }


def canal_heredado_estado() -> dict[str, Any]:
    """z2 (ronda 4): estado del canal heredado para la consola (admin).

    El canal heredado (WEBHOOK_URL) no vive en la BD: sus entregas se
    registran bajo el identificador literal "entorno" y por eso no aparecía
    entre los receptores de la vista Webhooks — el operador no podía ver si
    el entorno tenía un canal activo ni sus entregas."""
    url = os.environ.get("WEBHOOK_URL", "").strip()
    return {"activo": bool(url), "url": url}
