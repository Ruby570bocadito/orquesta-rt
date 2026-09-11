"""Notificación webhook REAL de eventos operativos (v16).

Los receptores los configura el admin en la consola (BD del despliegue,
tabla `webhooks`): cada receptor se suscribe a los eventos que le interesen
y el orquestador le entrega un POST HTTP real firmado, con registro de
entregas y un reintento ante fallo transitorio:

    X-Orquesta-Firma:  sha256=<HMAC-SHA256(cuerpo, secreto_del_receptor)>
    X-Orquesta-Evento: hallazgo.registrado | ...
    X-Orquesta-Entrega: id único de entrega (cabecera de idempotencia)
    X-Orquesta-Id:      engagement al que pertenece el evento

Prácticas del sector (Stripe/GitHub/Svix): firma HMAC-SHA256 sobre el
cuerpo crudo, cabecera de tipo de evento, identificador de entrega y
registro de resultados. El reintento es UNO (t+2 s) solo ante 5xx o error
de red: un webhook operacional avisa, no bloquea nunca al orquestador.

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
import json
import os
import secrets
import sqlite3
import threading
import time
import uuid
from datetime import datetime, timezone
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
    "webhook.prueba",
)

# Redes de metadatos de nube vetadas como receptor (SSRF): el webhook es
# una configuración de admin, pero el límite link-local es defense-in-depth.
_HOSTS_VETADOS = {"metadata.google.internal"}
_CIDRS_VETADOS = ("169.254.",)

MAX_ENTREGAS = 500  # poda del registro de entregas por despliegue


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

def validar_url(url: str) -> str:
    """Valida la URL del receptor y la devuelve normalizada (str.strip).

    Exige http/https y host; veta los endpoints de metadatos de nube.
    Lanza ValueError con mensaje accionable (el endpoint lo traduce a 422).
    """
    limpio = (url or "").strip()
    partes = urlparse(limpio)
    if partes.scheme not in ("http", "https"):
        raise ValueError("la URL debe usar http:// o https://")
    host = partes.hostname or ""
    if not host:
        raise ValueError("la URL necesita un host (p. ej. https://n8n.interno/webhook)")
    if host.lower() in _HOSTS_VETADOS or host.startswith(_CIDRS_VETADOS):
        raise ValueError("receptor no permitido: endpoints de metadatos de nube vetados")
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
        with httpx.Client(timeout=5.0, follow_redirects=True) as cliente:
            r = cliente.post(url, content=cuerpo, headers=cabeceras)
        return {"ok": 200 <= r.status_code < 300, "http": r.status_code, "error": None}
    except Exception as exc:
        return {"ok": False, "http": None, "error": str(exc)[:200]}


def _entregar(webhook_id: str, url: str, secreto: str, evento: str,
              engagement_id: str, carga: dict[str, Any]) -> dict[str, Any]:
    """Entrega con UN reintento (t+2 s) ante 5xx o error de red. Cada intento
    usa un cuerpo NUEVO (ts distinto) y por tanto firma nueva."""
    entrega = uuid.uuid4().hex
    intentos = 0
    resultado: dict[str, Any] = {"ok": False, "http": None, "error": None}
    for intento in (1, 2):
        intentos = intento
        cuerpo = _cuerpo(evento, engagement_id, entrega, carga)
        cabeceras = {
            "X-Orquesta-Firma": firmar(cuerpo, secreto) if secreto else "",
            "X-Orquesta-Evento": evento,
            "X-Orquesta-Entrega": entrega,
            "X-Orquesta-Id": engagement_id,
        }
        cabeceras = {k: v for k, v in cabeceras.items() if v}
        resultado = _post(url, cuerpo, cabeceras)
        if resultado["ok"] or (resultado["http"] or 0) < 500:
            break  # éxito, 4xx del receptor o respuesta firme: no reintentar
        time.sleep(2.0)
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
            # Poda: conserva las últimas MAX_ENTREGAS del despliegue.
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
    return {
        "configurado": bool(activos) or bool(url),
        "detalle": "POST real firmado (HMAC-SHA256) con registro de entregas · "
                   "receptores configurables en Integraciones (admin)",
        "servidor": url or (f"{activos} receptor(es) en BD" if activos else ""),
        "firmado": True,
        "receptores_activos": activos,
        "canal_heredado": bool(url),
        "eventos": list(EVENTOS),
    }
