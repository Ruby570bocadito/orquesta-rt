"""Memoria del caso: SQLite cifrable + cadena de custodia de evidencias.

Principios de diseño (capítulos 2 y 5 del blueprint):
- Trazabilidad total: registro inmutable (append-only) de toda acción.
- Evidencias verificables: SHA-256 + firma HMAC encadenada por caso.
- Higiene: bóveda de credenciales con caducidad y certificado de borrado.

SQLite es la elección M1: cero dependencias externas, un fichero por caso,
cifrado en reposo asumible con SQLCipher o cifrado a nivel de volumen.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from .models import (
    Aprobacion,
    Actor,
    DecisionGuardrail,
    Evidencia,
    EventoAuditoria,
    Fase,
    Hallazgo,
    Objetivo,
    ResumenFase,
    ROEPolitica,
    Severidad,
    UsoTokens,
)

SCHEMA = """
CREATE TABLE IF NOT EXISTS engagements (
    id TEXT PRIMARY KEY,
    nombre TEXT NOT NULL,
    cliente TEXT NOT NULL,
    roe_json TEXT NOT NULL,
    fase_actual TEXT NOT NULL,
    estado_fase TEXT NOT NULL,
    tenant_id TEXT NOT NULL DEFAULT 'predeterminada',
    presupuesto_tokens_json TEXT NOT NULL DEFAULT '{}',
    coste_acumulado_usd REAL NOT NULL DEFAULT 0,
    tokens_acumulados INTEGER NOT NULL DEFAULT 0,
    certificado_borrado TEXT,
    creado_en TEXT NOT NULL,
    actualizado_en TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS hallazgos (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL,
    titulo TEXT NOT NULL,
    severidad TEXT NOT NULL,
    tecnica_mitre TEXT,
    activo TEXT DEFAULT '',
    descripcion TEXT DEFAULT '',
    recomendacion TEXT DEFAULT '',
    estado TEXT NOT NULL DEFAULT 'propuesto',
    deteccion TEXT NOT NULL DEFAULT 'pendiente',
    evidencias_json TEXT NOT NULL DEFAULT '[]',
    creado_por TEXT NOT NULL,
    creado_en TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS evidencias (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL,
    tipo TEXT NOT NULL,
    titulo TEXT NOT NULL,
    contenido TEXT DEFAULT '',
    hash_sha256 TEXT NOT NULL,
    firma_hmac TEXT NOT NULL,
    hash_previo TEXT NOT NULL DEFAULT '',
    fase TEXT NOT NULL,
    actor TEXT NOT NULL,
    hallazgo_id TEXT,
    creado_en TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS aprobaciones (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL,
    fase TEXT NOT NULL,
    titulo TEXT NOT NULL,
    descripcion TEXT DEFAULT '',
    herramienta TEXT DEFAULT '',
    argumentos_json TEXT DEFAULT '{}',
    tecnica_mitre TEXT,
    riesgo TEXT NOT NULL,
    ruido_estimado INTEGER DEFAULT 50,
    motivo TEXT DEFAULT '',
    referencia_roe TEXT DEFAULT '',
    estado TEXT NOT NULL DEFAULT 'pendiente',
    decidida_por TEXT,
    comentario_operador TEXT DEFAULT '',
    creada_en TEXT NOT NULL,
    decidida_en TEXT
);

CREATE TABLE IF NOT EXISTS uso_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id TEXT NOT NULL,
    fase TEXT NOT NULL,
    modelo TEXT NOT NULL,
    tipo_modelo TEXT NOT NULL,
    tokens_entrada INTEGER NOT NULL,
    tokens_salida INTEGER NOT NULL,
    cache_hit INTEGER NOT NULL DEFAULT 0,
    coste_usd REAL NOT NULL DEFAULT 0,
    creado_en TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS auditoria (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL,
    actor TEXT NOT NULL,
    accion TEXT NOT NULL,
    detalle TEXT DEFAULT '',
    herramienta TEXT DEFAULT '',
    parametros_hash TEXT DEFAULT '',
    resultado TEXT DEFAULT '',
    guardrail TEXT,
    creado_en TEXT NOT NULL
);
-- El registro de auditoría es append-only: se bloquea UPDATE/DELETE por
-- política del proceso (triggers defensivos).
CREATE TRIGGER IF NOT EXISTS auditoria_no_update
    BEFORE UPDATE ON auditoria
BEGIN
    SELECT RAISE(ABORT, 'auditoria es append-only');
END;
CREATE TRIGGER IF NOT EXISTS auditoria_no_delete
    BEFORE DELETE ON auditoria
BEGIN
    SELECT RAISE(ABORT, 'auditoria es append-only');
END;

CREATE TABLE IF NOT EXISTS objetivos (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL,
    nombre TEXT NOT NULL,
    tipo TEXT NOT NULL,
    estado TEXT NOT NULL DEFAULT 'descubierto',
    detalle TEXT DEFAULT '',
    fase TEXT NOT NULL,
    severidad TEXT,
    tecnica_mitre TEXT,
    descubierto_en TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS resumenes_fase (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id TEXT NOT NULL,
    fase TEXT NOT NULL,
    texto TEXT NOT NULL,
    hallazgos_clave_json TEXT DEFAULT '[]',
    tokens_ahorrados_estimados INTEGER DEFAULT 0,
    creado_en TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_auditoria_caso ON auditoria(engagement_id, creado_en);
CREATE INDEX IF NOT EXISTS idx_evidencias_caso ON evidencias(engagement_id, creado_en);
CREATE INDEX IF NOT EXISTS idx_hallazgos_caso ON hallazgos(engagement_id);
CREATE INDEX IF NOT EXISTS idx_aprobaciones_estado ON aprobaciones(engagement_id, estado);
CREATE INDEX IF NOT EXISTS idx_objetivos_caso ON objetivos(engagement_id, tipo);
CREATE INDEX IF NOT EXISTS idx_objetivos_descubrimiento ON objetivos(engagement_id, descubierto_en);

CREATE TABLE IF NOT EXISTS config_caso (
    engagement_id TEXT NOT NULL,
    clave TEXT NOT NULL,
    valor TEXT NOT NULL,
    actualizado_en TEXT NOT NULL,
    PRIMARY KEY (engagement_id, clave)
);

CREATE TABLE IF NOT EXISTS razonamientos (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL,
    tipo TEXT NOT NULL,
    fase TEXT NOT NULL,
    entrada_json TEXT NOT NULL,
    entrada_hash TEXT NOT NULL,
    salida_json TEXT NOT NULL,
    salida_hash TEXT NOT NULL,
    modelo TEXT NOT NULL,
    tipo_modelo TEXT NOT NULL,
    tokens_entrada INTEGER NOT NULL DEFAULT 0,
    tokens_salida INTEGER NOT NULL DEFAULT 0,
    coste_usd REAL NOT NULL DEFAULT 0,
    confianza REAL,
    creado_en TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_razonamientos_caso ON razonamientos(engagement_id, tipo, creado_en);
"""


def _ts(dt: datetime | None = None) -> str:
    dt = dt or datetime.now(timezone.utc)
    return dt.isoformat()


class MemoriaCaso:
    """DAO del caso. Un fichero SQLite por engagement (aislamiento por cliente)."""

    def __init__(self, db_path: str | Path, clave_caso: str | None = None):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        # Clave HMAC del caso: para firmar evidencias. En producción viene del
        # gestor de secretos on-prem (Vault / SOPS); nunca se guarda en la BD.
        self.clave_caso = (clave_caso or os.environ.get("CLAVE_CASO", "")).encode()
        if not self.clave_caso:
            # Clase de desarrollo: clave derivada de la ruta. En producción se
            # exige CLAVE_CASO y la ausencia es un fallo de arranque.
            self.clave_caso = hashlib.sha256(str(self.db_path).encode()).hexdigest().encode()[:32]
        # z3 (auditoría seguridad): claves LEGADAS, solo para VERIFICAR
        # evidencias existentes firmadas antes de una rotación de clave
        # (p. ej. la clave hardcodeada histórica de los despliegues dev).
        # JAMÁS se usan para firmar evidencias nuevas: la firma siempre sale
        # de self.clave_caso. Configurables vía CLAVES_CASO_LEGADO (coma).
        legadas = os.environ.get("CLAVES_CASO_LEGADO", "")
        self.claves_legado = tuple(
            c.strip().encode() for c in legadas.split(",") if c.strip())
        self._conn = sqlite3.connect(str(self.db_path), timeout=10)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        # Optimización de producción: WAL + synchronous NORMAL mantiene la
        # durabilidad ante fallos de proceso con I/O sustancialmente menor
        # (solo checkpoint/compactación fuerza fsync completo).
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        # Concurrencia real: el flujo SSE y los hilos del threadpool de la
        # API tocan el mismo fichero SQLite. busy_timeout convierte el error
        # "database is locked" en una espera corta (hasta 5 s) encolaando
        # escritores en vez de fallar la petición del operador.
        self._conn.execute("PRAGMA busy_timeout=5000")
        self._conn.executescript(SCHEMA)
        # v23 modo continuo CTEM: tablas de programas y corridas (migración
        # idempotente — CREATE TABLE IF NOT EXISTS en BDs ya abiertas).
        from .ctem import crear_tablas as _ctem_tablas
        _ctem_tablas(self._conn)
        # -- migraciones incrementales --------------------------------------
        # Casos creados antes de la columna `deteccion` (purple teaming):
        # ALTER TABLE idempotente guiado por table_info (CREATE TABLE IF NOT
        # EXISTS no añade columnas a BDs existentes).
        _cols_hallazgos = {fila[1] for fila in self._conn.execute(
            "PRAGMA table_info(hallazgos)")}
        if "deteccion" not in _cols_hallazgos:
            self._conn.execute(
                "ALTER TABLE hallazgos ADD COLUMN deteccion TEXT NOT NULL "
                "DEFAULT 'pendiente'")
        # v21 multi-tenant: los casos preexistentes quedan en la organización
        # por defecto (mismo comportamiento observable que antes del cambio).
        _cols_eng = {fila[1] for fila in self._conn.execute(
            "PRAGMA table_info(engagements)")}
        if "tenant_id" not in _cols_eng:
            self._conn.execute(
                "ALTER TABLE engagements ADD COLUMN tenant_id TEXT NOT NULL "
                "DEFAULT 'predeterminada'")
        self._conn.commit()

    # -- utilidades ----------------------------------------------------------

    @staticmethod
    def _ts_static() -> str:
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def nuevo_id(prefijo: str) -> str:
        return f"{prefijo}_{uuid.uuid4().hex[:12]}"

    @staticmethod
    def hash_objeto(obj: Any) -> str:
        return hashlib.sha256(
            json.dumps(obj, sort_keys=True, ensure_ascii=False).encode()
        ).hexdigest()

    def _firma(self, hash_contenido: str) -> str:
        return hmac.new(self.clave_caso, hash_contenido.encode(), hashlib.sha256).hexdigest()

    def _firma_valida(self, hash_contenido: str, firma_hmac: str) -> bool:
        """z3 (auditoría seguridad): verificación de firma con rotación de
        clave. Valida contra la clave VIGENTE y, si no coincide, contra las
        claves legadas (CLAVES_CASO_LEGADO) para no invalidar la cadena de
        custodia de evidencias firmadas antes de una rotación. La firma de
        evidencias NUEVAS siempre usa la clave vigente."""
        if hmac.compare_digest(self._firma(hash_contenido), firma_hmac):
            return True
        for clave in getattr(self, "claves_legado", ()):
            if hmac.compare_digest(
                    hmac.new(clave, hash_contenido.encode(),
                             hashlib.sha256).hexdigest(), firma_hmac):
                return True
        return False

    # -- engagement ----------------------------------------------------------

    def crear_engagement(self, eng) -> None:
        tenant_id = getattr(eng, "tenant_id", None) or "predeterminada"
        self._conn.execute(
            "INSERT INTO engagements (id, nombre, cliente, roe_json, "
            "fase_actual, estado_fase, tenant_id, presupuesto_tokens_json, "
            "coste_acumulado_usd, tokens_acumulados, certificado_borrado, "
            "creado_en, actualizado_en) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                eng.id, eng.nombre, eng.cliente, eng.roe.model_dump_json(),
                eng.fase_actual.value, eng.estado_fase.value, tenant_id,
                json.dumps(eng.presupuesto_tokens), eng.coste_acumulado_usd,
                eng.tokens_acumulados, eng.certificado_borrado,
                _ts(eng.creado_en), _ts(eng.actualizado_en),
            ),
        )
        self._conn.commit()

    def obtener_engagement(self, engagement_id: str) -> Optional[sqlite3.Row]:
        cur = self._conn.execute("SELECT * FROM engagements WHERE id=?", (engagement_id,))
        return cur.fetchone()

    def listar_engagements(self) -> list[sqlite3.Row]:
        return list(self._conn.execute("SELECT * FROM engagements ORDER BY creado_en DESC"))

    def actualizar_fase(self, engagement_id: str, fase: Fase, estado: str) -> None:
        self._conn.execute(
            "UPDATE engagements SET fase_actual=?, estado_fase=?, actualizado_en=? WHERE id=?",
            (fase.value, estado, _ts(), engagement_id),
        )
        self._conn.commit()

    # -- auditoría (append-only) ---------------------------------------------

    def registrar_auditoria(
        self,
        engagement_id: str,
        actor: Actor,
        accion: str,
        detalle: str = "",
        herramienta: str = "",
        parametros: Any = None,
        resultado: str = "ok",
        guardrail: DecisionGuardrail | None = None,
    ) -> EventoAuditoria:
        ev = EventoAuditoria(
            id=self.nuevo_id("aud"),
            engagement_id=engagement_id,
            actor=actor,
            accion=accion,
            detalle=detalle,
            herramienta=herramienta,
            parametros_hash=self.hash_objeto(parametros) if parametros else "",
            resultado=resultado,
            guardrail=guardrail,
        )
        self._conn.execute(
            "INSERT INTO auditoria VALUES (?,?,?,?,?,?,?,?,?,?)",
            (ev.id, ev.engagement_id, ev.actor.value, ev.accion, ev.detalle,
             ev.herramienta, ev.parametros_hash, ev.resultado,
             ev.guardrail.value if ev.guardrail else None, _ts(ev.creado_en)),
        )
        self._conn.commit()
        return ev

    def listar_auditoria(self, engagement_id: str, limite: int = 500) -> list[sqlite3.Row]:
        return list(self._conn.execute(
            "SELECT * FROM auditoria WHERE engagement_id=? ORDER BY creado_en DESC LIMIT ?",
            (engagement_id, limite),
        ))

    # -- evidencias (cadena de custodia) ---------------------------------------

    def guardar_evidencia(self, ev: Evidencia) -> Evidencia:
        if not ev.hash_sha256:
            ev.hash_sha256 = hashlib.sha256(ev.contenido.encode()).hexdigest()
        if not ev.firma_hmac:
            ev.firma_hmac = self._firma(ev.hash_sha256)
        # BEGIN IMMEDIATE: serializa la lectura del último hash con el INSERT
        # en una transacción de escritura. Antes el SELECT-then-INSERT iba sin
        # transacción: dos escritores concurrentes (corrida CTEM + arsenal,
        # p. ej.) leían el MISMO hash_previo, insertaban dos eslabones
        # hermanos y verificar_cadena reportaba "ruptura de encadenamiento"
        # FALSA — una alarma de integridad que enmascaraba manipulaciones
        # verdaderas en el mecanismo central del producto.
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            # El último eslabón se busca por ROWID (orden REAL de inserción,
            # el mismo que BEGIN IMMEDIATE serializa). Ordenar por creado_en
            # era frágil bajo concurrencia: la evidencia B pudo CREARSE
            # (reloj del modelo) antes que la A y confirmarse DESPUÉS —
            # quedaba antes en la lectura y la cadena daba por rota.
            ultimo = self._conn.execute(
                "SELECT hash_sha256 FROM evidencias WHERE engagement_id=? "
                "ORDER BY rowid DESC LIMIT 1",
                (ev.engagement_id,),
            ).fetchone()
            ev.hash_previo = ultimo["hash_sha256"] if ultimo else "genesis"
            self._conn.execute(
                "INSERT INTO evidencias VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (ev.id, ev.engagement_id, ev.tipo.value, ev.titulo, ev.contenido,
                 ev.hash_sha256, ev.firma_hmac, ev.hash_previo, ev.fase.value,
                 ev.actor.value, ev.hallazgo_id, _ts(ev.creado_en)),
            )
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise
        return ev

    def listar_evidencias(self, engagement_id: str) -> list[sqlite3.Row]:
        # Por rowid: el orden de inserción ES el orden de la cadena —
        # verificar_cadena y esta consulta deben recorrerla igual.
        return list(self._conn.execute(
            "SELECT * FROM evidencias WHERE engagement_id=? ORDER BY rowid",
            (engagement_id,),
        ))

    def verificar_cadena(self, engagement_id: str) -> dict[str, Any]:
        """Verifica la cadena de custodia completa del caso.

        Comprueba tres niveles de integridad por evidencia:
        1. Hash: SHA-256(contenido) == hash_sha256 almacenado (no manipulado)
        2. Firma: HMAC(hash, clave_caso) == firma_hmac (no falsificada)
        3. Encadenamiento: hash_previo == hash de la evidencia anterior
        """
        filas = self.listar_evidencias(engagement_id)
        previo = "genesis"
        for fila in filas:
            if hashlib.sha256((fila["contenido"] or "").encode()).hexdigest() != fila["hash_sha256"]:
                return {"valida": False, "total": len(filas),
                        "primer_error": f"contenido manipulado en {fila['id']}"}
            if fila["hash_previo"] != previo:
                return {"valida": False, "total": len(filas),
                        "primer_error": f"ruptura de encadenamiento en {fila['id']}"}
            if not self._firma_valida(fila["hash_sha256"], fila["firma_hmac"]):
                return {"valida": False, "total": len(filas),
                        "primer_error": f"firma inválida en {fila['id']}"}
            previo = fila["hash_sha256"]
        return {"valida": True, "total": len(filas), "primer_error": None}

    # -- hallazgos -------------------------------------------------------------

    def guardar_hallazgo(self, h: Hallazgo) -> Hallazgo:
        # DEDUP por identidad sustantiva del hallazgo (título, activo,
        # severidad, técnica y descripción): al reanudar una fase tras una
        # aprobación, la fase se re-ejecuta completa y las herramientas
        # reales vuelven a observar el MISMO hecho, que se registraba dos
        # veces con ids distintos (inflando la cuenta de riesgo del caso).
        # Dos hallazgos que difieren en severidad, técnica o activo son
        # hechos DIFERENTES y no se deduplican (la matriz ATT&CK los
        # necesita separados). Si existe una fila previa idéntica con otro
        # id, se conserva la ORIGINAL (con su fecha, sus evidencias y su
        # estado de detección) y se descarta la copia.
        previa = self._conn.execute(
            "SELECT * FROM hallazgos WHERE engagement_id=? "
            "AND lower(titulo)=lower(?) AND COALESCE(activo,'')=COALESCE(?,'') "
            "AND severidad=? AND COALESCE(tecnica_mitre,'')=COALESCE(?,'') "
            "AND descripcion=? AND id<>? LIMIT 1",
            (h.engagement_id, h.titulo, h.activo, h.severidad.value,
             h.tecnica_mitre, h.descripcion, h.id)).fetchone()
        if previa is not None:
            # Se conserva la ORIGINAL: se devuelve reconstruida de BD para que
            # el llamador (notificación webhook, custodia de evidencias)
            # referencie un id REAL. Antes se devolvía la copia descartada: su
            # id no existía en BD y los webhooks difundían hallazgos fantasma.
            return self._hallazgo_de_fila(previa)
        # Columnas explícitas y PRESERVACIÓN del resultado de detección:
        # una re-guardada desde una copia de modelo obsoleta (valor por
        # defecto "pendiente") no puede borrar lo que el blue team ya
        # registró en BD. El reset explícito va por marcar_deteccion().
        deteccion = h.deteccion
        if deteccion == "pendiente":
            fila = self._conn.execute(
                "SELECT deteccion FROM hallazgos WHERE id=?", (h.id,)).fetchone()
            if fila is not None:
                deteccion = fila["deteccion"]
        self._conn.execute(
            "INSERT OR REPLACE INTO hallazgos "
            "(id, engagement_id, titulo, severidad, tecnica_mitre, activo, "
            " descripcion, recomendacion, estado, deteccion, evidencias_json, "
            " creado_por, creado_en) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (h.id, h.engagement_id, h.titulo, h.severidad.value, h.tecnica_mitre,
             h.activo, h.descripcion, h.recomendacion, h.estado, deteccion,
             json.dumps(h.evidencias), h.creado_por.value, _ts(h.creado_en)),
        )
        self._conn.commit()
        return h

    def _hallazgo_de_fila(self, fila: sqlite3.Row) -> Hallazgo:
        """Reconstruye el modelo Hallazgo desde su fila en BD (dedup)."""
        return Hallazgo(
            id=fila["id"], engagement_id=fila["engagement_id"],
            titulo=fila["titulo"], severidad=Severidad(fila["severidad"]),
            tecnica_mitre=fila["tecnica_mitre"], activo=fila["activo"] or "",
            descripcion=fila["descripcion"] or "",
            recomendacion=fila["recomendacion"] or "",
            estado=fila["estado"], deteccion=fila["deteccion"],
            evidencias=json.loads(fila["evidencias_json"] or "[]"),
            creado_por=Actor(fila["creado_por"]),
            creado_en=datetime.fromisoformat(fila["creado_en"]),
        )

    def marcar_deteccion(self, engagement_id: str, hallazgo_id: str,
                         deteccion: str) -> None:
        """Registra el resultado de detección del blue team sobre un hallazgo
        (purple teaming, patrón VECTR). El valor ya viene validado por la API."""
        cur = self._conn.execute(
            "UPDATE hallazgos SET deteccion=? WHERE id=? AND engagement_id=?",
            (deteccion, hallazgo_id, engagement_id),
        )
        if cur.rowcount == 0:
            raise KeyError(f"Hallazgo {hallazgo_id} no existe en {engagement_id}")
        self._conn.commit()

    def listar_hallazgos(self, engagement_id: str) -> list[sqlite3.Row]:
        return list(self._conn.execute(
            "SELECT * FROM hallazgos WHERE engagement_id=? ORDER BY creado_en",
            (engagement_id,),
        ))

    # -- aprobaciones ------------------------------------------------------------

    def crear_aprobacion(self, a: Aprobacion) -> Aprobacion:
        self._conn.execute(
            "INSERT INTO aprobaciones VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (a.id, a.engagement_id, a.fase.value, a.titulo, a.descripcion,
             a.herramienta, json.dumps(a.argumentos, ensure_ascii=False),
             a.tecnica_mitre, a.riesgo.value, a.ruido_estimado, a.motivo,
             a.referencia_roe, a.estado, a.decidida_por, a.comentario_operador,
             _ts(a.creada_en), _ts(a.decidida_en) if a.decidida_en else None),
        )
        self._conn.commit()
        return a

    def listar_aprobaciones(self, engagement_id: str, solo_pendientes: bool = False) -> list[sqlite3.Row]:
        if solo_pendientes:
            return list(self._conn.execute(
                "SELECT * FROM aprobaciones WHERE engagement_id=? AND estado='pendiente' "
                "ORDER BY creada_en", (engagement_id,)))
        return list(self._conn.execute(
            "SELECT * FROM aprobaciones WHERE engagement_id=? ORDER BY creada_en",
            (engagement_id,)))

    def decidir_aprobacion(self, aprobacion_id: str, decidida: bool, operador: str,
                           comentario: str = "") -> Optional[sqlite3.Row]:
        estado = "aprobada" if decidida else "rechazada"
        cur = self._conn.execute(
            "UPDATE aprobaciones SET estado=?, decidida_por=?, comentario_operador=?, "
            "decidida_en=? WHERE id=? AND estado='pendiente' RETURNING *",
            (estado, operador, comentario, _ts(), aprobacion_id),
        ).fetchone()
        self._conn.commit()
        return cur

    # -- economía del token --------------------------------------------------------

    def registrar_uso_tokens(self, engagement_id: str, uso: UsoTokens) -> None:
        self._conn.execute(
            "INSERT INTO uso_tokens (engagement_id, fase, modelo, tipo_modelo, "
            "tokens_entrada, tokens_salida, cache_hit, coste_usd, creado_en) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            (engagement_id, uso.fase.value, uso.modelo, uso.tipo.value,
             uso.tokens_entrada, uso.tokens_salida, int(uso.cache_hit),
             uso.coste_usd, _ts(uso.creado_en)),
        )
        self._conn.execute(
            "UPDATE engagements SET tokens_acumulados = tokens_acumulados + ?, "
            "coste_acumulado_usd = coste_acumulado_usd + ?, actualizado_en=? WHERE id=?",
            (uso.tokens_entrada + uso.tokens_salida, uso.coste_usd, _ts(), engagement_id),
        )
        self._conn.commit()

    def resumen_tokens(self, engagement_id: str) -> dict[str, Any]:
        por_fase = list(self._conn.execute(
            "SELECT fase, SUM(tokens_entrada+tokens_salida) AS tokens, "
            "SUM(coste_usd) AS coste FROM uso_tokens WHERE engagement_id=? "
            "GROUP BY fase ORDER BY fase", (engagement_id,)))
        por_modelo = list(self._conn.execute(
            "SELECT modelo, tipo_modelo, SUM(tokens_entrada) AS entrada, "
            "SUM(tokens_salida) AS salida, SUM(coste_usd) AS coste, "
            "AVG(cache_hit) AS tasa_cache FROM uso_tokens WHERE engagement_id=? "
            "GROUP BY modelo, tipo_modelo", (engagement_id,)))
        registros = list(self._conn.execute(
            "SELECT fase, modelo, tipo_modelo, tokens_entrada, tokens_salida, "
            "cache_hit, coste_usd, creado_en FROM uso_tokens WHERE engagement_id=? "
            "ORDER BY creado_en", (engagement_id,)))
        return {"por_fase": [dict(f) for f in por_fase],
                "por_modelo": [dict(m) for m in por_modelo],
                "registros": [dict(r) for r in registros]}

    # -- superficie de ataque (objetivos) ---------------------------------------

    def guardar_objetivo(self, obj: "Objetivo") -> "Objetivo":
        """Registra o actualiza un activo de la superficie de ataque.

        Idempotente por (engagement, nombre, tipo): si ya existe, refresca
        detalle/severidad sin duplicar filas ni perder el estado alcanzado.
        """
        existente = self._conn.execute(
            "SELECT id, estado FROM objetivos WHERE engagement_id=? AND nombre=? AND tipo=?",
            (obj.engagement_id, obj.nombre, obj.tipo.value),
        ).fetchone()
        if existente:
            self._conn.execute(
                "UPDATE objetivos SET detalle=?, severidad=?, tecnica_mitre=?, fase=? WHERE id=?",
                (obj.detalle, obj.severidad.value if obj.severidad else None,
                 obj.tecnica_mitre, obj.fase.value, existente["id"]),
            )
            self._conn.commit()
            obj.id = existente["id"]
            # El estado solo sube (descubierto→confirmado→explotado...); jamás retrocede.
            return obj
        self._conn.execute(
            "INSERT INTO objetivos VALUES (?,?,?,?,?,?,?,?,?,?)",
            (obj.id, obj.engagement_id, obj.nombre, obj.tipo.value, obj.estado.value,
             obj.detalle, obj.fase.value, obj.severidad.value if obj.severidad else None,
             obj.tecnica_mitre, _ts(obj.descubierto_en)),
        )
        self._conn.commit()
        return obj

    def listar_objetivos(self, engagement_id: str) -> list[sqlite3.Row]:
        return list(self._conn.execute(
            "SELECT * FROM objetivos WHERE engagement_id=? ORDER BY descubierto_en, rowid",
            (engagement_id,),
        ))

    def actualizar_objetivo_estado(self, engagement_id: str, nombre: str,
                                   estado: str, detalle: str = "") -> bool:
        cur = self._conn.execute(
            "UPDATE objetivos SET estado=?, detalle=CASE WHEN ?!='' THEN ? ELSE detalle END "
            "WHERE engagement_id=? AND nombre=?",
            (estado, detalle, detalle, engagement_id, nombre),
        )
        self._conn.commit()
        return cur.rowcount > 0

    # -- ROE vivo ---------------------------------------------------------------

    def actualizar_roe(self, engagement_id: str, roe: "ROEPolitica") -> None:
        """Persiste cambios del ROE firmados por el operador (techo, parada...)."""
        self._conn.execute(
            "UPDATE engagements SET roe_json=?, actualizado_en=? WHERE id=?",
            (roe.model_dump_json(), _ts(), engagement_id),
        )
        self._conn.commit()

    # -- estadísticas del almacén ------------------------------------------------

    def estadisticas_memoria(self, engagement_id: str) -> dict[str, Any]:
        def _cuenta(sql: str) -> int:
            return self._conn.execute(sql, (engagement_id,)).fetchone()[0]

        tamano = self.db_path.stat().st_size if self.db_path.exists() else 0
        return {
            "evidencias": _cuenta("SELECT COUNT(*) FROM evidencias WHERE engagement_id=?"),
            "hallazgos": _cuenta("SELECT COUNT(*) FROM hallazgos WHERE engagement_id=?"),
            "aprobaciones": _cuenta("SELECT COUNT(*) FROM aprobaciones WHERE engagement_id=?"),
            "auditoria": _cuenta("SELECT COUNT(*) FROM auditoria WHERE engagement_id=?"),
            "objetivos": _cuenta("SELECT COUNT(*) FROM objetivos WHERE engagement_id=?"),
            "resumenes": _cuenta("SELECT COUNT(*) FROM resumenes_fase WHERE engagement_id=?"),
            "tamano_db_bytes": tamano,
            # HONESTO: CLAVE_CASO alimenta la firma HMAC de evidencias, NO el
            # cifrado en reposo de la BD (SQLite sin SQLCipher). Antes el campo
            # "cifrado_reposo" afirmaba un cifrado que no existe — dato
            # engañoso para la auditoría de cumplimiento del cliente.
            "clave_hmac_activa": os.environ.get("CLAVE_CASO", "") != "",
        }

    # -- compaction -----------------------------------------------------------------

    def guardar_resumen_fase(self, resumen: ResumenFase, engagement_id: str) -> None:
        self._conn.execute(
            "INSERT INTO resumenes_fase (engagement_id, fase, texto, "
            "hallazgos_clave_json, tokens_ahorrados_estimados, creado_en) "
            "VALUES (?,?,?,?,?,?)",
            (engagement_id, resumen.fase.value, resumen.texto,
             json.dumps(resumen.hallazgos_clave, ensure_ascii=False),
             resumen.tokens_ahorrados_estimados, _ts(resumen.creado_en)),
        )
        self._conn.commit()

    def resumen_acumulado(self, engagement_id: str) -> str:
        filas = list(self._conn.execute(
            "SELECT fase, texto FROM resumenes_fase WHERE engagement_id=? ORDER BY id",
            (engagement_id,)))
        return "\n".join(f"[{f['fase']}] {f['texto']}" for f in filas)

    # -- configuración del caso (KV persistente) --------------------------------

    def config_caso(self, engagement_id: str, clave: str) -> Optional[str]:
        fila = self._conn.execute(
            "SELECT valor FROM config_caso WHERE engagement_id=? AND clave=?",
            (engagement_id, clave)).fetchone()
        return fila["valor"] if fila else None

    def fijar_config_caso(self, engagement_id: str, clave: str, valor: str) -> None:
        self._conn.execute(
            "INSERT INTO config_caso (engagement_id, clave, valor, actualizado_en) "
            "VALUES (?,?,?,?) ON CONFLICT(engagement_id, clave) "
            "DO UPDATE SET valor=excluded.valor, actualizado_en=excluded.actualizado_en",
            (engagement_id, clave, valor, _ts()))
        self._conn.commit()

    # -- trazas de razonamiento (motor adaptativo; append-only) ------------------

    def guardar_razonamiento(
        self,
        engagement_id: str,
        tipo: str,
        fase: Fase,
        entrada: dict[str, Any],
        salida: dict[str, Any],
        modelo: str = "",
        tipo_modelo: str = "",
        tokens_entrada: int = 0,
        tokens_salida: int = 0,
        coste_usd: float = 0.0,
        confianza: float | None = None,
    ) -> dict[str, Any]:
        """Persiste una traza de razonamiento con hash criptográfico de
        entrada y salida: lo que la IA razonó queda firmado e inalterable,
        y la consola puede mostrar la historia completa de decisiones."""
        entrada_json = json.dumps(entrada, ensure_ascii=False, default=str)
        salida_json = json.dumps(salida, ensure_ascii=False, default=str)
        registro = {
            "id": self.nuevo_id("raz"),
            "engagement_id": engagement_id,
            "tipo": tipo,
            "fase": fase.value,
            "entrada_json": entrada_json,
            "entrada_hash": hashlib.sha256(entrada_json.encode()).hexdigest(),
            "salida_json": salida_json,
            "salida_hash": hashlib.sha256(salida_json.encode()).hexdigest(),
            "modelo": modelo,
            "tipo_modelo": tipo_modelo,
            "tokens_entrada": tokens_entrada,
            "tokens_salida": tokens_salida,
            "coste_usd": coste_usd,
            "confianza": confianza,
            "creado_en": _ts(),
        }
        self._conn.execute(
            "INSERT INTO razonamientos (id, engagement_id, tipo, fase, entrada_json, "
            "entrada_hash, salida_json, salida_hash, modelo, tipo_modelo, "
            "tokens_entrada, tokens_salida, coste_usd, confianza, creado_en) "
            "VALUES (:id, :engagement_id, :tipo, :fase, :entrada_json, :entrada_hash, "
            ":salida_json, :salida_hash, :modelo, :tipo_modelo, :tokens_entrada, "
            ":tokens_salida, :coste_usd, :confianza, :creado_en)",
            registro,
        )
        self._conn.commit()
        return registro

    def listar_razonamientos(
        self, engagement_id: str, tipo: str | None = None, limite: int = 50
    ) -> list[dict[str, Any]]:
        if tipo:
            filas = self._conn.execute(
                "SELECT * FROM razonamientos WHERE engagement_id=? AND tipo=? "
                "ORDER BY creado_en DESC LIMIT ?",
                (engagement_id, tipo, limite)).fetchall()
        else:
            filas = self._conn.execute(
                "SELECT * FROM razonamientos WHERE engagement_id=? "
                "ORDER BY creado_en DESC LIMIT ?",
                (engagement_id, limite)).fetchall()
        salida = []
        for f in filas:
            d = dict(f)
            d["entrada"] = json.loads(d.pop("entrada_json"))
            d["salida"] = json.loads(d.pop("salida_json"))
            salida.append(d)
        return salida

    def cerrar(self) -> None:
        self._conn.close()

    def __enter__(self) -> "MemoriaCaso":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Cierre garantizado: toda consulta de la API que abre la memoria
        del caso libera la conexión SQLite (sin fugas de descriptores ni
        bloqueos WAL residuales bajo concurrencia)."""
        try:
            if exc_type is None:
                self._conn.commit()
        finally:
            self._conn.close()
