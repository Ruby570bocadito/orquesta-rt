"""API REST del orquestador (FastAPI) — backend de la consola del operador.

Endpoints principales:
  GET    /api/salud                       estado del servicio
  GET    /api/engagements                 listar casos
  POST   /api/engagements                 crear caso (ROE incluido)
  GET    /api/engagements/{id}            detalle del caso
  POST   /api/engagements/{id}/avanzar    ejecutar fase activa (si no hay bloqueos)
  GET    /api/engagements/{id}/estado     estado completo para la consola
  GET    /api/engagements/{id}/aprobaciones
  POST   /api/aprobaciones/{id}/decision  aprobar | rechazar (+comentario)
  GET    /api/engagements/{id}/hallazgos
  GET    /api/engagements/{id}/evidencias
  GET    /api/engagements/{id}/auditoria
  GET    /api/engagements/{id}/tokens
  GET    /api/engagements/{id}/informe    ruta del informe consolidado

Autenticación: en producción detrás de mTLS + sesión del despliegue on-prem.
"""
from __future__ import annotations

import json
import logging
import os
import re
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from contextlib import asynccontextmanager
from typing import Annotated, Any, Literal

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field, ValidationError

from .memory import MemoriaCaso
from .navigator import construir_capa_navigator, registrar_capa
from .purpleteam import construir_paquete_purple
from .respaldo import construir_respaldo_completo
from .models import (
    Actor,
    DecisionGuardrail,
    Engagement,
    Evidencia,
    Fase,
    Hallazgo,
    ROEPolitica,
    Severidad,
    VentanaHoraria,
)

try:
    from . import auth
except ImportError:  # ejecución como paquete top-level
    from orchestrator import auth  # type: ignore
from .router import RouterModelos
from .graph import OrquestadorEngagement
from .skills import BibliotecaSkills
from .transportes import transportes_de
from . import threatled
from . import ctem

try:
    from . import sso
except ImportError:  # ejecución como paquete top-level
    from orchestrator import sso  # type: ignore

RAIZ_CASOS = Path(os.environ.get("RAIZ_CASOS", "casos"))
RAIZ_SKILLS = Path(os.environ.get("RAIZ_SKILLS", "skills"))


@asynccontextmanager
async def _lifespan(app: FastAPI):
    """Ciclo de vida moderno de FastAPI (sustituye a on_event, deprecado):
    registra el guardián del sidecar sin bloquear el arranque y arranca el
    planificador CTEM (corridas continuas de cadenas threat-led)."""
    import asyncio
    asyncio.get_running_loop().run_in_executor(None, _sidecar_arranque)

    async def _bucle_ctem() -> None:
        """Corridas programadas del modo continuo: cada CTEM_SEGUNDOS (60
        por defecto) comprueba programas vencidos en TODOS los casos y
        ejecuta sus corridas. Los fallos de una BD no detienen el bucle."""
        import os as _os
        try:
            periodo = max(10, int(_os.environ.get("CTEM_SEGUNDOS", "60")))
        except ValueError:
            periodo = 60
        while True:
            await asyncio.sleep(periodo)
            try:
                await asyncio.get_running_loop().run_in_executor(
                    None, ctem.ejecutar_pendientes, RAIZ_CASOS)
            except Exception:
                continue  # el planificador nunca tumba la API

    _tarea_ctem = asyncio.create_task(_bucle_ctem())
    try:
        yield
    finally:
        _tarea_ctem.cancel()


app = FastAPI(
    title="Plataforma Red Team Orquestado por IA",
    version="0.1.0",
    description="Consola API del orquestador — operator-in-command.",
    lifespan=_lifespan,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.environ.get("CONSOLE_ORIGINS", "*").split(","),
    allow_methods=["*"],
    allow_headers=["*"],
)
# Compresión de respuestas (informes HTML y exportaciones de custodia son
# volúmenes de cientos de KB): ahorro real de ancho de banda sin coste CPU.
app.add_middleware(GZipMiddleware, minimum_size=1024)


# ---------------------------------------------------------------------------
# Correlación de peticiones (X-Request-ID): toda respuesta lleva el id para
# depuración y correlación con logs/proxies del despliegue on-prem.
# ---------------------------------------------------------------------------


@app.middleware("http")
async def _request_id_middleware(request: Request, call_next):
    rid = request.headers.get("X-Request-ID") or uuid.uuid4().hex[:16]
    request.state.request_id = rid
    respuesta = await call_next(request)
    respuesta.headers["X-Request-ID"] = rid
    return respuesta


# ---------------------------------------------------------------------------
# Limitador de tasa en proceso (ventana deslizante) para endpoints de
# autenticación: mitiga fuerza bruta sin dependencias externas. En un
# despliegue multi-proceso se sustituye por el limitador del reverse proxy;
# el contrato (429 con Retry-After) no cambia.
# ---------------------------------------------------------------------------


class _LimitadorTasa:
    """Ventana deslizante en proceso con PODA de memoria.

    La clave proviene de la IP del cliente (vía proxy): un atacante que
    suplante X-Forwarded-For no puede ya hacer crecer el diccionario sin
    límite — las claves caducadas se podan en cada evaluación y el total
    queda acotado por un tope duro (las más antiguas se descartan).
    """

    MAX_CLAVES = 10_000

    def __init__(self, maximo: int, ventana_s: float = 60.0):
        self.maximo = maximo
        self.ventana = ventana_s
        self._eventos: dict[str, list[float]] = {}

    def permitir(self, clave: str) -> tuple[bool, int]:
        ahora = time.time()
        # Poda de claves caducadas (amortiza el coste, acota la memoria)
        if len(self._eventos) > self.MAX_CLAVES // 2:
            for k in [k for k, v in self._eventos.items()
                      if not v or ahora - v[-1] >= self.ventana]:
                del self._eventos[k]
        if len(self._eventos) >= self.MAX_CLAVES:
            # Tope duro: expulsa las claves más antiguas (DoS de memoria)
            antiguas = sorted(self._eventos.items(),
                              key=lambda kv: kv[1][-1] if kv[1] else 0)
            for k, _ in antiguas[: self.MAX_CLAVES // 4]:
                del self._eventos[k]
        cola = [t for t in self._eventos.get(clave, []) if ahora - t < self.ventana]
        if len(cola) >= self.maximo:
            reintentar = int(self.ventana - (ahora - cola[0])) + 1
            self._eventos[clave] = cola
            return False, max(1, reintentar)
        cola.append(ahora)
        self._eventos[clave] = cola
        return True, 0


_limitador_auth = _LimitadorTasa(maximo=10, ventana_s=60.0)


def _clave_cliente(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for", "")
    return (fwd.split(",")[0].strip() if fwd
            else (request.client.host if request.client else "desconocido"))


def _guardar_rate(request: Request, extra: str = "") -> None:
    permitido, reintentar = _limitador_auth.permitir(
        f"{_clave_cliente(request)}{extra}")
    if not permitido:
        raise HTTPException(
            429, f"Demasiados intentos: espera {reintentar}s y reintenta.")

# ---------------------------------------------------------------------------
# Autenticación (deny-by-default): TODA ruta exige sesión de operador salvo
# las explícitamente públicas. Un endpoint nuevo queda protegido por defecto.
# ---------------------------------------------------------------------------

RUTAS_PUBLICAS = {
    "/api/salud",
    "/api/auth/estado",
    "/api/auth/login",
    "/api/auth/registrar",
    "/api/auth/sso/estado",
    "/api/auth/sso/inicio",
    "/api/auth/sso/callback",
}

# Escrituras (métodos con efectos) permitidas a un LECTOR: solo su propia
# contraseña. Todo lo demás exige nivel operador (RBAC v21, deny-by-default:
# un endpoint nuevo de escritura queda protegido sin tocar su código).
RUTAS_ESCRITURA_LECTOR = {
    "/api/auth/contrasena",
    # v22: calcular rutas de ataque es una CONSULTA pura al motor Neo4j
    # (Cypher allShortestPaths, sin mutación de ningún dato): la puede pedir
    # un lector. El aislamiento de casos no aplica (el motor es del
    # despliegue, no del caso) y no crea evidencias ni aprobaciones.
    "/api/integraciones/rutas",
    # v22: enriquecimiento CVE es una LECTURA externa (API pública del NVD,
    # solo GET saliente): tampoco muta el despliegue ni crea evidencias.
    "/api/integraciones/nvd/enriquecer",
}
_RE_ENGAGEMENT = re.compile(r"^/api/engagements/([^/]+)(?:/.*)?$")


def _rol_claims(request: Request) -> dict[str, Any]:
    return getattr(request.state, "operador", None) or {}


def rol_de(request: Request) -> str:
    return str(_rol_claims(request).get("rol", ""))


def tenant_de(request: Request) -> str:
    return str(_rol_claims(request).get("ten") or auth.TENANT_PREDETERMINADA)


def es_admin(request: Request) -> bool:
    return auth.tiene_nivel(rol_de(request), 4)


def _respuesta_error(estado: int, detalle: str) -> JSONResponse:
    return JSONResponse(status_code=estado, content={"detail": detalle})


def _tenant_de_caso(engagement_id: str) -> str | None:
    """Organización propietaria del caso (None si no existe)."""
    if len(engagement_id) > 64 or not re.fullmatch(r"[A-Za-z0-9._-]+", engagement_id):
        return None
    ruta = RAIZ_CASOS / f"{engagement_id}.db"
    if not ruta.exists():
        return None
    memoria = MemoriaCaso(ruta)
    try:
        fila = memoria.obtener_engagement(engagement_id)
        return str(fila["tenant_id"]) if fila else None
    finally:
        memoria.cerrar()


@app.middleware("http")
async def _auth_middleware(request: Request, call_next):
    if request.method == "OPTIONS" or request.url.path in RUTAS_PUBLICAS:
        return await call_next(request)
    cabecera = request.headers.get("Authorization", "")
    if not cabecera.startswith("Bearer "):
        return _respuesta_error(
            401, "Sesión requerida: autentícate en la consola.")
    claims = auth.verificar_token(cabecera[7:])
    if not claims:
        return _respuesta_error(
            401, "Sesión inválida o expirada: vuelve a iniciar sesión.")
    request.state.operador = claims
    # --- RBAC v21: escritura exige nivel operador -------------------------
    if request.method not in ("GET", "HEAD", "OPTIONS"):
        if (request.url.path not in RUTAS_ESCRITURA_LECTOR
                and not auth.tiene_nivel(claims.get("rol", ""), 2)):
            return _respuesta_error(
                403, "Tu rol es de solo lectura: puedes consultar el caso "
                     "pero no ejecutar acciones.")
    # --- Aislamiento multi-tenant: el caso debe ser de tu organización -----
    coincidencia = _RE_ENGAGEMENT.match(request.url.path)
    if coincidencia and not auth.tiene_nivel(claims.get("rol", ""), 4):
        caso_tenant = _tenant_de_caso(coincidencia.group(1))
        if caso_tenant is None:
            return _respuesta_error(404, "Engagement no existe")
        if caso_tenant != tenant_de(request):
            return _respuesta_error(
                403, "Este caso pertenece a otra organización: tu cuenta "
                     "solo accede a los de la suya.")
    return await call_next(request)


def operador_de(request: Request) -> str:
    """Identidad REAL del operador autenticado (no editable por el cliente)."""
    claims = getattr(request.state, "operador", None) or {}
    return str(claims.get("sub", "desconocido"))


def _sidecar_arranque() -> None:
    """Guardián de resiliencia: si la consola está caída, se relanza.
    No bloquea el arranque de la API (se ejecuta en segundo plano)."""
    import threading

    def _tarea() -> None:
        try:
            from .sidecar import asegurar_consola
            asegurar_consola()
        except Exception:
            pass

    threading.Thread(target=_tarea, daemon=True).start()


# ---------------------------------------------------------------------------
# Fábricas perezosas (una memoria por engagement, abierta bajo demanda)
# ---------------------------------------------------------------------------


def _memoria_de(engagement_id: str) -> MemoriaCaso:
    # Guardia de ID (v14, hallado por fuzzing): un id hostil NUNCA llega al
    # sistema de ficheros. Con ids de 10k caracteres, Path.exists() lanza
    # OSError ENAMETOOLONG (500 en vez de 404) y cualquier carácter de ruta
    # es una superficie de traversal. Los IDs legítimos son `caso_<hex>`
    # generados por el servidor o identificadores cortos de despliegues
    # antiguos/demos: solo se aceptan caracteres de id seguros, ≤64.
    if len(engagement_id) > 64 or not re.fullmatch(r"[A-Za-z0-9._-]+", engagement_id):
        raise HTTPException(404, "Engagement no existe")
    ruta = RAIZ_CASOS / f"{engagement_id}.db"
    if not ruta.exists():
        raise HTTPException(404, f"Engagement {engagement_id} no existe")
    return MemoriaCaso(ruta)


def _creador(engagement_id: str) -> OrquestadorEngagement:
    memoria = _memoria_de(engagement_id)
    fila = memoria.obtener_engagement(engagement_id)
    roe = ROEPolitica.model_validate_json(fila["roe_json"])
    router = RouterModelos(memoria=memoria, engagement_id=engagement_id)
    router.configurar_presupuestos(json.loads(fila["presupuesto_tokens_json"]))
    skills = BibliotecaSkills(RAIZ_SKILLS)
    # Transportes REALES acotados al ROE del caso: httpx, DNS, sockets, TLS.
    return OrquestadorEngagement(engagement_id, memoria, router, roe, skills,
                                 transportes=transportes_de(roe))


def _engagement_modelo(fila) -> Engagement:
    return Engagement(
        id=fila["id"], nombre=fila["nombre"], cliente=fila["cliente"],
        roe=ROEPolitica.model_validate_json(fila["roe_json"]),
        fase_actual=Fase(fila["fase_actual"]), estado_fase=fila["estado_fase"],
        creado_en=fila["creado_en"], actualizado_en=fila["actualizado_en"],
        presupuesto_tokens=json.loads(fila["presupuesto_tokens_json"]),
        coste_acumulado_usd=fila["coste_acumulado_usd"],
        tokens_acumulados=fila["tokens_acumulados"],
        certificado_borrado=fila["certificado_borrado"],
    )


# ---------------------------------------------------------------------------
# Modelos de petición
# ---------------------------------------------------------------------------


# Cadenas acotadas para listas de alcance (endurecimiento de producción):
# cada elemento ≤ 253 chars (longitud máxima de un dominio) y cada lista
# acotada: el cuerpo de una petición no puede crecer sin límite.
CadenaAlcance = Annotated[str, Field(max_length=253)]
CadenaTecnica = Annotated[str, Field(max_length=24)]


class PeticionCrear(BaseModel):
    nombre: str = Field(min_length=3, max_length=120)
    cliente: str = Field(min_length=2, max_length=120)
    # Solo un admin puede crear el caso EN OTRA organización; el resto lo
    # tiene en la suya (claim `ten`) y el campo se ignora.
    tenant_id: str | None = Field(default=None, max_length=41)
    alcance_dominios: list[CadenaAlcance] = Field(default_factory=list, max_length=100)
    alcance_cidrs: list[CadenaAlcance] = Field(default_factory=list, max_length=100)
    alcance_excluido: list[CadenaAlcance] = Field(default_factory=list, max_length=100)
    tecnicas_prohibidas: list[CadenaTecnica] = Field(
        default_factory=lambda: ["T1485", "T1489"], max_length=50)
    tecnicas_con_aprobacion: list[CadenaTecnica] = Field(default_factory=list, max_length=50)
    techo_ruido: int = Field(default=50, ge=0, le=100)
    ventana_inicio: str = "00:00"
    ventana_fin: str = "23:59"
    ventana_dias: list[Annotated[str, Field(max_length=3)]] = Field(
        default_factory=lambda: ["lun", "mar", "mie", "jue", "vie", "sab", "dom"],
        max_length=7)


class PeticionDecision(BaseModel):
    decidir: bool
    comentario: str = Field(default="", max_length=2000)
    # La identidad del operador ya NO viaja en el cuerpo: la establece la
    # sesión autenticada (JWT). Un cliente no puede firmar en nombre de otro.


class PeticionAvanzar(BaseModel):
    notas_cliente: str = Field(default="", max_length=4000)
    vector_elegido: str = Field(default="", max_length=200)
    perfil_objetivo: str = Field(default="", max_length=200)
    # Integraciones reales (opcionales, según fase y adaptadores del operador):
    modulo: str = Field(default="", max_length=120)  # p. ej. exploit/multi/http/... (F3, MSF RPC)
    opciones: dict[Annotated[str, Field(max_length=60)], Annotated[str, Field(max_length=500)]] = Field(
        default_factory=dict, max_length=50)  # opciones del módulo (RHOSTS...)
    destinatarios: list[Annotated[str, Field(max_length=254)]] = Field(
        default_factory=list, max_length=20)  # F6: envío autorizado


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@app.get("/api/salud")
def salud() -> dict[str, Any]:
    """Chequeo de salud con componentes REALES (para monitorización y
    HEALTHCHECK de Docker): memoria de casos, base de operadores y
    configuración del router IA (sin pings salientes ni secretos)."""
    # Guardián de resiliencia en cada chequeo de salud: si la consola Next.js
    # está caída, el sidecar la relanza desde este proceso (que sobrevive a
    # los ciclos del servidor de desarrollo).
    try:
        from .sidecar import asegurar_consola
        asegurar_consola()
    except Exception:
        pass
    componentes: dict[str, Any] = {
        "api": {"ok": True},
        "memoria_casos": {
            "ok": RAIZ_CASOS.exists(),
            "detalle": str(RAIZ_CASOS),
        },
        "operadores": {
            "ok": Path(os.environ.get("DB_USUARIOS", "usuarios.db")).exists(),
        },
        "router_ia": RouterModelos().estado_backends(),
    }
    ok_total = all(c.get("ok", True) for k, c in componentes.items()
                   if k in ("memoria_casos", "operadores", "api"))
    return {"estado": "ok" if ok_total else "degradado",
            "servicio": "orquestador", "version": app.version,
            "componentes": componentes}


@app.get("/api/engagements")
def listar(request: Request) -> list[dict[str, Any]]:
    """Casos visibles: TODOS para admin, solo los de tu organización para
    el resto (RBAC multi-tenant v21)."""
    admin = es_admin(request)
    tenant = tenant_de(request)
    salida = []
    if RAIZ_CASOS.exists():
        for db in sorted(RAIZ_CASOS.glob("*.db")):
            try:
                memoria = MemoriaCaso(db)
                fila = memoria.obtener_engagement(db.stem)
                if fila:
                    if not admin and str(fila["tenant_id"]) != tenant:
                        memoria.cerrar()
                        continue
                    salida.append({
                        "id": fila["id"], "nombre": fila["nombre"],
                        "cliente": fila["cliente"],
                        "fase_actual": fila["fase_actual"],
                        "estado_fase": fila["estado_fase"],
                        "coste_acumulado_usd": fila["coste_acumulado_usd"],
                        "tokens_acumulados": fila["tokens_acumulados"],
                    })
                memoria.cerrar()
            except Exception:
                continue
    return salida


def _detalle_validacion(exc: ValidationError) -> str:
    """Convierte un ValidationError de pydantic en un mensaje 422 accionable
    (campo + causa) en lugar del volcado completo de errores."""
    try:
        primero = exc.errors()[0]
        campo = ".".join(str(x) for x in primero.get("loc", ()) if x != "body")
        mensaje = str(primero.get("msg", ""))
        entrada = str(primero.get("input", ""))[:60]
        causa = mensaje.replace("Value error, ", "")
        return f"{campo}: {causa} (valor recibido: {entrada})"
    except Exception:  # nunca fallar al construir el error
        return "ROE inválido: revisa dominios y CIDRs del alcance"


@app.post("/api/engagements")
def crear(p: PeticionCrear, request: Request) -> dict[str, Any]:
    engagement_id = f"caso_{uuid.uuid4().hex[:10]}"
    # RBAC multi-tenant: el caso nace en la organización del creador; un
    # admin puede colocarl en otra existente (cross-tenant gestionado).
    tenant = tenant_de(request)
    if p.tenant_id and es_admin(request):
        candidata = p.tenant_id.strip().lower()
        if candidata and auth.organizacion_existe(candidata):
            tenant = candidata
    try:
        roe = ROEPolitica(
            engagement_id=engagement_id, cliente=p.cliente,
            alcance_dominios=p.alcance_dominios, alcance_cidrs=p.alcance_cidrs,
            alcance_excluido=p.alcance_excluido,
            tecnicas_prohibidas=p.tecnicas_prohibidas,
            tecnicas_con_aprobacion=p.tecnicas_con_aprobacion,
            techo_ruido=p.techo_ruido,
            ventanas_activas=VentanaHoraria(
                inicio=p.ventana_inicio, fin=p.ventana_fin, dias=p.ventana_dias),
            parada_emergencia=False,
        )
    except ValidationError as exc:
        # Alcance inválido (CIDR/dominio malformado): 422 accionable, nunca
        # un 500 ni un caso guardado con un boundary roto.
        detalle = _detalle_validacion(exc)
        raise HTTPException(422, detalle)
    eng = Engagement(
        id=engagement_id, nombre=p.nombre, cliente=p.cliente, roe=roe,
        tenant_id=tenant,
        creado_en=datetime.now(timezone.utc), actualizado_en=datetime.now(timezone.utc),
    )
    memoria = MemoriaCaso(RAIZ_CASOS / f"{engagement_id}.db")
    memoria.crear_engagement(eng)
    memoria.registrar_auditoria(
        engagement_id, Actor.HUMANO,
        "engagement.crear",
        detalle=f"Caso creado: {p.nombre} (por {operador_de(request)}, "
                f"organización {tenant})",
        herramienta="api", resultado="ok")
    memoria.cerrar()
    return {"id": engagement_id, "nombre": p.nombre}


@app.get("/api/engagements/{engagement_id}")
def detalle(engagement_id: str) -> dict[str, Any]:
    with _memoria_de(engagement_id) as memoria:
        fila = memoria.obtener_engagement(engagement_id)
        if not fila:
            raise HTTPException(404, "no existe")
        return _engagement_modelo(fila).model_dump(mode="json")


@app.get("/api/engagements/{engagement_id}/estado")
def estado_completo(engagement_id: str) -> dict[str, Any]:
    """Estado consolidado para la consola: caso + bloqueos + superficie + almacén."""
    with _memoria_de(engagement_id) as memoria:
        fila = memoria.obtener_engagement(engagement_id)
        if not fila:
            raise HTTPException(404, "no existe")
        aprobadas = memoria.listar_aprobaciones(engagement_id)
        ruido_ejecutado = sum(
            int(a["ruido_estimado"] or 0) for a in aprobadas if a["estado"] == "aprobada")
        return {
            "engagement": _engagement_modelo(fila).model_dump(mode="json"),
            "aprobaciones_pendientes": [
                dict(a) | {"argumentos": json.loads(a["argumentos_json"])}
                for a in memoria.listar_aprobaciones(engagement_id, solo_pendientes=True)
            ],
            "cadena_custodia": memoria.verificar_cadena(engagement_id),
            "resumen_acumulado": memoria.resumen_acumulado(engagement_id),
            "objetivos": [dict(o) for o in memoria.listar_objetivos(engagement_id)],
            "memoria": memoria.estadisticas_memoria(engagement_id),
            "ruido_ejecutado": ruido_ejecutado,
        }


@app.get("/api/engagements/{engagement_id}/objetivos")
def objetivos(engagement_id: str) -> list[dict[str, Any]]:
    with _memoria_de(engagement_id) as memoria:
        return [dict(o) for o in memoria.listar_objetivos(engagement_id)]


class PeticionParada(BaseModel):
    """Parada de emergencia. La identidad del autor la fija la sesión JWT."""
    activar: bool = True
    motivo: str = Field(default="parada de emergencia desde consola", max_length=500)


@app.post("/api/engagements/{engagement_id}/parada_emergencia")
def parada_emergencia(engagement_id: str, p: PeticionParada, request: Request) -> dict[str, Any]:
    """Kill switch del ROE: suspende toda tool call hasta que el operador
    la desactive explícitamente. Queda registrado en la auditoría inmutable
    como decisión humana con guardrail 'denegar'."""
    with _memoria_de(engagement_id) as memoria:
        fila = memoria.obtener_engagement(engagement_id)
        if not fila:
            raise HTTPException(404, "no existe")
        roe = ROEPolitica.model_validate_json(fila["roe_json"])
        roe.parada_emergencia = p.activar
        memoria.actualizar_roe(engagement_id, roe)
        memoria.registrar_auditoria(
            engagement_id, Actor.HUMANO, "roe.parada_emergencia",
            detalle=(("ACTIVADA" if p.activar else "DESACTIVADA")
                     + f": {p.motivo} — por {operador_de(request)}"),
            herramienta="consola", resultado="denegar" if p.activar else "ok",
            guardrail=None)
        try:
            from . import webhook as _wh
        except ImportError:
            from orchestrator import webhook as _wh  # type: ignore
        _wh.despachar_en_segundo_plano(
            "roe.parada_emergencia", engagement_id,
            {"activada": p.activar, "motivo": p.motivo,
             "operador": operador_de(request)})
        return {"parada_emergencia": roe.parada_emergencia}


class PeticionRoe(BaseModel):
    """Cambio de ROE vivo. La identidad del autor NO viaja en el cuerpo:
    la fija la sesión JWT (la auditoría registra al operador real)."""
    techo_ruido: int | None = Field(default=None, ge=0, le=100)
    ventana_inicio: Annotated[str | None, Field(max_length=5)] = None
    ventana_fin: Annotated[str | None, Field(max_length=5)] = None
    ventana_dias: list[Annotated[str, Field(max_length=3)]] | None = Field(default=None, max_length=7)
    alcance_excluido: list[CadenaAlcance] | None = Field(default=None, max_length=100)


@app.post("/api/engagements/{engagement_id}/roe")
def actualizar_roe(engagement_id: str, p: PeticionRoe, request: Request) -> dict[str, Any]:
    """Actualiza el ROE vivo del caso (techo de ruido, ventana horaria...).
    Cada cambio queda auditado como decisión humana CON IDENTIDAD real."""
    identidad = operador_de(request)
    with _memoria_de(engagement_id) as memoria:
        fila = memoria.obtener_engagement(engagement_id)
        if not fila:
            raise HTTPException(404, "no existe")
        roe = ROEPolitica.model_validate_json(fila["roe_json"])
        cambios: list[str] = []
        try:
            if p.techo_ruido is not None and p.techo_ruido != roe.techo_ruido:
                cambios.append(f"techo_ruido {roe.techo_ruido}→{p.techo_ruido}")
                roe.techo_ruido = p.techo_ruido
            if p.ventana_inicio and p.ventana_inicio != roe.ventanas_activas.inicio:
                cambios.append(f"ventana.inicio {roe.ventanas_activas.inicio}→{p.ventana_inicio}")
                roe.ventanas_activas.inicio = p.ventana_inicio
            if p.ventana_fin and p.ventana_fin != roe.ventanas_activas.fin:
                cambios.append(f"ventana.fin {roe.ventanas_activas.fin}→{p.ventana_fin}")
                roe.ventanas_activas.fin = p.ventana_fin
            if p.ventana_dias is not None:
                cambios.append(f"ventana.dias →{','.join(p.ventana_dias)}")
                roe.ventanas_activas.dias = p.ventana_dias
            if p.alcance_excluido is not None:
                cambios.append("alcance_excluido actualizado")
                roe.alcance_excluido = p.alcance_excluido
        except ValidationError as exc:
            # validate_assignment=True valida CADA mutación: una exclusión
            # malformada por esta vía ya no entra en el boundary (antes sí).
            raise HTTPException(422, _detalle_validacion(exc))
        memoria.actualizar_roe(engagement_id, roe)
        memoria.registrar_auditoria(
            engagement_id, Actor.HUMANO, "roe.actualizar",
            detalle=("; ".join(cambios) or "sin cambios") + f" — por {identidad}",
            herramienta="consola", resultado="ok")
        return {"roe": roe.model_dump(mode="json"), "cambios": cambios}


@app.get("/api/engagements/{engagement_id}/memoria")
def estadisticas_memoria(engagement_id: str) -> dict[str, Any]:
    with _memoria_de(engagement_id) as memoria:
        return memoria.estadisticas_memoria(engagement_id)


@app.get("/api/engagements/{engagement_id}/memoria/buscar")
def buscar_memoria(engagement_id: str, q: str, limite: int = 20,
                   tipos: str = "") -> dict[str, Any]:
    """Búsqueda REAL en la memoria del caso (BM25 español + embeddings
    locales opcionales). Consulta el índice de evidencias, hallazgos,
    objetivos, auditoría, aprobaciones y resúmenes del caso."""
    consulta = (q or "").strip()
    if len(consulta) < 2:
        raise HTTPException(400, "consulta demasiado corta (mínimo 2 caracteres)")
    with _memoria_de(engagement_id) as memoria:
        try:
            from .busqueda import buscar_caso
        except ImportError:  # paquete top-level
            from busqueda import buscar_caso  # type: ignore
        lista_tipos = [t.strip() for t in tipos.split(",") if t.strip()] if tipos else None
        return buscar_caso(
            memoria, engagement_id, consulta, limite=min(max(limite, 1), 50),
            tipos=lista_tipos,
            local_base=os.environ.get("API_LOCAL_BASE", ""),
            local_clave=os.environ.get("API_LOCAL_CLAVE", ""))


@app.post("/api/engagements/{engagement_id}/avanzar")
def avanzar(engagement_id: str, p: PeticionAvanzar, request: Request) -> dict[str, Any]:
    orch = _creador(engagement_id)
    try:
        # La ejecución de una fase es una acción humana consciente: queda
        # vinculada a la identidad autenticada en la auditoría inmutable.
        orch.memoria.registrar_auditoria(
            engagement_id, Actor.HUMANO, "engagement.avanzar",
            detalle=f"Ejecución de fase solicitada por {operador_de(request)}",
            herramienta="consola", resultado="ok")
        return orch.avanzar({
            "notas_cliente": p.notas_cliente,
            "vector_elegido": p.vector_elegido,
            "perfil_objetivo": p.perfil_objetivo,
            "modulo": p.modulo,
            "opciones": p.opciones,
            "destinatarios": p.destinatarios,
        })
    finally:
        # Cierre garantizado de recursos del ciclo: memoria del caso y pool
        # httpx del router (antes quedaban vivos hasta el GC).
        orch.router.cerrar()
        orch.memoria.cerrar()


@app.get("/api/engagements/{engagement_id}/aprobaciones")
def aprobaciones(engagement_id: str, solo_pendientes: bool = False) -> list[dict[str, Any]]:
    with _memoria_de(engagement_id) as memoria:
        return [
            dict(a) | {"argumentos": json.loads(a["argumentos_json"])}
            for a in memoria.listar_aprobaciones(engagement_id, solo_pendientes)
        ]


@app.post("/api/aprobaciones/{aprobacion_id}/decision")
def decidir(aprobacion_id: str, p: PeticionDecision, request: Request) -> dict[str, Any]:
    """Decisión de firma ROE. La identidad queda fijada por la sesión JWT:
    la auditoría refleja QUIÉN decidió de verdad, sin suplantaciones."""
    identidad = operador_de(request)
    # La aprobación puede vivir en la BD de cualquier caso: buscarla.
    if RAIZ_CASOS.exists():
        for db in sorted(RAIZ_CASOS.glob("*.db")):
            memoria = MemoriaCaso(db)
            pendientes = memoria.listar_aprobaciones(db.stem, solo_pendientes=True)
            if any(a["id"] == aprobacion_id for a in pendientes):
                from .models import Actor
                memoria.decidir_aprobacion(aprobacion_id, p.decidir, identidad, p.comentario)
                memoria.registrar_auditoria(
                    db.stem, Actor.HUMANO, "aprobacion.decision",
                    detalle=(f"{'Aprobada' if p.decidir else 'Rechazada'}: {aprobacion_id} "
                             f"por {identidad}" + (f" — “{p.comentario}”" if p.comentario else "")),
                    herramienta="consola", resultado="aprobada" if p.decidir else "rechazada")
                try:
                    from . import webhook as _wh
                except ImportError:
                    from orchestrator import webhook as _wh  # type: ignore
                _wh.despachar_en_segundo_plano(
                    "aprobacion.decidida", db.stem,
                    {"aprobacion_id": aprobacion_id,
                     "decision": "aprobada" if p.decidir else "rechazada",
                     "operador": identidad})
                memoria.cerrar()
                return {"id": aprobacion_id, "estado": "aprobada" if p.decidir else "rechazada"}
            memoria.cerrar()
    raise HTTPException(404, "aprobación no encontrada o ya decidida")


@app.get("/api/engagements/{engagement_id}/hallazgos")
def hallazgos(engagement_id: str) -> list[dict[str, Any]]:
    with _memoria_de(engagement_id) as memoria:
        return [dict(h) | {"evidencias": json.loads(h["evidencias_json"])}
                for h in memoria.listar_hallazgos(engagement_id)]


class PeticionHallazgoAlta(BaseModel):
    """Registro MANUAL de hallazgo (v16): el operador documenta lo que
    observa fuera del ciclo del agente (verificación manual, evidencia
    aportada por el cliente, brecha vista durante el paseo por el alcance)."""
    titulo: str = Field(min_length=3, max_length=200)
    severidad: Literal["critica", "alta", "media", "baja", "informativa"]
    tecnica_mitre: str | None = Field(default=None, max_length=12)
    activo: str = Field(default="", max_length=200)
    descripcion: str = Field(default="", max_length=4000)
    recomendacion: str = Field(default="", max_length=4000)


@app.post("/api/engagements/{engagement_id}/hallazgos")
def registrar_hallazgo(engagement_id: str, p: PeticionHallazgoAlta,
                       request: Request) -> dict[str, Any]:
    """Alta manual de hallazgo con identidad real. La técnica debe cumplir
    el formato ATT&CK (T#### / T####.###) o llega None: nunca se adivina.
    Auditado como decisión HUMANA y notificado vía webhook si hay receptor."""
    identidad = operador_de(request)
    with _memoria_de(engagement_id) as memoria:
        if memoria.obtener_engagement(engagement_id) is None:
            raise HTTPException(404, "no existe")
        tecnica = (p.tecnica_mitre or "").strip().upper() or None
        if tecnica:
            try:
                from .navigator import _RE_TECNICA
            except ImportError:
                from orchestrator.navigator import _RE_TECNICA  # type: ignore
            if not _RE_TECNICA.fullmatch(tecnica):
                raise HTTPException(
                    422, f"Técnica ATT&CK inválida: '{tecnica}'. "
                         "Formato esperado: T#### o T####.###")
        h = Hallazgo(
            id=memoria.nuevo_id("hal"), engagement_id=engagement_id,
            titulo=p.titulo.strip(), severidad=Severidad(p.severidad),
            tecnica_mitre=tecnica, activo=p.activo.strip(),
            descripcion=p.descripcion, recomendacion=p.recomendacion,
            evidencias=[], estado="confirmado", creado_por=Actor.HUMANO)
        memoria.guardar_hallazgo(h)
        memoria.registrar_auditoria(
            engagement_id, Actor.HUMANO, "hallazgo.registrar",
            detalle=(f"{h.id} [{p.severidad}] {p.titulo}"
                     f" ({tecnica or 'sin técnica'}) — por {identidad}"),
            herramienta="consola", resultado="ok")
        try:
            from . import webhook as _wh
        except ImportError:
            from orchestrator import webhook as _wh  # type: ignore
        _wh.despachar_en_segundo_plano(
            "hallazgo.registrado", engagement_id,
            {"hallazgo_id": h.id, "titulo": h.titulo,
             "severidad": p.severidad, "tecnica_mitre": tecnica or "",
             "activo": h.activo, "registro": "manual"})
        return {"id": h.id, "tecnica_mitre": tecnica,
                "severidad": p.severidad, "titulo": h.titulo}


class PeticionDeteccion(BaseModel):
    """Resultado de detección del blue team sobre un hallazgo (purple team)."""
    deteccion: Literal["pendiente", "detectado", "no_detectado", "prevenido"]


@app.patch("/api/engagements/{engagement_id}/hallazgos/{hallazgo_id}/deteccion")
def marcar_deteccion_hallazgo(engagement_id: str, hallazgo_id: str,
                              p: PeticionDeteccion,
                              request: Request) -> dict[str, Any]:
    """Registra el resultado de detección del equipo azul (purple teaming,
    patrón VECTR): la defensa ¿detectó, no detectó o previno la acción?
    Queda auditado con la identidad real del operador que lo documenta."""
    identidad = operador_de(request)
    with _memoria_de(engagement_id) as memoria:
        existentes = memoria.listar_hallazgos(engagement_id)
        if not any(h["id"] == hallazgo_id for h in existentes):
            raise HTTPException(404, "hallazgo no encontrado")
        memoria.marcar_deteccion(engagement_id, hallazgo_id, p.deteccion)
        memoria.registrar_auditoria(
            engagement_id, Actor.HUMANO, "hallazgo.deteccion",
            detalle=f"{hallazgo_id} → {p.deteccion} — por {identidad}",
            herramienta="consola", resultado="ok")
        try:
            from . import webhook as _wh
        except ImportError:
            from orchestrator import webhook as _wh  # type: ignore
        _wh.despachar_en_segundo_plano(
            "hallazgo.deteccion", engagement_id,
            {"hallazgo_id": hallazgo_id, "deteccion": p.deteccion,
             "operador": identidad})
        return {"id": hallazgo_id, "deteccion": p.deteccion}


@app.get("/api/engagements/{engagement_id}/evidencias")
def evidencias(engagement_id: str) -> dict[str, Any]:
    with _memoria_de(engagement_id) as memoria:
        return {
            "evidencias": [dict(e) for e in memoria.listar_evidencias(engagement_id)],
            "cadena": memoria.verificar_cadena(engagement_id),
        }


@app.get("/api/engagements/{engagement_id}/auditoria")
def auditoria(engagement_id: str, limite: int = 200) -> list[dict[str, Any]]:
    # límite acotado como el resto de endpoints de listado: un valor
    # negativo en SQLite LIMIT significaría "sin límite" y un valor
    # enorme obligaría a volcar toda la auditoría en memoria.
    acotado = min(max(limite, 1), 1000)
    with _memoria_de(engagement_id) as memoria:
        return [dict(e) for e in memoria.listar_auditoria(engagement_id, acotado)]


@app.get("/api/engagements/{engagement_id}/tokens")
def tokens(engagement_id: str) -> dict[str, Any]:
    with _memoria_de(engagement_id) as memoria:
        return memoria.resumen_tokens(engagement_id)


@app.get("/api/engagements/{engagement_id}/informe")
def informe(engagement_id: str, formato: str = "md") -> dict[str, Any]:
    if formato not in ("md", "html"):
        raise HTTPException(422, f"formato inválido: '{formato}' (válidos: md, html)")
    with _memoria_de(engagement_id) as memoria:
        if not memoria.listar_evidencias(engagement_id):
            raise HTTPException(409, "sin evidencias: ejecute fases antes de consolidar")
        from .reporting import construir_informe, construir_informe_html
        if formato == "html":
            ruta = construir_informe_html(engagement_id, memoria, carpeta_salida=RAIZ_CASOS)
        else:
            ruta = construir_informe(engagement_id, memoria, carpeta_salida=RAIZ_CASOS)
        return {"ruta": str(ruta), "formato": formato,
                "contenido": Path(ruta).read_text(encoding="utf-8")}


# ---------------------------------------------------------------------------
# Copiloto del operador (IA real con contexto del caso; análisis, nunca acción)
# ---------------------------------------------------------------------------


class PeticionCopiloto(BaseModel):
    pregunta: str = Field(min_length=3, max_length=4000)
    # Multi-turno acotado: máx 20 turnos, cada turno ≤ 4000 chars (el texto
    # sobrante se trunca después igualmente en _normalizar_historial; aquí se
    # impide que un cuerpo gigante consuma memoria/parsing del servidor).
    historial: list[dict[Annotated[str, Field(max_length=20)],
                         Annotated[str, Field(max_length=4000)]]] = Field(
        default_factory=list, max_length=20)


@app.get("/api/engagements/{engagement_id}/attack-navigator")
def capa_navigator(engagement_id: str) -> Response:
    """Capa MITRE ATT&CK Navigator (JSON importable) del caso.

    Técnicas REALES: observadas en hallazgos (score por severidad) e
    intentadas vía solicitudes de aprobación. Sin relleno: si una técnica
    no figura, no se observó ni se intentó. La exportación queda auditada
    en el propio caso (patrón exportar/respaldo)."""
    memoria = _memoria_de(engagement_id)  # 404 si el caso no existe
    try:
        capa = construir_capa_navigator(memoria, engagement_id)
        registrar_capa(memoria, engagement_id, capa)
    finally:
        memoria.cerrar()
    return Response(
        content=json.dumps(capa, ensure_ascii=False, indent=2),
        media_type="application/json; charset=utf-8",
        headers={"Content-Disposition":
                 f'attachment; filename="capa_attack_{engagement_id}.json"'})


@app.get("/api/engagements/{engagement_id}/copiloto/config")
def copiloto_config(engagement_id: str) -> dict[str, Any]:
    """Estado del copiloto para este caso + política de salida efectiva."""
    with _memoria_de(engagement_id) as memoria:
        habilitado = memoria.config_caso(engagement_id, "copiloto_habilitado") == "1"
        router = RouterModelos()
        try:
            return {
                "habilitado": habilitado,
                "politica_salida": router.politica_salida,
                "backends": router.estado_backends(),
            }
        finally:
            router.cerrar()


@app.post("/api/engagements/{engagement_id}/copiloto/config")
def copiloto_config_fijar(engagement_id: str, p: dict[str, bool],
                          request: Request) -> dict[str, Any]:
    """Habilita/deshabilita el copiloto (decisión consciente de perímetro).

    La decisión queda en la auditoría del caso con la identidad real: es el
    operador quien asume que el contexto del caso viajará al backend de
    frontera configurado (o exige local con POLITICA_SALIDA=perimetro)."""
    memoria = _memoria_de(engagement_id)
    try:
        habilitado = bool(p.get("habilitado"))
        memoria.fijar_config_caso(engagement_id, "copiloto_habilitado",
                                  "1" if habilitado else "0")
        memoria.registrar_auditoria(
            engagement_id, Actor.HUMANO, "copiloto_config",
            detalle=("copiloto habilitado" if habilitado else "copiloto deshabilitado")
                    + f" por {operador_de(request)}: el contexto del caso viaja al "
                      "backend de inferencia configurado; con política perimetro "
                      "solo usa LLM local",
            herramienta="copiloto",
            parametros={"habilitado": habilitado},
            guardrail=DecisionGuardrail.PERMITIR)
        # Estado COMPLETO tras el cambio (la consola renderiza política y
        # backends desde esta misma respuesta; devolver solo {habilitado}
        # hacía desaparecer la información de configuración en pantalla).
        router = RouterModelos()
        try:
            return {"habilitado": habilitado, "politica_salida": router.politica_salida,
                    "backends": router.estado_backends()}
        finally:
            router.cerrar()
    finally:
        memoria.cerrar()


@app.post("/api/engagements/{engagement_id}/copiloto")
def copiloto_consultar(engagement_id: str, p: PeticionCopiloto,
                       request: Request) -> dict[str, Any]:
    """Consulta REAL al copiloto: RAG local (BM25) + router semántico.

    - Niega el servicio si el operador no habilitó el copiloto para el caso.
    - Registra en auditoría la consulta (pregunta truncada + tokens + modelo).
    - No ejecuta ninguna acción: solo análisis."""
    memoria = _memoria_de(engagement_id)
    if memoria.config_caso(engagement_id, "copiloto_habilitado") != "1":
        memoria.cerrar()
        raise HTTPException(
            403, "Copiloto deshabilitado para este caso: actívalo en la vista "
                 "Copiloto tras revisar la implicación de perímetro.")
    router = RouterModelos(memoria=memoria, engagement_id=engagement_id)
    router.configurar_presupuestos(
        json.loads(memoria.obtener_engagement(engagement_id)["presupuesto_tokens_json"]))
    try:
        try:
            from . import copiloto as _cop
        except ImportError:
            from orchestrator import copiloto as _cop  # type: ignore
        try:
            # Arsenal real del despliegue (índice cacheado de portadas):
            # el copiloto cita técnicas que EXISTEN, nunca playbooks inventados.
            arsenal = _biblioteca_catalogo().indice_para_prompt()
            resultado = _cop.consultar(memoria, router, engagement_id, p.pregunta.strip(),
                                       historial=p.historial, arsenal=arsenal)
        except RuntimeError as exc:
            raise HTTPException(503, f"Backend de inferencia no disponible: {exc}")
        memoria.registrar_auditoria(
            engagement_id, Actor.HUMANO, "copiloto_consulta",
            detalle=(f"consulta al copiloto ({resultado['modelo']}, "
                     f"{resultado['tokens_entrada'] + resultado['tokens_salida']} tokens): "
                     + p.pregunta.strip()[:200]),
            herramienta="copiloto",
            parametros={"pregunta_len": len(p.pregunta)},
            guardrail=DecisionGuardrail.PERMITIR)
        return resultado
    finally:
        router.cerrar()
        memoria.cerrar()


# ---------------------------------------------------------------------------
# Motor de razonamiento adaptativo: cobertura determinista, prioridades
# mecánicas, plan de fase con IA validado contra el catálogo real y
# reflexión de fase. Todo propuesta: NADA ejecuta acciones ofensivas.
# ---------------------------------------------------------------------------


@app.get("/api/engagements/{engagement_id}/razonamiento/cobertura")
def razonamiento_cobertura(engagement_id: str) -> dict[str, Any]:
    """Cobertura determinista de la superficie real (sin LLM, instantáneo)."""
    with _memoria_de(engagement_id) as memoria:
        try:
            from . import razonador
        except ImportError:
            from orchestrator import razonador  # type: ignore
        try:
            return razonador.evaluar_cobertura(memoria, engagement_id)
        except ValueError as exc:
            raise HTTPException(404, str(exc))


@app.get("/api/engagements/{engagement_id}/razonamiento/prioridades")
def razonamiento_prioridades(engagement_id: str) -> dict[str, Any]:
    """Prioridades adaptativas por reglas (sin LLM): la adaptación al caso
    funciona aunque no haya ningún backend de inferencia configurado."""
    with _memoria_de(engagement_id) as memoria:
        try:
            from . import razonador
        except ImportError:
            from orchestrator import razonador  # type: ignore
        # Arsenal REAL del despliegue (portadas del catálogo de skills):
        # permite a las reglas proponer playbooks pertinentes no trabajados.
        portadas = [
            {"nombre": p.nombre, "fase": p.fase,
             "tecnica_mitre": p.tecnica_mitre, "riesgo": p.riesgo}
            for p in _biblioteca_catalogo().listar()
        ]
        return razonador.prioridades_siguientes(memoria, engagement_id,
                                                arsenal=portadas)


@app.post("/api/engagements/{engagement_id}/razonamiento/plan")
def razonamiento_plan(engagement_id: str, request: Request) -> dict[str, Any]:
    """Plan de fase propuesto por IA (validado contra el catálogo REAL).

    - No ejecuta nada ni crea aprobaciones: el operador materializa cada
      paso por el canal de fase con su boundary y firma.
    - Sin backend: 503 con el requisito exacto (nunca un plan fingido).
    - La traza queda persistida con hash de entrada/salida."""
    memoria = _memoria_de(engagement_id)
    router = RouterModelos(memoria=memoria, engagement_id=engagement_id)
    router.configurar_presupuestos(
        json.loads(memoria.obtener_engagement(engagement_id)["presupuesto_tokens_json"]))
    try:
        try:
            from . import razonador
        except ImportError:
            from orchestrator import razonador  # type: ignore
        try:
            resultado = razonador.planificar_fase(memoria, router, engagement_id)
        except RuntimeError as exc:
            memoria.registrar_auditoria(
                engagement_id, Actor.HUMANO, "razonamiento_plan_error",
                detalle=f"plan IA sin backend: {str(exc)[:300]}",
                herramienta="razonador", resultado="error")
            raise HTTPException(503, f"Backend de inferencia no disponible: {exc}")
        memoria.registrar_auditoria(
            engagement_id, Actor.HUMANO, "razonamiento_plan",
            detalle=(f"plan IA de fase generado ({resultado['modelo']}, "
                     f"{len(resultado['pasos'])} pasos válidos, "
                     f"{len(resultado['descartados'])} descartados por catálogo)"),
            herramienta="razonador",
            parametros={"tokens": resultado["tokens"]},
            guardrail=DecisionGuardrail.PERMITIR)
        return resultado
    finally:
        router.cerrar()
        memoria.cerrar()


@app.post("/api/engagements/{engagement_id}/razonamiento/reflexion")
def razonamiento_reflexion(engagement_id: str, request: Request) -> dict[str, Any]:
    """Reflexión de cobertura de la fase actual (IA real sobre datos reales)."""
    memoria = _memoria_de(engagement_id)
    router = RouterModelos(memoria=memoria, engagement_id=engagement_id)
    router.configurar_presupuestos(
        json.loads(memoria.obtener_engagement(engagement_id)["presupuesto_tokens_json"]))
    try:
        try:
            from . import razonador
        except ImportError:
            from orchestrator import razonador  # type: ignore
        try:
            resultado = razonador.reflexion_fase(memoria, router, engagement_id)
        except RuntimeError as exc:
            memoria.registrar_auditoria(
                engagement_id, Actor.HUMANO, "razonamiento_reflexion_error",
                detalle=f"reflexión sin backend: {str(exc)[:300]}",
                herramienta="razonador", resultado="error")
            raise HTTPException(503, f"Backend de inferencia no disponible: {exc}")
        memoria.registrar_auditoria(
            engagement_id, Actor.HUMANO, "razonamiento_reflexion",
            detalle=(f"reflexión de cobertura generada ({resultado['modelo']}, "
                     f"{resultado['tokens']} tokens)"),
            herramienta="razonador", guardrail=DecisionGuardrail.PERMITIR)
        return resultado
    finally:
        router.cerrar()
        memoria.cerrar()


@app.get("/api/engagements/{engagement_id}/razonamiento")
def razonamiento_trazas(engagement_id: str, tipo: str = "",
                        limite: int = 50) -> dict[str, Any]:
    """Historial de trazas de razonamiento (con hashes de integridad)."""
    with _memoria_de(engagement_id) as memoria:
        trazas = memoria.listar_razonamientos(
            engagement_id, tipo=tipo or None, limite=min(max(limite, 1), 200))
        return {"total": len(trazas), "trazas": trazas}


@app.get("/api/engagements/{engagement_id}/hallazgos.csv")
def hallazgos_csv(engagement_id: str) -> Response:
    """Exportación CSV real de hallazgos (gestión de remediación, ticketing)."""
    import csv
    import io
    with _memoria_de(engagement_id) as memoria:
        filas = memoria.listar_hallazgos(engagement_id)
        if not filas:
            raise HTTPException(409, "sin hallazgos que exportar")
        columnas = [k for k in filas[0].keys() if k != "id"]
        if "titulo" not in columnas:
            raise HTTPException(500, "esquema de hallazgos inesperado")
        buffer = io.StringIO()
        escritor = csv.DictWriter(buffer, fieldnames=columnas, extrasaction="ignore")
        escritor.writeheader()
        for fila in filas:
            escritor.writerow(dict(fila))
        memoria.registrar_auditoria(
            engagement_id, Actor.SISTEMA, "hallazgos.export_csv",
            detalle=f"{len(filas)} hallazgos exportados a CSV",
            guardrail=DecisionGuardrail.PERMITIR)
        contenido = buffer.getvalue()
    return Response(
        content=contenido, media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition":
                 f'attachment; filename="hallazgos_{engagement_id}.csv"'})


@app.get("/api/engagements/{engagement_id}/exportar")
def exportar_caso(engagement_id: str) -> dict[str, Any]:
    """Copia de custodia/archivo del caso completo en JSON REAL.

    Incluye ROE, objetivos, hallazgos, aprobaciones, auditoría, tokens y la
    verificación de la cadena de custodia en el momento de la exportación.
    Los metadatos de evidencias viajan íntegros; el contenido firmado queda
    en el almacén del despliegue (este export NO altera ninguna cadena)."""
    memoria = _memoria_de(engagement_id)
    try:
        fila = memoria.obtener_engagement(engagement_id)
        if not fila:
            raise HTTPException(404, "no existe")
        def _dicts(filas) -> list[dict[str, Any]]:
            return [dict(f) for f in filas]
        cadena = memoria.verificar_cadena(engagement_id)
        paquete = {
            "formato": "orquestart-caso/1",
            "exportado_en": datetime.now(timezone.utc).isoformat(),
            "engagement": dict(fila) | {"roe": json.loads(fila["roe_json"])},
            "objetivos": _dicts(memoria.listar_objetivos(engagement_id)),
            "hallazgos": _dicts(memoria.listar_hallazgos(engagement_id)),
            "evidencias": _dicts(memoria.listar_evidencias(engagement_id)),
            "aprobaciones": _dicts(memoria.listar_aprobaciones(engagement_id)),
            "auditoria": _dicts(memoria.listar_auditoria(engagement_id, limite=100000)),
            "tokens": memoria.resumen_tokens(engagement_id),
            "memoria": memoria.estadisticas_memoria(engagement_id),
            "cadena_custodia": cadena,
        }
        memoria.registrar_auditoria(
            engagement_id, Actor.SISTEMA, "caso.exportado",
            detalle=("exportación de custodia: "
                     f"{len(paquete['evidencias'])} evidencias, "
                     f"{len(paquete['auditoria'])} eventos de auditoría; "
                     f"cadena {'VÁLIDA' if cadena.get('valida') else 'INVÁLIDA'}"),
            guardrail=DecisionGuardrail.PERMITIR)
        return paquete
    finally:
        memoria.cerrar()


@app.get("/api/engagements/{engagement_id}/respaldo")
def respaldo_caso(engagement_id: str) -> Response:
    """Respaldo de archivo del caso completo en un ZIP REAL.

    Contenido verificado por el propio endpoint antes de servirse:
      - caso.json           → paquete de custodia completo (formato orquestart-caso/1)
      - informe.md          → informe ejecutivo Markdown (si hay evidencias)
      - informe.html        → informe imprimible autocontenido (si hay evidencias)
    Uso operativo: archivado fuera de línea del caso al cierre, transferencia
    al gestor documental del cliente o conservación legal. La generación
    queda auditada en el caso."""
    import io
    import zipfile
    from .reporting import construir_informe, construir_informe_html
    # Paquete de custodia REAL (incluye la verificación de la cadena y 404 si
    # el caso no existe).
    paquete = exportar_caso(engagement_id)
    hay_evidencias = bool(paquete["evidencias"])
    try:
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as z:
            z.writestr(f"{engagement_id}/caso.json",
                       json.dumps(paquete, ensure_ascii=False, indent=2,
                                  default=str))
            if hay_evidencias:
                with _memoria_de(engagement_id) as m2:
                    ruta_md = construir_informe(engagement_id, m2, carpeta_salida=RAIZ_CASOS)
                    ruta_html = construir_informe_html(engagement_id, m2, carpeta_salida=RAIZ_CASOS)
                z.write(ruta_md, f"{engagement_id}/informe.md")
                z.write(ruta_html, f"{engagement_id}/informe.html")
            # Manifiesto: qué contiene el respaldo y en qué estado quedó la cadena
            z.writestr(f"{engagement_id}/MANIFIESTO.txt",
                       f"Respaldo del caso {engagement_id}\n"
                       f"Generado: {datetime.now(timezone.utc).isoformat()}\n"
                       f"Formato de custodia: orquestart-caso/1\n"
                       f"Cadena de custodia: "
                       f"{'VÁLIDA' if paquete['cadena_custodia'].get('valida') else 'INVÁLIDA'}\n"
                       f"Evidencias: {len(paquete['evidencias'])}\n"
                       f"Eventos de auditoría: {len(paquete['auditoria'])}\n"
                       f"Hallazgos: {len(paquete['hallazgos'])}\n"
                       f"Objetivos: {len(paquete['objetivos'])}\n")
        contenido = buffer.getvalue()
        memoria = _memoria_de(engagement_id)
        memoria.registrar_auditoria(
            engagement_id, Actor.SISTEMA, "caso.respaldo",
            detalle=(f"respaldo ZIP generado ({len(contenido)} bytes, "
                     f"{len(paquete['auditoria'])} eventos, "
                     f"cadena {'VÁLIDA' if paquete['cadena_custodia'].get('valida') else 'INVÁLIDA'})"),
            guardrail=DecisionGuardrail.PERMITIR)
        memoria.cerrar()
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(500, f"respaldo fallido: {str(exc)[:200]}")
    return Response(
        content=contenido, media_type="application/zip",
        headers={"Content-Disposition":
                 f'attachment; filename="respaldo_{engagement_id}.zip"'})


@app.get("/api/engagements/{engagement_id}/objetivos/dif")
def dif_superficie(engagement_id: str, desde: str = "", hasta: str = "") -> dict[str, Any]:
    """Diferencial REAL de superficie de ataque: activos descubiertos en el
    intervalo indicado (ISO-8601). Útil para revisar qué cambió entre dos
    repasos del caso sin reescanear."""
    from datetime import datetime as _dt, timezone as _tz
    with _memoria_de(engagement_id) as memoria:
        try:
            d_desde = _dt.fromisoformat(desde) if desde else None
            d_hasta = _dt.fromisoformat(hasta) if hasta else None
        except ValueError as exc:
            raise HTTPException(400, f"fecha inválida (usa ISO-8601): {exc}")
        def _aware(t: _dt) -> _dt:
            # Normaliza naive→UTC aware para comparar con los registros del caso
            return t.replace(tzinfo=_tz.utc) if t.tzinfo is None else t
        if d_desde:
            d_desde = _aware(d_desde)
        if d_hasta:
            d_hasta = _aware(d_hasta)
        todos = [dict(o) for o in memoria.listar_objetivos(engagement_id)]
        def _en_rango(o: dict[str, Any]) -> bool:
            try:
                t = _dt.fromisoformat(o["descubierto_en"])
            except (ValueError, KeyError):
                return False
            t = _aware(t)
            if d_desde and t < d_desde:
                return False
            if d_hasta and t > d_hasta:
                return False
            return True
        nuevos = [o for o in todos if _en_rango(o)]
        por_estado: dict[str, int] = {}
        por_tipo: dict[str, int] = {}
        for o in nuevos:
            por_estado[o["estado"]] = por_estado.get(o["estado"], 0) + 1
            por_tipo[o["tipo"]] = por_tipo.get(o["tipo"], 0) + 1
        return {
            "desde": desde or None,
            "hasta": hasta or None,
            "total_superficie": len(todos),
            "nuevos": nuevos,
            "resumen": {"nuevos": len(nuevos), "por_estado": por_estado,
                        "por_tipo": por_tipo},
        }


# ---------------------------------------------------------------------------
# Integraciones reales (C2, explotación, AD, SMTP, router LLM)
# ---------------------------------------------------------------------------


def _estado_webhook() -> dict[str, Any]:
    """Estado del canal de notificaciones real (sin secretos)."""
    try:
        from . import webhook
    except ImportError:
        from orchestrator import webhook  # type: ignore
    return webhook.estado()


def _estado_integraciones() -> dict[str, Any]:
    """Configuración REAL visible desde la consola (sin secretos)."""
    try:
        from .integraciones import ldap, metasploit, smtp_envio
    except ImportError:
        from integraciones import ldap, metasploit, smtp_envio
    sliver_cfg = bool(
        os.environ.get("SLIVER_CONFIG") or
        (os.environ.get("SLIVER_HOST") and os.environ.get("SLIVER_TOKEN")))
    mythic_cfg = bool(os.environ.get("MYTHIC_URL") and os.environ.get("MYTHIC_TOKEN"))
    msf_cfg = bool(os.environ.get("MSF_HOST") and os.environ.get("MSF_USER")
                   and os.environ.get("MSF_PASS"))
    smtp = smtp_envio.estado()
    return {
        "c2": {
            "sliver": {
                "configurado": sliver_cfg,
                "detalle": "API gRPC oficial (sliver-py) · SLIVER_CONFIG o SLIVER_HOST+SLIVER_TOKEN",
            },
            "mythic": {
                "configurado": mythic_cfg,
                "detalle": "API GraphQL oficial · MYTHIC_URL + MYTHIC_TOKEN",
                "servidor": os.environ.get("MYTHIC_URL", ""),
            },
            "metasploit": {
                "configurado": msf_cfg,
                "detalle": "MSG-RPC oficial · MSF_HOST + MSF_PORT + MSF_USER + MSF_PASS",
                "servidor": os.environ.get("MSF_HOST", ""),
            },
        },
        "active_directory": {
            "configurado": bool(os.environ.get("LDAP_HOST") and os.environ.get("LDAP_BIND_DN")),
            "detalle": "LDAP real (ldap3) · LDAP_HOST + LDAP_BIND_DN + LDAP_BIND_CLAVE + LDAP_BASE_DN",
            "servidor": os.environ.get("LDAP_HOST", ""),
        },
        "phishing_smtp": {
            "configurado": bool(smtp.get("configurado")),
            "detalle": "SMTP del equipo · SMTP_HOST + SMTP_USUARIO + SMTP_REMITENTE",
            "servidor": smtp.get("host", ""),
        },
        "attack_paths": {
            "configurado": bool(os.environ.get("BLOODHOUND_URL")
                                and os.environ.get("BLOODHOUND_USER")),
            "detalle": "BloodHound CE · API REST oficial · BLOODHOUND_URL + "
                       "BLOODHOUND_USER + BLOODHOUND_SECRET",
            "servidor": os.environ.get("BLOODHOUND_URL", ""),
        },
        "motor_rutas": {
            "configurado": bool(os.environ.get("NEO4J_URL")),
            "detalle": "Motor Neo4j real · Cypher dirigido sobre esquema "
                       "BloodHound · NEO4J_URL + NEO4J_USER + NEO4J_PASS",
            "servidor": os.environ.get("NEO4J_URL", ""),
        },
        "nvd": {
            "configurado": True,
            "detalle": "NVD API 2.0 (NIST) pública · enriquecimiento CVE real "
                       "de hallazgos; complemento cuando no hay MISP",
            "servidor": "services.nvd.nist.gov",
        },
        "threat_intel": {
            "configurado": bool(os.environ.get("MISP_URL") and os.environ.get("MISP_KEY")),
            "detalle": "MISP · API JSON oficial · MISP_URL + MISP_KEY (MISP_SSL=0 solo labs)",
            "servidor": os.environ.get("MISP_URL", ""),
        },
        "sso": sso.estado(),
        "router_llm": RouterModelos().estado_backends(),
        "webhook": _estado_webhook(),
        "osint": {
            "hibp": {
                "configurado": bool(os.environ.get("HIBP_API_KEY")),
                "detalle": "Have I Been Pwned v3 · HIBP_API_KEY (clave gratuita)",
            },
            "crt_sh": {"configurado": True, "detalle": "Certificate Transparency (público)"},
            "wayback": {"configurado": True, "detalle": "Internet Archive CDX (público)"},
        },
    }


@app.get("/api/integraciones")
def listar_integraciones() -> dict[str, Any]:
    return _estado_integraciones()


# ---------------------------------------------------------------------------
# Biblioteca de TÉCNICAS (skills): catálogo visible para el operador.
# La biblioteca alimenta los prompts de los agentes con progressive
# disclosure (solo nombre+descripción en el índice; cuerpo bajo demanda).
# Aquí se expone al operador: qué técnicas tiene el despliegue, con qué
# fase/ATT&CK enlazan, qué riesgo conllevan y cuáles exigen aprobación
# explícita. Nunca se ejecuta nada desde aquí: es conocimiento, no acción.
# ---------------------------------------------------------------------------


def _biblioteca_skills() -> BibliotecaSkills:
    return BibliotecaSkills(RAIZ_SKILLS)


# Catálogo del operador CACHEDO a nivel de módulo: parsear YAML de todas las
# portadas en cada GET sería trabajo repetido; el índice se relee del disco
# solo al recargar explícitamente (POST /api/skills/recargar), que además
# es el gesto honesto si el operador quiere garantizar frescura total.
_BIBLIOTECA_CATALOGO: BibliotecaSkills | None = None


def _biblioteca_catalogo() -> BibliotecaSkills:
    global _BIBLIOTECA_CATALOGO
    if _BIBLIOTECA_CATALOGO is None:
        _BIBLIOTECA_CATALOGO = BibliotecaSkills(RAIZ_SKILLS)
    return _BIBLIOTECA_CATALOGO


@app.get("/api/skills")
def listar_skills() -> dict[str, Any]:
    """Catálogo REAL de técnicas del despliegue (solo portadas, índice cacheado)."""
    biblioteca = _biblioteca_catalogo()
    portadas = biblioteca.listar()
    por_fase: dict[str, int] = {}
    por_riesgo: dict[str, int] = {}
    con_aprobacion = 0
    for p in portadas:
        por_fase[p.fase or "sin_fase"] = por_fase.get(p.fase or "sin_fase", 0) + 1
        por_riesgo[p.riesgo] = por_riesgo.get(p.riesgo, 0) + 1
        if p.requiere_aprobacion:
            con_aprobacion += 1
    return {
        "total": len(portadas),
        "raiz": str(RAIZ_SKILLS),
        "por_fase": por_fase,
        "por_riesgo": por_riesgo,
        "con_aprobacion": con_aprobacion,
        "tecnicas": [
            {
                "nombre": p.nombre,
                "descripcion": p.descripcion,
                "fase": p.fase,
                "tecnica_mitre": p.tecnica_mitre,
                "riesgo": p.riesgo,
                "requiere_aprobacion": p.requiere_aprobacion,
                "fuentes_permitidas": p.fuentes_permitidas,
            }
            for p in portadas
        ],
    }


@app.get("/api/skills/{nombre}")
def ver_skill(nombre: str) -> dict[str, Any]:
    """Playbook completo de una técnica (progressive disclosure, bajo demanda).

    El cuerpo llega con la MISMA cadena de custodia que verá el modelo:
    hash sha256 del contenido real en disco, verifiable por el operador."""
    biblioteca = _biblioteca_skills()
    skill = biblioteca.obtener(nombre)
    if skill is None:
        raise HTTPException(
            404, f"La técnica '{nombre}' no está en la biblioteca "
                 f"({len(biblioteca.listar())} disponibles; usa recargar si "
                 "acabas de añadirla al disco)")
    p = skill.portada
    return {
        "nombre": p.nombre,
        "descripcion": p.descripcion,
        "fase": p.fase,
        "tecnica_mitre": p.tecnica_mitre,
        "riesgo": p.riesgo,
        "requiere_aprobacion": p.requiere_aprobacion,
        "fuentes_permitidas": p.fuentes_permitidas,
        "hash_contenido": skill.hash_contenido,
        "cuerpo": skill.cargar_cuerpo()[:50_000],
    }


class PeticionRecargar(BaseModel):
    motivo: str = Field(default="recarga manual desde consola", max_length=200)


@app.post("/api/skills/recargar")
def recargar_skills(p: PeticionRecargar) -> dict[str, Any]:
    """Invalida la caché del catálogo y relee la biblioteca desde disco.

    El índice de portadas se cachea para no re-parsear YAML en cada GET;
    esta acción construye la biblioteca de cero (igual que hará el próximo
    engagement al instanciar la suya, que SIEMPRE lee el disco actual).
    Queda constancia en el log del servicio (la auditoría de acciones vive
    en cada caso)."""
    global _BIBLIOTECA_CATALOGO
    _BIBLIOTECA_CATALOGO = BibliotecaSkills(RAIZ_SKILLS)
    total = len(_BIBLIOTECA_CATALOGO.listar())
    logging.getLogger("orquestador").info(
        "skills.recargar: %d técnicas vigentes (%s)", total, p.motivo[:120])
    return {
        "total": total,
        "mensaje": f"Biblioteca recargada: {total} técnicas vigentes",
    }


class PeticionProbar(BaseModel):
    nombre: str = Field(min_length=2, max_length=40)


@app.post("/api/integraciones/probar")
def probar_integracion(p: PeticionProbar) -> dict[str, Any]:
    """Prueba REAL de conexión con la integración indicada.

    Toques únicamente los endpoints oficiales configurados por el operador;
    nunca se devuelve éxito si la conexión no ocurrió de verdad.
    """
    nombre = p.nombre.strip().lower()
    try:
        if nombre == "sliver":
            try:
                from .integraciones import sliver
            except ImportError:
                from integraciones import sliver
            return sliver.estado()
        if nombre == "mythic":
            try:
                from .integraciones import mythic
            except ImportError:
                from integraciones import mythic
            return mythic.estado()
        if nombre in ("metasploit", "msf"):
            try:
                from .integraciones import metasploit
            except ImportError:
                from integraciones import metasploit
            return metasploit.estado()
        if nombre in ("ldap", "active_directory", "ad"):
            try:
                from .integraciones import ldap
            except ImportError:
                from integraciones import ldap
            return ldap.enumerar("resumen")
        if nombre in ("bloodhound", "bloodhound_ce", "attack_paths"):
            try:
                from .integraciones import bloodhound
            except ImportError:
                from integraciones import bloodhound
            return bloodhound.estado()
        if nombre in ("neo4j", "rutas", "motor_rutas"):
            try:
                from .integraciones import rutas
            except ImportError:
                from integraciones import rutas
            return rutas.estado()
        if nombre == "nvd":
            try:
                from .integraciones import nvd
            except ImportError:
                from integraciones import nvd
            return nvd.estado()
        if nombre in ("misp", "threat_intel"):
            try:
                from .integraciones import misp
            except ImportError:
                from integraciones import misp
            return misp.estado()
        if nombre == "smtp":
            try:
                from .integraciones import smtp_envio
            except ImportError:
                from integraciones import smtp_envio
            estado = smtp_envio.estado()
            if not estado.get("configurado"):
                return {"conectado": False, "error": estado.get("error", "no configurado")}
            return {"conectado": True, **estado,
                    "nota": "configuración verificada; el envío real exige fase F6 firmada"}
        if nombre == "crt_sh":
            # Consulta real mínima a Certificate Transparency
            import httpx
            with httpx.Client(timeout=15, follow_redirects=True) as c:
                r = c.get("https://crt.sh/", params={"q": "%.example.com", "output": "json"})
            return {"conectado": r.status_code == 200, "http": r.status_code,
                    "error": None if r.status_code == 200 else f"crt.sh respondió {r.status_code}"}
        if nombre == "wayback":
            # Consulta real mínima a la API CDX del Internet Archive
            import httpx
            with httpx.Client(timeout=15, follow_redirects=True) as c:
                r = c.get("https://web.archive.org/cdx/search/cdx",
                          params={"url": "example.com", "limit": "1", "output": "json"})
            return {"conectado": r.status_code == 200, "http": r.status_code,
                    "error": None if r.status_code == 200 else f"CDX respondió {r.status_code}"}
        if nombre == "hibp":
            clave = os.environ.get("HIBP_API_KEY", "")
            if not clave:
                return {"conectado": False,
                        "error": "HIBP_API_KEY no configurada: obtén la clave gratuita "
                                 "en haveibeenpwned.com/API/Key y añádela al entorno del backend"}
            import httpx
            with httpx.Client(timeout=15) as c:
                r = c.get("https://haveibeenpwned.com/api/v3/breaches",
                          params={"domain": "example.com"},
                          headers={"hibp-api-key": clave, "user-agent": "OrquestaRT"})
            return {"conectado": r.status_code == 200, "http": r.status_code,
                    "error": None if r.status_code == 200 else f"HIBP respondió {r.status_code}"}
        if nombre in ("llm_frontera", "frontera"):
            r = RouterModelos().probar_backend("frontera")
            return r
        if nombre in ("llm_local", "local", "ollama"):
            return RouterModelos().probar_backend("local")
        if nombre == "webhook":
            # POST real de prueba a los receptores configurados (v16: el éxito
            # exige una respuesta HTTP 2xx de al menos un receptor).
            try:
                from . import webhook
            except ImportError:
                from orchestrator import webhook  # type: ignore
            if not webhook.configurado():
                return {"conectado": False,
                        "error": "sin receptores de webhook: da de alta uno en "
                                 "Integraciones (admin) o define WEBHOOK_URL en "
                                 "el entorno del backend"}
            entregas = webhook.despachar(
                "webhook.prueba", "prueba",
                {"mensaje": "Prueba de conexión del orquestador — si lees esto, "
                            "el receptor funciona"})
            if entregas:
                return {"conectado": True,
                        "nota": f"POST real recibido por {entregas} receptor(es)"}
            return {"conectado": False,
                    "error": "ningún receptor aceptó el POST: revisa las entregas "
                             "recientes en Integraciones → Webhooks"}
    except Exception as exc:
        return {"conectado": False, "error": f"prueba fallida: {str(exc)[:200]}"}
    raise HTTPException(400, f"integración desconocida: {nombre}")


@app.get("/api/integraciones/ldap/grafo")
def grafo_empleados_ldap() -> dict[str, Any]:
    """Grafo organizacional REAL del directorio bajo ROE (solo lectura).

    Devuelve la plantilla que el directorio realmente declara: cuentas,
    cargos, departamentos y cadena de mando (atributo `manager`). Es la
    respuesta honesta al grafo de empleados: sin LDAP configurado se
    devuelve el requisito exacto — jamás una plantilla inventada.
    """
    try:
        from .integraciones import ldap
    except ImportError:
        from integraciones import ldap
    r = ldap.enumerar("empleados")
    if not r.get("conectado"):
        return {"conectado": False,
                "requisito": r.get("error", "LDAP no configurado"),
                "nodos": [], "aristas": [], "departamentos": {}, "resumen": {}}
    return {
        "conectado": True,
        "base_dn": r.get("base_dn", ""),
        "nodos": r.get("nodos", []),
        "aristas": r.get("aristas", []),
        "departamentos": r.get("departamentos", {}),
        "resumen": r.get("resumen", {}),
        "nota": "Leído directamente del controlador de dominio con "
                "credenciales bajo ROE (solo lectura).",
    }


# ---------------------------------------------------------------------------
# Rutas de ataque (v22): el motor Neo4j REAL calcula los paths con Cypher
# dirigido sobre la colección cargada (laboratorio o su producción). Sin
# motor configurado, requisito exacto — jamás rutas fabricadas.
# ---------------------------------------------------------------------------


class PeticionRutas(BaseModel):
    origen: str = Field(default="", max_length=200)
    limite: int = Field(default=5, ge=1, le=20)


@app.post("/api/integraciones/rutas")
def rutas_de_ataque(p: PeticionRutas) -> dict[str, Any]:
    try:
        from .integraciones import rutas
    except ImportError:
        from integraciones import rutas
    return rutas.rutas(p.origen or None, p.limite)


@app.get("/api/integraciones/rutas")
def estado_rutas() -> dict[str, Any]:
    """Estado del motor + orígenes y objetivos de alto valor REALES."""
    try:
        from .integraciones import rutas
    except ImportError:
        from integraciones import rutas
    base = rutas.estado()
    if not base.get("conectado"):
        return {"motor": base}
    return {
        "motor": base,
        "origenes": rutas.origenes(),
        "objetivos": rutas.objetivos(),
    }


# ---------------------------------------------------------------------------
# Intel complementaria (v22): enriquecimiento CVE REAL vía NVD cuando el
# despliegue no tiene MISP (el conector oficial sigue listo para su instancia).
# ---------------------------------------------------------------------------


class PeticionNvd(BaseModel):
    texto: str = Field(min_length=4, max_length=2_000)


@app.post("/api/integraciones/nvd/enriquecer")
def enriquecer_nvd(p: PeticionNvd) -> dict[str, Any]:
    try:
        from .integraciones import nvd
    except ImportError:
        from integraciones import nvd
    return nvd.enriquecer(p.texto)


# ---------------------------------------------------------------------------
# Arsenal (v20): evasión verificada, persistencia real del lab, AD ofensivo.
# Todas las acciones pasan por el MISMO boundary que las herramientas del
# agente (scope del ROE, política, riesgo) y producen evidencia con cadena
# de custodia. Nada aquí es simulado: lo que el módulo no puede ejecutar en
# el host se reporta como requisito o artefacto, jamás como éxito.
# ---------------------------------------------------------------------------


class PeticionEvasion(BaseModel):
    """Generación de artefacto de evasión con verificación real."""
    payload_b64: str = Field(min_length=4, max_length=150_000)
    metodo: Literal["aes_cbc", "xor_cascada", "base64_dividido"] = "aes_cbc"
    formato: Literal["python", "powershell", "binario"] = "python"
    nota: str = Field(default="", max_length=500)


class PeticionEscaneo(BaseModel):
    """Re-escaneo real de un artefacto ya custodiado en el caso."""
    evidencia_id: str = Field(min_length=2, max_length=40)


class PeticionPersistencia(BaseModel):
    """Implantación REAL de persistencia en el host del lab (bajo ROE)."""
    metodo: str = Field(min_length=2, max_length=40)
    comando: str = Field(min_length=1, max_length=400)
    raiz: str = Field(default="", max_length=253)


ACCIONES_AD = Literal[
    "kerberoasting", "asrep", "dcsync", "pass_the_hash",
    "laps", "gmsa", "trusts", "rutas_da",
]

HERRAMIENTA_AD = {
    "kerberoasting": "ad.kerberoasting",
    "asrep": "ad.asrep_roasting",
    "dcsync": "ad.dcsync",
    "pass_the_hash": "ad.pass_the_hash",
    "laps": "ad.laps_leer",
    "gmsa": "ad.gmsa_leer",
    "trusts": "ad.trusts",
    "rutas_da": "ad.rutas_da",
}


class PeticionAccionAD(BaseModel):
    accion: ACCIONES_AD
    host: str = Field(default="", max_length=253)
    usuario: str = Field(default="", max_length=64)
    hash_nt: str = Field(default="", max_length=64)
    dn_objetivo: str = Field(default="", max_length=253)


def _guardrail_y_fase(engagement_id: str, memoria: MemoriaCaso):
    """ROE real del caso + motor de guardrails + fase actual."""
    from .guardrails import MotorGuardrails
    fila = memoria.obtener_engagement(engagement_id)
    if fila is None:
        raise HTTPException(404, "no existe")
    roe = ROEPolitica.model_validate_json(fila["roe_json"])
    fase = Fase(fila["fase_actual"])
    return roe, MotorGuardrails(roe, memoria), fase, fila


def _guardar_evidencia_arsenal(memoria: MemoriaCaso, engagement_id: str,
                               fase: Fase, titulo: str, contenido: dict,
                               identidad: str) -> str:
    """Evidencia JSON real del arsenal, con cadena de custodia y auditoría."""
    from .models import Evidencia, TipoEvidencia
    import hashlib as _hashlib
    texto = json.dumps(contenido, ensure_ascii=False, sort_keys=True)
    ev = Evidencia(
        id=memoria.nuevo_id("ev"), engagement_id=engagement_id,
        tipo=TipoEvidencia.JSON, titulo=titulo, contenido=texto,
        hash_sha256=_hashlib.sha256(texto.encode()).hexdigest(),
        fase=fase, actor=Actor.HUMANO)
    memoria.guardar_evidencia(ev)
    memoria.registrar_auditoria(
        engagement_id, Actor.HUMANO, "arsenal.evidencia",
        detalle=f"{titulo} — por {identidad}",
        herramienta="consola", resultado="ok")
    return ev.id


@app.get("/api/engagements/{engagement_id}/arsenal")
def arsenal_estado(engagement_id: str) -> dict[str, Any]:
    """Estado real del arsenal del caso: reglas de detección incluidas,
    estado de persistencia en el host y configuración AD del despliegue."""
    with _memoria_de(engagement_id) as memoria:
        if memoria.obtener_engagement(engagement_id) is None:
            raise HTTPException(404, "no existe")
        evasiones: list[dict[str, Any]] = []
        for fila in memoria.listar_evidencias(engagement_id):
            titulo = str(fila["titulo"] or "")
            if not titulo.startswith("[Arsenal]"):
                continue
            e = dict(fila)
            contenido = e.get("contenido", "")
            if isinstance(contenido, str) and contenido.startswith("{"):
                try:
                    e["contenido"] = json.loads(contenido)
                except Exception:
                    pass
            evasiones.append(e)
        from . import evasion, persistencia
        return {
            "reglas_deteccion": evasion.reglas_incluidas(),
            "persistencia": persistencia.estado(),
            "evidencias": evasiones[-25:],
        }


@app.post("/api/engagements/{engagement_id}/arsenal/evasion")
def arsenal_evasion(engagement_id: str, p: PeticionEvasion,
                    request: Request) -> dict[str, Any]:
    """Genera el artefacto con transformación real y lo verifica contra el
    motor de detección (YARA) antes y después. Exige firma (boundary)."""
    import base64 as _base64
    from . import evasion
    identidad = operador_de(request)
    with _memoria_de(engagement_id) as memoria:
        roe, motor, fase, _fila = _guardrail_y_fase(engagement_id, memoria)
        argumentos = {"host": "127.0.0.1", "metodo": p.metodo, "formato": p.formato}
        veredicto = motor.evaluar("evasion.generar", argumentos, fase, actor="humano")
        if veredicto.denegado:
            raise HTTPException(403, veredicto.motivo)
        if veredicto.decision == DecisionGuardrail.REQUIERE_APROBACION:
            return {"estado": "espera_aprobacion",
                    "aprobacion_id": veredicto.aprobacion_id,
                    "motivo": veredicto.motivo}
        try:
            datos = _base64.b64decode(p.payload_b64, validate=True)
        except Exception:
            raise HTTPException(422, "payload_b64 no es base64 válido")
        if len(datos) > 100_000:
            raise HTTPException(422, "payload demasiado grande (máximo 100 KB)")
        resultado = evasion.generar(datos, p.metodo, p.formato)
        if "error" in resultado:
            raise HTTPException(422, resultado["error"])
        ev_id = _guardar_evidencia_arsenal(
            memoria, engagement_id, fase,
            f"[Arsenal][Evasion] {p.metodo}/{p.formato} "
            f"{resultado['hash_artefacto'][:12]}",
            {"tipo": "evasion", **resultado, "nota_operador": p.nota,
             "regla": "motor YARA real; evasión solo si detecciones=0 y "
                      "round-trip verificado"},
            identidad)
        return {"estado": "ejecutado", "evidencia_id": ev_id, "resultado": resultado}


@app.post("/api/engagements/{engagement_id}/arsenal/evasion/escanear")
def arsenal_escanear(engagement_id: str, p: PeticionEscaneo,
                     request: Request) -> dict[str, Any]:
    """Re-escaneo real (YARA) de un artefacto ya custodiado: bajo riesgo,
    el boundary lo permite directo y lo audita."""
    import base64 as _base64
    from . import evasion
    identidad = operador_de(request)
    with _memoria_de(engagement_id) as memoria:
        roe, motor, fase, _fila = _guardrail_y_fase(engagement_id, memoria)
        veredicto = motor.evaluar("evasion.escanear", {"host": "127.0.0.1"}, fase,
                                  actor="humano")
        if veredicto.denegado:
            raise HTTPException(403, veredicto.motivo)
        evidencias = memoria.listar_evidencias(engagement_id)
        objetivo = next((e for e in evidencias if e["id"] == p.evidencia_id), None)
        if objetivo is None:
            raise HTTPException(404, "evidencia no encontrada")
        try:
            contenido = json.loads(objetivo["contenido"])
            artefacto = _base64.b64decode(contenido["artefacto_b64"])
        except Exception:
            raise HTTPException(422, "la evidencia no contiene un artefacto "
                                     "de evasión escaneable")
        escaneo = evasion.escanear(artefacto)
        return {"estado": "ejecutado", "evidencia_id": p.evidencia_id,
                "escaneo": escaneo, "operador": identidad}


class _PeticionPersistenciaAccion(BaseModel):
    metodo: str = Field(min_length=2, max_length=40)
    raiz: str = Field(default="", max_length=253)


@app.post("/api/engagements/{engagement_id}/arsenal/persistencia")
def arsenal_persistencia(engagement_id: str, p: PeticionPersistencia,
                         request: Request) -> dict[str, Any]:
    """Implanta persistencia REAL en el host del lab con prueba de
    activación. Alta riesgo: el boundary exige firma del operador."""
    identidad = operador_de(request)
    with _memoria_de(engagement_id) as memoria:
        roe, motor, fase, _fila = _guardrail_y_fase(engagement_id, memoria)
        argumentos = {"host": "127.0.0.1", "metodo": p.metodo, "comando": p.comando}
        veredicto = motor.evaluar("persistencia.implantar", argumentos, fase,
                                  actor="humano")
        if veredicto.denegado:
            raise HTTPException(403, veredicto.motivo)
        if veredicto.decision == DecisionGuardrail.REQUIERE_APROBACION:
            return {"estado": "espera_aprobacion",
                    "aprobacion_id": veredicto.aprobacion_id,
                    "motivo": veredicto.motivo}
        resultado = _ejecutar_persistencia(
            memoria, engagement_id, fase, identidad,
            metodo=p.metodo, comando=p.comando, raiz=p.raiz, accion="implantar")
        return resultado


def _ejecutar_persistencia(memoria: MemoriaCaso, engagement_id: str, fase: Fase,
                           identidad: str, *, metodo: str, comando: str = "",
                           raiz: str = "", accion: str) -> dict[str, Any]:
    from . import persistencia
    if accion == "implantar":
        resultado = persistencia.implantar(metodo, comando, raiz=raiz or None)
        titulo = f"[Arsenal][Persistencia] implantado {metodo}"
    elif accion == "verificar":
        resultado = persistencia.verificar(metodo, raiz=raiz or None)
        titulo = f"[Arsenal][Persistencia] verificado {metodo}"
    else:
        resultado = persistencia.retirar(metodo, raiz=raiz or None)
        titulo = f"[Arsenal][Persistencia] retirado {metodo}"
    if "error" in resultado and not resultado.get("implantado", resultado.get("retirado", True)):
        return {"estado": "fallo", "error": resultado["error"], "resultado": resultado}
    ev_id = _guardar_evidencia_arsenal(
        memoria, engagement_id, fase, titulo,
        {"tipo": "persistencia", "accion": accion, **resultado}, identidad)
    return {"estado": "ejecutado", "evidencia_id": ev_id, "resultado": resultado}


@app.post("/api/engagements/{engagement_id}/arsenal/persistencia/verificar")
def arsenal_persistencia_verificar(engagement_id: str, p: _PeticionPersistenciaAccion,
                                   request: Request) -> dict[str, Any]:
    identidad = operador_de(request)
    with _memoria_de(engagement_id) as memoria:
        roe, motor, fase, _fila = _guardrail_y_fase(engagement_id, memoria)
        veredicto = motor.evaluar(
            "persistencia.verificar",
            {"host": "127.0.0.1", "metodo": p.metodo}, fase, actor="humano")
        if veredicto.denegado:
            raise HTTPException(403, veredicto.motivo)
        return _ejecutar_persistencia(
            memoria, engagement_id, fase, identidad,
            metodo=p.metodo, raiz=p.raiz, accion="verificar")


@app.post("/api/engagements/{engagement_id}/arsenal/persistencia/retirar")
def arsenal_persistencia_retirar(engagement_id: str, p: _PeticionPersistenciaAccion,
                                 request: Request) -> dict[str, Any]:
    """Limpieza REAL con verificación de ausencia: higiene de cierre."""
    identidad = operador_de(request)
    with _memoria_de(engagement_id) as memoria:
        roe, motor, fase, _fila = _guardrail_y_fase(engagement_id, memoria)
        veredicto = motor.evaluar(
            "persistencia.retirar",
            {"host": "127.0.0.1", "metodo": p.metodo}, fase, actor="humano")
        if veredicto.denegado:
            raise HTTPException(403, veredicto.motivo)
        return _ejecutar_persistencia(
            memoria, engagement_id, fase, identidad,
            metodo=p.metodo, raiz=p.raiz, accion="retirar")


@app.post("/api/engagements/{engagement_id}/arsenal/ad")
def arsenal_ad(engagement_id: str, p: PeticionAccionAD,
               request: Request) -> dict[str, Any]:
    """Acción AD ofensiva real (impacket/LDAP) contra el host del ROE.
    El boundary decide: lecturas bajas pasan; roasting/dcsync/PTH exigen firma."""
    identidad = operador_de(request)
    herramienta = HERRAMIENTA_AD[p.accion]
    argumentos: dict[str, Any] = {"host": p.host or "127.0.0.1"}
    # Validación de entrada ANTES del boundary: nunca crear una aprobación
    # para una petición malformada.
    if p.accion == "dcsync":
        if not p.dn_objetivo:
            raise HTTPException(422, "dcsync exige dn_objetivo (p. ej. CN=krbtgt,CN=Users,...)")
        argumentos["dn_objetivo"] = p.dn_objetivo
    if p.accion == "pass_the_hash":
        if not (p.usuario and p.hash_nt):
            raise HTTPException(422, "pass_the_hash exige usuario y hash_nt")
        if not re.fullmatch(r"[0-9a-fA-F]{32}", p.hash_nt.strip().replace(":", "")):
            raise HTTPException(422, "hash_nt debe ser 32 hexadecimales (formato NTLM)")
        argumentos.update({"usuario": p.usuario, "hash_nt": p.hash_nt})
    with _memoria_de(engagement_id) as memoria:
        roe, motor, fase, _fila = _guardrail_y_fase(engagement_id, memoria)
        veredicto = motor.evaluar(herramienta, argumentos, fase, actor="humano")
        if veredicto.denegado:
            raise HTTPException(403, veredicto.motivo)
        if veredicto.decision == DecisionGuardrail.REQUIERE_APROBACION:
            return {"estado": "espera_aprobacion",
                    "aprobacion_id": veredicto.aprobacion_id,
                    "motivo": veredicto.motivo}
        resultado = transportes_de(roe).get(herramienta)(**argumentos)
        if isinstance(resultado, dict) and resultado.get("error"):
            return {"estado": "sin_resultado", "resultado": resultado,
                    "nota": "el módulo reporta el requisito o fallo real: "
                            "nunca datos inventados"}
        ev_id = _guardar_evidencia_arsenal(
            memoria, engagement_id, fase,
            f"[Arsenal][AD] {p.accion} {argumentos['host']}",
            {"tipo": "ad", "accion": p.accion, **resultado}, identidad)
        return {"estado": "ejecutado", "evidencia_id": ev_id, "resultado": resultado}


# ---------------------------------------------------------------------------
# Autenticación de operadores (cuentas reales, JWT, control de acceso)
# ---------------------------------------------------------------------------


class PeticionRegistro(BaseModel):
    usuario: str = Field(min_length=3, max_length=32)
    contrasena: str = Field(min_length=8, max_length=128)
    rol: str = "admin"
    # Organización destino del alta (solo admin: bootstrap/otros tenants).
    tenant_id: str | None = Field(default=None, max_length=41)


class PeticionLogin(BaseModel):
    usuario: str = Field(min_length=1, max_length=32)
    contrasena: str = Field(min_length=1, max_length=128)


class PeticionContrasena(BaseModel):
    actual: str = Field(min_length=1, max_length=128)
    nueva: str = Field(min_length=8, max_length=128)


class PeticionBaja(BaseModel):
    usuario: str = Field(min_length=3, max_length=32)


@app.get("/api/auth/estado")
def auth_estado() -> dict[str, Any]:
    """Público: indica si el despliegue ya tiene operadores dados de alta.

    Sin operadores, la consola muestra el alta de arranque (bootstrap):
    la primera cuenta creada es admin del despliegue.
    """
    return {"hay_operadores": auth.hay_operadores()}


@app.post("/api/auth/registrar")
def auth_registrar(p: PeticionRegistro, request: Request) -> dict[str, Any]:
    """Alta de operador.

    - Bootstrap: si NO hay operadores, la primera cuenta es admin (sin token).
    - Después: SOLO un admin autenticado puede dar de alta cuentas.

    Nota: la ruta es pública en el middleware (el bootstrap no tiene sesión),
    así que la identidad del admin se verifica AQUÍ con el JWT explícito.
    """
    _guardar_rate(request, ":registrar")
    bootstrap = not auth.hay_operadores()
    if not bootstrap:
        cabecera = request.headers.get("Authorization", "")
        claims = (auth.verificar_token(cabecera[7:])
                  if cabecera.startswith("Bearer ") else None)
        if not claims or not auth.tiene_nivel(claims.get("rol", ""), 4):
            raise HTTPException(
                403, "Solo un operador admin puede dar de alta cuentas.")
        rol = p.rol
    else:
        rol = "admin"
    tenant = auth.TENANT_PREDETERMINADA
    # En este punto el peticionario es SIEMPRE admin (o el bootstrap): se
    # honra su elección de organización, pero solo si ya existe — jamás se
    # crea una cuenta huérfana de tenant.
    if p.tenant_id:
        candidata = p.tenant_id.strip().lower()
        if candidata and auth.organizacion_existe(candidata):
            tenant = candidata
    try:
        cuenta = auth.crear_operador(p.usuario, p.contrasena, rol, tenant)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    auth.registrar_auditoria_sistema(
        operador_de(request), "operador.alta",
        f"{p.usuario} · rol {rol} · organización {tenant}")
    return cuenta


@app.post("/api/auth/login")
def auth_login(p: PeticionLogin, request: Request) -> dict[str, Any]:
    """Login real: scrypt + bloqueo temporal por fuerza bruta → JWT."""
    _guardar_rate(request, ":login")
    try:
        sesion = auth.verificar_credenciales(p.usuario, p.contrasena)
    except ValueError as exc:  # cuenta bloqueada temporalmente
        raise HTTPException(429, str(exc))
    if not sesion:
        raise HTTPException(401, "Credenciales incorrectas")
    token = auth.emitir_token(sesion["usuario"], sesion["rol"],
                              sesion.get("tenant_id", auth.TENANT_PREDETERMINADA))
    return {**sesion, **token}


@app.get("/api/auth/sesion")
def auth_sesion(request: Request) -> dict[str, Any]:
    """Verificación de sesión activa (el cliente la usa al arrancar)."""
    claims = getattr(request.state, "operador", None) or {}
    return {"usuario": claims.get("sub"), "rol": claims.get("rol"),
            "tenant_id": claims.get("ten") or auth.TENANT_PREDETERMINADA,
            "expira_en": claims.get("exp")}


@app.post("/api/auth/contrasena")
def auth_contrasena(p: PeticionContrasena, request: Request) -> dict[str, Any]:
    claims = getattr(request.state, "operador", None) or {}
    try:
        cambiada = auth.cambiar_contrasena(str(claims.get("sub")), p.actual, p.nueva)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    if not cambiada:
        raise HTTPException(401, "La contraseña actual no es correcta")
    return {"cambiada": True}


@app.get("/api/auth/operadores")
def auth_operadores(request: Request) -> list[dict[str, Any]]:
    """Listado de cuentas autenticadas (sin material sensible)."""
    return auth.listar_operadores()


@app.post("/api/auth/eliminar")
def auth_eliminar(p: PeticionBaja, request: Request) -> dict[str, Any]:
    claims = getattr(request.state, "operador", None) or {}
    if not auth.tiene_nivel(claims.get("rol", ""), 4):
        raise HTTPException(403, "Solo un operador admin puede eliminar cuentas.")
    try:
        auth.eliminar_operador(p.usuario, str(claims.get("sub")))
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    return {"eliminado": p.usuario}


class PeticionRol(BaseModel):
    usuario: str = Field(min_length=3, max_length=32)
    rol: str = Field(pattern="^(admin|gestor|operador|lector)$")


class PeticionRestablecer(BaseModel):
    usuario: str = Field(min_length=3, max_length=32)
    nueva: str = Field(min_length=8, max_length=128)


@app.post("/api/auth/rol")
def auth_rol(p: PeticionRol, request: Request) -> dict[str, Any]:
    """Cambio de rol de una cuenta (solo admin, con protección de último admin)."""
    claims = getattr(request.state, "operador", None) or {}
    if not auth.tiene_nivel(claims.get("rol", ""), 4):
        raise HTTPException(403, "Solo un operador admin puede cambiar roles.")
    try:
        return auth.cambiar_rol(p.usuario, p.rol, str(claims.get("sub")))
    except ValueError as exc:
        raise HTTPException(400, str(exc))


@app.post("/api/auth/restablecer")
def auth_restablecer(p: PeticionRestablecer, request: Request) -> dict[str, Any]:
    """Restablecimiento administrativo de credencial (solo admin)."""
    claims = getattr(request.state, "operador", None) or {}
    if not auth.tiene_nivel(claims.get("rol", ""), 4):
        raise HTTPException(403, "Solo un operador admin puede restablecer credenciales.")
    try:
        return auth.restablecer_contrasena(p.usuario, p.nueva)
    except ValueError as exc:
        raise HTTPException(400, str(exc))


# ---------------------------------------------------------------------------
# Organizaciones (multi-tenant v21) y SSO OIDC
# ---------------------------------------------------------------------------


class PeticionOrganizacion(BaseModel):
    id: str = Field(min_length=2, max_length=41)
    nombre: str = Field(min_length=2, max_length=120)


class PeticionTenant(BaseModel):
    usuario: str = Field(min_length=3, max_length=32)
    tenant_id: str = Field(min_length=2, max_length=41)


@app.get("/api/auth/organizaciones")
def auth_organizaciones(request: Request) -> list[dict[str, Any]]:
    """Lista de organizaciones. Admin: todas; gestor/operador/lector: la suya."""
    if es_admin(request):
        return auth.listar_organizaciones()
    return [o for o in auth.listar_organizaciones() if o["id"] == tenant_de(request)]


@app.post("/api/auth/organizaciones")
def auth_crear_organizacion(p: PeticionOrganizacion, request: Request) -> dict[str, Any]:
    if not es_admin(request):
        raise HTTPException(403, "Solo un operador admin puede crear organizaciones.")
    try:
        org = auth.crear_organizacion(p.id, p.nombre)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    auth.registrar_auditoria_sistema(
        operador_de(request), "organizacion.alta", f"{p.id} ({p.nombre})")
    return org


@app.post("/api/auth/tenant")
def auth_asignar_tenant(p: PeticionTenant, request: Request) -> dict[str, Any]:
    if not es_admin(request):
        raise HTTPException(
            403, "Solo un operador admin puede mover cuentas de organización.")
    try:
        resultado = auth.asignar_tenant(p.usuario, p.tenant_id)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    auth.registrar_auditoria_sistema(
        operador_de(request), "operador.tenant",
        f"{p.usuario} → {p.tenant_id}")
    return resultado


@app.get("/api/auth/sso/estado")
def auth_sso_estado() -> dict[str, Any]:
    """Público: ¿el despliegue tiene SSO OIDC activo? (sin secretos)."""
    return sso.estado()


@app.get("/api/auth/sso/inicio")
def auth_sso_inicio() -> dict[str, Any]:
    """Inicio del flujo: URL de autorización del IdP con state+PKCE."""
    try:
        return sso.url_autorizacion()
    except RuntimeError as exc:
        raise HTTPException(503, str(exc))


@app.get("/api/auth/sso/callback")
def auth_sso_callback(request: Request) -> dict[str, Any]:
    """Callback del flujo: canjea el código, VERIFICA el id_token (RS256,
    iss/aud/exp/nonce) y emite el JWT de la plataforma."""
    code = request.query_params.get("code", "")
    state = request.query_params.get("state", "")
    try:
        cuenta = sso.canjear_codigo(code, state)
    except RuntimeError as exc:
        raise HTTPException(401, str(exc))
    except ValueError as exc:
        raise HTTPException(403, str(exc))
    token = auth.emitir_token(cuenta["usuario"], cuenta["rol"],
                              cuenta.get("tenant_id", auth.TENANT_PREDETERMINADA))
    auth.registrar_auditoria_sistema(
        cuenta["usuario"], "sso.login", "Login federado OIDC verificado")
    return {**cuenta, **token}


# ---------------------------------------------------------------------------
# Planificación threat-led (v21): cadenas estilo Atomic Red Team.
# Conocimiento + contraste contra lo EJERCITADO del caso: nada se ejecuta
# desde aquí, y el plan solo puede declarar "ejercitado" con evidencia real.
# ---------------------------------------------------------------------------


@app.get("/api/threatled/cadenas")
def threatled_cadenas() -> dict[str, Any]:
    cadenas = threatled.catalogo()
    return {"cadenas": cadenas, "total": len(cadenas),
            "ruido": "cada paso muestra el ruido REAL que el boundary exigirá"}


@app.get("/api/threatled/cadenas/{cadena_id}")
def threatled_cadena(cadena_id: str) -> dict[str, Any]:
    cadena = threatled.obtener(cadena_id)
    if not cadena:
        raise HTTPException(
            404, f"Cadena '{cadena_id}' no existe: consulta /api/threatled/cadenas")
    return threatled.detalle(cadena)


class PeticionPlanThreatled(BaseModel):
    cadena_id: str = Field(min_length=3, max_length=60)


@app.post("/api/engagements/{engagement_id}/threatled/plan")
def threatled_plan(engagement_id: str, p: PeticionPlanThreatled,
                   request: Request) -> dict[str, Any]:
    """Plan threat-led CONTRASTADO con este caso: cada paso queda como
    ejercitado (con evidencia real), disponible (herramienta del boundary)
    o manual (guion del operador). Queda en auditoría y custodia."""
    cadena = threatled.obtener(p.cadena_id)
    if not cadena:
        raise HTTPException(
            404, f"Cadena '{p.cadena_id}' no existe: consulta /api/threatled/cadenas")
    with _memoria_de(engagement_id) as memoria:
        fila = memoria.obtener_engagement(engagement_id)
        if not fila:
            raise HTTPException(404, "no existe")
        hallazgos = [dict(h) for h in memoria.listar_hallazgos(engagement_id)]
        acciones = [dict(a) for a in memoria.listar_auditoria(engagement_id, 1000)]
        tecnicas = threatled.tecnicas_ejercitadas_de(hallazgos, acciones)
        plan = threatled.plan_para_caso(cadena, tecnicas)
        plan["caso"] = {"id": engagement_id, "nombre": fila["nombre"],
                        "cliente": fila["cliente"]}
        memoria.registrar_auditoria(
            engagement_id, Actor.HUMANO, "threatled.plan",
            detalle=f"Plan threat-led '{cadena.nombre}' contrastado "
                    f"({plan['resumen']['ejercitados']} ejercitados / "
                    f"{plan['resumen']['disponibles']} disponibles / "
                    f"{plan['resumen']['manuales']} manuales)",
            herramienta="threatled", resultado="ok")
        ev = memoria.guardar_evidencia(Evidencia(
            id=MemoriaCaso.nuevo_id("ev"),
            engagement_id=engagement_id,
            tipo="json", titulo=f"Plan threat-led: {cadena.nombre}",
            contenido=json.dumps(plan, ensure_ascii=False, indent=2),
            hash_sha256="", firma_hmac="", hash_previo="",
            fase=fila["fase_actual"], actor=Actor.HUMANO, hallazgo_id=None,
            creado_en=datetime.now(timezone.utc).isoformat()))
        plan["evidencia_id"] = ev.id
        return plan


# ---------------------------------------------------------------------------
# Modo continuo CTEM (v23): la exposición se mide PERIÓDICAMENTE. Una corrida
# es una instantánea REAL del caso (hallazgos, auditoría, detecciones VECTR)
# contrastada con la cadena y con la corrida anterior (delta). La corrida
# MIDE: no ejecuta técnicas ni fabrica argumentos — eso sigue siendo
# territorio del operador y del boundary.
# ---------------------------------------------------------------------------


class PeticionProgramaCtem(BaseModel):
    cadena_id: str = Field(min_length=3, max_length=60)
    intervalo_horas: int = Field(ge=ctem.INTERVALO_MIN_HORAS,
                                 le=ctem.INTERVALO_MAX_HORAS)


class PeticionCorridaCtem(BaseModel):
    cadena_id: str = Field(min_length=3, max_length=60)


@app.get("/api/engagements/{engagement_id}/ctem")
def ctem_estado(engagement_id: str, request: Request) -> dict[str, Any]:
    """Estado continuo del caso: programas, corridas y último delta."""
    with _memoria_de(engagement_id) as memoria:
        if memoria.obtener_engagement(engagement_id) is None:
            raise HTTPException(404, "no existe")
        programas = ctem.programas_de(memoria, engagement_id)
        corridas = ctem.corridas_de(memoria, engagement_id, limite=50)
        ultimo = corridas[0]["resumen"] if corridas else None
        return {
            "programas": programas,
            "corridas": corridas,
            "ultimo_resumen": ultimo,
            "ultimo_delta": (ultimo or {}).get("delta"),
        }


@app.post("/api/engagements/{engagement_id}/ctem/programas")
def ctem_programar(engagement_id: str, p: PeticionProgramaCtem,
                   request: Request) -> dict[str, Any]:
    """Programa (o reprograma) una cadena como instrumento continuo:
    corrida automática cada `intervalo_horas` (planificador del despliegue)."""
    identidad = operador_de(request)
    cadena = threatled.obtener(p.cadena_id)
    if cadena is None:
        raise HTTPException(
            404, f"Cadena '{p.cadena_id}' no existe: consulta /api/threatled/cadenas")
    with _memoria_de(engagement_id) as memoria:
        if memoria.obtener_engagement(engagement_id) is None:
            raise HTTPException(404, "no existe")
        try:
            programa = ctem.programar(
                memoria, engagement_id, p.cadena_id, p.intervalo_horas,
                operador=identidad)
        except ValueError as e:
            raise HTTPException(422, str(e))
        memoria.registrar_auditoria(
            engagement_id, Actor.HUMANO, "ctem.programar",
            detalle=(f"Cadena '{cadena.nombre}' {programa['estado']} en modo "
                     f"continuo: corrida cada {p.intervalo_horas} h"),
            herramienta="ctem", resultado="ok")
        return programa


@app.post("/api/engagements/{engagement_id}/ctem/corridas")
def ctem_corrida(engagement_id: str, p: PeticionCorridaCtem,
                 request: Request) -> dict[str, Any]:
    """Ejecuta una corrida AHORA: instantánea real + delta contra la corrida
    anterior de la misma cadena. Custodiada como evidencia y notificada por
    webhook a los receptores suscritos a `ctem.corrida`."""
    identidad = operador_de(request)
    cadena = threatled.obtener(p.cadena_id)
    if cadena is None:
        raise HTTPException(
            404, f"Cadena '{p.cadena_id}' no existe: consulta /api/threatled/cadenas")
    with _memoria_de(engagement_id) as memoria:
        if memoria.obtener_engagement(engagement_id) is None:
            raise HTTPException(404, "no existe")
        resumen = ctem.ejecutar_corrida(
            memoria, engagement_id, cadena, disparo="manual",
            operador=identidad)
        try:
            from .webhook import despachar_en_segundo_plano
            despachar_en_segundo_plano(
                "ctem.corrida", engagement_id,
                {"corrida_id": resumen["corrida_id"],
                 "cadena_id": cadena.id,
                 "cobertura": resumen["cobertura"],
                 "delta": resumen["delta"]})
        except Exception:
            pass  # los webhooks nunca bloquean la operación (v16)
        return resumen


@app.delete("/api/engagements/{engagement_id}/ctem/programas/{programa_id}")
def ctem_cancelar(engagement_id: str, programa_id: str,
                  request: Request) -> dict[str, Any]:
    """Detiene el modo continuo de una cadena (historial conservado)."""
    identidad = operador_de(request)
    with _memoria_de(engagement_id) as memoria:
        try:
            resultado = ctem.cancelar(memoria, engagement_id, programa_id)
        except LookupError as e:
            raise HTTPException(404, str(e))
        memoria.registrar_auditoria(
            engagement_id, Actor.HUMANO, "ctem.cancelar",
            detalle=(f"Programa continuo {programa_id} detenido "
                     f"(cadena {resultado['cadena_id']}) por {identidad}"),
            herramienta="ctem", resultado="ok")
        return resultado


# ---------------------------------------------------------------------------
# Enriquecimiento con threat intel REAL (MISP, v21): los activos del caso
# se contrastan contra el intel del equipo y las coincidencias se custodian.
# ---------------------------------------------------------------------------


class PeticionEnriquecer(BaseModel):
    valores: list[Annotated[str, Field(max_length=253)]] = Field(
        default_factory=list, max_length=50)
    # Sin valores explícitos se usan los activos del caso (objetivos con
    # forma de dominio/host/IP) — siempre datos reales del engagement.


@app.post("/api/engagements/{engagement_id}/threat-intel/enriquecer")
def enriquecer_threat_intel(engagement_id: str, p: PeticionEnriquecer,
                            request: Request) -> dict[str, Any]:
    try:
        from .integraciones import misp
    except ImportError:
        from integraciones import misp
    valores = p.valores
    if not valores:
        with _memoria_de(engagement_id) as memoria:
            if not memoria.obtener_engagement(engagement_id):
                raise HTTPException(404, "no existe")
            objetivo = {"dominio", "host", "servicio"}
            valores = [o["nombre"] for o in memoria.listar_objetivos(engagement_id)
                       if o["tipo"] in objetivo][:50]
    if not valores:
        return {"conectado": False,
                "error": "El caso no tiene activos consultables aún y no "
                         "se indicaron valores; ejecuta fases de recon o "
                         "pásalos explícitos."}
    resultado = misp.buscar_iocs(valores)
    if resultado.get("conectado") and resultado.get("total", 0) > 0:
        with _memoria_de(engagement_id) as memoria:
            if memoria.obtener_engagement(engagement_id):
                memoria.guardar_evidencia(Evidencia(
                    id=MemoriaCaso.nuevo_id("ev"),
                    engagement_id=engagement_id,
                    tipo="json",
                    titulo=f"Threat intel MISP: {resultado['total']} coincidencia(s)",
                    contenido=json.dumps(resultado, ensure_ascii=False, indent=2),
                    hash_sha256="", firma_hmac="", hash_previo="",
                    fase=memoria.obtener_engagement(engagement_id)["fase_actual"],
                    actor=Actor.HUMANO, hallazgo_id=None,
                    creado_en=datetime.now(timezone.utc).isoformat()))
                memoria.registrar_auditoria(
                    engagement_id, Actor.HUMANO, "threat_intel.enriquecer",
                    detalle=f"MISP: {resultado['total']} coincidencia(s) sobre "
                            f"{len(resultado['buscados'])} valores",
                    herramienta="misp", resultado="ok")
    return resultado


# ---------------------------------------------------------------------------
# Paquete purple team y respaldo completo del sistema (v15)
# ---------------------------------------------------------------------------

@app.get("/api/engagements/{engagement_id}/purple-team.zip")
def paquete_purple_team(engagement_id: str, request: Request) -> Response:
    """ZIP con el informe purple team del caso (resultados de detección del
    blue team, patrón VECTR) y esqueletos Sigma para las técnicas cuya
    fuente de logs es conocida. Solo datos reales del caso."""
    identidad = operador_de(request)
    with _memoria_de(engagement_id) as memoria:
        try:
            contenido, resumen = construir_paquete_purple(engagement_id, memoria)
        except ValueError as exc:  # p. ej. "sin hallazgos"
            raise HTTPException(409, str(exc))
        memoria.registrar_auditoria(
            engagement_id, Actor.HUMANO, "caso.purple_team",
            detalle=(f"paquete purple team generado ({resumen['reglas']} reglas "
                     f"Sigma, {resumen['sin_fuente']} técnicas sin fuente "
                     f"mapeada) — por {identidad}"),
            herramienta="consola", resultado="ok")
    return Response(
        content=contenido, media_type="application/zip",
        headers={"Content-Disposition":
                 f'attachment; filename="purple_{engagement_id}.zip"'})


@app.get("/api/admin/respaldo-completo")
def respaldo_completo(request: Request) -> Response:
    """Copia de seguridad consistente de TODAS las BDs del sistema
    (usuarios.db + cada caso) vía VACUUM INTO, con manifiesto SHA-256.
    Solo admin; la acción queda en la auditoría de sistema."""
    claims = getattr(request.state, "operador", None) or {}
    if not auth.tiene_nivel(claims.get("rol", ""), 4):
        raise HTTPException(403, "solo admin")
    identidad = str(claims.get("sub") or "?")
    contenido, manifiesto = construir_respaldo_completo(
        RAIZ_CASOS, auth.RUTA_DB)
    auth.registrar_auditoria_sistema(
        identidad, "sistema.respaldo",
        f"respaldo completo: {manifiesto['total_bases']} BDs, "
        f"{len(contenido)} bytes")
    marca = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    return Response(
        content=contenido, media_type="application/zip",
        headers={"Content-Disposition":
                 f'attachment; filename="orquesta_respaldo_{marca}.zip"'})


@app.get("/api/admin/auditoria-sistema")
def auditoria_sistema(request: Request, limite: int = 200) -> list[dict[str, Any]]:
    """Auditoría de nivel despliegue (respaldos, gestión de cuentas)."""
    claims = getattr(request.state, "operador", None) or {}
    if not auth.tiene_nivel(claims.get("rol", ""), 4):
        raise HTTPException(403, "solo admin")
    acotado = min(max(limite, 1), 1000)
    return auth.listar_auditoria_sistema(acotado)


# ---------------------------------------------------------------------------
# Webhooks de notificación operativa (v16): receptores configurables por el
# admin, entrega real firmada con registro de entregas. La gestión queda en
# la auditoría de sistema.
# ---------------------------------------------------------------------------


class PeticionWebhookAlta(BaseModel):
    url: str = Field(min_length=8, max_length=2048)
    eventos: list[Annotated[str, Field(max_length=40)]] = Field(
        min_length=1, max_length=10)
    secreto: str = Field(default="", max_length=256)
    descripcion: str = Field(default="", max_length=200)


class PeticionWebhookCambio(BaseModel):
    url: str | None = Field(default=None, min_length=8, max_length=2048)
    eventos: list[Annotated[str, Field(max_length=40)]] | None = Field(
        default=None, min_length=1, max_length=10)
    activo: bool | None = None
    descripcion: str | None = Field(default=None, max_length=200)
    secreto: str | None = Field(default=None, max_length=256)


def _admin_webhooks(request: Request) -> str:
    claims = getattr(request.state, "operador", None) or {}
    if not auth.tiene_nivel(claims.get("rol", ""), 4):
        raise HTTPException(403, "Solo un operador admin gestiona webhooks.")
    return str(claims.get("sub") or "?")


def _modulo_webhook():
    try:
        from . import webhook
    except ImportError:
        from orchestrator import webhook  # type: ignore
    return webhook


@app.get("/api/admin/webhooks")
def webhooks_lista(request: Request) -> dict[str, Any]:
    """Receptores configurados (SIN secretos) y catálogo de eventos."""
    _admin_webhooks(request)
    wh = _modulo_webhook()
    return {"receptores": wh.listar_webhooks(), "eventos": list(wh.EVENTOS)}


@app.post("/api/admin/webhooks")
def webhooks_alta(p: PeticionWebhookAlta, request: Request) -> dict[str, Any]:
    """Alta de receptor. El secreto generado (si no se aporta) SOLO se
    devuelve en esta respuesta: nunca vuelve a salir de la BD."""
    identidad = _admin_webhooks(request)
    wh = _modulo_webhook()
    try:
        creado = wh.crear_webhook(p.url, p.eventos, p.secreto, p.descripcion)
    except ValueError as exc:
        raise HTTPException(422, str(exc))
    auth.registrar_auditoria_sistema(
        identidad, "webhook.alta",
        f"{creado['id']} → {creado['url']} ({', '.join(creado['eventos'])})")
    return creado


@app.patch("/api/admin/webhooks/{webhook_id}")
def webhooks_cambio(webhook_id: str, p: PeticionWebhookCambio,
                    request: Request) -> dict[str, Any]:
    identidad = _admin_webhooks(request)
    wh = _modulo_webhook()
    try:
        actualizado = wh.actualizar_webhook(
            webhook_id, url=p.url, eventos=p.eventos, activo=p.activo,
            descripcion=p.descripcion, secreto=p.secreto)
    except ValueError as exc:
        raise HTTPException(422, str(exc))
    except LookupError as exc:
        raise HTTPException(404, str(exc))
    auth.registrar_auditoria_sistema(
        identidad, "webhook.actualizar",
        f"{webhook_id}: {', '.join(k for k in p.model_dump(exclude_none=True))}")
    return actualizado


@app.delete("/api/admin/webhooks/{webhook_id}")
def webhooks_baja(webhook_id: str, request: Request) -> dict[str, Any]:
    identidad = _admin_webhooks(request)
    wh = _modulo_webhook()
    try:
        wh.eliminar_webhook(webhook_id)
    except LookupError as exc:
        raise HTTPException(404, str(exc))
    auth.registrar_auditoria_sistema(
        identidad, "webhook.baja", f"{webhook_id} eliminado con sus entregas")
    return {"eliminado": webhook_id}


@app.post("/api/admin/webhooks/{webhook_id}/probar")
def webhooks_probar(webhook_id: str, request: Request) -> dict[str, Any]:
    """Ping REAL sincrónico al receptor (webhook.prueba firmado)."""
    identidad = _admin_webhooks(request)
    wh = _modulo_webhook()
    try:
        resultado = wh.probar_webhook(webhook_id)
    except LookupError as exc:
        raise HTTPException(404, str(exc))
    auth.registrar_auditoria_sistema(
        identidad, "webhook.prueba",
        f"{webhook_id}: {'entregado' if resultado['enviado'] else 'FALLO'} "
        f"(http={resultado['http']}, intento con reintento)")
    return resultado


@app.get("/api/admin/webhooks/{webhook_id}/entregas")
def webhooks_entregas(webhook_id: str, request: Request,
                      limite: int = 20) -> list[dict[str, Any]]:
    """Últimas entregas del receptor (resultado HTTP real de cada una)."""
    _admin_webhooks(request)
    wh = _modulo_webhook()
    if not any(w["id"] == webhook_id for w in wh.listar_webhooks()):
        raise HTTPException(404, f"webhook {webhook_id} no existe")
    return wh.entregas_de(webhook_id, limite)


# ---------------------------------------------------------------------------
# Analítica de cobertura ATT&CK entre campañas (v16): matriz técnica ×
# campaña agregada de TODOS los casos del despliegue (solo lectura).
# ---------------------------------------------------------------------------


@app.get("/api/analitica/cobertura-attack")
def cobertura_attack() -> dict[str, Any]:
    """Cobertura ATT&CK agregada entre campañas: matriz técnica × campaña,
    técnicas recurrentes y cobertura de detección por campaña (VECTR).
    Solo técnicas con ID ATT&CK válido; solo lectura."""
    try:
        from . import cobertura_attack
    except ImportError:
        from orchestrator import cobertura_attack  # type: ignore
    return cobertura_attack.construir_cobertura(RAIZ_CASOS)


@app.get("/api/analitica/cobertura-attack.csv")
def cobertura_attack_csv() -> Response:
    """Matriz técnica × campaña en CSV (una fila por celda poblada)."""
    try:
        from . import cobertura_attack
    except ImportError:
        from orchestrator import cobertura_attack  # type: ignore
    cobertura = cobertura_attack.construir_cobertura(RAIZ_CASOS)
    contenido = cobertura_attack.csv_cobertura(cobertura)
    return Response(
        content=contenido, media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition":
                 'attachment; filename="cobertura_attack_orquesta.csv"'})


# ---------------------------------------------------------------------------
# Eventos en vivo (SSE): auditoría del caso en tiempo real
# ---------------------------------------------------------------------------


def _parse_last_event_id(valor: str | None) -> int | None:
    """Convierte la cabecera Last-Event-ID en punto de partida seguro:
    solo enteros no negativos; cualquier otra cosa (None, 'banana', '-3')
    significa 'sin punto de partida fiable'."""
    if not valor:
        return None
    bruto = valor.strip()
    if not bruto.isdigit():
        return None
    return int(bruto)


def flujo_eventos_sse(ruta_db: Path, engagement_id: str,
                      punto_partida: int | None = None):
    """Generador del flujo SSE de auditoría del caso (función de módulo
    para poder testearla con islice sin abrir una conexión infinita).

    La consola consume el flujo con fetch+ReadableStream (permite enviar el
    token JWT en cabecera, a diferencia de EventSource). Heartbeat cada
    ciclo; la conexión se recicla cada 4 minutos y el cliente reconecta.

    Resiliencia estándar SSE (MDN): cada evento lleva `id:` y, si el
    cliente reconecta enviando `Last-Event-ID`, el flujo se reanuda en el
    evento siguiente a ese id (sin huecos ni duplicados) en lugar de
    saltar a la cola del flujo.
    """
    import sqlite3 as _sq
    import time as _t
    # check_same_thread=False: Starlette itera el generador síncrono a
    # través del pool de workers de anyio y puede CAMBIAR de hilo entre
    # celdas del generador. La conexión la crea y la cierra únicamente
    # este generador (un propietario), por lo que el uso es seguro; con
    # la comprobación por defecto el flujo SSE moría con
    # ProgrammingError "created in a thread can only be used in that
    # same thread" al reciclar la conexión.
    conn = _sq.connect(str(ruta_db),
                       check_same_thread=False, timeout=10)
    conn.row_factory = _sq.Row
    conn.execute("PRAGMA busy_timeout=5000")
    maximo = conn.execute(
        "SELECT COALESCE(MAX(rowid), 0) FROM auditoria").fetchone()[0]
    # Reanudación honesta: un id válido dentro de la cola reanuda ahí;
    # un id imposible (no numérico, negativo o más allá de la cola) cae
    # al final del flujo.
    if punto_partida is not None and 0 <= punto_partida <= maximo:
        ultimo = punto_partida
    else:
        ultimo = maximo
    yield f"data: {json.dumps({'tipo': 'conectado', 'engagement_id': engagement_id})}\n\n"
    inicio = _t.time()
    try:
        while _t.time() - inicio < 240:  # reciclado periódico del flujo
            filas = conn.execute(
                "SELECT rowid, * FROM auditoria WHERE rowid > ? ORDER BY rowid LIMIT 100",
                (ultimo,)).fetchall()
            for fila in filas:
                ultimo = fila["rowid"]
                ev = {k: fila[k] for k in fila.keys() if k != "rowid"}
                yield (f"id: {ultimo}\n"
                       "data: " + json.dumps(
                           {"tipo": "auditoria", "evento": ev},
                           ensure_ascii=False) + "\n\n")
            yield ": ping\n\n"
            _t.sleep(1.5)
    finally:
        conn.close()
    yield "event: fin\ndata: {}\n\n"


@app.get("/api/engagements/{engagement_id}/eventos")
def eventos_en_vivo(engagement_id: str, request: Request) -> StreamingResponse:
    """Flujo Server-Sent Events con la auditoría nueva del caso."""
    if len(engagement_id) > 64 or not re.fullmatch(r"[A-Za-z0-9._-]+", engagement_id):
        raise HTTPException(404, f"Engagement {engagement_id} no existe")
    if not (RAIZ_CASOS / f"{engagement_id}.db").exists():
        raise HTTPException(404, f"Engagement {engagement_id} no existe")
    punto = _parse_last_event_id(request.headers.get("last-event-id"))
    return StreamingResponse(
        flujo_eventos_sse(RAIZ_CASOS / f"{engagement_id}.db", engagement_id, punto),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})
