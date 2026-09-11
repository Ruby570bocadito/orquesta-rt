"""Router semántico de modelos + economía del token.

Capítulo 3 del blueprint: el coste no crece con usuarios sino con llamadas x
contexto. Este router aplica cinco de las nueve técnicas de ahorro:

1. Routing semántico: cada tarea se clasifica y va al modelo mínimo suficiente.
   - LOCAL (Ollama/vLLM): enumeración, parsing, formateo, resúmenes mecánicos.
   - FRONTERA (API comercial): selección de exploit, análisis de rutas AD,
     redacción crítica del informe.
2. Prompt caching: los prefijos estables (system prompt + ROE + catálogo de
   skills) viajan al principio; el historial creciente detrás.
3. Salidas estructuradas: JSON esquematizado, nunca prosa que reparsear.
4. Presupuesto por fase: techo de tokens por fase; el router rechaza (o
   compacta) al acercarse al límite.
5. Compaction: `compactar()` produce el resumen denso que abre la fase
   siguiente; la memoria del caso lo conserva.
"""
from __future__ import annotations

import json
import os
import random
import time
from dataclasses import dataclass, field
from typing import Any, Optional

from .models import Fase, TipoModelo, UsoTokens


class PresupuestoAgotado(RuntimeError):
    """El techo de tokens (de fase o de caso) bloquea la llamada: es un
    control de economía del token, no un error transitorio."""


class BackendIndisponible(RuntimeError):
    """Ningún backend puede atender la tarea (circuito abierto o sin
    configuración): el error documenta el requisito exacto, nunca se
    inventa una salida."""

# Precios de referencia (USD por millón de tokens). Configurables por entorno.
_PRECIOS: dict[str, dict[str, float]] = {
    # Proveedor de frontera (cualquier API OpenAI-compatible; por defecto GLM)
    "frontera": {"entrada": 3.0, "salida": 12.0},
    # Inferencia local: coste marginal por llamada ~ 0 (la GPU ya está on-prem)
    "local": {"entrada": 0.0, "salida": 0.0},
}

# Clasificador de tareas -> clase de modelo. Reglas declarativas simples:
# en producción puede sustituirse por un clasificador entrenado sin tocar
# el contrato del router.
_TAREAS_FRONTERA = (
    "seleccion_exploit", "analisis_ruta_ad", "redaccion_informe",
    "decision_critica", "scoping_redaccion", "analisis_filtraciones",
    "analisis_caso", "planificacion_adaptativa", "reflexion_cobertura",
)
_TAREAS_LOCALES = (
    "enumeracion", "parsing", "formateo", "resumen_mecanico",
    "deduplicacion", "extraccion_campos",
)

# Temperatura por tarea: el razonamiento analítico pide determinismo
# (propuestas reproducibles, auditables); la redacción creativa, rango.
_TEMPERATURAS: dict[str, float] = {
    "seleccion_exploit": 0.1,
    "analisis_ruta_ad": 0.1,
    "decision_critica": 0.1,
    "planificacion_adaptativa": 0.2,
    "reflexion_cobertura": 0.2,
    "analisis_caso": 0.3,
    "redaccion_informe": 0.6,
    "scoping_redaccion": 0.5,
}
_TEMPERATURA_DEFECTO = 0.3

# Circuit breaker: tras N fallos consecutivos el backend se abre durante
# T segundos; el router enruta al otro backend si existe y de lo contrario
# documenta el requisito (sin reintentos infinitos contra un servicio muerto).
_CIRCUITO_FALLOS = 3
_CIRCUITO_SEGUNDOS = 60.0

# Errores transitorios que merecen reintento con backoff (429/5xx/red).
_ERRORES_TRANSITORIOS = (429, 500, 502, 503, 504)


def _es_transitorio(exc: Exception) -> bool:
    """Clasifica un fallo de transporte: ¿merece reintento con backoff?
    HTTP 429/5xx, timeouts y errores de conexión sí; 4xx (petición mala,
    auth) no: reintentarlos solo gasta cuota y tiempo."""
    status = getattr(exc, "status_code", None) or getattr(exc, "response", None)
    if status is not None and not isinstance(status, int):
        status = getattr(status, "status_code", None)
    if isinstance(status, int) and status in _ERRORES_TRANSITORIOS:
        return True
    nombre = type(exc).__name__.lower()
    if any(s in nombre for s in ("timeout", "connect", "network", "readerror")):
        return True
    texto = str(exc).lower()
    return any(f"{c}" in texto for c in ("429", " 500", " 502", " 503", " 504"))


@dataclass
class PresupuestoFase:
    """Techo de tokens por fase (en miles) y contabilidad local."""

    fase: Fase
    techo_miles: int
    usados: int = 0

    @property
    def restante(self) -> int:
        return max(0, self.techo_miles * 1000 - self.usados)

    @property
    def agotandose(self) -> bool:
        return self.usados > self.techo_miles * 1000 * 0.85


@dataclass
class RespuestaRouter:
    texto: str
    modelo: str
    tipo: TipoModelo
    tokens_entrada: int = 0
    tokens_salida: int = 0
    coste_usd: float = 0.0
    cache_hit: bool = False
    crudo: Any = None


class RouterModelos:
    """Router híbrido configurable: API comercial + LLM local.

    Variables de entorno:
      API_FRONTERA_BASE   p. ej. https://api.z.ai/api/paas/v4  (OpenAI-compatible)
      API_FRONTERA_CLAVE  clave de API
      MODELO_FRONTERA     p. ej. glm-4.7
      API_LOCAL_BASE      p. ej. http://vllm:8000/v1  (Ollama/vLLM)
      MODELO_LOCAL        p. ej. qwen2.5:14b
      POLITICA_SALIDA     perimetro | hibrido  (qué puede salir de la red)
    """

    def __init__(self, memoria=None, engagement_id: str = ""):
        self.memoria = memoria
        self.engagement_id = engagement_id
        self.frontera_base = os.environ.get("API_FRONTERA_BASE", "")
        self.frontera_clave = os.environ.get("API_FRONTERA_CLAVE", "")
        self.modelo_frontera = os.environ.get("MODELO_FRONTERA", "glm-4.7")
        self.local_base = os.environ.get("API_LOCAL_BASE", "")
        self.modelo_local = os.environ.get("MODELO_LOCAL", "qwen2.5:14b")
        # perimetro: nada sale de la red -> frontera deshabilitada por política
        self.politica_salida = os.environ.get("POLITICA_SALIDA", "hibrido")
        self._presupuestos: dict[Fase, PresupuestoFase] = {}
        self._http = None
        # Circuit breaker por clase de backend (estado de proceso):
        # {clase: {"fallos": int, "abierto_hasta": epoch}}
        self._circuitos: dict[str, dict[str, float]] = {
            "frontera": {"fallos": 0.0, "abierto_hasta": 0.0},
            "local": {"fallos": 0.0, "abierto_hasta": 0.0},
        }

    # -- presupuesto ------------------------------------------------------------

    def configurar_presupuestos(self, presupuesto: dict[str, int]) -> None:
        self._presupuestos = {
            Fase(k): PresupuestoFase(fase=Fase(k), techo_miles=v)
            for k, v in presupuesto.items()
        }

    def presupuesto_fase(self, fase: Fase) -> PresupuestoFase:
        if fase not in self._presupuestos:
            self._presupuestos[fase] = PresupuestoFase(fase=fase, techo_miles=100)
        return self._presupuestos[fase]

    # -- clasificación ------------------------------------------------------------

    def clasificar_tarea(self, tarea: str) -> TipoModelo:
        """Enruta al modelo mínimo suficiente (routing semántico)."""
        if tarea in _TAREAS_FRONTERA:
            return TipoModelo.FRONTERA
        if tarea in _TAREAS_LOCALES:
            return TipoModelo.LOCAL
        # por defecto, mecánica -> local
        return TipoModelo.LOCAL

    def _elegir_modelo(self, tarea: str) -> tuple[TipoModelo, str, str]:
        """Enruta al modelo mínimo suficiente evitando circuitos abiertos.

        Si el backend natural está con circuito abierto por fallos
        consecutivos, se enruta al otro backend si está disponible; si no
        hay alternativa se lanza BackendIndisponible con el requisito
        exacto (el fallo se documenta, no se oculta ni se simula)."""
        clase = self.clasificar_tarea(tarea)
        alternativo = None
        if clase == TipoModelo.FRONTERA:
            ok_natural = (self.politica_salida != "perimetro"
                          and self.frontera_base and self.frontera_clave
                          and not self._circuito_abierto("frontera"))
            if ok_natural:
                return TipoModelo.FRONTERA, self.modelo_frontera, self.frontera_base
            if self.local_base and not self._circuito_abierto("local"):
                alternativo = (TipoModelo.LOCAL, self.modelo_local, self.local_base)
        else:
            if self.local_base and not self._circuito_abierto("local"):
                return TipoModelo.LOCAL, self.modelo_local, self.local_base
            if (self.frontera_base and self.frontera_clave
                    and self.politica_salida != "perimetro"
                    and not self._circuito_abierto("frontera")):
                alternativo = (TipoModelo.FRONTERA, self.modelo_frontera,
                               self.frontera_base)
        if alternativo:
            return alternativo
        motivos = []
        if self._circuito_abierto("frontera"):
            motivos.append("backend frontera con circuito abierto (fallos "
                           "consecutivos); se reabre automáticamente")
        if self._circuito_abierto("local"):
            motivos.append("backend local con circuito abierto")
        if not self.frontera_base or not self.frontera_clave:
            motivos.append("frontera no configurada "
                           "(falta API_FRONTERA_BASE o API_FRONTERA_CLAVE)")
        if not self.local_base:
            motivos.append("local no configurado (falta API_LOCAL_BASE)")
        raise BackendIndisponible(
            "Ningún backend puede atender la tarea " + tarea + ": "
            + "; ".join(motivos))

    # -- circuit breaker ------------------------------------------------------------

    def _circuito_abierto(self, clase: str) -> bool:
        c = self._circuitos.get(clase, {"fallos": 0.0, "abierto_hasta": 0.0})
        return c["abierto_hasta"] > time.time()

    def _registrar_exito(self, clase: str) -> None:
        self._circuitos[clase] = {"fallos": 0.0, "abierto_hasta": 0.0}

    def _registrar_fallo(self, clase: str) -> None:
        c = self._circuitos.setdefault(clase, {"fallos": 0.0, "abierto_hasta": 0.0})
        c["fallos"] = float(c.get("fallos", 0)) + 1
        if c["fallos"] >= _CIRCUITO_FALLOS:
            c["abierto_hasta"] = time.time() + _CIRCUITO_SEGUNDOS
            c["fallos"] = 0.0

    def _presupuesto_caso(self) -> int:
        """Techo duro de tokens para TODO el caso (0 = sin techo). Se lee de
        config_caso ('presupuesto_caso_tokens') y se compara con el consumo
        real registrado: control de economía a nivel de engagement."""
        if self.memoria is None or not self.engagement_id:
            return 0
        valor = self.memoria.config_caso(self.engagement_id, "presupuesto_caso_tokens")
        try:
            return max(0, int(valor)) if valor else 0
        except (TypeError, ValueError):
            return 0

    # -- llamada --------------------------------------------------------------------

    def completar(
        self,
        tarea: str,
        sistema: str,
        usuario: str,
        fase: Fase,
        esquema_json: dict[str, Any] | None = None,
        max_tokens: int = 2048,
        reintentos: int = 2,
    ) -> RespuestaRouter:
        """Ejecuta una llamada al modelo mínimo suficiente, con contabilidad,
        reintentos con backoff exponencial y circuit breaker.

        - `sistema` debe contener SOLO el prefijo estable (system prompt + ROE +
          catálogo): es lo que el proveedor cachea. El historial va en `usuario`.
        - Si `esquema_json` está presente se fuerza salida estructurada.
        - Errores 429/5xx/timeout → reintento con backoff (2 por defecto).
        - Backend con circuito abierto → se enruta al otro backend si existe;
          si no, BackendIndisponible con el requisito exacto (sin inventar).
        """
        pres = self.presupuesto_fase(fase)
        if pres.agotandose:
            raise PresupuestoAgotado(
                f"Presupuesto de tokens de la fase {fase.value} casi agotado "
                f"({pres.usados}/{pres.techo_miles * 1000}). Compacte la fase "
                "antes de continuar.")
        techo_caso = self._presupuesto_caso()
        if techo_caso:
            usados_caso = 0
            if self.memoria is not None:
                resumen = self.memoria.resumen_tokens(self.engagement_id)
                usados_caso = sum(int(f.get("tokens", 0) or 0)
                                  for f in resumen.get("por_fase", []))
            if usados_caso >= techo_caso:
                raise PresupuestoAgotado(
                    f"Presupuesto de tokens del CASO agotado "
                    f"({usados_caso}/{techo_caso}). El operador puede elevarlo "
                    "explícitamente en la configuración del caso.")

        tipo, modelo, base = self._elegir_modelo(tarea)
        clase_backend = "frontera" if tipo == TipoModelo.FRONTERA else "local"
        mensajes = [{"role": "system", "content": sistema},
                    {"role": "user", "content": usuario}]
        cuerpo: dict[str, Any] = {
            "model": modelo,
            "messages": mensajes,
            "max_tokens": max_tokens,
            "temperature": _TEMPERATURAS.get(tarea, _TEMPERATURA_DEFECTO),
        }
        if esquema_json is not None:
            cuerpo["response_format"] = {
                "type": "json_schema",
                "json_schema": {"name": "salida", "schema": esquema_json},
            }

        respuesta_cruda: Any = None
        ultimo_error: Exception | None = None
        for intento in range(reintentos + 1):
            try:
                respuesta_cruda = self._post_openai_compat(base, cuerpo)
                self._registrar_exito(clase_backend)
                break
            except Exception as exc:  # noqa: BLE001 — clasificamos abajo
                ultimo_error = exc
                transitorio = _es_transitorio(exc)
                self._registrar_fallo(clase_backend)
                if not transitorio or intento >= reintentos:
                    break
                # backoff exponencial con jitter: 0.4s, 0.8s, 1.6s...
                time.sleep(0.4 * (2 ** intento) + random.uniform(0, 0.25))
        if respuesta_cruda is None:
            raise RuntimeError(
                f"Llamada al backend {clase_backend} falló tras "
                f"{reintentos + 1} intentos: {ultimo_error}") from ultimo_error

        texto = ""
        uso = respuesta_cruda.get("usage", {}) if isinstance(respuesta_cruda, dict) else {}
        try:
            texto = respuesta_cruda["choices"][0]["message"]["content"] or ""
        except (KeyError, IndexError, TypeError):
            texto = json.dumps(respuesta_cruda, ensure_ascii=False)[:4000]

        tokens_in = int(uso.get("prompt_tokens", len(usuario) // 4))
        tokens_out = int(uso.get("completion_tokens", len(texto) // 4))
        cache_hit = bool(uso.get("prompt_tokens_details", {}).get("cached_tokens"))
        precio = _PRECIOS["frontera"] if tipo == TipoModelo.FRONTERA else _PRECIOS["local"]
        factor_cache = 0.1 if cache_hit else 1.0
        coste = (tokens_in / 1e6 * precio["entrada"] * factor_cache
                 + tokens_out / 1e6 * precio["salida"])

        registro = UsoTokens(
            fase=fase, modelo=modelo, tipo=tipo, tokens_entrada=tokens_in,
            tokens_salida=tokens_out, cache_hit=cache_hit, coste_usd=round(coste, 6),
        )
        pres.usados += tokens_in + tokens_out
        if self.memoria is not None:
            self.memoria.registrar_uso_tokens(self.engagement_id, registro)

        return RespuestaRouter(
            texto=texto, modelo=modelo, tipo=tipo, tokens_entrada=tokens_in,
            tokens_salida=tokens_out, coste_usd=registro.coste_usd,
            cache_hit=cache_hit, crudo=respuesta_cruda,
        )

    # -- transporte -------------------------------------------------------------------

    def _post_openai_compat(self, base: str, cuerpo: dict[str, Any]) -> Any:
        """POST a un endpoint OpenAI-compatible (GLM, vLLM, Ollama serve)."""
        if self._http is None:
            import httpx
            self._http = httpx.Client(timeout=120)
        cabeceras = {"Content-Type": "application/json"}
        if self.frontera_clave and base == self.frontera_base:
            cabeceras["Authorization"] = f"Bearer {self.frontera_clave}"
        r = self._http.post(
            f"{base.rstrip('/')}/chat/completions",
            json=cuerpo, headers=cabeceras,
        )
        r.raise_for_status()
        return r.json()

    # -- estado y prueba real de backends --------------------------------------

    def estado_backends(self) -> dict[str, Any]:
        """Estado de configuración de ambos backends (sin secretos)."""
        def _circuito(clase: str) -> dict[str, Any]:
            c = self._circuitos.get(clase, {"fallos": 0.0, "abierto_hasta": 0.0})
            abierto = c["abierto_hasta"] > time.time()
            return {
                "abierto": abierto,
                "reabre_en_s": max(0, round(c["abierto_hasta"] - time.time(), 1))
                                if abierto else 0,
                "fallos_consecutivos": int(c.get("fallos", 0)),
            }
        return {
            "frontera": {
                "configurado": bool(self.frontera_base and self.frontera_clave),
                "base": self.frontera_base,
                "modelo": self.modelo_frontera,
                "politica_salida": self.politica_salida,
                "circuito": _circuito("frontera"),
                "nota": "API OpenAI-compatible (GLM/Z.ai) para tareas críticas",
            },
            "local": {
                "configurado": bool(self.local_base),
                "base": self.local_base,
                "modelo": self.modelo_local,
                "circuito": _circuito("local"),
                "nota": "Ollama/vLLM on-prem para tareas mecánicas",
            },
        }

    def probar_backend(self, clase: str) -> dict[str, Any]:
        """Ping REAL al backend: GET {base}/models (OpenAI-compatible).

        Devuelve conectado=True solo si el backend respondió de verdad.
        """
        if clase == "frontera":
            base, clave, modelo = self.frontera_base, self.frontera_clave, self.modelo_frontera
            if self.politica_salida == "perimetro":
                return {"conectado": False, "clase": clase,
                        "error": "política de salida 'perimetro': el router no "
                                 "envía nada a la frontera por configuración"}
        else:
            base, clave, modelo = self.local_base, "", self.modelo_local
        if not base or (clase == "frontera" and not clave):
            return {"conectado": False, "clase": clase,
                    "error": f"backend {clase} no configurado"
                             + (" (falta API_FRONTERA_BASE o API_FRONTERA_CLAVE)" if clase == "frontera"
                                else " (falta API_LOCAL_BASE)")}
        try:
            if self._http is None:
                import httpx
                self._http = httpx.Client(timeout=8)
            cabeceras = {"Authorization": f"Bearer {clave}"} if clave else {}
            r = self._http.get(f"{base.rstrip('/')}/models", headers=cabeceras)
            modelos = []
            try:
                datos = r.json()
                modelos = [m.get("id", "") for m in datos.get("data", [])[:10]]
            except Exception:
                pass
            return {"conectado": r.status_code == 200, "clase": clase,
                    "base": base, "modelo": modelo,
                    "http": r.status_code, "modelos": modelos}
        except Exception as exc:
            return {"conectado": False, "clase": clase, "base": base,
                    "error": str(exc)[:200]}

    # -- compaction ---------------------------------------------------------------------

    def compactar(
        self, fase: Fase, historial: str, hallazgos_clave: list[str]
    ) -> str:
        """Comprime la historia de la fase en un resumen denso (compaction).

        Se ejecuta AL CERRAR la fase, con el modelo local (barato). El
        siguiente capítulo arranca con este resumen + evidencias intactas,
        no con la historia lineal: es la técnica que reduce >70 % de los
        tokens de prompt documentada en la investigación de contexto.
        """
        try:
            r = self.completar(
                tarea="resumen_mecanico",
                sistema="Eres un compresor de contexto para operaciones de red "
                        "team. Resume en menos de 200 tokens: objetivos logrados, "
                        "activos descubiertos, credenciales encontradas (sin "
                        "valores en claro), rutas abiertas y pendientes. Sin prosa.",
                usuario=historial[-30_000:],
                fase=fase,
                max_tokens=400,
            )
            texto = r.texto.strip()
        except Exception:  # sin backend: resumen extractivo de emergencia
            texto = historial[-1200:]
        return texto

    def cerrar(self) -> None:
        if self._http is not None:
            self._http.close()
