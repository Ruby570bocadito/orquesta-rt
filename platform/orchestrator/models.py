"""Modelos de dominio de la plataforma de red team orquestada por IA.

Define los tipos compartidos por el orquestador, los servidores MCP, la API
y la consola. Todos los objetos ofensivos llevan trazabilidad: actor, marca
temporal y referencia al ROE vigente.

Este software es PROPRIETARIO y de código cerrado. Véase el fichero LICENSE
en la raíz del repositorio.
"""
from __future__ import annotations

import enum
from datetime import datetime, timezone
from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

# ---------------------------------------------------------------------------
# Enumeraciones del ciclo ofensivo (fases F0-F7 del blueprint)
# ---------------------------------------------------------------------------


class Fase(str, enum.Enum):
    """Fases del engagement. Cada fase es un nodo del grafo LangGraph."""

    F0_SCOPING = "F0_scoping"
    F1_OSINT = "F1_osint"
    F2_RECON = "F2_recon"
    F3_ACCESO = "F3_acceso_inicial"
    F4_DOMINIO = "F4_dominio_ad"
    F5_C2 = "F5_c2_postex"
    F6_PHISHING = "F6_phishing"
    F7_INFORME = "F7_informe"
    CIERRE = "cierre"  # higiene de cierre: limpieza y certificado de borrado


class EstadoFase(str, enum.Enum):
    PENDIENTE = "pendiente"
    ACTIVA = "activa"
    ESPERA_APROBACION = "espera_aprobacion"
    COMPLETADA = "completada"
    BLOQUEADA = "bloqueada"  # denegada por guardrail o fallo no recuperable


class Severidad(str, enum.Enum):
    CRITICA = "critica"
    ALTA = "alta"
    MEDIA = "media"
    BAJA = "baja"
    INFORMATIVA = "informativa"


class Actor(str, enum.Enum):
    """Actor de toda acción registrada. La auditoría distingue siempre."""

    AGENTE = "agente"
    HUMANO = "humano"
    SISTEMA = "sistema"  # guardrails, memoria, planificador


class DecisionGuardrail(str, enum.Enum):
    """Resultado de evaluar una tool call contra el ROE en el boundary."""

    PERMITIR = "permitir"                # baja riesgoso, dentro de scope y ROE
    REQUIERE_APROBACION = "requiere_aprobacion"  # el humano decide en consola
    DENEGAR = "denegar"                  # fuera de scope, técnica prohibida o
                                         # presupuesto de ruido agotado


class TipoModelo(str, enum.Enum):
    """Clase de modelo según el router semántico (capítulo 3 del blueprint)."""

    LOCAL = "local"            # Ollama / vLLM: tareas mecánicas, enumeración
    FRONTERA = "frontera"      # API comercial: decisión crítica, redacción


class TipoObjetivo(str, enum.Enum):
    """Clase de activo en la superficie de ataque descubierta."""

    DOMINIO = "dominio"
    HOST = "host"
    SERVICIO = "servicio"
    CREDENCIAL = "credencial"
    RUTA = "ruta"
    ACTIVO_HUMANO = "activo_humano"


class EstadoObjetivo(str, enum.Enum):
    """Ciclo de vida del activo durante el engagement."""

    DESCUBIERTO = "descubierto"
    CONFIRMADO = "confirmado"
    RIESGO = "riesgo"
    EXPLOTADO = "explotado"
    NEUTRALIZADO = "neutralizado"


class TipoEvidencia(str, enum.Enum):
    COMANDO = "comando"            # salida de comando registrada
    CAPTURA = "captura"            # screenshot / volcado referenciado
    FICHERO = "fichero"
    JSON = "json"                  # salida estructurada de herramienta
    NOTA = "nota"                  # nota del operador o del agente
    FIRMA = "firma"                # manifiesto firmado del informe


# ---------------------------------------------------------------------------
# ROE máquina-legible
# ---------------------------------------------------------------------------


class VentanaHoraria(BaseModel):
    """Franja en la que está permitida la actividad activa (hora local)."""

    inicio: str = "08:00"
    fin: str = "20:00"
    dias: list[str] = Field(default_factory=lambda: ["lun", "mar", "mie", "jue", "vie"])


class ROEPolitica(BaseModel):
    """Reglas de compromiso máquina-legible (fase 0).

    El motor de guardrails la consulta ANTES de cada tool call. Nada de lo
    que aparece aquí es decorativo: prohibir una técnica o acotar un scope
    se convierte en un control activo del boundary, no en una cláusula muerta.
    """

    model_config = ConfigDict(validate_assignment=True)

    engagement_id: str
    cliente: str
    alcance_dominios: list[str] = Field(default_factory=list)
    alcance_cidrs: list[str] = Field(default_factory=list)
    alcance_excluido: list[str] = Field(
        default_factory=list,
        description="Dominios/CIDRs vetados aunque parezcan del cliente",
    )
    tecnicas_prohibidas: list[str] = Field(
        default_factory=list,
        description="IDs MITRE ATT&CK o nombres de técnica vetados",
    )
    tecnicas_con_aprobacion: list[str] = Field(
        default_factory=list,
        description="Técnicas permitidas solo con firma humana previa",
    )
    techo_ruido: int = Field(
        default=50, ge=0, le=100,
        description="Nivel máximo de ruido aceptable (0-100) acordado con el cliente",
    )
    ventanas_activas: VentanaHoraria = Field(default_factory=VentanaHoraria)
    parada_emergencia: bool = Field(
        default=False,
        description="Kill switch: True detiene el ciclo y suspende toda tool call",
    )
    notas: str = ""

    # -- Validación de alcance (v11) ---------------------------------------
    # Un CIDR malformado en el ROE NO era rechazado al crear el caso y luego,
    # en el boundary, abortaba el bucle de comprobación de alcance: los CIDRs
    # válidos posteriores NUNCA se evaluaban (objetivos legítimos denegados
    # con "fuera de alcance" a mitad de engagement). La validación vive AQUÍ,
    # en el modelo, para cubrir creación AND actualización de ROE.

    @field_validator("alcance_cidrs")
    @classmethod
    def _validar_cidrs(cls, v: list[str]) -> list[str]:
        import ipaddress as _ip

        for cidr in v:
            try:
                _ip.ip_network(cidr, strict=False)
            except ValueError as exc:
                raise ValueError(
                    f"CIDR inválido en el alcance: '{cidr}'. "
                    "Usa notación CIDR, p. ej. 192.168.1.0/24 o 2001:db8::/32"
                ) from exc
        return v

    @field_validator("alcance_dominios")
    @classmethod
    def _validar_dominios(cls, v: list[str]) -> list[str]:
        import re as _re

        # "localhost" se admite explícitamente: es el objetivo del lab local
        # documentado (README) y aparecer en ROEs ya almacenados.
        patron = _re.compile(
            r"^(?:localhost|(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,})$"
        )
        for dom in v:
            if not patron.fullmatch(dom.lower().strip()):
                raise ValueError(
                    f"Dominio inválido en el alcance: '{dom}'. "
                    "Usa un nombre de dominio real, p. ej. cliente.com (o 'localhost' para el lab)"
                )
        return v

    @field_validator("alcance_excluido")
    @classmethod
    def _validar_excluido(cls, v: list[str]) -> list[str]:
        """Cada entrada debe ser un dominio válido O un CIDR válido."""
        import ipaddress as _ip
        import re as _re

        patron = _re.compile(
            r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$"
        )
        for item in v:
            destino = item.lower().strip()
            es_dominio = bool(patron.fullmatch(destino))
            es_cidr = True
            try:
                _ip.ip_network(item, strict=False)
            except ValueError:
                es_cidr = False
            if not (es_dominio or es_cidr):
                raise ValueError(
                    f"Entrada de exclusión inválida: '{item}'. "
                    "Debe ser un dominio (cliente.com) o un CIDR (10.0.0.0/8)"
                )
        return v


# ---------------------------------------------------------------------------
# Entidades del caso
# ---------------------------------------------------------------------------


def _ahora() -> datetime:
    return datetime.now(timezone.utc)


class Hallazgo(BaseModel):
    """Hallazgo de seguridad registrado durante el engagement."""

    id: str
    engagement_id: str
    titulo: str
    severidad: Severidad
    tecnica_mitre: Optional[str] = None  # p. ej. T1558.003 (Kerberoasting)
    activo: str = ""                     # host, dominio o URL afectada
    descripcion: str = ""
    recomendacion: str = ""
    estado: Literal["propuesto", "confirmado", "descartado"] = "propuesto"
    # Resultado de detección registrado por el equipo azul (purple teaming,
    # patrón VECTR): el operador humano documenta si la defensa observó la
    # acción. "pendiente" = todavía sin verificación defensiva.
    deteccion: Literal["pendiente", "detectado", "no_detectado", "prevenido"] = "pendiente"
    evidencias: list[str] = Field(default_factory=list, description="IDs de evidencia")
    creado_por: Actor = Actor.AGENTE
    creado_en: datetime = Field(default_factory=_ahora)


class Evidencia(BaseModel):
    """Evidencia verificable con cadena de custodia.

    Cada evidencia encadena el hash de la anterior (cadena de custodia) y se
    firma con HMAC-SHA256 usando la clave del caso. El cliente puede auditar
    la cadena sin confiar a ciegas en el proveedor.
    """

    id: str
    engagement_id: str
    tipo: TipoEvidencia
    titulo: str
    contenido: str = ""          # texto o ruta relativa al almacén del caso
    hash_sha256: str = ""
    firma_hmac: str = ""         # HMAC-SHA256(hash, clave_del_caso)
    hash_previo: str = ""        # encadenamiento tipo blockchain
    fase: Fase
    actor: Actor = Actor.AGENTE
    hallazgo_id: Optional[str] = None
    creado_en: datetime = Field(default_factory=_ahora)


class Aprobacion(BaseModel):
    """Petición de aprobación humana (operator-in-command).

    Nace en el boundary de guardrails cuando una acción supera el umbral de
    riesgo o toca una técnica que exige firma. Muere con la decisión humana.
    """

    id: str
    engagement_id: str
    fase: Fase
    titulo: str
    descripcion: str = ""
    herramienta: str = ""                  # servidor MCP / skill propuesta
    argumentos: dict[str, Any] = Field(default_factory=dict)
    tecnica_mitre: Optional[str] = None
    riesgo: Severidad = Severidad.MEDIA
    ruido_estimado: int = Field(default=50, ge=0, le=100)
    motivo: str = ""                       # por qué pide aprobación
    referencia_roe: str = ""               # cláusula del ROE implicada
    estado: Literal["pendiente", "aprobada", "rechazada", "expirada"] = "pendiente"
    decidida_por: Optional[str] = None
    comentario_operador: str = ""
    creada_en: datetime = Field(default_factory=_ahora)
    decidida_en: Optional[datetime] = None


class UsoTokens(BaseModel):
    """Registro de consumo por llamada al modelo (economía del token)."""

    fase: Fase
    modelo: str
    tipo: TipoModelo
    tokens_entrada: int = 0
    tokens_salida: int = 0
    cache_hit: bool = False
    coste_usd: float = 0.0
    creado_en: datetime = Field(default_factory=_ahora)


class EventoAuditoria(BaseModel):
    """Entrada del registro inmutable. Nada se edita ni se borra nunca."""

    id: str
    engagement_id: str
    actor: Actor
    accion: str
    detalle: str = ""
    herramienta: str = ""
    parametros_hash: str = ""   # SHA-256 de los argumentos (no los argumentos)
    resultado: str = ""         # ok | denegado | aprobado | error | ...
    guardrail: Optional[DecisionGuardrail] = None
    creado_en: datetime = Field(default_factory=_ahora)


class ResumenFase(BaseModel):
    """Compaction al cerrar cada fase (capítulo 3 del blueprint).

    El agente arranca la fase siguiente con este resumen denso y las
    evidencias intactas, no con la historia lineal completa.
    """

    fase: Fase
    texto: str
    hallazgos_clave: list[str] = Field(default_factory=list)
    tokens_ahorrados_estimados: int = 0
    creado_en: datetime = Field(default_factory=_ahora)


class Engagement(BaseModel):
    """Caso de red team completo: contrato, estado y economía."""

    id: str
    nombre: str
    cliente: str
    roe: ROEPolitica
    fase_actual: Fase = Fase.F0_SCOPING
    estado_fase: EstadoFase = EstadoFase.PENDIENTE
    # Organización (tenant) propietaria del caso — RBAC multi-tenant v21.
    tenant_id: str = "predeterminada"
    creado_en: datetime = Field(default_factory=_ahora)
    actualizado_en: datetime = Field(default_factory=_ahora)
    presupuesto_tokens: dict[str, int] = Field(
        default_factory=lambda: {
            # Techos por fase (miles de tokens): fases mecánicas estrechas,
            # explotación y redacción holgadas (tabla 4 del blueprint).
            "F0_scoping": 40,
            "F1_osint": 60,
            "F2_recon": 60,
            "F3_acceso_inicial": 120,
            "F4_dominio_ad": 150,
            "F5_c2_postex": 120,
            "F6_phishing": 100,
            "F7_informe": 180,
            "cierre": 30,
        }
    )
    coste_acumulado_usd: float = 0.0
    tokens_acumulados: int = 0
    certificado_borrado: Optional[str] = None  # hash del certificado de higiene


class Objetivo(BaseModel):
    """Activo de la superficie de ataque descubierto durante el engagement.

    Alimenta la vista de objetivos de la consola y el cálculo de rutas.
    El estado solo avanza (descubierto→confirmado→explotado→neutralizado).
    """

    id: str
    engagement_id: str
    nombre: str
    tipo: TipoObjetivo
    estado: EstadoObjetivo = EstadoObjetivo.DESCUBIERTO
    detalle: str = ""
    fase: Fase
    severidad: Optional[Severidad] = None
    tecnica_mitre: Optional[str] = None
    descubierto_en: datetime = Field(default_factory=_ahora)


class ContextoAgente(BaseModel):
    """Contexto mínimo que viaja a cada subagente (subagentes aislados).

    El planner nunca ve las miles de páginas del OSINT: ve el mapa
    resumido. Este objeto es ese contrato de aislamiento.
    """

    engagement_id: str
    fase: Fase
    objetivo: str
    resumen_previo: str = ""          # compaction de fases anteriores
    presupuesto_tokens: int = 100_000
    datos_referenciados: list[str] = Field(
        default_factory=list,
        description="Rutas a ficheros del caso, no contenidos",
    )
