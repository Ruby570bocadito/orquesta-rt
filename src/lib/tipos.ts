/**
 * Tipos compartidos de la consola — espejo de orchestrator/models.py.
 * La consola consume la API del orquestador en modo live o el motor de
 * demostración en modo demo; ambos hablan este contrato.
 */

export type FaseId =
  | "F0_scoping"
  | "F1_osint"
  | "F2_recon"
  | "F3_acceso_inicial"
  | "F4_dominio_ad"
  | "F5_c2_postex"
  | "F6_phishing"
  | "F7_informe"
  | "cierre";

export type EstadoFase = "pendiente" | "activa" | "espera_aprobacion" | "completada" | "bloqueada";
export type Severidad = "critica" | "alta" | "media" | "baja" | "informativa";
export type Actor = "agente" | "humano" | "sistema";
export type DecisionGuardrail = "permitir" | "requiere_aprobacion" | "denegar";
export type TipoModelo = "local" | "frontera";

export interface VentanaHoraria {
  inicio: string;
  fin: string;
  dias: string[];
}

export interface ROEPolitica {
  engagement_id: string;
  cliente: string;
  alcance_dominios: string[];
  alcance_cidrs: string[];
  alcance_excluido: string[];
  tecnicas_prohibidas: string[];
  tecnicas_con_aprobacion: string[];
  techo_ruido: number;
  ventanas_activas: VentanaHoraria;
  parada_emergencia: boolean;
  notas: string;
}

export interface Hallazgo {
  id: string;
  engagement_id: string;
  titulo: string;
  severidad: Severidad;
  tecnica_mitre?: string | null;
  activo: string;
  descripcion: string;
  recomendacion: string;
  estado: "propuesto" | "confirmado" | "descartado";
  /** Resultado de detección del blue team (purple teaming, patrón VECTR). */
  deteccion: "pendiente" | "detectado" | "no_detectado" | "prevenido";
  evidencias: string[];
  creado_por: Actor;
  creado_en: string;
}

export interface Evidencia {
  id: string;
  engagement_id: string;
  tipo: "comando" | "captura" | "fichero" | "json" | "nota" | "firma";
  titulo: string;
  contenido: string;
  hash_sha256: string;
  firma_hmac: string;
  hash_previo: string;
  fase: FaseId;
  actor: Actor;
  hallazgo_id?: string | null;
  creado_en: string;
}

export interface Aprobacion {
  id: string;
  engagement_id: string;
  fase: FaseId;
  titulo: string;
  descripcion: string;
  herramienta: string;
  argumentos: Record<string, unknown>;
  tecnica_mitre?: string | null;
  riesgo: Severidad;
  ruido_estimado: number;
  motivo: string;
  referencia_roe: string;
  estado: "pendiente" | "aprobada" | "rechazada" | "expirada";
  decidida_por?: string | null;
  comentario_operador: string;
  creada_en: string;
  decidida_en?: string | null;
}

export interface EventoAuditoria {
  id: string;
  engagement_id: string;
  actor: Actor;
  accion: string;
  detalle: string;
  herramienta: string;
  parametros_hash: string;
  resultado: string;
  guardrail?: DecisionGuardrail | null;
  creado_en: string;
}

export type TipoObjetivo = "dominio" | "host" | "servicio" | "credencial" | "ruta" | "activo_humano";
export type EstadoObjetivo = "descubierto" | "confirmado" | "riesgo" | "explotado" | "neutralizado";

/** Activo de la superficie de ataque descubierto durante el engagement. */
export interface Objetivo {
  id: string;
  nombre: string;
  tipo: TipoObjetivo;
  estado: EstadoObjetivo;
  detalle: string;
  fase: FaseId;
  severidad?: Severidad | null;
  tecnica_mitre?: string | null;
  descubierto_en: string;
}

export const ETIQUETA_OBJETIVO: Record<TipoObjetivo, string> = {
  dominio: "Dominio",
  host: "Host",
  servicio: "Servicio",
  credencial: "Credencial",
  ruta: "Ruta",
  activo_humano: "Activo humano",
};

export const ETIQUETA_ESTADO_OBJETIVO: Record<EstadoObjetivo, string> = {
  descubierto: "Descubierto",
  confirmado: "Confirmado",
  riesgo: "Riesgo",
  explotado: "Explotado",
  neutralizado: "Neutralizado",
};

export interface UsoTokens {
  fase: FaseId;
  modelo: string;
  tipo: TipoModelo;
  tokens_entrada: number;
  tokens_salida: number;
  cache_hit: boolean;
  coste_usd: number;
  creado_en: string;
}

export interface Engagement {
  id: string;
  nombre: string;
  cliente: string;
  roe: ROEPolitica;
  fase_actual: FaseId;
  estado_fase: EstadoFase;
  creado_en: string;
  actualizado_en: string;
  presupuesto_tokens: Record<string, number>;
  coste_acumulado_usd: number;
  tokens_acumulados: number;
  certificado_borrado?: string | null;
}

/** Estado de una integración real (C2, AD, SMTP, router LLM, OSINT). */
export interface EstadoIntegracion {
  configurado: boolean;
  detalle: string;
  servidor?: string;
}

export interface ResultadoPrueba {
  conectado: boolean;
  error?: string;
  [clave: string]: unknown;
}

export interface EstadoIntegraciones {
  c2: Record<string, EstadoIntegracion>;
  active_directory: EstadoIntegracion;
  phishing_smtp: EstadoIntegracion;
  attack_paths: EstadoIntegracion;
  motor_rutas: EstadoIntegracion;
  threat_intel: EstadoIntegracion;
  nvd: EstadoIntegracion;
  sso: EstadoIntegracion;
  router_llm: Record<string, EstadoIntegracion>;
  webhook: EstadoIntegracion;
  osint: Record<string, EstadoIntegracion>;
}

export const ETIQUETA_INTEGRACION: Record<string, string> = {
  sliver: "Sliver C2 · gRPC oficial",
  mythic: "Mythic C2 · GraphQL oficial",
  metasploit: "Metasploit · MSG-RPC",
  active_directory: "Active Directory · LDAP",
  phishing_smtp: "Phishing · SMTP del equipo",
  attack_paths: "BloodHound CE · Attack paths",
  motor_rutas: "Rutas de ataque · Motor Neo4j",
  threat_intel: "MISP · Threat intel",
  nvd: "Intel CVE · NVD (NIST)",
  sso: "SSO · OIDC federado",
  llm_frontera: "Router IA · Frontera (GLM vía puente)",
  llm_local: "Router IA · Local (Ollama/vLLM)",
  webhook: "Notificaciones · Webhook firmado",
  hibp: "Filtraciones · HIBP v3",
  crt_sh: "OSINT · Certificate Transparency",
  wayback: "OSINT · Internet Archive CDX",
};

// ---------------------------------------------------------------------------
// Planificación threat-led (v21): cadenas estilo Atomic Red Team
// ---------------------------------------------------------------------------

export interface ResumenCadena {
  id: string;
  nombre: string;
  perfil: string;
  objetivo: string;
  descripcion: string;
  pasos: number;
  tecnicas: string[];
  manuales: number;
  ruido_total_estimado: number;
}

export type EstadoPasoThreatled = "ejercitado" | "disponible" | "manual";

export interface PasoPlanThreatled {
  orden: number;
  tecnica: string;
  nombre: string;
  fase: string;
  descripcion: string;
  herramienta: string;
  deteccion: string;
  estado: EstadoPasoThreatled;
  nota: string;
  ruido_estimado: number;
}

export interface PlanThreatled {
  cadena_id: string;
  nombre: string;
  perfil: string;
  objetivo: string;
  pasos: PasoPlanThreatled[];
  resumen: {
    total: number;
    ejercitados: number;
    disponibles: number;
    manuales: number;
    ruido_total_estimado: number;
  };
  caso?: { id: string; nombre: string; cliente: string };
  evidencia_id?: string;
}

/** Modo continuo CTEM (v23): corridas y programas por cadena. */
export interface DeltaCtem {
  primera_corrida: boolean;
  nuevas_tecnicas: string[];
  hallazgos_nuevos: number;
  detecciones_nuevas: number;
  cobertura_ejercitados: { antes: number | null; despues: number };
}

export interface CorridaCtem {
  id: string;
  cadena_id: string;
  disparo: "manual" | "programada";
  operador: string;
  creado_en: string;
  resumen: {
    cadena_nombre?: string;
    instante?: string;
    cobertura?: { total: number; ejercitados: number; disponibles: number; manuales: number };
    detecciones_documentadas?: number;
    delta?: DeltaCtem;
    corrida_id?: string;
    evidencia_id?: string;
  };
}

export interface ProgramaCtem {
  id: string;
  cadena_id: string;
  intervalo_horas: number;
  activo: number;
  creado_por: string;
  creado_en: string;
  ultima_corrida_en: string | null;
  proxima_corrida_en: string | null;
}

export interface EstadoCtem {
  programas: ProgramaCtem[];
  corridas: CorridaCtem[];
  ultimo_resumen: CorridaCtem["resumen"] | null;
  ultimo_delta: DeltaCtem | null;
}

export interface Organizacion {
  id: string;
  nombre: string;
  creado_en: string;
  operadores: number;
}

/** Estado SSO del despliegue (público, sin secretos). */
export interface EstadoSSO {
  configurado: boolean;
  issuer: string;
  auto_alta: boolean;
  rol_jit: string | null;
  detalle: string;
}

/** Nodo del grafo de plantilla: una persona REAL del directorio (LDAP). */
export interface NodoPlantilla {
  cuenta: string;
  nombre: string;
  cargo: string;
  departamento: string;
  correo: string;
  manager: string | null;
  nivel: number;
}

/** Grafo organizacional leído directamente del controlador de dominio. */
export interface GrafoPlantilla {
  conectado: boolean;
  requisito?: string;
  base_dn?: string;
  nodos: NodoPlantilla[];
  aristas: { de: string; a: string }[];
  departamentos: Record<string, number>;
  resumen?: {
    total: number;
    con_manager: number;
    raices: number;
    profundidad: number;
  };
  nota?: string;
}

export interface EstadoConsola {
  engagement: Engagement;
  hallazgos: Hallazgo[];
  evidencias: Evidencia[];
  aprobaciones: Aprobacion[];
  auditoria: EventoAuditoria[];
  usoTokens: UsoTokens[];
  resumenAcumulado: string;
  cadenaCustodia: { valida: boolean; total: number; primer_error?: string | null };
}

/** Etiquetas en español para la UI. */
export const ETIQUETA_FASE: Record<FaseId, string> = {
  F0_scoping: "F0 · Scoping y ROE",
  F1_osint: "F1 · OSINT",
  F2_recon: "F2 · Reconocimiento",
  F3_acceso_inicial: "F3 · Acceso inicial",
  F4_dominio_ad: "F4 · Dominio AD",
  F5_c2_postex: "F5 · C2 y postex.",
  F6_phishing: "F6 · Phishing",
  F7_informe: "F7 · Informe",
  cierre: "Cierre · Higiene",
};

export const ORDEN_FASES: FaseId[] = [
  "F0_scoping",
  "F1_osint",
  "F2_recon",
  "F3_acceso_inicial",
  "F4_dominio_ad",
  "F5_c2_postex",
  "F6_phishing",
  "F7_informe",
  "cierre",
];

export const QUE_HACE_IA: Record<FaseId, string> = {
  F0_scoping: "Redacta alcance, ROE y criterios de éxito a partir de la plantilla y la entrevista.",
  F1_osint: "Orquesta recolectores de dominios, fugas, redes y código; deduplica y puntúa hallazgos.",
  F2_recon: "Ejecuta enumeración externa, correlaciona superficies y propone vectores ordenados por probabilidad y ruido.",
  F3_acceso_inicial: "Prepara la explotación vía adaptador, genera variantes y aplica plan B ante fallos.",
  F4_dominio_ad: "Construye el grafo del dominio, calcula rutas más cortas a Domain Admin y estima ruido.",
  F5_c2_postex: "Gestiona implantes vía adaptador con bucle agente local, jitter OPSEC y colección programada.",
  F6_phishing: "Genera campañas de simulación personalizadas por perfil con métricas de click y reporte.",
  F7_informe: "Consolida evidencias, redacta hallazgos, mapea ATT&CK y exporta el informe.",
  cierre: "Ejecuta y documenta la limpieza: implantes retirados, artefactos eliminados, certificado de borrado.",
};

export const QUE_APRUEBA_HUMANO: Record<FaseId, string> = {
  F0_scoping: "Firma el ROE y los límites duros.",
  F1_osint: "Prioriza objetivos humanos clave; autoriza la búsqueda de filtraciones.",
  F2_recon: "Valida el vector inicial propuesto.",
  F3_acceso_inicial: "Autoriza cada explotación y payload.",
  F4_dominio_ad: "Aprueba movimientos y técnicas ruidosas.",
  F5_c2_postex: "Define ventanas y aprueba acciones sensibles.",
  F6_phishing: "Aprueba plantillas y destinatarios.",
  F7_informe: "Revisa y firma el entregable.",
  cierre: "Valida la limpieza y cierra el engagement.",
};

export const ARTEFACTO_FASE: Record<FaseId, string> = {
  F0_scoping: "Contrato de engagement versionado",
  F1_osint: "Mapa de superficie humano y digital",
  F2_recon: "Inventario vivo con ATT&CK",
  F3_acceso_inicial: "Evidencias de entrada y cronología",
  F4_dominio_ad: "Ruta de compromiso verificada",
  F5_c2_postex: "Telemetría y capturas postex",
  F6_phishing: "Informe de campaña con métricas",
  F7_informe: "Informe ejecutivo y técnico",
  cierre: "Certificado de borrado",
};

export function formatoCoste(usd: number): string {
  if (usd === 0) return "0,00 $";
  if (usd < 0.01) return `${usd.toFixed(4).replace(".", ",")} $`;
  return `${usd.toFixed(2).replace(".", ",")} $`;
}

export function formatoTokens(n: number): string {
  return new Intl.NumberFormat("es-ES").format(n);
}

// ─── Técnicas (skills) del despliegue ───────────────────────────────────────
// Biblioteca de TTP ejecutables: procedimiento, herramientas, criterios y
// OPSEC. El índice (nombre + descripción) es lo único que ve el modelo;
// el cuerpo completo se carga bajo demanda (progressive disclosure).

export interface Tecnica {
  nombre: string;
  descripcion: string;
  fase: string;
  tecnica_mitre: string;
  riesgo: string;
  requiere_aprobacion: boolean;
  fuentes_permitidas: string[];
}

export interface CatalogoTecnicas {
  total: number;
  raiz: string;
  por_fase: Record<string, number>;
  por_riesgo: Record<string, number>;
  con_aprobacion: number;
  tecnicas: Tecnica[];
}

export interface TecnicaDetalle extends Tecnica {
  hash_contenido: string;
  cuerpo: string;
}

// ---------------------------------------------------------------------------
// Rutas de ataque (v22): motor Neo4j real con esquema BloodHound
// ---------------------------------------------------------------------------

export interface NodoRuta {
  nombre: string;
  tipo: string;
  asreproastable?: boolean;
  kerberoasteable?: boolean;
}

export interface RutaAtaque {
  nodos: NodoRuta[];
  aristas: string[];
  saltos: number;
}

export interface MotorRutasEstado {
  conectado: boolean;
  motor?: string;
  objetos?: Record<string, number>;
  aristas?: Record<string, number>;
  cargado?: boolean;
  esquema?: string;
  nota?: string;
  error?: string;
}

export interface OrigenRuta {
  nombre: string;
  admincount: boolean;
  asreproastable: boolean;
  displayname: string;
  cargo: string;
}

export interface ObjetivoRuta {
  nombre: string;
  tipo: string;
}

export interface VistaRutas {
  motor: MotorRutasEstado;
  origenes?: { conectado: boolean; usuarios?: OrigenRuta[]; total?: number; error?: string };
  objetivos?: { conectado: boolean; objetivos?: ObjetivoRuta[]; total?: number; error?: string };
}

export interface RespuestaRutas {
  conectado: boolean;
  origen?: string;
  rutas?: RutaAtaque[];
  total?: number;
  nota?: string;
  error?: string;
}

// ---------------------------------------------------------------------------
// Intel CVE real vía NVD (v22)
// ---------------------------------------------------------------------------

export interface CveEnriquecido {
  cve: string;
  publicado: string;
  severidad: string | null;
  cvss_base: number | null;
  vector: string | null;
  descripcion: string;
  consulta: string;
}

export interface RespuestaNvd {
  conectado: boolean;
  servicio?: string;
  consultas?: { consulta: string; http: number }[];
  coincidencias?: CveEnriquecido[];
  total?: number;
  nota?: string;
  error?: string;
}
