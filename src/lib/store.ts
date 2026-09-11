"use client";

/**
 * Store EN VIVO de la consola — cliente de la API del orquestador.
 *
 * Sin simulación: todo el estado viene del backend Python
 * (/api/orchestrator/*), que ejecuta herramientas reales, aplica el
 * boundary de guardrails y persiste en la memoria del caso con cadena de
 * custodia.
 *
 * v6: sesión de operador autenticada (JWT Bearer), eventos EN VIVO por
 * SSE (con sondeo de respaldo) y búsqueda real en la memoria del caso.
 */

import { create } from "zustand";
import {
  Aprobacion,
  CatalogoTecnicas,
  Engagement,
  EstadoIntegraciones,
  Evidencia,
  EventoAuditoria,
  FaseId,
  GrafoPlantilla,
  Hallazgo,
  Objetivo,
  RespuestaNvd,
  RespuestaRutas,
  ResultadoPrueba,
  UsoTokens,
  VistaRutas,
} from "./tipos";

// ---------------------------------------------------------------------------
// Transporte HTTP (con sesión autenticada)
// ---------------------------------------------------------------------------

const BASE = "/api/orchestrator";
const CLAVE_TOKEN = "orquestart.token";
const CLAVE_CASO = "orquestart.caso";

let _token: string | null = null;
if (typeof window !== "undefined") {
  try {
    _token = localStorage.getItem(CLAVE_TOKEN);
  } catch {
    /* sin almacenamiento */
  }
}

function fijarToken(token: string | null) {
  _token = token;
  try {
    if (token) localStorage.setItem(CLAVE_TOKEN, token);
    else localStorage.removeItem(CLAVE_TOKEN);
  } catch {
    /* ignora */
  }
}

/** Error de sesión expirada: la UI lo trata volviendo al acceso. */
export class SesionExpirada extends Error {
  constructor() {
    super("sesion_expirada");
  }
}

async function api<T>(ruta: string, opciones: RequestInit = {}): Promise<T> {
  const cabeceras: Record<string, string> = {
    "Content-Type": "application/json",
    ...((opciones.headers as Record<string, string>) ?? {}),
  };
  if (_token) cabeceras["Authorization"] = `Bearer ${_token}`;
  const r = await fetch(`${BASE}${ruta}`, { cache: "no-store", ...opciones, headers: cabeceras });
  if (r.status === 401) {
    // Sesión ausente o expirada: limpiar y señalizar (sin bucles).
    fijarToken(null);
    usarConsola.setState({ sesion: null, estadoAuth: "requiere_login" });
    throw new SesionExpirada();
  }
  let cuerpo: Record<string, unknown> = {};
  try {
    cuerpo = await r.json();
  } catch {
    /* respuesta vacía */
  }
  if (!r.ok) {
    const detalle =
      (cuerpo.detalle as string) ?? (cuerpo.error as string) ?? `HTTP ${r.status}`;
    throw new Error(typeof detalle === "string" ? detalle : JSON.stringify(detalle));
  }
  return cuerpo as T;
}

// ---------------------------------------------------------------------------
// Tipos locales
// ---------------------------------------------------------------------------

export interface ItemActividad {
  id: string;
  titulo: string;
  detalle: string;
  tono: "normal" | "exito" | "aviso" | "alerta" | "bloqueo";
  ts: string;
}

export interface EstadisticasMemoria {
  evidencias: number;
  hallazgos: number;
  aprobaciones: number;
  auditoria: number;
  objetivos: number;
  resumenes: number;
  tamano_db_bytes: number;
  cifrado_reposo: boolean;
}

export interface CasoResumen {
  id: string;
  nombre: string;
  cliente: string;
  fase_actual: FaseId;
  estado_fase: string;
  coste_acumulado_usd: number;
  tokens_acumulados: number;
}

export interface DatosNuevoCaso {
  nombre: string;
  cliente: string;
  alcance_dominios: string[];
  alcance_cidrs: string[];
  alcance_excluido: string[];
  tecnicas_prohibidas: string[];
  techo_ruido: number;
  ventana_inicio: string;
  ventana_fin: string;
}

export interface ResultadoAvance {
  ejecutada: boolean;
  fase?: string;
  espera?: boolean;
  parada?: boolean;
  resumen: string;
  bloqueos?: string[];
}

export interface SesionOperador {
  usuario: string;
  rol: "admin" | "gestor" | "operador" | "lector";
  tenant_id: string;
}

export type EstadoAuth = "cargando" | "sin_operadores" | "requiere_login" | "autenticado";

export interface ResultadoBusqueda {
  id: string;
  tipo: string;
  titulo: string;
  fragmento: string;
  puntuacion: number;
  fase: string;
  creado_en: string;
  extra: Record<string, unknown>;
}

// --- Copiloto (IA real con contexto del caso) -------------------------------
export interface ConfigCopiloto {
  habilitado: boolean;
  politica_salida: string;
  backends: {
    frontera: { configurado: boolean; base: string; modelo: string; politica_salida: string };
    local: { configurado: boolean; base: string; modelo: string };
  };
}

export interface FuenteCopiloto {
  id: string;
  tipo: string;
  titulo: string;
  fragmento: string;
}

export interface MensajeCopiloto {
  rol: "operador" | "copiloto";
  texto: string;
  modelo?: string;
  tipo_modelo?: string;
  tokens?: number;
  coste_usd?: number;
  fuentes?: FuenteCopiloto[];
  secciones?: { titulo: string; cuerpo: string }[];
  sugerencias?: SugerenciaCopiloto[];
  error?: boolean;
  ts: string;
}

export interface SugerenciaCopiloto {
  titulo: string;
  detalle: string;
  confianza: number;
  canal: string;
}

// --- Razonamiento adaptativo -------------------------------------------------
export interface CoberturaCaso {
  fase_actual: string;
  estado_fase: string;
  objetivos_total: number;
  objetivos_por_tipo: Record<string, Record<string, number>>;
  hallazgos_total: number;
  hallazgos_por_severidad: Record<string, number>;
  evidencias_total: number;
  transportes_aplicados: string[];
  huecos: { fase: string; hueco: string }[];
  sin_explorar: {
    hosts: string[]; dominios: string[]; servicios: string[];
    rutas_en_riesgo: string[];
  };
}

export interface PrioridadAdaptativa {
  herramienta: string;
  objetivo: string;
  justificacion: string;
  confianza: number;
  fase_sugerida: string;
  estado: string;
}

export interface PrioridadesAdaptativas {
  fase_actual: string;
  ventana_abierta: boolean;
  cobertura: { objetivos_total: number; hallazgos_total: number; huecos: { fase: string; hueco: string }[] };
  prioridades: PrioridadAdaptativa[];
}

export interface PlanAdaptativo {
  id: string;
  fase: string;
  pasos: {
    orden: number; herramienta: string; objetivo: string;
    justificacion: string; confianza: number; intrusivo: boolean; ruido: string;
  }[];
  descartados: { paso: Record<string, unknown>; motivo: string }[];
  modelo: string;
  tipo_modelo: string;
  tokens: number;
  coste_usd: number;
  nota: string;
}

// Cobertura ATT&CK agregada entre campañas (v16)
export interface CeldaCobertura {
  estado: "observada" | "intentada";
  hallazgos: number;
  severidad_max: string | null;
  deteccion: { detectado: number; no_detectado: number; prevenido: number; pendiente: number };
  cobertura_pct: number | null;
}
export interface CampanaCobertura {
  id: string;
  nombre: string;
  cliente: string;
  fase: string;
  estado_fase: string;
  creado_en: string;
  hallazgos_con_tecnica: number;
  tecnicas_observadas: number;
  tecnicas_intentadas: number;
  deteccion: { detectado: number; no_detectado: number; prevenido: number; pendiente: number };
  cobertura_deteccion_pct: number | null;
  ids_invalidos: number;
}
export interface FilaCobertura {
  tecnica: string;
  celdas: Record<string, CeldaCobertura | null>;
  campanas: number;
}
export interface RecurrenteCobertura {
  tecnica: string;
  campanas: { id: string; nombre: string }[];
}
export interface TotalesCobertura {
  campañas: number;
  tecnicas_distintas: number;
  tecnicas_observadas: number;
  tecnicas_intentadas: number;
  hallazgos_con_tecnica: number;
  ids_invalidos: number;
  por_severidad: Record<string, number>;
  deteccion: { detectado: number; no_detectado: number; prevenido: number; pendiente: number };
  cobertura_deteccion_media_pct: number | null;
  cobertura_deteccion_global_pct: number | null;
}
export interface CoberturaAttack {
  generado: string;
  fuente: string;
  campañas: CampanaCobertura[];
  matriz: FilaCobertura[];
  recurrentes: RecurrenteCobertura[];
  totales: TotalesCobertura;
  errores: { bd: string; motivo: string }[];
}

// Webhooks de notificación operativa (v16)
export interface ReceptorWebhook {
  id: string;
  url: string;
  eventos: string[];
  activo: boolean;
  descripcion: string;
  tiene_secreto: boolean;
  creado_en: string;
  actualizado_en: string;
  secreto_generado?: string;
}
export interface EntregaWebhook {
  webhook_id: string;
  evento: string;
  engagement_id: string;
  ok: boolean;
  http: number | null;
  error: string | null;
  intentos: number;
  creado_en: string;
}

export interface ReflexionFase {
  id: string;
  fase: string;
  reflexion: string;
  confianza_media: number | null;
  modelo: string;
  tipo_modelo: string;
  tokens: number;
  coste_usd: number;
}

export interface TrazaRazonamiento {
  id: string;
  tipo: string;
  fase: string;
  salida: Record<string, unknown>;
  modelo: string;
  tipo_modelo: string;
  tokens_entrada: number;
  tokens_salida: number;
  coste_usd: number;
  confianza: number | null;
  creado_en: string;
  entrada_hash: string;
  salida_hash: string;
}

// --- Equipo (gestión admin de operadores) -----------------------------------
export interface OperadorCuenta {
  usuario: string;
  rol: string;
  tenant_id: string;
  sso_sub: string | null;
  creado_en: string;
  ultimo_acceso: string | null;
}

// --- Diferencial de superficie -----------------------------------------------
export interface DifSuperficie {
  desde: string | null;
  hasta: string | null;
  total_superficie: number;
  nuevos: Objetivo[];
  resumen: { nuevos: number; por_estado: Record<string, number>; por_tipo: Record<string, number> };
}

// --- Arsenal (v20): evasión verificada, persistencia real, AD ofensivo -------
export interface DeteccionYara {
  regla: string;
  meta: Record<string, string>;
  cadenas: string[];
}

export interface ResultadoEvasion {
  metodo: string;
  formato: string;
  hash_payload: string;
  hash_artefacto: string;
  entropia_antes: number;
  entropia_despues: number;
  detecciones_antes: DeteccionYara[];
  detecciones_despues: DeteccionYara[];
  reglas: string[];
  roundtrip: { tipo: string; salida?: string; rc?: number; error?: string; hash_reconstruido?: string };
  roundtrip_ok: boolean;
  evasion_verificada: boolean;
  artefacto_b64: string;
  tamano_artefacto: number;
  motor: string;
}

export interface MetodoPersistencia {
  metodo: string;
  tecnica: string;
  titulo: string;
  sistema: string;
  tipo: string;
  disponible: boolean;
  detalle: string;
  estado: string;
}

export interface EstadoArsenal {
  reglas_deteccion: string[];
  persistencia: { raiz: string; metodos: Record<string, MetodoPersistencia>; limpio_total: boolean };
  evidencias: Evidencia[];
}

export interface ResultadoAccionArsenal {
  estado: "ejecutado" | "espera_aprobacion" | "fallo" | "sin_resultado";
  mensaje: string;
  aprobacion_id?: string;
  evidencia_id?: string;
  resultado?: ResultadoEvasion | Record<string, unknown>;
  escaneo?: { detecciones: DeteccionYara[]; limpio: boolean };
}

interface EstadoConsola {
  // sesión
  estadoAuth: EstadoAuth;
  sesion: SesionOperador | null;
  // conexión
  iniciado: boolean;
  corriendo: boolean; // sondeo en vivo activo
  fuenteViva: "sse" | "sondeo" | null;
  sincronizando: boolean;
  errorBackend: string | null;
  ultimaSync: string | null;
  // casos
  casos: CasoResumen[];
  casoActivo: string | null;
  // estado del engagement
  engagement: Engagement | null;
  hallazgos: Hallazgo[];
  evidencias: Evidencia[];
  aprobaciones: Aprobacion[];
  auditoria: EventoAuditoria[];
  usoTokens: UsoTokens[];
  objetivos: Objetivo[];
  memoria: EstadisticasMemoria | null;
  resumenAcumulado: string;
  cadenaCustodia: { valida: boolean; total: number; primer_error?: string | null };
  ruidoAcumulado: number;
  actividad: ItemActividad[];
  // integraciones reales (C2/AD/SMTP/LLM/OSINT)
  integraciones: EstadoIntegraciones | null;
  pruebasIntegracion: Record<string, { cargando: boolean; resultado?: ResultadoPrueba }>;
  plantilla: GrafoPlantilla | null;
  plantillaEstado: "inactiva" | "cargando" | "lista" | "error";
  // rutas de ataque (motor Neo4j real, v22) e intel NVD
  vistaRutas: VistaRutas | null;
  rutasResultado: RespuestaRutas | null;
  rutasCargando: boolean;
  nvdResultado: RespuestaNvd | null;
  nvdCargando: boolean;
  // biblioteca de técnicas del despliegue (skills)
  tecnicas: CatalogoTecnicas | null;
  // búsqueda en memoria del caso
  buscandoMemoria: boolean;
  resultadosBusqueda: ResultadoBusqueda[] | null;
  metodoBusqueda: string | null;
  // copiloto
  copilotoConfig: ConfigCopiloto | null;
  copilotoConversacion: MensajeCopiloto[];
  copilotoOcupado: boolean;
  // razonamiento adaptativo
  cobertura: CoberturaCaso | null;
  prioridades: PrioridadesAdaptativas | null;
  planRazon: PlanAdaptativo | null;
  reflexion: ReflexionFase | null;
  trazasRazon: TrazaRazonamiento[] | null;
  razonOcupado: string | null; // "cobertura" | "plan" | "reflexion" | null
  errorRazon: string | null;
  // cobertura ATT&CK agregada entre campañas (v16)
  coberturaAttack: CoberturaAttack | null;
  coberturaAttackOcupada: boolean;
  // planificación threat-led (v21)
  cadenas: import("./tipos").ResumenCadena[] | null;
  planThreatled: import("./tipos").PlanThreatled | null;
  threatledOcupado: boolean;
  organizaciones: import("./tipos").Organizacion[] | null;
  // webhooks de notificación (admin)
  webhooks: ReceptorWebhook[] | null;
  eventosWebhook: string[];
  webhooksOcupado: boolean;
  // equipo (admin)
  operadores: OperadorCuenta[] | null;
  // diferencial de superficie
  difSuperficie: DifSuperficie | null;
  difOcupado: boolean;
  // arsenal (v20): evasión / persistencia / AD
  arsenal: EstadoArsenal | null;
  arsenalOcupado: boolean;
  arsenalCargando: boolean;

  // sesión: acciones
  iniciarAuth(): Promise<void>;
  iniciarSesion(usuario: string, contrasena: string): Promise<void>;
  completarSso(code: string, state: string): Promise<void>;
  registrarPrimerOperador(usuario: string, contrasena: string): Promise<void>;
  cerrarSesion(): void;
  // caso: acciones
  iniciar(): Promise<void>;
  cargarCasos(): Promise<void>;
  crearCaso(datos: DatosNuevoCaso): Promise<string>;
  seleccionarCaso(id: string | null): void;
  recibirEvento(ev: EventoAuditoria): void;
  refrescar(): Promise<void>;
  avanzarFase(contexto?: { notas_cliente?: string; vector_elegido?: string; perfil_objetivo?: string; modulo?: string; opciones?: Record<string, string>; destinatarios?: string[] }): Promise<ResultadoAvance>;
  decidir(id: string, aprobar: boolean, comentario: string): Promise<void>;
  registrarHallazgo(datos: { titulo: string; severidad: string; tecnica_mitre?: string; activo?: string; descripcion?: string; recomendacion?: string }): Promise<{ id: string }>;
  marcarDeteccion(hallazgoId: string, deteccion: Hallazgo["deteccion"]): Promise<void>;
  paradaEmergencia(activar: boolean, motivo?: string): Promise<void>;
  alternarPausa(): void;
  cargarIntegraciones(): Promise<void>;
  probarIntegracion(nombre: string): Promise<void>;
  consultarPlantilla(): Promise<void>;
  cargarRutas(): Promise<void>;
  calcularRutas(origen: string): Promise<void>;
  enriquecerNvd(texto: string): Promise<void>;
  cargarTecnicas(): Promise<void>;
  recargarTecnicas(): Promise<number>;
  buscarEnMemoria(consulta: string): Promise<void>;
  limpiarBusqueda(): void;
  // copiloto
  cargarCopilotoConfig(): Promise<void>;
  alternarCopiloto(habilitado: boolean): Promise<void>;
  consultarCopiloto(pregunta: string): Promise<void>;
  limpiarConversacionCopiloto(): void;
  // razonamiento adaptativo
  cargarCobertura(): Promise<void>;
  cargarPrioridades(): Promise<void>;
  generarPlan(): Promise<void>;
  generarReflexion(): Promise<void>;
  cargarTrazasRazon(): Promise<void>;
  // cobertura ATT&CK agregada entre campañas (v16)
  cargarCoberturaAttack(): Promise<void>;
  // planificación threat-led (v21)
  cargarCadenas(): Promise<void>;
  generarPlanThreatled(cadenaId: string): Promise<void>;
  cargarOrganizaciones(): Promise<void>;
  crearOrganizacion(id: string, nombre: string): Promise<void>;
  // webhooks de notificación (admin)
  cargarWebhooks(): Promise<void>;
  crearWebhook(datos: { url: string; eventos: string[]; secreto: string; descripcion: string }): Promise<ReceptorWebhook>;
  actualizarWebhook(id: string, datos: { url?: string; eventos?: string[]; activo?: boolean; descripcion?: string; secreto?: string }): Promise<void>;
  eliminarWebhook(id: string): Promise<void>;
  probarWebhook(id: string): Promise<{ enviado: boolean; http: number | null; error: string | null }>;
  cargarEntregasWebhook(id: string): Promise<EntregaWebhook[]>;
  // equipo (admin)
  cargarOperadores(): Promise<void>;
  crearOperadorCuenta(usuario: string, contrasena: string, rol: string, tenant_id?: string): Promise<void>;
  cambiarRolOperador(usuario: string, rol: string): Promise<void>;
  restablecerOperador(usuario: string, nueva: string): Promise<void>;
  eliminarOperadorCuenta(usuario: string): Promise<void>;
  // diferencial de superficie
  calcularDif(desde: string, hasta?: string): Promise<void>;
  limpiarDif(): void;
  // arsenal (v20)
  cargarArsenal(): Promise<void>;
  generarEvasion(datos: { payload_b64: string; metodo: string; formato: string; nota?: string }): Promise<ResultadoAccionArsenal>;
  escanearArtefactoEvasion(evidenciaId: string): Promise<ResultadoAccionArsenal>;
  accionPersistencia(accion: "implantar" | "verificar" | "retirar", datos: { metodo: string; comando?: string; raiz?: string }): Promise<ResultadoAccionArsenal>;
  accionAD(datos: { accion: string; host?: string; usuario?: string; hash_nt?: string; dn_objetivo?: string }): Promise<ResultadoAccionArsenal>;
}

// ---------------------------------------------------------------------------
// Derivados
// ---------------------------------------------------------------------------

function _limpiar(texto: string): string {
  return (texto || "").replace(/_/g, " ").trim();
}

function _tonoDe(ev: Record<string, unknown>): ItemActividad["tono"] {
  const accion = String(ev.accion ?? "");
  const resultado = String(ev.resultado ?? "");
  if (accion.startsWith("boundary:")) {
    if (resultado === "denegar") return "alerta";
    if (resultado === "requiere_aprobacion") return "bloqueo";
    if (resultado === "permitir") return "normal";
  }
  if (resultado === "error") return "alerta";
  if (accion.startsWith("fase.fin") || accion === "aprobacion.decision") return "exito";
  if (accion.startsWith("roe.")) return "aviso";
  return "normal";
}

function _tituloDe(ev: Record<string, unknown>): string {
  const accion = String(ev.accion ?? "");
  const herramienta = String(ev.herramienta ?? "");
  if (accion.startsWith("boundary:")) {
    const decision = String(ev.resultado ?? "");
    const etiqueta =
      decision === "denegar" ? "Bloqueado por el boundary" :
      decision === "requiere_aprobacion" ? "El boundary exige tu firma" :
      "Autorizado por el boundary";
    return `${etiqueta}: ${_limpiar(herramienta) || accion.slice(9)}`;
  }
  if (accion === "aprobacion.decision") return "Decisión del operador registrada";
  if (accion === "engagement.avanzar") return "Ejecución de fase solicitada";
  if (accion === "fase.inicio:F7_informe") return "F7: consolidando informe";
  if (accion.startsWith("fase.inicio")) return `Inicio de ${_limpiar(segmentoDeAccion(accion))}`;
  if (accion.startsWith("fase.fin")) return `Fase completada: ${_limpiar(segmentoDeAccion(accion))}`;
  if (accion === "engagement.crear") return "Caso creado";
  if (accion === "roe.parada_emergencia") return "PARADA DE EMERGENCIA (ROE)";
  if (accion === "roe.actualizar") return "ROE actualizado por el operador";
  if (accion === "copiloto_consulta") return "Consulta al copiloto (IA)";
  if (accion === "copiloto_config") return "Configuración del copiloto";
  if (accion === "caso.exportado") return "Exportación de custodia del caso";
  if (accion === "hallazgos.export_csv") return "Hallazgos exportados a CSV";
  if (accion === "hallazgo.deteccion") return "Resultado de detección registrado (blue team)";
  if (accion === "caso.purple_team") return "Paquete purple team generado (detección + Sigma)";
  return _limpiar(accion) || "Evento del sistema";
}

function segmentoDeAccion(accion: string): string {
  return accion.split(":")[1] ?? accion;
}

function derivarActividad(auditoria: EventoAuditoria[]): ItemActividad[] {
  return auditoria.slice(0, 40).map((ev) => {
    const e = ev as unknown as Record<string, unknown>;
    return {
      id: ev.id,
      titulo: _tituloDe(e),
      detalle: String(ev.detalle ?? "").slice(0, 240),
      tono: _tonoDe(e),
      ts: ev.creado_en,
    };
  });
}

// ---------------------------------------------------------------------------
// Flujo SSE en vivo (auditoría del caso sin esperar al sondeo)
// ---------------------------------------------------------------------------

let _controlSSE: AbortController | null = null;
let _ultimoRefrescoTotal = 0;
// Resiliencia SSE estándar (MDN): último `id:` recibido del caso activo.
// Se envía como Last-Event-ID al reconectar para no perder eventos del hueco.
let _ultimoIdSSE = "";
let _idSSEactual = "";

function detenerSSE() {
  if (_controlSSE) _controlSSE.abort();
  _controlSSE = null;
}

async function arrancarSSE(id: string) {
  detenerSSE();
  if (_idSSEactual !== id) {
    // caso distinto: el last-event-id anterior no aplica
    _idSSEactual = id;
    _ultimoIdSSE = "";
  }
  const control = new AbortController();
  _controlSSE = control;
  try {
    const cabeceras: Record<string, string> = {};
    if (_token) cabeceras["Authorization"] = `Bearer ${_token}`;
    if (_ultimoIdSSE) cabeceras["Last-Event-ID"] = _ultimoIdSSE;
    const r = await fetch(`${BASE}/engagements/${id}/eventos`, {
      headers: cabeceras,
      signal: control.signal,
      cache: "no-store",
    });
    if (!r.ok || !r.body) throw new Error(`SSE ${r.status}`);
    if (_controlSSE !== control) return; // sustituido mientras conectaba
    usarConsola.setState({ fuenteViva: "sse" });
    const lector = r.body.getReader();
    const decodificador = new TextDecoder();
    let buffer = "";
    const procesar = (bloque: string) => {
      buffer += bloque;
      const partes = buffer.split("\n\n");
      buffer = partes.pop() ?? "";
      for (const parte of partes) {
        const lineas = parte.split("\n");
        const lineaId = lineas.find((l) => l.startsWith("id:"));
        if (lineaId && lineaId.slice(3).trim()) {
          _ultimoIdSSE = lineaId.slice(3).trim();
        }
        const linea = lineas.find((l) => l.startsWith("data:"));
        if (!linea) continue;
        try {
          const mensaje = JSON.parse(linea.slice(5).trim());
          if (mensaje.tipo === "auditoria" && mensaje.evento) {
            usarConsola.getState().recibirEvento(mensaje.evento as EventoAuditoria);
          }
        } catch {
          /* fragmento no JSON: ignorar */
        }
      }
    };
    while (true) {
      const { done, value } = await lector.read();
      if (done) break;
      procesar(decodificador.decode(value, { stream: true }));
    }
  } catch {
    /* abortado o fallo de conexión */
  }
  if (_controlSSE === control) {
    _controlSSE = null;
    usarConsola.setState({ fuenteViva: "sondeo" });
    // Reciclado del flujo (el backend cierra a los 4 min): reconexión suave.
    setTimeout(() => {
      const estado = usarConsola.getState();
      if (estado.estadoAuth === "autenticado" && estado.corriendo &&
          estado.casoActivo === id && estado.sesion) {
        arrancarSSE(id);
      }
    }, 5000);
  }
}

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

let _temporizador: ReturnType<typeof setInterval> | null = null;
const INTERVALO_SONDEO_MS = 3000;

export const usarConsola = create<EstadoConsola>((set, get) => ({
  estadoAuth: "cargando",
  sesion: null,
  iniciado: false,
  corriendo: true,
  fuenteViva: null,
  sincronizando: false,
  errorBackend: null,
  ultimaSync: null,
  casos: [],
  casoActivo: null,
  engagement: null,
  hallazgos: [],
  evidencias: [],
  aprobaciones: [],
  auditoria: [],
  usoTokens: [],
  objetivos: [],
  memoria: null,
  resumenAcumulado: "",
  cadenaCustodia: { valida: true, total: 0, primer_error: null },
  ruidoAcumulado: 0,
  actividad: [],
  integraciones: null,
  pruebasIntegracion: {},
  plantilla: null,
  plantillaEstado: "inactiva",
  vistaRutas: null,
  rutasResultado: null,
  rutasCargando: false,
  nvdResultado: null,
  nvdCargando: false,
  tecnicas: null,
  buscandoMemoria: false,
  resultadosBusqueda: null,
  metodoBusqueda: null,
  copilotoConfig: null,
  copilotoConversacion: [],
  copilotoOcupado: false,
  // razonamiento adaptativo
  cobertura: null,
  prioridades: null,
  planRazon: null,
  reflexion: null,
  trazasRazon: null,
  razonOcupado: null,
  errorRazon: null,
  coberturaAttack: null,
  coberturaAttackOcupada: false,
  cadenas: null,
  planThreatled: null,
  threatledOcupado: false,
  organizaciones: null,
  webhooks: null,
  eventosWebhook: [],
  webhooksOcupado: false,
  operadores: null,
  difSuperficie: null,
  difOcupado: false,
  arsenal: null,
  arsenalOcupado: false,
  arsenalCargando: false,

  // -- sesión ---------------------------------------------------------------

  async iniciarAuth() {
    set({ estadoAuth: "cargando" });
    try {
      const estado = await api<{ hay_operadores: boolean }>("/auth/estado");
      if (!estado.hay_operadores) {
        set({ estadoAuth: "sin_operadores", sesion: null });
        return;
      }
      if (!_token) {
        set({ estadoAuth: "requiere_login", sesion: null });
        return;
      }
      const sesion = await api<{ usuario: string; rol: string; tenant_id?: string }>(
        "/auth/sesion");
      set({
        estadoAuth: "autenticado",
        sesion: {
          usuario: sesion.usuario,
          rol: ((sesion.rol as SesionOperador["rol"]) || "operador"),
          tenant_id: sesion.tenant_id ?? "predeterminada",
        },
      });
      await get().iniciar();
    } catch (e) {
      if (e instanceof SesionExpirada) return; // ya redirigido al login
      set({ errorBackend: (e as Error).message });
      // Backend aún arrancando: reintento suave sin bloquear la UI
      setTimeout(() => {
        if (get().estadoAuth === "cargando") get().iniciarAuth().catch(() => undefined);
      }, 4000);
    }
  },

  async iniciarSesion(usuario, contrasena) {
    const r = await api<{ usuario: string; rol: string; tenant_id?: string; token: string }>(
      "/auth/login",
      { method: "POST", body: JSON.stringify({ usuario, contrasena }) });
    fijarToken(r.token);
    set({
      sesion: {
        usuario: r.usuario,
        rol: (r.rol as SesionOperador["rol"]) || "operador",
        tenant_id: r.tenant_id ?? "predeterminada",
      },
      estadoAuth: "autenticado",
      errorBackend: null,
    });
    await get().iniciar();
  },

  async completarSso(code: string, state: string) {
    // Callback del flujo OIDC: el código se canjea en el backend, que
    // VERIFICA el id_token (RS256/JWKS) y devuelve el JWT de la plataforma.
    const r = await api<{
      usuario: string; rol: string; tenant_id?: string; token: string;
    }>(`/auth/sso/callback?code=${encodeURIComponent(code)}&state=${encodeURIComponent(state)}`);
    fijarToken(r.token);
    set({
      sesion: {
        usuario: r.usuario,
        rol: (r.rol as SesionOperador["rol"]) || "lector",
        tenant_id: r.tenant_id ?? "predeterminada",
      },
      estadoAuth: "autenticado",
      errorBackend: null,
    });
    await get().iniciar();
  },

  async registrarPrimerOperador(usuario, contrasena) {
    await api("/auth/registrar", {
      method: "POST",
      body: JSON.stringify({ usuario, contrasena, rol: "admin" }),
    });
    await get().iniciarSesion(usuario, contrasena);
  },

  cerrarSesion() {
    fijarToken(null);
    detenerSSE();
    if (_temporizador) {
      clearInterval(_temporizador);
      _temporizador = null;
    }
    set({
      sesion: null,
      estadoAuth: "requiere_login",
      iniciado: false,
      casos: [],
      casoActivo: null,
      engagement: null,
      hallazgos: [],
      evidencias: [],
      aprobaciones: [],
      auditoria: [],
      usoTokens: [],
      objetivos: [],
      memoria: null,
      resumenAcumulado: "",
      actividad: [],
      resultadosBusqueda: null,
      fuenteViva: null,
    });
  },

  // -- ciclo en vivo ----------------------------------------------------------

  async iniciar() {
    if (_temporizador) clearInterval(_temporizador);
    set({ iniciado: false });
    await get().cargarCasos();
    let guardado: string | null = null;
    try {
      guardado = localStorage.getItem(CLAVE_CASO);
    } catch {
      /* sin almacenamiento */
    }
    const casos = get().casos;
    const activo = casos.some((c) => c.id === guardado) ? guardado : (casos[0]?.id ?? null);
    set({ iniciado: true, casoActivo: activo });
    if (activo) {
      await get().refrescar().catch(() => undefined);
      arrancarSSE(activo); // eventos en vivo: latencia ~1,5 s
    }
    _temporizador = setInterval(() => {
      if (get().corriendo && get().casoActivo && !get().sincronizando) {
        get().refrescar().catch(() => undefined);
      }
    }, INTERVALO_SONDEO_MS);
  },

  async cargarCasos() {
    try {
      const casos = await api<CasoResumen[]>("/engagements");
      set({ casos, errorBackend: null });
    } catch (e) {
      set({ errorBackend: (e as Error).message });
    }
  },

  async crearCaso(datos) {
    const r = await api<{ id: string; nombre: string }>("/engagements", {
      method: "POST",
      body: JSON.stringify(datos),
    });
    await get().cargarCasos();
    set({ casoActivo: r.id });
    try {
      localStorage.setItem(CLAVE_CASO, r.id);
    } catch {
      /* ignora */
    }
    await get().refrescar();
    arrancarSSE(r.id);
    return r.id;
  },

  seleccionarCaso(id) {
    set({
      casoActivo: id,
      engagement: null,
      hallazgos: [],
      evidencias: [],
      aprobaciones: [],
      auditoria: [],
      usoTokens: [],
      objetivos: [],
      memoria: null,
      resumenAcumulado: "",
      actividad: [],
      resultadosBusqueda: null,
    });
    try {
      if (id) localStorage.setItem(CLAVE_CASO, id);
      else localStorage.removeItem(CLAVE_CASO);
    } catch {
      /* ignora */
    }
    if (id) {
      get().refrescar().catch(() => undefined);
      if (get().corriendo) arrancarSSE(id);
      else detenerSSE();
    } else {
      detenerSSE();
    }
  },

  /** Evento de auditoría llegado por SSE: fusión inmediata + refresco con tope. */
  recibirEvento(ev: EventoAuditoria) {
    const { casoActivo, auditoria, corriendo } = get();
    if (!corriendo || !casoActivo || ev.engagement_id !== casoActivo) return;
    if (auditoria.some((a) => a.id === ev.id)) return;
    const nueva = [ev, ...auditoria].slice(0, 400);
    set({ auditoria: nueva, actividad: derivarActividad(nueva) });
    const ahora = Date.now();
    if (ahora - _ultimoRefrescoTotal > 1500) {
      _ultimoRefrescoTotal = ahora;
      get().refrescar().catch(() => undefined);
    }
  },

  async refrescar() {
    const id = get().casoActivo;
    if (!id) return;
    set({ sincronizando: true });
    try {
      const [estado, hallazgos, evEvid, auditoria, tokens] = await Promise.all([
        api<Record<string, unknown>>(`/engagements/${id}/estado`),
        api<Hallazgo[]>(`/engagements/${id}/hallazgos`),
        api<{ evidencias: Evidencia[]; cadena: EstadoConsola["cadenaCustodia"] }>(
          `/engagements/${id}/evidencias`),
        api<EventoAuditoria[]>(`/engagements/${id}/auditoria?limite=300`),
        api<{ registros: Record<string, unknown>[] }>(`/engagements/${id}/tokens`),
      ]);
      const usoTokens: UsoTokens[] = (tokens.registros ?? []).map((r) => ({
        fase: String(r.fase) as FaseId,
        modelo: String(r.modelo),
        tipo: (r.tipo_modelo === "frontera" ? "frontera" : "local") as UsoTokens["tipo"],
        tokens_entrada: Number(r.tokens_entrada ?? 0),
        tokens_salida: Number(r.tokens_salida ?? 0),
        cache_hit: Boolean(r.cache_hit),
        coste_usd: Number(r.coste_usd ?? 0),
        creado_en: String(r.creado_en ?? ""),
      }));
      const aprobaciones = await api<Aprobacion[]>(`/engagements/${id}/aprobaciones`);
      set({
        engagement: estado.engagement as Engagement,
        aprobaciones,
        hallazgos,
        evidencias: evEvid.evidencias,
        cadenaCustodia: evEvid.cadena,
        auditoria,
        usoTokens,
        objetivos: (estado.objetivos as Objetivo[]) ?? [],
        memoria: (estado.memoria as EstadisticasMemoria) ?? null,
        resumenAcumulado: String(estado.resumen_acumulado ?? ""),
        ruidoAcumulado: Number(estado.ruido_ejecutado ?? 0),
        actividad: derivarActividad(auditoria),
        errorBackend: null,
        ultimaSync: new Date().toISOString(),
      });
    } catch (e) {
      set({ errorBackend: (e as Error).message });
    } finally {
      set({ sincronizando: false });
    }
  },

  // Hallazgo manual del operador (v16): alta auditada + webhook
  async registrarHallazgo(datos: { titulo: string; severidad: string; tecnica_mitre?: string; activo?: string; descripcion?: string; recomendacion?: string }) {
    const id = get().casoActivo;
    if (!id) throw new Error("sin caso activo");
    const creado = await api<{ id: string }>(`/engagements/${id}/hallazgos`, {
      method: "POST",
      body: JSON.stringify(datos),
    });
    await get().refrescar();
    return creado;
  },

  async avanzarFase(contexto = {}) {
    const id = get().casoActivo;
    if (!id) throw new Error("sin caso activo");
    const r = await api<ResultadoAvance>(`/engagements/${id}/avanzar`, {
      method: "POST",
      body: JSON.stringify({
        notas_cliente: contexto.notas_cliente ?? "",
        vector_elegido: contexto.vector_elegido ?? "",
        perfil_objetivo: contexto.perfil_objetivo ?? "",
        modulo: contexto.modulo ?? "",
        opciones: contexto.opciones ?? {},
        destinatarios: contexto.destinatarios ?? [],
      }),
    });
    await get().refrescar();
    await get().cargarCasos();
    return r;
  },

  async decidir(idAprobacion, aprobar, comentario) {
    // La identidad real la establece la sesión JWT del operador en el backend.
    await api(`/aprobaciones/${idAprobacion}/decision`, {
      method: "POST",
      body: JSON.stringify({ decidir: aprobar, comentario }),
    });
    await get().refrescar();
  },

  async marcarDeteccion(hallazgoId, deteccion) {
    const id = get().casoActivo;
    if (!id) return;
    await api(`/engagements/${id}/hallazgos/${hallazgoId}/deteccion`, {
      method: "PATCH",
      body: JSON.stringify({ deteccion }),
    });
    await get().refrescar();
  },

  async paradaEmergencia(activar, motivo = "") {
    const id = get().casoActivo;
    if (!id) return;
    await api(`/engagements/${id}/parada_emergencia`, {
      method: "POST",
      body: JSON.stringify({
        activar,
        motivo: motivo || (activar ? "kill switch desde consola" : "reanudación del operador"),
      }),
    });
    await get().refrescar();
  },

  alternarPausa() {
    const nuevo = !get().corriendo;
    set({ corriendo: nuevo });
    if (nuevo && get().casoActivo) {
      get().refrescar().catch(() => undefined);
      arrancarSSE(get().casoActivo!);
    } else {
      detenerSSE();
    }
  },

  async cargarIntegraciones() {
    try {
      const estado = await api<EstadoIntegraciones>("/integraciones");
      set({ integraciones: estado, errorBackend: null });
    } catch (e) {
      set({ errorBackend: (e as Error).message });
    }
  },

  async cargarTecnicas() {
    try {
      const catalogo = await api<CatalogoTecnicas>("/skills");
      set({ tecnicas: catalogo, errorBackend: null });
    } catch (e) {
      set({ errorBackend: (e as Error).message });
    }
  },

  async recargarTecnicas() {
    const r = await api<{ total: number; mensaje: string }>("/skills/recargar", {
      method: "POST",
      body: JSON.stringify({ motivo: "recarga desde la consola del operador" }),
    });
    await get().cargarTecnicas();
    return r.total;
  },

  async probarIntegracion(nombre) {
    set({
      pruebasIntegracion: {
        ...get().pruebasIntegracion,
        [nombre]: { cargando: true },
      },
    });
    try {
      const resultado = await api<ResultadoPrueba>("/integraciones/probar", {
        method: "POST",
        body: JSON.stringify({ nombre }),
      });
      set({
        pruebasIntegracion: {
          ...get().pruebasIntegracion,
          [nombre]: { cargando: false, resultado },
        },
      });
    } catch (e) {
      set({
        pruebasIntegracion: {
          ...get().pruebasIntegracion,
          [nombre]: {
            cargando: false,
            resultado: { conectado: false, error: (e as Error).message },
          },
        },
      });
    }
  },

  async consultarPlantilla() {
    set({ plantillaEstado: "cargando" });
    try {
      const grafo = await api<GrafoPlantilla>("/integraciones/ldap/grafo");
      set({ plantilla: grafo, plantillaEstado: "lista", errorBackend: null });
    } catch {
      set({ plantillaEstado: "error" });
    }
  },

  async cargarRutas() {
    set({ rutasCargando: true });
    try {
      const vista = await api<VistaRutas>("/integraciones/rutas");
      set({ vistaRutas: vista, rutasCargando: false, errorBackend: null });
    } catch (e) {
      set({ rutasCargando: false });
      throw e;
    }
  },

  async calcularRutas(origen: string) {
    set({ rutasCargando: true });
    try {
      const r = await api<RespuestaRutas>("/integraciones/rutas", {
        method: "POST",
        body: JSON.stringify({ origen, limite: 5 }),
      });
      set({ rutasResultado: r, rutasCargando: false, errorBackend: null });
    } catch (e) {
      set({ rutasCargando: false });
      throw e;
    }
  },

  async enriquecerNvd(texto: string) {
    set({ nvdCargando: true });
    try {
      const r = await api<RespuestaNvd>("/integraciones/nvd/enriquecer", {
        method: "POST",
        body: JSON.stringify({ texto }),
      });
      set({ nvdResultado: r, nvdCargando: false, errorBackend: null });
    } catch (e) {
      set({ nvdCargando: false });
      throw e;
    }
  },

  async buscarEnMemoria(consulta) {
    const id = get().casoActivo;
    if (!id || consulta.trim().length < 2) return;
    set({ buscandoMemoria: true });
    try {
      const r = await api<{
        resultados: ResultadoBusqueda[];
        metodo: string;
        total_indexado: number;
      }>(`/engagements/${id}/memoria/buscar?q=${encodeURIComponent(consulta.trim())}`);
      set({
        resultadosBusqueda: r.resultados,
        metodoBusqueda: `${r.metodo} · ${r.total_indexado} artefactos indexados`,
        buscandoMemoria: false,
      });
    } catch {
      set({ buscandoMemoria: false, resultadosBusqueda: [], metodoBusqueda: null });
    }
  },

  limpiarBusqueda() {
    set({ resultadosBusqueda: null, metodoBusqueda: null });
  },

  // ------------------------------------------------------------------
  // Copiloto del operador (IA real con contexto del caso)
  // ------------------------------------------------------------------
  async cargarCopilotoConfig() {
    const id = get().casoActivo;
    if (!id) return;
    try {
      const cfg = await api<ConfigCopiloto>(`/engagements/${id}/copiloto/config`);
      set({ copilotoConfig: cfg });
    } catch {
      set({ copilotoConfig: null });
    }
  },

  async alternarCopiloto(habilitado: boolean) {
    const id = get().casoActivo;
    if (!id) return;
    const cfg = await api<ConfigCopiloto>(`/engagements/${id}/copiloto/config`, {
      method: "POST",
      body: JSON.stringify({ habilitado }),
    });
    set({ copilotoConfig: cfg });
  },

  async consultarCopiloto(pregunta: string) {
    const id = get().casoActivo;
    const texto = pregunta.trim();
    if (!id || !texto || get().copilotoOcupado) return;
    const conversacionPrevia = get().copilotoConversacion;
    const mensajeOperador: MensajeCopiloto = {
      rol: "operador", texto, ts: new Date().toISOString(),
    };
    set({
      copilotoOcupado: true,
      copilotoConversacion: [...conversacionPrevia, mensajeOperador],
    });
    try {
      // Multi-turno: el hilo reciente viaja al backend (el servidor no
      // guarda estado de conversación; la sesión es del operador).
      const historial = conversacionPrevia.slice(-6).map((m) => ({
        rol: m.rol, texto: m.texto.slice(0, 600),
      }));
      const r = await api<{
        respuesta: string; modelo: string; tipo_modelo: string;
        tokens_entrada: number; tokens_salida: number; coste_usd: number;
        fuentes: FuenteCopiloto[];
        secciones?: Record<string, string>;
        sugerencias?: SugerenciaCopiloto[];
      }>(`/engagements/${id}/copiloto`, {
        method: "POST",
        body: JSON.stringify({ pregunta: texto, historial }),
      });
      const secciones = Object.entries(r.secciones || {}).map(
        ([titulo, cuerpo]) => ({ titulo, cuerpo }));
      const respuesta: MensajeCopiloto = {
        rol: "copiloto",
        texto: r.respuesta,
        modelo: r.modelo,
        tipo_modelo: r.tipo_modelo,
        tokens: r.tokens_entrada + r.tokens_salida,
        coste_usd: r.coste_usd,
        fuentes: r.fuentes,
        secciones,
        sugerencias: r.sugerencias || [],
        ts: new Date().toISOString(),
      };
      set({ copilotoConversacion: [...get().copilotoConversacion, respuesta] });
    } catch (error) {
      const respuesta: MensajeCopiloto = {
        rol: "copiloto",
        texto: (error as Error).message || "Fallo del copiloto",
        error: true,
        ts: new Date().toISOString(),
      };
      set({ copilotoConversacion: [...get().copilotoConversacion, respuesta] });
    } finally {
      set({ copilotoOcupado: false });
    }
  },

  limpiarConversacionCopiloto() {
    set({ copilotoConversacion: [] });
  },

  // ------------------------------------------------------------------
  // Razonamiento adaptativo: cobertura, prioridades, plan y reflexión
  // ------------------------------------------------------------------
  async cargarCobertura() {
    const id = get().casoActivo;
    if (!id) return;
    set({ razonOcupado: "cobertura", errorRazon: null });
    try {
      const cobertura = await api<CoberturaCaso>(
        `/engagements/${id}/razonamiento/cobertura`);
      set({ cobertura, razonOcupado: null });
    } catch (error) {
      set({ razonOcupado: null, errorRazon: (error as Error).message });
    }
  },

  // Cobertura ATT&CK agregada entre campañas (v16): matriz técnica × campaña
  async cargarCoberturaAttack() {
    set({ coberturaAttackOcupada: true });
    try {
      const coberturaAttack = await api<CoberturaAttack>(
        "/analitica/cobertura-attack");
      set({ coberturaAttack, coberturaAttackOcupada: false });
    } catch (error) {
      set({ coberturaAttackOcupada: false });
      throw error;
    }
  },

  // Planificación threat-led (v21)
  async cargarCadenas() {
    try {
      const r = await api<{ cadenas: import("./tipos").ResumenCadena[] }>(
        "/threatled/cadenas");
      set({ cadenas: r.cadenas });
    } catch {
      set({ cadenas: [] });
    }
  },

  async generarPlanThreatled(cadenaId: string) {
    const caso = get().casoActivo;
    if (!caso) throw new Error("Selecciona un caso para contrastar la cadena");
    set({ threatledOcupado: true });
    try {
      const plan = await api<import("./tipos").PlanThreatled>(
        `/engagements/${caso}/threatled/plan`,
        { method: "POST", body: JSON.stringify({ cadena_id: cadenaId }) });
      set({ planThreatled: plan, threatledOcupado: false });
    } catch (error) {
      set({ threatledOcupado: false });
      throw error;
    }
  },

  async cargarOrganizaciones() {
    try {
      const organizaciones = await api<import("./tipos").Organizacion[]>(
        "/auth/organizaciones");
      set({ organizaciones });
    } catch {
      set({ organizaciones: [] });
    }
  },

  async crearOrganizacion(id: string, nombre: string) {
    await api("/auth/organizaciones", {
      method: "POST",
      body: JSON.stringify({ id, nombre }),
    });
    await get().cargarOrganizaciones();
  },

  // Webhooks de notificación operativa (v16, admin)
  async cargarWebhooks() {
    try {
      const r = await api<{ receptores: ReceptorWebhook[]; eventos: string[] }>(
        "/admin/webhooks");
      set({ webhooks: r.receptores, eventosWebhook: r.eventos });
    } catch {
      // no-admin o backend caído: la vista muestra el estado correspondiente
      set({ webhooks: [], eventosWebhook: [] });
    }
  },

  async crearWebhook(datos: { url: string; eventos: string[]; secreto: string; descripcion: string }) {
    const creado = await api<ReceptorWebhook>("/admin/webhooks", {
      method: "POST",
      body: JSON.stringify(datos),
    });
    const webhooks = usarConsola.getState().webhooks ?? [];
    set({ webhooks: [...webhooks, { ...creado }] });
    return creado;
  },

  async actualizarWebhook(id: string, datos: { url?: string; eventos?: string[]; activo?: boolean; descripcion?: string; secreto?: string }) {
    const actualizado = await api<ReceptorWebhook>(`/admin/webhooks/${id}`, {
      method: "PATCH",
      body: JSON.stringify(datos),
    });
    const webhooks = usarConsola.getState().webhooks ?? [];
    set({ webhooks: webhooks.map((w) => (w.id === id ? actualizado : w)) });
  },

  async eliminarWebhook(id: string) {
    await api<{ eliminado: string }>(`/admin/webhooks/${id}`, { method: "DELETE" });
    const webhooks = usarConsola.getState().webhooks ?? [];
    set({ webhooks: webhooks.filter((w) => w.id !== id) });
  },

  async probarWebhook(id: string) {
    return api<{ enviado: boolean; http: number | null; error: string | null }>(
      `/admin/webhooks/${id}/probar`, { method: "POST" });
  },

  async cargarEntregasWebhook(id: string) {
    return api<EntregaWebhook[]>(`/admin/webhooks/${id}/entregas?limite=20`);
  },

  async cargarPrioridades() {
    const id = get().casoActivo;
    if (!id) return;
    try {
      const prioridades = await api<PrioridadesAdaptativas>(
        `/engagements/${id}/razonamiento/prioridades`);
      set({ prioridades });
    } catch (error) {
      set({ errorRazon: (error as Error).message });
    }
  },

  async generarPlan() {
    const id = get().casoActivo;
    if (!id || get().razonOcupado) return;
    set({ razonOcupado: "plan", errorRazon: null });
    try {
      const plan = await api<PlanAdaptativo>(
        `/engagements/${id}/razonamiento/plan`, { method: "POST" });
      set({ planRazon: plan, razonOcupado: null });
      await get().cargarTrazasRazon();
    } catch (error) {
      set({ razonOcupado: null, errorRazon: (error as Error).message });
    }
  },

  async generarReflexion() {
    const id = get().casoActivo;
    if (!id || get().razonOcupado) return;
    set({ razonOcupado: "reflexion", errorRazon: null });
    try {
      const reflexion = await api<ReflexionFase>(
        `/engagements/${id}/razonamiento/reflexion`, { method: "POST" });
      set({ reflexion, razonOcupado: null });
      await get().cargarTrazasRazon();
    } catch (error) {
      set({ razonOcupado: null, errorRazon: (error as Error).message });
    }
  },

  async cargarTrazasRazon() {
    const id = get().casoActivo;
    if (!id) return;
    try {
      const r = await api<{ total: number; trazas: TrazaRazonamiento[] }>(
        `/engagements/${id}/razonamiento?limite=30`);
      set({ trazasRazon: r.trazas });
    } catch {
      set({ trazasRazon: null });
    }
  },

  // ------------------------------------------------------------------
  // Equipo: gestión admin de operadores (cuentas reales)
  // ------------------------------------------------------------------
  async cargarOperadores() {
    const lista = await api<OperadorCuenta[]>("/auth/operadores");
    set({ operadores: lista });
  },

  async crearOperadorCuenta(usuario: string, contrasena: string, rol: string,
                            tenant_id?: string) {
    await api("/auth/registrar", {
      method: "POST",
      body: JSON.stringify({ usuario, contrasena, rol, tenant_id }),
    });
    await get().cargarOperadores();
  },

  async cambiarRolOperador(usuario: string, rol: string) {
    await api("/auth/rol", { method: "POST", body: JSON.stringify({ usuario, rol }) });
    await get().cargarOperadores();
  },

  async restablecerOperador(usuario: string, nueva: string) {
    await api("/auth/restablecer", {
      method: "POST", body: JSON.stringify({ usuario, nueva }),
    });
  },

  async eliminarOperadorCuenta(usuario: string) {
    await api("/auth/eliminar", { method: "POST", body: JSON.stringify({ usuario }) });
    await get().cargarOperadores();
  },

  // ------------------------------------------------------------------
  // Diferencial de superficie (activos nuevos desde una fecha)
  // ------------------------------------------------------------------
  async calcularDif(desde: string, hasta?: string) {
    const id = get().casoActivo;
    if (!id || !desde) return;
    set({ difOcupado: true });
    try {
      const params = new URLSearchParams({ desde });
      if (hasta) params.set("hasta", hasta);
      const r = await api<DifSuperficie>(
        `/engagements/${id}/objetivos/dif?${params.toString()}`);
      set({ difSuperficie: r });
    } catch {
      set({ difSuperficie: null });
    } finally {
      set({ difOcupado: false });
    }
  },

  limpiarDif() {
    set({ difSuperficie: null });
  },

  // ------------------------------------------------------------------
  // Arsenal (v20): evasión verificada, persistencia real, AD ofensivo
  // ------------------------------------------------------------------
  async cargarArsenal() {
    const id = get().casoActivo;
    if (!id) return;
    set({ arsenalCargando: true });
    try {
      const estado = await api<EstadoArsenal>(`/engagements/${id}/arsenal`);
      set({ arsenal: estado, errorBackend: null });
    } catch (e) {
      set({ errorBackend: (e as Error).message });
    } finally {
      set({ arsenalCargando: false });
    }
  },

  async generarEvasion(datos) {
    const id = get().casoActivo;
    if (!id) return { estado: "fallo", mensaje: "sin caso activo" };
    set({ arsenalOcupado: true });
    try {
      const r = await api<Record<string, unknown>>(
        `/engagements/${id}/arsenal/evasion`,
        { method: "POST", body: JSON.stringify(datos) });
      await get().cargarArsenal();
      await get().refrescar();
      if (r.estado === "espera_aprobacion") {
        return { estado: "espera_aprobacion", mensaje: "Firma requerida: la acción está en la cola de Aprobaciones. Apruébala y vuelve a ejecutarla.", aprobacion_id: String(r.aprobacion_id ?? "") };
      }
      return { estado: "ejecutado", mensaje: "Artefacto generado y verificado contra el motor de detección", evidencia_id: String(r.evidencia_id ?? ""), resultado: r.resultado as ResultadoEvasion };
    } catch (e) {
      return { estado: "fallo", mensaje: (e as Error).message };
    } finally {
      set({ arsenalOcupado: false });
    }
  },

  async escanearArtefactoEvasion(evidenciaId) {
    const id = get().casoActivo;
    if (!id) return { estado: "fallo", mensaje: "sin caso activo" };
    set({ arsenalOcupado: true });
    try {
      const r = await api<Record<string, unknown>>(
        `/engagements/${id}/arsenal/evasion/escanear`,
        { method: "POST", body: JSON.stringify({ evidencia_id: evidenciaId }) });
      const escaneo = r.escaneo as ResultadoAccionArsenal["escaneo"];
      return { estado: "ejecutado", mensaje: escaneo?.limpio ? "Re-escaneo: LIMPIO (0 detecciones)" : `Re-escaneo: ${escaneo?.detecciones.length ?? 0} detecciones`, escaneo };
    } catch (e) {
      return { estado: "fallo", mensaje: (e as Error).message };
    } finally {
      set({ arsenalOcupado: false });
    }
  },

  async accionPersistencia(accion, datos) {
    const id = get().casoActivo;
    if (!id) return { estado: "fallo", mensaje: "sin caso activo" };
    set({ arsenalOcupado: true });
    try {
      const rutas = { implantar: "", verificar: "/verificar", retirar: "/retirar" };
      const r = await api<Record<string, unknown>>(
        `/engagements/${id}/arsenal/persistencia${rutas[accion]}`,
        { method: "POST", body: JSON.stringify(datos) });
      await get().cargarArsenal();
      await get().refrescar();
      if (r.estado === "espera_aprobacion") {
        return { estado: "espera_aprobacion", mensaje: "Firma requerida: la acción está en la cola de Aprobaciones. Apruébala y vuelve a ejecutarla.", aprobacion_id: String(r.aprobacion_id ?? "") };
      }
      const res = r.resultado as Record<string, unknown>;
      const activo = res?.["activo"];
      const detalle = accion === "implantar"
        ? (activo === true ? "Implantado y ACTIVADO con prueba real" : "Implantado: ver la prueba de activación")
        : accion === "verificar" ? "Verificación real ejecutada"
        : "Retirado con verificación de ausencia";
      return { estado: "ejecutado", mensaje: detalle, evidencia_id: String(r.evidencia_id ?? ""), resultado: res };
    } catch (e) {
      return { estado: "fallo", mensaje: (e as Error).message };
    } finally {
      set({ arsenalOcupado: false });
    }
  },

  async accionAD(datos) {
    const id = get().casoActivo;
    if (!id) return { estado: "fallo", mensaje: "sin caso activo" };
    set({ arsenalOcupado: true });
    try {
      const r = await api<Record<string, unknown>>(
        `/engagements/${id}/arsenal/ad`,
        { method: "POST", body: JSON.stringify(datos) });
      await get().cargarArsenal();
      await get().refrescar();
      if (r.estado === "espera_aprobacion") {
        return { estado: "espera_aprobacion", mensaje: "Firma requerida: la acción está en la cola de Aprobaciones. Apruébala y vuelve a ejecutarla.", aprobacion_id: String(r.aprobacion_id ?? "") };
      }
      if (r.estado === "sin_resultado") {
        const res = r.resultado as Record<string, unknown>;
        return { estado: "sin_resultado", mensaje: String(res?.["error"] ?? "sin datos reales"), resultado: res };
      }
      return { estado: "ejecutado", mensaje: "Acción AD ejecutada con datos reales", evidencia_id: String(r.evidencia_id ?? ""), resultado: r.resultado as Record<string, unknown> };
    } catch (e) {
      return { estado: "fallo", mensaje: (e as Error).message };
    } finally {
      set({ arsenalOcupado: false });
    }
  },
}));

// ---------------------------------------------------------------------------
// Exportaciones de entregables
// ---------------------------------------------------------------------------

/** Descarga el informe consolidado por el backend (Markdown o HTML). */
export async function descargarInformeBackend(
  id: string,
  formato: "md" | "html" = "md",
): Promise<string> {
  const r = await fetch(`${BASE}/engagements/${id}/informe?formato=${formato}`, {
    cache: "no-store",
    headers: _token ? { Authorization: `Bearer ${_token}` } : {},
  });
  if (!r.ok) {
    let detalle = `HTTP ${r.status}`;
    try {
      const cuerpo = await r.json();
      detalle = String(cuerpo.detail ?? cuerpo.error ?? detalle);
    } catch {
      /* ignora */
    }
    throw new Error(detalle);
  }
  const { contenido } = (await r.json()) as { contenido: string };
  const mime = formato === "html" ? "text/html;charset=utf-8" : "text/markdown;charset=utf-8";
  const blob = new Blob([contenido], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `informe_${id}_${new Date().toISOString().slice(0, 10)}.${formato}`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
  return a.download;
}

/** Descarga la copia de custodia/archivo del caso completo (JSON real). */
export async function descargarCustodiaCaso(id: string): Promise<string> {
  const r = await fetch(`${BASE}/engagements/${id}/exportar`, {
    cache: "no-store",
    headers: _token ? { Authorization: `Bearer ${_token}` } : {},
  });
  if (!r.ok) {
    let detalle = `HTTP ${r.status}`;
    try {
      const cuerpo = await r.json();
      detalle = String(cuerpo.detail ?? cuerpo.error ?? detalle);
    } catch {
      /* ignora */
    }
    throw new Error(detalle);
  }
  const contenido = await r.text();
  const blob = new Blob([contenido], { type: "application/json;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `custodia_${id}_${new Date().toISOString().slice(0, 10)}.json`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
  return a.download;
}

/** Descarga el respaldo de archivo del caso (ZIP real: custodia + informes). */
export async function descargarRespaldoCaso(id: string): Promise<string> {
  const r = await fetch(`${BASE}/engagements/${id}/respaldo`, {
    cache: "no-store",
    headers: _token ? { Authorization: `Bearer ${_token}` } : {},
  });
  if (!r.ok) {
    let detalle = `HTTP ${r.status}`;
    try {
      const cuerpo = await r.json();
      detalle = String(cuerpo.detail ?? cuerpo.error ?? detalle);
    } catch {
      /* ignora */
    }
    throw new Error(detalle);
  }
  const contenido = await r.blob();
  const url = URL.createObjectURL(contenido);
  const a = document.createElement("a");
  a.href = url;
  a.download = `respaldo_${id}_${new Date().toISOString().slice(0, 10)}.zip`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
  return a.download;
}

/** Descarga el CSV real de hallazgos generado por el backend. */
export async function descargarCSVHallazgos(id: string): Promise<void> {
  const r = await fetch(`${BASE}/engagements/${id}/hallazgos.csv`, {
    cache: "no-store",
    headers: _token ? { Authorization: `Bearer ${_token}` } : {},
  });
  if (!r.ok) {
    let detalle = `HTTP ${r.status}`;
    try {
      const cuerpo = await r.json();
      detalle = String(cuerpo.detail ?? cuerpo.error ?? detalle);
    } catch {
      /* ignora */
    }
    throw new Error(detalle);
  }
  const contenido = await r.text();
  const blob = new Blob([contenido], { type: "text/csv;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `hallazgos_${id}_${new Date().toISOString().slice(0, 10)}.csv`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

/** Descarga la capa MITRE ATT&CK Navigator del caso (JSON importable, real). */
export async function descargarCapaNavigator(id: string): Promise<string> {
  const r = await fetch(`${BASE}/engagements/${id}/attack-navigator`, {
    cache: "no-store",
    headers: _token ? { Authorization: `Bearer ${_token}` } : {},
  });
  if (!r.ok) {
    let detalle = `HTTP ${r.status}`;
    try {
      const cuerpo = await r.json();
      detalle = String(cuerpo.detail ?? cuerpo.error ?? detalle);
    } catch {
      /* ignora */
    }
    throw new Error(detalle);
  }
  const contenido = await r.text();
  const blob = new Blob([contenido], { type: "application/json;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `capa_attack_${id}_${new Date().toISOString().slice(0, 10)}.json`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
  return a.download;
}

/** Descarga la matriz de cobertura ATT&CK entre campañas (CSV, v16). */
export async function descargarCoberturaAttackCsv(): Promise<string> {
  const r = await fetch(`${BASE}/analitica/cobertura-attack.csv`, {
    cache: "no-store",
    headers: _token ? { Authorization: `Bearer ${_token}` } : {},
  });
  if (!r.ok) {
    let detalle = `HTTP ${r.status}`;
    try {
      const cuerpo = await r.json();
      detalle = String(cuerpo.detail ?? cuerpo.error ?? detalle);
    } catch {
      /* ignora */
    }
    throw new Error(detalle);
  }
  const contenido = await r.text();
  const blob = new Blob([contenido], { type: "text/csv;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `cobertura_attack_${new Date().toISOString().slice(0, 10)}.csv`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
  return a.download;
}

/** Playbook completo de una técnica (progressive disclosure bajo demanda). */
export async function obtenerDetalleTecnica(nombre: string): Promise<import("./tipos").TecnicaDetalle> {
  return api<import("./tipos").TecnicaDetalle>(`/skills/${encodeURIComponent(nombre)}`);
}

/** Descarga el paquete purple team del caso (informe de detección + Sigma). */
export async function descargarPaquetePurpleTeam(id: string): Promise<string> {
  const r = await fetch(`${BASE}/engagements/${id}/purple-team.zip`, {
    cache: "no-store",
    headers: _token ? { Authorization: `Bearer ${_token}` } : {},
  });
  if (!r.ok) {
    let detalle = `HTTP ${r.status}`;
    try {
      const cuerpo = await r.json();
      detalle = String(cuerpo.detail ?? cuerpo.error ?? detalle);
    } catch {
      /* ignora */
    }
    throw new Error(detalle);
  }
  const blob = await r.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `purple_${id}_${new Date().toISOString().slice(0, 10)}.zip`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
  return a.download;
}

/** Copia de seguridad completa del sistema (solo admin): BDs + manifiesto SHA-256. */
export async function descargarRespaldoCompleto(): Promise<string> {
  const r = await fetch(`${BASE}/admin/respaldo-completo`, {
    cache: "no-store",
    headers: _token ? { Authorization: `Bearer ${_token}` } : {},
  });
  if (!r.ok) {
    let detalle = `HTTP ${r.status}`;
    try {
      const cuerpo = await r.json();
      detalle = String(cuerpo.detail ?? cuerpo.error ?? detalle);
    } catch {
      /* ignora */
    }
    throw new Error(detalle);
  }
  const blob = await r.blob();
  const url = URL.createObjectURL(blob);
  const marca = new Date().toISOString().slice(0, 19).replace(/[:T]/g, "");
  const a = document.createElement("a");
  a.href = url;
  a.download = `orquesta_respaldo_${marca}.zip`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
  return a.download;
}
