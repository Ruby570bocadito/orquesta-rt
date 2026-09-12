"use client";

/**
 * OrquestaRT — Consola del operador (shell).
 *
 * Sidebar (escritorio) + barra superior + navegación móvil. Todas las
 * vistas se alimentan del estado EN VIVO del orquestador Python vía
 * /api/orchestrator/* (store.ts). Incluye ejecución de fases con contexto,
 * paleta de comandos (Ctrl/Cmd+K), exportación del informe del backend y
 * parada de emergencia del ROE.
 */

import { useEffect, useMemo, useRef, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  LayoutDashboard, Workflow, ShieldQuestion, FileWarning, FileLock2, Brain,
  Coins, History, Radio, Pause, Play, RotateCcw, ShieldCheck, Menu,
  Crosshair, Download, Command, OctagonX, SlidersHorizontal, FolderKanban,
  CircleAlert, Cable, LogOut, FileText, Sparkles, Users, Archive, Database,
  FileArchive, Swords, Map, Target, GraduationCap, Grid3X3, ChevronDown, Bomb,
  GitBranch,
} from "lucide-react";
import { toast } from "@/hooks/use-toast";
import {
  AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent,
  AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { VistaPanel } from "@/components/consola/panel";
import { VistaPipeline } from "@/components/consola/pipeline";
import { VistaAprobaciones } from "@/components/consola/aprobaciones";
import { VistaHallazgos, VistaEvidencias } from "@/components/consola/datos";
import { VistaMemoria } from "@/components/consola/memoria";
import { VistaIntegraciones } from "@/components/consola/integraciones";
import { VistaCoste, VistaCronologia } from "@/components/consola/analitica";
import { VistaCobertura } from "@/components/consola/cobertura";
import { VistaObjetivos } from "@/components/consola/objetivos";
import { VistaArsenal } from "@/components/consola/arsenal";
import { VistaCasos } from "@/components/consola/casos";
import { VistaCopiloto } from "@/components/consola/copiloto";
import { VistaRazonamiento } from "@/components/consola/razonamiento";
import { DialogoHigiene } from "@/components/consola/higiene";
import { VistaEquipo } from "@/components/consola/equipo";
import { VistaTecnicas } from "@/components/consola/tecnicas";
import { VistaCadenas } from "@/components/consola/cadenas";
import { PaletaComandos, AccionPaleta } from "@/components/consola/paleta";
import { Insignia } from "@/components/consola/ui";
import { Acceso } from "@/components/consola/acceso";
import { usarConsola, descargarInformeBackend, descargarCustodiaCaso, descargarRespaldoCaso, descargarCapaNavigator, descargarPaquetePurpleTeam, descargarCoberturaAttackCsv } from "@/lib/store";
import { DialogEjecutarFase } from "@/components/consola/dialogo-fase";
import { ETIQUETA_FASE, formatoCoste, formatoTokens } from "@/lib/tipos";
import { cn } from "@/lib/utils";

type Pestaña =
  | "casos" | "panel" | "objetivos" | "pipeline" | "aprobaciones" | "hallazgos"
  | "evidencias" | "memoria" | "copiloto" | "razonamiento" | "tecnicas"
  | "integraciones" | "cobertura" | "coste" | "cronologia" | "equipo"
  | "arsenal" | "cadenas";

type DefPestaña = { id: Pestaña; etiqueta: string; icono: React.ComponentType<{ className?: string }> };

/**
 * Navegación agrupada: 16 destinos ordenados en 4 secciones con sentido
 * operativo. La paleta de comandos deriva de esta misma estructura (una
 * única fuente de verdad).
 */
const GRUPOS_NAVEGACION: { titulo: string; pestañas: DefPestaña[] }[] = [
  {
    titulo: "Campaña",
    pestañas: [
      { id: "casos", etiqueta: "Casos", icono: FolderKanban },
      { id: "panel", etiqueta: "Panel", icono: LayoutDashboard },
      { id: "objetivos", etiqueta: "Objetivos", icono: Crosshair },
      { id: "arsenal", etiqueta: "Arsenal", icono: Bomb },
      { id: "pipeline", etiqueta: "Pipeline", icono: Workflow },
      { id: "aprobaciones", etiqueta: "Aprobaciones", icono: ShieldQuestion },
      { id: "cronologia", etiqueta: "Cronología", icono: History },
    ],
  },
  {
    titulo: "Resultados",
    pestañas: [
      { id: "hallazgos", etiqueta: "Hallazgos", icono: FileWarning },
      { id: "evidencias", etiqueta: "Evidencias", icono: FileLock2 },
      { id: "cobertura", etiqueta: "Cobertura ATT&CK", icono: Grid3X3 },
      { id: "tecnicas", etiqueta: "Técnicas", icono: Swords },
    ],
  },
  {
    titulo: "Inteligencia IA",
    pestañas: [
      { id: "copiloto", etiqueta: "Copiloto IA", icono: Sparkles },
      { id: "razonamiento", etiqueta: "Razonamiento", icono: Brain },
      { id: "cadenas", etiqueta: "Cadenas", icono: GitBranch },
      { id: "coste", etiqueta: "Coste IA", icono: Coins },
    ],
  },
  {
    titulo: "Sistema",
    pestañas: [
      { id: "memoria", etiqueta: "Memoria", icono: Database },
      { id: "integraciones", etiqueta: "Integraciones", icono: Cable },
      { id: "equipo", etiqueta: "Equipo", icono: Users },
    ],
  },
];

const PESTAÑAS: DefPestaña[] = GRUPOS_NAVEGACION.flatMap((g) => g.pestañas);

/**
 * Vistas de DESPLIEGUE, no del caso: funcionan sin engagement activo.
 * Cobertura es la analítica agregada ENTRE campañas; Técnicas es la
 * biblioteca del despliegue; Integraciones y Equipo son configuración
 * global. El resto exige un caso activo (son vistas del engagement).
 */
const PESTAÑAS_GLOBALES: ReadonlySet<Pestaña> = new Set<Pestaña>([
  "casos", "cobertura", "tecnicas", "integraciones", "equipo",
]);

export function Consola() {
  const [pestaña, setPestaña] = useState<Pestaña>("panel");
  const [menuMovil, setMenuMovil] = useState(false);
  const [paletaAbierta, setPaletaAbierta] = useState(false);
  const [confirmarParada, setConfirmarParada] = useState(false);
  const [ejecutarFase, setEjecutarFase] = useState(false);
  const estadoAuth = usarConsola((s) => s.estadoAuth);
  const sesion = usarConsola((s) => s.sesion);
  const iniciarAuth = usarConsola((s) => s.iniciarAuth);
  const iniciado = usarConsola((s) => s.iniciado);
  const pendientes = usarConsola((s) => s.aprobaciones.filter((a) => a.estado === "pendiente").length);
  const sinCaso = usarConsola((s) => !s.casoActivo);
  const paradaActiva = usarConsola((s) => s.engagement?.roe.parada_emergencia ?? false);

  // Arranque: control de acceso (bootstrap/login) y luego cliente en vivo
  useEffect(() => {
    iniciarAuth().catch(() => undefined);
  }, [iniciarAuth]);

  // Reacciones al cambio de estado: aviso de firmas pendientes y decisiones
  useEffect(() => {
    return usarConsola.subscribe((estado, previo) => {
      const ahora = estado.aprobaciones.filter((a) => a.estado === "pendiente").length;
      const antes = previo.aprobaciones.filter((a) => a.estado === "pendiente").length;
      if (ahora > antes) {
        setPestaña((actual) => (actual === "panel" ? "aprobaciones" : actual));
        const nueva = estado.aprobaciones.find(
          (a) => a.estado === "pendiente" && !previo.aprobaciones.some((p) => p.id === a.id),
        );
        if (nueva) {
          toast({
            title: "El boundary detiene el ciclo",
            description: `Requiere tu firma: ${nueva.titulo}`,
          });
        }
      }
      const decidida = estado.aprobaciones.find(
        (a) => a.estado !== "pendiente" &&
          previo.aprobaciones.some((p) => p.id === a.id && p.estado === "pendiente"),
      );
      if (decidida) {
        toast({
          title: decidida.estado === "aprobada" ? "Acción autorizada" : "Acción rechazada",
          description: decidida.titulo,
        });
      }
      if (
        estado.engagement?.estado_fase === "completada" &&
        estado.engagement.fase_actual === "cierre" &&
        !(previo.engagement?.fase_actual === "cierre" && previo.engagement?.estado_fase === "completada")
      ) {
        toast({ title: "Engagement completado", description: "Informe consolidado y cadena de custodia verificada" });
      }
    });
  }, []);

  const exportarInforme = async (formato: "md" | "html" = "md") => {
    const id = usarConsola.getState().casoActivo;
    if (!id) return;
    try {
      const nombre = await descargarInformeBackend(id, formato);
      toast({
        title: `Informe ${formato.toUpperCase()} exportado`,
        description: `${nombre} · generado por el backend con cadena de custodia`,
      });
    } catch (e) {
      toast({
        title: "No se pudo generar el informe",
        description: (e as Error).message,
        variant: "destructive",
      });
    }
  };

  const exportarCustodia = async () => {
    const id = usarConsola.getState().casoActivo;
    if (!id) return;
    try {
      const nombre = await descargarCustodiaCaso(id);
      toast({
        title: "Custodia exportada",
        description: `${nombre} · caso completo con verificación de cadena incluida`,
      });
    } catch (e) {
      toast({
        title: "No se pudo exportar la custodia",
        description: (e as Error).message,
        variant: "destructive",
      });
    }
  };

  const exportarRespaldo = async () => {
    const id = usarConsola.getState().casoActivo;
    if (!id) return;
    try {
      const nombre = await descargarRespaldoCaso(id);
      toast({
        title: "Respaldo del caso generado",
        description: `${nombre} · custodia JSON + informes MD/HTML con manifiesto`,
      });
    } catch (e) {
      toast({
        title: "No se pudo generar el respaldo",
        description: (e as Error).message,
        variant: "destructive",
      });
    }
  };

  const exportarNavigator = async () => {
    const id = usarConsola.getState().casoActivo;
    if (!id) return;
    try {
      const nombre = await descargarCapaNavigator(id);
      toast({
        title: "Capa MITRE ATT&CK exportada",
        description: `${nombre} · importable en el ATT&CK Navigator (solo técnicas observadas o intentadas)`,
      });
    } catch (e) {
      toast({
        title: "No se pudo generar la capa ATT&CK",
        description: (e as Error).message,
        variant: "destructive",
      });
    }
  };

  const exportarPurpleTeam = async () => {
    const id = usarConsola.getState().casoActivo;
    if (!id) return;
    try {
      const nombre = await descargarPaquetePurpleTeam(id);
      toast({
        title: "Paquete purple team exportado",
        description: `${nombre} · resultados de detección del blue team + esqueletos Sigma`,
      });
    } catch (e) {
      toast({
        title: "No se pudo generar el paquete purple team",
        description: (e as Error).message,
        variant: "destructive",
      });
    }
  };

  const exportarCoberturaCsv = async () => {
    try {
      const nombre = await descargarCoberturaAttackCsv();
      toast({
        title: "Matriz de cobertura ATT&CK exportada",
        description: `${nombre} · técnica × campaña, todas las campañas del despliegue`,
      });
    } catch (e) {
      toast({
        title: "No se pudo exportar la matriz de cobertura",
        description: (e as Error).message,
        variant: "destructive",
      });
    }
  };

  const paradaEmergencia = async (activar: boolean) => {
    try {
      await usarConsola.getState().paradaEmergencia(activar);
      toast({
        title: activar ? "PARADA DE EMERGENCIA ACTIVADA" : "Parada desactivada",
        description: activar
          ? "Toda tool call está denegada por el boundary hasta que la desactive."
          : "El boundary vuelve a evaluar acciones según el ROE.",
        variant: activar ? "destructive" : "default",
      });
    } catch (e) {
      toast({ title: "Error en la parada de emergencia", description: (e as Error).message, variant: "destructive" });
    }
  };

  const avanzar = () => setEjecutarFase(true);

  // Acciones de la paleta de comandos
  const acciones: AccionPaleta[] = useMemo(() => {
    return [
      ...PESTAÑAS.map((p) => ({
        id: `nav-${p.id}`,
        etiqueta: `Ir a ${p.etiqueta}`,
        icono: p.icono,
        grupo: "navegacion" as const,
        ejecutar: () => setPestaña(p.id),
      })),
      {
        id: "op-avanzar", etiqueta: "Ejecutar fase actual del orquestador", icono: Play,
        grupo: "operacion", ejecutar: avanzar,
      },
      {
        id: "op-pausa", etiqueta: "Pausar / reanudar sondeo en vivo", icono: Pause, grupo: "operacion",
        ejecutar: () => usarConsola.getState().alternarPausa(),
      },
      {
        id: "op-sync", etiqueta: "Sincronizar ahora", icono: RotateCcw, grupo: "operacion",
        ejecutar: () => usarConsola.getState().refrescar().catch(() => undefined),
      },
      {
        id: "exp-informe", etiqueta: "Exportar informe del engagement (Markdown)", icono: Download,
        grupo: "entregables", ejecutar: () => exportarInforme("md"),
      },
      {
        id: "exp-informe-html", etiqueta: "Exportar informe imprimible (HTML)", icono: FileText,
        grupo: "entregables", ejecutar: () => exportarInforme("html"),
      },
      {
        id: "exp-custodia", etiqueta: "Exportar custodia del caso (JSON)", icono: Archive,
        grupo: "entregables", ejecutar: () => exportarCustodia(),
      },
      {
        id: "exp-respaldo", etiqueta: "Respaldo de archivo del caso (ZIP)", icono: FileArchive,
        grupo: "entregables", ejecutar: () => exportarRespaldo(),
      },
      {
        id: "exp-navigator", etiqueta: "Exportar capa MITRE ATT&CK (Navigator JSON)", icono: Map,
        grupo: "entregables", ejecutar: () => exportarNavigator(),
      },
      {
        id: "exp-purple", etiqueta: "Exportar paquete purple team (detección + Sigma)", icono: GraduationCap,
        grupo: "entregables", ejecutar: () => exportarPurpleTeam(),
      },
      {
        id: "exp-cobertura-csv", etiqueta: "Exportar matriz de cobertura ATT&CK entre campañas (CSV)", icono: Grid3X3,
        grupo: "entregables", ejecutar: () => exportarCoberturaCsv(),
      },
      {
        id: "seg-parada", etiqueta: "PARADA DE EMERGENCIA (kill switch ROE)", icono: OctagonX,
        grupo: "seguridad", peligrosa: true,
        ejecutar: () => setConfirmarParada(true),
      },
    ];
  }, []);

  const elegir = (p: Pestaña) => {
    setPestaña(p);
    setMenuMovil(false);
  };

  // Sin sesión autenticada la consola no renderiza NADA: puerta de entrada.
  // (colocado tras TODOS los hooks: el orden no puede cambiar entre renders)
  if (estadoAuth !== "autenticado" || !sesion) {
    if (estadoAuth === "cargando") {
      return (
        <div className="flex min-h-screen items-center justify-center bg-ink">
          <div className="text-center">
            <div className="mx-auto mb-4 h-7 w-7 animate-spin rounded-full border-2 border-line border-t-crimson-bright" />
            <p className="font-mono text-xs text-zinc-500">Estableciendo sesión con el orquestador…</p>
          </div>
        </div>
      );
    }
    return <Acceso />;
  }

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      transition={{ duration: 0.35 }}
      className="flex min-h-screen bg-ink"
    >
      {/* ─── Sidebar (escritorio) ─── */}
      <aside className="fixed inset-y-0 left-0 z-40 hidden w-60 flex-col border-r border-line bg-sidebar lg:flex">
        <Marca />

        <nav className="flex-1 overflow-y-auto px-3 py-4" aria-label="Secciones de la consola">
          {GRUPOS_NAVEGACION.map((grupo, gi) => (
            <div key={grupo.titulo} className={gi > 0 ? "mt-5" : undefined}>
              <p className="mb-1 px-3 font-mono text-[9px] font-semibold uppercase tracking-[0.2em] text-zinc-600">
                {grupo.titulo}
              </p>
              <div className="space-y-0.5">
                {grupo.pestañas.map((p) => (
                  <ElementoNav
                    key={p.id}
                    def={p}
                    activa={pestaña === p.id}
                    insignia={p.id === "aprobaciones" && pendientes > 0 ? pendientes : undefined}
                    onClick={() => elegir(p.id)}
                  />
                ))}
              </div>
            </div>
          ))}
        </nav>

        <div className="space-y-2 border-t border-line p-3">
          <button
            onClick={() => setPaletaAbierta(true)}
            className="flex w-full items-center justify-between rounded-lg border border-line bg-panel px-3 py-2 text-[11px] text-zinc-400 transition-colors hover:bg-raised hover:text-zinc-200"
            aria-label="Abrir paleta de comandos"
          >
            <span className="flex items-center gap-1.5">
              <Command className="h-3.5 w-3.5" /> Paleta de comandos
            </span>
            <kbd className="rounded border border-line bg-raised px-1 font-mono text-[9px] text-zinc-500">Ctrl K</kbd>
          </button>
          <EstadoBackend />
        </div>
      </aside>

      {/* ─── Columna principal ─── */}
      <div className="flex min-h-screen w-full flex-1 flex-col lg:pl-60">
        <BarraSuperior
          onMenu={() => setMenuMovil((v) => !v)}
          onPaleta={() => setPaletaAbierta(true)}
          onParada={() => setConfirmarParada(true)}
          onAvanzar={avanzar}
          exportadores={{
            informeMd: () => exportarInforme("md"),
            informeHtml: () => exportarInforme("html"),
            custodia: exportarCustodia,
            respaldo: exportarRespaldo,
            navigator: exportarNavigator,
            purple: exportarPurpleTeam,
          }}
        />

        {/* Navegación móvil */}
        <AnimatePresence>
          {menuMovil && (
            <motion.nav
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: "auto" }}
              exit={{ opacity: 0, height: 0 }}
              className="sticky top-[61px] z-30 overflow-hidden border-b border-line bg-ink/95 backdrop-blur-xl lg:hidden"
              aria-label="Menú móvil de la consola"
            >
              <div className="grid grid-cols-2 gap-x-2 gap-y-0.5 p-3">
                {GRUPOS_NAVEGACION.map((grupo) => (
                  <div key={grupo.titulo} className="col-span-2">
                    <p className="mb-1 mt-2 px-1 font-mono text-[9px] font-semibold uppercase tracking-[0.2em] text-zinc-600 first:mt-0">
                      {grupo.titulo}
                    </p>
                    <div className="grid grid-cols-2 gap-1">
                      {grupo.pestañas.map((p) => (
                        <ElementoNav
                          key={p.id}
                          def={p}
                          activa={pestaña === p.id}
                          insignia={p.id === "aprobaciones" && pendientes > 0 ? pendientes : undefined}
                          onClick={() => elegir(p.id)}
                          variante="movil"
                        />
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </motion.nav>
          )}
        </AnimatePresence>

        {/* Contenido */}
        <main className="mx-auto w-full max-w-6xl flex-1 px-4 py-6 sm:px-6 lg:px-8">
          <AnimatePresence mode="wait">
            {!iniciado ? (
              <motion.div key="carga" exit={{ opacity: 0 }} className="flex h-72 items-center justify-center">
                <div className="text-center">
                  <div className="mx-auto mb-4 h-7 w-7 animate-spin rounded-full border-2 border-line border-t-crimson-bright" />
                  <p className="font-mono text-xs text-zinc-500">Conectando con el orquestador…</p>
                </div>
              </motion.div>
            ) : sinCaso && !PESTAÑAS_GLOBALES.has(pestaña) ? (
              <motion.div
                key="sin-caso"
                initial={{ opacity: 0, y: 8 }}
                animate={{ opacity: 1, y: 0 }}
                className="flex h-72 flex-col items-center justify-center gap-4 text-center"
              >
                <FolderKanban className="h-8 w-8 text-zinc-600" />
                <div>
                  <p className="text-sm font-medium text-zinc-300">Sin caso activo</p>
                  <p className="mt-1 max-w-sm text-xs leading-relaxed text-zinc-500">
                    Crea un engagement con su ROE (alcance, técnicas prohibidas, techo de ruido)
                    para empezar a operar. El boundary no ejecuta nada fuera del alcance firmado.
                  </p>
                </div>
                <button
                  onClick={() => elegir("casos")}
                  className="rounded-lg bg-crimson px-4 py-2 text-xs font-semibold text-white transition-colors hover:bg-crimson-bright"
                >
                  Ir a Casos
                </button>
              </motion.div>
            ) : (
              <motion.div
                key={pestaña}
                initial={{ opacity: 0, y: 8 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -6 }}
                transition={{ duration: 0.22, ease: "easeOut" }}
              >
                {pestaña === "casos" && <VistaCasos />}
                {pestaña === "panel" && <VistaPanel />}
                {pestaña === "cobertura" && <VistaCobertura />}
                {pestaña === "objetivos" && <VistaObjetivos />}
                {pestaña === "arsenal" && <VistaArsenal />}
                {pestaña === "pipeline" && <VistaPipeline onEjecutarFase={avanzar} />}
                {pestaña === "aprobaciones" && <VistaAprobaciones />}
                {pestaña === "hallazgos" && <VistaHallazgos />}
                {pestaña === "evidencias" && <VistaEvidencias />}
                {pestaña === "memoria" && <VistaMemoria />}
                {pestaña === "copiloto" && <VistaCopiloto />}
                {pestaña === "razonamiento" && <VistaRazonamiento />}
                {pestaña === "cadenas" && <VistaCadenas />}
                {pestaña === "tecnicas" && <VistaTecnicas />}
                {pestaña === "integraciones" && <VistaIntegraciones />}
                {pestaña === "coste" && <VistaCoste />}
                {pestaña === "cronologia" && <VistaCronologia />}
                {pestaña === "equipo" && <VistaEquipo />}
              </motion.div>
            )}
          </AnimatePresence>
        </main>

        {/* Pie */}
        <footer className="mt-auto border-t border-line">
          <div className="mx-auto flex max-w-6xl flex-wrap items-center justify-between gap-2 px-4 py-4 font-mono text-[10px] text-zinc-600 sm:px-6 lg:px-8">
            <p>
              <span className="font-semibold text-zinc-500">OrquestaRT</span> · uso exclusivo en
              engagements autorizados con ROE firmado
            </p>
            <p>núcleo Python/LangGraph + MCP · consola Next.js · on-prem</p>
          </div>
        </footer>
      </div>

      {/* Paleta de comandos (Ctrl/Cmd+K) */}
      <PaletaComandos abierta={paletaAbierta} onOpenChange={setPaletaAbierta} acciones={acciones} />

      {/* Diálogo: ejecutar fase con contexto de operador */}
      <DialogEjecutarFase
        abierta={ejecutarFase}
        onOpenChange={setEjecutarFase}
        onHecho={(resumen) => {
          toast({
            title: "Fase ejecutada por el orquestador",
            description: resumen,
          });
        }}
      />

      {/* Parada de emergencia: activación y desactivación según estado */}
      <AlertDialog open={confirmarParada} onOpenChange={setConfirmarParada}>
        <AlertDialogContent className="border-crimson/40 bg-panel text-zinc-200">
          <AlertDialogHeader>
            <AlertDialogTitle className="flex items-center gap-2 text-base">
              <OctagonX className="h-5 w-5 text-crimson-bright" />
              {paradaActiva ? "Desactivar parada de emergencia" : "Parada de emergencia"}
            </AlertDialogTitle>
            <AlertDialogDescription className="text-xs leading-relaxed text-zinc-400">
              {paradaActiva
                ? "La parada del ROE está ACTIVA: el boundary deniega toda tool call. Al desactivarla, el boundary vuelve a evaluar cada acción según el ROE firmado. El cambio queda registrado en la auditoría inmutable."
                : "Activa el kill switch del ROE: el boundary denegará TODA tool call del agente de inmediato, incluso las ya aprobadas. La acción queda registrada en la auditoría inmutable como decisión humana. Podrás desactivarla desde esta misma barra cuando lo decidas."}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel className="border-line bg-transparent text-zinc-400 hover:bg-raised hover:text-zinc-200">
              Cancelar
            </AlertDialogCancel>
            <AlertDialogAction
              onClick={() => paradaEmergencia(!paradaActiva)}
              className={paradaActiva
                ? "border border-amber-400/40 bg-amber-400/10 text-amber-200 hover:bg-amber-400/20"
                : "bg-crimson text-white hover:bg-crimson-bright"}
            >
              {paradaActiva ? "Desactivar y reanudar" : "Sí, detener todo"}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </motion.div>
  );
}

/** Elemento de navegación compartido por el sidebar (escritorio) y el menú móvil. */
function ElementoNav({
  def: p,
  activa,
  insignia,
  onClick,
  variante = "escritorio",
}: {
  def: DefPestaña;
  activa: boolean;
  insignia?: number;
  onClick: () => void;
  variante?: "escritorio" | "movil";
}) {
  if (variante === "movil") {
    return (
      <button
        onClick={onClick}
        className={cn(
          "flex items-center gap-2 rounded-lg px-3 py-2.5 text-[13px] font-medium",
          activa ? "bg-raised text-zinc-100" : "text-zinc-500 hover:bg-raised/60",
        )}
      >
        <p.icono className={cn("h-4 w-4 shrink-0", activa && "text-crimson-bright")} />
        <span className="truncate">{p.etiqueta}</span>
        {insignia !== undefined && (
          <span className="ml-auto flex h-4.5 min-w-4.5 items-center justify-center rounded-full bg-amber-400 px-1 text-[10px] font-bold text-zinc-950">
            {insignia}
          </span>
        )}
      </button>
    );
  }
  return (
    <button
      onClick={onClick}
      aria-current={activa ? "page" : undefined}
      className={cn(
        "relative flex w-full items-center gap-2.5 rounded-lg px-3 py-2 text-[13px] font-medium transition-colors",
        activa ? "text-zinc-100" : "text-zinc-500 hover:bg-raised hover:text-zinc-300",
      )}
    >
      {activa && (
        <motion.span
          layoutId="nav-activa"
          className="absolute inset-0 rounded-lg border border-line bg-raised"
          transition={{ type: "spring", bounce: 0.18, duration: 0.45 }}
        />
      )}
      <p.icono className={cn("relative h-4 w-4", activa && "text-crimson-bright")} />
      <span className="relative">{p.etiqueta}</span>
      {insignia !== undefined && (
        <span className="relative ml-auto flex h-4.5 min-w-4.5 items-center justify-center rounded-full bg-amber-400 px-1 text-[10px] font-bold text-zinc-950">
          {insignia}
        </span>
      )}
    </button>
  );
}

/**
 * Menú consolidado de exportaciones del caso activo: un solo botón en la
 * barra en lugar de cuatro, y con la custodia y el respaldo visibles (antes
 * solo estaban en la paleta de comandos).
 */
function MenuExportar({
  deshabilitado,
  exportadores,
}: {
  deshabilitado: boolean;
  exportadores: Exportadores;
}) {
  const [abierta, setAbierta] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!abierta) return;
    const fuera = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setAbierta(false);
    };
    const escape = (e: KeyboardEvent) => {
      if (e.key === "Escape") setAbierta(false);
    };
    document.addEventListener("mousedown", fuera);
    document.addEventListener("keydown", escape);
    return () => {
      document.removeEventListener("mousedown", fuera);
      document.removeEventListener("keydown", escape);
    };
  }, [abierta]);

  const items: { id: string; etiqueta: string; detalle: string; icono: React.ComponentType<{ className?: string }>; ejecutar: () => void }[] = [
    { id: "md", etiqueta: "Informe Markdown", detalle: "informe del engagement generado por el backend", icono: Download, ejecutar: exportadores.informeMd },
    { id: "html", etiqueta: "Informe HTML", detalle: "versión imprimible para entregar al cliente", icono: FileText, ejecutar: exportadores.informeHtml },
    { id: "navigator", etiqueta: "Capa ATT&CK Navigator", detalle: "JSON importable · solo técnicas observadas o intentadas", icono: Map, ejecutar: exportadores.navigator },
    { id: "purple", etiqueta: "Paquete purple team", detalle: "detección del blue team + esqueletos Sigma", icono: Target, ejecutar: exportadores.purple },
    { id: "custodia", etiqueta: "Custodia del caso", detalle: "JSON con cadena de custodia verificada", icono: Archive, ejecutar: exportadores.custodia },
    { id: "respaldo", etiqueta: "Respaldo del caso", detalle: "ZIP: custodia + informes MD/HTML con manifiesto", icono: FileArchive, ejecutar: exportadores.respaldo },
  ];

  return (
    <div ref={ref} className="relative">
      <button
        onClick={() => setAbierta((v) => !v)}
        disabled={deshabilitado}
        aria-expanded={abierta}
        aria-haspopup="menu"
        className="flex h-8 items-center gap-1.5 rounded-lg border border-line bg-panel px-2.5 text-xs font-medium text-zinc-300 transition-colors hover:bg-raised hover:text-zinc-100 disabled:cursor-not-allowed disabled:opacity-40"
        aria-label="Exportar entregables del caso"
        title="Exportar entregables del caso"
      >
        <Download className="h-3.5 w-3.5" />
        <span className="hidden sm:inline">Exportar</span>
        <ChevronDown className={cn("h-3 w-3 transition-transform", abierta && "rotate-180")} />
      </button>
      {abierta && (
        <div
          role="menu"
          aria-label="Entregables exportables"
          className="absolute right-0 top-9 z-50 w-72 overflow-hidden rounded-xl border border-line bg-panel shadow-[0_12px_32px_rgba(0,0,0,0.5)]"
        >
          <p className="border-b border-line px-3 py-2 font-mono text-[9px] font-semibold uppercase tracking-[0.2em] text-zinc-600">
            Entregables del caso
          </p>
          {items.map((item) => (
            <button
              key={item.id}
              role="menuitem"
              onClick={() => {
                setAbierta(false);
                item.ejecutar();
              }}
              className="flex w-full items-start gap-2.5 px-3 py-2.5 text-left transition-colors hover:bg-raised"
            >
              <item.icono className="mt-0.5 h-3.5 w-3.5 shrink-0 text-zinc-500" />
              <span className="min-w-0">
                <span className="block text-[12px] font-medium text-zinc-200">{item.etiqueta}</span>
                <span className="block text-[11px] leading-snug text-zinc-500">{item.detalle}</span>
              </span>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

function Marca() {
  return (
    <div className="flex items-center justify-between border-b border-line px-4 py-4">
      <div className="flex items-center gap-2.5">
        <span className="flex h-8 w-8 items-center justify-center rounded-lg border border-crimson/40 bg-crimson/10">
          <Radio className="h-4 w-4 text-crimson-bright" aria-hidden />
        </span>
        <span className="text-[15px] font-semibold tracking-tight text-zinc-100">
          Orquesta<span className="text-crimson-bright">RT</span>
        </span>
      </div>
      <span className="rounded border border-line-strong px-1.5 py-0.5 font-mono text-[9px] uppercase tracking-[0.14em] text-zinc-500">
        consola
      </span>
    </div>
  );
}

/** Caja de estado de conexión del sidebar. */
function EstadoBackend() {
  const errorBackend = usarConsola((s) => s.errorBackend);
  const ultimaSync = usarConsola((s) => s.ultimaSync);
  const corriendo = usarConsola((s) => s.corriendo);
  const fuenteViva = usarConsola((s) => s.fuenteViva);
  return (
    <div className="rounded-lg border border-line bg-panel p-3">
      <p className="flex items-center gap-1.5 font-mono text-[9px] uppercase tracking-[0.16em] text-zinc-500">
        <span className={cn(
          "h-1.5 w-1.5 rounded-full",
          errorBackend ? "bg-red-400" : corriendo ? "bg-emerald-400" : "bg-amber-400",
        )} />
        {errorBackend ? "orquestador desconectado"
          : corriendo ? (fuenteViva === "sse" ? "en vivo · SSE" : "en vivo · sondeo")
          : "sondeo pausado"}
      </p>
      <p className="mt-1.5 text-[11px] leading-relaxed text-zinc-600">
        {errorBackend
          ? `No hay conexión con la API Python: ${errorBackend.slice(0, 80)}`
          : ultimaSync
            ? `Última sincronización ${new Date(ultimaSync).toLocaleTimeString("es-ES")}`
            : "Esperando la primera sincronización…"}
      </p>
    </div>
  );
}

type Exportadores = {
  informeMd: () => void;
  informeHtml: () => void;
  custodia: () => void;
  respaldo: () => void;
  navigator: () => void;
  purple: () => void;
};

function BarraSuperior({
  onMenu, onPaleta, onParada, onAvanzar, exportadores,
}: {
  onMenu: () => void;
  onPaleta: () => void;
  onParada: () => void;
  onAvanzar: () => void;
  exportadores: Exportadores;
}) {
  const engagement = usarConsola((s) => s.engagement);
  const corriendo = usarConsola((s) => s.corriendo);
  const sincronizando = usarConsola((s) => s.sincronizando);
  const parada = usarConsola((s) => s.engagement?.roe.parada_emergencia ?? false);
  const errorBackend = usarConsola((s) => s.errorBackend);
  const pendientes = usarConsola((s) => s.aprobaciones.filter((a) => a.estado === "pendiente").length);
  const alternarPausa = usarConsola((s) => s.alternarPausa);
  const refrescar = usarConsola((s) => s.refrescar);
  const sesion = usarConsola((s) => s.sesion);
  const cerrarSesion = usarConsola((s) => s.cerrarSesion);
  // Higiene de la cuenta (v26): estado local de la cabecera — el chip de
  // sesión abre el diálogo con el estado vivo y el cierre global.
  const [higieneAbierta, setHigieneAbierta] = useState(false);

  const completada = engagement?.estado_fase === "completada";
  // Ejecutar está disponible cuando no hay firmas pendientes y el ciclo no
  // está parado ni completado: incluye reanudar una fase en espera_aprobacion
  // cuyas decisiones ya fueron tomadas.
  const faseEjecutable =
    !!engagement && !parada && !completada && pendientes === 0;

  return (
    <header className="sticky top-0 z-40 border-b border-line bg-ink/85 backdrop-blur-xl">
      <div className="flex flex-wrap items-center gap-x-4 gap-y-2 px-4 py-3 sm:px-6 lg:px-6">
        {/* Marca móvil */}
        <div className="flex items-center gap-2 lg:hidden">
          <span className="flex h-7 w-7 items-center justify-center rounded-lg border border-crimson/40 bg-crimson/10">
            <Radio className="h-3.5 w-3.5 text-crimson-bright" aria-hidden />
          </span>
          <span className="text-sm font-semibold text-zinc-100">
            Orquesta<span className="text-crimson-bright">RT</span>
          </span>
        </div>

        {/* Engagement */}
        <div className="order-3 min-w-0 flex-1 basis-full lg:order-2 lg:basis-auto">
          {engagement ? (
            <div className="flex min-w-0 flex-wrap items-center gap-2">
              <span className="truncate text-[13px] font-medium text-zinc-200">{engagement.nombre}</span>
              <Insignia tono={completada ? "esmeralda" : pendientes > 0 ? "ambar" : "crimson"}>
                {completada ? "engagement completado" : pendientes > 0 ? "esperando aprobación" : ETIQUETA_FASE[engagement.fase_actual]}
              </Insignia>
              {parada && <Insignia tono="rojo">parada de emergencia</Insignia>}
            </div>
          ) : (
            <span className="font-mono text-xs text-zinc-500">sin caso activo</span>
          )}
        </div>

        {/* Indicadores y controles */}
        <div className="order-2 ml-auto flex items-center gap-2 lg:order-3">
          {engagement && (
            <div className="hidden items-center gap-3 rounded-lg border border-line bg-panel px-3 py-1.5 font-mono text-[11px] xl:flex">
              <span className="text-zinc-500">
                tok <span className="font-semibold text-zinc-200">{formatoTokens(engagement.tokens_acumulados)}</span>
              </span>
              <span className="h-3 w-px bg-line-strong" aria-hidden />
              <span className="text-zinc-500">
                coste <span className="font-semibold text-zinc-200">{formatoCoste(engagement.coste_acumulado_usd)}</span>
              </span>
            </div>
          )}

          <Insignia
            tono={errorBackend ? "rojo" : !corriendo ? "ambar" : "esmeralda"}
            className="gap-1.5"
          >
            <span className="relative flex h-1.5 w-1.5">
              {corriendo && !errorBackend && (
                <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-70" />
              )}
              <span className={cn(
                "relative inline-flex h-1.5 w-1.5 rounded-full",
                errorBackend ? "bg-red-400" : corriendo ? "bg-emerald-400" : "bg-amber-400",
              )} />
            </span>
            {/* En móvil y en vivo basta el punto con su color: los estados
                que exigen atención (sin conexión / pausado) siempre llevan
                texto. Evita el desbordamiento de la barra a 390px. */}
            {errorBackend || !corriendo ? (
              <span className="whitespace-nowrap">{errorBackend ? "sin conexión" : "pausado"}</span>
            ) : (
              <span className="hidden whitespace-nowrap sm:inline">en vivo</span>
            )}
          </Insignia>

          <div className="flex items-center gap-1">
            <button
              onClick={onPaleta}
              className="flex h-8 w-8 items-center justify-center rounded-lg border border-line bg-panel text-zinc-400 transition-colors hover:bg-raised hover:text-zinc-100"
              aria-label="Abrir paleta de comandos (Ctrl+K)"
              title="Paleta de comandos (Ctrl+K)"
            >
              <SlidersHorizontal className="h-3.5 w-3.5" />
            </button>
            <button
              onClick={() => refrescar().catch(() => undefined)}
              disabled={sincronizando}
              className="flex h-8 w-8 items-center justify-center rounded-lg border border-line bg-panel text-zinc-400 transition-colors hover:bg-raised hover:text-zinc-100 disabled:opacity-40"
              aria-label="Sincronizar ahora"
              title="Sincronizar ahora"
            >
              <RotateCcw className={cn("h-3.5 w-3.5", sincronizando && "animate-spin")} />
            </button>
            <button
              onClick={onAvanzar}
              disabled={!faseEjecutable}
              className="flex h-8 items-center gap-1.5 rounded-lg bg-crimson px-2.5 text-xs font-semibold text-white transition-colors hover:bg-crimson-bright disabled:cursor-not-allowed disabled:opacity-40"
              aria-label="Ejecutar fase actual"
              title={pendientes > 0 ? "Resuelve las aprobaciones pendientes primero" : "Ejecutar la fase actual del orquestador"}
            >
              <Play className="h-3.5 w-3.5" />
              <span className="hidden sm:inline">Ejecutar fase</span>
            </button>
            <MenuExportar deshabilitado={!engagement} exportadores={exportadores} />
            <button
              onClick={alternarPausa}
              className="flex h-8 items-center gap-1.5 rounded-lg border border-line bg-panel px-2.5 text-xs font-medium text-zinc-300 transition-colors hover:bg-raised hover:text-zinc-100"
              aria-label={corriendo ? "Pausar sondeo en vivo" : "Reanudar sondeo en vivo"}
            >
              {corriendo ? <Pause className="h-3.5 w-3.5" /> : <Play className="h-3.5 w-3.5" />}
              <span className="hidden md:inline">{corriendo ? "Pausar" : "Reanudar"}</span>
            </button>
            {parada ? (
              <button
                onClick={onParada}
                className="flex h-8 items-center gap-1.5 rounded-lg border border-amber-400/40 bg-amber-400/10 px-2.5 text-xs font-medium text-amber-200 transition-colors hover:bg-amber-400/20"
                aria-label="Gestionar parada de emergencia"
                title="La parada de emergencia está ACTIVA: gestiona su desactivación"
              >
                <CircleAlert className="h-3.5 w-3.5" />
                <span className="hidden md:inline">Gestionar parada</span>
              </button>
            ) : (
              <button
                onClick={onParada}
                disabled={!engagement}
                className="flex h-8 items-center gap-1.5 rounded-lg border border-crimson/40 bg-crimson/10 px-2.5 text-xs font-medium text-red-300 transition-colors hover:bg-crimson/20 hover:text-red-200 disabled:opacity-40"
                aria-label="Parada de emergencia"
                title="Parada de emergencia (kill switch del ROE)"
              >
                <OctagonX className="h-3.5 w-3.5" />
                <span className="hidden md:inline">Parada</span>
              </button>
            )}

            {/* Sesión del operador autenticado: el chip abre la higiene
                de la cuenta (v26): estado vivo + cerrar-todas. */}
            {sesion && (
              <div
                className="flex h-8 items-center gap-2 rounded-lg border border-line bg-panel pl-2 pr-1 sm:pl-2.5"
                title={`Sesión: ${sesion.usuario} (${sesion.rol})`}
              >
                <button
                  onClick={() => setHigieneAbierta(true)}
                  className="flex items-center gap-2 rounded-md px-0.5 py-0.5 transition-colors hover:opacity-80"
                  aria-label="Abrir higiene de la cuenta"
                  title="Higiene de la cuenta"
                >
                  <span className="flex h-5 w-5 items-center justify-center rounded-full bg-raised font-mono text-[9px] font-bold uppercase text-crimson-bright">
                    {sesion.usuario.slice(0, 2)}
                  </span>
                  <span className="hidden max-w-24 truncate text-xs text-zinc-300 md:inline">
                    {sesion.usuario}
                  </span>
                </button>
                <button
                  onClick={cerrarSesion}
                  className="flex h-6 w-6 items-center justify-center rounded-md text-zinc-500 transition-colors hover:bg-raised hover:text-red-300"
                  aria-label="Cerrar sesión"
                  title="Cerrar sesión"
                >
                  <LogOut className="h-3.5 w-3.5" />
                </button>
              </div>
            )}

            <button
              onClick={onMenu}
              className="flex h-8 w-8 items-center justify-center rounded-lg border border-line bg-panel text-zinc-300 lg:hidden"
              aria-label="Abrir menú de secciones"
            >
              <Menu className="h-4 w-4" />
            </button>
          </div>
        </div>
      </div>

      {/* Cinta de estado */}
      <div className="border-t border-line/60 bg-panel/40">
        <div className="flex items-center gap-2 px-4 py-1.5 font-mono text-[10px] text-zinc-600 sm:px-6">
          <ShieldCheck className="h-3 w-3 shrink-0 text-crimson-bright/70" />
          <span className="truncate">
            operator-in-command: el grafo no avanza sin decisión humana · herramientas reales acotadas al ROE
          </span>
        </div>
      </div>

      {/* Higiene de la cuenta (v26): abierto desde el chip de sesión. */}
      <DialogoHigiene abierto={higieneAbierta} onCerrar={() => setHigieneAbierta(false)} />
    </header>
  );
}
