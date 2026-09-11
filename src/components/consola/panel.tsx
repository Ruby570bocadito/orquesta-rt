"use client";

/** Vista Panel: KPIs del engagement, feed de actividad y resumen del ROE. */

import { motion } from "framer-motion";
import { Entrada, Tarjeta, Insignia, TituloSeccion, InsigniaSeveridad, barraRuido } from "@/components/consola/ui";
import { usarConsola } from "@/lib/store";
import {
  ETIQUETA_FASE,
  ORDEN_FASES,
  formatoCoste,
  formatoTokens,
  Severidad,
} from "@/lib/tipos";
import {
  Activity,
  FileSignature,
  Gauge,
  Hourglass,
  ShieldAlert,
  Ban,
  CheckCircle2,
  TrendingUp,
} from "lucide-react";
import { cn } from "@/lib/utils";

const TONO_ACTIVIDAD: Record<string, string> = {
  normal: "border-line",
  exito: "border-emerald-500/35",
  aviso: "border-amber-500/35",
  alerta: "border-crimson/40",
  bloqueo: "border-violet-500/35",
};

const PUNTO_ACTIVIDAD: Record<string, string> = {
  normal: "bg-zinc-500",
  exito: "bg-emerald-400",
  aviso: "bg-amber-400",
  alerta: "bg-red-400",
  bloqueo: "bg-violet-400",
};

function Kpi({
  icono,
  titulo,
  valor,
  detalle,
  tono,
  indice,
}: {
  icono: React.ReactNode;
  titulo: string;
  valor: string;
  detalle: string;
  tono: string;
  indice: number;
}) {
  return (
    <Entrada indice={indice}>
      <Tarjeta className="group flex items-start gap-4 transition-colors duration-300 hover:border-line-strong">
        <div className={cn("flex h-10 w-10 shrink-0 items-center justify-center rounded-lg ring-1 transition-transform duration-300 group-hover:scale-105", tono)}>
          {icono}
        </div>
        <div className="min-w-0">
          <p className="font-mono text-[10px] uppercase tracking-[0.14em] text-zinc-500">{titulo}</p>
          <p className="mt-1 truncate text-[22px] font-semibold leading-tight tracking-tight text-zinc-50">{valor}</p>
          <p className="mt-0.5 text-xs text-zinc-500">{detalle}</p>
        </div>
      </Tarjeta>
    </Entrada>
  );
}

export function VistaPanel() {
  const engagement = usarConsola((s) => s.engagement);
  const hallazgos = usarConsola((s) => s.hallazgos);
  const aprobaciones = usarConsola((s) => s.aprobaciones);
  const actividad = usarConsola((s) => s.actividad);
  const evidencias = usarConsola((s) => s.evidencias);
  const ruidoAcumulado = usarConsola((s) => s.ruidoAcumulado);
  const cadena = usarConsola((s) => s.cadenaCustodia);

  if (!engagement) return null;

  const pendientes = aprobaciones.filter((a) => a.estado === "pendiente");
  const criticos = hallazgos.filter((h) => h.severidad === "critica").length;
  const altos = hallazgos.filter((h) => h.severidad === "alta").length;
  const medios = hallazgos.filter((h) => h.severidad === "media").length;
  const roe = engagement.roe;

  // Progreso del ciclo: fases completadas sobre el total (9)
  const faseIdx = ORDEN_FASES.indexOf(engagement.fase_actual);
  const progreso = engagement.estado_fase === "completada"
    ? 100
    : Math.round((faseIdx / (ORDEN_FASES.length - 1)) * 100);
  const fasesCompletadas = engagement.estado_fase === "completada"
    ? ORDEN_FASES.length
    : faseIdx;

  return (
    <div className="space-y-5">
      {/* KPIs */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <Kpi
          indice={0}
          icono={<Activity className="h-[18px] w-[18px] text-teal-300" />}
          titulo="Fase activa"
          valor={ETIQUETA_FASE[engagement.fase_actual]}
          detalle={
            engagement.estado_fase === "completada"
              ? "ciclo completado"
              : engagement.estado_fase === "espera_aprobacion"
                ? "detenida: requiere decisión"
                : "en ejecución"
          }
          tono="bg-teal-500/10 ring-teal-500/25"
        />
        <Kpi
          indice={1}
          icono={<Hourglass className="h-[18px] w-[18px] text-amber-300" />}
          titulo="Aprobaciones"
          valor={String(pendientes.length)}
          detalle="pendientes de tu firma"
          tono="bg-amber-500/10 ring-amber-500/25"
        />
        <Kpi
          indice={2}
          icono={<ShieldAlert className="h-[18px] w-[18px] text-red-300" />}
          titulo="Hallazgos crít./altos"
          valor={`${criticos} / ${altos}`}
          detalle={`${medios} medios registrados`}
          tono="bg-crimson/10 ring-crimson/30"
        />
        <Kpi
          indice={3}
          icono={<TrendingUp className="h-[18px] w-[18px] text-emerald-300" />}
          titulo="Coste IA acumulado"
          valor={formatoCoste(engagement.coste_acumulado_usd)}
          detalle={`${formatoTokens(engagement.tokens_acumulados)} tokens · caché activa`}
          tono="bg-emerald-500/10 ring-emerald-500/25"
        />
      </div>

      {/* Progreso del ciclo */}
      <Entrada indice={4}>
        <Tarjeta className="py-4">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <p className="font-mono text-[10px] uppercase tracking-[0.14em] text-zinc-500">
              Progreso del engagement
            </p>
            <p className="font-mono text-[10px] text-zinc-500">
              {fasesCompletadas} de {ORDEN_FASES.length} fases · <span className="text-zinc-300">{progreso}%</span>
            </p>
          </div>
          <div className="mt-2 h-2 overflow-hidden rounded-full bg-zinc-800">
            <motion.div
              initial={{ width: 0 }}
              animate={{ width: `${progreso}%` }}
              transition={{ duration: 0.9, ease: [0.16, 1, 0.3, 1] }}
              className="h-full rounded-full bg-gradient-to-r from-teal-500 via-teal-400 to-emerald-400"
            />
          </div>
        </Tarjeta>
      </Entrada>

      <div className="grid grid-cols-1 gap-5 lg:grid-cols-3">
        {/* Feed de actividad */}
        <Entrada indice={1} className="lg:col-span-2">
          <Tarjeta>
            <TituloSeccion
              titulo="Actividad del agente"
              descripcion="Feed en vivo del orquestador: cada acción queda registrada y las críticas esperan tu firma"
            />
            <div className="max-h-96 space-y-1.5 overflow-y-auto pr-1">
              {actividad.length === 0 && (
                <p className="py-8 text-center font-mono text-xs text-zinc-600">
                  El orquestador arrancará en unos segundos…
                </p>
              )}
              <motion.div initial="oculto" animate="visible" variants={{ visible: { transition: { staggerChildren: 0.04 } } }}>
                {actividad.slice(0, 12).map((item) => (
                  <motion.div
                    key={item.id}
                    variants={{ oculto: { opacity: 0, y: 6 }, visible: { opacity: 1, y: 0 } }}
                    className={cn(
                      "flex items-start gap-3 rounded-lg border bg-ink/60 px-3 py-2.5 transition-colors",
                      TONO_ACTIVIDAD[item.tono ?? "normal"],
                    )}
                  >
                    <span className={cn("mt-[7px] h-1.5 w-1.5 shrink-0 rounded-full", PUNTO_ACTIVIDAD[item.tono ?? "normal"])} aria-hidden />
                    <div className="min-w-0 flex-1">
                      <p className="text-[13px] font-medium text-zinc-200">{item.titulo}</p>
                      {item.detalle && (
                        <p className="mt-0.5 text-xs leading-relaxed text-zinc-500">{item.detalle}</p>
                      )}
                    </div>
                    <span className="shrink-0 font-mono text-[10px] text-zinc-600">
                      {new Date(item.ts).toLocaleTimeString("es-ES", { hour: "2-digit", minute: "2-digit", second: "2-digit" })}
                    </span>
                  </motion.div>
                ))}
              </motion.div>
            </div>
          </Tarjeta>
        </Entrada>

        {/* ROE vivo */}
        <Entrada indice={2}>
          <Tarjeta className="h-full">
            <TituloSeccion
              titulo="ROE máquina-legible"
              descripcion="Política firmada en F0: el boundary la aplica antes de cada tool call"
            />
            <div className="space-y-4 text-sm">
              <div>
                <p className="mb-1.5 flex items-center gap-1.5 font-mono text-[10px] font-semibold uppercase tracking-[0.14em] text-zinc-500">
                  <Gauge className="h-3 w-3" /> Alcance autorizado
                </p>
                <div className="flex flex-wrap gap-1.5">
                  {roe.alcance_dominios.map((d) => (
                    <Insignia key={d} tono="teal">{d}</Insignia>
                  ))}
                  {roe.alcance_cidrs.map((c) => (
                    <Insignia key={c} tono="teal">{c}</Insignia>
                  ))}
                  {roe.alcance_excluido.map((c) => (
                    <Insignia key={c} tono="rojo">excluido · {c}</Insignia>
                  ))}
                </div>
              </div>

              <div>
                <p className="mb-1.5 flex items-center gap-1.5 font-mono text-[10px] font-semibold uppercase tracking-[0.14em] text-zinc-500">
                  <Ban className="h-3 w-3" /> Prohibidas
                </p>
                <div className="flex flex-wrap gap-1.5">
                  {roe.tecnicas_prohibidas.map((t) => (
                    <Insignia key={t} tono="rojo">{t}</Insignia>
                  ))}
                </div>
                <p className="mb-1.5 mt-3 flex items-center gap-1.5 font-mono text-[10px] font-semibold uppercase tracking-[0.14em] text-zinc-500">
                  <FileSignature className="h-3 w-3" /> Requieren firma
                </p>
                <div className="flex flex-wrap gap-1.5">
                  {roe.tecnicas_con_aprobacion.map((t) => (
                    <Insignia key={t} tono="ambar">{t}</Insignia>
                  ))}
                </div>
              </div>

              <div>
                <div className="mb-1.5 flex items-center justify-between font-mono text-[10px] font-semibold uppercase tracking-[0.14em] text-zinc-500">
                  <span>Techo de ruido</span>
                  <span className="text-zinc-400">{roe.techo_ruido}/100</span>
                </div>
                <div className="h-1.5 overflow-hidden rounded-full bg-zinc-800">
                  <motion.div
                    initial={{ width: 0 }}
                    animate={{ width: `${roe.techo_ruido}%` }}
                    transition={{ duration: 0.8, ease: [0.16, 1, 0.3, 1] }}
                    className="h-full rounded-full bg-gradient-to-r from-emerald-500 to-amber-400"
                  />
                </div>
                <p className="mt-1.5 font-mono text-[10px] text-zinc-600">
                  ventana {roe.ventanas_activas.inicio}–{roe.ventanas_activas.fin} · {roe.ventanas_activas.dias.join(", ")}
                </p>
              </div>

              <div>
                <div className="mb-1.5 flex items-center justify-between font-mono text-[10px] font-semibold uppercase tracking-[0.14em] text-zinc-500">
                  <span>Ruido OPSEC acumulado</span>
                  <span className={cn(ruidoAcumulado > roe.techo_ruido && "text-amber-300")}>
                    {ruidoAcumulado}/{roe.techo_ruido}{ruidoAcumulado > roe.techo_ruido ? " · techo superado" : ""}
                  </span>
                </div>
                <div className="h-1.5 overflow-hidden rounded-full bg-zinc-800">
                  <motion.div
                    initial={{ width: 0 }}
                    animate={{ width: `${Math.min(100, (ruidoAcumulado / roe.techo_ruido) * 100)}%` }}
                    transition={{ duration: 0.8, ease: [0.16, 1, 0.3, 1] }}
                    className={cn("h-full rounded-full", barraRuido((ruidoAcumulado / roe.techo_ruido) * 100))}
                  />
                </div>
                <p className="mt-1.5 font-mono text-[10px] text-zinc-600">
                  suma del ruido estimado de cada acción que firmaste
                </p>
              </div>

              <div className={cn("rounded-lg border p-3", cadena.valida ? "border-emerald-500/30 bg-emerald-500/5" : "border-crimson/40 bg-crimson/5")}>
                <p className="font-mono text-[10px] font-semibold uppercase tracking-[0.14em] text-zinc-500">
                  Cadena de custodia
                </p>
                <p className={cn("mt-1 flex items-center gap-1.5 text-[13px]", cadena.valida ? "text-emerald-300" : "text-red-300")}>
                  <CheckCircle2 className="h-3.5 w-3.5 shrink-0" />
                  {cadena.valida
                    ? `${cadena.total} evidencias firmadas (SHA-256 + HMAC)`
                    : `INTERRUPTIDA: ${cadena.primer_error ?? "error desconocido"}`}
                </p>
              </div>
            </div>
          </Tarjeta>
        </Entrada>
      </div>

      {/* Últimos hallazgos */}
      {hallazgos.length > 0 && (
        <Entrada indice={3}>
          <Tarjeta>
            <TituloSeccion titulo="Hallazgos recientes" descripcion="Los 3 más recientes del engagement" />
            <div className="space-y-1.5">
              {hallazgos.slice(0, 3).map((h) => (
                <div key={h.id} className="flex flex-wrap items-center gap-3 rounded-lg border border-line bg-ink/60 px-4 py-2.5 transition-colors hover:border-line-strong">
                  <InsigniaSeveridad severidad={h.severidad as Severidad} />
                  <span className="min-w-0 flex-1 truncate text-[13px] text-zinc-200">{h.titulo}</span>
                  {h.tecnica_mitre && (
                    <code className="rounded border border-line bg-raised px-1.5 py-0.5 font-mono text-[10px] text-zinc-400">{h.tecnica_mitre}</code>
                  )}
                </div>
              ))}
            </div>
          </Tarjeta>
        </Entrada>
      )}
    </div>
  );
}
