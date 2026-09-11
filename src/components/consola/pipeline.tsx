"use client";

/** Vista Pipeline: cadena de fases F0→cierre con detalle IA/humano/artefacto. */

import { motion } from "framer-motion";
import { Tarjeta, Insignia, TituloSeccion } from "@/components/consola/ui";
import { usarConsola } from "@/lib/store";
import {
  ARTEFACTO_FASE,
  ETIQUETA_FASE,
  FaseId,
  ORDEN_FASES,
  QUE_APRUEBA_HUMANO,
  QUE_HACE_IA,
} from "@/lib/tipos";
import { Bot, FileText, UserCheck, CheckCircle2, Clock, Lock, Play } from "lucide-react";
import { cn } from "@/lib/utils";

function IconoEstado({ estado }: { estado: string }) {
  if (estado === "completada") return <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />;
  if (estado === "espera_aprobacion") return <Lock className="h-3.5 w-3.5 text-amber-300" />;
  if (estado === "activa") return <Clock className="h-3.5 w-3.5 animate-pulse text-teal-300" />;
  return <Clock className="h-3.5 w-3.5 text-zinc-700" />;
}

export function VistaPipeline({ onEjecutarFase }: { onEjecutarFase?: () => void }) {
  const engagement = usarConsola((s) => s.engagement);
  const usoTokens = usarConsola((s) => s.usoTokens);
  const pendientes = usarConsola((s) => s.aprobaciones.filter((a) => a.estado === "pendiente").length);
  if (!engagement) return null;

  const faseIdx = ORDEN_FASES.indexOf(engagement.fase_actual);
  const ejecutable =
    !!onEjecutarFase && pendientes === 0 &&
    (engagement.estado_fase === "pendiente" || engagement.estado_fase === "espera_aprobacion");

  const tokensPorFase = new Map<FaseId, number>();
  for (const u of usoTokens) {
    tokensPorFase.set(u.fase, (tokensPorFase.get(u.fase) ?? 0) + u.tokens_entrada + u.tokens_salida);
  }

  return (
    <div className="space-y-5">
      <Tarjeta>
        <div className="flex flex-wrap items-center justify-between gap-3">
          <TituloSeccion
            titulo="Pipeline orquestado del engagement"
            descripcion="Cadena de fases dirigida por el grafo de estado: cada transición crítica exige aprobación humana en consola"
          />
          {ejecutable && (
            <button
              onClick={onEjecutarFase}
              className="flex items-center gap-1.5 rounded-lg bg-crimson px-3.5 py-2 text-xs font-semibold text-white transition-colors hover:bg-crimson-bright"
            >
              <Play className="h-3.5 w-3.5" /> Ejecutar {ETIQUETA_FASE[engagement.fase_actual]}
            </button>
          )}
        </div>

        {/* Stepper horizontal */}
        <div className="overflow-x-auto pb-2">
          <ol className="flex min-w-max items-stretch gap-1.5">
            {ORDEN_FASES.map((fase, i) => {
              const estado =
                i < faseIdx ? "completada" : i === faseIdx ? engagement.estado_fase : "pendiente";
              return (
                <li key={fase} className="flex items-center gap-1.5">
                  <motion.div
                    initial={{ opacity: 0, y: 8 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.3, delay: Math.min(i * 0.04, 0.3) }}
                    className={cn(
                      "flex w-40 flex-col gap-1.5 rounded-lg border p-3 transition-colors duration-300",
                      estado === "completada" && "border-emerald-500/30 bg-emerald-500/[0.06]",
                      estado === "activa" && "border-teal-400/50 bg-teal-500/[0.09] shadow-[0_0_24px_-6px] shadow-teal-500/40",
                      estado === "espera_aprobacion" && "border-amber-400/50 bg-amber-500/[0.09] shadow-[0_0_24px_-6px] shadow-amber-500/40",
                      estado === "pendiente" && "border-line bg-ink/60",
                    )}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span
                        className={cn(
                          "font-mono text-[10px] font-semibold",
                          estado === "pendiente" ? "text-zinc-600" : "text-zinc-200",
                        )}
                      >
                        {ETIQUETA_FASE[fase]}
                      </span>
                      <IconoEstado estado={estado} />
                    </div>
                    <span className="font-mono text-[9px] text-zinc-600">
                      {tokensPorFase.get(fase)
                        ? `${(tokensPorFase.get(fase)! / 1000).toFixed(1)} K tokens`
                        : "—"}
                    </span>
                  </motion.div>
                  {i < ORDEN_FASES.length - 1 && (
                    <div
                      className={cn(
                        "h-px w-3 shrink-0",
                        i < faseIdx ? "bg-emerald-500/50" : "bg-line-strong",
                      )}
                      aria-hidden
                    />
                  )}
                </li>
              );
            })}
          </ol>
        </div>
      </Tarjeta>

      {/* Detalle de fases */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2 xl:grid-cols-3">
        {ORDEN_FASES.map((fase, i) => {
          const estado = i < faseIdx ? "completada" : i === faseIdx ? engagement.estado_fase : "pendiente";
          return (
            <motion.div
              key={fase}
              initial={{ opacity: 0, y: 12 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.35, delay: Math.min(i * 0.05, 0.4) }}
            >
              <Tarjeta
                className={cn(
                  "h-full transition-colors duration-300",
                  estado === "activa" && "border-teal-500/40",
                  estado === "espera_aprobacion" && "border-amber-500/40",
                  estado === "pendiente" && "opacity-70",
                )}
              >
                <div className="mb-3 flex items-center justify-between gap-2">
                  <h3 className={cn("font-mono text-xs font-semibold tracking-tight", estado === "pendiente" ? "text-zinc-500" : "text-zinc-100")}>
                    {ETIQUETA_FASE[fase]}
                  </h3>
                  <Insignia
                    tono={estado === "completada" ? "esmeralda" : estado === "activa" ? "teal" : estado === "espera_aprobacion" ? "ambar" : "slate"}
                  >
                    {estado.replace("_", " ")}
                  </Insignia>
                </div>
                <div className="space-y-2.5 text-xs leading-relaxed">
                  <div className="flex items-start gap-2">
                    <Bot className="mt-0.5 h-3.5 w-3.5 shrink-0 text-teal-300" />
                    <p className="text-zinc-400">{QUE_HACE_IA[fase]}</p>
                  </div>
                  <div className="flex items-start gap-2">
                    <UserCheck className="mt-0.5 h-3.5 w-3.5 shrink-0 text-amber-300" />
                    <p className="text-zinc-400">{QUE_APRUEBA_HUMANO[fase]}</p>
                  </div>
                  <div className="flex items-start gap-2">
                    <FileText className="mt-0.5 h-3.5 w-3.5 shrink-0 text-zinc-600" />
                    <p className="text-zinc-500">
                      Artefacto: <span className="text-zinc-400">{ARTEFACTO_FASE[fase]}</span>
                    </p>
                  </div>
                  {tokensPorFase.get(fase) && (
                    <p className="font-mono text-[10px] text-zinc-600">
                      consumo {tokensPorFase.get(fase)!.toLocaleString("es-ES")} tok · techo {engagement.presupuesto_tokens[fase] ?? 0} K
                    </p>
                  )}
                </div>
              </Tarjeta>
            </motion.div>
          );
        })}
      </div>
    </div>
  );
}
