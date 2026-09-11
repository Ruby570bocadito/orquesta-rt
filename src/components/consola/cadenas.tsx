"use client";

/**
 * Vista Cadenas (planificación threat-led v21): cadenas de ataque estilo
 * Atomic Red Team referenciando SOLO herramientas reales del boundary.
 * El plan por caso contrasta cada paso contra lo EJERCITADO de verdad
 * (hallazgos + auditoría del caso) — nada de marcas de verificación
 * inventadas: "ejercitado" exige evidencia.
 */

import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import {
  CircleCheck, CircleDashed, Construction, GitBranch, Loader2, Route,
  ShieldAlert, Swords,
} from "lucide-react";
import { Tarjeta, Insignia, TituloSeccion } from "@/components/consola/ui";
import { usarConsola } from "@/lib/store";
import {
  PlanThreatled,
  ResumenCadena,
  EstadoPasoThreatled,
} from "@/lib/tipos";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

const TONO_ESTADO: Record<EstadoPasoThreatled, "esmeralda" | "teal" | "ambar"> = {
  ejercitado: "esmeralda",
  disponible: "teal",
  manual: "ambar",
};

const ETIQUETA_ESTADO: Record<EstadoPasoThreatled, string> = {
  ejercitado: "ejercitado en este caso",
  disponible: "herramienta del despliegue",
  manual: "guion manual del operador",
};

const ICONO_ESTADO = {
  ejercitado: CircleCheck,
  disponible: CircleDashed,
  manual: Construction,
};

function tonoRuido(ruido: number): string {
  if (ruido >= 60) return "text-red-300";
  if (ruido >= 30) return "text-amber-300";
  return "text-zinc-400";
}

export function VistaCadenas() {
  const cadenas = usarConsola((s) => s.cadenas);
  const cargarCadenas = usarConsola((s) => s.cargarCadenas);
  const plan = usarConsola((s) => s.planThreatled);
  const generarPlan = usarConsola((s) => s.generarPlanThreatled);
  const ocupado = usarConsola((s) => s.threatledOcupado);
  const casoActivo = usarConsola((s) => s.casoActivo);
  const [seleccionada, setSeleccionada] = useState<string | null>(null);

  useEffect(() => {
    if (!cadenas) void cargarCadenas();
  }, [cadenas, cargarCadenas]);

  const contrastar = async (id: string) => {
    setSeleccionada(id);
    try {
      await generarPlan(id);
    } catch {
      /* el toast de error lo muestra el llamador genérico */
    }
  };

  if (!cadenas) {
    return (
      <div className="flex h-64 items-center justify-center gap-2 text-sm text-zinc-500">
        <Loader2 className="h-4 w-4 animate-spin" /> cargando cadenas threat-led…
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <TituloSeccion
        titulo="Planificación threat-led"
        descripcion="Cadenas estilo Atomic Red Team: cada paso emula el comportamiento secuencial de un adversario real y referencia herramientas que este despliegue ejecuta de verdad (o queda marcado como guion manual). Contrasta el plan con lo ya ejercitado en el caso."
      />

      {!casoActivo ? (
        <Tarjeta className="border-amber-400/30">
          <p className="flex items-center gap-2 text-[12px] text-amber-200">
            <ShieldAlert className="h-4 w-4" />
            Selecciona o crea un caso para contrastar una cadena contra su evidencia real.
          </p>
        </Tarjeta>
      ) : null}

      {/* Selector de cadenas */}
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
        {cadenas.map((c: ResumenCadena, i: number) => (
          <motion.div
            key={c.id}
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: i * 0.04 }}
            onClick={() => void contrastar(c.id)}
            className="cursor-pointer"
          >
            <Tarjeta
              className={cn(
                "flex h-full flex-col gap-2 transition-colors hover:border-zinc-600",
                seleccionada === c.id && "border-crimson-bright/60",
              )}
            >
              <div className="flex items-start justify-between gap-2">
                <p className="flex items-center gap-2 text-sm font-semibold text-zinc-100">
                  <Swords className="h-4 w-4 text-crimson-bright" />
                  {c.nombre}
                </p>
                <Insignia tono={c.manuales ? "ambar" : "esmeralda"}>
                  {c.pasos} pasos · {c.manuales} manuales
                </Insignia>
              </div>
              <p className="font-mono text-[11px] text-zinc-500">{c.perfil}</p>
              <p className="flex-1 text-[12px] leading-relaxed text-zinc-400">
                {c.objetivo}
              </p>
              <div className="flex flex-wrap gap-1">
                {c.tecnicas.map((t) => (
                  <span key={t} className="rounded bg-ink px-1.5 py-0.5 font-mono text-[10px] text-zinc-400">
                    {t}
                  </span>
                ))}
              </div>
              <div className="flex items-center justify-between pt-1">
                <span className={cn("font-mono text-[11px]", tonoRuido(c.ruido_total_estimado))}>
                  ruido total estimado {c.ruido_total_estimado}
                </span>
                <Button
                  variant="outline"
                  size="sm"
                  className="h-7 gap-1.5 border-line bg-panel text-[11px] text-zinc-300 hover:bg-raised"
                  disabled={ocupado || !casoActivo}
                  onClick={(e) => {
                    e.stopPropagation();
                    void contrastar(c.id);
                  }}
                >
                  {ocupado && seleccionada === c.id ? (
                    <Loader2 className="h-3 w-3 animate-spin" />
                  ) : (
                    <GitBranch className="h-3 w-3" />
                  )}
                  contrastar con el caso
                </Button>
              </div>
            </Tarjeta>
          </motion.div>
        ))}
      </div>

      {/* Plan contrastado */}
      {plan ? (
        <motion.section
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          className="space-y-3"
        >
          <div className="flex flex-wrap items-center gap-2">
            <Route className="h-4 w-4 text-crimson-bright" />
            <h3 className="text-[13px] font-semibold text-zinc-200">
              Plan contrastado: {plan.nombre}
            </h3>
            <Insignia tono="esmeralda">{plan.resumen.ejercitados} ejercitados</Insignia>
            <Insignia tono="teal">{plan.resumen.disponibles} disponibles</Insignia>
            <Insignia tono="ambar">{plan.resumen.manuales} manuales</Insignia>
            <Insignia tono="slate">
              ruido acumulado {plan.resumen.ruido_total_estimado}
            </Insignia>
            {plan.evidencia_id ? (
              <span className="font-mono text-[10px] text-zinc-600">
                evidencia {plan.evidencia_id}
              </span>
            ) : null}
          </div>

          <div className="space-y-2">
            {plan.pasos.map((p) => {
              const Icono = ICONO_ESTADO[p.estado];
              return (
                <Tarjeta key={p.orden} className="flex gap-3">
                  <div className="flex flex-col items-center pt-1">
                    <span className="font-mono text-[11px] text-zinc-600">
                      {String(p.orden).padStart(2, "0")}
                    </span>
                    <Icono
                      className={cn(
                        "mt-1 h-4 w-4",
                        p.estado === "ejercitado" && "text-emerald-400",
                        p.estado === "disponible" && "text-sky-400",
                        p.estado === "manual" && "text-amber-400",
                      )}
                    />
                  </div>
                  <div className="flex-1 space-y-1.5">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="rounded bg-ink px-1.5 py-0.5 font-mono text-[10px] text-crimson-bright">
                        {p.tecnica}
                      </span>
                      <span className="text-[13px] font-medium text-zinc-100">
                        {p.nombre}
                      </span>
                      <Insignia tono={TONO_ESTADO[p.estado]}>
                        {ETIQUETA_ESTADO[p.estado]}
                      </Insignia>
                      <span className="font-mono text-[10px] text-zinc-600">
                        {p.fase} · {p.herramienta} ·{" "}
                        <span className={tonoRuido(p.ruido_estimado)}>
                          ruido {p.ruido_estimado}
                        </span>
                      </span>
                    </div>
                    <p className="text-[12px] leading-relaxed text-zinc-400">
                      {p.descripcion}
                    </p>
                    <p className="rounded-md border border-line bg-ink p-2 font-mono text-[10px] leading-relaxed text-zinc-500">
                      <span className="text-zinc-400">detección esperada:</span>{" "}
                      {p.deteccion}
                    </p>
                    <p className="text-[11px] text-zinc-500">{p.nota}</p>
                  </div>
                </Tarjeta>
              );
            })}
          </div>
        </motion.section>
      ) : null}
    </div>
  );
}
