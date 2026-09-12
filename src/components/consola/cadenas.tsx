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
  CircleCheck, CircleDashed, Construction, GitBranch, Loader2, Repeat,
  Route, ShieldAlert, Swords, XCircle,
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
  const ctem = usarConsola((s) => s.ctem);
  const cargarCtem = usarConsola((s) => s.cargarCtem);
  const corridaCtem = usarConsola((s) => s.corridaCtem);
  const programarCtem = usarConsola((s) => s.programarCtem);
  const cancelarCtem = usarConsola((s) => s.cancelarCtem);
  const ctemOcupado = usarConsola((s) => s.ctemOcupado);
  const [seleccionada, setSeleccionada] = useState<string | null>(null);
  const [horas, setHoras] = useState(24);

  useEffect(() => {
    if (!cadenas) void cargarCadenas();
  }, [cadenas, cargarCadenas]);

  useEffect(() => {
    if (casoActivo) void cargarCtem();
  }, [casoActivo, cargarCtem]);

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

      {/* Modo continuo CTEM (v23): la exposición se mide periódicamente */}
      {casoActivo ? (
        <motion.section
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          className="space-y-3"
        >
          <div className="flex flex-wrap items-center gap-2">
            <Repeat className="h-4 w-4 text-crimson-bright" />
            <h3 className="text-[13px] font-semibold text-zinc-200">
              Continuidad (CTEM)
            </h3>
            <Insignia tono="slate">
              la exposición se mide cada corrida · delta contra la anterior
            </Insignia>
          </div>

          <Tarjeta className="flex flex-col gap-3">
            <p className="text-[12px] leading-relaxed text-zinc-400">
              Programa una cadena como instrumento continuo: el despliegue
              lanza una <span className="text-zinc-200">corrida</span> con el
              intervalo elegido, toma la instantánea real del caso (hallazgos,
              detecciones VECTR, cobertura) y calcula el delta contra la
              corrida anterior. La corrida mide: no ejecuta técnicas.
            </p>
            <div className="flex flex-wrap items-center gap-2">
              <select
                aria-label="cadena para el modo continuo"
                value={seleccionada ?? plan?.cadena_id ?? ""}
                onChange={(e) => setSeleccionada(e.target.value || null)}
                className="h-8 rounded-md border border-line bg-panel px-2 font-mono text-[11px] text-zinc-300"
              >
                <option value="">elige cadena…</option>
                {(cadenas ?? []).map((c) => (
                  <option key={c.id} value={c.id}>
                    {c.nombre}
                  </option>
                ))}
              </select>
              <select
                aria-label="intervalo de corridas"
                value={horas}
                onChange={(e) => setHoras(Number(e.target.value))}
                className="h-8 rounded-md border border-line bg-panel px-2 font-mono text-[11px] text-zinc-300"
              >
                <option value={24}>cada 24 h</option>
                <option value={48}>cada 48 h</option>
                <option value={168}>cada 7 días</option>
                <option value={720}>cada 30 días</option>
              </select>
              <Button
                variant="outline"
                size="sm"
                className="h-8 gap-1.5 border-line bg-panel text-[11px] text-zinc-300 hover:bg-raised"
                disabled={ctemOcupado || !seleccionada}
                onClick={() => {
                  const id = seleccionada;
                  if (id) void corridaCtem(id).catch(() => {});
                }}
              >
                {ctemOcupado ? (
                  <Loader2 className="h-3 w-3 animate-spin" />
                ) : (
                  <Repeat className="h-3 w-3" />
                )}
                corrida ahora
              </Button>
              <Button
                variant="outline"
                size="sm"
                className="h-8 gap-1.5 border-line bg-panel text-[11px] text-zinc-300 hover:bg-raised"
                disabled={ctemOcupado || !seleccionada}
                onClick={() => {
                  const id = seleccionada;
                  if (id) void programarCtem(id, horas).catch(() => {});
                }}
              >
                <GitBranch className="h-3 w-3" />
                programar
              </Button>
            </div>

            {/* Programas activos */}
            {ctem && ctem.programas.some((p) => p.activo) ? (
              <div className="flex flex-wrap gap-2">
                {ctem.programas
                  .filter((p) => p.activo)
                  .map((p) => (
                    <span
                      key={p.id}
                      className="flex items-center gap-2 rounded-md border border-line bg-ink px-2 py-1 font-mono text-[10px] text-zinc-400"
                    >
                      {p.cadena_id} · cada {p.intervalo_horas} h
                      {p.proxima_corrida_en
                        ? ` · próxima ${new Date(p.proxima_corrida_en).toLocaleString("es-ES", { dateStyle: "short", timeStyle: "short" })}`
                        : ""}
                      <button
                        aria-label="detener programa"
                        title="detener programa"
                        className="text-zinc-500 hover:text-red-300"
                        onClick={() => void cancelarCtem(p.id).catch(() => {})}
                      >
                        <XCircle className="h-3.5 w-3.5" />
                      </button>
                    </span>
                  ))}
              </div>
            ) : null}

            {/* Último delta */}
            {ctem?.ultimo_delta ? (
              <div className="flex flex-wrap items-center gap-1.5">
                {ctem.ultimo_delta.primera_corrida ? (
                  <Insignia tono="teal">primera corrida · base de la serie</Insignia>
                ) : (
                  <>
                    <Insignia tono="esmeralda">
                      +{ctem.ultimo_delta.hallazgos_nuevos} hallazgos
                    </Insignia>
                    <Insignia tono={ctem.ultimo_delta.detecciones_nuevas ? "ambar" : "slate"}>
                      +{ctem.ultimo_delta.detecciones_nuevas} detecciones
                    </Insignia>
                    {ctem.ultimo_delta.nuevas_tecnicas.length ? (
                      <Insignia tono="ambar">
                        nuevas técnicas: {ctem.ultimo_delta.nuevas_tecnicas.join(", ")}
                      </Insignia>
                    ) : (
                      <Insignia tono="slate">sin técnicas nuevas</Insignia>
                    )}
                  </>
                )}
              </div>
            ) : null}

            {/* Historial de corridas (últimas 5) */}
            {ctem && ctem.corridas.length ? (
              <div className="space-y-1">
                {ctem.corridas.slice(0, 5).map((c) => (
                  <div
                    key={c.id}
                    className="flex flex-wrap items-center justify-between gap-2 rounded-md border border-line bg-ink px-2 py-1.5 font-mono text-[10px] text-zinc-500"
                  >
                    <span className="text-zinc-400">
                      {c.resumen?.cadena_nombre ?? c.cadena_id}
                    </span>
                    <span>
                      {c.resumen?.cobertura
                        ? `${c.resumen.cobertura.ejercitados}/${c.resumen.cobertura.total} ejercitados · `
                        : ""}
                      {c.resumen?.detecciones_documentadas ?? 0} detecciones
                    </span>
                    <span>
                      {new Date(c.creado_en).toLocaleString("es-ES", {
                        dateStyle: "short",
                        timeStyle: "short",
                      })}{" "}
                      · {c.disparo}
                      {c.resumen?.evidencia_id
                        ? ` · evidencia ${c.resumen.evidencia_id}`
                        : ""}
                    </span>
                  </div>
                ))}
              </div>
            ) : null}
          </Tarjeta>
        </motion.section>
      ) : null}
    </div>
  );
}
