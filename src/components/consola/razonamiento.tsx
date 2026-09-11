"use client";

/**
 * Vista Razonamiento IA: el cerebro adaptativo de la plataforma.
 *
 * Cuatro niveles, todos sobre datos REALES del caso:
 *  - Cobertura (determinista, instantánea): superficie vista vs. huecos.
 *  - Prioridades (reglas pures): la adaptación funciona sin ningún LLM.
 *  - Plan de fase (IA): pasos validados contra el catálogo real de
 *    transportes; NUNCA ejecuta — cada paso se materializa por el canal
 *    de fase con su boundary y firma humana.
 *  - Reflexión (IA): autocrítica de cobertura de la fase en curso.
 * Toda traza queda persistida con hashes y es consultable abajo.
 */

import { useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  Brain, Compass, ListChecks, RefreshCw, ScanSearch, Sparkles, TriangleAlert,
  CircleCheck, Clock, Hash, Loader2, Ban,
} from "lucide-react";
import { Tarjeta, Insignia, TituloSeccion, Vacio } from "@/components/consola/ui";
import { usarConsola } from "@/lib/store";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

function BarraConfianza({ valor }: { valor: number }) {
  const pct = Math.round(Math.max(0, Math.min(1, valor)) * 100);
  return (
    <div className="flex items-center gap-2">
      <div className="h-1.5 w-20 overflow-hidden rounded-full bg-zinc-800">
        <motion.div
          initial={{ width: 0 }}
          animate={{ width: `${pct}%` }}
          transition={{ duration: 0.6, ease: "easeOut" }}
          className={cn(
            "h-full rounded-full",
            pct >= 75 ? "bg-emerald-500" : pct >= 50 ? "bg-amber-500" : "bg-zinc-500",
          )}
        />
      </div>
      <span className="w-9 text-right text-[11px] tabular-nums text-zinc-400">{pct}%</span>
    </div>
  );
}

export function VistaRazonamiento() {
  const cobertura = usarConsola((s) => s.cobertura);
  const prioridades = usarConsola((s) => s.prioridades);
  const plan = usarConsola((s) => s.planRazon);
  const reflexion = usarConsola((s) => s.reflexion);
  const trazas = usarConsola((s) => s.trazasRazon);
  const ocupado = usarConsola((s) => s.razonOcupado);
  const error = usarConsola((s) => s.errorRazon);
  const casoActivo = usarConsola((s) => s.casoActivo);
  const cargarCobertura = usarConsola((s) => s.cargarCobertura);
  const cargarPrioridades = usarConsola((s) => s.cargarPrioridades);
  const generarPlan = usarConsola((s) => s.generarPlan);
  const generarReflexion = usarConsola((s) => s.generarReflexion);
  const cargarTrazas = usarConsola((s) => s.cargarTrazasRazon);

  useEffect(() => {
    if (casoActivo) {
      cargarCobertura().catch(() => undefined);
      cargarPrioridades().catch(() => undefined);
      cargarTrazas().catch(() => undefined);
    }
  }, [casoActivo, cargarCobertura, cargarPrioridades, cargarTrazas]);

  if (!casoActivo) {
    return <Vacio mensaje="Selecciona un caso para ver el razonamiento adaptativo" />;
  }

  return (
    <div className="space-y-4">
      <TituloSeccion
        titulo="Razonamiento adaptativo"
        descripcion="Cobertura determinista · prioridades por reglas · plan y reflexión con IA — todo propuesta, nada ejecuta"
      />

      {error && (
        <Tarjeta className="border-red-500/40 bg-red-500/5 p-3">
          <p className="flex items-center gap-2 text-sm text-red-300">
            <TriangleAlert className="h-4 w-4" /> {error}
          </p>
        </Tarjeta>
      )}

      {/* COBERTURA DETERMINISTA */}
      <Tarjeta className="p-4">
        <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
          <p className="flex flex-wrap items-center gap-2 text-sm font-semibold text-zinc-100">
            <ScanSearch className="h-4 w-4 text-crimson-bright" /> Cobertura de la superficie
            <Insignia tono="slate">determinista · sin LLM</Insignia>
          </p>
          <Button variant="outline" size="sm" className="border-line text-zinc-300 hover:bg-panel"
                  onClick={() => cargarCobertura().catch(() => undefined)}
                  disabled={ocupado === "cobertura"}>
            {ocupado === "cobertura"
              ? <Loader2 className="mr-1 h-3.5 w-3.5 animate-spin" />
              : <RefreshCw className="mr-1 h-3.5 w-3.5" />} Recalcular
          </Button>
        </div>
        {!cobertura ? (
          <p className="text-sm text-zinc-500">Calculando cobertura…</p>
        ) : (
          <div className="grid gap-3 md:grid-cols-3">
            <div className="space-y-2 rounded-lg border border-line bg-panel p-3">
              <p className="text-xs font-medium text-zinc-400">Objetivos: {cobertura.objetivos_total}</p>
              {Object.entries(cobertura.objetivos_por_tipo).map(([tipo, estados]) => (
                <div key={tipo} className="flex items-center justify-between text-[11px] text-zinc-500">
                  <span className="capitalize">{tipo}</span>
                  <span className="tabular-nums">{estados.total} · {estados.descubierto ?? 0} nuevos</span>
                </div>
              ))}
            </div>
            <div className="space-y-2 rounded-lg border border-line bg-panel p-3">
              <p className="text-xs font-medium text-zinc-400">Hallazgos: {cobertura.hallazgos_total}</p>
              {Object.entries(cobertura.hallazgos_por_severidad).map(([sev, n]) => (
                <div key={sev} className="flex items-center justify-between text-[11px] text-zinc-500">
                  <span className="capitalize">{sev}</span>
                  <span className="tabular-nums">{n}</span>
                </div>
              ))}
            </div>
            <div className="space-y-2 rounded-lg border border-line bg-panel p-3">
              <p className="text-xs font-medium text-zinc-400">
                Transportes aplicados: {cobertura.transportes_aplicados.length}
              </p>
              <div className="max-h-24 space-y-1 overflow-y-auto">
                {cobertura.transportes_aplicados.map((t) => (
                  <div key={t} className="flex items-center gap-1 text-[11px] text-zinc-500">
                    <CircleCheck className="h-3 w-3 text-emerald-500" /> {t}
                  </div>
                ))}
                {cobertura.transportes_aplicados.length === 0 && (
                  <p className="text-[11px] text-zinc-600">ninguno todavía</p>
                )}
              </div>
            </div>
            {cobertura.huecos.length > 0 && (
              <div className="space-y-2 rounded-lg border border-amber-500/25 bg-amber-500/5 p-3 md:col-span-3">
                <p className="flex items-center gap-2 text-xs font-medium text-amber-300">
                  <TriangleAlert className="h-3.5 w-3.5" /> Huecos de cobertura ({cobertura.huecos.length})
                </p>
                {cobertura.huecos.map((h, i) => (
                  <motion.p
                    key={h.hueco}
                    initial={{ opacity: 0, x: -6 }} animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: i * 0.04 }}
                    className="text-[11px] text-zinc-400"
                  >
                    <b className="text-zinc-300">[{h.fase}]</b> {h.hueco}
                  </motion.p>
                ))}
              </div>
            )}
          </div>
        )}
      </Tarjeta>

      {/* PRIORIDADES ADAPTATIVAS (reglas pures) */}
      <Tarjeta className="p-4">
        <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
          <p className="flex flex-wrap items-center gap-2 text-sm font-semibold text-zinc-100">
            <Compass className="h-4 w-4 text-crimson-bright" /> Prioridades adaptativas
            <Insignia tono="teal">reglas pures · sin backend IA</Insignia>
            {prioridades && (
              <Insignia tono={prioridades.ventana_abierta ? "esmeralda" : "ambar"}>
                ventana {prioridades.ventana_abierta ? "abierta" : "cerrada"}
              </Insignia>
            )}
          </p>
          <Button variant="outline" size="sm" className="border-line text-zinc-300 hover:bg-panel"
                  onClick={() => cargarPrioridades().catch(() => undefined)}>
            <RefreshCw className="mr-1 h-3.5 w-3.5" /> Actualizar
          </Button>
        </div>
        {!prioridades || prioridades.prioridades.length === 0 ? (
          <p className="text-sm text-zinc-500">
            Sin prioridades pendientes: la superficie descubierta está cubierta o el caso no ha arrancado.
          </p>
        ) : (
          <div className="space-y-2">
            <AnimatePresence initial={false}>
              {prioridades.prioridades.map((p, i) => (
                <motion.div
                  key={`${p.herramienta}-${p.objetivo}`}
                  initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: i * 0.04 }}
                  className={cn(
                    "rounded-lg border p-3",
                    p.estado === "pospuesta_ventana_cerrada"
                      ? "border-amber-500/25 bg-amber-500/5"
                      : "border-line bg-panel",
                  )}
                >
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      {p.estado === "pospuesta_ventana_cerrada"
                        ? <Clock className="h-3.5 w-3.5 text-amber-400" />
                        : <ListChecks className="h-3.5 w-3.5 text-emerald-500" />}
                      <span className="font-mono text-xs text-zinc-200">{p.herramienta}</span>
                      <span className="text-xs text-zinc-500">→ {p.objetivo || "—"}</span>
                      <Insignia tono="slate">F {p.fase_sugerida}</Insignia>
                      {p.estado === "pospuesta_ventana_cerrada" && (
                        <Insignia tono="ambar">pospuesta: ventana cerrada</Insignia>
                      )}
                      {p.estado === "canal_fase" && (
                        <Insignia tono="esmeralda">canal de fase</Insignia>
                      )}
                    </div>
                    <BarraConfianza valor={p.confianza} />
                  </div>
                  <p className="mt-1.5 text-xs leading-relaxed text-zinc-500">{p.justificacion}</p>
                </motion.div>
              ))}
            </AnimatePresence>
          </div>
        )}
      </Tarjeta>

      {/* PLAN Y REFLEXIÓN CON IA */}
      <div className="grid gap-4 lg:grid-cols-2">
        <Tarjeta className="p-4">
          <div className="mb-3 flex items-center justify-between gap-2">
            <p className="flex flex-wrap items-center gap-2 text-sm font-semibold text-zinc-100">
              <Sparkles className="h-4 w-4 text-crimson-bright" /> Plan de fase (IA)
            </p>
            <Button size="sm" className="bg-crimson text-white hover:bg-crimson/85"
                    onClick={() => generarPlan().catch(() => undefined)}
                    disabled={!!ocupado}>
              {ocupado === "plan"
                ? <Loader2 className="mr-1 h-3.5 w-3.5 animate-spin" />
                : <Sparkles className="mr-1 h-3.5 w-3.5" />} Generar
            </Button>
          </div>
          {!plan ? (
            <p className="text-xs leading-relaxed text-zinc-500">
              El planificador IA propone pasos adaptados a la cobertura real, con
              confianza por paso. Sin backend configurado, el botón devuelve el
              requisito exacto (nunca un plan fingido).
            </p>
          ) : (
            <div className="space-y-2">
              <p className="text-[11px] text-zinc-500">
                {plan.modelo} · {plan.tokens} tokens · {plan.pasos.length} pasos
                {plan.descartados.length > 0 && (
                  <> · <b className="text-amber-400">{plan.descartados.length} descartado(s) fuera de catálogo</b></>
                )}
              </p>
              {plan.pasos.map((paso, i) => (
                <motion.div
                  key={`${plan.id}-${paso.orden}`}
                  initial={{ opacity: 0, x: -8 }} animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: i * 0.05 }}
                  className="rounded-lg border border-line bg-panel p-3"
                >
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <span className="rounded bg-raised px-1.5 py-0.5 font-mono text-[11px] text-zinc-400">
                        #{paso.orden}
                      </span>
                      <span className="font-mono text-xs text-zinc-200">{paso.herramienta}</span>
                      <Insignia tono={paso.intrusivo ? "ambar" : "esmeralda"}>
                        {paso.intrusivo ? "activo" : "pasivo"}
                      </Insignia>
                    </div>
                    <BarraConfianza valor={paso.confianza} />
                  </div>
                  <p className="mt-1.5 text-xs leading-relaxed text-zinc-500">
                    <b className="text-zinc-400">{paso.objetivo || "—"}</b> — {paso.justificacion}
                  </p>
                </motion.div>
              ))}
              <p className="border-t border-line pt-2 text-[11px] leading-relaxed text-zinc-600">
                {plan.nota}
              </p>
            </div>
          )}
        </Tarjeta>

        <Tarjeta className="p-4">
          <div className="mb-3 flex items-center justify-between gap-2">
            <p className="flex flex-wrap items-center gap-2 text-sm font-semibold text-zinc-100">
              <Brain className="h-4 w-4 text-crimson-bright" /> Reflexión de fase (IA)
            </p>
            <Button size="sm" variant="outline" className="border-line text-zinc-300 hover:bg-panel"
                    onClick={() => generarReflexion().catch(() => undefined)}
                    disabled={!!ocupado}>
              {ocupado === "reflexion"
                ? <Loader2 className="mr-1 h-3.5 w-3.5 animate-spin" />
                : <Brain className="mr-1 h-3.5 w-3.5" />} Reflexionar
            </Button>
          </div>
          {!reflexion ? (
            <p className="text-xs leading-relaxed text-zinc-500">
              La autocrítica evalúa la fase en curso SOLO con datos reales:
              observaciones, huecos, hipótesis con confianza y siguientes pasos.
            </p>
          ) : (
            <div className="space-y-2">
              <p className="text-[11px] text-zinc-500">
                {reflexion.modelo} · {reflexion.tokens} tokens
                {reflexion.confianza_media !== null && (
                  <> · confianza media {Math.round(reflexion.confianza_media * 100)}%</>
                )}
              </p>
              <pre className="max-h-72 overflow-y-auto whitespace-pre-wrap rounded-lg border border-line bg-panel p-3 text-xs leading-relaxed text-zinc-300">
                {reflexion.reflexion}
              </pre>
            </div>
          )}
        </Tarjeta>
      </div>

      {/* TRAZAS PERSISTIDAS */}
      <Tarjeta className="p-4">
        <p className="mb-3 flex flex-wrap items-center gap-2 text-sm font-semibold text-zinc-100">
          <Hash className="h-4 w-4 text-crimson-bright" /> Trazas de razonamiento
          <Insignia tono="slate">{trazas?.length ?? 0} con hash de integridad</Insignia>
        </p>
        {!trazas || trazas.length === 0 ? (
          <p className="text-sm text-zinc-500">Sin trazas todavía: genera un plan o una reflexión.</p>
        ) : (
          <div className="space-y-1.5">
            {trazas.slice(0, 12).map((t) => (
              <div key={t.id}
                   className="flex flex-wrap items-center justify-between gap-2 rounded border border-line bg-panel px-3 py-2 text-[11px]">
                <div className="flex items-center gap-2">
                  <Insignia tono={t.tipo === "plan_fase" ? "crimson" : "teal"}>
                    {t.tipo === "plan_fase" ? "plan" : "reflexión"}
                  </Insignia>
                  <span className="font-mono text-zinc-400">{t.fase}</span>
                  <span className="text-zinc-600">{t.modelo}</span>
                </div>
                <div className="flex items-center gap-3 text-zinc-600">
                  <span>{t.tokens_entrada + t.tokens_salida} tokens</span>
                  <span className="hidden font-mono sm:inline" title={t.salida_hash}>
                    {t.salida_hash.slice(0, 10)}…
                  </span>
                  <span>{new Date(t.creado_en).toLocaleString("es-ES")}</span>
                </div>
              </div>
            ))}
          </div>
        )}
      </Tarjeta>
    </div>
  );
}
