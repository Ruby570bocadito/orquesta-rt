"use client";

/** Vista Memoria del caso: resumen compactado, búsqueda real, presupuestos por fase y estado del almacén. */

import { useMemo, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  Brain, Database, FileText, ShieldCheck, Trash2, Layers, Search, X,
} from "lucide-react";
import { Tarjeta, Insignia, TituloSeccion } from "@/components/consola/ui";
import { usarConsola } from "@/lib/store";
import { ETIQUETA_FASE, ORDEN_FASES, formatoTokens, FaseId } from "@/lib/tipos";
import { cn } from "@/lib/utils";

const ETIQUETA_TIPO_BUSQUEDA: Record<string, string> = {
  evidencia: "Evidencia",
  hallazgo: "Hallazgo",
  objetivo: "Objetivo",
  auditoria: "Auditoría",
  aprobacion: "Aprobación",
  resumen: "Resumen",
};

function PanelBusqueda() {
  const [consulta, setConsulta] = useState("");
  const buscando = usarConsola((s) => s.buscandoMemoria);
  const resultados = usarConsola((s) => s.resultadosBusqueda);
  const metodo = usarConsola((s) => s.metodoBusqueda);
  const buscar = usarConsola((s) => s.buscarEnMemoria);
  const limpiar = usarConsola((s) => s.limpiarBusqueda);

  const enviar = (e: React.FormEvent) => {
    e.preventDefault();
    if (consulta.trim().length >= 2) buscar(consulta);
  };

  return (
    <Tarjeta>
      <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
        <p className="flex items-center gap-2 text-sm font-semibold text-zinc-100">
          <Search className="h-4 w-4 text-crimson-bright" />
          Búsqueda en la memoria del caso
        </p>
        {metodo && <Insignia tono="teal">{metodo}</Insignia>}
      </div>

      <form onSubmit={enviar} className="flex gap-2">
        <div className="relative flex-1">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-zinc-600" />
          <input
            value={consulta}
            onChange={(e) => setConsulta(e.target.value)}
            placeholder="p. ej. kerberoasting, cabeceras ausentes, backup_adm…"
            className="w-full rounded-lg border border-line bg-raised py-2 pl-8 pr-3 text-[13px] text-zinc-200 placeholder:text-zinc-600 focus:border-crimson/50 focus:outline-none"
            aria-label="Consulta de búsqueda en la memoria"
          />
        </div>
        <button
          type="submit"
          disabled={buscando || consulta.trim().length < 2}
          className="flex h-9 items-center gap-1.5 rounded-lg bg-crimson px-3 text-xs font-semibold text-white transition-colors hover:bg-crimson-bright disabled:cursor-not-allowed disabled:opacity-40"
        >
          {buscando ? (
            <span className="h-3.5 w-3.5 animate-spin rounded-full border-2 border-white/40 border-t-white" />
          ) : (
            "Buscar"
          )}
        </button>
        {resultados && (
          <button
            type="button"
            onClick={() => { limpiar(); setConsulta(""); }}
            className="flex h-9 w-9 items-center justify-center rounded-lg border border-line bg-panel text-zinc-500 transition-colors hover:bg-raised hover:text-zinc-200"
            aria-label="Limpiar búsqueda"
          >
            <X className="h-3.5 w-3.5" />
          </button>
        )}
      </form>

      <AnimatePresence>
        {resultados && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: "auto" }}
            exit={{ opacity: 0, height: 0 }}
            className="overflow-hidden"
          >
            <div className="mt-4 space-y-2">
              {resultados.length === 0 ? (
                <p className="rounded-lg border border-line bg-ink/60 px-3 py-6 text-center font-mono text-xs text-zinc-600">
                  Sin coincidencias en la memoria del caso
                </p>
              ) : (
                resultados.map((r, i) => (
                  <motion.div
                    key={r.id}
                    initial={{ opacity: 0, y: 6 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ duration: 0.25, delay: Math.min(i * 0.03, 0.25) }}
                    className="rounded-lg border border-line bg-ink/60 p-3 transition-colors hover:border-line-strong"
                  >
                    <div className="flex flex-wrap items-center gap-2">
                      <Insignia tono={
                        r.tipo === "hallazgo" ? "rojo" : r.tipo === "evidencia" ? "teal" : "slate"
                      }>
                        {ETIQUETA_TIPO_BUSQUEDA[r.tipo] ?? r.tipo}
                      </Insignia>
                      <span className="text-[13px] font-medium text-zinc-200">{r.titulo}</span>
                      {r.fase && (
                        <span className="font-mono text-[10px] text-zinc-600">
                          {ETIQUETA_FASE[r.fase as FaseId] ?? r.fase}
                        </span>
                      )}
                      <span className="ml-auto font-mono text-[10px] text-zinc-600">
                        score {r.puntuacion.toFixed(3)}
                      </span>
                    </div>
                    <p className="mt-1.5 line-clamp-2 text-xs leading-relaxed text-zinc-400">
                      {r.fragmento}
                    </p>
                  </motion.div>
                ))
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </Tarjeta>
  );
}

export function VistaMemoria() {
  const engagement = usarConsola((s) => s.engagement);
  const resumen = usarConsola((s) => s.resumenAcumulado);
  const hallazgos = usarConsola((s) => s.hallazgos);
  const evidencias = usarConsola((s) => s.evidencias);
  const auditoria = usarConsola((s) => s.auditoria);
  const aprobaciones = usarConsola((s) => s.aprobaciones);
  const usoTokens = usarConsola((s) => s.usoTokens);
  const memoria = usarConsola((s) => s.memoria);

  const consumoPorFase = useMemo(() => {
    const mapa = new Map<string, number>();
    for (const u of usoTokens) {
      mapa.set(u.fase, (mapa.get(u.fase) ?? 0) + u.tokens_entrada + u.tokens_salida);
    }
    return mapa;
  }, [usoTokens]);

  if (!engagement) return null;

  const faseIdx = ORDEN_FASES.indexOf(engagement.fase_actual);

  const filas = ORDEN_FASES.map((fase) => {
    const techo = (engagement.presupuesto_tokens[fase] ?? 0) * 1000;
    const usado = consumoPorFase.get(fase) ?? 0;
    return { fase, techo, usado, pct: techo > 0 ? Math.min(100, (usado / techo) * 100) : 0 };
  });

  return (
    <div className="space-y-5">
      <TituloSeccion
        titulo="Memoria del caso"
        descripcion="Estado compactado del engagement: lo que el grafo recuerda entre fases. Cifrado en reposo, resúmenes jerárquicos y borrado certificado al cierre"
      />

      <div className="grid grid-cols-1 gap-5 lg:grid-cols-3">
        {/* Resumen compactado */}
        <Tarjeta className="lg:col-span-2">
          <div className="mb-4 flex items-center justify-between gap-3">
            <p className="flex items-center gap-2 text-sm font-semibold text-zinc-100">
              <Brain className="h-4 w-4 text-crimson-bright" />
              Resumen compactado del contexto
            </p>
            <Insignia tono="teal">compaction jerárquica</Insignia>
          </div>
          <div className="rounded-lg border border-line bg-ink p-4">
            {resumen ? (
              <p className="whitespace-pre-line text-[13px] leading-relaxed text-zinc-300">{resumen}</p>
            ) : (
              <p className="py-4 text-center font-mono text-xs text-zinc-600">
                El primer resumen aparecerá al completar F1…
              </p>
            )}
          </div>
          <div className="mt-4 grid grid-cols-2 gap-3 sm:grid-cols-4">
            {[
              { etiqueta: "Hallazgos", valor: hallazgos.length, icono: FileText },
              { etiqueta: "Evidencias", valor: evidencias.length, icono: ShieldCheck },
              { etiqueta: "Aprobaciones", valor: aprobaciones.length, icono: Layers },
              { etiqueta: "Eventos", valor: auditoria.length, icono: Database },
            ].map((m) => (
              <div key={m.etiqueta} className="rounded-lg border border-line bg-ink/60 p-3">
                <p className="flex items-center gap-1.5 font-mono text-[9px] uppercase tracking-wider text-zinc-600">
                  <m.icono className="h-3 w-3" /> {m.etiqueta}
                </p>
                <p className="mt-1 text-xl font-semibold tabular-nums text-zinc-100">{m.valor}</p>
              </div>
            ))}
          </div>
        </Tarjeta>

        {/* Estado del almacén */}
        <Tarjeta>
          <p className="flex items-center gap-2 text-sm font-semibold text-zinc-100">
            <Database className="h-4 w-4 text-crimson-bright" />
            Almacén del caso
          </p>
          <dl className="mt-4 space-y-3 text-[13px]">
            <div className="flex items-center justify-between gap-2">
              <dt className="text-zinc-500">Motor</dt>
              <dd className="font-mono text-xs text-zinc-300">SQLite por caso (WAL)</dd>
            </div>
            <div className="flex items-center justify-between gap-2">
              <dt className="text-zinc-500">Cifrado en reposo</dt>
              <dd>
                <Insignia tono={memoria?.cifrado_reposo ? "esmeralda" : "ambar"}>
                  {memoria?.cifrado_reposo ? "CLAVE_CASO activa" : "clave por ruta (dev)"}
                </Insignia>
              </dd>
            </div>
            <div className="flex items-center justify-between gap-2">
              <dt className="text-zinc-500">Tamaño del almacén</dt>
              <dd className="font-mono text-xs text-zinc-300">
                {memoria ? `${(memoria.tamano_db_bytes / 1024).toFixed(1)} KB` : "—"}
              </dd>
            </div>
            <div className="flex items-center justify-between gap-2">
              <dt className="text-zinc-500">Auditoría</dt>
              <dd className="font-mono text-xs text-zinc-300">append-only</dd>
            </div>
            <div className="flex items-center justify-between gap-2">
              <dt className="text-zinc-500">Custodia</dt>
              <dd className="font-mono text-xs text-emerald-300">SHA-256 + HMAC</dd>
            </div>
            <div className="flex items-center justify-between gap-2">
              <dt className="text-zinc-500">Retención</dt>
              <dd className="text-xs text-zinc-300">hasta cierre + {engagement.certificado_borrado ? "borrado" : "viva"}</dd>
            </div>
          </dl>
          <div
            className={cn(
              "mt-5 rounded-lg border p-3",
              engagement.certificado_borrado
                ? "border-emerald-500/30 bg-emerald-500/5"
                : "border-line bg-ink/60",
            )}
          >
            <p className="flex items-start gap-2 text-[11px] leading-relaxed text-zinc-400">
              <Trash2 className={cn("mt-0.5 h-3.5 w-3.5 shrink-0", engagement.certificado_borrado ? "text-emerald-300" : "text-zinc-500")} />
              {engagement.certificado_borrado ? (
                <span>
                  Certificado de borrado emitido <span className="font-mono text-[10px] text-emerald-300/80">{engagement.certificado_borrado}</span>
                </span>
              ) : (
                <span>
                  Al cierre se emite un certificado de borrado: memoria, índices y claves se
                  destruyen salvo el informe y la auditoría pactados en el ROE.
                </span>
              )}
            </p>
          </div>
        </Tarjeta>
      </div>

      {/* Búsqueda real en la memoria del caso */}
      <PanelBusqueda />

      {/* Presupuestos por fase */}
      <Tarjeta>
        <TituloSeccion
          titulo="Presupuesto de tokens por fase"
          descripcion="Techos definidos en el blueprint (cap. 3): fases mecánicas estrechas, explotación y redacción holgadas. El router avisa antes de rebasar"
        />
        <div className="space-y-3">
          {filas.map((f, i) => {
            const pasada = i < faseIdx || engagement.estado_fase === "completada";
            return (
              <motion.div
                key={f.fase}
                initial={{ opacity: 0, x: -8 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ duration: 0.3, delay: Math.min(i * 0.04, 0.3) }}
                className="flex items-center gap-4"
              >
                <span className={cn("w-40 shrink-0 truncate font-mono text-[11px]", pasada ? "text-zinc-400" : i === faseIdx ? "text-zinc-200" : "text-zinc-600")}>
                  {ETIQUETA_FASE[f.fase]}
                </span>
                <div className="h-2 flex-1 overflow-hidden rounded-full bg-zinc-800/70">
                  <motion.div
                    initial={{ width: 0 }}
                    animate={{ width: `${Math.max(f.pct, f.usado > 0 ? 2 : 0)}%` }}
                    transition={{ duration: 0.6, delay: 0.15 + Math.min(i * 0.05, 0.35), ease: [0.16, 1, 0.3, 1] }}
                    className={cn(
                      "h-full rounded-full",
                      f.pct >= 100 ? "bg-crimson" : f.pct >= 70 ? "bg-amber-400" : "bg-teal-400/80",
                    )}
                  />
                </div>
                <span className="w-36 shrink-0 text-right font-mono text-[10px] text-zinc-500">
                  {formatoTokens(f.usado)} / {formatoTokens(f.techo)}
                </span>
              </motion.div>
            );
          })}
        </div>
      </Tarjeta>
    </div>
  );
}
