"use client";

/**
 * Vista Objetivos: superficie de ataque observada durante el engagement.
 * Cada activo descubierto/confirmado/explotado queda catalogado aquí con su
 * fase, técnica ATT&CK y estado de higiene al cierre.
 */

import { useMemo, useState } from "react";
import { motion } from "framer-motion";
import {
  CalendarClock, Crosshair, Globe, KeyRound, Network, Route, Server, Users,
} from "lucide-react";
import { Tarjeta, Insignia, TituloSeccion, Vacio, Entrada, FiltroSegmentado } from "@/components/consola/ui";
import { VistaGrafo } from "@/components/consola/grafo";
import { usarConsola } from "@/lib/store";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  ETIQUETA_ESTADO_OBJETIVO,
  ETIQUETA_FASE,
  ETIQUETA_OBJETIVO,
  EstadoObjetivo,
  TipoObjetivo,
} from "@/lib/tipos";
import { cn } from "@/lib/utils";

const ICONO_TIPO: Record<TipoObjetivo, React.ComponentType<{ className?: string }>> = {
  dominio: Globe,
  host: Server,
  servicio: Network,
  credencial: KeyRound,
  ruta: Route,
  activo_humano: Users,
};

const ESTILO_ESTADO: Record<EstadoObjetivo, string> = {
  descubierto: "bg-zinc-500/12 text-zinc-300 border-zinc-500/30",
  confirmado: "bg-teal-500/12 text-teal-300 border-teal-500/30",
  riesgo: "bg-amber-500/12 text-amber-300 border-amber-500/30",
  explotado: "bg-crimson/15 text-red-300 border-crimson/35",
  neutralizado: "bg-emerald-500/12 text-emerald-300 border-emerald-500/30",
};

const ANILLO_ESTADO: Record<EstadoObjetivo, string> = {
  descubierto: "ring-zinc-600/30",
  confirmado: "ring-teal-500/25",
  riesgo: "ring-amber-500/25",
  explotado: "ring-crimson/30",
  neutralizado: "ring-emerald-500/25",
};

export function VistaObjetivos() {
  const objetivos = usarConsola((s) => s.objetivos);
  const dif = usarConsola((s) => s.difSuperficie);
  const difOcupado = usarConsola((s) => s.difOcupado);
  const calcularDif = usarConsola((s) => s.calcularDif);
  const limpiarDif = usarConsola((s) => s.limpiarDif);
  const [filtro, setFiltro] = useState<string>("todos");
  const [difDesde, setDifDesde] = useState<string>("");
  const [vista, setVista] = useState<"lista" | "grafo">("lista");

  const presentes = useMemo(() => {
    const set = new Set<EstadoObjetivo>();
    for (const o of objetivos) set.add(o.estado);
    const orden: EstadoObjetivo[] = ["explotado", "riesgo", "confirmado", "descubierto", "neutralizado"];
    return orden.filter((e) => set.has(e));
  }, [objetivos]);

  const filtrados = useMemo(
    () => (filtro === "todos" ? objetivos : objetivos.filter((o) => o.estado === filtro)),
    [objetivos, filtro],
  );

  const criticos = objetivos.filter((o) => o.severidad === "critica").length;

  if (objetivos.length === 0) {
    return (
      <div>
        <TituloSeccion
          titulo="Superficie de ataque"
          descripcion="Catálogo vivo de activos descubiertos durante el engagement"
        />
        <Vacio mensaje="La superficie se poblará desde F1 (OSINT) a medida que el agente descubra activos" />
      </div>
    );
  }

  return (
    <div className="space-y-5">
      <TituloSeccion
        titulo={`Superficie de ataque (${objetivos.length} activos)`}
        descripcion="Catálogo vivo de la superficie observada: cada activo con su fase de descubrimiento, técnica ATT&CK y estado de higiene"
      />

      {/* Resumen de estados + conmutador de vista */}
      <div className="flex flex-wrap items-center justify-between gap-2">
        <FiltroSegmentado
          grupo="objetivos"
          valor={filtro}
          onChange={setFiltro}
          opciones={[
            { valor: "todos", etiqueta: `todos · ${objetivos.length}` },
            ...presentes.map((e) => ({ valor: e, etiqueta: `${ETIQUETA_ESTADO_OBJETIVO[e].toLowerCase()} · ${objetivos.filter((o) => o.estado === e).length}` })),
          ]}
        />
        <div className="flex items-center gap-2">
          <FiltroSegmentado
            grupo="vista-objetivos"
            valor={vista}
            onChange={(v) => setVista(v as "lista" | "grafo")}
            opciones={[
              { valor: "lista", etiqueta: "lista" },
              { valor: "grafo", etiqueta: "grafo" },
            ]}
          />
          {criticos > 0 && (
            <Insignia tono="crimson">
              <Crosshair className="h-3 w-3" /> {criticos}
            </Insignia>
          )}
        </div>
      </div>

      <Tarjeta className="p-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="space-y-1">
            <p className="flex items-center gap-2 text-sm font-semibold text-zinc-100">
              <CalendarClock className="h-4 w-4 text-crimson-bright" /> Diferencial de superficie
            </p>
            <p className="text-xs text-zinc-500">
              Activos NUEVOS desde la fecha que elijas: qué cambió en la superficie
              entre dos repasos del caso, con I/O real y sin datos inventados.
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <Input
              type="date"
              value={difDesde}
              onChange={(e) => setDifDesde(e.target.value)}
              className="w-[150px] border-line bg-panel text-xs text-zinc-200"
            />
            <Button
              size="sm" variant="outline"
              className="border-line text-zinc-200 hover:bg-panel hover:text-zinc-100"
              disabled={!difDesde || difOcupado}
              onClick={() => calcularDif(difDesde).catch(() => undefined)}
            >
              Calcular diferencial
            </Button>
            {dif && (
              <Button size="sm" variant="ghost" className="text-zinc-500 hover:bg-panel hover:text-zinc-200"
                      onClick={limpiarDif}>
                Cerrar
              </Button>
            )}
          </div>
        </div>
        {dif && (
          <div className="mt-3 space-y-2 border-t border-line pt-3">
            <div className="flex flex-wrap items-center gap-2 text-xs text-zinc-400">
              <Insignia tono={dif.resumen.nuevos > 0 ? "ambar" : "teal"}>
                {dif.resumen.nuevos} nuevos
              </Insignia>
              <span>desde {dif.desde?.slice(0, 10)} · total superficie: {dif.total_superficie}</span>
              {Object.entries(dif.resumen.por_tipo).map(([tipo, n]) => (
                <Insignia key={tipo} tono="slate">{ETIQUETA_OBJETIVO[tipo as TipoObjetivo] ?? tipo}: {n}</Insignia>
              ))}
            </div>
            {dif.nuevos.length > 0 ? (
              <div className="max-h-56 space-y-1 overflow-y-auto pr-1">
                {dif.nuevos.map((o) => (
                  <div key={o.id} className="flex items-center justify-between gap-2 rounded-md border border-line bg-panel/60 px-2.5 py-1.5">
                    <span className="truncate font-mono text-[11px] text-zinc-200" title={o.nombre}>{o.nombre}</span>
                    <span className={cn("shrink-0 rounded border px-1.5 py-0.5 text-[10px]", ESTILO_ESTADO[o.estado])}>
                      {ETIQUETA_ESTADO_OBJETIVO[o.estado]}
                    </span>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-xs text-zinc-600">Sin activos nuevos en el intervalo consultado.</p>
            )}
          </div>
        )}
      </Tarjeta>

      {vista === "grafo" ? (
        <VistaGrafo />
      ) : (
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-3">
        {filtrados.map((o, i) => {
          const Icono = ICONO_TIPO[o.tipo];
          return (
            <motion.div
              key={o.id}
              layout
              initial={{ opacity: 0, scale: 0.96 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ duration: 0.3, delay: Math.min(i * 0.03, 0.3) }}
            >
              <Tarjeta
                className={cn(
                  "group h-full p-4 transition-all duration-300 hover:border-line-strong hover:shadow-[0_0_20px_-8px] hover:shadow-crimson/20",
                )}
              >
                <div className="flex items-start justify-between gap-2">
                  <span
                    className={cn(
                      "flex h-8 w-8 shrink-0 items-center justify-center rounded-lg ring-1 transition-transform duration-300 group-hover:scale-105",
                      "bg-ink/70",
                      ANILLO_ESTADO[o.estado],
                    )}
                  >
                    <Icono className={cn("h-4 w-4", o.estado === "explotado" ? "text-red-300" : o.estado === "riesgo" ? "text-amber-300" : o.estado === "confirmado" ? "text-teal-300" : o.estado === "neutralizado" ? "text-emerald-300" : "text-zinc-400")} />
                  </span>
                  <span className={cn("rounded-md border px-1.5 py-0.5 text-[10px] font-medium", ESTILO_ESTADO[o.estado])}>
                    {ETIQUETA_ESTADO_OBJETIVO[o.estado]}
                  </span>
                </div>
                <p className="mt-2.5 truncate font-mono text-[12px] font-semibold text-zinc-100" title={o.nombre}>
                  {o.nombre}
                </p>
                <p className="mt-1 line-clamp-2 min-h-8 text-[11px] leading-relaxed text-zinc-500">{o.detalle}</p>
                <div className="mt-2.5 flex flex-wrap items-center gap-1.5 border-t border-line pt-2.5">
                  <Insignia tono="slate">{ETIQUETA_OBJETIVO[o.tipo]}</Insignia>
                  <Insignia tono="crimson">{ETIQUETA_FASE[o.fase]}</Insignia>
                  {o.tecnica_mitre && (
                    <code className="rounded border border-line bg-raised px-1.5 py-0.5 font-mono text-[9px] text-zinc-400">
                      {o.tecnica_mitre}
                    </code>
                  )}
                </div>
              </Tarjeta>
            </motion.div>
          );
        })}
      </div>
      )}

      <Entrada indice={1}>
        <p className="text-center font-mono text-[10px] text-zinc-600">
          superficie observada con herramientas reales acotadas al ROE · al cierre, los explotados pasan a <span className="text-emerald-400">neutralizado</span> mediante higiene documentada
        </p>
      </Entrada>
    </div>
  );
}
