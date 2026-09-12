"use client";

/** Primitivas visuales de la consola — sistema de diseño OrquestaRT. */

import { motion } from "framer-motion";
import { cn } from "@/lib/utils";
import { Severidad } from "@/lib/tipos";

/** Filtro segmentado compacto (píldoras con indicador animado). */
export function FiltroSegmentado({
  grupo,
  opciones,
  valor,
  onChange,
}: {
  grupo: string;
  opciones: { valor: string; etiqueta: string }[];
  valor: string;
  onChange: (v: string) => void;
}) {
  return (
    <div className="flex flex-wrap items-center gap-1 rounded-lg border border-line bg-ink/60 p-1" role="group" aria-label="Filtro de la lista">
      {opciones.map((o) => {
        const activo = valor === o.valor;
        return (
          <button
            key={o.valor}
            onClick={() => onChange(o.valor)}
            aria-pressed={activo}
            className={cn(
              "relative rounded-md px-2.5 py-1 font-mono text-[10px] uppercase tracking-[0.1em] transition-colors",
              activo ? "text-zinc-100" : "text-zinc-500 hover:text-zinc-300",
            )}
          >
            {activo && (
              <motion.span
                layoutId={`seg-${grupo}`}
                className="absolute inset-0 rounded-md border border-line-strong bg-raised"
                transition={{ type: "spring", bounce: 0.2, duration: 0.4 }}
              />
            )}
            <span className="relative">{o.etiqueta}</span>
          </button>
        );
      })}
    </div>
  );
}

/** Copia texto al portapapeles con fallback y devuelve true si tuvo éxito. */
export async function copiarTexto(texto: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(texto);
    return true;
  } catch {
    return false;
  }
}

/** Aparición sutil y escalonada para listas y tarjetas. */
export function Entrada({
  children,
  className,
  indice = 0,
}: {
  children: React.ReactNode;
  className?: string;
  indice?: number;
}) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.35, delay: Math.min(indice * 0.05, 0.4), ease: [0.21, 0.47, 0.32, 0.98] }}
      className={className}
    >
      {children}
    </motion.div>
  );
}

export function Tarjeta({
  className,
  children,
}: {
  className?: string;
  children: React.ReactNode;
}) {
  return (
    <div
      className={cn(
        "surface rounded-xl border border-line p-5 shadow-[0_1px_0_0_rgba(255,255,255,0.03)_inset]",
        className,
      )}
    >
      {children}
    </div>
  );
}

const COLORES_SEVERIDAD: Record<Severidad, string> = {
  critica: "bg-crimson/15 text-red-300 border-crimson/35",
  alta: "bg-orange-500/12 text-orange-300 border-orange-500/30",
  media: "bg-amber-500/12 text-amber-300 border-amber-500/30",
  baja: "bg-teal-500/12 text-teal-300 border-teal-500/30",
  informativa: "bg-zinc-500/12 text-zinc-300 border-zinc-500/30",
};

const ETIQUETA_SEVERIDAD: Record<Severidad, string> = {
  critica: "Crítica",
  alta: "Alta",
  media: "Media",
  baja: "Baja",
  informativa: "Informativa",
};

export function InsigniaSeveridad({ severidad }: { severidad: Severidad }) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-md border px-2 py-0.5 text-[11px] font-medium whitespace-nowrap",
        COLORES_SEVERIDAD[severidad],
      )}
    >
      {ETIQUETA_SEVERIDAD[severidad]}
    </span>
  );
}

export function Insignia({
  children,
  tono = "slate",
  className,
  title,
}: {
  children: React.ReactNode;
  tono?: "slate" | "esmeralda" | "ambar" | "rojo" | "teal" | "crimson";
  className?: string;
  // z2-ronda-10: tooltip nativo — la salud derivada explica su estado
  // (fechas de la última entrega/éxito/fallo) al pasar el ratón, sin
  // ocupar espacio en la tarjeta.
  title?: string;
}) {
  const tonos = {
    slate: "bg-zinc-500/12 text-zinc-300 border-zinc-500/30",
    esmeralda: "bg-emerald-500/12 text-emerald-300 border-emerald-500/30",
    ambar: "bg-amber-500/12 text-amber-300 border-amber-500/30",
    rojo: "bg-red-500/12 text-red-300 border-red-500/30",
    teal: "bg-teal-500/12 text-teal-300 border-teal-500/30",
    crimson: "bg-crimson/15 text-red-300 border-crimson/35",
  };
  return (
    <span
      title={title}
      className={cn(
        "inline-flex items-center gap-1 rounded-md border px-2 py-0.5 text-[11px] font-medium whitespace-nowrap",
        tonos[tono],
        className,
      )}
    >
      {children}
    </span>
  );
}

export function TituloSeccion({
  titulo,
  descripcion,
  accion,
}: {
  titulo: string;
  descripcion?: string;
  accion?: React.ReactNode;
}) {
  return (
    <div className="mb-5 flex flex-wrap items-start justify-between gap-3">
      <div>
        <h2 className="text-base font-semibold tracking-tight text-zinc-100">{titulo}</h2>
        {descripcion && <p className="mt-1 max-w-2xl text-[13px] leading-relaxed text-zinc-500">{descripcion}</p>}
      </div>
      {accion}
    </div>
  );
}

export function Vacio({ mensaje }: { mensaje: string }) {
  return (
    <div className="flex flex-col items-center justify-center rounded-xl border border-dashed border-line-strong bg-panel/40 p-12 text-center">
      <div className="mb-3 h-1 w-8 rounded-full bg-crimson/60" aria-hidden />
      <p className="text-sm text-zinc-500">{mensaje}</p>
    </div>
  );
}

export function barraRuido(valor: number, max = 100) {
  const pct = Math.min(100, (valor / max) * 100);
  if (pct >= 75) return "bg-red-400";
  if (pct >= 50) return "bg-amber-400";
  return "bg-emerald-400";
}
