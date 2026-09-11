"use client";

/** Vistas Coste IA (economía del token) y Cronología (auditoría inmutable). */

import { useMemo, useState } from "react";
import {
  Bar,
  BarChart,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip as ReTooltip,
  XAxis,
  YAxis,
} from "recharts";
import { motion } from "framer-motion";
import { Tarjeta, Insignia, TituloSeccion, Vacio, Entrada, FiltroSegmentado } from "@/components/consola/ui";
import { usarConsola } from "@/lib/store";
import { ETIQUETA_FASE, formatoCoste, formatoTokens } from "@/lib/tipos";
import { Bot, ShieldCheck, User, Cpu, Cloud } from "lucide-react";
import { cn } from "@/lib/utils";

const COLORES_FASE = [
  "#e5484d", "#2dd4bf", "#34d399", "#a3e635", "#fbbf24",
  "#fb923c", "#f87171", "#d8b4fe", "#a1a1aa",
];

export function VistaCoste() {
  const usoTokens = usarConsola((s) => s.usoTokens);

  const porFase = useMemo(() => {
    const mapa = new Map<string, { tokens: number; coste: number }>();
    for (const u of usoTokens) {
      const previo = mapa.get(u.fase) ?? { tokens: 0, coste: 0 };
      mapa.set(u.fase, {
        tokens: previo.tokens + u.tokens_entrada + u.tokens_salida,
        coste: previo.coste + u.coste_usd,
      });
    }
    return Array.from(mapa.entries()).map(([fase, v], i) => ({
      fase: ETIQUETA_FASE[fase as keyof typeof ETIQUETA_FASE] ?? fase,
      corta: (ETIQUETA_FASE[fase as keyof typeof ETIQUETA_FASE] ?? fase).split(" · ")[0],
      ...v,
      color: COLORES_FASE[i % COLORES_FASE.length],
    }));
  }, [usoTokens]);

  const porModelo = useMemo(() => {
    const mapa = new Map<string, { tokens: number; coste: number; llamadas: number; cache: number; tipo: string }>();
    for (const u of usoTokens) {
      const previo = mapa.get(u.modelo) ?? { tokens: 0, coste: 0, llamadas: 0, cache: 0, tipo: u.tipo };
      mapa.set(u.modelo, {
        tokens: previo.tokens + u.tokens_entrada + u.tokens_salida,
        coste: previo.coste + u.coste_usd,
        llamadas: previo.llamadas + 1,
        cache: previo.cache + (u.cache_hit ? 1 : 0),
        tipo: previo.tipo,
      });
    }
    return Array.from(mapa.entries()).map(([modelo, v]) => ({ modelo, ...v }));
  }, [usoTokens]);

  const totalTokens = porFase.reduce((acc, f) => acc + f.tokens, 0);
  const totalCoste = porFase.reduce((acc, f) => acc + f.coste, 0);
  const localTokens = porModelo.filter((m) => m.tipo === "local").reduce((a, m) => a + m.tokens, 0);
  const shareLocal = totalTokens > 0 ? Math.round((localTokens / totalTokens) * 100) : 0;
  const llamadasCache = usoTokens.filter((u) => u.cache_hit).length;

  if (usoTokens.length === 0) {
    return (
      <div>
        <TituloSeccion titulo="Economía del token" descripcion="El router enviará cada tarea al modelo mínimo suficiente" />
        <Vacio mensaje="Sin llamadas registradas todavía" />
      </div>
    );
  }

  return (
    <div className="space-y-5">
      <div className="grid grid-cols-1 gap-5 lg:grid-cols-3">
        <Entrada className="lg:col-span-2">
          <Tarjeta className="h-full">
            <TituloSeccion
              titulo="Consumo por fase"
              descripcion="Techos por fase (blueprint cap. 3): fases mecánicas estrechas, explotación y redacción holgadas"
            />
            <div className="h-64 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={porFase} margin={{ top: 8, right: 8, left: 0, bottom: 0 }}>
                  <XAxis dataKey="corta" tick={{ fill: "#8b8b96", fontSize: 11 }} axisLine={{ stroke: "#27272a" }} tickLine={false} />
                  <YAxis tick={{ fill: "#71717a", fontSize: 11 }} axisLine={false} tickLine={false} tickFormatter={(v: number) => `${(v / 1000).toFixed(0)}K`} />
                  <ReTooltip
                    cursor={{ fill: "rgba(255,255,255,0.04)" }}
                    contentStyle={{ background: "#121216", border: "1px solid #27272a", borderRadius: 10, fontSize: 12, color: "#e4e4e7" }}
                    formatter={(valor) => [`${formatoTokens(Number(valor))} tokens`, "Consumo"]}
                  />
                  <Bar dataKey="tokens" radius={[5, 5, 0, 0]}>
                    {porFase.map((f) => (
                      <Cell key={f.fase} fill={f.color} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          </Tarjeta>
        </Entrada>

        <Entrada indice={1}>
          <Tarjeta className="h-full">
            <TituloSeccion titulo="Reparto local vs frontera" descripcion="Router semántico: la mayoría de llamadas en LLM local" />
            <div className="h-40 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={[
                      { name: "Local", value: localTokens, fill: "#34d399" },
                      { name: "Frontera", value: totalTokens - localTokens, fill: "#fbbf24" },
                    ]}
                    dataKey="value"
                    innerRadius={44}
                    outerRadius={66}
                    strokeWidth={0}
                  />
                  <ReTooltip
                    contentStyle={{ background: "#121216", border: "1px solid #27272a", borderRadius: 10, fontSize: 12, color: "#e4e4e7" }}
                    formatter={(valor, nombre) => [formatoTokens(Number(valor)), String(nombre)]}
                  />
                </PieChart>
              </ResponsiveContainer>
            </div>
            <div className="space-y-1.5 text-xs">
              <p className="flex items-center justify-between">
                <span className="flex items-center gap-1.5 text-zinc-400"><Cpu className="h-3.5 w-3.5 text-emerald-400" /> Local (0 $/llamada)</span>
                <span className="font-semibold tabular-nums text-zinc-200">{shareLocal}%</span>
              </p>
              <p className="flex items-center justify-between">
                <span className="flex items-center gap-1.5 text-zinc-400"><Cloud className="h-3.5 w-3.5 text-amber-300" /> Frontera (decisiones críticas)</span>
                <span className="font-semibold tabular-nums text-zinc-200">{100 - shareLocal}%</span>
              </p>
              <p className="pt-1.5 font-mono text-[10px] text-zinc-600">
                caché en {llamadasCache}/{usoTokens.length} llamadas · coste total {formatoCoste(totalCoste)}
              </p>
            </div>
          </Tarjeta>
        </Entrada>
      </div>

      <Entrada indice={2}>
        <Tarjeta>
          <TituloSeccion titulo="Detalle por modelo" descripcion="Contabilidad exacta que alimenta el margen del producto on-prem" />
          <div className="overflow-x-auto">
            <table className="w-full min-w-max text-sm">
              <thead>
                <tr className="border-b border-line text-left font-mono text-[10px] uppercase tracking-[0.14em] text-zinc-500">
                  <th className="pb-2.5 pr-4 font-medium">Modelo</th>
                  <th className="pb-2.5 pr-4 font-medium">Clase</th>
                  <th className="pb-2.5 pr-4 font-medium">Llamadas</th>
                  <th className="pb-2.5 pr-4 font-medium">Tokens</th>
                  <th className="pb-2.5 pr-4 font-medium">Caché</th>
                  <th className="pb-2.5 font-medium text-right">Coste</th>
                </tr>
              </thead>
              <tbody>
                {porModelo.map((m) => (
                  <tr key={m.modelo} className="border-b border-line/50 last:border-0 transition-colors hover:bg-white/[0.02]">
                    <td className="py-2.5 pr-4 font-mono text-xs text-zinc-200">{m.modelo}</td>
                    <td className="py-2.5 pr-4">
                      <Insignia tono={m.tipo === "local" ? "esmeralda" : "ambar"}>{m.tipo}</Insignia>
                    </td>
                    <td className="py-2.5 pr-4 tabular-nums text-zinc-300">{m.llamadas}</td>
                    <td className="py-2.5 pr-4 tabular-nums text-zinc-300">{formatoTokens(m.tokens)}</td>
                    <td className="py-2.5 pr-4 tabular-nums text-zinc-400">{m.cache}/{m.llamadas}</td>
                    <td className="py-2.5 text-right font-semibold tabular-nums text-zinc-200">{formatoCoste(m.coste)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Tarjeta>
      </Entrada>
    </div>
  );
}

const ICONO_ACTOR = {
  agente: <Bot className="h-3.5 w-3.5 text-teal-300" />,
  humano: <User className="h-3.5 w-3.5 text-emerald-300" />,
  sistema: <ShieldCheck className="h-3.5 w-3.5 text-zinc-400" />,
};

export function VistaCronologia() {
  const auditoria = usarConsola((s) => s.auditoria);
  const [filtro, setFiltro] = useState("todos");

  const lista = useMemo(
    () => (filtro === "todos" ? auditoria : auditoria.filter((ev) => ev.actor === filtro)),
    [auditoria, filtro],
  );

  if (auditoria.length === 0) {
    return (
      <div>
        <TituloSeccion titulo="Cronología de auditoría" descripcion="Registro inmutable: actor, acción, resultado" />
        <Vacio mensaje="Sin eventos registrados todavía" />
      </div>
    );
  }

  return (
    <div>
      <TituloSeccion
        titulo={`Cronología de auditoría (${auditoria.length})`}
        descripcion="Append-only: nada se edita ni se borra. Es la columna vertebral del informe y de la defensa legal"
      />
      <div className="mb-4 flex flex-wrap items-center gap-2">
        <FiltroSegmentado
          grupo="cronologia"
          valor={filtro}
          onChange={setFiltro}
          opciones={[
            { valor: "todos", etiqueta: `todos · ${auditoria.length}` },
            ...(auditoria.some((e) => e.actor === "agente") ? [{ valor: "agente", etiqueta: `agente · ${auditoria.filter((e) => e.actor === "agente").length}` }] : []),
            ...(auditoria.some((e) => e.actor === "humano") ? [{ valor: "humano", etiqueta: `humano · ${auditoria.filter((e) => e.actor === "humano").length}` }] : []),
            ...(auditoria.some((e) => e.actor === "sistema") ? [{ valor: "sistema", etiqueta: `sistema · ${auditoria.filter((e) => e.actor === "sistema").length}` }] : []),
          ]}
        />
      </div>
      <ol className="relative ml-3 space-y-1 border-l border-line">
        {lista.map((ev, i) => (
          <motion.li
            key={ev.id}
            initial={{ opacity: 0, x: -8 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.28, delay: Math.min(i * 0.03, 0.35) }}
            className="relative py-1.5 pl-6"
          >
            <span
              className={cn(
                "absolute -left-[4.5px] top-[19px] h-2 w-2 rounded-full border-2 border-ink",
                ev.actor === "humano" ? "bg-emerald-400" :
                ev.guardrail === "requiere_aprobacion" ? "bg-amber-400" :
                ev.guardrail === "denegar" ? "bg-crimson-bright" :
                "bg-zinc-600",
              )}
              aria-hidden
            />
            <div className={cn(
              "rounded-lg border px-4 py-2.5",
              ev.actor === "humano" ? "border-emerald-500/25 bg-emerald-500/[0.05]" :
              ev.guardrail === "requiere_aprobacion" ? "border-violet-500/25 bg-violet-500/[0.05]" :
              ev.guardrail === "denegar" ? "border-crimson/30 bg-crimson/[0.05]" :
              "border-line bg-ink/60",
            )}>
              <div className="flex flex-wrap items-center gap-2">
                <span className="flex items-center gap-1.5 font-mono text-[10px] font-semibold uppercase tracking-[0.14em] text-zinc-500">
                  {ICONO_ACTOR[ev.actor]} {ev.actor}
                </span>
                <code className="font-mono text-xs text-zinc-300">{ev.accion}</code>
                {ev.guardrail && (
                  <Insignia tono={ev.guardrail === "permitir" ? "esmeralda" : ev.guardrail === "denegar" ? "rojo" : "ambar"}>
                    boundary: {ev.guardrail.replace("_", " ")}
                  </Insignia>
                )}
                <span className="ml-auto font-mono text-[10px] text-zinc-600">
                  {new Date(ev.creado_en).toLocaleTimeString("es-ES")}
                </span>
              </div>
              {ev.detalle && <p className="mt-1 text-xs leading-relaxed text-zinc-400">{ev.detalle}</p>}
              <p className="mt-1 flex flex-wrap items-center gap-2 font-mono text-[10px] text-zinc-600">
                {ev.herramienta && <span>herramienta: <code className="text-zinc-500">{ev.herramienta}</code></span>}
                <span>resultado: <span className={ev.resultado === "ok" || ev.resultado === "aprobada" ? "text-emerald-400" : ev.resultado === "rechazada" ? "text-crimson-bright" : "text-zinc-400"}>{ev.resultado}</span></span>
              </p>
            </div>
          </motion.li>
        ))}
      </ol>
    </div>
  );
}
