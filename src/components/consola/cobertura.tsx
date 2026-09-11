"use client";

/**
 * Vista Cobertura ATT&CK (v16): analítica agregada ENTRE campañas.
 * Matriz técnica × campaña (heatmap estándar de los gestores de cobertura),
 * técnicas recurrentes (debilidades que se repiten entre engagements) y
 * cobertura de detección por campaña (patrón VECTR: detectado / no detectado
 * / prevenido). SOLO técnicas con ID ATT&CK válido registradas de verdad:
 * la matriz vacía significa que todavía no hay técnicas ejercitadas, no
 * un error. La lectura es de solo-lectura sobre todos los casos.
 */

import { useEffect, useState } from "react";
import {
  Download, Grid3X3, Loader2, RefreshCw, ShieldAlert, ShieldCheck, ShieldX,
} from "lucide-react";
import { Tarjeta, Insignia, TituloSeccion, Vacio } from "@/components/consola/ui";
import { Button } from "@/components/ui/button";
import { usarConsola, descargarCoberturaAttackCsv } from "@/lib/store";
import { cn } from "@/lib/utils";

// Mismo lenguaje de color que la capa Navigator y el informe (consistencia
// visual de entregables): la severidad MÁXIMA pinta la celda.
const COLOR_SEV: Record<string, string> = {
  critica: "#b91c1c", alta: "#c2410c", media: "#a16207",
  baja: "#3f6212", informativa: "#52525b",
};

function Pct({ valor }: { valor: number | null }) {
  if (valor === null) return <span className="text-zinc-600">—</span>;
  const tono = valor >= 70 ? "text-emerald-300" : valor >= 40 ? "text-amber-300" : "text-red-300";
  return <span className={cn("font-semibold tabular-nums", tono)}>{valor}%</span>;
}

export function VistaCobertura() {
  const coberturaAttack = usarConsola((s) => s.coberturaAttack);
  const ocupada = usarConsola((s) => s.coberturaAttackOcupada);
  const cargarCoberturaAttack = usarConsola((s) => s.cargarCoberturaAttack);
  const [error, setError] = useState<string | null>(null);
  const [descargando, setDescargando] = useState(false);

  useEffect(() => {
    cargarCoberturaAttack().catch((e: Error) => setError(e.message));
  }, [cargarCoberturaAttack]);

  const exportarCsv = async () => {
    setDescargando(true);
    try {
      await descargarCoberturaAttackCsv();
    } finally {
      setDescargando(false);
    }
  };

  if (error) {
    return (
      <div>
        <TituloSeccion titulo="Cobertura ATT&CK entre campañas" descripcion="Analítica agregada de todos los casos del despliegue" />
        <Vacio mensaje={`No se pudo calcular la cobertura: ${error}`} />
      </div>
    );
  }

  if (!coberturaAttack) {
    return (
      <div className="flex items-center gap-2 py-10 text-sm text-zinc-500">
        <Loader2 className="h-4 w-4 animate-spin" /> Calculando cobertura entre campañas…
      </div>
    );
  }

  const t = coberturaAttack.totales;
  const campanas = coberturaAttack.campañas;
  const hayDatos = t.tecnicas_distintas > 0;

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <TituloSeccion
          titulo="Cobertura ATT&CK entre campañas"
          descripcion="Matriz técnica × campaña agregada de TODOS los casos, técnicas recurrentes y cobertura de detección (patrón VECTR). Solo técnicas realmente observadas o intentadas."
        />
        <div className="flex gap-2">
          <Button
            variant="outline" size="sm"
            className="h-8 gap-1.5 border-line bg-panel text-xs text-zinc-300 hover:bg-raised"
            onClick={() => cargarCoberturaAttack().catch((e: Error) => setError(e.message))}
            disabled={ocupada}
          >
            {ocupada ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <RefreshCw className="h-3.5 w-3.5" />}
            Actualizar
          </Button>
          <Button
            variant="outline" size="sm"
            className="h-8 gap-1.5 border-line bg-panel text-xs text-zinc-300 hover:bg-raised"
            onClick={exportarCsv} disabled={descargando || !hayDatos}
          >
            {descargando ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Download className="h-3.5 w-3.5" />}
            CSV
          </Button>
        </div>
      </div>

      {!hayDatos ? (
        <Vacio mensaje="Sin técnicas ATT&CK registradas todavía: la matriz se puebla con los hallazgos y aprobaciones reales de cada campaña" />
      ) : (
        <>
          {/* --- KPIs del programa ------------------------------------ */}
          <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
            {[
              { etiqueta: "Campañas", valor: t.campañas, detalle: `${t.hallazgos_con_tecnica} hallazgos con técnica` },
              { etiqueta: "Técnicas distintas", valor: t.tecnicas_distintas, detalle: `${t.tecnicas_observadas} observadas · ${t.tecnicas_intentadas} solo intentadas` },
              { etiqueta: "Recurrentes", valor: coberturaAttack.recurrentes.length, detalle: "en ≥ 2 campañas" },
              { etiqueta: "Cobertura detección", valor: null, detalle: "global sobre lo evaluado", pct: t.cobertura_deteccion_global_pct },
              { etiqueta: "Media por campaña", valor: null, detalle: "cobertura de detección", pct: t.cobertura_deteccion_media_pct },
              { etiqueta: "IDs inválidos", valor: t.ids_invalidos, detalle: "ignorados, sin inferencia" },
            ].map((k) => (
              <Tarjeta key={k.etiqueta} className="p-4">
                <p className="font-mono text-[10px] uppercase tracking-[0.14em] text-zinc-500">{k.etiqueta}</p>
                {k.valor !== null && k.valor !== undefined ? (
                  <p className="mt-1 text-2xl font-semibold tabular-nums text-zinc-100">{k.valor}</p>
                ) : (
                  <p className="mt-1 text-2xl font-semibold"><Pct valor={k.pct ?? null} /></p>
                )}
                <p className="mt-0.5 text-[11px] leading-snug text-zinc-500">{k.detalle}</p>
              </Tarjeta>
            ))}
          </div>

          {/* --- Heatmap técnica × campaña ----------------------------- */}
          <Tarjeta>
            <TituloSeccion
              titulo="Matriz técnica × campaña"
              descripcion="Celda pintada por la severidad MÁXIMA del hallazgo (misma escala que el informe y la capa Navigator). Borde discontinuo = técnica intentada sin hallazgo asociado. Escudo = resultado defensivo documentado."
            />
            <div className="overflow-x-auto">
              <table className="w-full min-w-max border-collapse text-sm">
                <thead>
                  <tr className="border-b border-line text-left">
                    <th className="pb-2.5 pr-4 font-mono text-[10px] font-medium uppercase tracking-[0.14em] text-zinc-500">Técnica</th>
                    {campanas.map((c) => (
                      <th key={c.id} className="pb-2.5 pr-3 align-bottom">
                        <p className="max-w-[150px] truncate text-xs font-semibold text-zinc-300" title={`${c.nombre} — ${c.cliente}`}>{c.nombre}</p>
                        <p className="max-w-[150px] truncate font-mono text-[10px] font-normal text-zinc-600">{c.cliente}</p>
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {coberturaAttack.matriz.map((fila) => (
                    <tr key={fila.tecnica} className="border-b border-line/40 last:border-0">
                      <td className="py-2 pr-4">
                        <span className="flex items-center gap-2">
                          <code className="font-mono text-xs font-semibold text-zinc-200">{fila.tecnica}</code>
                          {fila.campanas > 1 && (
                            <Insignia tono="ambar">{fila.campanas} campañas</Insignia>
                          )}
                        </span>
                      </td>
                      {campanas.map((c) => {
                        const celda = fila.celdas[c.id];
                        if (!celda) return <td key={c.id} className="py-2 pr-3"><span className="block h-9 rounded-md border border-line/30 bg-ink/20" /></td>;
                        const color = COLOR_SEV[celda.severidad_max ?? "informativa"] ?? COLOR_SEV.informativa;
                        const observada = celda.estado === "observada";
                        const d = celda.deteccion;
                        return (
                          <td key={c.id} className="py-2 pr-3">
                            <div
                              className={cn(
                                "flex h-9 min-w-[110px] flex-col justify-center rounded-md border px-2.5",
                                observada ? "border-transparent" : "border-dashed border-line bg-ink/30",
                              )}
                              style={observada ? { backgroundColor: `${color}26`, borderColor: `${color}66` } : undefined}
                              title={observada
                                ? `${celda.hallazgos} hallazgo(s) · severidad máx: ${celda.severidad_max ?? "?"}`
                                : "Intentada (solicitud de aprobación) sin hallazgo asociado"}
                            >
                              <span className="flex items-center gap-1.5">
                                {observada ? (
                                  <span className="font-mono text-xs font-semibold tabular-nums" style={{ color }}>
                                    {celda.hallazgos}
                                  </span>
                                ) : (
                                  <span className="font-mono text-[10px] uppercase tracking-wide text-zinc-500">intentada</span>
                                )}
                                {d.prevenido > 0 && <ShieldCheck className="h-3.5 w-3.5 text-emerald-300" />}
                                {d.detectado > 0 && <ShieldAlert className="h-3.5 w-3.5 text-teal-300" />}
                                {d.no_detectado > 0 && <ShieldX className="h-3.5 w-3.5 text-red-300" />}
                              </span>
                              {observada && celda.cobertura_pct !== null && (
                                <span className="text-[10px] leading-tight text-zinc-500">detección {celda.cobertura_pct}%</span>
                              )}
                            </div>
                          </td>
                        );
                      })}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <p className="mt-3 flex flex-wrap items-center gap-3 text-[11px] text-zinc-500">
              <span className="flex items-center gap-1"><ShieldCheck className="h-3.5 w-3.5 text-emerald-300" /> prevenido</span>
              <span className="flex items-center gap-1"><ShieldAlert className="h-3.5 w-3.5 text-teal-300" /> detectado</span>
              <span className="flex items-center gap-1"><ShieldX className="h-3.5 w-3.5 text-red-300" /> no detectado</span>
              <span className="flex items-center gap-1"><Grid3X3 className="h-3.5 w-3.5 text-zinc-500" /> color = severidad máxima</span>
            </p>
          </Tarjeta>

          {/* --- Debilidades recurrentes ------------------------------- */}
          {coberturaAttack.recurrentes.length > 0 && (
            <Tarjeta>
              <TituloSeccion
                titulo={`Técnicas recurrentes (${coberturaAttack.recurrentes.length})`}
                descripcion="Observadas en dos o más campañas: la misma debilidad se explota de nuevo. Son las candidatas naturales para priorizar la remediación del cliente"
              />
              <ul className="space-y-2">
                {coberturaAttack.recurrentes.map((r) => (
                  <li key={r.tecnica} className="flex flex-wrap items-center gap-2 rounded-lg border border-line bg-ink/40 px-3 py-2">
                    <code className="font-mono text-xs font-semibold text-zinc-100">{r.tecnica}</code>
                    <span className="text-xs text-zinc-500">en {r.campanas.length} campañas:</span>
                    {r.campanas.map((c) => (
                      <Insignia key={c.id} tono="slate">{c.nombre}</Insignia>
                    ))}
                  </li>
                ))}
              </ul>
            </Tarjeta>
          )}

          {/* --- Resumen por campaña ----------------------------------- */}
          <Tarjeta>
            <TituloSeccion titulo="Cobertura de detección por campaña" descripcion="El equipo azul, ¿vio lo que el rojo ejecutó? Evaluado sobre hallazgos con técnica ATT&CK y detección documentada" />
            <div className="overflow-x-auto">
              <table className="w-full min-w-max text-sm">
                <thead>
                  <tr className="border-b border-line text-left font-mono text-[10px] uppercase tracking-[0.14em] text-zinc-500">
                    <th className="pb-2.5 pr-4 font-medium">Campaña</th>
                    <th className="pb-2.5 pr-4 font-medium">Cliente</th>
                    <th className="pb-2.5 pr-4 font-medium">Técnicas</th>
                    <th className="pb-2.5 pr-4 font-medium">Detecciones</th>
                    <th className="pb-2.5 font-medium text-right">Cobertura</th>
                  </tr>
                </thead>
                <tbody>
                  {campanas.map((c) => (
                    <tr key={c.id} className="border-b border-line/50 last:border-0 transition-colors hover:bg-white/[0.02]">
                      <td className="py-2.5 pr-4 text-zinc-200">{c.nombre}</td>
                      <td className="py-2.5 pr-4 text-zinc-400">{c.cliente}</td>
                      <td className="py-2.5 pr-4 tabular-nums text-zinc-300">{c.tecnicas_observadas} obs · {c.tecnicas_intentadas} int.</td>
                      <td className="py-2.5 pr-4">
                        <span className="flex flex-wrap items-center gap-x-2 gap-y-0.5 text-[11px] tabular-nums">
                          <span className="text-emerald-300">{c.deteccion.prevenido} prev.</span>
                          <span className="text-teal-300">{c.deteccion.detectado} det.</span>
                          <span className="text-red-300">{c.deteccion.no_detectado} no</span>
                          <span className="text-zinc-500">{c.deteccion.pendiente} pend.</span>
                        </span>
                      </td>
                      <td className="py-2.5 text-right"><Pct valor={c.cobertura_deteccion_pct} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Tarjeta>
        </>
      )}

      {coberturaAttack.errores.length > 0 && (
        <p className="rounded-lg border border-amber-500/30 bg-amber-500/[0.06] px-3 py-2 font-mono text-[11px] text-amber-200/90">
          Omitidas por ilegibles: {coberturaAttack.errores.map((e) => e.bd).join(", ")}
        </p>
      )}
    </div>
  );
}
