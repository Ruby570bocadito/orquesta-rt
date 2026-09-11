"use client";

/**
 * Grafo de plantilla REAL desde el directorio (v17).
 *
 * Lee personas directamente del controlador de dominio por LDAP (solo
 * lectura, credenciales bajo ROE): cuentas, cargos, departamentos y la
 * cadena de mando que el atributo `manager` declara. Nada se deduce ni
 * se inventa: si el LDAP no está configurado, la tarjeta muestra el
 * requisito exacto; si el DC no devuelve personas, se dice también.
 *
 * La sección vive plegada para no cargar la vista de Integraciones: el
 * organigrama solo se consulta cuando el operador lo pide.
 */

import { useMemo, useState } from "react";
import { motion } from "framer-motion";
import {
  Building2, ChevronDown, ChevronUp, Loader2, Network, Users,
} from "lucide-react";
import { Tarjeta, Insignia } from "@/components/consola/ui";
import { usarConsola } from "@/lib/store";
import type { NodoPlantilla } from "@/lib/tipos";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

const NODO_W = 184;
const NODO_H = 44;
const GAP_Y = 14;
const COL_W = NODO_W + 56;
const PADDING = 16;
/** Límite de renderizado del SVG: más allá, se renderiza un subconjunto
 * y se avisa (honestidad sobre lo que se dibuja). */
const MAX_NODOS_SVG = 250;

function CajaNodo({ nodo, x, y }: { nodo: NodoPlantilla; x: number; y: number }) {
  const raiz = !nodo.manager;
  return (
    <g transform={`translate(${x}, ${y})`}>
      <rect
        width={NODO_W}
        height={NODO_H}
        rx={8}
        className={cn(
          raiz ? "fill-zinc-800/70 stroke-emerald-500/50" : "fill-zinc-800/40 stroke-zinc-600/60",
        )}
        strokeWidth={1}
      />
      <text x={12} y={18} className="fill-zinc-100 text-[11px] font-medium">
        {nodo.nombre.slice(0, 22)}
      </text>
      <text x={12} y={32} className="fill-zinc-400 font-mono text-[10px]">
        {(nodo.cargo || nodo.departamento).slice(0, 26)}
      </text>
    </g>
  );
}

function Organigrama({ nodos }: { nodos: NodoPlantilla[] }) {
  const { svgNodos, aristasPos, ancho, alto, recortado } = useMemo(() => {
    const maxNivel = Math.max(0, ...nodos.map((n) => n.nivel));
    const porNivel = new Map<number, NodoPlantilla[]>();
    for (const n of nodos) {
      const lista = porNivel.get(n.nivel) ?? [];
      lista.push(n);
      porNivel.set(n.nivel, lista);
    }
    const posicion = new Map<string, { x: number; y: number }>();
    let maxFilas = 0;
    const maximo = Math.min(nodos.length, MAX_NODOS_SVG);
    let colocados = 0;
    for (let nivel = 0; nivel <= maxNivel && colocados < maximo; nivel++) {
      const lista = (porNivel.get(nivel) ?? []).sort(
        (a, b) => a.departamento.localeCompare(b.departamento) || a.cuenta.localeCompare(b.cuenta),
      );
      maxFilas = Math.max(maxFilas, lista.length);
      lista.forEach((n, i) => {
        if (colocados >= maximo) return;
        posicion.set(n.cuenta, {
          x: nivel * COL_W + PADDING,
          y: i * (NODO_H + GAP_Y) + PADDING,
        });
        colocados++;
      });
    }
    const svgNodos = nodos
      .filter((n) => posicion.has(n.cuenta))
      .map((n) => ({ nodo: n, pos: posicion.get(n.cuenta)! }));
    const aristasPos = nodos
      .filter((n) => n.manager && posicion.has(n.cuenta) && posicion.has(n.manager))
      .map((n) => {
        const origen = posicion.get(n.manager!)!;
        const destino = posicion.get(n.cuenta)!;
        return {
          d: `M ${origen.x + NODO_W} ${origen.y + NODO_H / 2}`
            + ` C ${origen.x + NODO_W + 28} ${origen.y + NODO_H / 2},`
            + ` ${destino.x - 28} ${destino.y + NODO_H / 2},`
            + ` ${destino.x} ${destino.y + NODO_H / 2}`,
        };
      });
    return {
      svgNodos,
      aristasPos,
      ancho: (maxNivel + 1) * COL_W + PADDING * 2,
      alto: maxFilas * (NODO_H + GAP_Y) + PADDING * 2,
      recortado: nodos.length > MAX_NODOS_SVG,
    };
  }, [nodos]);

  return (
    <div>
      <div className="overflow-x-auto rounded-lg border border-line bg-ink">
        <svg
          width={ancho}
          height={alto}
          role="img"
          aria-label="Organigrama real del directorio"
          className="min-w-full"
        >
          {aristasPos.map((a, i) => (
            <path key={i} d={a.d} fill="none" className="stroke-zinc-600/50" strokeWidth={1.2} />
          ))}
          {svgNodos.map(({ nodo, pos }) => (
            <CajaNodo key={nodo.cuenta} nodo={nodo} x={pos.x} y={pos.y} />
          ))}
        </svg>
      </div>
      <p className="mt-2 text-[10px] text-zinc-600">
        {recortado
          ? `Se dibujan los primeros ${MAX_NODOS_SVG} de ${nodos.length} nodos para mantener el gráfico legible; la consulta devolvió todos.`
          : "Niveles = profundidad real de la cadena de mando declarada en el directorio. Un nodo raíz es una persona cuyo manager no quedó recogido en la lectura."}
      </p>
    </div>
  );
}

export function SeccionPlantilla() {
  const [plegada, setPlegada] = useState(true);
  const plantilla = usarConsola((s) => s.plantilla);
  const plantillaEstado = usarConsola((s) => s.plantillaEstado);
  const consultarPlantilla = usarConsola((s) => s.consultarPlantilla);
  const ldapConfigurado = usarConsola(
    (s) => Boolean(s.integraciones?.active_directory?.configurado),
  );

  const conectado = Boolean(plantilla?.conectado);
  const resumen = plantilla?.resumen;
  const departamentos = Object.entries(plantilla?.departamentos ?? {});
  const insignia = conectado
    ? { tono: "teal" as const, texto: `${resumen?.total ?? 0} personas leídas` }
    : plantilla
      ? { tono: "rojo" as const, texto: "sin conexión con el directorio" }
      : ldapConfigurado
        ? { tono: "ambar" as const, texto: "LDAP listo · consulta pendiente" }
        : { tono: "slate" as const, texto: "requiere LDAP configurado" };

  return (
    <motion.section initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}>
      <Tarjeta>
        <button
          type="button"
          onClick={() => setPlegada((v) => !v)}
          className="flex w-full items-center justify-between gap-3 text-left"
          aria-expanded={!plegada}
        >
          <div className="flex items-center gap-2">
            <Network className="h-4 w-4 text-teal-300" />
            <h3 className="text-[13px] font-semibold text-zinc-200">
              Grafo de plantilla · Directorio real
            </h3>
            <Insignia tono={insignia.tono}>{insignia.texto}</Insignia>
          </div>
          {plegada ? (
            <ChevronDown className="h-4 w-4 text-zinc-500" />
          ) : (
            <ChevronUp className="h-4 w-4 text-zinc-500" />
          )}
        </button>

        {plegada ? (
          <p className="mt-2 text-[12px] leading-relaxed text-zinc-500">
            Organigrama REAL leído del controlador de dominio: cargos,
            departamentos y cadena de mando declarada (atributo manager).
            Solo lectura, bajo ROE. Despliega para consultarlo.
          </p>
        ) : (
          <div className="mt-4 space-y-4">
            <div className="flex flex-wrap items-center gap-3">
              <Button
                variant="outline"
                size="sm"
                className="h-8 gap-1.5 border-line bg-panel text-xs text-zinc-300 hover:bg-raised"
                onClick={() => void consultarPlantilla()}
                disabled={plantillaEstado === "cargando"}
              >
                {plantillaEstado === "cargando" ? (
                  <Loader2 className="h-3.5 w-3.5 animate-spin" />
                ) : (
                  <Users className="h-3.5 w-3.5" />
                )}
                {plantillaEstado === "cargando"
                  ? "consultando el controlador de dominio…"
                  : plantilla
                    ? "Volver a leer del directorio"
                    : "Leer plantilla del directorio"}
              </Button>
              {conectado && plantilla?.base_dn ? (
                <span className="font-mono text-[11px] text-zinc-500">
                  base: {plantilla.base_dn}
                </span>
              ) : null}
            </div>

            {plantillaEstado === "error" ? (
              <p className="rounded-md border border-line bg-ink p-3 font-mono text-[11px] text-red-300">
                La consulta no llegó al orquestador: revisa que el backend está
                en marcha y vuelve a intentarlo.
              </p>
            ) : null}

            {plantilla && !conectado ? (
              <p className="rounded-md border border-line bg-ink p-3 font-mono text-[11px] leading-relaxed text-amber-200/80">
                {plantilla.requisito}
              </p>
            ) : null}

            {plantilla && conectado && !plantilla.nodos.length ? (
              <p className="rounded-md border border-line bg-ink p-3 font-mono text-[11px] text-zinc-400">
                El directorio respondió correctamente pero no devolvió personas
                legibles con estas credenciales: no hay grafo que dibujar.
              </p>
            ) : null}

            {plantilla && conectado && plantilla.nodos.length > 0 ? (
              <>
                <div className="flex flex-wrap gap-2">
                  <Insignia tono="teal">
                    {resumen?.total ?? plantilla.nodos.length} personas
                  </Insignia>
                  <Insignia tono="esmeralda">
                    {resumen?.con_manager ?? "—"} con manager declarado
                  </Insignia>
                  <Insignia tono="slate">
                    {resumen?.raices ?? "—"} raíces
                  </Insignia>
                  <Insignia tono="slate">
                    {resumen?.profundidad ?? "—"} niveles
                  </Insignia>
                </div>

                {departamentos.length > 0 ? (
                  <div className="flex flex-wrap items-center gap-1.5">
                    <Building2 className="mr-1 h-3.5 w-3.5 text-zinc-500" />
                    {departamentos.map(([dep, n]) => (
                      <Insignia key={dep} tono="slate">
                        {dep} · {n}
                      </Insignia>
                    ))}
                  </div>
                ) : null}

                <Organigrama nodos={plantilla.nodos} />

                {plantilla.nota ? (
                  <p className="text-[11px] text-zinc-600">{plantilla.nota}</p>
                ) : null}
              </>
            ) : null}
          </div>
        )}
      </Tarjeta>
    </motion.section>
  );
}
