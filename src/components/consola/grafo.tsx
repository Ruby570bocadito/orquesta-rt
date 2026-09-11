"use client";

/**
 * Grafo de relaciones del caso: representación visual de la superficie
 * observada. Todo el contenido se DERIVA de datos reales del engagement
 * (objetivos y hallazgos registrados con herramientas reales); ninguna
 * arista se inventa:
 *
 *  - capa por tipo de activo (dominio → host → servicio/ruta → persona/credencial)
 *  - subdominio: nombre que termina en "." + dominio padre registrado
 *  - hallazgo → activo: el campo `activo` del hallazgo coincide con el nombre
 *  - relación evidenciada: el detalle de un objetivo menciona el nombre de otro
 *    (p. ej. "IP A de acme.com (DNS real)" enlaza el host con su dominio)
 *
 * Si un activo no tiene relaciones, queda como nodo aislado: también es
 * información honesta (fue observado, pero sin vínculo registrado aún).
 */

import { useMemo, useState } from "react";
import {
  Crosshair, Globe, KeyRound, Network, Route, Server, Users,
} from "lucide-react";
import { Insignia } from "@/components/consola/ui";
import { usarConsola } from "@/lib/store";
import {
  EstadoObjetivo, TipoObjetivo,
} from "@/lib/tipos";
import { cn } from "@/lib/utils";

const ICONO: Record<TipoObjetivo, React.ComponentType<{ className?: string }>> = {
  dominio: Globe,
  host: Server,
  servicio: Network,
  credencial: KeyRound,
  ruta: Route,
  activo_humano: Users,
};

const COLOR_ESTADO: Record<EstadoObjetivo, string> = {
  descubierto: "#a1a1aa",
  confirmado: "#2dd4bf",
  riesgo: "#fbbf24",
  explotado: "#f87171",
  neutralizado: "#34d399",
};

const COLOR_SEVERIDAD: Record<string, string> = {
  critica: "#f87171",
  alta: "#fb923c",
  media: "#fbbf24",
  baja: "#a1a1aa",
  info: "#a1a1aa",
};

/** Filas de la disposición: cada tipo de activo vive en una capa fija. */
const CAPAS: { tipos: TipoObjetivo[]; etiqueta: string }[] = [
  { tipos: ["dominio"], etiqueta: "Dominios" },
  { tipos: ["host"], etiqueta: "Hosts" },
  { tipos: ["servicio", "ruta"], etiqueta: "Servicios · rutas" },
  { tipos: ["activo_humano", "credencial"], etiqueta: "Personas · credenciales" },
];

const ANCHO_NODO = 168;
const ALTO_NODO = 40;
const MARGEN_X = 28;
const SEPARACION_FILA = 104;

type NodoGrafico = {
  id: string;
  nombre: string;
  tipo: TipoObjetivo;
  estado: EstadoObjetivo;
  severidad: string | null;
  detalle: string;
  x: number;
  y: number;
};

type AristaGrafico = { desde: NodoGrafico; hasta: NodoGrafico; motivo: string };

export function VistaGrafo() {
  const objetivos = usarConsola((s) => s.objetivos);
  const hallazgos = usarConsola((s) => s.hallazgos);
  const [seleccion, setSeleccion] = useState<string | null>(null);

  const { nodos, aristas, ancho, alto } = useMemo(() => {
    // Solo las capas con contenido ocupan fila: nada de huecos vacíos.
    const capasVivas = CAPAS
      .map((capa) => ({ ...capa,
        nodos: objetivos
          .filter((o) => capa.tipos.includes(o.tipo))
          .sort((a, b) => a.nombre.localeCompare(b.nombre))
          .map((o) => ({
            id: o.id,
            nombre: o.nombre,
            tipo: o.tipo,
            estado: o.estado,
            severidad: (o as { severidad?: string | null }).severidad ?? null,
            detalle: o.detalle,
            x: 0, y: 0,
          })),
      }))
      .filter((capa) => capa.nodos.length > 0);

    const maxFila = Math.max(1, ...capasVivas.map((c) => c.nodos.length));
    const ancho = Math.max(680, maxFila * (ANCHO_NODO + MARGEN_X) + MARGEN_X);
    const alto = Math.max(160, capasVivas.length * SEPARACION_FILA + 36);

    const nodos: NodoGrafico[] = [];
    capasVivas.forEach((capa, i) => {
      const hueco = ancho / capa.nodos.length;
      capa.nodos.forEach((n, j) => {
        n.x = hueco * j + hueco / 2;
        n.y = 28 + i * SEPARACION_FILA;
        nodos.push(n);
      });
    });

    const aristas: AristaGrafico[] = [];
    const vistas = new Set<string>();

    const enlazar = (a: NodoGrafico, b: NodoGrafico, motivo: string) => {
      const clave = `${a.id}→${b.id}:${motivo}`;
      if (a.id === b.id || vistas.has(clave)) return;
      vistas.add(clave);
      aristas.push({ desde: a, hasta: b, motivo });
    };

    for (const n of nodos) {
      for (const padre of nodos) {
        if (padre.y >= n.y) continue;
        // (1) subdominio registrado de un dominio de una capa superior
        if (padre.tipo === "dominio" && n.tipo === "dominio" &&
            n.nombre.endsWith(`.${padre.nombre}`)) {
          enlazar(padre, n, "subdominio");
        }
        // (2) el mismo activo observado en dos capas (p. ej. dominio y host
        //     con el mismo nombre) es UNA sola entidad: se conecta.
        if (padre.nombre.toLowerCase() === n.nombre.toLowerCase()) {
          enlazar(padre, n, "mismo activo observado en dos capas");
        }
        // (3) el detalle del objetivo menciona a otro activo (evidencia real)
        if (padre.nombre.length > 3 &&
            n.detalle.toLowerCase().includes(padre.nombre.toLowerCase())) {
          enlazar(padre, n, "relación evidenciada");
        }
      }
    }

    return { nodos, aristas, ancho, alto };
  }, [objetivos]);

  const { hallazgosPorActivo, huerfanos } = useMemo(() => {
    const nombres = new Set(nodos.map((n) => n.nombre.toLowerCase()));
    const mapa = new Map<string, typeof hallazgos>();
    let huerfanos = 0;
    for (const h of hallazgos) {
      const activo = (h.activo || "").trim();
      if (!activo || !nombres.has(activo.toLowerCase())) {
        huerfanos += 1;
        continue;
      }
      const lista = mapa.get(activo.toLowerCase()) ?? [];
      lista.push(h);
      mapa.set(activo.toLowerCase(), lista);
    }
    return { hallazgosPorActivo: mapa, huerfanos };
  }, [hallazgos, nodos]);

  const vecinos = useMemo(() => {
    if (!seleccion) return null;
    const ids = new Set<string>([seleccion]);
    for (const a of aristas) {
      if (a.desde.id === seleccion) ids.add(a.hasta.id);
      if (a.hasta.id === seleccion) ids.add(a.desde.id);
    }
    return ids;
  }, [seleccion, aristas]);

  if (nodos.length === 0) {
    return (
      <p className="py-10 text-center text-sm text-zinc-600">
        El grafo se puebla a medida que el agente registra activos en la superficie (F1 en adelante).
      </p>
    );
  }

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <Insignia tono="slate">{nodos.length} activos</Insignia>
        <Insignia tono="crimson">{aristas.length} relaciones</Insignia>
        <span className="text-[11px] text-zinc-600">
          derivado solo de lo observado en el caso · aristas: subdominios, hallazgos y relaciones evidenciadas
        </span>
      </div>

      <div className="overflow-x-auto rounded-xl border border-line bg-ink/40 p-2">
        <svg
          viewBox={`0 0 ${ancho} ${alto}`}
          width={ancho}
          height={alto}
          className="min-w-full"
          role="img"
          aria-label="Grafo de relaciones de la superficie de ataque del caso"
        >
          {/* aristas */}
          {aristas.map((a, i) => {
            const activa = !vecinos || (vecinos.has(a.desde.id) && vecinos.has(a.hasta.id));
            return (
              <line
                key={i}
                x1={a.desde.x} y1={a.desde.y + ALTO_NODO / 2}
                x2={a.hasta.x} y2={a.hasta.y - ALTO_NODO / 2}
                stroke={activa ? "#dc2626" : "#3f3f46"}
                strokeOpacity={activa ? 0.55 : 0.3}
                strokeWidth={activa ? 1.6 : 1}
              >
                <title>{a.motivo}</title>
              </line>
            );
          })}

          {/* nodos */}
          {nodos.map((n) => {
            const Icono = ICONO[n.tipo];
            const aten = !vecinos || vecinos.has(n.id);
            const color = COLOR_ESTADO[n.estado];
            const chips = hallazgosPorActivo.get(n.nombre.toLowerCase()) ?? [];
            return (
              <g
                key={n.id}
                transform={`translate(${n.x - ANCHO_NODO / 2}, ${n.y - ALTO_NODO / 2})`}
                opacity={aten ? 1 : 0.25}
                className="cursor-pointer"
                onClick={() => setSeleccion(seleccion === n.id ? null : n.id)}
              >
                <rect
                  width={ANCHO_NODO} height={ALTO_NODO} rx={10}
                  fill="#101014" stroke={seleccion === n.id ? "#dc2626" : color}
                  strokeOpacity={seleccion === n.id ? 0.95 : 0.45}
                  strokeWidth={seleccion === n.id ? 2 : 1.2}
                />
                <g transform="translate(10, 9)" style={{ color }}>
                  <Icono className="h-[22px] w-[22px]" />
                </g>
                <text
                  x={40} y={17}
                  fill="#e4e4e7" fontSize={11} fontFamily="ui-monospace, monospace"
                >
                  {n.nombre.length > 20 ? `${n.nombre.slice(0, 19)}…` : n.nombre}
                </text>
                <text x={40} y={31} fill="#71717a" fontSize={9.5}>
                  {n.tipo}
                  {n.severidad === "critica" ? " · crítica" : ""}
                </text>
                {chips.length > 0 && (
                  <>
                    <circle cx={ANCHO_NODO - 10} cy={10} r={7}
                            fill={COLOR_SEVERIDAD[chips[0].severidad] ?? "#fbbf24"}
                            fillOpacity={0.9} />
                    <text x={ANCHO_NODO - 10} y={13.4} textAnchor="middle"
                          fontSize={9} fontWeight={700} fill="#101014">
                      {chips.length}
                    </text>
                  </>
                )}
                <title>{`${n.nombre}\n${n.detalle || ""}${chips.length ? `\n${chips.length} hallazgo(s) asociado(s)` : ""}`}</title>
              </g>
            );
          })}
        </svg>
      </div>

      {/* leyenda */}
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5 text-[11px] text-zinc-500">
        {Object.entries(COLOR_ESTADO).map(([estado, color]) => (
          <span key={estado} className="flex items-center gap-1.5">
            <span className={cn("inline-block h-2.5 w-2.5 rounded-full")} style={{ background: color }} />
            {estado}
          </span>
        ))}
        <span className="flex items-center gap-1.5">
          <Crosshair className="h-3 w-3 text-crimson" /> clic en un nodo para aislar sus relaciones
        </span>
        {huerfanos > 0 && (
          <span className="text-amber-400/80">
            {huerfanos} hallazgo(s) con activo fuera del grafo (no graficado aún)
          </span>
        )}
      </div>
    </div>
  );
}
