"use client";

/**
 * Vista Técnicas: biblioteca REAL de skills del despliegue.
 *
 * Cada skill es un playbook de TTP ejecutable (procedimiento, herramientas,
 * criterios de éxito, OPSEC y evidencias a capturar) que alimenta los
 * prompts de los agentes con progressive disclosure: solo nombre y
 * descripción viajan en el índice; el cuerpo se carga bajo demanda — aquí
 * exactamente igual: el catálogo llega ligero y el playbook completo se
 * pide al abrirlo. Sin simulación: lo que muestra esta vista es lo que hay
 * en el disco del despliegue (misma fuente que leerá el modelo).
 *
 * El operador puede filtrar por fase/riesgo, buscar por texto o ATT&CK,
 * ver el hash sha256 del contenido (custodia del conocimiento) y recargar
 * la biblioteca tras añadir técnicas nuevas al disco SIN reiniciar.
 */

import { useEffect, useMemo, useState } from "react";
import { motion } from "framer-motion";
import {
  BookOpen, Fingerprint, Loader2, RefreshCw, Search, ShieldAlert,
  Swords, X,
} from "lucide-react";
import { toast } from "@/hooks/use-toast";
import { Button } from "@/components/ui/button";
import { Insignia, Tarjeta, TituloSeccion } from "@/components/consola/ui";
import { obtenerDetalleTecnica, usarConsola } from "@/lib/store";
import type { Tecnica, TecnicaDetalle } from "@/lib/tipos";
import { cn } from "@/lib/utils";

const RIESGOS = ["alta", "media", "baja"] as const;

const TONO_RIESGO: Record<string, "rojo" | "ambar" | "esmeralda" | "slate"> = {
  alta: "rojo",
  media: "ambar",
  baja: "esmeralda",
};

const TONO_FASE: Record<string, "crimson" | "teal" | "slate"> = {
  F0_scoping: "slate", F1_osint: "teal", F2_recon: "teal",
  F3_acceso_inicial: "crimson", F4_dominio_ad: "crimson",
  F5_c2_postex: "crimson", F6_phishing: "crimson", F7_informe: "slate",
};

function TarjetaTecnica({
  tecnica, abierta, onAbrir,
}: {
  tecnica: Tecnica;
  abierta: boolean;
  onAbrir: () => void;
}) {
  return (
    <Tarjeta
      className={cn(
        "flex h-full cursor-pointer flex-col transition-colors hover:border-zinc-600",
        abierta && "border-crimson-bright/60",
      )}
    >
      <button
        type="button"
        onClick={onAbrir}
        className="flex h-full flex-col text-left"
        aria-expanded={abierta}
      >
        <div className="mb-2 flex items-start justify-between gap-2">
          <p className="flex items-center gap-2 text-sm font-semibold text-zinc-100">
            <Swords className="h-4 w-4 shrink-0 text-crimson-bright" />
            {tecnica.nombre}
          </p>
          <Insignia tono={TONO_RIESGO[tecnica.riesgo] ?? "slate"}>
            riesgo {tecnica.riesgo}
          </Insignia>
        </div>
        <p className="mb-3 line-clamp-3 flex-1 text-[12px] leading-relaxed text-zinc-400">
          {tecnica.descripcion || "sin descripción en la portada"}
        </p>
        <div className="flex flex-wrap items-center gap-1.5">
          {tecnica.fase ? (
            <Insignia tono={TONO_FASE[tecnica.fase] ?? "slate"}>{tecnica.fase}</Insignia>
          ) : null}
          {tecnica.tecnica_mitre ? (
            <span className="inline-flex items-center rounded-md border border-line bg-ink px-2 py-0.5 font-mono text-[10px] text-zinc-400">
              ATT&CK {tecnica.tecnica_mitre}
            </span>
          ) : null}
          {tecnica.requiere_aprobacion ? (
            <span className="inline-flex items-center gap-1 rounded-md border border-amber-400/30 bg-amber-400/10 px-1.5 py-0.5 text-[10px] font-medium text-amber-300">
              <ShieldAlert className="h-3 w-3" /> aprobación humana
            </span>
          ) : null}
        </div>
      </button>
    </Tarjeta>
  );
}

function PanelTecnica({
  nombre, onCerrar,
}: {
  nombre: string;
  onCerrar: () => void;
}) {
  const [detalle, setDetalle] = useState<TecnicaDetalle | null>(null);
  const [error, setError] = useState<string | null>(null);

  // El componente se monta con key=nombre (remount por técnica): el estado
  // inicial null es siempre limpio; aquí solo se resuelve la petición.
  useEffect(() => {
    let vivo = true;
    obtenerDetalleTecnica(nombre)
      .then((d) => { if (vivo) setDetalle(d); })
      .catch((e) => { if (vivo) setError((e as Error).message); });
    return () => { vivo = false; };
  }, [nombre]);

  return (
    <Tarjeta className="border-crimson-bright/40">
      <div className="mb-3 flex items-start justify-between gap-3">
        <div className="flex items-center gap-2">
          <BookOpen className="h-4 w-4 text-crimson-bright" />
          <h3 className="text-sm font-semibold text-zinc-100">
            Playbook: {nombre}
          </h3>
        </div>
        <Button
          variant="ghost" size="icon"
          className="h-7 w-7 text-zinc-500 hover:bg-raised hover:text-zinc-200"
          onClick={onCerrar} aria-label="Cerrar playbook"
        >
          <X className="h-4 w-4" />
        </Button>
      </div>

      {error ? (
        <p className="rounded-md border border-red-400/30 bg-red-400/10 p-3 text-[12px] text-red-300">
          {error}
        </p>
      ) : !detalle ? (
        <div className="flex h-24 items-center justify-center gap-2 text-xs text-zinc-500">
          <Loader2 className="h-4 w-4 animate-spin" /> cargando cuerpo completo bajo demanda…
        </div>
      ) : (
        <div className="space-y-3">
          <div className="flex flex-wrap items-center gap-1.5">
            {detalle.fase ? (
              <Insignia tono={TONO_FASE[detalle.fase] ?? "slate"}>{detalle.fase}</Insignia>
            ) : null}
            <Insignia tono={TONO_RIESGO[detalle.riesgo] ?? "slate"}>
              riesgo {detalle.riesgo}
            </Insignia>
            {detalle.tecnica_mitre ? (
              <span className="inline-flex items-center gap-1 rounded-md border border-line bg-ink px-2 py-0.5 font-mono text-[10px] text-zinc-400">
                <Fingerprint className="h-3 w-3" /> {detalle.tecnica_mitre}
              </span>
            ) : null}
            {detalle.requiere_aprobacion ? (
              <span className="inline-flex items-center gap-1 rounded-md border border-amber-400/30 bg-amber-400/10 px-1.5 py-0.5 text-[10px] font-medium text-amber-300">
                <ShieldAlert className="h-3 w-3" /> requiere aprobación humana
              </span>
            ) : null}
          </div>

          {detalle.fuentes_permitidas?.length ? (
            <p className="text-[11px] leading-relaxed text-zinc-500">
              <span className="text-zinc-400">Fuentes permitidas:</span>{" "}
              {detalle.fuentes_permitidas.join(" · ")}
            </p>
          ) : null}

          <p className="truncate font-mono text-[10px] text-zinc-600" title={detalle.hash_contenido}>
            sha256: {detalle.hash_contenido.slice(0, 32)}…
          </p>

          <pre className="max-h-[420px] overflow-auto rounded-md border border-line bg-ink p-3 font-mono text-[11px] leading-relaxed text-zinc-300">
            {detalle.cuerpo.trim()}
          </pre>
        </div>
      )}
    </Tarjeta>
  );
}

export function VistaTecnicas() {
  const tecnicas = usarConsola((s) => s.tecnicas);
  const cargarTecnicas = usarConsola((s) => s.cargarTecnicas);
  const recargarTecnicas = usarConsola((s) => s.recargarTecnicas);
  const [recargando, setRecargando] = useState(false);
  const [busqueda, setBusqueda] = useState("");
  const [faseFiltro, setFaseFiltro] = useState<string>("");
  const [riesgoFiltro, setRiesgoFiltro] = useState<string>("");
  const [abierta, setAbierta] = useState<string | null>(null);

  useEffect(() => {
    if (!tecnicas) void cargarTecnicas();
  }, [tecnicas, cargarTecnicas]);

  const listaFiltrada = useMemo(() => {
    if (!tecnicas) return [];
    const q = busqueda.trim().toLowerCase();
    return tecnicas.tecnicas.filter((t) => {
      if (faseFiltro && t.fase !== faseFiltro) return false;
      if (riesgoFiltro && t.riesgo !== riesgoFiltro) return false;
      if (!q) return true;
      return (
        t.nombre.toLowerCase().includes(q) ||
        t.descripcion.toLowerCase().includes(q) ||
        t.tecnica_mitre.toLowerCase().includes(q)
      );
    });
  }, [tecnicas, busqueda, faseFiltro, riesgoFiltro]);

  const fases = useMemo(
    () => Object.keys(tecnicas?.por_fase ?? {}).sort(),
    [tecnicas],
  );

  const recargar = async () => {
    setRecargando(true);
    try {
      const total = await recargarTecnicas();
      toast({
        title: "Biblioteca recargada",
        description: `${total} técnicas vigentes leídas del disco.`,
      });
    } catch (e) {
      toast({
        title: "No se pudo recargar la biblioteca",
        description: (e as Error).message,
        variant: "destructive",
      });
    } finally {
      setRecargando(false);
    }
  };

  if (!tecnicas) {
    return (
      <div className="flex h-64 items-center justify-center gap-2 text-sm text-zinc-500">
        <Loader2 className="h-4 w-4 animate-spin" /> leyendo la biblioteca real del despliegue…
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <TituloSeccion
        titulo="Biblioteca de técnicas"
        descripcion="Playbooks de TTP disponibles en este despliegue: procedimiento, herramientas, criterios, OPSEC y evidencias. Es exactamente el índice que reciben los agentes — el cuerpo completo se carga bajo demanda, igual que hace el modelo."
        accion={
          <Button
            variant="outline" size="sm"
            className="h-8 gap-1.5 border-line bg-panel text-xs text-zinc-300 hover:bg-raised"
            onClick={recargar} disabled={recargando}
          >
            <RefreshCw className={cn("h-3.5 w-3.5", recargando && "animate-spin")} />
            Recargar del disco
          </Button>
        }
      />

      {/* resumen real de la biblioteca */}
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <Tarjeta className="p-4">
          <p className="text-2xl font-bold text-zinc-100">{tecnicas.total}</p>
          <p className="text-[11px] text-zinc-500">técnicas en el catálogo</p>
        </Tarjeta>
        <Tarjeta className="p-4">
          <p className="text-2xl font-bold text-amber-300">{tecnicas.con_aprobacion}</p>
          <p className="text-[11px] text-zinc-500">exigen aprobación humana</p>
        </Tarjeta>
        <Tarjeta className="p-4">
          <p className="text-2xl font-bold text-zinc-100">{fases.length}</p>
          <p className="text-[11px] text-zinc-500">fases con cobertura</p>
        </Tarjeta>
        <Tarjeta className="p-4">
          <p className="text-2xl font-bold text-red-300">
            {tecnicas.por_riesgo["alta"] ?? 0}
          </p>
          <p className="text-[11px] text-zinc-500">de riesgo alto</p>
        </Tarjeta>
      </div>

      {/* filtros */}
      <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
        <div className="relative flex-1">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-zinc-600" />
          <input
            value={busqueda}
            onChange={(e) => setBusqueda(e.target.value)}
            placeholder="Buscar por nombre, texto o ATT&CK (p. ej. T1558)…"
            className="w-full rounded-md border border-line bg-panel py-2 pl-8 pr-3 text-xs text-zinc-200 placeholder:text-zinc-600 focus:border-crimson-bright/50 focus:outline-none"
          />
        </div>
        <select
          value={faseFiltro}
          onChange={(e) => setFaseFiltro(e.target.value)}
          className="rounded-md border border-line bg-panel px-2 py-2 text-xs text-zinc-300 focus:outline-none"
          aria-label="Filtrar por fase"
        >
          <option value="">todas las fases</option>
          {fases.map((f) => (
            <option key={f} value={f}>{f} ({tecnicas.por_fase[f]})</option>
          ))}
        </select>
        <select
          value={riesgoFiltro}
          onChange={(e) => setRiesgoFiltro(e.target.value)}
          className="rounded-md border border-line bg-panel px-2 py-2 text-xs text-zinc-300 focus:outline-none"
          aria-label="Filtrar por riesgo"
        >
          <option value="">todo riesgo</option>
          {RIESGOS.map((r) => (
            <option key={r} value={r}>riesgo {r}</option>
          ))}
        </select>
      </div>

      {/* playbook abierto */}
      {abierta ? (
        <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}>
          <PanelTecnica key={abierta} nombre={abierta} onCerrar={() => setAbierta(null)} />
        </motion.div>
      ) : null}

      {/* catálogo */}
      {listaFiltrada.length === 0 ? (
        <Tarjeta className="p-8 text-center text-sm text-zinc-500">
          Ninguna técnica coincide con los filtros.
        </Tarjeta>
      ) : (
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
          {listaFiltrada.map((t, i) => (
            <motion.div
              key={t.nombre}
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: Math.min(i * 0.04, 0.3) }}
            >
              <TarjetaTecnica
                tecnica={t}
                abierta={abierta === t.nombre}
                onAbrir={() => setAbierta(abierta === t.nombre ? null : t.nombre)}
              />
            </motion.div>
          ))}
        </div>
      )}

      <Tarjeta>
        <div className="flex items-start gap-3">
          <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0 text-amber-300" />
          <p className="text-[12px] leading-relaxed text-zinc-400">
            Las técnicas son conocimiento, no acción: ejecutarlas exige el canal
            del orquestador (fase + boundary + aprobación humana) y respetar el
            ROE del caso. La biblioteca vive en el disco del despliegue, montada
            de solo lectura para el agente; tras añadir o retirar playbooks,
            usa <span className="text-zinc-200">Recargar del disco</span> para
            que la siguiente fase los vea en su índice sin reiniciar el servicio.
          </p>
        </div>
      </Tarjeta>
    </div>
  );
}
