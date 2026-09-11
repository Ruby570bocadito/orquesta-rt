"use client";

/** Vistas Hallazgos y Evidencias: entregables técnicos del engagement. */

import { useEffect, useMemo, useState } from "react";
import { motion } from "framer-motion";
import { Check, Copy, FileSpreadsheet, Plus, ChevronDown, ChevronUp, Loader2 } from "lucide-react";
import { toast } from "@/hooks/use-toast";
import { Tarjeta, Insignia, InsigniaSeveridad, TituloSeccion, Vacio, Entrada, FiltroSegmentado, copiarTexto } from "@/components/consola/ui";
import { usarConsola, descargarCSVHallazgos } from "@/lib/store";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { ETIQUETA_FASE, Severidad, formatoTokens } from "@/lib/tipos";
import { CheckCircle2, FileSearch, Fingerprint, ShieldCheck, TriangleAlert } from "lucide-react";
import { cn } from "@/lib/utils";

const ORDEN_SEVERIDAD: Record<Severidad, number> = { critica: 0, alta: 1, media: 2, baja: 3, informativa: 4 };
const ETIQUETAS_SEV: Record<Severidad, string> = {
  critica: "crítica", alta: "alta", media: "media", baja: "baja", informativa: "informativa",
};

type EstadoDeteccion = import("@/lib/tipos").Hallazgo["deteccion"];
const OPCIONES_DETECCION: { valor: EstadoDeteccion; etiqueta: string; clase: string }[] = [
  { valor: "pendiente", etiqueta: "pendiente", clase: "text-zinc-400" },
  { valor: "detectado", etiqueta: "detectado", clase: "text-emerald-300" },
  { valor: "no_detectado", etiqueta: "no detectado", clase: "text-crimson-bright" },
  { valor: "prevenido", etiqueta: "prevenido", clase: "text-sky-300" },
];

/** Métricas purple team del caso: solo cuenta verificaciones registradas por el operador. */
function TiraPurpleTeam({ hallazgos }: { hallazgos: import("@/lib/tipos").Hallazgo[] }) {
  const total = hallazgos.length;
  const verificados = hallazgos.filter((h) => h.deteccion && h.deteccion !== "pendiente");
  const detectados = verificados.filter((h) => h.deteccion === "detectado").length;
  const prevenidosCount = verificados.filter((h) => h.deteccion === "prevenido").length;
  const ciegos = verificados.filter((h) => h.deteccion === "no_detectado").length;
  return (
    <Tarjeta className="border-violet-500/20 bg-violet-500/[0.04]">
      <div className="flex flex-wrap items-center gap-x-6 gap-y-2">
        <div>
          <p className="font-mono text-[10px] uppercase tracking-wider text-violet-300/80">cobertura de detección (purple team)</p>
          <p className="text-lg font-semibold text-zinc-100">
            {verificados.length}/{total}
            <span className="ml-1.5 text-[11px] font-normal text-zinc-500">hallazgos verificados por el blue team</span>
          </p>
        </div>
        <div className="flex flex-wrap gap-4 font-mono text-[11px]">
          <span className="text-emerald-300">detectados: {detectados}</span>
          <span className="text-sky-300">prevenidos: {prevenidosCount}</span>
          <span className="text-crimson-bright">puntos ciegos: {ciegos}</span>
          <span className="text-zinc-500">sin verificar: {total - verificados.length}</span>
        </div>
      </div>
    </Tarjeta>
  );
}

function SelectorDeteccion({ hallazgo }: { hallazgo: import("@/lib/tipos").Hallazgo }) {
  const [guardando, setGuardando] = useState<EstadoDeteccion | null>(null);
  const actual = (hallazgo.deteccion ?? "pendiente") as EstadoDeteccion;
  const elegir = async (valor: EstadoDeteccion) => {
    if (valor === actual || guardando) return;
    setGuardando(valor);
    try {
      await usarConsola.getState().marcarDeteccion(hallazgo.id, valor);
    } catch (e) {
      toast({ title: "No se pudo registrar", description: (e as Error).message, variant: "destructive" });
    } finally {
      setGuardando(null);
    }
  };
  return (
    <div
      className="mt-3 flex flex-wrap items-center gap-1.5"
      role="group"
      aria-label={`Resultado de detección para ${hallazgo.titulo}`}
    >
      <span className="font-mono text-[10px] uppercase tracking-wider text-zinc-600">detección blue team:</span>
      {OPCIONES_DETECCION.map((o) => {
        const activo = o.valor === actual;
        return (
          <button
            key={o.valor}
            type="button"
            disabled={guardando !== null}
            onClick={() => elegir(o.valor)}
            aria-pressed={activo}
            className={cn(
              "rounded-full border px-2 py-0.5 text-[11px] transition-colors disabled:opacity-50",
              activo
                ? cn("border-line-strong bg-raised font-semibold", o.clase)
                : "border-line text-zinc-500 hover:bg-panel hover:text-zinc-300",
            )}
          >
            {o.etiqueta}
          </button>
        );
      })}
      {guardando && <span className="font-mono text-[10px] text-zinc-500">guardando…</span>}
    </div>
  );
}

function FormularioHallazgo() {
  /** Alta manual de hallazgo (v16): registro auditado con identidad real.
   *  La técnica debe tener formato ATT&CK válido o ir vacía: sin adivinar. */
  const [abierto, setAbierto] = useState(false);
  const [titulo, setTitulo] = useState("");
  const [severidad, setSeveridad] = useState<string>("media");
  const [tecnica, setTecnica] = useState("");
  const [activo, setActivo] = useState("");
  const [descripcion, setDescripcion] = useState("");
  const [creando, setCreando] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const alta = async () => {
    setCreando(true);
    setError(null);
    try {
      const creado = await usarConsola.getState().registrarHallazgo({
        titulo, severidad, tecnica_mitre: tecnica || undefined,
        activo: activo || undefined, descripcion: descripcion || undefined,
      });
      toast({
        title: "Hallazgo registrado",
        description: `${creado.id} · quedará auditado y notificado si hay receptor webhook`,
      });
      setTitulo(""); setTecnica(""); setActivo(""); setDescripcion("");
      setAbierto(false);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setCreando(false);
    }
  };

  return (
    <div>
      <Button
        variant="outline" size="sm"
        className="h-8 gap-1.5 border-line bg-panel text-xs text-zinc-300 hover:bg-raised"
        onClick={() => setAbierto((a) => !a)}
      >
        {abierto ? <ChevronUp className="h-3.5 w-3.5" /> : <Plus className="h-3.5 w-3.5" />}
        Registrar hallazgo manual
      </Button>
      {abierto && (
        <motion.div
          initial={{ opacity: 0, y: -6 }} animate={{ opacity: 1, y: 0 }}
          className="mt-3 space-y-3 rounded-lg border border-line bg-ink/40 p-4"
        >
          <div className="grid gap-3 md:grid-cols-2">
            <div className="md:col-span-2">
              <label className="mb-1 block font-mono text-[10px] uppercase tracking-[0.14em] text-zinc-500">Título</label>
              <Input value={titulo} onChange={(e) => setTitulo(e.target.value)}
                placeholder="Brecha observada durante la verificación manual"
                className="h-9 border-line bg-ink text-xs" />
            </div>
            <div>
              <label className="mb-1 block font-mono text-[10px] uppercase tracking-[0.14em] text-zinc-500">Técnica ATT&CK (opcional)</label>
              <Input value={tecnica} onChange={(e) => setTecnica(e.target.value)}
                placeholder="T#### o T####.###"
                className="h-9 border-line bg-ink font-mono text-xs" />
            </div>
            <div>
              <label className="mb-1 block font-mono text-[10px] uppercase tracking-[0.14em] text-zinc-500">Activo afectado (opcional)</label>
              <Input value={activo} onChange={(e) => setActivo(e.target.value)}
                placeholder="host, dominio o URL"
                className="h-9 border-line bg-ink font-mono text-xs" />
            </div>
          </div>
          <div>
            <label className="mb-1.5 block font-mono text-[10px] uppercase tracking-[0.14em] text-zinc-500">Severidad</label>
            <div className="flex flex-wrap gap-2">
              {(Object.keys(ETIQUETAS_SEV) as Severidad[]).map((s) => (
                <button key={s} type="button"
                  onClick={() => setSeveridad(s)}
                  className={cn(
                    "rounded-full border px-3 py-1 text-[11px] transition-colors",
                    severidad === s
                      ? "border-crimson/50 bg-crimson/15 text-zinc-100"
                      : "border-line bg-ink text-zinc-400 hover:bg-raised",
                  )}
                >
                  {ETIQUETAS_SEV[s]}
                </button>
              ))}
            </div>
          </div>
          <div>
            <label className="mb-1 block font-mono text-[10px] uppercase tracking-[0.14em] text-zinc-500">Descripción (opcional)</label>
            <Input value={descripcion} onChange={(e) => setDescripcion(e.target.value)}
              placeholder="Qué se observó, dónde y con qué evidencia"
              className="h-9 border-line bg-ink text-xs" />
          </div>
          {error && <p className="text-[11px] text-red-300">{error}</p>}
          <Button size="sm" className="h-9 gap-1.5 bg-crimson text-xs text-white hover:bg-crimson-bright"
            onClick={alta} disabled={creando || titulo.trim().length < 3}>
            {creando ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Plus className="h-3.5 w-3.5" />}
            Registrar hallazgo
          </Button>
        </motion.div>
      )}
    </div>
  );
}

export function VistaHallazgos() {
  const hallazgos = usarConsola((s) => s.hallazgos);
  const casoActivo = usarConsola((s) => s.casoActivo);
  const [filtro, setFiltro] = useState("todos");

  const exportarCSV = async () => {
    if (!casoActivo) return;
    try {
      await descargarCSVHallazgos(casoActivo);
      toast({ title: "CSV descargado", description: "Hallazgos exportados por el backend (auditado)" });
    } catch (e) {
      toast({ title: "No se pudo exportar", description: (e as Error).message, variant: "destructive" });
    }
  };

  const presentes = useMemo(() => {
    const set = new Set<Severidad>();
    for (const h of hallazgos) set.add(h.severidad);
    return Object.keys(ORDEN_SEVERIDAD)
      .map((s) => s as Severidad)
      .filter((s) => set.has(s));
  }, [hallazgos]);

  const ordenados = useMemo(() => {
    const base = [...hallazgos].sort((a, b) => ORDEN_SEVERIDAD[a.severidad] - ORDEN_SEVERIDAD[b.severidad]);
    return filtro === "todos" ? base : base.filter((h) => h.severidad === filtro);
  }, [hallazgos, filtro]);

  if (hallazgos.length === 0) {
    return (
      <div>
        <TituloSeccion titulo="Hallazgos" descripcion="Se poblarán a medida que las fases confirmen resultados; también puedes registrar verificaciones manuales" />
        <div className="mb-4"><FormularioHallazgo /></div>
        <Vacio mensaje="Aún no hay hallazgos confirmados" />
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <TituloSeccion
        titulo={`Hallazgos del engagement (${hallazgos.length})`}
        descripcion="Cada hallazgo lleva mapeo ATT&CK, receta de verificación y resultado de detección del blue team (purple teaming)"
        accion={
          <Button
            size="sm" variant="outline"
            className="border-line text-zinc-200 hover:bg-panel hover:text-zinc-100"
            onClick={exportarCSV}
          >
            <FileSpreadsheet className="mr-2 h-4 w-4" /> Exportar CSV
          </Button>
        }
      />
      <TiraPurpleTeam hallazgos={hallazgos} />
      <FormularioHallazgo />
      {presentes.length > 1 && (
        <FiltroSegmentado
          grupo="hallazgos"
          valor={filtro}
          onChange={setFiltro}
          opciones={[
            { valor: "todos", etiqueta: `todos · ${hallazgos.length}` },
            ...presentes.map((s) => ({
              valor: s,
              etiqueta: `${ETIQUETAS_SEV[s]} · ${hallazgos.filter((h) => h.severidad === s).length}`,
            })),
          ]}
        />
      )}
      {ordenados.map((h, i) => (
        <motion.div
          key={h.id}
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.35, delay: Math.min(i * 0.06, 0.4) }}
        >
          <Tarjeta
            className={cn(
              "transition-colors duration-300 hover:border-line-strong",
              h.severidad === "critica" && "border-l-2 border-l-crimson",
            )}
          >
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div className="flex min-w-0 items-center gap-3">
                <InsigniaSeveridad severidad={h.severidad} />
                <h3 className="text-sm font-semibold text-zinc-100">{h.titulo}</h3>
              </div>
              <div className="flex flex-wrap items-center gap-2">
                {h.tecnica_mitre && (
                  <code className="rounded border border-line bg-raised px-1.5 py-0.5 font-mono text-[10px] text-zinc-400">
                    ATT&CK {h.tecnica_mitre}
                  </code>
                )}
                <Insignia tono="esmeralda">
                  <CheckCircle2 className="h-3 w-3" /> {h.estado}
                </Insignia>
              </div>
            </div>
            {h.activo && (
              <p className="mt-2 font-mono text-[11px] text-zinc-500">
                <span className="font-semibold uppercase tracking-wider text-zinc-600">activo:</span>{" "}
                <span className="text-zinc-400">{h.activo}</span>
              </p>
            )}
            <p className="mt-2.5 text-[13px] leading-relaxed text-zinc-300">{h.descripcion}</p>
            <div className="mt-3 rounded-lg border border-emerald-500/20 bg-emerald-500/[0.05] p-3">
              <p className="text-xs leading-relaxed text-emerald-200/90">
                <strong className="font-semibold">Recomendación:</strong> {h.recomendacion}
              </p>
            </div>
            <SelectorDeteccion hallazgo={h} />
            <div className="mt-2 flex items-center justify-between font-mono text-[10px] text-zinc-600">
              <span>registrado por {h.creado_por} · {new Date(h.creado_en).toLocaleTimeString("es-ES")}</span>
              <span>{h.evidencias.length > 0 ? `${h.evidencias.length} evidencia(s) vinculada(s)` : "sin evidencias vinculadas"}</span>
            </div>
          </Tarjeta>
        </motion.div>
      ))}
    </div>
  );
}

export function VistaEvidencias() {
  const evidencias = usarConsola((s) => s.evidencias);
  const cadenaBackend = usarConsola((s) => s.cadenaCustodia);
  const [filtro, setFiltro] = useState("todos");
  const [copiado, setCopiado] = useState<string | null>(null);
  const [verificacion, setVerificacion] = useState<{
    hashOk: boolean | null;
    cadenaOk: boolean | null;
  }>({ hashOk: null, cadenaOk: null });

  const tipos = useMemo(() => Array.from(new Set(evidencias.map((e) => e.tipo))), [evidencias]);
  const lista = useMemo(
    () => (filtro === "todos" ? evidencias : evidencias.filter((e) => e.tipo === filtro)),
    [evidencias, filtro],
  );

  // Verificación INDEPENDIENTE en el navegador: recalcula el SHA-256 del
  // contenido y comprueba el encadenamiento (el hash_previo de cada bloque
  // debe ser el hash del anterior; el primero referencia "genesis").
  // La firma HMAC completa la verifica el orquestador (la clave del caso
  // nunca sale del servidor): su veredicto llega en cadenaCustodia.
  useEffect(() => {
    let cancelado = false;
    async function verificar() {
      if (evidencias.length === 0) {
        setVerificacion({ hashOk: null, cadenaOk: null });
        return;
      }
      let hashOk = true;
      let cadenaOk = true;
      let previo = "genesis";
      for (const e of evidencias) {
        if (e.hash_previo !== previo) cadenaOk = false;
        try {
          const datos = await window.crypto.subtle.digest(
            "SHA-256", new TextEncoder().encode(e.contenido));
          const hash = Array.from(new Uint8Array(datos))
            .map((b) => b.toString(16).padStart(2, "0")).join("");
          if (hash !== e.hash_sha256) hashOk = false;
        } catch {
          hashOk = false;
        }
        previo = e.hash_sha256;
      }
      if (!cancelado) setVerificacion({ hashOk, cadenaOk });
    }
    verificar();
    return () => {
      cancelado = true;
    };
  }, [evidencias]);

  const localOk = verificacion.hashOk === true && verificacion.cadenaOk === true;

  if (evidencias.length === 0) {
    return (
      <div>
        <TituloSeccion titulo="Evidencias" descripcion="Cadena de custodia firmada del engagement" />
        <Vacio mensaje="Aún no hay evidencias registradas" />
      </div>
    );
  }

  const copiarHash = async (id: string, hash: string) => {
    if (await copiarTexto(hash)) {
      setCopiado(id);
      setTimeout(() => setCopiado((c) => (c === id ? null : c)), 1600);
    }
  };

  return (
    <div className="space-y-4">
      <Entrada>
        <Tarjeta className={cn(localOk && cadenaBackend.valida ? "border-emerald-500/30" : "border-crimson/50")}>
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-3">
              {localOk && cadenaBackend.valida ? (
                <ShieldCheck className="h-7 w-7 text-emerald-400" />
              ) : (
                <TriangleAlert className="h-7 w-7 text-crimson-bright" />
              )}
              <div>
                <p className="text-sm font-semibold text-zinc-100">
                  Cadena de custodia {localOk && cadenaBackend.valida ? "VÁLIDA" : "INTERRUPTIDA"}
                </p>
                <p className="text-xs text-zinc-400">
                  {evidencias.length} evidencias · SHA-256 + firma HMAC encadenada (cada bloque referencia el hash del anterior)
                </p>
              </div>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <Insignia tono={verificacion.hashOk === null ? "slate" : localOk ? "esmeralda" : "rojo"}>
                {verificacion.hashOk === null
                  ? "verificando en el navegador…"
                  : localOk
                    ? "verificación independiente (hashes + encadenado) ✓"
                    : "verificación independiente FALLIDA"}
              </Insignia>
              <Insignia tono={cadenaBackend.valida ? "esmeralda" : "rojo"}>
                {cadenaBackend.valida
                  ? `orquestador: cadena completa OK (${cadenaBackend.total})`
                  : `orquestador: ${cadenaBackend.primer_error ?? "cadena inválida"}`}
              </Insignia>
            </div>
          </div>
        </Tarjeta>
      </Entrada>

      {tipos.length > 1 && (
        <FiltroSegmentado
          grupo="evidencias"
          valor={filtro}
          onChange={setFiltro}
          opciones={[
            { valor: "todos", etiqueta: `todas · ${evidencias.length}` },
            ...tipos.map((t) => ({
              valor: t,
              etiqueta: `${t} · ${evidencias.filter((e) => e.tipo === t).length}`,
            })),
          ]}
        />
      )}

      <div className="space-y-2">
        {lista.map((e, i) => (
          <motion.div
            key={e.id}
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.3, delay: Math.min(i * 0.04, 0.35) }}
          >
            <details className="group rounded-xl border border-line bg-panel transition-colors open:border-line-strong hover:border-line-strong">
              <summary className="flex cursor-pointer flex-wrap items-center gap-3 p-4 text-sm [&::-webkit-details-marker]:hidden">
                <FileSearch className="h-4 w-4 shrink-0 text-zinc-500 transition-colors group-open:text-crimson-bright" />
                <span className="min-w-0 flex-1 truncate font-medium text-zinc-200">{e.titulo}</span>
                <Insignia tono="slate">{e.tipo}</Insignia>
                <Insignia tono="crimson">{ETIQUETA_FASE[e.fase]}</Insignia>
                <span className="hidden font-mono text-[10px] text-zinc-600 sm:inline">
                  {new Date(e.creado_en).toLocaleTimeString("es-ES")}
                </span>
              </summary>
              <div className="border-t border-line p-4 text-xs">
                <div className="mb-3 grid grid-cols-1 gap-2 sm:grid-cols-3">
                  <div className="rounded-lg border border-line bg-ink/60 p-2.5">
                    <p className="mb-1 flex items-center justify-between gap-1 font-mono text-[9px] font-semibold uppercase tracking-[0.14em] text-zinc-500">
                      <span className="flex items-center gap-1"><Fingerprint className="h-3 w-3" /> SHA-256</span>
                      <button
                        onClick={() => copiarHash(e.id, e.hash_sha256)}
                        className="rounded p-0.5 text-zinc-600 transition-colors hover:text-zinc-300"
                        aria-label="Copiar hash SHA-256"
                      >
                        {copiado === e.id ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
                      </button>
                    </p>
                    <p className="break-all font-mono text-[10px] leading-relaxed text-zinc-400">{e.hash_sha256}</p>
                  </div>
                  <div className="rounded-lg border border-line bg-ink/60 p-2.5">
                    <p className="mb-1 font-mono text-[9px] font-semibold uppercase tracking-[0.14em] text-zinc-500">Firma HMAC</p>
                    <p className="break-all font-mono text-[10px] leading-relaxed text-emerald-300/70">{e.firma_hmac.slice(0, 48)}…</p>
                  </div>
                  <div className="rounded-lg border border-line bg-ink/60 p-2.5">
                    <p className="mb-1 font-mono text-[9px] font-semibold uppercase tracking-[0.14em] text-zinc-500">Hash previo (cadena)</p>
                    <p className="break-all font-mono text-[10px] leading-relaxed text-zinc-500">
                      {e.hash_previo === "genesis" ? "genesis (primera evidencia)" : e.hash_previo.slice(0, 48) + "…"}
                    </p>
                  </div>
                </div>
                <pre className="max-h-64 overflow-auto rounded-lg border border-line bg-ink p-3 font-mono text-[11px] leading-relaxed text-zinc-300">
                  {e.contenido}
                </pre>
                <p className="mt-2 font-mono text-[10px] text-zinc-600">
                  actor: {e.actor} · {formatoTokens(e.contenido.length)} caracteres
                </p>
              </div>
            </details>
          </motion.div>
        ))}
      </div>
    </div>
  );
}
