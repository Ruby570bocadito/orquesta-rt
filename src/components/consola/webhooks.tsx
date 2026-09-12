"use client";

/**
 * Sección Webhooks de notificación operativa (v16, admin).
 *
 * Gestión REAL de receptores: alta con firma HMAC-SHA256 (secreto generado
 * o propio, mostrado UNA sola vez), suscripción por evento, prueba con POST
 * sincrónico real, registro de entregas (HTTP real de cada intento) y baja.
 * La prueba y las entregas muestran lo que el receptor respondió de verdad:
 * nada de éxito simulado.
 */

import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import {
  BellRing, CheckCircle2, ChevronDown, ChevronUp, Loader2, Plus, RefreshCw,
  Send, Trash2, XCircle,
} from "lucide-react";
import { Tarjeta, Insignia, TituloSeccion, Vacio } from "@/components/consola/ui";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { usarConsola, EntregaWebhook } from "@/lib/store";
import { cn } from "@/lib/utils";

const ETIQUETA_EVENTO: Record<string, string> = {
  "hallazgo.registrado": "Hallazgo registrado",
  "hallazgo.deteccion": "Detección documentada",
  "aprobacion.solicitada": "Aprobación solicitada",
  "aprobacion.decidida": "Aprobación decidida",
  "roe.parada_emergencia": "Parada de emergencia",
  "webhook.prueba": "Ping de prueba",
};

/** Bloque de entregas compartido por receptores de BD y el canal heredado
 *  (z2-ronda-4): mismo registro, mismo formato — el receptor "entorno" es
 *  el canal heredado WEBHOOK_URL. */
function BloqueEntregas({ id, entregas }: { id: string; entregas: Record<string, EntregaWebhook[]> }) {
  return (
    <div className="mt-2 rounded-md border border-line bg-ink p-2">
      {(entregas[id] ?? []).length === 0 ? (
        <p className="px-1 text-[11px] text-zinc-500">Sin entregas registradas todavía</p>
      ) : (
        <ul className="space-y-1">
          {entregas[id].map((e, i) => (
            <li key={i} className="flex flex-wrap items-center gap-2 font-mono text-[10px]">
              <span className={e.ok ? "text-emerald-300" : "text-red-300"}>
                {e.ok ? "OK" : "FALLO"}{e.http ? ` ${e.http}` : ""}
              </span>
              <span className="text-zinc-400">{ETIQUETA_EVENTO[e.evento] ?? e.evento}</span>
              <span className="text-zinc-600">{e.engagement_id}</span>
              {e.intentos > 1 && <span className="text-amber-300">{e.intentos} intentos</span>}
              {e.error && <span className="text-red-300/80">{e.error.slice(0, 90)}</span>}
              <span className="ml-auto text-zinc-600">{new Date(e.creado_en).toLocaleString("es-ES")}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

export function SeccionWebhooks() {
  const sesion = usarConsola((s) => s.sesion);
  const webhooks = usarConsola((s) => s.webhooks);
  const eventosCatalogo = usarConsola((s) => s.eventosWebhook);
  // z2-ronda-4: canal heredado WEBHOOK_URL (visible y con sus entregas)
  const canalHeredado = usarConsola((s) => s.canalHeredado);
  const cargarWebhooks = usarConsola((s) => s.cargarWebhooks);
  const crearWebhook = usarConsola((s) => s.crearWebhook);
  const actualizarWebhook = usarConsola((s) => s.actualizarWebhook);
  const eliminarWebhook = usarConsola((s) => s.eliminarWebhook);
  const probarWebhook = usarConsola((s) => s.probarWebhook);
  const cargarEntregasWebhook = usarConsola((s) => s.cargarEntregasWebhook);

  const [abierto, setAbierto] = useState(false);
  const [url, setUrl] = useState("");
  const [descripcion, setDescripcion] = useState("");
  const [secreto, setSecreto] = useState("");
  const [seleccion, setSeleccion] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [creando, setCreando] = useState(false);
  const [secretoGenerado, setSecretoGenerado] = useState<string | null>(null);
  const [probando, setProbando] = useState<string | null>(null);
  const [resultadoPrueba, setResultadoPrueba] = useState<Record<string, { ok: boolean; texto: string }>>({});
  const [entregasDe, setEntregasDe] = useState<string | null>(null);
  const [entregas, setEntregas] = useState<Record<string, EntregaWebhook[]>>({});
  const [porEliminar, setPorEliminar] = useState<string | null>(null);

  const esAdmin = sesion?.rol === "admin";

  useEffect(() => {
    if (esAdmin) void cargarWebhooks();
  }, [esAdmin, cargarWebhooks]);

  if (!esAdmin) {
    return (
      <Tarjeta>
        <div className="flex items-start gap-3">
          <BellRing className="mt-0.5 h-4 w-4 shrink-0 text-zinc-400" />
          <p className="text-[12px] leading-relaxed text-zinc-400">
            Los webhooks de notificación operativa los gestiona un operador
            <span className="font-semibold text-zinc-200"> admin</span>: cada receptor
            recibe un POST real firmado (HMAC-SHA256) con los eventos que elija
            (hallazgos, detecciones, aprobaciones, parada de emergencia).
          </p>
        </div>
      </Tarjeta>
    );
  }

  const alternarEvento = (ev: string) => {
    setSeleccion((s) => (s.includes(ev) ? s.filter((x) => x !== ev) : [...s, ev]));
  };

  const generarSecreto = () => {
    const bytes = new Uint8Array(32);
    crypto.getRandomValues(bytes);
    setSecreto(Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join(""));
  };

  const alta = async () => {
    setCreando(true);
    setError(null);
    try {
      const creado = await crearWebhook({ url, eventos: seleccion, secreto, descripcion });
      setSecretoGenerado(creado.secreto_generado ?? null);
      setUrl("");
      setDescripcion("");
      setSecreto("");
      setSeleccion([]);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setCreando(false);
    }
  };

  const probar = async (id: string) => {
    setProbando(id);
    try {
      const r = await probarWebhook(id);
      setResultadoPrueba((m) => ({
        ...m, [id]: r.enviado
          ? { ok: true, texto: `POST entregado (HTTP ${r.http})` }
          : { ok: false, texto: `sin entrega${r.http ? ` — HTTP ${r.http}` : ""}${r.error ? ` — ${r.error}` : ""}` },
      }));
    } catch (e) {
      setResultadoPrueba((m) => ({ ...m, [id]: { ok: false, texto: (e as Error).message } }));
    } finally {
      setProbando(null);
    }
  };

  const verEntregas = async (id: string) => {
    if (entregasDe === id) {
      setEntregasDe(null);
      return;
    }
    setEntregasDe(id);
    try {
      const lista = await cargarEntregasWebhook(id);
      setEntregas((m) => ({ ...m, [id]: lista }));
    } catch {
      setEntregas((m) => ({ ...m, [id]: [] }));
    }
  };

  const lista = webhooks ?? [];

  return (
    <Tarjeta>
      <div className="flex flex-wrap items-start justify-between gap-3">
        <TituloSeccion
          titulo="Webhooks de notificación operativa"
          descripcion="POST real firmado (HMAC-SHA256) a los receptores que elijas — Slack, Mattermost, n8n o un endpoint propio. Entrega con registro y un reintento ante fallo transitorio."
        />
        <Button
          variant="outline" size="sm"
          className="h-8 gap-1.5 border-line bg-panel text-xs text-zinc-300 hover:bg-raised"
          onClick={() => setAbierto((a) => !a)}
        >
          {abierto ? <ChevronUp className="h-3.5 w-3.5" /> : <Plus className="h-3.5 w-3.5" />}
          Nuevo receptor
        </Button>
      </div>

      {secretoGenerado && (
        <div className="mb-4 rounded-lg border border-emerald-500/30 bg-emerald-500/[0.07] p-3">
          <p className="text-xs font-semibold text-emerald-200">Secreto generado — cópialo AHORA: no volverá a mostrarse</p>
          <p className="mt-1 break-all font-mono text-[11px] text-emerald-100">{secretoGenerado}</p>
          <Button variant="outline" size="sm" className="mt-2 h-7 border-line bg-panel text-[11px] text-zinc-300 hover:bg-raised"
            onClick={() => setSecretoGenerado(null)}>Entendido</Button>
        </div>
      )}

      {abierto && (
        <motion.div
          initial={{ opacity: 0, y: -6 }} animate={{ opacity: 1, y: 0 }}
          className="mb-5 space-y-3 rounded-lg border border-line bg-ink/40 p-4"
        >
          <div className="grid gap-3 md:grid-cols-2">
            <div>
              <label className="mb-1 block font-mono text-[10px] uppercase tracking-[0.14em] text-zinc-500">URL del receptor</label>
              <Input value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://n8n.interno/webhook/orquesta"
                className="h-9 border-line bg-ink font-mono text-xs" />
            </div>
            <div>
              <label className="mb-1 block font-mono text-[10px] uppercase tracking-[0.14em] text-zinc-500">Descripción (opcional)</label>
              <Input value={descripcion} onChange={(e) => setDescripcion(e.target.value)} placeholder="Canal #red-team de Mattermost"
                className="h-9 border-line bg-ink text-xs" />
            </div>
          </div>
          <div>
            <label className="mb-1 block font-mono text-[10px] uppercase tracking-[0.14em] text-zinc-500">
              Secreto de firma (opcional: vacío = lo genera el servidor)
            </label>
            <div className="flex gap-2">
              <Input value={secreto} onChange={(e) => setSecreto(e.target.value)} placeholder="mínimo 16 caracteres si lo escribes"
                className="h-9 border-line bg-ink font-mono text-xs" />
              <Button variant="outline" size="sm" className="h-9 shrink-0 border-line bg-panel text-xs text-zinc-300 hover:bg-raised"
                onClick={generarSecreto}>Generar</Button>
            </div>
          </div>
          <div>
            <label className="mb-1.5 block font-mono text-[10px] uppercase tracking-[0.14em] text-zinc-500">Eventos a los que suscribir</label>
            <div className="flex flex-wrap gap-2">
              {(eventosCatalogo.length ? eventosCatalogo : Object.keys(ETIQUETA_EVENTO)).map((ev) => (
                <button
                  key={ev} type="button"
                  onClick={() => alternarEvento(ev)}
                  className={cn(
                    "rounded-full border px-3 py-1 text-[11px] transition-colors",
                    seleccion.includes(ev)
                      ? "border-crimson/50 bg-crimson/15 text-zinc-100"
                      : "border-line bg-ink text-zinc-400 hover:bg-raised",
                  )}
                >
                  {ETIQUETA_EVENTO[ev] ?? ev}
                </button>
              ))}
            </div>
          </div>
          {error && <p className="text-[11px] text-red-300">{error}</p>}
          <Button size="sm" className="h-9 gap-1.5 bg-crimson text-xs text-white hover:bg-crimson-bright"
            onClick={alta} disabled={creando || !url || seleccion.length === 0}>
            {creando ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Send className="h-3.5 w-3.5" />}
            Dar de alta receptor
          </Button>
        </motion.div>
      )}

      {lista.length === 0 && !canalHeredado?.activo && !abierto ? (
        <Vacio mensaje="Sin receptores configurados: los eventos operativos no se notifican a ningún canal todavía" />
      ) : (
        <ul className="space-y-3">
          {lista.map((w) => {
            const prueba = resultadoPrueba[w.id];
            return (
              <li key={w.id} className="rounded-lg border border-line bg-ink/40 p-3.5">
                <div className="flex flex-wrap items-center gap-2">
                  <p className="min-w-0 flex-1 truncate font-mono text-xs text-zinc-100" title={w.url}>{w.url}</p>
                  <Insignia tono={w.activo ? "esmeralda" : "slate"}>{w.activo ? "activo" : "pausado"}</Insignia>
                  {w.descripcion && <span className="text-[11px] text-zinc-500">{w.descripcion}</span>}
                </div>
                <div className="mt-2 flex flex-wrap gap-1.5">
                  {w.eventos.map((ev) => (
                    <Insignia key={ev} tono="ambar">{ETIQUETA_EVENTO[ev] ?? ev}</Insignia>
                  ))}
                  {w.tiene_secreto && <Insignia tono="esmeralda">firmado</Insignia>}
                </div>
                <div className="mt-3 flex flex-wrap items-center gap-2">
                  <Button variant="outline" size="sm" className="h-7 gap-1.5 border-line bg-panel text-[11px] text-zinc-300 hover:bg-raised"
                    onClick={() => probar(w.id)} disabled={probando === w.id}>
                    {probando === w.id ? <Loader2 className="h-3 w-3 animate-spin" /> : <Send className="h-3 w-3" />}
                    Probar
                  </Button>
                  <Button variant="outline" size="sm" className="h-7 gap-1.5 border-line bg-panel text-[11px] text-zinc-300 hover:bg-raised"
                    onClick={() => actualizarWebhook(w.id, { activo: !w.activo }).catch((e: Error) => setError(e.message))}>
                    {w.activo ? "Pausar" : "Reactivar"}
                  </Button>
                  <Button variant="outline" size="sm" className="h-7 gap-1.5 border-line bg-panel text-[11px] text-zinc-300 hover:bg-raised"
                    onClick={() => verEntregas(w.id)}>
                    {entregasDe === w.id ? <ChevronUp className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />}
                    Entregas
                  </Button>
                  {porEliminar === w.id ? (
                    <span className="flex items-center gap-1.5 text-[11px] text-red-300">
                      ¿eliminar receptor y entregas?
                      <button className="rounded border border-red-500/40 px-2 py-0.5 hover:bg-red-500/10"
                        onClick={() => { eliminarWebhook(w.id).catch((e: Error) => setError(e.message)); setPorEliminar(null); }}>
                        Sí, eliminar
                      </button>
                      <button className="rounded border border-line px-2 py-0.5 text-zinc-400 hover:bg-raised"
                        onClick={() => setPorEliminar(null)}>No</button>
                    </span>
                  ) : (
                    <Button variant="ghost" size="sm" className="h-7 gap-1.5 px-2 text-[11px] text-zinc-500 hover:text-red-300"
                      onClick={() => setPorEliminar(w.id)}>
                      <Trash2 className="h-3 w-3" />
                    </Button>
                  )}
                </div>
                {prueba && (
                  <p className={cn("mt-2 flex items-center gap-1.5 text-[11px]", prueba.ok ? "text-emerald-300" : "text-red-300")}>
                    {prueba.ok ? <CheckCircle2 className="h-3.5 w-3.5" /> : <XCircle className="h-3.5 w-3.5" />}
                    {prueba.texto}
                  </p>
                )}
                {entregasDe === w.id && (
                  <BloqueEntregas id={w.id} entregas={entregas} />
                )}
              </li>
            );
          })}
        </ul>
      )}

      {/* z2-ronda-4: canal heredado WEBHOOK_URL — vive en el ENTORNO del
          despliegue, no en la BD, así que no salía entre los receptores y
          el operador no veía sus entregas. Lectura solo: se configura por
          entorno y pasa por el mismo veto SSRF que los receptores. */}
      {canalHeredado?.activo && (
        <ul className="mt-3 space-y-3">
          <li className="rounded-lg border border-dashed border-line bg-ink/40 p-3.5">
            <div className="flex flex-wrap items-center gap-2">
              <p className="min-w-0 flex-1 truncate font-mono text-xs text-zinc-100" title={canalHeredado.url}>
                {canalHeredado.url}
              </p>
              <Insignia tono="slate">canal heredado · WEBHOOK_URL</Insignia>
            </div>
            <p className="mt-1 text-[11px] text-zinc-500">
              recibe TODOS los eventos · se configura por entorno (no en la consola) ·
              mismo veto SSRF y firma que los receptores de la BD
            </p>
            <div className="mt-3 flex flex-wrap items-center gap-2">
              <Button variant="outline" size="sm" className="h-7 gap-1.5 border-line bg-panel text-[11px] text-zinc-300 hover:bg-raised"
                onClick={() => verEntregas("entorno")}>
                {entregasDe === "entorno" ? <ChevronUp className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />}
                Entregas
              </Button>
            </div>
            {entregasDe === "entorno" && <BloqueEntregas id="entorno" entregas={entregas} />}
          </li>
        </ul>
      )}

      <p className="mt-4 flex items-center gap-2 font-mono text-[10px] text-zinc-600">
        <RefreshCw className="h-3 w-3" />
        Verificación del receptor: cabecera X-Orquesta-Firma = sha256=HMAC(cuerpo, secreto) · cabecera X-Orquesta-Evento con el tipo
      </p>
    </Tarjeta>
  );
}
