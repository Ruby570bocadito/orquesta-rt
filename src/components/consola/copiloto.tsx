"use client";

/**
 * Vista Copiloto: análisis conversacional del caso con IA real.
 *
 * El copiloto NO ejecuta acciones: consulta el contexto real del caso
 * (ROE, objetivos, hallazgos, memoria con RAG local BM25) y responde vía
 * el router semántico. El operador debe habilitarlo explícitamente por
 * caso: es una decisión de perímetro consciente que queda auditada.
 */

import { useEffect, useRef, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  Brain, Send, ShieldAlert, Sparkles, Trash2, XCircle, Loader2, Quote,
} from "lucide-react";
import { Tarjeta, Insignia, TituloSeccion, Vacio } from "@/components/consola/ui";
import { usarConsola } from "@/lib/store";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent,
  AlertDialogDescription, AlertDialogFooter, AlertDialogHeader,
  AlertDialogTitle, AlertDialogTrigger,
} from "@/components/ui/alert-dialog";
import { cn } from "@/lib/utils";

const SUGERENCIAS: Record<string, string[]> = {
  F0_scoping: [
    "Resume el alcance del ROE y qué riesgos legales debo vigilar",
    "¿Qué fases del pipeline aplican a este alcance?",
  ],
  F1_osint: [
    "¿Qué debilidades de correo o DNS hemos confirmado hasta ahora?",
    "Resume los subdominios y rutas descubiertos y qué merecen más atención",
  ],
  F2_recon: [
    "¿Qué vectores iniciales propone el pipeline y por qué?",
    "Analiza los servicios expuestos: ¿dónde hay más probabilidad de entrada?",
  ],
  F3_acceso: [
    "¿Qué hallazgos justificarían el vector elegido?",
    "¿Qué plan B recomiendas si el vector inicial falla?",
  ],
  F4_dominio: [
    "¿Qué rutas a dominio constan en la memoria del caso?",
    "¿Qué credenciales confirmadas tenemos y de dónde salieron?",
  ],
  F5_c2: [
    "¿Qué agentes C2 están activos según la memoria?",
    "Resume la evidencia de post-explotación recopilada",
  ],
  F6_phishing: [
    "¿Qué debilidades de correo hacen viable la campaña autorizada?",
    "¿Qué controles detectarían nuestra campaña?",
  ],
  F7_informe: [
    "Ayúdame a priorizar los hallazgos para el informe ejecutivo",
    "¿Qué evidencias clave soportan cada hallazgo crítico?",
  ],
  cierre: [
    "Resume el engagement para el informe final",
    "¿Qué higiene de cierre queda pendiente?",
  ],
};

const CLAVE_FASE: Record<string, string> = {
  F0_scoping: "F0_scoping", F0: "F0_scoping",
  F1_osint: "F1_osint", F1: "F1_osint",
  F2_recon: "F2_recon", F2: "F2_recon",
  F3_acceso: "F3_acceso", F3: "F3_acceso",
  F4_dominio: "F4_dominio", F4: "F4_dominio",
  F5_c2: "F5_c2", F5: "F5_c2",
  F6_phishing: "F6_phishing", F6: "F6_phishing",
  F7_informe: "F7_informe", F7: "F7_informe",
  cierre: "cierre",
};

export function VistaCopiloto() {
  const config = usarConsola((s) => s.copilotoConfig);
  const conversacion = usarConsola((s) => s.copilotoConversacion);
  const ocupado = usarConsola((s) => s.copilotoOcupado);
  const fase = usarConsola((s) => s.engagement?.fase_actual ?? "");
  const cargarConfig = usarConsola((s) => s.cargarCopilotoConfig);
  const alternar = usarConsola((s) => s.alternarCopiloto);
  const consultar = usarConsola((s) => s.consultarCopiloto);
  const limpiar = usarConsola((s) => s.limpiarConversacionCopiloto);
  const [borrador, setBorrador] = useState("");
  const finRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    cargarConfig().catch(() => undefined);
  }, [cargarConfig]);

  useEffect(() => {
    finRef.current?.scrollIntoView({ behavior: "smooth", block: "end" });
  }, [conversacion.length, ocupado]);

  const clave = CLAVE_FASE[fase] ?? "";
  const sugerencias = SUGERENCIAS[clave] ?? SUGERENCIAS.F2_recon;

  const enviar = (texto: string) => {
    if (!texto.trim() || ocupado) return;
    setBorrador("");
    consultar(texto).catch(() => undefined);
  };

  return (
    <div className="space-y-4">
      <TituloSeccion
        titulo="Copiloto del caso"
        descripcion="IA real · análisis con contexto del caso (ROE, objetivos, hallazgos y memoria) · nunca ejecuta acciones"
      />

      {/* Estado del copiloto: decisión consciente de perímetro */}
      <Tarjeta className="p-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <Insignia tono={config?.habilitado ? "esmeralda" : "slate"}>
                {config?.habilitado ? "Habilitado" : "Deshabilitado"}
              </Insignia>
              <span className="text-xs text-zinc-500">
                política de salida: <b className="text-zinc-300">{config?.politica_salida ?? "—"}</b>
              </span>
            </div>
            <p className="max-w-xl text-xs leading-relaxed text-zinc-500">
              {config?.habilitado
                ? `Cada consulta envía contexto del caso al backend configurado (${config?.backends?.frontera?.configurado ? `frontera: ${config?.backends?.frontera?.modelo}` : config?.backends?.local?.configurado ? "inferencia local" : "ninguno configurado"}). La consulta queda registrada en la auditoría.`
                : "El copiloto está deshabilitado por defecto: activarlo implica que fragmentos del caso viajan al backend de inferencia configurado. Con POLITICA_SALIDA=perimetro solo se usaría inferencia local."}
            </p>
          </div>
          {config?.habilitado ? (
            <AlertDialog>
              <AlertDialogTrigger asChild>
                <Button variant="outline" className="border-line text-zinc-300 hover:bg-panel hover:text-zinc-100">
                  <XCircle className="mr-2 h-4 w-4" /> Deshabilitar
                </Button>
              </AlertDialogTrigger>
              <AlertDialogContent className="border-line bg-raised text-zinc-100">
                <AlertDialogHeader>
                  <AlertDialogTitle>Deshabilitar copiloto</AlertDialogTitle>
                  <AlertDialogDescription className="text-zinc-400">
                    El copiloto dejará de responder en este caso. La decisión queda
                    registrada en la auditoría del caso.
                  </AlertDialogDescription>
                </AlertDialogHeader>
                <AlertDialogFooter>
                  <AlertDialogCancel className="border-line bg-transparent text-zinc-300 hover:bg-panel hover:text-zinc-100">
                    Cancelar
                  </AlertDialogCancel>
                  <AlertDialogAction
                    className="bg-crimson text-white hover:bg-crimson/85"
                    onClick={() => alternar(false).catch(() => undefined)}
                  >
                    Deshabilitar
                  </AlertDialogAction>
                </AlertDialogFooter>
              </AlertDialogContent>
            </AlertDialog>
          ) : (
            <AlertDialog>
              <AlertDialogTrigger asChild>
                <Button className="bg-emerald-600 text-white hover:bg-emerald-500">
                  <Sparkles className="mr-2 h-4 w-4" /> Habilitar copiloto
                </Button>
              </AlertDialogTrigger>
              <AlertDialogContent className="border-line bg-raised text-zinc-100">
                <AlertDialogHeader>
                  <AlertDialogTitle className="flex items-center gap-2">
                    <ShieldAlert className="h-5 w-5 text-amber-400" /> Habilitación de perímetro
                  </AlertDialogTitle>
                  <AlertDialogDescription className="text-zinc-400">
                    Al habilitar, cada consulta enviará al backend de inferencia
                    configurado un resumen del caso (ROE, fase, hallazgos,
                    objetivos y fragmentos relevantes de la memoria). En un
                    entorno on-prem estricto, configura
                    <code className="mx-1 rounded bg-black/40 px-1 text-xs">POLITICA_SALIDA=perimetro</code>
                    para forzar inferencia local. La habilitación queda firmada en
                    la auditoría con tu identidad.
                  </AlertDialogDescription>
                </AlertDialogHeader>
                <AlertDialogFooter>
                  <AlertDialogCancel className="border-line bg-transparent text-zinc-300 hover:bg-panel hover:text-zinc-100">
                    Cancelar
                  </AlertDialogCancel>
                  <AlertDialogAction
                    className="bg-emerald-600 text-white hover:bg-emerald-500"
                    onClick={() => alternar(true).catch(() => undefined)}
                  >
                    Habilitar y firmar en auditoría
                  </AlertDialogAction>
                </AlertDialogFooter>
              </AlertDialogContent>
            </AlertDialog>
          )}
        </div>
      </Tarjeta>

      {!config?.habilitado ? (
        <Vacio mensaje="Habilita el copiloto para consultar al analista IA sobre este caso" />
      ) : (
        <>
          <Tarjeta className="flex h-[52vh] flex-col overflow-hidden p-0">
            <div className="flex items-center justify-between border-b border-line px-4 py-2">
              <span className="text-xs font-medium tracking-wide text-zinc-500">
                Conversación del caso · {conversacion.length} mensajes
              </span>
              <Button
                variant="ghost" size="sm"
                className="h-7 text-xs text-zinc-500 hover:bg-panel hover:text-zinc-200"
                onClick={limpiar}
                disabled={conversacion.length === 0}
              >
                <Trash2 className="mr-1 h-3.5 w-3.5" /> Limpiar vista
              </Button>
            </div>
            <div className="flex-1 space-y-4 overflow-y-auto p-4">
              {conversacion.length === 0 && (
                <div className="space-y-2 pt-6 text-center">
                  <Brain className="mx-auto h-8 w-8 text-zinc-700" />
                  <p className="text-sm text-zinc-500">
                    Pregunta al copiloto sobre el estado del caso, vectores,
                    hallazgos o próximos pasos.
                  </p>
                </div>
              )}
              <AnimatePresence initial={false}>
                {conversacion.map((m, i) => (
                  <motion.div
                    key={`${m.ts}-${i}`}
                    initial={{ opacity: 0, y: 8 }}
                    animate={{ opacity: 1, y: 0 }}
                    className={cn("flex", m.rol === "operador" ? "justify-end" : "justify-start")}
                  >
                    <div
                      className={cn(
                        "max-w-[85%] space-y-2 rounded-lg border px-3.5 py-2.5 text-sm leading-relaxed",
                        m.rol === "operador"
                          ? "border-crimson/35 bg-crimson/10 text-zinc-100"
                          : m.error
                            ? "border-red-500/40 bg-red-500/10 text-red-200"
                            : "border-line bg-panel text-zinc-200",
                      )}
                    >
                      {m.rol === "copiloto" && m.secciones && m.secciones.length > 0 ? (
                        <div className="space-y-2">
                          {m.secciones.map((sec) => (
                            <div key={sec.titulo} className="rounded border border-line/60 bg-black/10 p-2">
                              <p className="mb-1 text-[11px] font-semibold uppercase tracking-wide text-crimson-bright">
                                {sec.titulo}
                              </p>
                              <p className="whitespace-pre-wrap text-[13px] leading-relaxed">{sec.cuerpo}</p>
                            </div>
                          ))}
                        </div>
                      ) : (
                        <p className="whitespace-pre-wrap">{m.texto}</p>
                      )}
                      {m.rol === "copiloto" && !m.error && (
                        <div className="flex flex-wrap items-center gap-2 border-t border-line/70 pt-2 text-[11px] text-zinc-500">
                          <span>{m.modelo} · {m.tipo_modelo}</span>
                          {typeof m.tokens === "number" && <span>· {m.tokens} tokens</span>}
                          {typeof m.coste_usd === "number" && m.coste_usd > 0 && (
                            <span>· ${m.coste_usd.toFixed(4)}</span>
                          )}
                        </div>
                      )}
                      {m.fuentes && m.fuentes.length > 0 && (
                        <div className="space-y-1 border-t border-line/70 pt-2">
                          <span className="text-[11px] font-medium text-zinc-500">
                            Fuentes del caso usadas:
                          </span>
                          {m.fuentes.slice(0, 4).map((f) => (
                            <div key={f.id} className="flex items-start gap-1.5 text-[11px] text-zinc-400">
                              <Quote className="mt-0.5 h-3 w-3 shrink-0 text-zinc-600" />
                              <span><b className="text-zinc-300">[{f.tipo}]</b> {f.titulo}</span>
                            </div>
                          ))}
                        </div>
                      )}
                      {m.rol === "copiloto" && m.sugerencias && m.sugerencias.length > 0 && (
                        <div className="space-y-1.5 border-t border-line/70 pt-2">
                          <span className="text-[11px] font-medium text-zinc-500">
                            Sugerencias accionables (canal correcto):
                          </span>
                          <div className="flex flex-wrap gap-1.5">
                            {m.sugerencias.map((s, j) => (
                              <button
                                key={`${m.ts}-sug-${j}`}
                                onClick={() => enviar(s.titulo)}
                                disabled={ocupado}
                                title={s.detalle}
                                className="group rounded-full border border-line bg-raised px-2.5 py-1 text-[11px] text-zinc-300 transition-colors hover:border-crimson/40 hover:text-zinc-100 disabled:opacity-50"
                              >
                                {s.titulo}
                                <span className="ml-1.5 text-zinc-500 group-hover:text-zinc-400">
                                  {Math.round(s.confianza * 100)}% · {s.canal}
                                </span>
                              </button>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  </motion.div>
                ))}
              </AnimatePresence>
              {ocupado && (
                <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="flex justify-start">
                  <div className="flex items-center gap-2 rounded-lg border border-line bg-panel px-3.5 py-2.5 text-sm text-zinc-500">
                    <Loader2 className="h-4 w-4 animate-spin" /> El copiloto analiza el caso…
                  </div>
                </motion.div>
              )}
              <div ref={finRef} />
            </div>
            <div className="border-t border-line p-3">
              <form
                className="flex gap-2"
                onSubmit={(e) => { e.preventDefault(); enviar(borrador); }}
              >
                <Input
                  value={borrador}
                  onChange={(e) => setBorrador(e.target.value)}
                  placeholder={ocupado ? "Esperando respuesta…" : "Pregunta sobre el caso…"}
                  disabled={ocupado}
                  className="border-line bg-panel text-zinc-100 placeholder:text-zinc-600"
                />
                <Button type="submit" disabled={ocupado || !borrador.trim()}
                        className="bg-crimson text-white hover:bg-crimson/85">
                  <Send className="h-4 w-4" />
                </Button>
              </form>
            </div>
          </Tarjeta>

          <div className="space-y-2">
            <p className="flex items-center gap-2 text-sm font-semibold text-zinc-100">
              <Sparkles className="h-4 w-4 text-crimson-bright" /> Sugeridas para esta fase
            </p>
            <div className="flex flex-wrap gap-2">
              {sugerencias.map((s) => (
                <button
                  key={s}
                  onClick={() => enviar(s)}
                  disabled={ocupado}
                  className="rounded-full border border-line bg-panel px-3 py-1.5 text-xs text-zinc-400 transition-colors hover:border-crimson/40 hover:text-zinc-100 disabled:opacity-50"
                >
                  {s}
                </button>
              ))}
            </div>
          </div>
        </>
      )}
    </div>
  );
}
