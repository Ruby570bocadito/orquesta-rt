"use client";

/** Vista Aprobaciones: la cola operator-in-command. Aprobar/rechazar con motivo. */

import { useState } from "react";
import { motion } from "framer-motion";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Tarjeta, Insignia, InsigniaSeveridad, TituloSeccion, Vacio, barraRuido } from "@/components/consola/ui";
import { usarConsola } from "@/lib/store";
import { ETIQUETA_FASE } from "@/lib/tipos";
import { Check, ShieldAlert, X } from "lucide-react";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { cn } from "@/lib/utils";

function TarjetaAprobacion({
  id,
  titulo,
  descripcion,
  herramienta,
  argumentos,
  tecnica,
  riesgo,
  ruido,
  motivo,
  referenciaRoe,
  fase,
  indice,
  onDecidir,
}: {
  id: string;
  titulo: string;
  descripcion: string;
  herramienta: string;
  argumentos: Record<string, unknown>;
  tecnica?: string | null;
  riesgo: "critica" | "alta" | "media" | "baja" | "informativa";
  ruido: number;
  motivo: string;
  referenciaRoe: string;
  fase: string;
  indice: number;
  onDecidir: (aprobar: boolean, comentario: string) => void;
}) {
  const [dialogo, setDialogo] = useState<"aprobar" | "rechazar" | null>(null);
  const [comentario, setComentario] = useState("");
  const techo = 50;

  return (
    <motion.div
      initial={{ opacity: 0, y: 14 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.35, delay: Math.min(indice * 0.07, 0.35) }}
    >
      <Tarjeta className={cn(riesgo === "critica" && "border-crimson/40")}>
        <div className="flex flex-wrap items-start justify-between gap-2">
          <div className="min-w-0">
            <div className="mb-1.5 flex flex-wrap items-center gap-2">
              <InsigniaSeveridad severidad={riesgo} />
              <Insignia tono="slate">{ETIQUETA_FASE[fase as keyof typeof ETIQUETA_FASE] ?? fase}</Insignia>
              {tecnica && <code className="rounded border border-line bg-raised px-1.5 py-0.5 font-mono text-[10px] text-zinc-400">ATT&CK {tecnica}</code>}
            </div>
            <h3 className="text-sm font-semibold text-zinc-100">{titulo}</h3>
          </div>
          <span className="font-mono text-[9px] text-zinc-600">{id.slice(0, 14)}…</span>
        </div>

        <p className="mt-2.5 text-[13px] leading-relaxed text-zinc-400">{descripcion}</p>

        <div className="mt-3 grid grid-cols-1 gap-2 text-xs sm:grid-cols-2">
          <div className="rounded-lg border border-line bg-ink/60 p-2.5">
            <p className="font-mono text-[9px] font-semibold uppercase tracking-[0.14em] text-zinc-500">Herramienta propuesta</p>
            <code className="mt-1 block font-mono text-[11px] text-teal-300">{herramienta}</code>
            {Object.keys(argumentos).length > 0 && (
              <p className="mt-1 truncate font-mono text-[10px] text-zinc-600">
                {Object.entries(argumentos)
                  .map(([k, v]) => `${k}=${String(v)}`)
                  .join(" · ")}
              </p>
            )}
          </div>
          <div className="rounded-lg border border-line bg-ink/60 p-2.5">
            <p className="font-mono text-[9px] font-semibold uppercase tracking-[0.14em] text-zinc-500">
              Ruido estimado vs techo ROE
            </p>
            <div className="mt-2 flex items-center gap-2">
              <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-zinc-800">
                <motion.div
                  initial={{ width: 0 }}
                  animate={{ width: `${Math.min(100, ruido)}%` }}
                  transition={{ duration: 0.6, ease: [0.16, 1, 0.3, 1] }}
                  className={cn("h-full rounded-full", barraRuido(ruido))}
                />
              </div>
              <span className="font-mono text-[10px] text-zinc-400">
                {ruido}/{techo}
              </span>
            </div>
          </div>
        </div>

        <div className="mt-3 rounded-lg border border-violet-500/25 bg-violet-500/[0.06] p-2.5">
          <p className="flex items-start gap-1.5 text-[11px] leading-relaxed text-violet-200/90">
            <ShieldAlert className="mt-0.5 h-3.5 w-3.5 shrink-0 text-violet-300" />
            <span>
              <strong className="font-semibold text-violet-200">Motivo del boundary:</strong> {motivo}{" "}
              <span className="font-mono text-[10px] text-violet-300/70">[{referenciaRoe}]</span>
            </span>
          </p>
        </div>

        <div className="mt-4 flex flex-wrap justify-end gap-2">
          <Button
            size="sm"
            variant="outline"
            onClick={() => { setDialogo("rechazar"); setComentario(""); }}
            className="border-crimson/40 bg-crimson/10 text-red-300 hover:bg-crimson/20 hover:text-red-200"
          >
            <X className="h-4 w-4" /> Rechazar
          </Button>
          <Button
            size="sm"
            onClick={() => { setDialogo("aprobar"); setComentario(""); }}
            className="bg-emerald-500 text-zinc-950 hover:bg-emerald-400"
          >
            <Check className="h-4 w-4" /> Aprobar y ejecutar
          </Button>
        </div>

        <Dialog open={dialogo !== null} onOpenChange={(abierto) => !abierto && setDialogo(null)}>
          <DialogContent className="border-line bg-panel text-zinc-200 sm:max-w-md">
            <DialogHeader>
              <DialogTitle className="flex items-center gap-2 text-base">
                {dialogo === "aprobar" ? (
                  <><Check className="h-5 w-5 text-emerald-400" /> Autorizar acción</>
                ) : (
                  <><X className="h-5 w-5 text-crimson-bright" /> Rechazar acción</>
                )}
              </DialogTitle>
              <DialogDescription className="text-xs leading-relaxed text-zinc-400">
                {dialogo === "aprobar"
                  ? "Tu firma queda registrada en la auditoría inmutable junto a la ejecución y su evidencia."
                  : "El agente recibirá el rechazo y activará el patrón de reflexión: propondrá alternativas ordenadas por ruido."}
              </DialogDescription>
            </DialogHeader>
            <p className="text-xs text-zinc-300">{titulo}</p>
            <Textarea
              value={comentario}
              onChange={(e) => setComentario(e.target.value)}
              placeholder={dialogo === "aprobar" ? "Comentario opcional para el registro…" : "Motivo del rechazo (opcional)…"}
              className="min-h-20 border-line bg-ink text-sm text-zinc-200 placeholder:text-zinc-600 focus-visible:ring-crimson/40"
            />
            <DialogFooter className="gap-2">
              <Button variant="ghost" size="sm" onClick={() => setDialogo(null)} className="text-zinc-400 hover:text-zinc-200">
                Cancelar
              </Button>
              <Button
                size="sm"
                onClick={() => {
                  onDecidir(dialogo === "aprobar", comentario);
                  setDialogo(null);
                }}
                className={dialogo === "aprobar" ? "bg-emerald-500 text-zinc-950 hover:bg-emerald-400" : "bg-crimson text-white hover:bg-crimson-bright"}
              >
                Confirmar decisión
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </Tarjeta>
    </motion.div>
  );
}

export function VistaAprobaciones() {
  const aprobaciones = usarConsola((s) => s.aprobaciones);
  const decidir = usarConsola((s) => s.decidir);

  const pendientes = aprobaciones.filter((a) => a.estado === "pendiente");
  const decididas = aprobaciones.filter((a) => a.estado !== "pendiente");

  return (
    <div className="space-y-6">
      <div>
        <TituloSeccion
          titulo="Cola de aprobaciones"
          descripcion="Acciones que el boundary detiene hasta tu firma: el modelo propone, el boundary decide, tú autorizas lo crítico"
        />
        {pendientes.length === 0 ? (
          <Vacio mensaje="Sin aprobaciones pendientes: el orquestador avanza de forma autónoma dentro del ROE" />
        ) : (
          <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
            {pendientes.map((a, i) => (
              <TarjetaAprobacion
                key={a.id}
                id={a.id}
                titulo={a.titulo}
                descripcion={a.descripcion}
                herramienta={a.herramienta}
                argumentos={a.argumentos}
                tecnica={a.tecnica_mitre}
                riesgo={a.riesgo}
                ruido={a.ruido_estimado}
                motivo={a.motivo}
                referenciaRoe={a.referencia_roe}
                fase={a.fase}
                indice={i}
                onDecidir={(aprobar, comentario) => decidir(a.id, aprobar, comentario)}
              />
            ))}
          </div>
        )}
      </div>

      {decididas.length > 0 && (
        <div>
          <TituloSeccion titulo="Decisiones registradas" descripcion="Trazabilidad de tus firmas en la auditoría del engagement" />
          <div className="space-y-1.5">
            {decididas.map((a, i) => (
              <motion.div
                key={a.id}
                initial={{ opacity: 0, y: 6 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.3, delay: Math.min(i * 0.05, 0.3) }}
                className="flex flex-wrap items-center gap-3 rounded-lg border border-line bg-ink/60 px-4 py-2.5"
              >
                {a.estado === "aprobada" ? (
                  <Check className="h-4 w-4 shrink-0 text-emerald-400" />
                ) : (
                  <X className="h-4 w-4 shrink-0 text-crimson-bright" />
                )}
                <span className="min-w-0 flex-1 truncate text-[13px] text-zinc-300">{a.titulo}</span>
                <Insignia tono="slate">{ETIQUETA_FASE[a.fase]}</Insignia>
                {a.comentario_operador && (
                  <span className="hidden max-w-64 truncate text-xs italic text-zinc-500 md:inline">
                    “{a.comentario_operador}”
                  </span>
                )}
                <Insignia tono={a.estado === "aprobada" ? "esmeralda" : "rojo"}>
                  {a.estado}
                </Insignia>
                <span className="hidden shrink-0 font-mono text-[10px] text-zinc-600 sm:inline">
                  {a.decidida_en ? new Date(a.decidida_en).toLocaleTimeString("es-ES") : ""}
                </span>
              </motion.div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
