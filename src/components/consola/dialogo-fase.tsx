"use client";

/**
 * Diálogo de ejecución de la fase activa: pide al operador el contexto que
 * el agente necesita según la fase (notas de cliente en F0, vector elegido
 * en F3, perfil objetivo en F6) y lo envía al orquestador. Sin contexto no
 * hay ejecución: el operador siempre manda.
 */

import { useEffect, useState } from "react";
import { Loader2, Play } from "lucide-react";
import {
  Dialog, DialogContent, DialogDescription, DialogFooter,
  DialogHeader, DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Insignia } from "@/components/consola/ui";
import { usarConsola } from "@/lib/store";
import { ETIQUETA_FASE, FaseId } from "@/lib/tipos";

export function DialogEjecutarFase({
  abierta,
  onOpenChange,
  onHecho,
}: {
  abierta: boolean;
  onOpenChange: (v: boolean) => void;
  onHecho: (resumen: string) => void;
}) {
  const engagement = usarConsola((s) => s.engagement);
  const [notas, setNotas] = useState("");
  const [vector, setVector] = useState("");
  const [modulo, setModulo] = useState("");
  const [rhosts, setRhosts] = useState("");
  const [perfil, setPerfil] = useState("");
  const [destinatarios, setDestinatarios] = useState("");
  const [ejecutando, setEjecutando] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fase = engagement?.fase_actual as FaseId | undefined;

  useEffect(() => {
    if (abierta) {
      setNotas("");
      setVector("");
      setModulo("");
      setRhosts("");
      setPerfil("");
      setDestinatarios("");
      setError(null);
    }
  }, [abierta]);

  if (!fase) return null;

  const pedirNotas = fase === "F0_scoping";
  const pedirVector = fase === "F3_acceso_inicial";
  const pedirPerfil = fase === "F6_phishing";
  const puedeEjecutar =
    !ejecutando && (!pedirNotas || notas.trim().length >= 5) &&
    (!pedirVector || vector.trim().length >= 4) &&
    (!pedirPerfil || perfil.trim().length >= 3);

  const ejecutar = async () => {
    setEjecutando(true);
    setError(null);
    try {
      const r = await usarConsola.getState().avanzarFase({
        notas_cliente: notas,
        vector_elegido: vector,
        perfil_objetivo: perfil,
        modulo: pedirVector ? modulo.trim() : "",
        opciones: pedirVector && rhosts.trim()
          ? { RHOSTS: rhosts.trim() } : {},
        destinatarios: pedirPerfil
          ? destinatarios.split(/[,;\s]+/).map((d) => d.trim()).filter(Boolean)
          : [],
      });
      onOpenChange(false);
      onHecho(r.resumen || `Fase ${r.fase ?? ""} procesada por el orquestador`);
      if (r.espera) {
        // El aviso de nueva aprobación lo emite la suscripción del shell
      }
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setEjecutando(false);
    }
  };

  return (
    <Dialog open={abierta} onOpenChange={onOpenChange}>
      <DialogContent className="border-line bg-panel text-zinc-200 sm:max-w-lg">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2 text-base">
            <Play className="h-4 w-4 text-crimson-bright" />
            Ejecutar fase
            <Insignia tono="crimson">{ETIQUETA_FASE[fase]}</Insignia>
          </DialogTitle>
          <DialogDescription className="text-xs leading-relaxed text-zinc-400">
            El agente ejecutará las herramientas de la fase dentro del ROE firmado.
            Las acciones por encima del umbral de riesgo se detendrán en el boundary
            y aparecerán en la cola de aprobaciones.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4 py-1">
          {pedirNotas && (
            <div className="space-y-1.5">
              <Label htmlFor="notas-f0" className="text-xs text-zinc-300">
                Notas de la entrevista con el cliente (definen el borrador de ROE)
              </Label>
              <Textarea
                id="notas-f0"
                value={notas}
                onChange={(e) => setNotas(e.target.value)}
                placeholder="Objetivos del cliente, activos críticos, restricciones del negocio, criterios de éxito…"
                className="min-h-24 border-line bg-ink/60 text-sm"
              />
            </div>
          )}

          {pedirVector && (
            <>
              <div className="space-y-1.5">
                <Label htmlFor="vector-f3" className="text-xs text-zinc-300">
                  Vector de acceso inicial a explotar (validado en F2)
                </Label>
                <Input
                  id="vector-f3"
                  value={vector}
                  onChange={(e) => setVector(e.target.value)}
                  placeholder="Servicio web expuesto en http://localhost:8080"
                  className="border-line bg-ink/60 font-mono text-xs"
                />
                <p className="text-[11px] leading-relaxed text-zinc-500">
                  Debe corresponder a un vector propuesto por el reconocimiento.
                  La explotación requiere tu firma en el boundary.
                </p>
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="modulo-f3" className="text-xs text-zinc-300">
                  Módulo Metasploit RPC (opcional — explotación REAL vía msfrpcd)
                </Label>
                <Input
                  id="modulo-f3"
                  value={modulo}
                  onChange={(e) => setModulo(e.target.value)}
                  placeholder="exploit/multi/http/... (vacío = plan B documentado)"
                  className="border-line bg-ink/60 font-mono text-xs"
                />
                <Input
                  id="rhosts-f3"
                  value={rhosts}
                  onChange={(e) => setRhosts(e.target.value)}
                  placeholder="RHOSTS = IP del objetivo (validada contra el ROE)"
                  className="border-line bg-ink/60 font-mono text-xs"
                />
                <p className="text-[11px] leading-relaxed text-zinc-500">
                  Se ejecuta module.execute en la infraestructura MSF que tengas
                  configurada (MSF_HOST/MSF_USER). RHOSTS debe estar dentro del
                  alcance del ROE: el transporte lo verifica antes de lanzar.
                </p>
              </div>
            </>
          )}

          {pedirPerfil && (
            <>
              <div className="space-y-1.5">
                <Label htmlFor="perfil-f6" className="text-xs text-zinc-300">
                  Perfil objetivo de la campaña autorizada
                </Label>
                <Input
                  id="perfil-f6"
                  value={perfil}
                  onChange={(e) => setPerfil(e.target.value)}
                  placeholder="empleado_generico | finanzas | helpdesk | dirección"
                  className="border-line bg-ink/60 font-mono text-xs"
                />
                <p className="text-[11px] leading-relaxed text-zinc-500">
                  La plantilla exige una aprobación; el envío, una segunda.
                </p>
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="destinatarios-f6" className="text-xs text-zinc-300">
                  Destinatarios autorizados para el envío real (SMTP del equipo)
                </Label>
                <Input
                  id="destinatarios-f6"
                  value={destinatarios}
                  onChange={(e) => setDestinatarios(e.target.value)}
                  placeholder="nombre@cliente.com, otro@cliente.com (vacío = solo plantilla)"
                  className="border-line bg-ink/60 font-mono text-xs"
                />
                <p className="text-[11px] leading-relaxed text-zinc-500">
                  Solo se envía vía la infraestructura SMTP configurada
                  (SMTP_HOST/SMTP_REMITENTE) y tras firmar el envío. Sin
                  infraestructura, la plataforma documenta el requisito: nunca
                  simula entregas.
                </p>
              </div>
            </>
          )}

          {error && (
            <p className="rounded-lg border border-crimson/40 bg-crimson/10 px-3 py-2 text-xs text-red-300">
              {error}
            </p>
          )}
        </div>

        <DialogFooter className="gap-2">
          <Button
            variant="outline"
            onClick={() => onOpenChange(false)}
            className="border-line bg-transparent text-zinc-400 hover:bg-raised hover:text-zinc-200"
          >
            Cancelar
          </Button>
          <Button
            onClick={ejecutar}
            disabled={!puedeEjecutar}
            className="bg-crimson text-white hover:bg-crimson-bright"
          >
            {ejecutando ? (
              <>
                <Loader2 className="h-3.5 w-3.5 animate-spin" /> Ejecutando…
              </>
            ) : (
              <>
                <Play className="h-3.5 w-3.5" /> Ejecutar
              </>
            )}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
