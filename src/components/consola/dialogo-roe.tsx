"use client";

/**
 * Diálogo de edición del ROE vivo (v28).
 *
 * El ROE nace firmado en F0, pero un engagement REAL cambia: el cliente
 * amplía la ventana horaria, el blue team pide bajar el techo de ruido,
 * aparece un activo que hay que excluir. Este diálogo expone la mutación
 * que el backend ya soportaba (POST /api/engagements/{id}/roe) con la
 * validación del mismo lado (boundary): techo 0-100, ventana HH:MM,
 * exclusiones línea a línea. Cada cambio queda auditado con identidad.
 *
 * NO permite tocar alcance principal ni técnicas prohibidas: eso exige un
 * ROE re-firmado (nuevo caso o flujo contractual), no una edición rápida.
 */

import { useEffect, useState } from "react";
import { Loader2, ShieldOff } from "lucide-react";
import { toast } from "@/hooks/use-toast";
import { usarConsola } from "@/lib/store";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { cn } from "@/lib/utils";
import {
  Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle,
} from "@/components/ui/dialog";

const DIAS = [
  { v: "lun", e: "L" }, { v: "mar", e: "M" }, { v: "mie", e: "X" },
  { v: "jue", e: "J" }, { v: "vie", e: "V" }, { v: "sab", e: "S" }, { v: "dom", e: "D" },
];

export function DialogoRoe({ abierto, cerrar }: { abierto: boolean; cerrar: () => void }) {
  const engagement = usarConsola((s) => s.engagement);
  const actualizarRoe = usarConsola((s) => s.actualizarRoe);
  const roe = engagement?.roe ?? null;

  const [techo, setTecho] = useState("35");
  const [inicio, setInicio] = useState("09:00");
  const [fin, setFin] = useState("18:00");
  const [dias, setDias] = useState<string[]>(["lun", "mar", "mie", "jue", "vie"]);
  const [excluido, setExcluido] = useState("");
  const [guardando, setGuardando] = useState(false);

  // Rehidratación CADA vez que se abre: el ROE vivo puede haber cambiado
  // por SSE desde la última edición.
  useEffect(() => {
    if (!abierto || !roe) return;
    setTecho(String(roe.techo_ruido));
    setInicio(roe.ventanas_activas.inicio);
    setFin(roe.ventanas_activas.fin);
    setDias(roe.ventanas_activas.dias);
    setExcluido(roe.alcance_excluido.join("\n"));
  }, [abierto, roe]);

  if (!roe) return null;

  const alternarDia = (d: string) =>
    setDias((actual) => (actual.includes(d) ? actual.filter((x) => x !== d) : [...actual, d]));

  const guardar = async () => {
    const t = Number(techo);
    if (!Number.isInteger(t) || t < 0 || t > 100) {
      toast({
        title: "Techo de ruido inválido",
        description: "Entero entre 0 y 100 (el boundary aplica el margen x5 como corte duro)",
        variant: "destructive",
      });
      return;
    }
    if (!/^\d{2}:\d{2}$/.test(inicio) || !/^\d{2}:\d{2}$/.test(fin)) {
      toast({ title: "Ventana horaria inválida", description: "Formato HH:MM", variant: "destructive" });
      return;
    }
    if (dias.length === 0) {
      toast({
        title: "Sin días de actividad",
        description: "Selecciona al menos un día: una ventana vacía detendría el ciclo",
        variant: "destructive",
      });
      return;
    }
    const listaExcluido = excluido.split("\n").map((l) => l.trim()).filter(Boolean);
    setGuardando(true);
    try {
      const { cambios } = await actualizarRoe({
        techo_ruido: t !== roe.techo_ruido ? t : undefined,
        ventana_inicio: inicio !== roe.ventanas_activas.inicio ? inicio : undefined,
        ventana_fin: fin !== roe.ventanas_activas.fin ? fin : undefined,
        ventana_dias: JSON.stringify(dias) !== JSON.stringify(roe.ventanas_activas.dias) ? dias : undefined,
        alcance_excluido:
          JSON.stringify(listaExcluido) !== JSON.stringify(roe.alcance_excluido) ? listaExcluido : undefined,
      });
      toast({
        title: cambios.length > 0 ? "ROE actualizado" : "Sin cambios",
        description: cambios.length > 0
          ? `${cambios.length} cambio(s) auditado(s): ${cambios.join("; ")}`
          : "El boundary aplica la política vigente",
      });
      cerrar();
    } catch (e) {
      toast({
        title: "El boundary rechazó el cambio",
        description: (e as Error).message,
        variant: "destructive",
      });
    } finally {
      setGuardando(false);
    }
  };

  return (
    <Dialog open={abierto} onOpenChange={(v) => !v && cerrar()}>
      <DialogContent className="border-line bg-raised text-zinc-100 sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>Editar ROE vivo</DialogTitle>
          <DialogDescription className="text-zinc-500">
            Cambios permitidos en caliente: techo de ruido, ventana horaria y
            exclusiones de alcance. Cada mutación se valida contra la política
            y queda auditada con tu identidad. El alcance principal y las
            técnicas prohibidas exigen un ROE re-firmado.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          <div className="grid grid-cols-3 items-end gap-3">
            <div className="space-y-1.5">
              <label className="text-xs text-zinc-500">Techo de ruido (0-100)</label>
              <Input type="number" min={0} max={100} value={techo}
                     onChange={(e) => setTecho(e.target.value)}
                     className="h-9 border-line bg-panel text-zinc-100" />
            </div>
            <div className="space-y-1.5">
              <label className="text-xs text-zinc-500">Ventana inicio</label>
              <Input type="time" value={inicio} onChange={(e) => setInicio(e.target.value)}
                     className="h-9 border-line bg-panel text-zinc-100" />
            </div>
            <div className="space-y-1.5">
              <label className="text-xs text-zinc-500">Ventana fin</label>
              <Input type="time" value={fin} onChange={(e) => setFin(e.target.value)}
                     className="h-9 border-line bg-panel text-zinc-100" />
            </div>
          </div>

          <div className="space-y-1.5">
            <label className="text-xs text-zinc-500">Días con actividad</label>
            <div className="flex gap-1.5">
              {DIAS.map((d) => (
                <button key={d.v} type="button" onClick={() => alternarDia(d.v)}
                        className={cn(
                          "h-8 w-9 rounded-md border text-xs font-medium transition-colors",
                          dias.includes(d.v)
                            ? "border-teal-500/40 bg-teal-500/15 text-teal-200"
                            : "border-line bg-panel text-zinc-500 hover:text-zinc-300",
                        )}>
                  {d.e}
                </button>
              ))}
            </div>
          </div>

          <div className="space-y-1.5">
            <label className="flex items-center gap-1.5 text-xs text-zinc-500">
              <ShieldOff className="h-3.5 w-3.5" />
              Alcance excluido (un dominio o CIDR por línea)
            </label>
            <Textarea value={excluido} onChange={(e) => setExcluido(e.target.value)}
                      rows={3} spellCheck={false}
                      placeholder={"p. ej.\n*.cliente-critical.local\n10.30.0.200/32"}
                      className="border-line bg-panel font-mono text-xs text-zinc-100" />
          </div>
        </div>

        <DialogFooter>
          <Button variant="outline"
                  className="border-line bg-transparent text-zinc-300 hover:bg-panel hover:text-zinc-100"
                  onClick={cerrar}>
            Cancelar
          </Button>
          <Button className="bg-crimson text-white hover:bg-crimson/85"
                  onClick={guardar} disabled={guardando}>
            {guardando && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
            Firmar cambios
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
