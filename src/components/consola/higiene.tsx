"use client";

/**
 * Higiene de la propia cuenta (v26, manejo del usuario web).
 *
 * Superficie de USUARIO para lo que el backend ya garantiza:
 *  - identidad y rol VIGENTES de la sesión (los de la BD, no los claims
 *    congelados del token);
 *  - caducidad del JWT actual y validez frente al corte de revocación
 *    que el middleware comprueba en cada petición (z3-F4);
 *  - «Cerrar sesión en todos los dispositivos»: fija el corte de
 *    revocación en ahora — muere TODO token emitido antes, INCLUIDO el
 *    actual. La credencial no se toca: no es un restablecimiento.
 *
 * Se abre desde el chip de sesión de la cabecera; cualquier rol
 * autenticado puede consultar SU higiene (no es una vista de admin).
 */

import { useEffect, useState } from "react";
import { Loader2, LogOut, ShieldCheck, TimerReset } from "lucide-react";
import { toast } from "@/hooks/use-toast";
import {
  usarConsola, obtenerHigiene, cerrarSesionesPropias,
} from "@/lib/store";
import { Button } from "@/components/ui/button";
import {
  Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle,
} from "@/components/ui/dialog";
import {
  AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent,
  AlertDialogDescription, AlertDialogFooter, AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Insignia } from "@/components/consola/ui";
import type { HigieneCuenta } from "@/lib/tipos";

function fecha(v: string | null | undefined): string {
  if (!v) return "—";
  try {
    return new Date(v).toLocaleString("es-ES", { dateStyle: "short", timeStyle: "short" });
  } catch {
    return v;
  }
}

function epoch(v: number | null | undefined): string {
  if (!v) return "—";
  try {
    return new Date(v * 1000).toLocaleString("es-ES", { dateStyle: "short", timeStyle: "short" });
  } catch {
    return String(v);
  }
}

function minutosRestantes(segundos: number | null | undefined): string {
  if (segundos == null) return "—";
  if (segundos <= 0) return "expirado";
  if (segundos < 3600) return `${Math.max(1, Math.round(segundos / 60))} min`;
  if (segundos < 86400) return `${Math.round(segundos / 3600)} h`;
  return `${Math.round(segundos / 86400)} días`;
}

// v27 — aviso de caducidad próxima: por debajo de este umbral la sesión
// sigue VÁLIDA (el middleware la acepta) pero puede morir a mitad de un
// engagement si el operador no renueva. El panel avisa ANTES de que pase.
const UMBRAL_AVISO_SEGUNDOS = 30 * 60;

function caducaPronto(higiene: HigieneCuenta): boolean {
  const s = higiene.token.segundos_restantes;
  return Boolean(
    higiene.token.sesion_valida &&
    s != null && s > 0 && s <= UMBRAL_AVISO_SEGUNDOS,
  );
}

function Fila({ etiqueta, children }: { etiqueta: string; children: React.ReactNode }) {
  return (
    <div className="flex items-start justify-between gap-4 border-b border-line/60 py-2 last:border-0">
      <span className="shrink-0 text-xs text-zinc-500">{etiqueta}</span>
      <span className="text-right font-mono text-xs text-zinc-200">{children}</span>
    </div>
  );
}

export function DialogoHigiene({ abierto, onCerrar }: { abierto: boolean; onCerrar: () => void }) {
  const [higiene, setHigiene] = useState<HigieneCuenta | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [cargando, setCargando] = useState(false);
  const [confirmar, setConfirmar] = useState(false);
  const [revocando, setRevocando] = useState(false);

  // Carga fresca en cada apertura: el estado puede cambiar entre aperturas
  // (corte de revocación, rol vigente tras una acción administrativa).
  useEffect(() => {
    if (!abierto) return;
    setCargando(true);
    setError(null);
    obtenerHigiene()
      .then(setHigiene)
      .catch((e: Error) => setError(e.message))
      .finally(() => setCargando(false));
  }, [abierto]);

  async function cerrarTodas() {
    setRevocando(true);
    try {
      await cerrarSesionesPropias();
      toast({
        title: "Sesiones revocadas",
        description: "Todas las sesiones de tu cuenta quedaron cerradas. Vuelve a iniciar sesión.",
      });
      // cerrarSesionesPropias() ya limpió la sesión local: la consola
      // muestra el acceso y este diálogo deja de existir en pantalla.
    } catch (e) {
      // La sesión pudo morir entre la apertura y la acción (401): el
      // store ya redirige al acceso; aquí solo informamos si hubo otra cosa.
      toast({
        title: "No se pudo completar el cierre",
        description: (e as Error).message,
        variant: "destructive",
      });
    } finally {
      setRevocando(false);
      setConfirmar(false);
      onCerrar();
    }
  }

  return (
    <>
      <Dialog open={abierto} onOpenChange={(v) => (!v ? onCerrar() : undefined)}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <ShieldCheck className="h-4 w-4 text-teal-300" />
              Higiene de la cuenta
            </DialogTitle>
            <DialogDescription>
              tu sesión actual y su validez · visible solo para ti
            </DialogDescription>
          </DialogHeader>

          {cargando && (
            <div className="flex items-center gap-2 py-6 text-sm text-zinc-400">
              <Loader2 className="h-4 w-4 animate-spin" /> consultando estado…
            </div>
          )}

          {!cargando && error && (
            <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-2 text-xs text-red-300">
              {error}
            </div>
          )}

          {!cargando && !error && higiene && (
            <div className="space-y-4">
              <div className="rounded-lg border border-line bg-panel/60 px-3 py-1.5">
                <Fila etiqueta="Usuario">{higiene.usuario}</Fila>
                <Fila etiqueta="Rol vigente">
                  <span className="inline-flex items-center gap-2">
                    {higiene.rol}
                    <Insignia tono="slate">{higiene.tenant_id}</Insignia>
                  </span>
                </Fila>
                <Fila etiqueta="Alta de la cuenta">{fecha(higiene.creado_en)}</Fila>
                <Fila etiqueta="Último acceso">{fecha(higiene.ultimo_acceso)}</Fila>
              </div>

              <div className="rounded-lg border border-line bg-panel/60 px-3 py-1.5">
                <Fila etiqueta="Sesión actual">
                  {higiene.token.sesion_valida
                    ? <Insignia tono="esmeralda">válida</Insignia>
                    : <Insignia tono="rojo">revocada</Insignia>}
                </Fila>
                <Fila etiqueta="Emitida">{epoch(higiene.token.emision)}</Fila>
                <Fila etiqueta="Caduca">
                  {epoch(higiene.token.expira_en)}
                  {higiene.token.segundos_restantes != null && (
                    <span className="ml-1 text-zinc-500">
                      (en {minutosRestantes(higiene.token.segundos_restantes)})
                    </span>
                  )}
                  {caducaPronto(higiene) && (
                    <Insignia tono="ambar">caduca pronto</Insignia>
                  )}
                </Fila>
                <Fila etiqueta="Corte de revocación">
                  {higiene.invalidar_antes
                    ? epoch(higiene.invalidar_antes)
                    : "sin cortes"}
                </Fila>
              </div>

              {caducaPronto(higiene) && (
                <div className="flex items-start gap-2 rounded-lg border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-xs leading-relaxed text-amber-200">
                  <TimerReset className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                  <span>
                    Tu sesión caduca en menos de 30 minutos. Renueva el acceso
                    cuando termines el paso en curso: si caduca a mitad de un
                    engagement perderás el hilo de la consola hasta volver a
                    entrar (el caso no pierde nada; tú sí el contexto).
                  </span>
                </div>
              )}

              <p className="text-[11px] leading-relaxed text-zinc-500">
                «Cerrar en todos los dispositivos» revoca <span className="text-zinc-300">todos</span> los
                tokens emitidos antes de ahora, también el de esta pestaña.
                Tu contraseña no cambia: podrás volver a entrar con ella.
              </p>
            </div>
          )}

          <div className="flex justify-end gap-2">
            <Button variant="outline" size="sm" onClick={onCerrar}>Cerrar</Button>
            <Button
              variant="destructive"
              size="sm"
              disabled={!higiene || revocando}
              onClick={() => setConfirmar(true)}
            >
              {revocando ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <LogOut className="h-3.5 w-3.5" />}
              Cerrar en todos los dispositivos
            </Button>
          </div>
        </DialogContent>
      </Dialog>

      <AlertDialog open={confirmar} onOpenChange={setConfirmar}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>¿Cerrar TODAS tus sesiones?</AlertDialogTitle>
            <AlertDialogDescription>
              Revoca cada token de tu cuenta, incluido el de esta pestaña:
              la consola vuelve al acceso y tendrás que iniciar sesión otra vez
              en todos tus dispositivos. La acción queda registrada en la
              auditoría del sistema y tu contraseña no cambia.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancelar</AlertDialogCancel>
            <AlertDialogAction
              className="bg-red-600 text-white hover:bg-red-500"
              onClick={(e) => { e.preventDefault(); void cerrarTodas(); }}
            >
              Sí, cerrar todas
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  );
}
