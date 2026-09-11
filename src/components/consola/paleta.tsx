"use client";

/**
 * Paleta de comandos del operador (Ctrl/Cmd + K).
 * Navegación entre vistas + acciones de simulación + seguridad (parada de
 * emergencia) + entregables (exportar informe). Todos los rótulos en español.
 */

import { useEffect } from "react";
import { CommandDialog, CommandEmpty, CommandGroup, CommandInput, CommandItem, CommandList, CommandSeparator } from "@/components/ui/command";
import {
  Coins, Crosshair, Download, FileLock2, FileWarning, History, LayoutDashboard,
  Brain, OctagonX, Pause, Play, RotateCcw, ShieldQuestion, Workflow, Zap,
} from "lucide-react";

export interface AccionPaleta {
  id: string;
  etiqueta: string;
  icono: React.ComponentType<{ className?: string }>;
  atajo?: string;
  grupo: "navegacion" | "operacion" | "entregables" | "seguridad";
  peligrosa?: boolean;
  ejecutar: () => void;
}

const GRUPOS: { id: AccionPaleta["grupo"]; titulo: string }[] = [
  { id: "navegacion", titulo: "Navegación" },
  { id: "operacion", titulo: "Operación" },
  { id: "entregables", titulo: "Entregables" },
  { id: "seguridad", titulo: "Seguridad" },
];

export function PaletaComandos({
  abierta,
  onOpenChange,
  acciones,
}: {
  abierta: boolean;
  onOpenChange: (v: boolean) => void;
  acciones: AccionPaleta[];
}) {
  // Atajo global Ctrl/Cmd + K
  useEffect(() => {
    const bajar = (e: KeyboardEvent) => {
      if ((e.key === "k" || e.key === "K") && (e.metaKey || e.ctrlKey)) {
        e.preventDefault();
        onOpenChange(!abierta);
      }
    };
    document.addEventListener("keydown", bajar);
    return () => document.removeEventListener("keydown", bajar);
  }, [abierta, onOpenChange]);

  return (
    <CommandDialog open={abierta} onOpenChange={onOpenChange}>
      <CommandInput placeholder="Buscar vista o acción del operador…" />
      <CommandList>
        <CommandEmpty>Sin resultados</CommandEmpty>
        {GRUPOS.map((g, i) => {
          const items = acciones.filter((a) => a.grupo === g.id);
          if (items.length === 0) return null;
          return (
            <div key={g.id}>
              {i > 0 && <CommandSeparator />}
              <CommandGroup heading={g.titulo}>
                {items.map((a) => (
                  <CommandItem
                    key={a.id}
                    onSelect={() => {
                      onOpenChange(false);
                      // deja cerrar el diálogo antes de ejecutar
                      setTimeout(a.ejecutar, 30);
                    }}
                    className={a.peligrosa ? "text-red-300 data-[selected=true]:bg-crimson/15" : undefined}
                  >
                    <a.icono className="mr-2 h-4 w-4 shrink-0" />
                    <span>{a.etiqueta}</span>
                    {a.atajo && (
                      <span className="ml-auto font-mono text-[10px] text-zinc-500">{a.atajo}</span>
                    )}
                  </CommandItem>
                ))}
              </CommandGroup>
            </div>
          );
        })}
      </CommandList>
    </CommandDialog>
  );
}

/** Acciones de navegación estándar (se construyen desde la consola). */
export const ICONOS_PALETA = {
  Coins, Crosshair, Download, FileLock2, FileWarning, History, LayoutDashboard,
  Brain, OctagonX, Pause, Play, RotateCcw, ShieldQuestion, Workflow, Zap,
};
