"use client";

/**
 * Vista Casos: gestión de engagements reales.
 *
 * Crear un caso define el ROE máquina-legible (alcance, exclusiones,
 * técnicas prohibidas, techo de ruido y ventana horaria): desde ese
 * momento el boundary lo aplica antes de cada tool call. No es decorativo.
 */

import { useState } from "react";
import { motion } from "framer-motion";
import { FolderKanban, Loader2, Plus, Target, Clock, Gauge } from "lucide-react";
import { toast } from "@/hooks/use-toast";
import { Entrada, Tarjeta, TituloSeccion, Insignia } from "@/components/consola/ui";
import { usarConsola, DatosNuevoCaso, CasoResumen } from "@/lib/store";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import {
  Dialog, DialogContent, DialogDescription, DialogFooter,
  DialogHeader, DialogTitle,
} from "@/components/ui/dialog";
import { ETIQUETA_FASE, FaseId, formatoCoste, formatoTokens } from "@/lib/tipos";
import { cn } from "@/lib/utils";

function _lista(texto: string): string[] {
  return texto
    .split(/[\n,;]+/)
    .map((t) => t.trim().toLowerCase())
    .filter(Boolean);
}

export function VistaCasos() {
  const casos = usarConsola((s) => s.casos);
  const casoActivo = usarConsola((s) => s.casoActivo);
  const seleccionarCaso = usarConsola((s) => s.seleccionarCaso);
  const [dialogo, setDialogo] = useState(false);
  const [creando, setCreando] = useState(false);

  const abrir = (id: string) => {
    seleccionarCaso(id);
    toast({ title: "Caso activo", description: "Las vistas muestran ahora este engagement" });
  };

  return (
    <div className="space-y-5">
      <Tarjeta>
        <div className="flex flex-wrap items-center justify-between gap-3">
          <TituloSeccion
            titulo="Engagements del equipo"
            descripcion="Cada caso es una base SQLite aislada con su ROE, su memoria y su cadena de custodia"
          />
          <Button
            onClick={() => setDialogo(true)}
            className="bg-crimson text-white hover:bg-crimson-bright"
          >
            <Plus className="h-4 w-4" /> Nuevo engagement
          </Button>
        </div>
      </Tarjeta>

      {casos.length === 0 ? (
        <Tarjeta>
          <div className="flex flex-col items-center gap-3 py-10 text-center">
            <FolderKanban className="h-8 w-8 text-zinc-600" />
            <p className="text-sm font-medium text-zinc-300">Aún no hay casos</p>
            <p className="max-w-md text-xs leading-relaxed text-zinc-500">
              Crea el primer engagement: definirás el alcance autorizado (dominios y CIDRs),
              las técnicas prohibidas y el techo de ruido. El orquestador no tocará nada
              fuera de ese contrato.
            </p>
            <Button onClick={() => setDialogo(true)} variant="outline" className="border-line bg-transparent text-zinc-300 hover:bg-raised">
              <Plus className="h-4 w-4" /> Crear engagement
            </Button>
          </div>
        </Tarjeta>
      ) : (
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
          {casos.map((caso, i) => (
            <TarjetaCaso
              key={caso.id}
              caso={caso}
              activo={caso.id === casoActivo}
              indice={i}
              onAbrir={() => abrir(caso.id)}
            />
          ))}
        </div>
      )}

      <DialogoNuevoCaso
        abierta={dialogo}
        onOpenChange={setDialogo}
        creando={creando}
        setCreando={setCreando}
      />
    </div>
  );
}

function TarjetaCaso({
  caso, activo, indice, onAbrir,
}: {
  caso: CasoResumen;
  activo: boolean;
  indice: number;
  onAbrir: () => void;
}) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3, delay: Math.min(indice * 0.05, 0.3) }}
    >
      <Tarjeta
        className={cn(
          "h-full transition-colors",
          activo && "border-crimson/50 shadow-[0_0_24px_-8px] shadow-crimson/40",
        )}
      >
        <div className="flex h-full flex-col gap-3">
          <div className="flex items-start justify-between gap-2">
            <div className="min-w-0">
              <p className="truncate text-sm font-semibold text-zinc-100">{caso.nombre}</p>
              <p className="mt-0.5 text-xs text-zinc-500">{caso.cliente}</p>
            </div>
            {activo && <Insignia tono="crimson">activo</Insignia>}
          </div>
          <div className="flex flex-wrap gap-1.5">
            <Insignia tono="teal">{ETIQUETA_FASE[caso.fase_actual as FaseId] ?? caso.fase_actual}</Insignia>
            <Insignia tono="slate">{caso.estado_fase.replace("_", " ")}</Insignia>
          </div>
          <div className="mt-auto flex items-center justify-between gap-2 border-t border-line pt-3 font-mono text-[10px] text-zinc-500">
            <span>tok {formatoTokens(caso.tokens_acumulados)}</span>
            <span>{formatoCoste(caso.coste_acumulado_usd)}</span>
            <button
              onClick={onAbrir}
              className={cn(
                "rounded-lg px-3 py-1.5 text-[11px] font-semibold transition-colors",
                activo
                  ? "bg-raised text-zinc-200 hover:bg-raised"
                  : "bg-crimson text-white hover:bg-crimson-bright",
              )}
            >
              {activo ? "seleccionado" : "operar"}
            </button>
          </div>
        </div>
      </Tarjeta>
    </motion.div>
  );
}

function DialogoNuevoCaso({
  abierta, onOpenChange, creando, setCreando,
}: {
  abierta: boolean;
  onOpenChange: (v: boolean) => void;
  creando: boolean;
  setCreando: (v: boolean) => void;
}) {
  const [nombre, setNombre] = useState("");
  const [cliente, setCliente] = useState("");
  const [dominios, setDominios] = useState("localhost");
  const [cidrs, setCidrs] = useState("127.0.0.0/8");
  const [excluidos, setExcluidos] = useState("");
  const [prohibidas, setProhibidas] = useState("T1485, T1489");
  const [techo, setTecho] = useState(80);
  const [inicio, setInicio] = useState("00:00");
  const [fin, setFin] = useState("23:59");
  const [error, setError] = useState<string | null>(null);

  // Misma regla que los validadores del backend (models.ROEPolitica):
  // feedback inmediato en el formulario sin esperar el 422.
  const PATRON_DOMINIO = /^(localhost|(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,})$/;
  const esDominio = (v: string) => PATRON_DOMINIO.test(v.trim().toLowerCase());
  const esCidr = (v: string) => {
    const valor = v.trim();
    const m4 = valor.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(\/(\d{1,2}))?$/);
    if (m4) {
      const octetos = [m4[1], m4[2], m4[3], m4[4]].map(Number);
      if (octetos.some((o) => o > 255)) return false;
      const prefijo = m4[6] === undefined ? undefined : Number(m4[6]);
      return prefijo === undefined || prefijo <= 32;
    }
    // IPv6 (suelta o con prefijo): forma hexadecimal con separadores ":"
    const sinPrefijo = valor.split("/");
    if (sinPrefijo.length > 2) return false;
    const [ip6, prefijo6] = sinPrefijo;
    if (prefijo6 !== undefined && (Number(prefijo6) > 128 || !/^\d+$/.test(prefijo6))) return false;
    return /^[0-9a-f:]+$/i.test(ip6) && ip6.includes(":") && ip6.length >= 2;
  };

  const crear = async () => {
    setError(null);
    const dominiosLista = _lista(dominios);
    const cidrsLista = _lista(cidrs);
    const excluidosLista = _lista(excluidos);
    const dominioMalo = dominiosLista.find((d) => !esDominio(d));
    if (dominioMalo !== undefined) {
      setError(`Dominio inválido en el alcance: "${dominioMalo}" (p. ej. cliente.com, o localhost para el lab)`);
      return;
    }
    const cidrMalo = cidrsLista.find((c) => !esCidr(c));
    if (cidrMalo !== undefined) {
      setError(`CIDR inválido en el alcance: "${cidrMalo}" (p. ej. 192.168.1.0/24)`);
      return;
    }
    const excluidoMalo = excluidosLista.find((x) => !esDominio(x) && !esCidr(x));
    if (excluidoMalo !== undefined) {
      setError(`Entrada de exclusión inválida: "${excluidoMalo}" (dominio o CIDR)`);
      return;
    }
    setCreando(true);
    try {
      const datos: DatosNuevoCaso = {
        nombre: nombre.trim(),
        cliente: cliente.trim(),
        alcance_dominios: dominiosLista,
        alcance_cidrs: cidrsLista,
        alcance_excluido: excluidosLista,
        tecnicas_prohibidas: _lista(prohibidas),
        techo_ruido: techo,
        ventana_inicio: inicio,
        ventana_fin: fin,
      };
      const id = await usarConsola.getState().crearCaso(datos);
      onOpenChange(false);
      toast({
        title: `Engagement creado: ${datos.nombre}`,
        description: `ROE firmado y activo (${id}). El boundary ya aplica su alcance.`,
      });
      setNombre(""); setCliente("");
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setCreando(false);
    }
  };

  const valido = nombre.trim().length >= 3 && cliente.trim().length >= 2;

  return (
    <Dialog open={abierta} onOpenChange={onOpenChange}>
      <DialogContent className="border-line bg-panel text-zinc-200 sm:max-w-xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2 text-base">
            <Target className="h-4 w-4 text-crimson-bright" /> Nuevo engagement
          </DialogTitle>
          <DialogDescription className="text-xs leading-relaxed text-zinc-400">
            Este formulario firma el ROE máquina-legible del caso. El boundary de
            guardrails lo aplicará antes de cada tool call: scope, exclusiones,
            técnicas vetadas, techo de ruido y ventana horaria.
          </DialogDescription>
        </DialogHeader>

        <div className="grid max-h-[60vh] gap-4 overflow-y-auto pr-1 sm:grid-cols-2">
          <div className="space-y-1.5">
            <Label htmlFor="caso-nombre" className="text-xs text-zinc-300">Nombre del caso</Label>
            <Input id="caso-nombre" value={nombre} onChange={(e) => setNombre(e.target.value)}
              placeholder="Test de intrusión externa Q3" className="border-line bg-ink/60 text-sm" />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="caso-cliente" className="text-xs text-zinc-300">Cliente</Label>
            <Input id="caso-cliente" value={cliente} onChange={(e) => setCliente(e.target.value)}
              placeholder="ACME S.L." className="border-line bg-ink/60 text-sm" />
          </div>
          <div className="space-y-1.5 sm:col-span-2">
            <Label htmlFor="caso-dominios" className="text-xs text-zinc-300">Dominios en alcance</Label>
            <Textarea id="caso-dominios" value={dominios} onChange={(e) => setDominios(e.target.value)}
              placeholder="localhost&#10;ejemplo.com" className="min-h-16 border-line bg-ink/60 font-mono text-xs" />
            <p className="text-[11px] text-zinc-500">Separa por coma, punto y coma o salto de línea.</p>
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="caso-cidrs" className="text-xs text-zinc-300">CIDRs en alcance</Label>
            <Input id="caso-cidrs" value={cidrs} onChange={(e) => setCidrs(e.target.value)}
              placeholder="127.0.0.0/8" className="border-line bg-ink/60 font-mono text-xs" />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="caso-excluidos" className="text-xs text-zinc-300">Exclusiones (vetadas)</Label>
            <Input id="caso-excluidos" value={excluidos} onChange={(e) => setExcluidos(e.target.value)}
              placeholder="10.30.0.1, corp.exemplo.com" className="border-line bg-ink/60 font-mono text-xs" />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="caso-prohibidas" className="text-xs text-zinc-300">Técnicas MITRE prohibidas</Label>
            <Input id="caso-prohibidas" value={prohibidas} onChange={(e) => setProhibidas(e.target.value)}
              placeholder="T1485, T1489" className="border-line bg-ink/60 font-mono text-xs" />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="caso-techo" className="flex items-center gap-1.5 text-xs text-zinc-300">
              <Gauge className="h-3 w-3" /> Techo de ruido (0–100)
            </Label>
            <Input id="caso-techo" type="number" min={0} max={100} value={techo}
              onChange={(e) => setTecho(Math.min(100, Math.max(0, Number(e.target.value) || 0)))}
              className="border-line bg-ink/60 font-mono text-xs" />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="caso-inicio" className="flex items-center gap-1.5 text-xs text-zinc-300">
              <Clock className="h-3 w-3" /> Ventana activa · inicio
            </Label>
            <Input id="caso-inicio" type="time" lang="es" step={60} value={inicio} onChange={(e) => setInicio(e.target.value)}
              className="border-line bg-ink/60 font-mono text-xs" />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="caso-fin" className="text-xs text-zinc-300">Ventana activa · fin</Label>
            <Input id="caso-fin" type="time" lang="es" step={60} value={fin} onChange={(e) => setFin(e.target.value)}
              className="border-line bg-ink/60 font-mono text-xs" />
          </div>
          {error && (
            <p className="rounded-lg border border-crimson/40 bg-crimson/10 px-3 py-2 text-xs text-red-300 sm:col-span-2">
              {error}
            </p>
          )}
        </div>

        <DialogFooter className="gap-2">
          <Button variant="outline" onClick={() => onOpenChange(false)}
            className="border-line bg-transparent text-zinc-400 hover:bg-raised hover:text-zinc-200">
            Cancelar
          </Button>
          <Button onClick={crear} disabled={!valido || creando} className="bg-crimson text-white hover:bg-crimson-bright">
            {creando ? (<><Loader2 className="h-3.5 w-3.5 animate-spin" /> Creando…</>) : "Firmar ROE y crear"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
