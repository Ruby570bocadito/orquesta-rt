"use client";

/**
 * Vista Arsenal (v20): evasión de detección VERIFICADA, persistencia REAL
 * del lab y Active Directory ofensivo — todo bajo el mismo boundary de
 * guardrails que las herramientas del agente.
 *
 * - Evasión: el artefacto se escanea contra un motor de firmas REAL (YARA)
 *   antes y después; la evasión solo se declara si detecciones=0 Y el
 *   round-trip reconstruye el payload byte a byte. Los artefactos quedan
 *   custodiados como evidencia con SHA-256.
 * - Persistencia: cada método se implanta de verdad en el host del lab, se
 *   VERIFICA ACTIVÁNDOLO (shell interactivo real, arranque de intérprete
 *   real, análisis real de unidad systemd) y se retira con verificación de
 *   ausencia. Alta riesgo → firma humana en la cola de Aprobaciones.
 * - AD: kerberoasting/asrep/dcsync/pass-the-hash reales con impacket y
 *   lecturas LDAP (LAPS, gMSA, trusts, rutas a DA). Sin DC configurado el
 *   requisito exacto se muestra — jamás datos inventados.
 */

import { useEffect, useMemo, useState } from "react";
import {
  BadgeCheck, Bug, ChevronDown, Download, FileCode2, KeyRound, Loader2,
  Radar, RefreshCw, ScanSearch, ShieldCheck, Trash2, Wrench,
} from "lucide-react";
import { toast } from "@/hooks/use-toast";
import { Button } from "@/components/ui/button";
import { Insignia, Tarjeta, TituloSeccion } from "@/components/consola/ui";
import { usarConsola } from "@/lib/store";
import type {
  DeteccionYara, EstadoArsenal, MetodoPersistencia, ResultadoEvasion,
} from "@/lib/store";
import { cn } from "@/lib/utils";

// ---------------------------------------------------------------------------

function ChipsDetecciones({ dets }: { dets: DeteccionYara[] }) {
  if (!dets.length) {
    return (
      <span className="inline-flex items-center gap-1 rounded-md border border-emerald-400/30 bg-emerald-400/10 px-2 py-0.5 text-[11px] font-medium text-emerald-300">
        <ShieldCheck className="h-3 w-3" /> 0 detecciones
      </span>
    );
  }
  return (
    <div className="flex flex-wrap gap-1.5">
      {dets.map((d) => (
        <span key={d.regla} className="inline-flex items-center gap-1 rounded-md border border-red-400/30 bg-red-400/10 px-2 py-0.5 text-[11px] font-medium text-red-300">
          <Bug className="h-3 w-3" /> {d.regla}
        </span>
      ))}
    </div>
  );
}

function ResultadoEvasionPanel({ r }: { r: ResultadoEvasion }) {
  const [abierto, setAbierto] = useState(false);
  const descargar = () => {
    const contenido = r.formato === "binario"
      ? atob(r.artefacto_b64)
      : atob(r.artefacto_b64);
    const bytes = new Uint8Array(contenido.length);
    for (let i = 0; i < contenido.length; i++) bytes[i] = contenido.charCodeAt(i);
    const blob = new Blob([bytes], { type: "application/octet-stream" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `evasion_${r.metodo}_${r.formato}_${r.hash_artefacto.slice(0, 10)}.${r.formato === "python" ? "py" : r.formato === "powershell" ? "ps1" : "bin"}`;
    a.click();
    URL.revokeObjectURL(url);
  };
  return (
    <Tarjeta className="border-crimson/40">
      <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
        <p className="text-sm font-semibold text-zinc-100">
          Artefacto {r.metodo} · {r.formato} · {r.tamano_artefacto} B
        </p>
        {r.evasion_verificada ? (
          <Insignia tono="esmeralda"><BadgeCheck className="mr-1 inline h-3 w-3" />evasión VERIFICADA</Insignia>
        ) : (
          <Insignia tono="ambar">sin verificación completa</Insignia>
        )}
      </div>
      <div className="grid gap-3 text-[12px] text-zinc-300 sm:grid-cols-2">
        <div>
          <p className="mb-1 text-zinc-500">Detecciones ANTES ({r.detecciones_antes.length})</p>
          <ChipsDetecciones dets={r.detecciones_antes} />
        </div>
        <div>
          <p className="mb-1 text-zinc-500">Detecciones DESPUÉS ({r.detecciones_despues.length})</p>
          <ChipsDetecciones dets={r.detecciones_despues} />
        </div>
        <div className="font-mono text-[11px] text-zinc-400">
          <p>entropía {r.entropia_antes} → {r.entropia_despues} bits/byte</p>
          <p className="truncate">payload {r.hash_payload.slice(0, 16)}…</p>
          <p className="truncate">artefacto {r.hash_artefacto.slice(0, 16)}…</p>
        </div>
        <div>
          <p className={cn("text-[12px]", r.roundtrip_ok ? "text-emerald-300" : "text-red-300")}>
            {r.roundtrip_ok ? "✓" : "✗"} Round-trip: {r.roundtrip.tipo}
          </p>
          {r.roundtrip.salida ? (
            <p className="mt-0.5 font-mono text-[10px] text-zinc-500">{r.roundtrip.salida}</p>
          ) : null}
          {r.roundtrip.error ? (
            <p className="mt-0.5 font-mono text-[10px] text-red-400">{r.roundtrip.error}</p>
          ) : null}
        </div>
      </div>
      <div className="mt-3 flex items-center gap-2">
        <Button size="sm" variant="outline" className="h-7 gap-1 text-[12px]" onClick={descargar}>
          <Download className="h-3 w-3" /> Descargar artefacto
        </Button>
        <button
          type="button"
          onClick={() => setAbierto(!abierto)}
          className="inline-flex items-center gap-1 text-[12px] text-zinc-400 hover:text-zinc-200"
          aria-expanded={abierto}
        >
          <ChevronDown className={cn("h-3 w-3 transition-transform", abierto && "rotate-180")} />
          {abierto ? "Ocultar" : "Ver"} código del loader
        </button>
      </div>
      {abierto ? (
        <pre className="mt-2 max-h-64 overflow-auto rounded-lg border border-line bg-ink p-3 font-mono text-[10px] leading-relaxed text-zinc-400">
          {atob(r.artefacto_b64)}
        </pre>
      ) : null}
    </Tarjeta>
  );
}

// ---------------------------------------------------------------------------

const ESTADO_PERSISTENCIA: Record<string, { tono: "esmeralda" | "ambar" | "slate"; texto: string }> = {
  implantado: { tono: "ambar", texto: "implantado" },
  verificado: { tono: "ambar", texto: "verificado" },
  limpio: { tono: "esmeralda", texto: "limpio" },
  artefacto: { tono: "slate", texto: "artefacto" },
};

function TarjetaPersistencia({ m }: { m: MetodoPersistencia }) {
  const accionPersistencia = usarConsola((s) => s.accionPersistencia);
  const ocupado = usarConsola((s) => s.arsenalOcupado);
  const comando = "echo beacon $(date +%s) >> /dev/null"; // demostración segura del lab
  const tono = ESTADO_PERSISTENCIA[m.estado] ?? ESTADO_PERSISTENCIA.limpio;
  const [detalle, setDetalle] = useState<Record<string, unknown> | null>(null);

  const ejecutar = async (accion: "implantar" | "verificar" | "retirar") => {
    const r = await accionPersistencia(accion, { metodo: m.metodo, comando });
    if (r.estado === "espera_aprobacion") {
      toast({ title: "Firma requerida", description: r.mensaje });
      return;
    }
    if (r.estado === "fallo") {
      toast({ title: `Persistencia · ${m.titulo}`, description: r.mensaje, variant: "destructive" });
      return;
    }
    setDetalle((r.resultado as Record<string, unknown>) ?? null);
    toast({
      title: `Persistencia · ${m.titulo}`,
      description: r.mensaje,
    });
  };

  return (
    <Tarjeta className="flex flex-col">
      <div className="mb-2 flex items-start justify-between gap-2">
        <div>
          <p className="text-sm font-semibold text-zinc-100">{m.titulo}</p>
          <p className="font-mono text-[10px] text-zinc-500">ATT&CK {m.tecnica} · {m.sistema}</p>
        </div>
        <Insignia tono={tono.tono}>{tono.texto}</Insignia>
      </div>
      <p className="mb-3 flex-1 text-[12px] leading-relaxed text-zinc-400">{m.detalle}</p>
      {m.tipo === "artefacto" ? (
        <p className="text-[11px] text-zinc-500">Generación de artefacto con hash: la implantación exige runtime (C2/objetivo del ROE).</p>
      ) : (
        <div className="flex flex-wrap gap-1.5">
          <Button size="sm" variant="outline" disabled={ocupado} className="h-7 gap-1 text-[11px]" onClick={() => ejecutar("implantar")}>
            {ocupado ? <Loader2 className="h-3 w-3 animate-spin" /> : <KeyRound className="h-3 w-3" />} Implantar
          </Button>
          <Button size="sm" variant="outline" disabled={ocupado} className="h-7 gap-1 text-[11px]" onClick={() => ejecutar("verificar")}>
            <ScanSearch className="h-3 w-3" /> Verificar
          </Button>
          <Button size="sm" variant="outline" disabled={ocupado} className="h-7 gap-1 text-[11px] text-red-300" onClick={() => ejecutar("retirar")}>
            <Trash2 className="h-3 w-3" /> Retirar
          </Button>
        </div>
      )}
      {detalle ? (
        <pre className="mt-2 max-h-40 overflow-auto rounded-lg border border-line bg-ink p-2 font-mono text-[10px] text-zinc-400">
          {JSON.stringify(detalle, null, 2)}
        </pre>
      ) : null}
    </Tarjeta>
  );
}

// ---------------------------------------------------------------------------

const ACCIONES_AD = [
  { id: "kerberoasting", etiqueta: "Kerberoasting", tecnica: "T1558.003", riesgo: "alta", descripcion: "TGS reales por SPN → hashes John" },
  { id: "asrep", etiqueta: "AS-REP roast", tecnica: "T1558.004", riesgo: "alta", descripcion: "AS-REQ sin preauth → hashes John" },
  { id: "dcsync", etiqueta: "DCSync", tecnica: "T1003.006", riesgo: "crítica", descripcion: "replicación DRSUAPI del DC" },
  { id: "pass_the_hash", etiqueta: "Pass the Hash", tecnica: "T1550.002", riesgo: "alta", descripcion: "SMB con hash NT sin contraseña" },
  { id: "laps", etiqueta: "LAPS", tecnica: "T1552.006", riesgo: "media", descripcion: "contraseñas locales de máquina" },
  { id: "gmsa", etiqueta: "gMSA", tecnica: "T1552.006", riesgo: "media", descripcion: "cuentas de servicio gestionadas" },
  { id: "trusts", etiqueta: "Trusts", tecnica: "T1482", riesgo: "baja", descripcion: "confianzas del dominio" },
  { id: "rutas_da", etiqueta: "Rutas a DA", tecnica: "T1098", riesgo: "baja", descripcion: "rutas reales desde memberOf" },
] as const;

const TONO_RIESGO_AD: Record<string, "rojo" | "ambar" | "esmeralda"> = {
  alta: "rojo", media: "ambar", "crítica": "rojo", baja: "esmeralda",
};

function SeccionAD() {
  const accionAD = usarConsola((s) => s.accionAD);
  const ocupado = usarConsola((s) => s.arsenalOcupado);
  const [host, setHost] = useState("");
  const [resultado, setResultado] = useState<{ accion: string; datos: Record<string, unknown> } | null>(null);

  const ejecutar = async (accion: string) => {
    const r = await accionAD({ accion, host: host || undefined });
    if (r.estado === "espera_aprobacion") {
      toast({ title: "Firma requerida", description: r.mensaje });
      return;
    }
    if (r.estado === "fallo" || r.estado === "sin_resultado") {
      toast({ title: `AD · ${accion}`, description: r.mensaje, variant: "destructive" });
      return;
    }
    setResultado({ accion, datos: (r.resultado as Record<string, unknown>) ?? {} });
    toast({ title: `AD · ${accion}`, description: r.mensaje });
  };

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <input
          value={host}
          onChange={(e) => setHost(e.target.value)}
          placeholder="host del DC en el alcance del ROE (opcional)"
          className="h-9 w-full max-w-sm rounded-lg border border-line bg-ink px-3 font-mono text-[12px] text-zinc-200 outline-none focus:border-crimson/50"
        />
      </div>
      <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
        {ACCIONES_AD.map((a) => (
          <button
            key={a.id}
            type="button"
            disabled={ocupado}
            onClick={() => ejecutar(a.id)}
            className="group flex flex-col rounded-xl border border-line bg-surface p-3 text-left transition-colors hover:border-zinc-600 disabled:opacity-50"
          >
            <div className="mb-1 flex items-center justify-between gap-1">
              <span className="text-[13px] font-semibold text-zinc-100">{a.etiqueta}</span>
              <Insignia tono={TONO_RIESGO_AD[a.riesgo] ?? "slate"}>{a.riesgo}</Insignia>
            </div>
            <span className="font-mono text-[10px] text-zinc-500">{a.tecnica}</span>
            <span className="mt-1 text-[11px] text-zinc-400">{a.descripcion}</span>
          </button>
        ))}
      </div>
      {resultado ? (
        <Tarjeta>
          <p className="mb-2 text-[12px] font-semibold text-zinc-200">Resultado real de {resultado.accion}</p>
          <pre className="max-h-72 overflow-auto rounded-lg border border-line bg-ink p-3 font-mono text-[10px] leading-relaxed text-zinc-400">
            {JSON.stringify(resultado.datos, null, 2)}
          </pre>
        </Tarjeta>
      ) : null}
    </div>
  );
}

// ---------------------------------------------------------------------------

export function VistaArsenal() {
  const casoActivo = usarConsola((s) => s.casoActivo);
  const arsenal = usarConsola((s) => s.arsenal);
  const arsenalCargando = usarConsola((s) => s.arsenalCargando);
  const arsenalOcupado = usarConsola((s) => s.arsenalOcupado);
  const cargarArsenal = usarConsola((s) => s.cargarArsenal);
  const generarEvasion = usarConsola((s) => s.generarEvasion);
  const escanearArtefactoEvasion = usarConsola((s) => s.escanearArtefactoEvasion);

  const [payload, setPayload] = useState("");
  const [metodo, setMetodo] = useState("aes_cbc");
  const [formato, setFormato] = useState("python");
  const [ultimo, setUltimo] = useState<ResultadoEvasion | null>(null);

  useEffect(() => {
    if (casoActivo) void cargarArsenal();
  }, [casoActivo, cargarArsenal]);

  const metodosPersistencia = useMemo(
    () => (arsenal ? Object.values(arsenal.persistencia.metodos) : []),
    [arsenal],
  );
  const activos = metodosPersistencia.filter((m) => m.estado === "implantado").length;

  const generar = async () => {
    if (!payload.trim()) {
      toast({ title: "Arsenal", description: "Pega un payload (texto o base64)", variant: "destructive" });
      return;
    }
    let payload_b64 = btoa(payload);
    // Si ya es base64 válido, úsalo tal cual (payload binario pegado en b64)
    try {
      const decodificado = atob(payload.trim());
      if (decodificado.length && payload.trim().length % 4 === 0 && /^[A-Za-z0-9+/=\s]+$/.test(payload.trim())) {
        payload_b64 = payload.trim().replace(/\s+/g, "");
      }
      void decodificado;
    } catch { /* no era base64: se codifica el texto */ }
    const r = await generarEvasion({ payload_b64, metodo, formato });
    if (r.estado === "espera_aprobacion") {
      toast({ title: "Firma requerida", description: r.mensaje });
      return;
    }
    if (r.estado === "fallo") {
      toast({ title: "Arsenal · Evasión", description: r.mensaje, variant: "destructive" });
      return;
    }
    if (r.resultado && "hash_artefacto" in r.resultado) {
      setUltimo(r.resultado as ResultadoEvasion);
      toast({ title: "Arsenal · Evasión", description: r.mensaje });
    }
  };

  if (!casoActivo) {
    return (
      <TituloSeccion titulo="Arsenal" descripcion="Selecciona un caso para operar el arsenal bajo su ROE." />
    );
  }

  return (
    <div className="space-y-8">
      <TituloSeccion
        titulo="Arsenal"
        descripcion="Evasión verificada (YARA real), persistencia real del lab y AD ofensivo — todo por el boundary del ROE, con evidencia y firma humana."
        accion={
          <Button size="sm" variant="outline" disabled={arsenalCargando} className="gap-1.5" onClick={() => void cargarArsenal()}>
            <RefreshCw className={cn("h-3.5 w-3.5", arsenalCargando && "animate-spin")} /> Estado
          </Button>
        }
      />

      {/* EVASIÓN ---------------------------------------------------------- */}
      <section>
        <TituloSeccion
          titulo="Evasión de detección"
          descripcion="El artefacto se escanea ANTES y DESPUÉS contra el motor de firmas. Evadido solo si: 0 detecciones + round-trip byte a byte."
        />
        {arsenal?.reglas_deteccion?.length ? (
          <p className="mb-2 font-mono text-[10px] text-zinc-500">
            reglas activas: {arsenal.reglas_deteccion.join(" · ")}
          </p>
        ) : null}
        <Tarjeta className="mb-3">
          <textarea
            value={payload}
            onChange={(e) => setPayload(e.target.value)}
            rows={4}
            placeholder="Payload de entrada (texto, shellcode en base64, EICAR de prueba…)"
            className="w-full resize-y rounded-lg border border-line bg-ink p-3 font-mono text-[12px] text-zinc-200 outline-none focus:border-crimson/50"
          />
          <div className="mt-2 flex flex-wrap items-center gap-2">
            <select value={metodo} onChange={(e) => setMetodo(e.target.value)}
              className="h-8 rounded-lg border border-line bg-ink px-2 text-[12px] text-zinc-200">
              <option value="aes_cbc">AES-256-CBC + PBKDF2</option>
              <option value="xor_cascada">XOR en cascada</option>
              <option value="base64_dividido">Base64 troceado</option>
            </select>
            <select value={formato} onChange={(e) => setFormato(e.target.value)}
              className="h-8 rounded-lg border border-line bg-ink px-2 text-[12px] text-zinc-200">
              <option value="python">Loader Python</option>
              <option value="powershell">Loader PowerShell</option>
              <option value="binario">Blob binario</option>
            </select>
            <Button size="sm" disabled={arsenalOcupado} className="h-8 gap-1.5 bg-crimson text-white hover:bg-crimson-bright" onClick={() => void generar()}>
              {arsenalOcupado ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Wrench className="h-3.5 w-3.5" />}
              Generar y verificar
            </Button>
          </div>
        </Tarjeta>
        {ultimo ? <ResultadoEvasionPanel r={ultimo} /> : null}
      </section>

      {/* PERSISTENCIA ------------------------------------------------------ */}
      <section>
        <TituloSeccion
          titulo="Persistencia del lab"
          descripcion="Implantar → verificar activación real → retirar sin rastro. La implantación exige firma en la cola de Aprobaciones."
          accion={activos > 0 ? <Insignia tono="ambar">{activos} activos</Insignia> : <Insignia tono="esmeralda">host limpio</Insignia>}
        />
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
          {metodosPersistencia.map((m) => <TarjetaPersistencia key={m.metodo} m={m} />)}
        </div>
      </section>

      {/* AD ----------------------------------------------------------------- */}
      <section>
        <TituloSeccion
          titulo="Active Directory ofensivo"
          descripcion="Técnicas reales con impacket/LDAP3 contra el DC del alcance. Sin DC configurado se muestra el requisito exacto — nada inventado."
        />
        <SeccionAD />
      </section>

      {/* HISTORIAL ---------------------------------------------------------- */}
      {arsenal?.evidencias?.length ? (
        <section>
          <TituloSeccion
            titulo="Artefactos custodiados"
            descripcion="Cada acción del arsenal queda como evidencia con cadena de custodia SHA-256+HMAC."
          />
          <div className="space-y-2">
            {arsenal.evidencias.map((ev) => (
              <Tarjeta key={ev.id} className="p-3">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <p className="flex items-center gap-2 text-[12px] font-medium text-zinc-200">
                    <FileCode2 className="h-3.5 w-3.5 text-crimson-bright" /> {ev.titulo}
                  </p>
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-[10px] text-zinc-500">{ev.hash_sha256?.slice(0, 12)}…</span>
                    {ev.titulo?.includes("Evasion") ? (
                      <Button size="sm" variant="outline" disabled={arsenalOcupado}
                        className="h-6 gap-1 px-2 text-[10px]"
                        onClick={async () => {
                          const r = await escanearArtefactoEvasion(ev.id);
                          toast({ title: "Re-escaneo YARA", description: r.mensaje, variant: r.estado === "ejecutado" ? undefined : "destructive" });
                        }}>
                        <Radar className="h-3 w-3" /> Re-escanear
                      </Button>
                    ) : null}
                  </div>
                </div>
              </Tarjeta>
            ))}
          </div>
        </section>
      ) : null}
    </div>
  );
}
