"use client";

/**
 * Rutas de ataque y enriquecimiento CVE (v22) — secciones PLEGADAS para no
 * cargar la vista de Integraciones.
 *
 * · Rutas de ataque: el motor Neo4j REAL del despliegue calcula los paths
 *   (Cypher dirigido, allShortestPaths) sobre la colección cargada. Cada
 *   ruta se dibuja como cadena de nodos/aristas tal y como la devuelve el
 *   motor: la plataforma no recalcula ni embellece. Orígenes sin ruta se
 *   declaran tal cual (honestidad > relleno).
 *
 * · Enriquecimiento CVE (NVD): contrasta un texto (p. ej. un hallazgo con
 *   "Apache 2.4.49") contra la API pública 2.0 del NIST y muestra los CVEs
 *   reales coincidentes con su CVSS. Complemento cuando el despliegue no
 *   tiene MISP; el conector oficial de MISP sigue disponible.
 */

import { useState } from "react";
import { motion } from "framer-motion";
import {
  ChevronDown, ChevronUp, Crown, KeyRound, Loader2, Route, Search,
  ShieldAlert, Swords, Target,
} from "lucide-react";
import { Tarjeta, Insignia } from "@/components/consola/ui";
import { usarConsola } from "@/lib/store";
import type { RutaAtaque } from "@/lib/tipos";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { cn } from "@/lib/utils";

const TONO_TIPO: Record<string, string> = {
  User: "border-sky-500/40 bg-sky-500/10 text-sky-200",
  Group: "border-amber-500/40 bg-amber-500/10 text-amber-200",
  Computer: "border-violet-500/40 bg-violet-500/10 text-violet-200",
  Domain: "border-crimson-bright/50 bg-crimson-bright/10 text-red-200",
};

function ChipNodo({ nodo }: { nodo: RutaAtaque["nodos"][number] }) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 rounded-md border px-2 py-0.5 font-mono text-[10px]",
        TONO_TIPO[nodo.tipo] ?? "border-line bg-ink text-zinc-300",
      )}
      title={`${nodo.tipo} ${nodo.nombre}`}
    >
      {nodo.tipo === "Group" ? <Crown className="h-3 w-3" /> : null}
      {nodo.tipo === "Computer" ? <Swords className="h-3 w-3" /> : null}
      {nodo.tipo === "Domain" ? <Target className="h-3 w-3" /> : null}
      {nodo.asreproastable ? <KeyRound className="h-3 w-3 text-amber-300" /> : null}
      {nodo.nombre.split("@")[0].replace(/\.TEST\.LOCAL$/i, "").slice(0, 22)}
    </span>
  );
}

function Ruta({ ruta, indice }: { ruta: RutaAtaque; indice: number }) {
  return (
    <div className="rounded-lg border border-line bg-ink/60 p-3">
      <div className="mb-2 flex items-center gap-2">
        <span className="font-mono text-[10px] text-zinc-600">
          ruta {indice + 1} · {ruta.saltos} saltos
        </span>
        {ruta.nodos.at(-1)?.tipo === "Domain" ? (
          <Insignia tono="crimson">DCSync potencial</Insignia>
        ) : null}
      </div>
      <div className="flex flex-wrap items-center gap-1.5">
        {ruta.nodos.map((nodo, i) => (
          <span key={`${nodo.nombre}-${i}`} className="flex items-center gap-1.5">
            {i > 0 ? (
              <span className="font-mono text-[9px] text-zinc-600">
                —{ruta.aristas[i - 1]}→
              </span>
            ) : null}
            <ChipNodo nodo={nodo} />
          </span>
        ))}
      </div>
    </div>
  );
}

export function SeccionRutas() {
  const [abierta, setAbierta] = useState(false);
  const vista = usarConsola((s) => s.vistaRutas);
  const resultado = usarConsola((s) => s.rutasResultado);
  const cargando = usarConsola((s) => s.rutasCargando);
  const cargarRutas = usarConsola((s) => s.cargarRutas);
  const calcularRutas = usarConsola((s) => s.calcularRutas);
  const [origen, setOrigen] = useState("");
  const [errorCarga, setErrorCarga] = useState<string | null>(null);

  const abrir = async () => {
    const siguiente = !abierta;
    setAbierta(siguiente);
    if (siguiente && !vista) {
      try {
        setErrorCarga(null);
        await cargarRutas();
      } catch (e) {
        setErrorCarga((e as Error).message);
      }
    }
  };

  const motor = vista?.motor;
  const usuarios = vista?.origenes?.usuarios ?? [];
  const objetivos = vista?.objetivos?.objetivos ?? [];

  // Insignia HONESTA derivada del estado: "sin consultar" (no se ha
  // preguntado al backend) vs el estado real del motor una vez consultado.
  const insignia = !vista ? (
    cargando ? (
      <Insignia tono="slate">consultando…</Insignia>
    ) : errorCarga ? (
      <Insignia tono="rojo">fallo de consulta</Insignia>
    ) : (
      <Insignia tono="slate">sin consultar</Insignia>
    )
  ) : motor?.conectado && motor.cargado ? (
    <Insignia tono="esmeralda">grafo cargado</Insignia>
  ) : motor?.conectado ? (
    <Insignia tono="ambar">sin colección</Insignia>
  ) : (
    <Insignia tono="slate">no configurado</Insignia>
  );

  return (
    <Tarjeta>
      <button
        className="flex w-full items-center justify-between gap-3"
        onClick={() => void abrir()}
      >
        <span className="flex items-center gap-2 text-sm font-semibold text-zinc-100">
          <Route className="h-4 w-4 text-crimson-bright" />
          Rutas de ataque · motor Neo4j
          {insignia}
        </span>
        {abierta ? (
          <ChevronUp className="h-4 w-4 text-zinc-500" />
        ) : (
          <ChevronDown className="h-4 w-4 text-zinc-500" />
        )}
      </button>

      {abierta ? (
        <motion.div
          initial={{ opacity: 0, height: 0 }}
          animate={{ opacity: 1, height: "auto" }}
          className="mt-4 space-y-4"
        >
          {errorCarga ? (
            <p className="rounded-md border border-line bg-ink p-3 font-mono text-[11px] text-red-300/80">
              {errorCarga}
            </p>
          ) : null}
          {!motor || !motor.conectado ? (
            <p className="rounded-md border border-line bg-ink p-3 font-mono text-[11px] leading-relaxed text-zinc-500">
              {motor?.error ?? "Motor no configurado: defina NEO4J_URL, NEO4J_USER y NEO4J_PASS en el entorno del backend, o apunte al BloodHound CE del despliegue (tarjeta BloodHound CE)."}
            </p>
          ) : !motor.cargado ? (
            <p className="rounded-md border border-line bg-ink p-3 font-mono text-[11px] leading-relaxed text-zinc-500">
              {motor.nota}
            </p>
          ) : (
            <>
              <div className="flex flex-wrap items-center gap-2 text-[11px] text-zinc-500">
                {Object.entries(motor.objetos ?? {}).map(([tipo, total]) => (
                  <span key={tipo} className="rounded-md border border-line bg-ink px-2 py-0.5 font-mono">
                    {tipo}: {total}
                  </span>
                ))}
                <span className="font-mono">{motor.motor}</span>
              </div>

              <div className="flex flex-wrap items-center gap-2">
                <select
                  value={origen}
                  onChange={(e) => setOrigen(e.target.value)}
                  className="h-9 rounded-md border border-line bg-ink px-2 font-mono text-xs text-zinc-200"
                >
                  <option value="">— elegir origen del grafo —</option>
                  {usuarios.map((u) => (
                    <option key={u.nombre} value={u.nombre}>
                      {u.nombre.split("@")[0]} · {u.cargo || u.displayname}
                      {u.admincount ? " · admin" : ""}
                      {u.asreproastable ? " · AS-REP" : ""}
                    </option>
                  ))}
                </select>
                <Button
                  variant="outline"
                  size="sm"
                  disabled={cargando}
                  className="h-8 gap-1.5 border-line bg-panel text-xs text-zinc-300 hover:bg-raised"
                  onClick={() => void calcularRutas(origen).catch((e) => setErrorCarga((e as Error).message))}
                >
                  {cargando ? (
                    <Loader2 className="h-3.5 w-3.5 animate-spin" />
                  ) : (
                    <Search className="h-3.5 w-3.5" />
                  )}
                  Calcular rutas (allShortestPaths)
                </Button>
                {origen ? (
                  <Button
                    variant="ghost"
                    size="sm"
                    disabled={cargando}
                    className="h-8 text-xs text-zinc-500"
                    onClick={() => {
                      setOrigen("");
                      void calcularRutas("").catch((e) => setErrorCarga((e as Error).message));
                    }}
                  >
                    desde todo el grafo
                  </Button>
                ) : null}
              </div>

              {objetivos.length ? (
                <p className="flex flex-wrap items-center gap-1.5 text-[11px] text-zinc-500">
                  <span className="font-mono text-zinc-600">objetivos de alto valor:</span>
                  {objetivos.map((o) => (
                    <Insignia key={o.nombre} tono={o.tipo === "Group" ? "ambar" : "crimson"}>
                      {o.nombre}
                    </Insignia>
                  ))}
                </p>
              ) : null}

              {resultado?.conectado ? (
                resultado.total ? (
                  <div className="space-y-2">
                    {resultado.rutas!.map((ruta, i) => (
                      <Ruta key={i} ruta={ruta} indice={i} />
                    ))}
                    <p className="font-mono text-[10px] text-zinc-600">{resultado.nota}</p>
                  </div>
                ) : (
                  <p className="rounded-md border border-line bg-ink p-3 font-mono text-[11px] text-zinc-500">
                    0 rutas desde «{resultado.origen}» hacia objetivos de alto valor
                    con la colección cargada: el grafo actual no conecta ese
                    origen. Es un resultado legítimo, no un error.
                  </p>
                )
              ) : resultado && !resultado.conectado ? (
                <p className="rounded-md border border-line bg-ink p-3 font-mono text-[11px] text-red-300/80">
                  {resultado.error}
                </p>
              ) : null}
            </>
          )}
        </motion.div>
      ) : null}
    </Tarjeta>
  );
}

export function SeccionNvd() {
  const [abierta, setAbierta] = useState(false);
  const [texto, setTexto] = useState("");
  const resultado = usarConsola((s) => s.nvdResultado);
  const cargando = usarConsola((s) => s.nvdCargando);
  const enriquecerNvd = usarConsola((s) => s.enriquecerNvd);

  return (
    <Tarjeta>
      <button
        className="flex w-full items-center justify-between gap-3"
        onClick={() => setAbierta(!abierta)}
      >
        <span className="flex items-center gap-2 text-sm font-semibold text-zinc-100">
          <ShieldAlert className="h-4 w-4 text-crimson-bright" />
          Enriquecimiento CVE · NVD real (NIST)
          <Insignia tono="esmeralda">API pública</Insignia>
        </span>
        {abierta ? (
          <ChevronUp className="h-4 w-4 text-zinc-500" />
        ) : (
          <ChevronDown className="h-4 w-4 text-zinc-500" />
        )}
      </button>

      {abierta ? (
        <motion.div
          initial={{ opacity: 0, height: 0 }}
          animate={{ opacity: 1, height: "auto" }}
          className="mt-4 space-y-3"
        >
          <p className="text-[12px] leading-relaxed text-zinc-500">
            Contrasta el texto de un hallazgo (producto + versión) contra la
            base CVE autoritativa del NIST. Complemento real cuando el
            despliegue no tiene MISP: el conector oficial sigue listo para su
            instancia.
          </p>
          <div className="flex gap-2">
            <Input
              value={texto}
              onChange={(e) => setTexto(e.target.value)}
              placeholder="p. ej. Apache 2.4.49 en el servidor web del alcance"
              className="h-9 border-line bg-ink font-mono text-xs"
            />
            <Button
              variant="outline"
              size="sm"
              disabled={cargando || texto.trim().length < 4}
              className="h-9 gap-1.5 border-line bg-panel text-xs text-zinc-300 hover:bg-raised"
              onClick={() => void enriquecerNvd(texto).catch(() => undefined)}
            >
              {cargando ? (
                <Loader2 className="h-3.5 w-3.5 animate-spin" />
              ) : (
                <Search className="h-3.5 w-3.5" />
              )}
              Enriquecer
            </Button>
          </div>

          {resultado && !resultado.conectado ? (
            <p className="rounded-md border border-line bg-ink p-3 font-mono text-[11px] text-zinc-500">
              {resultado.error}
            </p>
          ) : null}

          {resultado?.conectado ? (
            resultado.total ? (
              <div className="space-y-2">
                {resultado.coincidencias!.map((cve) => (
                  <div
                    key={cve.cve}
                    className="rounded-lg border border-line bg-ink/60 p-3"
                  >
                    <div className="mb-1 flex flex-wrap items-center gap-2">
                      <span className="font-mono text-xs font-semibold text-zinc-100">
                        {cve.cve}
                      </span>
                      {cve.severidad ? (
                        <Insignia
                          tono={
                            cve.severidad === "CRITICAL" || cve.severidad === "HIGH"
                              ? "crimson"
                              : cve.severidad === "MEDIUM"
                                ? "ambar"
                                : "slate"
                          }
                        >
                          {cve.severidad}
                          {cve.cvss_base !== null ? ` ${cve.cvss_base}` : ""}
                        </Insignia>
                      ) : null}
                      {cve.publicado ? (
                        <span className="font-mono text-[10px] text-zinc-600">
                          publicado {cve.publicado}
                        </span>
                      ) : null}
                    </div>
                    <p className="line-clamp-2 text-[11px] leading-relaxed text-zinc-400">
                      {cve.descripcion}
                    </p>
                  </div>
                ))}
                <p className="font-mono text-[10px] text-zinc-600">{resultado.nota}</p>
              </div>
            ) : (
              <p className="rounded-md border border-line bg-ink p-3 font-mono text-[11px] text-zinc-500">
                El NVD no devolvió coincidencias para «{resultado.consultas?.map((c) => c.consulta).join(", ")}».
              </p>
            )
          ) : null}
        </motion.div>
      ) : null}
    </Tarjeta>
  );
}
