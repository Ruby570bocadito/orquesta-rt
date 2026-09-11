"use client";

/**
 * Vista Integraciones: estado REAL de las conexiones con las herramientas
 * estándar del sector que el operador configura (Sliver gRPC, Mythic
 * GraphQL, Metasploit RPC, LDAP, SMTP, router LLM, OSINT). Sin datos
 * ficticios: cada tarjeta muestra la configuración del despliegue y la
 * prueba de conexión toca la API oficial configurada.
 */

import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import {
  Cable, CheckCircle2, Loader2, PlugZap, RefreshCw, ShieldQuestion,
  Wifi, WifiOff, XCircle,
} from "lucide-react";
import { Tarjeta, Insignia, TituloSeccion } from "@/components/consola/ui";
import { usarConsola } from "@/lib/store";
import { ETIQUETA_INTEGRACION, EstadoIntegracion, ResultadoPrueba } from "@/lib/tipos";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import { SeccionWebhooks } from "@/components/consola/webhooks";
import { SeccionPlantilla } from "@/components/consola/plantilla";
import { SeccionNvd, SeccionRutas } from "@/components/consola/rutas";

interface FilaIntegracion {
  clave: string;       // nombre para /integraciones/probar
  grupo: EstadoIntegracion | Record<string, EstadoIntegracion>;
  nota?: string;
}

function TarjetaIntegracion({
  clave, estado, prueba, onProbar,
}: {
  clave: string;
  estado?: EstadoIntegracion;
  prueba?: { cargando: boolean; resultado?: ResultadoPrueba };
  onProbar: (nombre: string) => void;
}) {
  const configurado = Boolean(estado?.configurado);
  const conectado = Boolean(prueba?.resultado?.conectado);
  return (
    <Tarjeta className="flex h-full flex-col">
      <div className="mb-3 flex items-start justify-between gap-2">
        <p className="flex items-center gap-2 text-sm font-semibold text-zinc-100">
          {configurado ? (
            <Wifi className="h-4 w-4 text-emerald-400" />
          ) : (
            <WifiOff className="h-4 w-4 text-zinc-500" />
          )}
          {ETIQUETA_INTEGRACION[clave] ?? clave}
        </p>
        <Insignia tono={configurado ? "esmeralda" : "slate"}>
          {configurado ? "configurado" : "no configurado"}
        </Insignia>
      </div>
      <p className="flex-1 font-mono text-[11px] leading-relaxed text-zinc-500">
        {estado?.detalle ?? "—"}
      </p>
      {estado?.servidor ? (
        <p className="mt-2 truncate font-mono text-[11px] text-zinc-400">
          <span className="text-zinc-600">servidor:</span> {estado.servidor}
        </p>
      ) : null}
      <div className="mt-4 flex items-center justify-between gap-3">
        <Button
          variant="outline"
          size="sm"
          className="h-8 gap-1.5 border-line bg-panel text-xs text-zinc-300 hover:bg-raised"
          onClick={() => onProbar(clave)}
          disabled={prueba?.cargando}
        >
          {prueba?.cargando ? (
            <Loader2 className="h-3.5 w-3.5 animate-spin" />
          ) : (
            <PlugZap className="h-3.5 w-3.5" />
          )}
          Probar conexión
        </Button>
        {prueba?.resultado ? (
          <motion.span
            initial={{ opacity: 0, x: 6 }}
            animate={{ opacity: 1, x: 0 }}
            className={cn(
              "flex items-center gap-1.5 text-[11px] font-medium",
              conectado ? "text-emerald-300" : "text-red-300",
            )}
          >
            {conectado ? (
              <CheckCircle2 className="h-3.5 w-3.5" />
            ) : (
              <XCircle className="h-3.5 w-3.5" />
            )}
            {conectado ? "conexión real establecida" : "sin conexión"}
          </motion.span>
        ) : null}
      </div>
      {prueba?.resultado && !conectado ? (
        <p className="mt-2 rounded-md border border-line bg-ink p-2 font-mono text-[10px] leading-relaxed text-zinc-500">
          {String(prueba.resultado.error ?? "sin detalle").slice(0, 300)}
        </p>
      ) : null}
      {prueba?.resultado && conectado ? (
        <p className="mt-2 rounded-md border border-line bg-ink p-2 font-mono text-[10px] leading-relaxed text-emerald-200/80">
          {resumenExito(prueba.resultado)}
        </p>
      ) : null}
    </Tarjeta>
  );
}

function resumenExito(r: ResultadoPrueba): string {
  const fragmentos: string[] = [];
  if (r.version) fragmentos.push(`versión ${JSON.stringify(r.version).slice(0, 60)}`);
  if (typeof r.base === "string" && r.base) fragmentos.push(r.base);
  if (r.modelos) fragmentos.push(`modelos: ${String(r.modelos).slice(0, 80)}`);
  if (r.nota) fragmentos.push(String(r.nota).slice(0, 120));
  if (r.unidades_organizativas) fragmentos.push(`${r.usuarios_total ?? "?"} usuarios, ${r.unidades_organizativas} OUs`);
  if (r.remitente) fragmentos.push(`remitente ${r.remitente}`);
  if (!fragmentos.length) {
    const claves = Object.keys(r).filter((k) => k !== "conectado");
    fragmentos.push(`respuesta real: ${claves.slice(0, 4).join(", ")}`);
  }
  return fragmentos.join(" · ");
}

export function VistaIntegraciones() {
  const integraciones = usarConsola((s) => s.integraciones);
  const cargarIntegraciones = usarConsola((s) => s.cargarIntegraciones);
  const probarIntegracion = usarConsola((s) => s.probarIntegracion);
  const pruebas = usarConsola((s) => s.pruebasIntegracion);
  const [sincronizando, setSincronizando] = useState(false);

  useEffect(() => {
    if (!integraciones) void cargarIntegraciones();
  }, [integraciones, cargarIntegraciones]);

  const recargar = async () => {
    setSincronizando(true);
    await cargarIntegraciones();
    setSincronizando(false);
  };

  if (!integraciones) {
    return (
      <div className="flex h-64 items-center justify-center gap-2 text-sm text-zinc-500">
        <Loader2 className="h-4 w-4 animate-spin" /> consultando estado real del despliegue…
      </div>
    );
  }

  const c2 = Object.entries(integraciones.c2 ?? {});
  const llm = Object.entries(integraciones.router_llm ?? {});
  const osint = Object.entries(integraciones.osint ?? {});

  const mapaEstado: Record<string, EstadoIntegracion> = {
    ...Object.fromEntries(c2),
    active_directory: integraciones.active_directory,
    phishing_smtp: integraciones.phishing_smtp,
    attack_paths: integraciones.attack_paths,
    motor_rutas: integraciones.motor_rutas,
    threat_intel: integraciones.threat_intel,
    nvd: integraciones.nvd,
    sso: integraciones.sso,
    ...Object.fromEntries(llm.map(([k, v]) => ([
      k === "frontera" ? "llm_frontera" : "llm_local", v] as const))),
    webhook: integraciones.webhook,
    ...Object.fromEntries(osint),
  };

  const grupos: { titulo: string; descripcion: string; claves: string[] }[] = [
    {
      titulo: "Mando y control (C2)",
      descripcion: "Frameworks del equipo conectados por su API oficial. Las tareas y retiradas exigen firma del operador en el boundary.",
      claves: c2.map(([k]) => k),
    },
    {
      titulo: "Directorio y campañas autorizadas",
      descripcion: "Colección AD por LDAP real con credenciales bajo ROE, y envío de campañas vía la infraestructura SMTP del equipo.",
      claves: ["active_directory", "phishing_smtp"],
    },
    {
      titulo: "Attack paths y threat intel",
      descripcion: "BloodHound CE por su API oficial y el motor Neo4j del despliegue (Cypher dirigido sobre esquema BloodHound); MISP/NVD para el intel.",
      claves: ["attack_paths", "motor_rutas", "threat_intel", "nvd"],
    },
    {
      titulo: "Identidad federada",
      descripcion: "SSO OIDC (authorization-code + PKCE, verificación RS256 del id_token) para el acceso de los operadores: alta JIT opcional como lector.",
      claves: ["sso"],
    },
    {
      titulo: "Router de modelos IA",
      descripcion: "Backends de inferencia del router semántico: frontera (GLM/Z.ai, OpenAI-compatible) y local (Ollama/vLLM on-prem).",
      claves: llm.map(([k, _]) => (k === "frontera" ? "llm_frontera" : "llm_local")),
    },
    {
      titulo: "Notificaciones del equipo",
      descripcion: "Canal webhook heredado del entorno (WEBHOOK_URL). Los receptores configurables por evento están más abajo en la sección admin.",
      claves: ["webhook"],
    },
    {
      titulo: "Fuentes OSINT",
      descripcion: "Fuentes pasivas ya activas (CT logs, Internet Archive) y las que requieren clave propia del operador (HIBP).",
      claves: osint.map(([k]) => k),
    },
  ];

  return (
    <div className="space-y-6">
      <TituloSeccion
        titulo="Integraciones del despliegue"
        descripcion="Estado real de las herramientas estándar del sector conectadas a esta plataforma. Sin instancias configuradas, cada tarjeta documenta el requisito exacto: nada se simula."
        accion={
          <Button
            variant="outline"
            size="sm"
            className="h-8 gap-1.5 border-line bg-panel text-xs text-zinc-300 hover:bg-raised"
            onClick={recargar}
            disabled={sincronizando}
          >
            <RefreshCw className={cn("h-3.5 w-3.5", sincronizando && "animate-spin")} />
            Actualizar estado
          </Button>
        }
      />

      {grupos.map((grupo, gi) => (
        <motion.section
          key={grupo.titulo}
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: gi * 0.05 }}
        >
          <div className="mb-3 flex items-center gap-2">
            <Cable className="h-3.5 w-3.5 text-crimson-bright" />
            <h3 className="text-[13px] font-semibold text-zinc-200">{grupo.titulo}</h3>
            <span className="text-[11px] text-zinc-600">— {grupo.descripcion}</span>
          </div>
          <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
            {grupo.claves.map((clave) => (
              <TarjetaIntegracion
                key={clave}
                clave={clave}
                estado={mapaEstado[clave]}
                prueba={pruebas[clave]}
                onProbar={probarIntegracion}
              />
            ))}
          </div>
        </motion.section>
      ))}

      {/* Grafo de plantilla REAL desde el directorio (v17) */}
      <SeccionPlantilla />

      {/* Rutas de ataque (motor Neo4j real) e intel CVE NVD (v22) */}
      <SeccionRutas />
      <SeccionNvd />

      {/* Webhooks de notificación operativa (v16): gestión admin real */}
      <SeccionWebhooks />

      <Tarjeta>
        <div className="flex items-start gap-3">
          <ShieldQuestion className="mt-0.5 h-4 w-4 shrink-0 text-amber-300" />
          <p className="text-[12px] leading-relaxed text-zinc-400">
            Las variables de configuración se definen en el entorno del backend
            (docker-compose / .env del despliegue on-prem). Las credenciales nunca
            llegan a esta consola: solo boleanos, direcciones y resultados reales de
            las pruebas. Toda acción ofensiva a través de estas integraciones pasa
            por el boundary de guardrails y exige tu firma.
          </p>
        </div>
      </Tarjeta>
    </div>
  );
}
