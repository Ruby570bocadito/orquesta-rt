/**
 * Proxy de la consola al orquestador Python (backend real).
 *
 * La consola consulta /api/orchestrator/* y este handler reenvía la
 * petición a la API FastAPI del orquestador (ORCHESTRATOR_URL, por defecto
 * http://127.0.0.1:8000). Si el orquestador no responde, se intenta
 * RELANZARLO una vez (bootstrap de instrumentation.ts) antes de devolver
 * 503 con un diagnóstico claro.
 *
 * - Reenvía la cabecera Authorization (sesión JWT del operador).
 * - Propaga la IP real del operador en X-Forwarded-For: el limitador de
 *   tasa del backend distingue operadores por IP aunque pasen por este
 *   proxy (si no, TODOS compartirían el cubo de 127.0.0.1).
 * - Propaga el User-Agent del navegador (v34): el registro de sesiones
 *   activas de la higiene muestra el dispositivo real de cada sesión
 *   ("Chrome · Linux"); sin esto, toda sesión vía consola nacía sin
 *   dispositivo identificado.
 * - Para flujos SSE (/eventos) transmite el stream sin buffering ni
 *   timeout: el backend recicla la conexión cada 4 minutos y el cliente
 *   reconecta automáticamente.
 */

import { NextRequest, NextResponse } from "next/server";

// El bootstrap del backend usa fs/child_process: runtime Node obligatorio.
export const runtime = "nodejs";

const BASE = process.env.ORCHESTRATOR_URL ?? "http://127.0.0.1:8000";

async function reenviar(req: NextRequest, segmentos: string[]) {
  // z3 (auditoría sesión 4): los segmentos "." / ".." permiten, tras la
  // normalización de URL del cliente HTTP (WHATWG), alcanzar rutas del
  // backend FUERA de /api (p. ej. /api/../openapi.json → /openapi.json),
  // que no pasan por la autenticación del orquestador. Se rechazan aquí,
  // antes de construir el destino.
  if (segmentos.some((s) => s === "." || s === "..")) {
    return NextResponse.json(
      {
        error: "ruta_invalida",
        detalle: "Los segmentos de ruta no pueden ser '.' ni '..'.",
      },
      { status: 400 },
    );
  }
  const ruta = segmentos.map(encodeURIComponent).join("/");
  const consulta = req.nextUrl.search ?? "";
  const destino = `${BASE}/api/${ruta}${consulta}`;
  const cuerpo =
    req.method !== "GET" && req.method !== "HEAD" ? await req.text() : undefined;
  const autorizacion = req.headers.get("authorization");
  const esFlujo = segmentos.length > 0 && segmentos[segmentos.length - 1] === "eventos";

  let respuesta = await intentar(destino, req.method, cuerpo, autorizacion, esFlujo, req);
  if (respuesta === null && !esFlujo) {
    // Backend caído: bootstrap (levanta uvicorn + lab) y reintento único
    try {
      const { arrancarBackend } = await import("@/instrumentation");
      await arrancarBackend();
    } catch {
      /* el reintento lo dirá */
    }
    respuesta = await intentar(destino, req.method, cuerpo, autorizacion, esFlujo, req);
  }
  if (respuesta === null) {
    return NextResponse.json(
      {
        error: "orquestador_no_disponible",
        detalle: `No se pudo contactar con el orquestador en ${BASE} tras relanzarlo. ` +
                 "Acción: ejecuta ./install.sh (crea el .venv con uvicorn+fastapi) " +
                 "y ./start.sh, o revisa logs/api.log para el error concreto.",
      },
      { status: 503 },
    );
  }
  return respuesta;
}

async function intentar(
  destino: string,
  metodo: string,
  cuerpo: string | undefined,
  autorizacion: string | null,
  flujo: boolean,
  req?: NextRequest,
): Promise<NextResponse | null> {
  try {
    const cabeceras: Record<string, string> = { "Content-Type": "application/json" };
    if (autorizacion) cabeceras["Authorization"] = autorizacion;
    if (req) {
      // v34: el dispositivo real de la sesión (higiene: sesiones activas).
      const agente = req.headers.get("user-agent");
      if (agente) cabeceras["User-Agent"] = agente;
      // IP real del operador, NO suplantable:
      //  - x-real-ip lo fija el reverse proxy de confianza (Caddy) con el
      //    remote_host real y sobrescribe cualquier valor del cliente.
      //  - Si solo hay x-forwarded-for, se usa el ÚLTIMO salto (el añadido
      //    por el proxy de confianza más próximo); el PRIMERO lo controla
      //    el cliente y permitiría suplantar la clave del limitador de tasa.
      const xff = req.headers.get("x-forwarded-for")?.split(",").map(s => s.trim()).filter(Boolean) ?? [];
      const ip = req.headers.get("x-real-ip")?.trim()
        || xff[xff.length - 1]
        || "";
      if (ip) cabeceras["X-Forwarded-For"] = ip;
    }
    const r = await fetch(destino, {
      method: metodo,
      headers: cabeceras,
      body: cuerpo,
      // Fases activas: I/O real puede tardar. En flujos SSE no hay timeout
      // (la conexión es larga por diseño y el backend la recicla).
      signal: flujo ? undefined : AbortSignal.timeout(120_000),
      cache: "no-store",
    });
    if (flujo && (r.headers.get("content-type") ?? "").includes("text/event-stream")) {
      // Transmisión directa del stream: sin buffering intermedio
      return new NextResponse(r.body, {
        status: r.status,
        headers: {
          "Content-Type": "text/event-stream",
          "Cache-Control": "no-cache",
          Connection: "keep-alive",
        },
      });
    }
    // Transmisión BINARIA-segura: el cuerpo se reenvía como stream de bytes
    // SIN decodificar. Antes se hacía r.text() + re-encode, lo que corrompía
    // cualquier entrega binaria (p. ej. el respaldo ZIP del caso: la cabecera
    // PK\x03\x04 perdía bytes y el archivo llegaba inválido al navegador).
    // Se preservan content-type y content-disposition del backend.
    const cabecerasSalida: Record<string, string> = {
      "Content-Type": r.headers.get("content-type") ?? "application/json",
    };
    const disposicion = r.headers.get("content-disposition");
    if (disposicion) cabecerasSalida["Content-Disposition"] = disposicion;
    return new NextResponse(r.body, {
      status: r.status,
      headers: cabecerasSalida,
    });
  } catch {
    return null;
  }
}

type Ctx = { params: Promise<{ path: string[] }> };

export async function GET(req: NextRequest, ctx: Ctx) {
  const { path } = await ctx.params;
  return reenviar(req, path);
}

export async function POST(req: NextRequest, ctx: Ctx) {
  const { path } = await ctx.params;
  return reenviar(req, path);
}

// PATCH: p. ej. marcar el resultado de detección de un hallazgo (v15).
// Sin este handler Next.js respondía 405 ANTES de llegar al orquestador.
export async function PATCH(req: NextRequest, ctx: Ctx) {
  const { path } = await ctx.params;
  return reenviar(req, path);
}
