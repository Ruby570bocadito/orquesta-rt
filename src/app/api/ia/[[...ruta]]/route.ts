/**
 * Puente IA — endpoint OpenAI-compatible sobre z-ai-web-dev-sdk (GLM real).
 *
 * El orquestador Python (RouterModelos) consume la frontera vía cualquier
 * API OpenAI-compatible. Este puente expone esa superficie sobre el SDK de
 * la consola: GLM responde DE VERDAD y el router mantiene su economía del
 * token (contabilidad, presupuestos por fase, política de salida).
 *
 * Seguridad de acceso:
 *   - Exige `Authorization: Bearer <token>` con el token interno persistido
 *     en db/puente-ia.token (0600, generado una sola vez por instrumentation).
 *   - Sin token válido: 401. Sin SDK inicializable: 503 honesto.
 *
 * Rutas:
 *   POST /api/ia/chat/completions  → GLM real (formato OpenAI)
 *   GET  /api/ia/models            → catálogo real disponible
 */

import { NextRequest, NextResponse } from "next/server";
import { readFileSync } from "node:fs";
import path from "node:path";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

// Ruta del token PORTABLE (raíz del proyecto = cwd del servidor Next).
const RUTA_TOKEN = process.env.PUENTE_IA_TOKEN_RUTA
  ?? path.join(process.env.ORQUESTA_RAIZ ?? process.cwd(), "db", "puente-ia.token");
const MODELO_POR_DEFECTO = process.env.MODELO_FRONTERA ?? "glm-4.6";

function tokenValido(req: NextRequest): boolean {
  const cabecera = req.headers.get("authorization") ?? "";
  if (!cabecera.startsWith("Bearer ")) return false;
  let esperado = process.env.PUENTE_IA_TOKEN ?? "";
  if (!esperado) {
    try {
      esperado = readFileSync(RUTA_TOKEN, "utf8").trim();
    } catch {
      return false;
    }
  }
  if (!esperado) return false;
  const recibido = cabecera.slice(7).trim();
  if (recibido.length !== esperado.length) return false;
  // comparación en tiempo constante
  let diff = 0;
  for (let i = 0; i < esperado.length; i++) {
    diff |= esperado.charCodeAt(i) ^ recibido.charCodeAt(i);
  }
  return diff === 0;
}

async function cliente() {
  const { default: ZAI } = await import("z-ai-web-dev-sdk");
  return ZAI.create();
}

function estimarTokens(texto: string): number {
  // Aproximación honesta ~4 chars/token cuando el backend no reporta usage.
  return Math.ceil((texto || "").length / 4);
}

export async function POST(req: NextRequest) {
  if (!tokenValido(req)) {
    return NextResponse.json(
      { error: { message: "Token de puente IA inválido o ausente", type: "auth" } },
      { status: 401 });
  }
  let cuerpo: {
    messages?: { role: string; content: string }[];
    mensajes?: { role: string; content: string }[];
    model?: string;
    max_tokens?: number;
  };
  try {
    cuerpo = await req.json();
  } catch {
    return NextResponse.json(
      { error: { message: "JSON inválido", type: "peticion" } }, { status: 400 });
  }
  const mensajes = (cuerpo.mensajes ?? cuerpo.messages) as
    | { role: string; content: string }[]
    | undefined;
  if (!mensajes?.length) {
    return NextResponse.json(
      { error: { message: "messages es obligatorio", type: "peticion" } },
      { status: 400 });
  }
  try {
    const zai = await cliente();
    const respuesta = await zai.chat.completions.create({
      model: cuerpo.model || MODELO_POR_DEFECTO,
      messages: mensajes.map((m) => ({
        role: m.role as "system" | "user" | "assistant",
        content: m.content,
      })),
      thinking: { type: "disabled" },
    });
    // Normalización a formato OpenAI: el SDK devuelve choices/usage u objeto
    // libre; nunca devolvemos éxito sin contenido real.
    const crudo = respuesta as {
      choices?: { message?: { content?: string } }[];
      usage?: { prompt_tokens?: number; completion_tokens?: number };
      content?: string;
      id?: string;
    };
    const texto =
      crudo?.choices?.[0]?.message?.content ?? crudo?.content ?? "";
    if (!texto) {
      return NextResponse.json(
        { error: { message: "El backend de frontera no devolvió contenido",
                   type: "backend" } },
        { status: 502 });
    }
    return NextResponse.json({
      id: crudo.id ?? `puente-${Date.now()}`,
      object: "chat.completion",
      created: Math.floor(Date.now() / 1000),
      model: cuerpo.model || MODELO_POR_DEFECTO,
      choices: [{ index: 0, message: { role: "assistant", content: texto },
                  finish_reason: "stop" }],
      usage: {
        prompt_tokens: crudo.usage?.prompt_tokens ??
          estimarTokens(mensajes.map((m) => m.content).join("\n")),
        completion_tokens: crudo.usage?.completion_tokens ??
          estimarTokens(texto),
      },
    });
  } catch (error) {
    return NextResponse.json(
      { error: { message: `Fallo del puente IA: ${(error as Error).message.slice(0, 200)}`,
                 type: "backend" } },
      { status: 502 });
  }
}

export async function GET(req: NextRequest) {
  // GET /api/ia (healthcheck interno) o GET /api/ia/models (catálogo).
  const ruta = req.nextUrl.pathname.replace(/\/+$/, "");
  if (ruta.endsWith("/models")) {
    if (!tokenValido(req)) {
      return NextResponse.json(
        { error: { message: "Token de puente IA inválido o ausente" } },
        { status: 401 });
    }
    return NextResponse.json({
      object: "list",
      data: [
        { id: MODELO_POR_DEFECTO, object: "model", owned_by: "puente-consola" },
      ],
    });
  }
  return NextResponse.json({
    servicio: "puente-ia",
    estado: "ok",
    formato: "openai-compatible (chat/completions, models)",
  });
}
