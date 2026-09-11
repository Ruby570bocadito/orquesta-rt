/**
 * Arranque del backend REAL con el servidor Next.js.
 *
 * Next.js ejecuta register() una vez al arrancar el proceso del servidor.
 * Aquí se levantan los dos procesos Python de la plataforma como hijos del
 * proceso Next (el supervisor del sistema mantiene vivo Next.js, y por tanto
 * mantiene vivo el backend):
 *
 *   1. orquestador  : uvicorn orchestrator.api:app en 127.0.0.1:8000
 *   2. lab objetivo : servidor HTTP real en 127.0.0.1:8080 (solo localhost)
 *
 * Si el orquestador ya responde (arranque previo, docker compose, etc.) no
 * se toca nada. El proxy /api/orchestrator/* relanza el backend si cae.
 */

export async function register() {
  if (process.env.NEXT_RUNTIME !== "nodejs") return;
  await arrancarBackend();
}

// Raíz del proyecto PORTABLE: se deduce del directorio actual (el proyecto
// puede desplegarse en cualquier ruta; no hay dependencia de una ubicación
// concreta del disco). PLAATAFORMA_DIR permite anularlo por entorno.
import path from "node:path";
const RAIZ = process.env.ORQUESTA_RAIZ ?? process.cwd();
const RAIZ_PLATAFORMA = process.env.PLATAFORMA_DIR ?? path.join(RAIZ, "platform");
const LOG_ORQUESTADOR = path.join(RAIZ, "logs", "api.log");
const LOG_LAB = path.join(RAIZ, "logs", "lab.log");
const RUTA_TOKEN_PUENTE = path.join(RAIZ, "db", "puente-ia.token");

/**
 * Token interno del puente IA (db/puente-ia.token): el orquestador Python
 * lo usa como API_FRONTERA_CLAVE para autenticarse contra /api/ia. Se genera
 * una sola vez y persiste con permisos 0600 — la consola y el orquestador
 * comparten la clave sin que haya secretos en el código.
 */
async function asegurarTokenPuente(): Promise<string> {
  const fs = await import(/* turbopackIgnore: true */ "node:fs");
  const { randomBytes } = await import(/* turbopackIgnore: true */ "node:crypto");
  try {
    const existente = fs.readFileSync(RUTA_TOKEN_PUENTE, "utf8").trim();
    if (existente) return existente;
  } catch {
    /* no existe aún */
  }
  const token = randomBytes(32).toString("hex");
  fs.mkdirSync(path.join(RAIZ, "db"), { recursive: true });
  fs.writeFileSync(RUTA_TOKEN_PUENTE, token + "\n", { mode: 0o600 });
  return token;
}

/**
 * Intérprete Python con las dependencias de la plataforma (uvicorn+fastapi).
 *
 * El "python3" del PATH NO siempre es el del entorno donde se instalaron
 * las dependencias: tras un reinicio, el proceso padre puede arrancar con
 * un PATH distinto y el backend moría con "No module named uvicorn" sin
 * diagnóstico claro. Resolución en orden, PROBANDO cada candidato:
 *   1. ORQUESTA_PYTHON (fijado por start.sh / docker compose)
 *   2. <raíz>/.venv/bin/python3            (creado por install.sh)
 *   3. <raíz>/platform/.venv/bin/python3
 *   4. python3 del PATH (solo si importa uvicorn+fastapi sin error)
 */
let _pythonResuelto: string | null = null;

// Segmentos de rura calculados en RUNTIME (join de array): Turbopack
// trata los literales de ruta en path.join como referencias de asset y
// seguía el symlink .venv/bin/python3 fuera de la raíz del proyecto,
// abortando `next build` ("points out of the filesystem root").
const _REL_VENV = [".venv", "bin", "python3"].join("/");
const _REL_VENV_PLATAFORMA = ["platform", ".venv", "bin", "python3"].join("/");

async function importable(py: string): Promise<boolean> {
  const { execFile } = await import(/* turbopackIgnore: true */ "node:child_process");
  return new Promise((resolve) => {
    execFile(py, ["-c", "import uvicorn, fastapi"], { timeout: 10_000 }, (err) =>
      resolve(!err),
    );
  });
}

export async function resolverPython(): Promise<string> {
  if (_pythonResuelto) return _pythonResuelto;
  const candidatos = [
    process.env.ORQUESTA_PYTHON,
    path.join(RAIZ, _REL_VENV),
    path.join(RAIZ, _REL_VENV_PLATAFORMA),
    "python3",
  ].filter((c): c is string => !!c);
  for (const candidato of candidatos) {
    if (await importable(candidato)) {
      _pythonResuelto = candidato;
      return candidato;
    }
  }
  // Ninguno sirve: se devuelve "python3" para que el error de import quede
  // en logs/api.log y la consola avise al operador con la acción concreta.
  console.error(
    "[instrumentation] ERROR: ningún intérprete Python con uvicorn+fastapi. " +
      "Ejecuta ./install.sh (crea .venv e instala platform/requirements.txt) " +
      "o exporta ORQUESTA_PYTHON=/ruta/a/python-con-dependencias",
  );
  return "python3";
}

/**
 * Single-flight del bootstrap (v13): cuando el backend cae, TODAS las
 * peticiones que lleguen al proxy intentan relanzarlo. Sin esta guarda,
 * cada petición lanzaba SU uvicorn → carrera de bind ("address already
 * in use" en logs/api.log). Con la promesa compartida, N peticiones
 * concurrentes esperan UN único arranque.
 */
let _bootstrapEnCurso: Promise<{ orquestador: boolean; lab: boolean }> | null = null;

export function arrancarBackend(): Promise<{ orquestador: boolean; lab: boolean }> {
  if (!_bootstrapEnCurso) {
    _bootstrapEnCurso = _arrancarBackendInterno().finally(() => {
      // Libera la guarda al terminar (bien o mal): un fallo permite
      // que la SIGUIENTE petición reintente el bootstrap.
      _bootstrapEnCurso = null;
    });
  }
  return _bootstrapEnCurso;
}

async function _arrancarBackendInterno(): Promise<{ orquestador: boolean; lab: boolean }> {
  const fs = await import(/* turbopackIgnore: true */ "node:fs");
  const { spawn } = await import(/* turbopackIgnore: true */ "node:child_process");
  fs.mkdirSync(path.join(RAIZ, "logs"), { recursive: true });

  const vivo = await saludar(8000).catch(() => false);

  let orquestador = vivo;
  if (!vivo) {
    // Espera REAL a que el uvicorn anterior libere el socket (si venía de
    // un SIGTERM con drain de SSE); evita "address already in use".
    const libre = await puertoLibre(8000);
    if (!libre) {
      console.warn(
        "[instrumentation] puerto 8000 sigue ocupado tras la espera: el error " +
          "de bind quedará en logs/api.log si el ocupante no cede",
      );
    }
    // Puente IA real: GLM vía SDK de la consola en formato OpenAI-compatible.
    const tokenPuente = await asegurarTokenPuente();
    const python = await resolverPython();
    const out = fs.openSync(LOG_ORQUESTADOR, "a");
    spawn(
      python,
      // timeout-graceful-shutdown: sin límite, una conexión SSE abierta
      // mantenía el drain INDEFINIDAMENTE al recibir SIGTERM → proceso
      // zombie solapado con el nuevo. 5 s garantiza relevo limpio.
      ["-m", "uvicorn", "orchestrator.api:app", "--host", "127.0.0.1",
       "--port", "8000", "--timeout-graceful-shutdown", "5"],
      {
        cwd: RAIZ_PLATAFORMA,
        detached: true,
        stdio: ["ignore", out, out],
        env: {
          ...process.env,
          RAIZ_CASOS: `${RAIZ_PLATAFORMA}/casos`,
          RAIZ_SKILLS: `${RAIZ_PLATAFORMA}/skills`,
          CLAVE_CASO: process.env.CLAVE_CASO ?? "clave-onprem-cambiar-en-produccion!",
          API_FRONTERA_BASE: "http://127.0.0.1:3000/api/ia",
          API_FRONTERA_CLAVE: tokenPuente,
          MODELO_FRONTERA: process.env.MODELO_FRONTERA ?? "glm-4.6",
        },
      },
    ).unref();
    // Espera controlada a que responda el healthcheck
    for (let i = 0; i < 20 && !orquestador; i++) {
      await new Promise((r) => setTimeout(r, 500));
      orquestador = await saludar(8000).catch(() => false);
    }
    fs.closeSync(out);
  }

  // Objetivo del lab: solo si nada escucha ya en 8080
  let lab = await labVivo().catch(() => false);
  if (!lab) {
    const out = fs.openSync(LOG_LAB, "a");
    spawn("python3", ["lab/servidor_lab.py", "--puerto", "8080"], {
      cwd: RAIZ_PLATAFORMA,
      detached: true,
      stdio: ["ignore", out, out],
      env: process.env,
    }).unref();
    fs.closeSync(out);
    for (let i = 0; i < 10 && !lab; i++) {
      await new Promise((r) => setTimeout(r, 300));
      lab = await labVivo().catch(() => false);
    }
  }

  console.log(
    `[instrumentation] orquestador: ${orquestador ? "en vivo :8000" : "NO DISPONIBLE"} · ` +
    `lab: ${lab ? "en vivo :8080" : "no disponible"}`,
  );

  // Última línea de resiliencia: si este proceso Next muere, el orquestador
  // Python (sidecar.py) relanza la consola. Si uvicorn muriera también,
  // el proxy reexporta arrancarBackend en la primera petición.
  try {
    const { execFile } = await import(/* turbopackIgnore: true */ "node:child_process");
    execFile(
      "bash",
      [path.join(RAIZ_PLATAFORMA, "..", "scripts", "dev-supervisor.sh")],
      { detached: true, stdio: "ignore" } as import("node:child_process").ExecFileOptionsWithStringEncoding,
    ).unref();
  } catch {
    /* best effort */
  }

  return { orquestador, lab };
}

async function saludar(puerto: number): Promise<boolean> {
  try {
    const r = await fetch(`http://127.0.0.1:${puerto}/api/salud`, {
      signal: AbortSignal.timeout(1500),
    });
    return r.ok;
  } catch {
    return false;
  }
}

/**
 * ¿Está LIBRE el puerto TCP (nadie escucha)? Con techo de espera.
 *
 * Carrera de relevo corregida: tras SIGTERM, el uvicorn anterior puede
 * tardar hasta 5 s en cerrar el socket (graceful shutdown drenando SSE).
 * Si se relanza sin esperar, el nuevo muere con "address already in use"
 * y el healthcheck sondea un proceso muerto hasta agotarse. Ahora se
 * espera (acotado) a que el connect sea rechazado = puerto libre.
 */
async function puertoLibre(puerto: number, techoMs = 8000): Promise<boolean> {
  const net = await import(/* turbopackIgnore: true */ "node:net");
  const inicio = Date.now();
  for (;;) {
    const libre = await new Promise<boolean>((resolve) => {
      const s = net.connect({ port: puerto, host: "127.0.0.1" });
      s.once("connect", () => { s.destroy(); resolve(false); }); // ocupado
      s.once("error", () => resolve(true));                      // libre
    });
    if (libre) return true;
    if (Date.now() - inicio >= techoMs) return false;
    await new Promise((r) => setTimeout(r, 300));
  }
}

async function labVivo(): Promise<boolean> {
  try {
    const r = await fetch("http://127.0.0.1:8080/robots.txt", {
      signal: AbortSignal.timeout(1500),
    });
    return r.ok;
  } catch {
    return false;
  }
}
