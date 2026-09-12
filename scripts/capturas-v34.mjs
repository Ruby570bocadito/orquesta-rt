/**
 * Capturas reales v34 (z1, sesión 06) — consola real + backend real.
 * Higiene con sesiones activas + Equipo con acceso federado administrable.
 *
 * Uso: node scripts/capturas-v34.mjs
 */
import { chromium } from "playwright";
import { mkdirSync } from "fs";

const BASE = "http://localhost:3000";
const SALIDA = "docs/demo";
mkdirSync(SALIDA, { recursive: true });

const UA_DESKTOP =
  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36";

async function entrar(pagina) {
  await pagina.goto(BASE, { waitUntil: "networkidle" });
  await pagina.locator("input[autocomplete=username]").fill("demo.v34");
  await pagina.locator("input[type=password]").first().fill("DemoV34segura!");
  await pagina.getByRole("button", { name: /Iniciar sesión/i }).first().click();
  await pagina.waitForLoadState("networkidle");
  await pagina.waitForTimeout(1500);
}

const navegador = await chromium.launch();
try {
  // ---- sesión de trabajo (escritorio) ------------------------------------
  const ctxEscritorio = await navegador.newContext({
    viewport: { width: 1280, height: 800 },
    userAgent: UA_DESKTOP,
  });
  const escritorio = await ctxEscritorio.newPage();
  await entrar(escritorio);

  // ---- segunda sesión (Android emulado): da 2 filas en "Sesiones activas"
  const ctxMovil = await navegador.newContext({
    viewport: { width: 390, height: 844 },
    isMobile: true, hasTouch: true,
    userAgent: "Mozilla/5.0 (Linux; Android 15; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36",
  });
  const movil = await ctxMovil.newPage();
  await entrar(movil);

  // ---- 1) Higiene con la tarjeta de sesiones activas (escritorio) --------
  await escritorio.getByRole("button", { name: /sesión|higiene|cuenta/i }).first().click();
  await escritorio.waitForTimeout(1500);
  const dialogo = escritorio.getByRole("dialog").first();
  await dialogo.waitFor({ state: "visible", timeout: 8000 });
  await escritorio.waitForTimeout(1500); // deja llegar la lista de sesiones
  await dialogo.screenshot({ path: `${SALIDA}/v34-01-higiene-sesiones.png` });
  console.log("ok v34-01-higiene-sesiones.png");

  await escritorio.keyboard.press("Escape");
  await escritorio.waitForTimeout(400);

  // ---- 2) Equipo: filas con botón SSO / Federado --------------------------
  await escritorio.getByRole("button", { name: /^Equipo$/i }).or(
    escritorio.locator("text=Equipo").first()).first().click();
  await escritorio.waitForTimeout(1500);
  await escritorio.screenshot({ path: `${SALIDA}/v34-02-equipo-sso.png` });
  console.log("ok v34-02-equipo-sso.png");

  // ---- 3) Diálogo del enlace federado sobre la cuenta vinculada ----------
  await escritorio.getByRole("button", { name: /Federado/i }).first().click();
  await escritorio.waitForTimeout(900);
  const dialogoSso = escritorio.getByRole("dialog").first();
  await dialogoSso.waitFor({ state: "visible", timeout: 8000 });
  await escritorio.screenshot({ path: `${SALIDA}/v34-03-dialogo-federado.png` });
  console.log("ok v34-03-dialogo-federado.png");

  await navegador.close();
  console.log("CAPTURAS COMPLETAS");
} catch (e) {
  console.error("FALLO:", e.message);
  await navegador.close();
  process.exit(1);
}
