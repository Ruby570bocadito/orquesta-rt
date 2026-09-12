"use client";

/**
 * Acceso del operador: puerta de entrada de la consola.
 *
 * Dos modos reales según el estado del despliegue:
 *  - bootstrap: si NO hay operadores dados de alta, crea la cuenta admin
 *    inicial (alta de arranque, una sola vez).
 *  - login: autenticación con scrypt + JWT en el backend.
 *
 * No es marketing: es el control de acceso de una herramienta operativa.
 */

import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import {
  KeyRound, Lock, Radio, ShieldCheck, User, Loader2, Fingerprint,
} from "lucide-react";
import { usarConsola } from "@/lib/store";

/** Estado SSO público del despliegue (sin secretos). */
interface SsoPublico {
  configurado: boolean;
  detalle: string;
}

export function Acceso() {
  const estadoAuth = usarConsola((s) => s.estadoAuth);
  const errorBackend = usarConsola((s) => s.errorBackend);
  const bootstrap = estadoAuth === "sin_operadores";
  const [usuario, setUsuario] = useState("");
  const [contrasena, setContrasena] = useState("");
  const [confirmacion, setConfirmacion] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [aviso, setAviso] = useState<string | null>(null);
  const [procesando, setProcesando] = useState(false);
  const [sso, setSso] = useState<SsoPublico | null>(null);
  const [ssoOcupado, setSsoOcupado] = useState(false);

  // El IdP puede devolver el código aquí ({redirect_uri}/acceso?sso=1&code=…):
  // el canje y la VERIFICACIÓN del id_token ocurren en el backend.
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const code = params.get("code");
    const state = params.get("state");
    if (code && state) {
      window.history.replaceState({}, "/");
      setSsoOcupado(true);
      usarConsola.getState().completarSso(code, state).catch((e: Error) => {
        setError(`SSO: ${e.message}`);
        setSsoOcupado(false);
      });
      return;
    }
    fetch("/api/orchestrator/auth/sso/estado")
      .then((r) => (r.ok ? r.json() : null))
      .then((d) => d && setSso(d))
      .catch(() => undefined);
  }, []);

  const entrarConSso = async () => {
    setError(null);
    setSsoOcupado(true);
    try {
      const r = await fetch("/api/orchestrator/auth/sso/inicio");
      const d = await r.json();
      if (!r.ok || !d.url) {
        setError(`SSO: ${d.detail ?? "no disponible"}`);
        setSsoOcupado(false);
        return;
      }
      window.location.href = d.url as string; // al /authorize del IdP
    } catch (e) {
      setError(`SSO: ${(e as Error).message}`);
      setSsoOcupado(false);
    }
  };

  // Misma regla que el backend (auth.crear_operador): validar AQUÍ evita un
  // 400 evitable y da feedback inmediato sin esperar al servidor.
  const PATRON_USUARIO = /^[A-Za-z0-9._-]{3,32}$/;
  const TRIVIALES = ["password", "contrasena", "contraseña", "12345678", "changeme"];

  const enviar = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setAviso(null);
    const nombre = usuario.trim();
    if (!PATRON_USUARIO.test(nombre)) {
      setError(
        "Usuario: 3-32 caracteres. Letras, números, punto, guion y guion bajo (sin espacios ni tildes).",
      );
      return;
    }
    if (contrasena.length < 8) {
      setError("La contraseña debe tener al menos 8 caracteres");
      return;
    }
    if (TRIVIALES.includes(contrasena.toLowerCase())) {
      setError("Contraseña trivial: elige una credencial real");
      return;
    }
    if (bootstrap && contrasena !== confirmacion) {
      setError("Las contraseñas no coinciden");
      return;
    }
    setProcesando(true);
    try {
      if (bootstrap) {
        await usarConsola.getState().registrarPrimerOperador(nombre, contrasena);
      } else {
        await usarConsola.getState().iniciarSesion(nombre, contrasena);
      }
    } catch (ex) {
      const mensaje = (ex as Error).message;
      if (mensaje.includes("ya existe")) {
        // El alta de arranque SÍ se creó antes (p. ej. el inicio de sesión
        // automático falló por una caída momentánea): la salida correcta NO
        // es repetir el alta (400 garantizado), es iniciar sesión.
        setAviso(
          "La cuenta ya existe. Inicia sesión con las credenciales que registraste.",
        );
        usarConsola.setState({ estadoAuth: "requiere_login" });
      } else {
        setError(mensaje);
      }
    } finally {
      setProcesando(false);
    }
  };

  return (
    <div className="flex min-h-screen items-center justify-center bg-ink px-4">
      <div className="pointer-events-none absolute inset-0 bg-grid opacity-40" aria-hidden />
      <motion.div
        initial={{ opacity: 0, y: 14 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4, ease: "easeOut" }}
        className="relative w-full max-w-sm"
      >
        <div className="mb-6 flex items-center justify-center gap-2.5">
          <span className="flex h-10 w-10 items-center justify-center rounded-xl border border-crimson/40 bg-crimson/10">
            <Radio className="h-5 w-5 text-crimson-bright" aria-hidden />
          </span>
          <span className="text-xl font-semibold tracking-tight text-zinc-100">
            Orquesta<span className="text-crimson-bright">RT</span>
          </span>
        </div>

        <div className="rounded-2xl border border-line bg-panel p-6 shadow-[0_16px_48px_-16px_rgba(0,0,0,0.6)]">
          <div className="mb-5 flex items-center gap-2">
            {bootstrap ? <KeyRound className="h-4 w-4 text-crimson-bright" /> : <Lock className="h-4 w-4 text-crimson-bright" />}
            <div>
              <h1 className="text-[15px] font-semibold text-zinc-100">
                {bootstrap ? "Alta del primer operador" : "Acceso de operador"}
              </h1>
              <p className="mt-0.5 text-xs text-zinc-500">
                {bootstrap
                  ? "El despliegue aún no tiene cuentas. La primera cuenta creada será admin."
                  : "Identifícate para operar el engagement. La sesión queda auditada."}
              </p>
            </div>
          </div>

          <form onSubmit={enviar} className="space-y-3">
            <label className="block">
              <span className="mb-1 block font-mono text-[10px] uppercase tracking-[0.14em] text-zinc-500">
                Operador
              </span>
              <div className="relative">
                <User className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-zinc-600" />
                <input
                  value={usuario}
                  onChange={(e) => setUsuario(e.target.value)}
                  required
                  minLength={3}
                  maxLength={32}
                  pattern="[A-Za-z0-9._\-]{3,32}"
                  autoComplete="username"
                  autoFocus
                  placeholder="p. ej. ana.red"
                  className="w-full rounded-lg border border-line bg-raised py-2 pl-8 pr-3 text-sm text-zinc-200 placeholder:text-zinc-600 focus:border-crimson/50 focus:outline-none"
                />
              </div>
              {bootstrap && (
                <span className="mt-1 block font-mono text-[10px] text-zinc-600">
                  letras, números y . _ - · sin espacios
                </span>
              )}
            </label>

            <label className="block">
              <span className="mb-1 block font-mono text-[10px] uppercase tracking-[0.14em] text-zinc-500">
                Contraseña
              </span>
              <div className="relative">
                <Lock className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-zinc-600" />
                <input
                  type="password"
                  value={contrasena}
                  onChange={(e) => setContrasena(e.target.value)}
                  required
                  minLength={8}
                  autoComplete={bootstrap ? "new-password" : "current-password"}
                  placeholder={bootstrap ? "mínimo 8 caracteres" : "tu contraseña"}
                  className="w-full rounded-lg border border-line bg-raised py-2 pl-8 pr-3 text-sm text-zinc-200 placeholder:text-zinc-600 focus:border-crimson/50 focus:outline-none"
                />
              </div>
            </label>

            {bootstrap && (
              <motion.label
                initial={{ opacity: 0, height: 0 }}
                animate={{ opacity: 1, height: "auto" }}
                className="block"
              >
                <span className="mb-1 block font-mono text-[10px] uppercase tracking-[0.14em] text-zinc-500">
                  Confirmar contraseña
                </span>
                <input
                  type="password"
                  value={confirmacion}
                  onChange={(e) => setConfirmacion(e.target.value)}
                  required
                  minLength={8}
                  autoComplete="new-password"
                  className="w-full rounded-lg border border-line bg-raised py-2 px-3 text-sm text-zinc-200 focus:border-crimson/50 focus:outline-none"
                />
              </motion.label>
            )}

            {aviso && (
              <motion.p
                initial={{ opacity: 0, y: -4 }}
                animate={{ opacity: 1, y: 0 }}
                role="status"
                className="rounded-lg border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-xs text-amber-300"
              >
                {aviso}
              </motion.p>
            )}

            {error && (
              <motion.p
                initial={{ opacity: 0, y: -4 }}
                animate={{ opacity: 1, y: 0 }}
                role="alert"
                className="rounded-lg border border-crimson/30 bg-crimson/10 px-3 py-2 text-xs text-red-300"
              >
                {error}
              </motion.p>
            )}

            <button
              type="submit"
              disabled={procesando || usuario.trim().length < 3 || contrasena.length < 8}
              className="flex h-9 w-full items-center justify-center gap-2 rounded-lg bg-crimson text-sm font-semibold text-white transition-colors hover:bg-crimson-bright disabled:cursor-not-allowed disabled:opacity-40"
            >
              {procesando && <Loader2 className="h-3.5 w-3.5 animate-spin" />}
              {bootstrap ? "Crear cuenta admin y entrar" : "Iniciar sesión"}
            </button>
          </form>

          {/* SSO OIDC: solo si el despliegue lo tiene configurado (estado REAL) */}
          {sso?.configurado ? (
            <>
              <div className="my-3 flex items-center gap-2" role="separator">
                <span className="h-px flex-1 bg-line" />
                <span className="font-mono text-[9px] uppercase tracking-widest text-zinc-600">
                  o identidad federada
                </span>
                <span className="h-px flex-1 bg-line" />
              </div>
              <button
                type="button"
                onClick={entrarConSso}
                disabled={ssoOcupado}
                className="flex h-9 w-full items-center justify-center gap-2 rounded-lg border border-line bg-raised text-sm font-medium text-zinc-200 transition-colors hover:bg-panel disabled:cursor-not-allowed disabled:opacity-40"
              >
                {ssoOcupado
                  ? <Loader2 className="h-3.5 w-3.5 animate-spin" />
                  : <Fingerprint className="h-3.5 w-3.5 text-emerald-400" />}
                Entrar con SSO del equipo
              </button>
            </>
          ) : null}

          {errorBackend && !procesando && (
            <p className="mt-3 border-t border-line pt-3 font-mono text-[10px] leading-relaxed text-amber-400/80">
              orquestador: {errorBackend.slice(0, 90)}
            </p>
          )}
        </div>

        <p className="mt-5 flex items-center justify-center gap-1.5 text-center font-mono text-[10px] text-zinc-600">
          <ShieldCheck className="h-3 w-3 text-crimson-bright/60" />
          uso exclusivo en engagements autorizados con ROE firmado
        </p>
      </motion.div>
    </div>
  );
}
