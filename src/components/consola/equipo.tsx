"use client";

/**
 * Vista Equipo: gestión de cuentas de operador y organizaciones (solo admin).
 * Altas reales con scrypt, RBAC con 4 roles, organizaciones multi-tenant
 * (aislamiento de casos), restablecimiento administrativo y baja de cuentas.
 */

import { useEffect, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  Users, UserPlus, KeyRound, Trash2, ShieldCheck, Loader2, DatabaseBackup,
  Building2, Fingerprint,
} from "lucide-react";
import { toast } from "@/hooks/use-toast";
import { Tarjeta, Insignia, TituloSeccion, Vacio } from "@/components/consola/ui";
import { usarConsola, descargarRespaldoCompleto } from "@/lib/store";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader,
  DialogTitle, DialogTrigger,
} from "@/components/ui/dialog";
import {
  AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent,
  AlertDialogDescription, AlertDialogFooter, AlertDialogHeader,
  AlertDialogTitle, AlertDialogTrigger,
} from "@/components/ui/alert-dialog";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import { Insignia as Chip } from "@/components/consola/ui";
import { cn } from "@/lib/utils";

function fecha(v: string | null): string {
  if (!v) return "—";
  try {
    return new Date(v).toLocaleString("es-ES", { dateStyle: "short", timeStyle: "short" });
  } catch {
    return v;
  }
}

export function VistaEquipo() {
  const sesion = usarConsola((s) => s.sesion);
  const operadores = usarConsola((s) => s.operadores);
  const cargar = usarConsola((s) => s.cargarOperadores);
  const crear = usarConsola((s) => s.crearOperadorCuenta);
  const cambiarRol = usarConsola((s) => s.cambiarRolOperador);
  const restablecer = usarConsola((s) => s.restablecerOperador);
  const eliminar = usarConsola((s) => s.eliminarOperadorCuenta);
  const organizaciones = usarConsola((s) => s.organizaciones);
  const cargarOrganizaciones = usarConsola((s) => s.cargarOrganizaciones);
  const crearOrganizacion = usarConsola((s) => s.crearOrganizacion);

  const [dialogoAlta, setDialogoAlta] = useState(false);
  const [nuevoUsuario, setNuevoUsuario] = useState("");
  const [nuevaClave, setNuevaClave] = useState("");
  const [nuevoRol, setNuevoRol] = useState("operador");
  const [nuevoTenant, setNuevoTenant] = useState("predeterminada");
  const [nuevaOrg, setNuevaOrg] = useState({ id: "", nombre: "" });
  const [creandoOrg, setCreandoOrg] = useState(false);
  const [creando, setCreando] = useState(false);
  const [reseteo, setReseteo] = useState<{ usuario: string; clave: string } | null>(null);
  const [ocupado, setOcupado] = useState(false);
  const [respaldando, setRespaldando] = useState(false);

  const esAdmin = sesion?.rol === "admin";

  useEffect(() => {
    if (esAdmin) {
      cargar().catch(() => undefined);
      cargarOrganizaciones().catch(() => undefined);
    }
  }, [esAdmin, cargar, cargarOrganizaciones]);

  if (!esAdmin) {
    return (
      <div className="space-y-4">
        <TituloSeccion titulo="Equipo" descripcion="solo un operador admin puede gestionar las cuentas del despliegue" />
        <Vacio mensaje="Solo un operador admin puede gestionar las cuentas del equipo" />
      </div>
    );
  }

  // Misma regla que el backend (auth.crear_operador): feedback inmediato
  // en el alta de cuentas sin esperar un 400 del servidor.
  const PATRON_USUARIO = /^[A-Za-z0-9._-]{3,32}$/;
  const TRIVIALES = ["password", "contrasena", "contraseña", "12345678", "changeme"];

  const altaOperador = async () => {
    const nombre = nuevoUsuario.trim();
    if (!PATRON_USUARIO.test(nombre)) {
      toast({
        title: "Usuario inválido",
        description:
          "3-32 caracteres: letras, números, punto, guion y guion bajo (sin espacios ni tildes)",
        variant: "destructive",
      });
      return;
    }
    if (nuevaClave.length < 8) {
      toast({
        title: "Datos incompletos",
        description: "La contraseña debe tener al menos 8 caracteres",
        variant: "destructive",
      });
      return;
    }
    if (TRIVIALES.includes(nuevaClave.toLowerCase())) {
      toast({
        title: "Contraseña trivial",
        description: "Elige una credencial real, no una contraseña de ejemplo",
        variant: "destructive",
      });
      return;
    }
    setCreando(true);
    try {
      await crear(nombre, nuevaClave, nuevoRol,
        nuevoTenant === "predeterminada" ? undefined : nuevoTenant);
      toast({ title: "Operador dado de alta", description: `${nombre} · rol ${nuevoRol} · org ${nuevoTenant}` });
      setNuevoUsuario(""); setNuevaClave(""); setNuevoRol("operador");
      setDialogoAlta(false);
    } catch (e) {
      toast({ title: "No se pudo crear la cuenta", description: (e as Error).message, variant: "destructive" });
    } finally {
      setCreando(false);
    }
  };

  const altaOrganizacion = async () => {
    const id = nuevaOrg.id.trim().toLowerCase();
    const nombre = nuevaOrg.nombre.trim();
    if (!/^[a-z0-9][a-z0-9._-]{1,40}$/.test(id)) {
      toast({
        title: "Id inválido",
        description: "2-41 caracteres en minúscula: letras, números, punto, guion y guion bajo",
        variant: "destructive",
      });
      return;
    }
    if (nombre.length < 2) {
      toast({ title: "Falta el nombre", variant: "destructive" });
      return;
    }
    setCreandoOrg(true);
    try {
      await crearOrganizacion(id, nombre);
      toast({ title: "Organización creada", description: `${id} · ${nombre}` });
      setNuevaOrg({ id: "", nombre: "" });
      setNuevoTenant(id);
    } catch (e) {
      toast({ title: "No se pudo crear", description: (e as Error).message, variant: "destructive" });
    } finally {
      setCreandoOrg(false);
    }
  };

  const hacerRespaldoCompleto = async () => {
    setRespaldando(true);
    try {
      const nombre = await descargarRespaldoCompleto();
      toast({
        title: "Respaldo completo generado",
        description: `${nombre} · incluye usuarios + todos los casos con manifiesto SHA-256`,
      });
    } catch (e) {
      toast({
        title: "No se pudo generar el respaldo",
        description: (e as Error).message,
        variant: "destructive",
      });
    } finally {
      setRespaldando(false);
    }
  };

  const hacerRestablecer = async () => {
    if (!reseteo || reseteo.clave.length < 8) return;
    setOcupado(true);
    try {
      await restablecer(reseteo.usuario, reseteo.clave);
      toast({ title: "Credencial restablecida", description: `${reseteo.usuario} deberá usar la nueva contraseña` });
      setReseteo(null);
    } catch (e) {
      toast({ title: "Error al restablecer", description: (e as Error).message, variant: "destructive" });
    } finally {
      setOcupado(false);
    }
  };

  const hacerRol = async (usuario: string, rol: string) => {
    try {
      await cambiarRol(usuario, rol);
      toast({ title: "Rol actualizado", description: `${usuario} → ${rol}` });
    } catch (e) {
      toast({ title: "No se pudo cambiar el rol", description: (e as Error).message, variant: "destructive" });
    }
  };

  const hacerEliminar = async (usuario: string) => {
    try {
      await eliminar(usuario);
      toast({ title: "Cuenta eliminada", description: usuario });
    } catch (e) {
      toast({ title: "No se pudo eliminar", description: (e as Error).message, variant: "destructive" });
    }
  };

  return (
    <div className="space-y-4">
      <TituloSeccion titulo="Equipo" descripcion="cuentas reales · scrypt + JWT · roles admin/gestor/operador/lector · organizaciones multi-tenant" />

      {/* Organizaciones (multi-tenant v21) */}
      <Tarjeta>
        <TituloSeccion
          titulo="Organizaciones (tenants)"
          descripcion="cada caso nace en una organización y solo las cuentas de esa organización (o admin) pueden abrirlo"
        />
        {organizaciones && organizaciones.length > 0 ? (
          <div className="mb-4 flex flex-wrap gap-2">
            {organizaciones.map((o) => (
              <span key={o.id}
                    className="inline-flex items-center gap-1.5 rounded-md border border-line bg-panel px-2.5 py-1.5 text-xs text-zinc-300">
                <Building2 className="h-3.5 w-3.5 text-zinc-500" />
                <span className="font-medium">{o.id}</span>
                <span className="text-zinc-600">· {o.nombre}</span>
                <span className="rounded bg-ink px-1.5 font-mono text-[10px] text-zinc-500">
                  {o.operadores} cuentas
                </span>
              </span>
            ))}
          </div>
        ) : (
          <p className="mb-4 text-xs text-zinc-600">cargando organizaciones…</p>
        )}
        <div className="flex flex-wrap items-end gap-2">
          <div className="space-y-1">
            <label className="text-[11px] text-zinc-500">id (slug minúscula)</label>
            <Input value={nuevaOrg.id}
                   onChange={(e) => setNuevaOrg((o) => ({ ...o, id: e.target.value }))}
                   placeholder="p. ej. cliente-x" className="h-8 w-44 border-line bg-panel text-xs text-zinc-100" />
          </div>
          <div className="space-y-1">
            <label className="text-[11px] text-zinc-500">nombre</label>
            <Input value={nuevaOrg.nombre}
                   onChange={(e) => setNuevaOrg((o) => ({ ...o, nombre: e.target.value }))}
                   placeholder="Cliente X S.L." className="h-8 w-52 border-line bg-panel text-xs text-zinc-100" />
          </div>
          <Button variant="outline" size="sm"
                  className="h-8 border-line text-zinc-200 hover:bg-panel hover:text-zinc-100"
                  onClick={altaOrganizacion} disabled={creandoOrg}>
            {creandoOrg ? <Loader2 className="mr-1.5 h-3.5 w-3.5 animate-spin" />
                         : <Building2 className="mr-1.5 h-3.5 w-3.5" />}
            Crear organización
          </Button>
        </div>
      </Tarjeta>

      <Tarjeta className="p-0">
        <div className="flex items-center justify-between border-b border-line px-4 py-3">
          <div className="flex items-center gap-2 text-sm text-zinc-400">
            <ShieldCheck className="h-4 w-4 text-emerald-400" />
            {operadores?.length ?? "…"} cuentas de operador
          </div>
          <Dialog open={dialogoAlta} onOpenChange={setDialogoAlta}>
            <DialogTrigger asChild>
              <Button size="sm" className="bg-crimson text-white hover:bg-crimson/85">
                <UserPlus className="mr-2 h-4 w-4" /> Alta de operador
              </Button>
            </DialogTrigger>
            <DialogContent className="border-line bg-raised text-zinc-100">
              <DialogHeader>
                <DialogTitle>Nueva cuenta de operador</DialogTitle>
                <DialogDescription className="text-zinc-500">
                  La contraseña se guarda con scrypt (n=2^14). Roles: admin
                  (despliegue), gestor (crea casos), operador (trabaja el
                  caso), lector (solo consulta). La organización aísla sus
                  casos (multi-tenant).
                </DialogDescription>
              </DialogHeader>
              <div className="space-y-3">
                <div className="space-y-1.5">
                  <label className="text-xs text-zinc-500">Usuario</label>
                  <Input value={nuevoUsuario} onChange={(e) => setNuevoUsuario(e.target.value)}
                         placeholder="p. ej. ana.lopez"
                         className="border-line bg-panel text-zinc-100" />
                </div>
                <div className="space-y-1.5">
                  <label className="text-xs text-zinc-500">Contraseña (mín. 8)</label>
                  <Input type="password" value={nuevaClave}
                         onChange={(e) => setNuevaClave(e.target.value)}
                         placeholder="credencial real"
                         className="border-line bg-panel text-zinc-100" />
                </div>
                <div className="space-y-1.5">
                  <label className="text-xs text-zinc-500">Rol</label>
                  <Select value={nuevoRol} onValueChange={setNuevoRol}>
                    <SelectTrigger className="border-line bg-panel text-zinc-100">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent className="border-line bg-raised text-zinc-100">
                      <SelectItem value="operador">operador</SelectItem>
                      <SelectItem value="gestor">gestor</SelectItem>
                      <SelectItem value="lector">lector</SelectItem>
                      <SelectItem value="admin">admin</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-1.5">
                  <label className="text-xs text-zinc-500">Organización</label>
                  <Select value={nuevoTenant} onValueChange={setNuevoTenant}>
                    <SelectTrigger className="border-line bg-panel text-zinc-100">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent className="border-line bg-raised text-zinc-100">
                      {(organizaciones ?? [{ id: "predeterminada", nombre: "", creado_en: "", operadores: 0 }]).map((o) => (
                        <SelectItem key={o.id} value={o.id}>{o.id}</SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
              </div>
              <DialogFooter>
                <Button variant="outline" className="border-line bg-transparent text-zinc-300 hover:bg-panel hover:text-zinc-100"
                        onClick={() => setDialogoAlta(false)}>
                  Cancelar
                </Button>
                <Button className="bg-crimson text-white hover:bg-crimson/85"
                        onClick={altaOperador} disabled={creando}>
                  {creando && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                  Crear cuenta
                </Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>
        </div>

        {operadores && operadores.length > 0 ? (
          <div className="divide-y divide-line">
            <AnimatePresence initial={false}>
              {operadores.map((op, i) => (
                <motion.div
                  key={op.usuario}
                  initial={{ opacity: 0, y: 6 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: i * 0.03 }}
                  className="flex flex-wrap items-center justify-between gap-3 px-4 py-3"
                >
                  <div className="min-w-0 space-y-0.5">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="truncate text-sm font-medium text-zinc-100">{op.usuario}</span>
                      <Chip tono={op.rol === "admin" ? "crimson" : op.rol === "gestor" ? "teal" : op.rol === "lector" ? "ambar" : "slate"}>
                        {op.rol}
                      </Chip>
                      <Chip tono="slate">
                        <Building2 className="mr-1 h-3 w-3" />
                        {op.tenant_id ?? "predeterminada"}
                      </Chip>
                      {op.sso_sub ? (
                        <Chip tono="esmeralda">
                          <Fingerprint className="mr-1 h-3 w-3" />
                          SSO
                        </Chip>
                      ) : null}
                      {op.usuario === sesion?.usuario && (
                        <span className="text-[11px] text-zinc-600">(tú)</span>
                      )}
                    </div>
                    <p className="text-xs text-zinc-600">
                      creado {fecha(op.creado_en)} · último acceso {fecha(op.ultimo_acceso)}
                    </p>
                  </div>
                  <div className="flex flex-wrap items-center gap-2">
                    <Select
                      value={op.rol}
                      onValueChange={(rol) => hacerRol(op.usuario, rol)}
                      disabled={op.usuario === sesion?.usuario}
                    >
                      <SelectTrigger className="h-8 w-[130px] border-line bg-panel text-xs text-zinc-200">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent className="border-line bg-raised text-zinc-100">
                        <SelectItem value="operador">operador</SelectItem>
                        <SelectItem value="gestor">gestor</SelectItem>
                        <SelectItem value="lector">lector</SelectItem>
                        <SelectItem value="admin">admin</SelectItem>
                      </SelectContent>
                    </Select>

                    <Button
                      variant="outline" size="sm"
                      className="h-8 border-line text-zinc-300 hover:bg-panel hover:text-zinc-100"
                      onClick={() => setReseteo({ usuario: op.usuario, clave: "" })}
                    >
                      <KeyRound className="mr-1.5 h-3.5 w-3.5" /> Restablecer
                    </Button>

                    <AlertDialog>
                      <AlertDialogTrigger asChild>
                        <Button
                          variant="outline" size="sm"
                          className="h-8 border-line text-red-300 hover:bg-red-500/10 hover:text-red-200"
                          disabled={op.usuario === sesion?.usuario}
                        >
                          <Trash2 className="h-3.5 w-3.5" />
                        </Button>
                      </AlertDialogTrigger>
                      <AlertDialogContent className="border-line bg-raised text-zinc-100">
                        <AlertDialogHeader>
                          <AlertDialogTitle>Eliminar cuenta {op.usuario}</AlertDialogTitle>
                          <AlertDialogDescription className="text-zinc-400">
                            La cuenta dejará de poder iniciar sesión. Las decisiones
                            ya firmadas conservan su identidad en la auditoría.
                          </AlertDialogDescription>
                        </AlertDialogHeader>
                        <AlertDialogFooter>
                          <AlertDialogCancel className="border-line bg-transparent text-zinc-300 hover:bg-panel hover:text-zinc-100">
                            Cancelar
                          </AlertDialogCancel>
                          <AlertDialogAction
                            className="bg-crimson text-white hover:bg-crimson/85"
                            onClick={() => hacerEliminar(op.usuario)}
                          >
                            Eliminar
                          </AlertDialogAction>
                        </AlertDialogFooter>
                      </AlertDialogContent>
                    </AlertDialog>
                  </div>
                </motion.div>
              ))}
            </AnimatePresence>
          </div>
        ) : (
          <div className="p-4">
            <Vacio mensaje="Sin cuentas cargadas todavía" />
          </div>
        )}
      </Tarjeta>

      <Dialog open={!!reseteo} onOpenChange={(v) => !v && setReseteo(null)}>
        <DialogContent className="border-line bg-raised text-zinc-100">
          <DialogHeader>
            <DialogTitle>Restablecer credencial de {reseteo?.usuario}</DialogTitle>
            <DialogDescription className="text-zinc-500">
              Restablecimiento administrativo: no necesitas la contraseña
              anterior. La cuenta se desbloquea si estaba bloqueada por
              intentos fallidos.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-1.5">
            <label className="text-xs text-zinc-500">Nueva contraseña (mín. 8)</label>
            <Input type="password" value={reseteo?.clave ?? ""}
                   onChange={(e) => setReseteo((r) => (r ? { ...r, clave: e.target.value } : r))}
                   className="border-line bg-panel text-zinc-100" />
          </div>
          <DialogFooter>
            <Button variant="outline" className="border-line bg-transparent text-zinc-300 hover:bg-panel hover:text-zinc-100"
                    onClick={() => setReseteo(null)}>
              Cancelar
            </Button>
            <Button className="bg-crimson text-white hover:bg-crimson/85"
                    onClick={hacerRestablecer} disabled={ocupado || (reseteo?.clave.length ?? 0) < 8}>
              {ocupado && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              Restablecer
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <div className={cn("flex items-start gap-2 rounded-lg border border-line bg-panel/60 p-3 text-xs leading-relaxed text-zinc-500")}>
        <Insignia tono="slate">protección</Insignia>
        <p>
          No puedes cambiar tu propio rol ni eliminar/degradar al último admin
          del despliegue: el backend lo deniega para evitar el bloqueo
          administrativo total.
        </p>
      </div>

      <Tarjeta>
        <TituloSeccion
          titulo="Copia de seguridad completa"
          descripcion="Snapshot consistente de TODAS las bases del sistema (usuarios + casos) con manifiesto SHA-256"
        />
        <div className="flex flex-wrap items-center gap-3">
          <Button
            variant="outline"
            className="border-line text-zinc-200 hover:bg-panel hover:text-zinc-100"
            onClick={hacerRespaldoCompleto}
            disabled={respaldando}
          >
            {respaldando
              ? <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              : <DatabaseBackup className="mr-2 h-4 w-4" />}
            Descargar respaldo completo (ZIP)
          </Button>
          <p className="min-w-0 flex-1 text-xs leading-relaxed text-zinc-500">
            Generado con <code className="text-zinc-400">VACUUM INTO</code> de SQLite:
            copia consistente en caliente aunque haya escritores activos. Verifica el
            SHA-256 del manifiesto antes de restaurar. Automatizable con cron vía
            <code className="ml-1 text-zinc-400">python -m orchestrator.cli respaldo-completo</code>.
          </p>
        </div>
      </Tarjeta>
    </div>
  );
}
