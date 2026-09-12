"""Guardián de la consola: mantiene el servicio completo en pie.

El orquestador es el proceso más longevo del despliegue; este sidecar lo
usa de ancla: si la consola Next.js (puerto 3000) no responde, relanza su
servidor de desarrollo en un proceso hijo DESACOPLADO. En producción con
docker compose esto no se usa (systemd/compose supervisa), pero garantiza
resiliencia en entornos donde no hay supervisor externo.
"""
from __future__ import annotations

import json
import subprocess
import urllib.request

import os

LOCK = "/tmp/orquestart-consola.lock"
# Raíz PORTABLE: directorio padre de platform/ (donde vive este paquete).
RAIZ = os.environ.get("ORQUESTA_RAIZ") or str(
    __import__("pathlib").Path(__file__).resolve().parents[2])


def _puerto_vivo(puerto: int, ruta: str = "/") -> bool:
    try:
        with urllib.request.urlopen(
            f"http://127.0.0.1:{puerto}{ruta}", timeout=2
        ) as r:
            return 200 <= r.status < 500
    except Exception:
        return False


def asegurar_consola() -> bool:
    """Si la consola no responde, arranca un supervisor desacoplado.

    Devuelve True si la consola está (o acaba de estar) atendida.
    Idempotente: el lockfile evita duplicar supervisores.
    """
    if _puerto_vivo(3000):
        return True
    try:
        import os
        # ¿Hay ya un supervisor anotado y vivo?
        if os.path.exists(LOCK):
            with open(LOCK, encoding="utf-8") as fh:
                pid = int(fh.read().strip() or "0")
            try:
                os.kill(pid, 0)
                return True  # el supervisor existe: se está recuperando
            except OSError:
                os.remove(LOCK)
        script = f"{RAIZ}/scripts/dev-supervisor.sh"
        if not os.path.exists(script):
            return False
        log = open(f"{RAIZ}/logs/dev-restart.log", "ab", 0)
        proc = subprocess.Popen(
            ["bash", script],
            cwd=RAIZ,
            stdout=log,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            start_new_session=True,  # desacoplado del ciclo de vida del padre
        )
        with open(LOCK, "w") as f:
            f.write(str(proc.pid))
        print(json.dumps({"sidecar": "consola", "pid": proc.pid}), flush=True)
        return True
    except Exception as exc:
        print(json.dumps({"sidecar": "consola", "error": str(exc)[:160]}), flush=True)
        return False
