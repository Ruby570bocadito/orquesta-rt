#!/usr/bin/env python3
"""Empaqueta el proyecto en un ZIP distribuible (sin secretos ni artefactos).

Incluye: código del backend (platform/), consola (src/), scripts de
verificación, configuración de despliegue y documentación.
Excluye: secretos (.env, db/puente-ia.token), datos de runtime (casos/,
usuarios.db), node_modules, .next, .git, logs y cachés.
"""
from __future__ import annotations

import fnmatch
import os
import zipfile
from pathlib import Path

RAIZ = Path("/home/z/my-project")
DESTINO = RAIZ / "download" / "orquesta-rt-plataforma-v23.zip"

# --- Incluidos de nivel raíz -------------------------------------------------
RAIZ_FICHEROS = [
    "README.md", "LICENSE", "Caddyfile", "Dockerfile.console",
    "docker-compose.yml", "package.json", "bun.lock", "tsconfig.json",
    "next.config.ts", "tailwind.config.ts", "postcss.config.mjs",
    "components.json", "eslint.config.mjs", "next-env.d.ts", ".gitignore",
    # Instalación/operación en un paso (v10)
    "install.sh", "start.sh", "stop.sh",
]
CARPETAS = ["src", "public", "scripts", "docs", "deploy", ".devcontainer"]

# --- lab/ con lista blanca (v22): scripts de laboratorio REALES -------------
# Solo el código que el operador necesita para montar SU laboratorio. Los
# binarios descargados (keycloak-*/, neo4j-community-*/), credenciales
# (keycloak-admin.txt, neo4j-admin.txt), pids, logs, downloads y el
# env_laboratorio.sh REAL (con secretos del propio despliegue) NO se
# empaquetan jamás — para eso está la plantilla env_laboratorio.ejemplo.sh.
LAB_INCLUIDOS = [
    "lab/coleccion.cypher",
    "lab/coleccion_dominio.py",
    "lab/env_laboratorio.ejemplo.sh",
    "lab/keycloak_arrancar.sh",
    "lab/provisionar_keycloak.sh",
    "lab/neo4j_arrancar.sh",
]

# --- Ficheros huérfanos de nivel raíz que NO deben volver a empaquetarse ---
RAIZ_EXCLUIDOS = ["examples", "tests", "prisma", "dev.log", "server.log"]

# --- platform/ con exclusiones ----------------------------------------------
PLATAFORMA_EXCLUIDAS = [
    "__pycache__", ".pytest_cache", "casos", "casos/*", "*.db", "*.db-shm",
    "*.db-wal", "usuarios.db", "*.pyc", ".venv", "*.bak*",
]

def excluido(rel: str, patrones: list[str]) -> bool:
    partes = Path(rel).parts
    for patron in patrones:
        if fnmatch.fnmatch(rel, patron):
            return True
        for p in partes:
            if fnmatch.fnmatch(p, patron):
                return True
    return False


def main() -> None:
    DESTINO.parent.mkdir(parents=True, exist_ok=True)
    if DESTINO.exists():
        DESTINO.unlink()

    total, omitidos = [], []
    with zipfile.ZipFile(DESTINO, "w", compression=zipfile.ZIP_DEFLATED) as z:
        def anadir(ruta: Path, rel: str) -> None:
            if excluido(rel, PLATAFORMA_EXCLUIDAS):
                omitidos.append(rel)
                return
            if ruta.is_file():
                z.write(ruta, f"orquesta-rt/{rel}")
                total.append(rel)

        for nombre in RAIZ_FICHEROS:
            ruta = RAIZ / nombre
            if ruta.is_file():
                z.write(ruta, f"orquesta-rt/{nombre}")
                total.append(nombre)
            else:
                omitidos.append(f"{nombre} (no existe)")

        for carpeta in CARPETAS:
            for ruta in sorted((RAIZ / carpeta).rglob("*")):
                if ruta.is_dir():
                    continue
                rel = str(ruta.relative_to(RAIZ))
                if "/node_modules/" in f"/{rel}/" or "__pycache__" in partes_de(rel):
                    omitidos.append(rel)
                    continue
                anadir(ruta, rel)

        # lab/ en lista blanca (v22): scripts de laboratorio, sin secretos
        for nombre in LAB_INCLUIDOS:
            ruta = RAIZ / nombre
            if ruta.is_file():
                z.write(ruta, f"orquesta-rt/{nombre}")
                total.append(nombre)
            else:
                omitidos.append(f"{nombre} (no existe)")

        # platform/ completo menos runtime/cachés
        for ruta in sorted((RAIZ / "platform").rglob("*")):
            if ruta.is_dir():
                continue
            rel = str(ruta.relative_to(RAIZ))
            if "__pycache__" in partes_de(rel) or "/.pytest_cache/" in f"/{rel}/":
                omitidos.append(rel)
                continue
            anadir(ruta, rel)

    tam = DESTINO.stat().st_size
    print(f"ZIP: {DESTINO}")
    print(f"  {len(total)} ficheros · {tam / 1024:.0f} KB")
    print(f"  {len(omitidos)} omitidos (runtime/cachés)")
    # Verificación anti-secretos REAL (v13): en lugar de adivinar por
    # substrings (falsos positivos con rutas y CSS), se comprueba que el
    # VALOR del token del puente y claves con forma de API key NO aparecen
    # en ningún fichero del paquete. Los nombres de ruta (db/puente-ia.token)
    # no son secretos: el secreto es el contenido del fichero, que nunca
    # se incluye.
    import re
    valor_token = ""
    try:
        valor_token = (RAIZ / "db" / "puente-ia.token").read_text().strip()
    except OSError:
        pass
    patrones_clave = re.compile(r"(?:hf_sk-|sk-|sk_|Bearer )[A-Za-z0-9_-]{20,}")
    sospechosos = []
    with zipfile.ZipFile(DESTINO) as z:
        for nombre in z.namelist():
            # El propio escáner contiene los patrones que busca: no se
            # auto-audit a sí mismo (auto-referencia, no secreto).
            if nombre.endswith("scripts/empaquetar.py"):
                continue
            if nombre.endswith((".ts", ".py", ".sh", ".yml", ".yaml", ".json",
                                ".md", ".toml", ".example", ".css", ".html")):
                try:
                    contenido = z.read(nombre).decode("utf-8", errors="ignore")
                except Exception:
                    continue
                if valor_token and valor_token in contenido:
                    sospechosos.append((nombre, "VALOR del token del puente"))
                if patrones_clave.search(contenido):
                    sospechosos.append((nombre, "clave con forma de API key"))
                if "MI_CLAVE_REAL=" in contenido:
                    sospechosos.append((nombre, "placeholder de clave relleno"))
    print("  anti-secretos:", "LIMPIO" if not sospechosos else f"REVISAR {sospechosos}")


def partes_de(rel: str) -> list[str]:
    return list(Path(rel).parts)


if __name__ == "__main__":
    main()
