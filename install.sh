#!/usr/bin/env bash
# ===========================================================================
# OrquestaRT — Instalación en un paso
#
#   ./install.sh
#
# Qué hace (idempotente: puedes ejecutarlo las veces que haga falta):
#   1. Comprueba prerrequisitos (python3, node/bun, curl).
#   2. Crea el entorno virtual .venv con las dependencias del orquestador
#      (platform/requirements.txt). Esto garantiza que el backend SIEMPRE
#      arranque, aunque el python del sistema no tenga nada instalado.
#   3. Instala las dependencias de la consola (bun install o npm install).
#   4. Crea los directorios de trabajo (logs/, db/, platform/casos).
#   5. Verifica que TODO es importable/ejecutable antes de darte el alta.
#
# Después de instalar:  ./start.sh   (levanta backend + consola)
# ===========================================================================
set -euo pipefail

RAIZ="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$RAIZ"

verde()  { printf "\033[1;32m%s\033[0m\n" "$*"; }
rojo()   { printf "\033[1;31m%s\033[0m\n" "$*"; }
ambar()  { printf "\033[1;33m%s\033[0m\n" "$*"; }

echo ""
echo "  ╔══════════════════════════════════════════════╗"
echo "  ║   OrquestaRT · instalación de la plataforma   ║"
echo "  ╚══════════════════════════════════════════════╝"
echo ""

# ---------------------------------------------------------------------------
# 1. Prerrequisitos
# ---------------------------------------------------------------------------
FALTAN=0
command -v python3 >/dev/null 2>&1 || { rojo "  ✗ Falta python3 (>= 3.11)"; FALTAN=1; }
command -v curl     >/dev/null 2>&1 || { rojo "  ✗ Falta curl"; FALTAN=1; }
if ! command -v bun >/dev/null 2>&1 && ! command -v npm >/dev/null 2>&1; then
  rojo "  ✗ Falta bun o node+npm (para la consola)"
  FALTAN=1
fi
[ "$FALTAN" = "1" ] && { echo ""; rojo "  Instala lo que falta y vuelve a ejecutar ./install.sh"; exit 1; }
verde "  ✓ Prerrequisitos presentes"

# ---------------------------------------------------------------------------
# 2. Entorno virtual del orquestador (backend Python)
# ---------------------------------------------------------------------------
if [ ! -x ".venv/bin/python3" ]; then
  ambar "  … Creando entorno virtual .venv (una sola vez)"
  python3 -m venv .venv
else
  verde "  ✓ .venv ya existe"
fi

ambar "  … Instalando dependencias del orquestador (puede tardar 1-2 min la primera vez)"
if ./.venv/bin/python3 -m pip install --quiet --upgrade pip >/dev/null 2>&1; then
  verde "  ✓ pip actualizado"
fi
if ./.venv/bin/python3 -m pip install --quiet -r platform/requirements.txt pytest; then
  verde "  ✓ Dependencias del orquestador instaladas (+ pytest para la suite)"
else
  rojo "  ✗ Error instalando platform/requirements.txt"
  exit 1
fi

# ---------------------------------------------------------------------------
# 3. Dependencias de la consola
# ---------------------------------------------------------------------------
if command -v bun >/dev/null 2>&1; then
  if [ -d node_modules ]; then verde "  ✓ node_modules ya existe"; else
    ambar "  … Instalando dependencias de la consola (bun)"
    bun install && verde "  ✓ Consola: dependencias instaladas"
  fi
else
  if [ -d node_modules ]; then verde "  ✓ node_modules ya existe"; else
    ambar "  … Instalando dependencias de la consola (npm)"
    npm install && verde "  ✓ Consola: dependencias instaladas"
  fi
fi

# ---------------------------------------------------------------------------
# 4. Directorios de trabajo
# ---------------------------------------------------------------------------
mkdir -p logs db platform/casos
verde "  ✓ Directorios de trabajo listos (logs/, db/, platform/casos/)"

# ---------------------------------------------------------------------------
# 5. Verificación final REAL (nada de "suponemos que funciona")
# ---------------------------------------------------------------------------
ambar "  … Verificando que el orquestador es importable"
if ./.venv/bin/python3 -c "import uvicorn, fastapi, cryptography, httpx, msgpack" 2>/dev/null; then
  verde "  ✓ Orquestador: uvicorn, fastapi, cryptography, httpx, msgpack OK"
else
  rojo "  ✗ Alguna dependencia del orquestador no se pudo importar"
  exit 1
fi

echo ""
verde "  ══════════════════════════════════════════════"
verde "   Instalación completada"
verde "  ══════════════════════════════════════════════"
echo ""
echo "   Siguiente paso:"
echo ""
echo "     ./start.sh          → arranca orquestador (:8000) y consola (:3000)"
echo ""
echo "   Luego abre  http://localhost:3000  — la primera pantalla te pedirá"
echo "   crear la cuenta admin del despliegue (alta de arranque, una sola vez)."
echo ""
echo "   Otros comandos:"
echo "     ./stop.sh           → detiene backend y consola"
echo "     docker compose up   → alternativa en contenedores"
echo ""
