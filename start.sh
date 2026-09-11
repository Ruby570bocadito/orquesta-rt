#!/usr/bin/env bash
# ===========================================================================
# OrquestaRT — Arranque en un paso
#
#   ./start.sh
#
# Levanta, en este orden:
#   1. Orquestador (FastAPI/uvicorn) en http://127.0.0.1:8000
#      - Usa el intérprete de .venv (creado por install.sh) con las
#        variables de entorno que la plataforma espera:
#        RAIZ_CASOS, RAIZ_SKILLS, CLAVE_CASO y el puente IA (GLM vía la
#        consola, token compartido en db/puente-ia.token).
#   2. Laboratorio objetivo (HTTP real) en http://127.0.0.1:8080
#   3. Consola de operador (Next.js) en http://localhost:3000
#
# Si algo ya está escuchando en su puerto, NO lo toca.
# Log de cada proceso: logs/api.log, logs/lab.log, logs/consola.log
# ===========================================================================
set -euo pipefail

RAIZ="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$RAIZ"

# Entorno opcional del despliegue (v22): lab/env_laboratorio.sh permite
# sobreescribir variables (OIDC_*, BLOODHOUND_*, NEO4J_*, MISP_*) sin tocar
# este script. Si no existe, nada cambia.
if [ -f "$RAIZ/lab/env_laboratorio.sh" ]; then
  # shellcheck disable=SC1091
  set -a; . "$RAIZ/lab/env_laboratorio.sh"; set +a
fi


verde() { printf "\033[1;32m%s\033[0m\n" "$*"; }
ambar() { printf "\033[1;33m%s\033[0m\n" "$*"; }
rojo()  { printf "\033[1;31m%s\033[0m\n" "$*"; }

vivo() { curl -s --connect-timeout 1 -m 1 -o /dev/null "$1"; }

# Higiene de logs (v13): los logs crecen con cada petición; si alguno pasa
# de 20 MB al arrancar, se conserva solo el último 1 MB. El guardián de la
# consola rota el suyo en caliente; aquí se rotan api.log y lab.log.
rotar_log() {
  local fichero="$1" tam=0
  tam=$(stat -c%s "$fichero" 2>/dev/null || echo 0)
  if [ "$tam" -gt $((20 * 1024 * 1024)) ]; then
    tail -c $((1 * 1024 * 1024)) "$fichero" > "$fichero.tmp" 2>/dev/null \
      && mv "$fichero.tmp" "$fichero"
    verde "  ✓ Log rotado: $(basename "$fichero") (${tam} B → 1 MB)"
  fi
}

espera() { # espera URL NOMBRE INTENTOS
  local i=0
  while [ "$i" -lt "$3" ]; do
    if vivo "$1"; then return 0; fi
    i=$((i + 1))
    sleep 0.5
  done
  return 1
}

# ---------------------------------------------------------------------------
# 0. ¿Instalado?
# ---------------------------------------------------------------------------
if [ ! -x ".venv/bin/python3" ]; then
  ambar "  No hay .venv: ejecutando ./install.sh primero…"
  ./install.sh
fi

mkdir -p logs db
rotar_log "$RAIZ/logs/api.log"
rotar_log "$RAIZ/logs/lab.log"
rotar_log "$RAIZ/logs/consola.log"

# ---------------------------------------------------------------------------
# 1. Puente IA: token compartido consola↔orquestador (se genera una vez)
# ---------------------------------------------------------------------------
if [ ! -s "db/puente-ia.token" ]; then
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 32 > db/puente-ia.token
  else
    ./.venv/bin/python3 -c "import secrets; print(secrets.token_hex(32))" > db/puente-ia.token
  fi
  chmod 600 db/puente-ia.token
fi
TOKEN_PUENTE="$(cat db/puente-ia.token)"

# ---------------------------------------------------------------------------
# 2. Orquestador (:8000)
# ---------------------------------------------------------------------------
export ORQUESTA_PYTHON="$RAIZ/.venv/bin/python3"
export ORQUESTA_RAIZ="$RAIZ"

if vivo http://127.0.0.1:8000/api/salud; then
  verde "  ✓ Orquestador ya en vivo  http://127.0.0.1:8000"
else
  ambar "  … Arrancando orquestador (uvicorn :8000)"
  # Guardia anti-carrera (v19): un proceso anterior aún APAGÁNDOSE puede
  # contestar /salud unos segundos y provocaría "address already in use"
  # seguido de un falso "en vivo". Se espera a que el puerto libere de
  # verdad antes de lanzar el nuevo intérprete.
  for i in $(seq 1 20); do
    vivo http://127.0.0.1:8000/api/salud || break
    sleep 0.5
  done
  if vivo http://127.0.0.1:8000/api/salud; then
    rojo "  ✗ El puerto 8000 sigue ocupado tras 10 s — ejecuta ./stop.sh"
    exit 1
  fi
  ( cd platform && env \
      RAIZ_CASOS="$RAIZ/platform/casos" \
      RAIZ_SKILLS="$RAIZ/platform/skills" \
      CLAVE_CASO="${CLAVE_CASO:-clave-onprem-cambiar-en-produccion!}" \
      API_FRONTERA_BASE="http://127.0.0.1:3000/api/ia" \
      API_FRONTERA_CLAVE="$TOKEN_PUENTE" \
      MODELO_FRONTERA="${MODELO_FRONTERA:-glm-4.6}" \
      "$RAIZ/.venv/bin/python3" -m uvicorn orchestrator.api:app \
        --host 127.0.0.1 --port 8000 --timeout-graceful-shutdown 5 \
        >> "$RAIZ/logs/api.log" 2>&1 & echo $! > "$RAIZ/logs/api.pid" )
  if espera http://127.0.0.1:8000/api/salud "orquestador" 40; then
    # Verificación de identidad (v19): /salud debe responder NUESTRO
    # proceso, no un moribundo que aún escucha.
    if ! kill -0 "$(cat "$RAIZ/logs/api.pid" 2>/dev/null)" 2>/dev/null; then
      rojo "  ✗ El proceso del orquestador murió al arrancar — mira logs/api.log"
      tail -5 logs/api.log 2>/dev/null || true
      exit 1
    fi
    verde "  ✓ Orquestador en vivo     http://127.0.0.1:8000"
  else
    rojo "  ✗ El orquestador no respondió — mira logs/api.log"
    tail -5 logs/api.log 2>/dev/null || true
    exit 1
  fi
fi

# ---------------------------------------------------------------------------
# 3. Laboratorio objetivo (:8080) — solo si nada escucha ya
# ---------------------------------------------------------------------------
if vivo http://127.0.0.1:8080/robots.txt; then
  verde "  ✓ Lab objetivo ya en vivo http://127.0.0.1:8080"
else
  ambar "  … Arrancando laboratorio objetivo (:8080, solo localhost)"
  ( cd platform && "$RAIZ/.venv/bin/python3" lab/servidor_lab.py \
      --puerto 8080 >> "$RAIZ/logs/lab.log" 2>&1 & )
  if espera http://127.0.0.1:8080/robots.txt "lab" 20; then
    verde "  ✓ Lab objetivo en vivo    http://127.0.0.1:8080"
  else
    ambar "  · Lab no disponible (opcional para operar) — mira logs/lab.log"
  fi
fi

# ---------------------------------------------------------------------------
# 4. Consola (:3000)
#    Modo: ./start.sh        → dev   (recarga en caliente, para operar/desarrollar)
#          ./start.sh prod   → producción (build standalone servido por Node)
#    El guardián (scripts/dev-supervisor.sh) mantiene vivo el servidor y
#    rota su log; instrumentation.ts también lo invoca — el lockfile evita
#    duplicados.
# ---------------------------------------------------------------------------
MODO_CONSOLA_EFECTIVO="${MODO_CONSOLA:-dev}"
case "${1:-}" in prod|dev) MODO_CONSOLA_EFECTIVO="$1" ;; esac
export MODO_CONSOLA="$MODO_CONSOLA_EFECTIVO"

if vivo http://127.0.0.1:3000/; then
  verde "  ✓ Consola ya en vivo      http://localhost:3000"
else
  ambar "  … Arrancando consola Next.js (:3000, modo $MODO_CONSOLA) vía guardián"
  # Lanzar el guardián ANTES de esperar (v19): él es quien arranca la
  # consola; si llegara a morir, sin este orden start.sh esperaría a
  # nadie y abortaría sin haber dejado guardián vivo.
  ( ORQUESTA_RAIZ="$RAIZ" MODO_CONSOLA="$MODO_CONSOLA" nohup bash scripts/dev-supervisor.sh >/dev/null 2>&1 & )
  if espera http://127.0.0.1:3000/ "consola" 240; then
    verde "  ✓ Consola en vivo         http://localhost:3000"
  else
    rojo "  ✗ La consola no respondió — mira logs/dev-restart.log"
    tail -5 logs/dev-restart.log 2>/dev/null || true
    exit 1
  fi
fi
# El guardián se asegura SIEMPRE (idempotente por lockfile): cubre el caso
# de consola ya viva cuyo guardián murió con ella en un ciclo anterior.
# Doble desacoplamiento (subshell + nohup + &): el patrón único `nohup &`
# queda huérfano y muere con el shell que lanzó start.sh.
( ORQUESTA_RAIZ="$RAIZ" nohup bash scripts/dev-supervisor.sh >/dev/null 2>&1 & )

echo ""
verde "  ══════════════════════════════════════════════"
verde "   OrquestaRT operativa"
verde "  ══════════════════════════════════════════════"
echo ""
echo "   Consola del operador :  http://localhost:3000"
echo "   API del orquestador  :  http://127.0.0.1:8000/api/salud"
echo "   Modo de la consola   :  $MODO_CONSOLA (reinicia con ./start.sh prod o ./start.sh dev)"
echo ""
echo "   Primera vez: la consola te pedirá crear la cuenta admin"
echo "   (3-32 caracteres: letras, números y . _ - · contraseña de 8+)."
echo ""
echo "   Detener todo:  ./stop.sh"
echo ""
