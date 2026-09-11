#!/usr/bin/env bash
# ===========================================================================
# OrquestaRT — Parada limpia
#
#   ./stop.sh
#
# Detiene consola (:3000), orquestador (:8000) y lab (:8080) de forma
# selectiva: solo mata los procesos que escuchan en esos puertos.
# ===========================================================================
set -uo pipefail

ambar() { printf "\033[1;33m%s\033[0m\n" "$*"; }
verde() { printf "\033[1;32m%s\033[0m\n" "$*"; }

matar_puerto() {
  local puerto="$1" nombre="$2"
  local pids p i
  pids=$(ss -tlnp 2>/dev/null | grep ":${puerto} " | \
         grep -oE 'pid=[0-9]+' | cut -d= -f2 | sort -u)
  for p in $pids; do kill "$p" 2>/dev/null || true; done
  # Espera ACTIVA hasta que el puerto quede realmente libre (v19): el
  # apagado elegante de uvicorn puede retener la escucha hasta 5 s con
  # SSE viva; "Parada completada" debe significar puerto libre, no
  # "señal enviada". Sin esto, un ./start.sh inmediato sufre una carrera
  # de bind y el healthcheck da un falso "en vivo" contra el moribundo.
  for i in $(seq 1 30); do
    pids=$(ss -tlnp 2>/dev/null | grep ":${puerto} " | \
           grep -oE 'pid=[0-9]+' | cut -d= -f2 | sort -u)
    [ -z "$pids" ] && break
    sleep 0.5
  done
  # Si algo sigue vivo tras 15 s (p. ej. una SSE reteniendo el apagado),
  # relevo forzado para no dejar zombies ni puertos colgados.
  pids=$(ss -tlnp 2>/dev/null | grep ":${puerto} " | \
         grep -oE 'pid=[0-9]+' | cut -d= -f2 | sort -u)
  for p in $pids; do kill -9 "$p" 2>/dev/null || true; done
  sleep 0.3
  verde "  ✓ $nombre detenido (puerto $puerto)"
}

ambar "  Deteniendo OrquestaRT…"
matar_puerto 3000 "Consola"
matar_puerto 8000 "Orquestador"
matar_puerto 8080 "Lab objetivo"
# El guardián de la consola debe morir también (si está activo)
[ -f /tmp/orquestart-consola.lock ] && \
  kill "$(cat /tmp/orquestart-consola.lock 2>/dev/null)" 2>/dev/null && \
  rm -f /tmp/orquestart-consola.lock
verde "  Parada completada."
