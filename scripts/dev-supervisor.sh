#!/bin/bash
# ===========================================================================
# OrquestaRT — Guardián de la consola Next.js (idempotente vía lockfile).
#
# Si el puerto 3000 responde, duerme; si no, relanza el servidor.
#
# MODO_CONSOLA=prod   → sirve el build de producción standalone
#                       (.next/standalone/server.js, generado por
#                       `bun run build`). Si no hay build, lo genera UNA
#                       vez antes de servir. Sin la variable, sirve dev.
#
# Higiene del log (v13): dev-restart.log se ROTACIÓN automática — si pasa
# del tope (20 MB) se conserva solo el último 1 MB. Antes crecía sin
# límite (59 MB en una sesión de 40 min) porque `next dev` registra cada
# petición HTTP.
# ===========================================================================
LOCK=/tmp/orquestart-consola.lock
RAIZ="${ORQUESTA_RAIZ:-$(pwd)}"
LOG="$RAIZ/logs/dev-restart.log"
TOPE_BYTES=$((20 * 1024 * 1024))   # 20 MB → rota
CONSERVAR_BYTES=$((1 * 1024 * 1024)) # conserva el último 1 MB
cd "$RAIZ"
mkdir -p "$RAIZ/logs"

rotar_log() {
  local tam=0
  tam=$(stat -c%s "$LOG" 2>/dev/null || echo 0)
  if [ "$tam" -gt "$TOPE_BYTES" ]; then
    tail -c "$CONSERVAR_BYTES" "$LOG" > "$LOG.tmp" 2>/dev/null && mv "$LOG.tmp" "$LOG"
    echo "[guardián] $(date '+%F %T') log rotado (${tam} B → ${CONSERVAR_BYTES} B)" >> "$LOG"
  fi
}

# --- lockfile: solo un guardián vivo --------------------------------------
# Cuidado: kill -0 prospera también sobre un proceso <defunct> (zombie,
# p. ej. el guardián de un ciclo start.sh que murió a medias). Un zombie
# NO está vivo: se consulta el estado real en /proc antes de decidir.
if [ -f "$LOCK" ]; then
  PID=$(cat "$LOCK" 2>/dev/null)
  if [ -n "$PID" ] && kill -0 "$PID" 2>/dev/null; then
    ESTADO=$(ps -o stat= -p "$PID" 2>/dev/null | head -c 1)
    if [ "$ESTADO" != "Z" ]; then
      exit 0  # guardián realmente vivo
    fi
  fi
fi
echo $$ > "$LOCK"

# --- comando de arranque según modo ---------------------------------------
ARRANQUE=(bun run dev)
if [ "${MODO_CONSOLA:-dev}" = "prod" ]; then
  if [ -f .next/standalone/server.js ]; then
    ARRANQUE=(bun run start)
  else
    echo "[guardián] $(date '+%F %T') MODO_CONSOLA=prod sin build: generando (una vez, puede tardar)" >> "$LOG"
    if bun run build >> "$LOG" 2>&1; then
      ARRANQUE=(bun run start)
      echo "[guardián] $(date '+%F %T') build de producción listo" >> "$LOG"
    else
      echo "[guardián] $(date '+%F %T') build FALLÓ: fallback a modo dev" >> "$LOG"
    fi
  fi
fi

while true; do
  rotar_log
  if curl -s -m 3 -o /dev/null http://127.0.0.1:3000/; then
    sleep 5
    continue
  fi
  echo "[guardián] $(date '+%F %T') 3000 caído, arrancando ${ARRANQUE[*]}" >> "$LOG"
  "${ARRANQUE[@]}" >> "$LOG" 2>&1
  echo "[guardián] $(date '+%F %T') servidor murió (código $?)" >> "$LOG"
  sleep 2
done
