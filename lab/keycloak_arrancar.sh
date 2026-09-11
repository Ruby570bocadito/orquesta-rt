#!/usr/bin/env bash
# Arranca un Keycloak REAL (distribución oficial 26.3.5) como IdP de laboratorio
# en :8081, con heap tuneado para entornos pequeños. Idempotente.
set -u
RAIZ="$(cd "$(dirname "$0")/.." && pwd)"
KC_DIR="$RAIZ/lab/keycloak-26.3.5"
PUERTO="${KEYCLOAK_PUERTO:-8081}"
ADMIN_PASS_FILE="$RAIZ/lab/keycloak-admin.txt"

mkdir -p "$RAIZ/lab/logs"
if [ ! -d "$KC_DIR" ]; then
  echo "ERROR: extraiga la distribución oficial en $KC_DIR (lab/downloads/keycloak.zip)" >&2
  exit 1
fi

# ¿Ya está vivo?
if curl -s -o /dev/null --connect-timeout 1 -m 2 "http://localhost:$PUERTO/health"; then
  echo "Keycloak ya está en marcha en :$PUERTO"
  exit 0
fi

if [ -f "$ADMIN_PASS_FILE" ]; then
  ADMIN_PASS="$(cat "$ADMIN_PASS_FILE")"
else
  ADMIN_PASS="$(head -c 24 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9' | head -c 20)"
  printf '%s' "$ADMIN_PASS" > "$ADMIN_PASS_FILE"
  chmod 600 "$ADMIN_PASS_FILE"
fi

export KC_BOOTSTRAP_ADMIN_USERNAME="admin"
export KC_BOOTSTRAP_ADMIN_PASSWORD="$ADMIN_PASS"
export JAVA_OPTS_APPEND="-Xms128m -Xmx512m -XX:MaxMetaspaceSize=256m"

nohup "$KC_DIR/bin/kc.sh" start-dev \
  --http-port="$PUERTO" \
  --hostname-strict=false \
  --health-enabled=true \
  > "$RAIZ/lab/logs/keycloak.log" 2>&1 &

echo $! > "$RAIZ/lab/keycloak.pid"
# Espera de vida real (hasta 90 s en arranque frío)
for i in $(seq 1 90); do
  if curl -s -o /dev/null --connect-timeout 1 -m 2 "http://localhost:$PUERTO/health"; then
    echo "Keycloak vivo en :$PUERTO (admin pass en lab/keycloak-admin.txt)"
    exit 0
  fi
  sleep 1
done
echo "ERROR: Keycloak no respondió en 90 s; revise lab/logs/keycloak.log" >&2
exit 1
