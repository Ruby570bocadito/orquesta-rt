#!/usr/bin/env bash
# ===========================================================================
# OrquestaRT — Arranque del motor de rutas de laboratorio (Neo4j REAL)
#
#   ./lab/neo4j_arrancar.sh
#
# Arranca la distribución oficial de Neo4j Community 5.x en
#   http://localhost:7474  (HTTP — API transaccional que usa la plataforma)
#   bolt://localhost:7687  (Bolt)
# con la colección de dominio de laboratorio cargable mediante
#   python3 lab/coleccion_dominio.py
#
# Idempotente: si ya está vivo, no toca nada.
# ===========================================================================
set -u
RAIZ="$(cd "$(dirname "$0")/.." && pwd)"
NJ_DIR="$RAIZ/lab/neo4j-community-5.26.12"
CLAVE="${NEO4J_PASS:-orquesta-lab-2026}"

mkdir -p "$RAIZ/lab/logs"
if [ ! -d "$NJ_DIR" ]; then
  echo "ERROR: extraiga la distribución oficial en $NJ_DIR (lab/downloads/neo4j.zip)" >&2
  exit 1
fi

# ¿Ya está vivo?
if curl -s -o /dev/null --connect-timeout 1 -m 2 "http://localhost:7474"; then
  echo "Neo4j ya está en marcha en :7474"
  exit 0
fi

# Ajustes de laboratorio solo la primera vez (idempotentes: append único)
CONF="$NJ_DIR/conf/neo4j.conf"
if ! grep -q "^server.default_listen_address=" "$CONF" 2>/dev/null; then
  {
    echo ""
    echo "# --- laboratorio OrquestaRT (añadido por lab/neo4j_arrancar.sh) ---"
    echo "server.default_listen_address=127.0.0.1"
    echo "server.memory.heap.initial_size=256m"
    echo "server.memory.heap.max_size=512m"
    echo "server.memory.pagecache.size=256m"
  } >> "$CONF"
  echo "configuración de laboratorio añadida a neo4j.conf"
fi

# Contraseña inicial (falla con mensaje si ya se fijó antes: es inocuo)
if ! "$NJ_DIR/bin/neo4j-admin" dbms set-initial-password "$CLAVE" \
     >>"$RAIZ/lab/logs/neo4j.log" 2>&1; then
  echo "(contraseña inicial ya fijada: se conserva)"
fi

"$NJ_DIR/bin/neo4j" start

for _ in $(seq 1 60); do
  if curl -s -o /dev/null --connect-timeout 1 -m 2 "http://localhost:7474"; then
    echo "Neo4j vivo en :7474"
    echo "Siguiente paso: cargue la colección del dominio de laboratorio con"
    echo "  python3 lab/coleccion_dominio.py"
    exit 0
  fi
  sleep 1
done

echo "ERROR: Neo4j no respondió en 60 s; revise lab/neo4j-community-5.26.12/logs/neo4j.log" >&2
exit 1
