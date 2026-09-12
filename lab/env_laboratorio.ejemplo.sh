#!/usr/bin/env bash
# ===========================================================================
# OrquestaRT — PLANTILLA de entorno del despliegue (v22)
#
#   cp lab/env_laboratorio.ejemplo.sh lab/env_laboratorio.sh   # y edite
#
# start.sh carga lab/env_laboratorio.sh si existe (set -a) para activar las
# integraciones REALES de su despliegue: IdP OIDC, motor Neo4j de rutas,
# BloodHound CE, MISP. NUNCA suba sus valores reales a un repositorio.
# ===========================================================================

# --- SSO OIDC (Keycloak / Entra ID / cualquier IdP con discovery) -----------
# Sin OIDC_ISSUER el SSO queda desactivado y el acceso es por contraseña.
#export OIDC_ISSUER="https://sso.su-dominio.com/realms/orquesta"
#export OIDC_CLIENT_ID="orquesta-rt"
#export OIDC_CLIENT_SECRET="CAMBIE-ESTE-SECRETO"
#export OIDC_REDIRECT_URI="https://consola.su-dominio.com/?sso=1"
#export OIDC_AUTO_ALTA="1"      # alta JIT como lector
#export OIDC_ROL_JIT="lector"

# --- Motor de rutas de ataque (Neo4j con colección BloodHound) --------------
# Rutas REALES calculadas por el motor (Cypher dirigido allShortestPaths).
#export NEO4J_URL="http://localhost:7474"
#export NEO4J_USER="neo4j"
#export NEO4J_PASS="CAMBIE-ESTA-CLAVE"

# --- BloodHound CE (opcional; rutas servidas por su API oficial) ------------
#export BLOODHOUND_URL="http://localhost:8080"
#export BLOODHOUND_USER="admin"
#export BLOODHOUND_SECRET="CAMBIE-ESTE-SECRETO"

# --- MISP (opcional; enriquecimiento y export de hallazgos) -----------------
#export MISP_URL="https://misp.su-dominio.com"
#export MISP_KEY="CAMBIE-ESTA-CLAVE-DE-API"
#export MISP_SSL="1"            # "0" solo para labs con certificado propio

# --- MISP DE LABORATORIO (v24) ----------------------------------------------
# Servidor compatible con la API real de MISP con intel semilla del lab
# (arranque: docker compose -f platform/lab/docker-compose.lab.yml up lab-misp).
# Ejercita el enriquecimiento end-to-end SIN una instancia productiva:
#export MISP_URL="http://localhost:8444"
#export MISP_KEY="clave-lab-misp"
#export MISP_SSL="0"
