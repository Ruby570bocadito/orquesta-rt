#!/usr/bin/env bash
# Aprovisiona el realm de laboratorio en el Keycloak REAL:
#   realm "orquesta", cliente confidencial "orquesta-rt" (standard flow + PKCE),
#   usuario "operador" con contraseña, y secret del cliente para el orquestador.
# Idempotente: si el realm/cliente ya existen, solo actualiza y recupera el secret.
set -eu
RAIZ="$(cd "$(dirname "$0")/.." && pwd)"
KC_DIR="$RAIZ/lab/keycloak-26.3.5"
KCADM="$KC_DIR/bin/kcadm.sh"
PUERTO="${KEYCLOAK_PUERTO:-8081}"
SERVER="http://localhost:$PUERTO"
ADMIN_PASS="$(cat "$RAIZ/lab/keycloak-admin.txt")"
REALM="orquesta"
CLIENTE="orquesta-rt"
# Secret de LABORATORIO (valor declarado; en producción use el gestor de secretos)
SECRET_LAB="orquesta-rt-lab-secret"
USER_PASS="Operador-Lab-2026"

"$KCADM" config credentials --server "$SERVER" --realm master \
  --user admin --password "$ADMIN_PASS" >/dev/null

# Realm (los flags booleanos compuestos rompen kcadm: solo lo esencial)
if "$KCADM" get realms/"$REALM" >/dev/null 2>&1; then
  echo "realm '$REALM' ya existe"
else
  "$KCADM" create realms -s realm="$REALM" -s enabled=true
  echo "realm '$REALM' creado"
fi

# Cliente confidencial (nuestro sso.py envía client_secret en el token endpoint)
if "$KCADM" get clients -r "$REALM" -q clientId="$CLIENTE" --fields id --format csv --noquotes 2>/dev/null | grep -qE '^[0-9a-f-]{36}$'; then
  echo "cliente '$CLIENTE' ya existe"
  CID="$($KCADM get clients -r "$REALM" -q clientId="$CLIENTE" --fields id --format csv --noquotes | tail -1)"
  "$KCADM" update "clients/$CID" -r "$REALM" -s secret="$SECRET_LAB" -s enabled=true
else
  "$KCADM" create clients -r "$REALM" -i \
    -s clientId="$CLIENTE" -s enabled=true \
    -s 'protocol=openid-connect' -s 'publicClient=false' \
    -s "secret=$SECRET_LAB" \
    -s 'standardFlowEnabled=true' -s 'directAccessGrantsEnabled=false' \
    -s 'redirectUris=["http://localhost:3000/?sso=1","http://localhost:3000/"]' \
    -s 'webOrigins=["http://localhost:3000"]'
  echo "cliente '$CLIENTE' creado"
fi

# Usuario de laboratorio con contraseña permanente (sin forzar cambio)
if "$KCADM" get users -r "$REALM" -q username=operador --fields id --format csv --noquotes 2>/dev/null | grep -q .; then
  echo "usuario 'operador' ya existe"
else
  "$KCADM" create users -r "$REALM" \
    -s username=operador -s enabled=true \
    -s firstName=Operador -s lastName="de Laboratorio" \
    -s email=operador@lab.local -s emailVerified=true
  UID_="$("$KCADM" get users -r "$REALM" -q username=operador --fields id --format csv --noquotes | tail -1)"
  "$KCADM" set-password -r "$REALM" --userid "$UID_" --new-password "$USER_PASS" --temporary=false
  echo "usuario 'operador' creado con contraseña de laboratorio"
fi

# Verificación REAL: discovery del realm responde y el token endpoint existe
curl -sf "$SERVER/realms/$REALM/.well-known/openid-configuration" | head -c 120; echo
echo "OK — variables para el orquestador:"
echo "  OIDC_ISSUER=$SERVER/realms/$REALM"
echo "  OIDC_CLIENT_ID=$CLIENTE"
echo "  OIDC_CLIENT_SECRET=$SECRET_LAB"
echo "  OIDC_REDIRECT_URI=http://localhost:3000/?sso=1"
echo "  LOGIN LAB: operador / $USER_PASS"
