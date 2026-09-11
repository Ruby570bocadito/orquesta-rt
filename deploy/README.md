# Despliegue OrquestaRT en Kubernetes (v21)

Despliegue productivo del conjunto: orquestador (FastAPI + SQLite por caso),
consola (Next.js) y entrada TLS. El lab ofensivo (:8080) NO se despliega en
el clúster: corre donde está el objetivo autorizado (host dedicado, jaula o
segmento del ROE) — el orquestador lo alcanza por red, jamás al revés.

## Orden de aplicación

```bash
# 1. Base: namespace, config, secret y almacenamiento
kubectl apply -f deploy/k8s/00-base.yaml

# 2. ANTES de seguir: edita 00-base.yaml y sustituye los PLACEHOLDER del
#    Secret (CLAVE_CASO, API_FRONTERA_CLAVE, OIDC_*, LDAP_*, SMTP_*, MISP_*,
#    BLOODHOUND_*). Sin CLAVE_CASO real, las evidencias no se firman.

# 3. Orquestador (construye y publica tu imagen primero)
docker build -t registry.corp.local/orquesta/orquestador:v21 platform/
docker push  registry.corp.local/orquesta/orquestador:v21
kubectl apply -f deploy/k8s/10-orquestador.yaml

# 4. Consola
docker build -t registry.corp.local/orquesta/consola:v21 .
docker push  registry.corp.local/orquesta/consola:v21
kubectl apply -f deploy/k8s/20-consola.yaml

# 5. Verificación
kubectl -n orquesta-rt get pods
kubectl -n orquesta-rt logs deploy/orquestador | tail -50
curl -sk https://consola.orquesta.local/api/salud | jq
```

## Decisiones de producción (y por qué)

- **1 réplica del orquestador con `Recreate`**: la memoria de casos es SQLite
  por fichero (un engagement = un `.db` firmado). Multi-réplica exige migrar a
  PostgreSQL; con el volumen actual la coherencia de la cadena de custodia
  prima sobre la disponibilidad de escritura.
- **2+ réplicas de consola**: stateless, escala horizontal real.
- **`readOnlyRootFilesystem` en el orquestador** con `emptyDir` para `/tmp`:
  el proceso escribe SOLO en `/datos` (casos + cuentas) — limita el blast
  radius si el pod se compromete.
- **Sondas contra `/api/salud`**: el endpoint comprueba memoria de casos,
  BD de operadores y router IA (componentes reales, no un ping vacío).
- **Secret como objeto Secret**: con ExternalSecrets/SealedSecrets o Vault
  en despliegues maduros; el `stringData` del fichero es placeholder a
  propósito (aplicarlo tal cual rompe el firmado de evidencias y se nota).
- **Ingress con timeouts largos**: el flujo en vivo usa SSE (eventos de
  auditoría en streaming); un proxy-read-timeout corto corta el flujo.

## RBAC multi-tenant y SSO en este despliegue

- Roles `admin / gestor / operador / lector` y organizaciones viajan FIRMADOS
  en el JWT (`rol`, `ten`): el aislamiento de casos se aplica en la API, no
  en el cliente.
- Para SSO OIDC define en el Secret: `OIDC_ISSUER`, `OIDC_CLIENT_ID`,
  `OIDC_CLIENT_SECRET`, `OIDC_REDIRECT_URI` (p. ej.
  `https://consola.orquesta.local/acceso?sso=1`). El flujo es
  authorization-code + PKCE con verificación criptográfica del id_token
  (RS256 vía JWKS) y alta JIT opcional como `lector`.

## Respaldos

```bash
# Respaldo completo consistente (VACUUM INTO por BD + manifiesto SHA-256):
kubectl -n orquesta-rt exec deploy/orquestador -- python - <<'EOF'
from orchestrator.respaldo import construir_respaldo_completo
import pathlib
contenido, manifiesto = construir_respaldo_completo()
pathlib.Path("/datos/respaldo.zip").write_bytes(contenido)
print(manifiesto)
EOF
kubectl -n orquesta-rt cp deploy/orquestador:/datos/respaldo.zip ./respaldo.zip
```
