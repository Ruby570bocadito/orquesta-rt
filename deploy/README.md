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

## Variables de endurecimiento y superficies admin (z2, ronda 3)

Variables documentadas aquí porque cambian la postura de seguridad del
despliegue: el valor por defecto es el SEGURO; el valor relajado existe para
laboratorio, migraciones o IdPs particulares, nunca como configuración de
producción por defecto.

### TLS saliente con credenciales (`*_TLS_VERIFICAR`)

Las integraciones que envían credenciales por TLS verifican el certificado
por defecto (`verify=True`):

| Variable | Afecta a | Por defecto |
|----------|----------|-------------|
| `MSF_TLS_VERIFICAR` | Metasploit RPC (login+token) | verificación ON |
| `BLOODHOUND_TLS_VERIFICAR` | BloodHound CE (API con JWT) | verificación ON |
| `MYTHIC_TLS_VERIFICAR` | Mythic (GraphQL con token) | verificación ON |

`*_TLS_VERIFICAR=0` desactiva la verificación (certificados autofirmados de
lab). NO vale `=false` ni `=no`: el contrato es "cualquier cosa distinta de
`0` verifica". En producción, si el CA corporativo no está en el almacén del
contenedor, añádelo a la imagen (no desactives la verificación).

### Webhooks: SSRF y canal heredado

- **Veto de metadatos de nube**: los receptores no pueden apuntar a
  link-local/IMDS (169.254.169.254, `fd00:ec2::254`, Alibaba 100.100.100.200,
  Oracle 192.0.0.192, nombres `metadata.*`), ni por nombre, ni por IP en
  forma alternativa, ni por DNS resuelto — verificado en el ALTA y de nuevo
  en cada DESPACHO (anti-rebinding). Redirecciones 3xx NO se siguen
  (`follow_redirects=False`, práctica GitHub/Stripe): da de alta la URL final.
  Escape documentado para casos excepcionales:
  `WEBHOOK_PERMITIR_METADATOS=1` (no debería existir un receptor allí).
- **Canal heredado** `WEBHOOK_URL` (+ opcional `WEBHOOK_SECRETO`): recibe
  TODOS los eventos y pasa por el MISMO veto SSRF que los receptores de BD.
  Preferir receptores gestionados en la consola (Integraciones) sobre el
  canal heredado: tienen rotación de secreto e historial de entregas.
- Cada intento lleva `X-Orquesta-Intento: 1|2` (junto a `X-Orquesta-Entrega`,
  constante en el reintento) para la idempotencia del receptor.

### SSO: vinculación de cuentas

El enlace silencioso por homonimia de email está DESACTIVADO por defecto
(una cuenta SSO nueva NO se pega a una cuenta local existente sin decisión
explícita). Capas de control:

- `SSO_VINCULAR_POR_NOMBRE=1`: permite la homonimia para cuentas NO
  privilegiadas — solo si tu IdP GARANTIZA el email verificado del dominio.
- Cuentas privilegiadas (rol `operador` o superior): exigen SIEMPRE
  pre-aprobación de admin (tabla `sso_vinculos_preaprobados`, caducidad de
  30 días), esté o no el flag activo.
- Gestión desde la API admin: `POST /api/auth/sso/vincular` (crea el vínculo
  pre-aprobado) y `GET /api/auth/operadores` (auditoría de cuentas). Los
  intentos de vínculo rechazados quedan en la auditoría del sistema.

### Métrica de fuerza bruta en el chequeo de salud

Con sesión autenticada, `/api/salud` incluye `componentes.limitador_auth`:
`bloqueos_24h` (respuestas 429 de las últimas 24 h) y `claves_activas`
(clientes con actividad reciente en la ventana). El payload ANÓNIMO de
`/api/salud` no la incluye (no revela si el despliegue está bajo ataque).
Útil para paneles de monitorización: un pico sostenido de `bloqueos_24h`
es fuerza bruta contra el login — cruza con los logs del proxy para las IPs
origen. Métrica operacional: NO afecta al `estado` del healthcheck.
