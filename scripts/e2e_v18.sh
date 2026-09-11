#!/usr/bin/env bash
# E2E v18: verificación del grafo de relaciones en navegador real.
# Autocontenido (el sandbox sega procesos next entre llamadas).
set -u
CAP="/home/z/my-project/download/verificacion"
mkdir -p "$CAP"
URL="http://127.0.0.1:3000"
USUARIO="op_e2e_v18"
CLAVE="Clave-E2E-2026!x"

ref_de() { # $1 = patrón de línea del snapshot → imprime la ref (eNN)
  agent-browser snapshot -i 2>/dev/null | rg -m1 "$1" | rg -o 'ref=(e[0-9]+)' | head -1 | tr -d ' '
}

existe() { agent-browser snapshot -i 2>/dev/null | rg -q "$1"; }

click_texto() { # $1 patrón
  local r; r=$(ref_de "$1")
  if [ -n "$r" ]; then agent-browser click "@$r" >/dev/null 2>&1; return 0; fi
  return 1
}

paso() { echo "== $1"; }

agent-browser close >/dev/null 2>&1 || true
agent-browser open "$URL" >/dev/null 2>&1
agent-browser wait --load networkidle >/dev/null 2>&1
sleep 1

# ---------------------------------------------------------- alta/login
paso "Acceso"
if existe "Alta del primer operador"; then
  R_U=$(ref_de 'ana\.red'); R_C=$(ref_de 'mínimo 8 caracteres')
  agent-browser fill "@$R_U" "$USUARIO" >/dev/null
  agent-browser fill "@$R_C" "$CLAVE" >/dev/null
  click_texto 'Crear cuenta admin y entrar'
  echo "alta bootstrap enviada"
else
  R_U=$(ref_de 'tu usuario|ana\.red'); R_C=$(ref_de 'tu contraseña')
  agent-browser fill "@$R_U" "$USUARIO" >/dev/null
  agent-browser fill "@$R_C" "$CLAVE" >/dev/null
  click_texto 'Iniciar sesión'
  echo "login enviado"
fi
agent-browser wait --load networkidle >/dev/null 2>&1; sleep 2

# ------------------------------------------------------- nuevo engagement
paso "Nuevo engagement"
click_texto 'Nuevo engagement'; sleep 1
R_N=$(ref_de 'Test de intrusión externa'); R_C=$(ref_de 'ACME S\.L\.')
R_D=$(ref_de 'localhost'); R_I=$(ref_de '127\.0\.0\.0/8')
agent-browser fill "@$R_N" "Verificación grafo v18" >/dev/null
agent-browser fill "@$R_C" "ACME Lab" >/dev/null
agent-browser fill "@$R_D" "lab-interno.test" >/dev/null
agent-browser fill "@$R_I" "127.0.0.1/32" >/dev/null
click_texto 'Crear engagement'; sleep 2
click_texto 'Verificación grafo v18'; sleep 2
agent-browser wait --load networkidle >/dev/null 2>&1

# --------------------------- ciclo F0→F1→F2 con firma de aprobaciones
ejecutar_fase() {
  local r; r=$(ref_de 'aria-label="Ejecutar fase actual"')
  [ -z "$r" ] && r=$(ref_de 'Ejecutar fase')
  [ -z "$r" ] && return 1
  agent-browser click "@$r" >/dev/null 2>&1; sleep 1
  if existe 'Notas de la entrevista'; then
    local rn; rn=$(ref_de 'Notas de la entrevista')
    [ -n "$rn" ] && agent-browser fill "@$rn" "Verificación E2E del grafo de relaciones con el lab local" >/dev/null
  fi
  click_texto 'Ejecutar fase$|Ejecutar fase'; sleep 2
  return 0
}

aprobar_pendientes() {
  local n=0
  while [ $n -lt 6 ]; do
    if ! existe 'Aprobar y ejecutar'; then return 0; fi
    click_texto 'Aprobar y ejecutar' || return 0
    sleep 1.5
    n=$((n+1))
  done
}

paso "Ciclo de fases con firma humana"
for vuelta in 1 2 3 4 5 6; do
  aprobar_pendientes
  if ! ejecutar_fase; then echo "sin botón de fase (¿ciclo completo?)"; fi
  sleep 2
done
aprobar_pendientes

# ------------------------------------------------- hallazgos manuales
paso "Hallazgos manuales (activos reales para el grafo)"
click_texto 'Hallazgos'; sleep 1
click_texto 'Registrar hallazgo manual'; sleep 1
R_T=$(ref_de 'Brecha observada'); R_M=$(ref_de 'T####'); R_A=$(ref_de 'host, dominio o URL')
agent-browser fill "@$R_T" "Cuentas de servicio con SPN candidatas a Kerberoasting" >/dev/null
agent-browser fill "@$R_M" "T1558.003" >/dev/null
agent-browser fill "@$R_A" "lab-interno.test" >/dev/null
R_D2=$(ref_de 'Qué se observó')
[ -n "$R_D2" ] && agent-browser fill "@$R_D2" "Enumeración LDAP de la verificación: cuentas con servicePrincipalName en el directorio del lab." >/dev/null
click_texto 'Registrar hallazgo$'; sleep 1.5

# -------------------------------------------------------------- grafo
paso "Objetivos → vista grafo"
click_texto 'Objetivos'; sleep 1.5
if ! click_texto '"grafo"'; then
  # botón con etiqueta exacta "grafo" (uppercase por CSS)
  agent-browser eval "Array.from(document.querySelectorAll('button')).find(b=>b.textContent.trim().toLowerCase()==='grafo')?.click(); 'ok'" >/dev/null 2>&1
fi
sleep 1
NODES=$(agent-browser eval "document.querySelectorAll('svg[aria-label*=\"Grafo\"] rect').length" 2>/dev/null | tail -1)
LINEAS=$(agent-browser eval "document.querySelectorAll('svg[aria-label*=\"Grafo\"] line').length" 2>/dev/null | tail -1)
echo "grafo: $NODES nodos · $LINEAS aristas"
agent-browser screenshot "$CAP/v18_grafo_escritorio.png" >/dev/null 2>&1

# ------------------------------------------------------------- móvil
paso "Móvil 390px"
agent-browser set viewport 390 844 >/dev/null 2>&1
sleep 1
OVERFLOW=$(agent-browser eval "document.documentElement.scrollWidth - document.documentElement.clientWidth" 2>/dev/null | tail -1)
echo "overflow móvil: ${OVERFLOW}px"
agent-browser screenshot "$CAP/v18_grafo_movil.png" >/dev/null 2>&1
agent-browser eval "window.scrollTo(0,0)" >/dev/null 2>&1

# ------------------------------------------------------------ errores
agent-browser errors > "$CAP/v18_errores.txt" 2>&1 || true
echo "errores de página: $(wc -l < "$CAP/v18_errores.txt") líneas"

agent-browser close >/dev/null 2>&1 || true
echo "E2E grafo terminado"
