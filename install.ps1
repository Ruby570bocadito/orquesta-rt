# ============================================================================
# OrquestaRT - instalacion en Windows (nativo, sin WSL ni Docker)
#
#   .\install.ps1
#
# Equivalente de install.sh para PowerShell. Idempotente.
#   1. Comprueba Python 3.11+ (prefiere el lanzador py -3.12) y bun/npm.
#   2. Crea .venv e instala platform\requirements.txt (+ pytest).
#   3. Instala las dependencias de la consola.
#   4. Crea logs\ db\ platform\casos\ y verifica que el backend importa.
#
# Si PowerShell bloquea el script:  powershell -ExecutionPolicy Bypass -File .\install.ps1
# ============================================================================
$ErrorActionPreference = "Stop"
$RAIZ = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $RAIZ

Write-Host ""
Write-Host "  OrquestaRT - instalacion (Windows)" -ForegroundColor Cyan
Write-Host ""

# 1. Interprete Python 3.11+ -------------------------------------------------
$pyExe = $null; $pyArgs = @()
if (Get-Command py -ErrorAction SilentlyContinue) {
  foreach ($v in @("-3.12", "-3.11", "-3")) {
    & py $v -c "import sys; raise SystemExit(0 if sys.version_info[:2] >= (3,11) else 1)" 2>$null
    if ($LASTEXITCODE -eq 0) { $pyExe = "py"; $pyArgs = @($v); break }
  }
}
if (-not $pyExe -and (Get-Command python -ErrorAction SilentlyContinue)) {
  & python -c "import sys; raise SystemExit(0 if sys.version_info[:2] >= (3,11) else 1)" 2>$null
  if ($LASTEXITCODE -eq 0) { $pyExe = "python" }
}
if (-not $pyExe) {
  Write-Host "  Falta Python 3.11+ (instala 3.12 desde https://python.org)" -ForegroundColor Red
  exit 1
}
Write-Host "  OK  Python 3.11+ encontrado" -ForegroundColor Green

# 2. Gestor de la consola (bun preferido, npm valido) ------------------------
$consola = $null
if (Get-Command bun -ErrorAction SilentlyContinue) { $consola = "bun" }
elseif (Get-Command npm -ErrorAction SilentlyContinue) { $consola = "npm" }
if (-not $consola) {
  Write-Host "  Falta bun o node+npm (para la consola)" -ForegroundColor Red
  exit 1
}
Write-Host "  OK  Gestor de la consola: $consola" -ForegroundColor Green

# 3. Entorno virtual del backend ---------------------------------------------
if (-not (Test-Path ".venv\Scripts\python.exe")) {
  Write-Host "  ... creando .venv (una sola vez)" -ForegroundColor Yellow
  & $pyExe @pyArgs -m venv .venv
}
$VPY = Join-Path $RAIZ ".venv\Scripts\python.exe"
Write-Host "  ... instalando dependencias del backend (1-2 min la primera vez)" -ForegroundColor Yellow
& $VPY -m pip install --quiet --upgrade pip
& $VPY -m pip install -r platform\requirements.txt pytest
if ($LASTEXITCODE -ne 0) {
  Write-Host "  ERROR instalando platform\requirements.txt" -ForegroundColor Red
  Write-Host "  Pista: si falla impacket por rutas largas, clona el repo en una ruta corta" -ForegroundColor Yellow
  Write-Host "         (p.ej. C:\orquesta-rt) o habilita rutas largas de Windows (ver docs\WINDOWS.md)." -ForegroundColor Yellow
  exit 1
}
Write-Host "  OK  Backend instalado" -ForegroundColor Green

# 4. Dependencias de la consola ----------------------------------------------
if (-not (Test-Path "node_modules")) {
  Write-Host "  ... instalando dependencias de la consola ($consola)" -ForegroundColor Yellow
  & $consola install
}
Write-Host "  OK  Consola instalada" -ForegroundColor Green

# 5. Directorios de trabajo --------------------------------------------------
New-Item -ItemType Directory -Force -Path logs, db, platform\casos | Out-Null

# 6. Verificacion real -------------------------------------------------------
& $VPY -c "import uvicorn, fastapi, cryptography, httpx, msgpack" 2>$null
if ($LASTEXITCODE -ne 0) {
  Write-Host "  ERROR: alguna dependencia del backend no importa" -ForegroundColor Red
  exit 1
}

Write-Host ""
Write-Host "  Instalacion completada. Siguiente:  .\start.ps1" -ForegroundColor Green
Write-Host "  Luego abre http://localhost:3000 (la primera vez crea la cuenta admin)." -ForegroundColor Gray
Write-Host ""
