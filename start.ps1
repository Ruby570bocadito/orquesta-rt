# ============================================================================
# OrquestaRT - arranque en Windows (nativo)
#
#   .\start.ps1
#
# Levanta la consola Next.js (:3000). El backend Python (:8000) y el lab
# (:8080) los auto-arranca instrumentation.ts usando ORQUESTA_PYTHON (el
# interprete del .venv). Ctrl+C detiene la consola; usa .\stop.ps1 para
# cerrar tambien el backend.
#
# Si PowerShell bloquea el script:  powershell -ExecutionPolicy Bypass -File .\start.ps1
# ============================================================================
$ErrorActionPreference = "Stop"
$RAIZ = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $RAIZ

if (-not (Test-Path ".venv\Scripts\python.exe")) {
  Write-Host "  No hay .venv: ejecutando install.ps1 primero ..." -ForegroundColor Yellow
  & "$RAIZ\install.ps1"
}

New-Item -ItemType Directory -Force -Path logs, db | Out-Null

# El backend se auto-arranca al iniciar `next dev` (register() de
# instrumentation.ts). Le decimos que interprete usar y cual es la raiz.
$env:ORQUESTA_PYTHON = Join-Path $RAIZ ".venv\Scripts\python.exe"
$env:ORQUESTA_RAIZ   = $RAIZ
if (-not $env:MODO_CONSOLA) { $env:MODO_CONSOLA = "dev" }

$consola = "bun"
if (-not (Get-Command bun -ErrorAction SilentlyContinue)) { $consola = "npm" }

Write-Host ""
Write-Host "  OrquestaRT arrancando ($consola run dev) ..." -ForegroundColor Cyan
Write-Host "  Consola    : http://localhost:3000" -ForegroundColor Green
Write-Host "  Primera vez: crea la cuenta admin (3-32 caracteres; contrasena de 8+)." -ForegroundColor Gray
Write-Host "  Parar      : Ctrl+C aqui, y .\stop.ps1 para cerrar el backend." -ForegroundColor DarkGray
Write-Host ""

& $consola run dev
