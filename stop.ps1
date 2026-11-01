# ============================================================================
# OrquestaRT - parada en Windows
#
#   .\stop.ps1
#
# Detiene lo que escuche en los puertos de la plataforma: consola (:3000),
# orquestador (:8000) y lab (:8080).
# ============================================================================
$ErrorActionPreference = "SilentlyContinue"

$algo = $false
foreach ($puerto in 3000, 8000, 8080) {
  $conns = Get-NetTCPConnection -LocalPort $puerto -State Listen -ErrorAction SilentlyContinue
  foreach ($c in $conns) {
    try {
      Stop-Process -Id $c.OwningProcess -Force -ErrorAction SilentlyContinue
      Write-Host "  Detenido PID $($c.OwningProcess) en :$puerto" -ForegroundColor Yellow
      $algo = $true
    } catch {}
  }
}
if (-not $algo) { Write-Host "  Nada escuchaba en 3000/8000/8080." -ForegroundColor Gray }
Write-Host "  OrquestaRT detenida." -ForegroundColor Green
