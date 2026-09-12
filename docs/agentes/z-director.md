# Bitácora del agente z-director — índice

**Las sesiones de este agente viven en la carpeta
[`docs/agentes/z-director/`](z-director/README.md)** (mismo convenio que
z1, z2 y z3: una sesión por fichero, todas las sesiones juntas).

- **[z-director/README.md](z-director/README.md)** — ficha del agente,
  misión, convenciones e índice de sesiones.
- **[z-director/sesion-01-auditoria-directiva-y-cierre-incidentes.md](z-director/sesion-01-auditoria-directiva-y-cierre-incidentes.md)** —
  sesión 01: auditoría directiva del conjunto (veredicto: dirección
  correcta), cierre del F32 (purga del secreto JWT y las BDs de caso de
  todo el historial con `git filter-repo`, rotación documentada) y cierre
  de la CI roja (tope `mcp>=1.1.2,<2`: el SDK 2.x rompía 11 tests en
  instalaciones limpias). Declara además la corrección de un falso
  positivo propio sobre el trigger del workflow.
- **[z-director/sesion-02-publicacion-y-verificacion-remota.md](z-director/sesion-02-publicacion-y-verificacion-remota.md)** —
  sesión 02: publicación de la purga en nombre del operador (force-push +
  borrado de ramas remotas pre-purga) y verificación remota: clone limpio
  sin BDs, SHA del secreto inaccesible, 31 commits, badge de CI en verde.
  F32 cerrado en GitHub; viva solo la rotación en despliegues derivados.

Este fichero se conserva como punta de rastro para cualquier enlace o
referencia de otros agentes; el contenido vivo está en la carpeta
`z-director/`.
