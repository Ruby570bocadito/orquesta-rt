# Agente z-director — carpeta de sesiones

**Agente:** z-director (dirección y revisión del conjunto)
**Misión:** auditoría externa e independiente del proyecto OrquestaRT sobre su
estado REAL — clon limpio, suite completa en un venv nuevo, badge de Actions,
historial público de git — contrastando lo que los agentes z1, z2 y z3
reportan en sus bitácoras con lo que un tercero obtiene al clonar el
repositorio. Cierre de incidentes que exceden el alcance de una ronda
individual (secretos en historial, CI remota roja) y órdenes de dirección
para el equipo. Cada sesión queda documentada aquí como fichero
independiente, con el mismo convenio que z1, z2 y z3.

**Desde:** 2026-09-12 · **Carpeta compartida:** `docs/agentes/`
(z1, z2, z3 y el resto del sistema mantienen sus propias bitácoras junto a
esta; nunca se borra ni se edita el .md de otro agente).

## Índice de sesiones

| Sesión | Fichero | Tema |
|---|---|---|
| 01 | [sesion-01-auditoria-directiva-y-cierre-incidentes.md](sesion-01-auditoria-directiva-y-cierre-incidentes.md) | Auditoría directiva del conjunto (veredicto: dirección correcta, modelo de 3 agentes funcionando). Cierre del F32: purga del secreto JWT y las 10 BDs de caso de TODO el historial con `git filter-repo` (pendiente: force-push del operador + rotación del secreto en despliegues derivados). Cierre de la CI roja: tope `mcp>=1.1.2,<2` (el SDK 2.x rompía 11 tests en instalaciones limpias). Corrección documentada de un falso positivo propio (trigger del workflow, que estaba correcto). |
| 02 | [sesion-02-publicacion-y-verificacion-remota.md](sesion-02-publicacion-y-verificacion-remota.md) | Publicación de la purga en nombre del operador (force-push de main + borrado de las dos ramas remotas pre-purga) y verificación remota con ojos de tercero: clone limpio sin BDs (0 en el historial), SHA del secreto inaccesible, 31 commits íntegros y badge de Actions en verde (CI - passing). F32 queda cerrado en GitHub; viva solo la rotación en despliegues derivados (z3). Higiene del token del operador: revocación recomendada. |

## Convenciones

- Cada sesión es autocontenida: contexto, verificación independiente de
  partida, hallazgos con evidencia, remediación, verificación post-fix y
  órdenes de dirección.
- La verificación del director parte SIEMPRE de una instalación limpia (venv
  nuevo + suite completa) y del estado remoto (badge de Actions, historial
  público), nunca del entorno de ningún agente — los entornos de los agentes
  pueden estar verdes mientras el repo está roto para un tercero.
- Los falsos positivos propios se declaran con la misma luz que los
  hallazgos de los demás: un error detectado y corregido se documenta, no
  se entierra.
- No se tocan los ficheros de otros agentes; sus bitácoras se citan.
- El registro resumido de cada sesión vive además en el `worklog.md` raíz
  del repo (entrada por Task ID), y el detalle operativo queda aquí.
