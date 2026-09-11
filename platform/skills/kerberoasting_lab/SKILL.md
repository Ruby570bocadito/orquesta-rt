---
nombre: kerberoasting_lab
descripcion: "Playbook de laboratorio para auditar cuentas de servicio con SPN en un dominio AD simulado: detección de candidatos, estimación de ruido y evidencias a capturar. Contenido EDUCATIVO del lab: los comandos concretos los ejecuta el tooling licenciado del equipo vía adaptador MCP, nunca este agente."
fase: "F4_dominio_ad"
tecnica_mitre: "T1558.003"
riesgo: "alta"
requiere_aprobacion: true
fuentes_permitidas:
  - "adaptador AD del lab (mock)"
  - "tooling licenciado del equipo (producción)"
---

# Skill: Kerberoasting (laboratorio)

## Propósito

Auditar cuentas de servicio con SPN registradas en un dominio Active
Directory **de laboratorio** para demostrar el riesgo de contraseñas
débiles en cuentas de servicio. Esta skill documenta el procedimiento,
los criterios y la higiene; la ejecución técnica corresponde SIEMPRE al
adaptador MCP del lab (mock) o al tooling licenciado en producción, tras
aprobación explícita del operador (el ROE la exige: `requiere_aprobacion: true`).

## Cuándo usarla

- El grafo del dominio (F4) muestra cuentas de servicio con SPN.
- El ROE no la prohíbe (`tecnicas_prohibidas`) y sí la contempla en
  `tecnicas_con_aprobacion`.
- Hay ventana horaria activa y presupuesto de ruido suficiente.

## Procedimiento (alto nivel)

1. **Candidatos**: desde el grafo, lista cuentas con SPN y clasifícalas por
   antigüedad de contraseña y privilegios del grafo.
2. **Ruido**: estima el ruido (solicitudes TGS contra el KDC) y compáralo con
   el techo del ROE. Si excede el techo: PARAR y proponer alternativa
   (AS-REP roasting suele ser más silencioso).
3. **Aprobación**: crea la petición en consola con objetivo, ruido estimado y
   referencia de ROE. NO continúes sin firma humana.
4. **Ejecución**: delega en el adaptador (`ad.kerberoasting`). El adaptador
   del lab devuelve resultados simulados; el de producción usa el tooling
   licenciado del equipo.
5. **Evidencias**: captura la lista de cuentas, el hash del volcado (en bóveda,
   nunca en contexto), y el resultado del crackeo offline.

## Criterios de éxito

- Lista de cuentas de servicio con SPN registrada como evidencia.
- Al menos una contraseña débil demostrada (en lab) o ausencia de ella.
- Nada en claro en el informe: solo longitudes y fortaleza estimada.

## Reglas OPSEC

- Filtrar la lista de SPNs antes de solicitar TGS para minimizar peticiones.
- Nunca solicitar TGS de cuentas Tier-0 si el objetivo puede lograrse sin ellas.
- El ruido real queda registrado por la auditoría: revísala antes de repetir.

## Evidencias a capturar

| Evidencia | Tipo | Contenido mínimo |
|---|---|---|
| Lista de candidatos | JSON | cuentas, SPN, antigüedad de contraseña |
| Petición de aprobación | JSON | id de aprobación y firma del operador |
| Resultado del adaptador | JSON | cuentas crackeadas (SIN hashes en claro) |

## Receta de verificación (para el blue team)

El hallazgo se verifica reejecutando la detección: consultar cuentas con
SPN y contraseñas antiguas/débiles, y confirmar que la política de
contraseñas de cuentas de servicio se ha endurecido. La detección del
ataque (peticiones TGS anómalas, id 4769 con cifrado RC4) debe disparar
una alerta en el SIEM del cliente tras la corrección.
