---
nombre: asrep_roasting_lab
descripcion: "Playbook de laboratorio para auditar cuentas de dominio sin preautenticación Kerberos (AS-REP roasting): detección de candidatos, estimación de ruido mínimo y evidencias a capturar. Contenido EDUCATIVO del lab: los comandos concretos los ejecuta el tooling licenciado del equipo vía adaptador MCP, nunca este agente."
fase: "F4_dominio_ad"
tecnica_mitre: "T1558.004"
riesgo: "alta"
requiere_aprobacion: true
fuentes_permitidas:
  - "adaptador AD del lab (mock)"
  - "tooling licenciado del equipo (producción)"
---

# Skill: AS-REP Roasting (laboratorio)

## Propósito

Auditar cuentas de dominio configuradas SIN preautenticación Kerberos
(`UF_DONT_REQUIRE_PREAUTH`) para demostrar el riesgo de que un atacante
sin credenciales solicite un AS-REP cifrable y lo rompa offline. Esta
skill documenta el procedimiento, los criterios y la higiene; la
ejecución técnica corresponde SIEMPRE al adaptador MCP del lab (mock) o
al tooling licenciado en producción, tras aprobación explícita del
operador (el ROE la exige: `requiere_aprobacion: true`).

Es la técnica complementaria de Kerberoasting: mientras Kerberoasting
abus de SPNs de cuentas de servicio, AS-REP roasting afecta a cuentas de
usuario con una flag de cuenta mal configurada. Suele ser más silencioso
(no genera solicitudes TGS masivas contra el KDC).

## Cuándo usarla

- El grafo del dominio (F4) sugiere cuentas antiguas o de servicio que
  podrían tener la preautenticación deshabilitada.
- Kerberoasting ya se evaluó y el ROE pide minimizar ruido en el KDC.
- El ROE no la prohíbe (`tecnicas_prohibidas`) y la ventana horaria está
  activa.

## Procedimiento (alto nivel)

1. **Candidatos**: consulta el grafo y clasifica las cuentas sin
   preautenticación por antigüedad de contraseña y privilegios.
2. **Ruido**: una solicitud AS por cuenta candidata: ruido mínimo y
   localizable. Documenta el número exacto de peticiones previstas.
3. **Aprobación**: crea la petición en consola con objetivo, ruido
   estimado y referencia de ROE. NO continúes sin firma humana.
4. **Ejecución**: delega en el adaptador (`ad.asrep`). El adaptador del
   lab devuelve resultados simulados; el de producción usa el tooling
   licenciado del equipo.
5. **Evidencias**: captura la lista de cuentas vulnerables, el hash del
   volcado (en bóveda, nunca en contexto) y el resultado del crackeo
   offline.

## Criterios de éxito

- Lista de cuentas sin preautenticación registrada como evidencia.
- Al menos una contraseña débil demostrada (en lab) o ausencia de ella.
- Nada en claro en el informe: solo longitudes y fortaleza estimada.

## Reglas OPSEC

- Limita las peticiones AS a las cuentas candidatas confirmadas: no
  barren todo el dominio "por si acaso".
- Las cuentas Tier-0 sin preautenticación son hallazgo crítico por sí
  mismas: regístralas aunque no se crackee el hash.
- El ruido real queda registrado por la auditoría: revísala antes de
  repetir.

## Evidencias a capturar

| Evidencia | Tipo | Contenido mínimo |
|---|---|---|
| Lista de cuentas sin preauth | JSON | cuentas, flag, antigüedad de contraseña |
| Petición de aprobación | JSON | id de aprobación y firma del operador |
| Resultado del adaptador | JSON | cuentas crackeadas (SIN hashes en claro) |

## Receta de verificación (para el blue team)

El hallazgo se verifica reejecutando la detección: enumerar cuentas con
`UF_DONT_REQUIRE_PREAUTH` y confirmar que la corrección (habilitar la
preautenticación Kerberos) elimina la exposición. La detección del
ataque (peticiones AS-REP sin preauth, id 4768 sin campo preauth) debe
disparar una alerta en el SIEM del cliente tras la corrección.
