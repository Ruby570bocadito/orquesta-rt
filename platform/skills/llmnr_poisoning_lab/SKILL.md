---
nombre: llmnr_poisoning_lab
descripcion: "Playbook de laboratorio para demostrar el riesgo de resolución de nombres LLMNR/NBT-NS y captura de desafíos NTLM en un segmento aislado: detección de exposición, condiciones de consentimiento y evidencias. Contenido EDUCATIVO del lab: los comandos concretos los ejecuta el tooling licenciado del equipo vía adaptador MCP, nunca este agente."
fase: "F3_acceso_inicial"
tecnica_mitre: "T1557.001"
riesgo: "alta"
requiere_aprobacion: true
fuentes_permitidas:
  - "adaptador del lab (mock)"
  - "tooling licenciado del equipo (producción)"
---

# Skill: Envenenamiento LLMNR/NBT-NS (laboratorio)

## Propósito

Demostrar, en un segmento de red **de laboratorio y con consentimiento
explícito del cliente en el ROE**, cómo la resolución de nombres de
respaldo (LLMNR/NBT-NS, mDNS) permite a un adversario con acceso a la
red local interceptar desafíos NTLMv2 de estaciones de trabajo. Esta
skill documenta el procedimiento, las condiciones y la higiene; la
ejecución técnica corresponde SIEMPRE al adaptador MCP del lab (mock) o
al tooling licenciado en producción, tras aprobación explícita del
operador (`requiere_aprobacion: true`).

Es una técnica de acceso inicial por credenciales: no explota un
software vulnerable, sino un comportamiento por defecto de la red
Windows. Su valor para el informe es doble: riesgo técnico y riesgo de
configuración base (GBPP del cliente).

## Condiciones INNEGOCIABLES

- El ROE debe contemplar explícitamente el envenenamiento de resolución
  de nombres en el segmento objetivo. Si no lo menciona: PARAR y
  proponer una enmienda del ROE.
- El segmento debe estar aislado (lab) o ser el acordado en el ROE.
  NUNCA se envenena un segmento con activos excluidos cerca: revisa la
  lista EXCLUIDO del ROE contra el rango del segmento.
- La captura de hashes NTLMv2 exige el mismo tratamiento que
  credenciales: bóveda, sin material en claro en contexto ni informe.

## Procedimiento (alto nivel)

1. **Detección de exposición**: comprueba en el lab si LLMNR/NBT-NS
   están activos y si existen resoluciones fallidas frecuentes (nombres
   mal escritos, recursos eliminados) que un atacante explotaría.
2. **Ruido y alcance**: un responder activo se anuncia en toda la
   red del segmento: es una de las técnicas más "visibles". Documenta
   la ventana exacta propuesta (idealmente minutos, no horas).
3. **Aprobación**: crea la petición en consola con segmento, ventana
   propuesta y ruido estimado. NO continúes sin firma humana.
4. **Ejecución**: delega en el adaptador (`red.responder`). El del lab
   devuelve resultados simulados; el de producción usa el tooling
   licenciado del equipo, solo durante la ventana aprobada.
5. **Evidencias**: captura el número de respuestas enviadas, los
   desafíos capturados (recuento y fortaleza estimada tras crackeo
   offline) y las cuentas involucradas (SIN hashes en claro).

## Criterios de éxito

- Demostración de que la resolución de nombres de respaldo sigue activa.
- Recuento de desafíos NTLMv2 capturados durante la ventana aprobada.
- Recomendación concreta: deshabilitar LLMNR/NBT-NS por GPO y habilitar
  firmado SMB/LDAP para bloquear relays.

## Reglas OPSEC y de seguridad

- Ventana mínima: el responder se detiene en cuanto se capturan los
  desafíos necesarios para demostrar el riesgo. No se deja corriendo.
- Ninguna técnica de relay se ejecuta en esta skill: la captura sola
  demuestra el riesgo. El relay contra activos reales exige una skill y
  una aprobación propias.
- Si aparece tráfico de un activo excluido: detén el responder
  inmediatamente y registra el incidente en la auditoría.

## Evidencias a capturar

| Evidencia | Tipo | Contenido mínimo |
|---|---|---|
| Detección de exposición | JSON | LLMNR/NBT-NS activos, tráfico de resolución fallida |
| Petición de aprobación | JSON | segmento, ventana, ruido estimado, firma |
| Resultado del adaptador | JSON | respuestas enviadas, desafíos capturados (recuento) |
| Incidente (si procede) | JSON | activo excluido alcanzado y parada de emergencia |

## Receta de verificación (para el blue team)

El hallazgo se verifica reejecutando la detección tras la corrección:
LLMNR y NBT-NS deshabilitados por GPO, mDNS restringido, y la detección
del ataque (eventos de respuesta anómala, tráfico del responder) debe
disparar una alerta en el NDR/SIEM del cliente. El firmado SMB/LDAP se
verifica con un intento de relay controlado en lab que debe fallar.
