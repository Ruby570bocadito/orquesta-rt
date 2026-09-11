# OrquestaRT — Qué es y cómo funciona (explicación para alguien de fuera)

> Esta página explica el proyecto como se la contaría a una persona externa:
> qué es, para qué sirve, cómo funciona por dentro y cómo se usa. Si buscas
> la demo con capturas y GIF, está en [docs/DEMOSTRACION.md](DEMOSTRACION.md);
> la arquitectura técnica, en [docs/ARQUITECTURA.md](ARQUITECTURA.md).

## 1. Qué es, en una frase

OrquestaRT es una plataforma web **on-prem** que dirige un agente de IA para
ejecutar pruebas de red team ( hacking ético autorizado ) **paso a paso,
dentro de un perímetro legal firmado y siempre bajo control humano**.

## 2. El problema que resuelve

Un agente de IA con herramientas ofensivas (escaneos, explotación…) es
peligroso si se le suelta solo: puede salirse del alcance, hacer ruido de más
o ejecutar algo que el cliente nunca autorizó. Los equipos red team reales
trabajan al revés: primero firman unas reglas de compromiso (ROE), luego
ejecutan con cuidado, y todo queda documentado para el cliente. OrquestaRT
traslada esa disciplina al agente: **la IA propone, el ROE dispone y el
operador humano firma cada decisión crítica**.

## 3. Para quién es

- **Equipos red team / pentesting** que quieren acelerar el trabajo repetitivo
  (reconocimiento, enumeración, pruebas de acceso) sin ceder el control.
- **Equipos purple team** que además quieren dejar registrada la cobertura de
  detección: qué vio el blue team de cada técnica.
- **Empresas** que necesitan la evidencia auditada de que las pruebas se
  hicieron dentro del alcance firmado — la plataforma genera ese registro por
  diseño, no al final a mano.

No es una herramienta de ataque "lista para lanzar": el laboratorio que
incluye es local y de juguete; contra objetivos reales las herramientas se
conectan vía skills, y nada se ejecuta sin tu firma.

## 4. Cómo funciona por dentro (3 piezas)

```
┌────────────────────┐   ┌─────────────────────┐   ┌──────────────────┐
│ Consola (Next.js)  │──▶│ Orquestador (FastAPI │──▶│ Lab objetivo     │
│ :3000 — lo que ves │   │ + LangGraph)  :8000  │   │ (HTTP) :8080     │
└────────────────────┘   └─────────────────────┘   └──────────────────┘
                                   │
                                   ▼
                         Guardián (boundary): el ROE es código.
                         Evalúa CADA tool call antes de ejecutarla.
```

1. **Consola** (`:3000`): la web del operador. Alta del primer usuario,
   gestión de casos, aprobaciones, hallazgos, evidencias, métricas y
   exportación de entregables. Todo en español, todo en vivo.
2. **Orquestador** (`:8000`): el cerebro en Python. Un grafo LangGraph recorre
   las fases del ciclo ofensivo (F0 scoping → F7 cierre). Antes de cada
   acción del agente, el **guardián** comprueba el ROE máquina-legible del
   caso: alcance (dominios/CIDRs), exclusiones, técnicas vetadas, techo de
   ruido y ventana horaria. Fuera del alcance → denegado y registrado en la
   auditoría inmutable.
3. **Control humano real**: las técnicas sensibles generan una **aprobación**
   y el ciclo se detiene hasta que un operador la firma. Hay kill switch
   (parada de emergencia) que deniega todo al instante. Nada avanza solo.

El modelo de IA (GLM) llega por un puente local con su propio token; los
resultados de cada acción quedan como **evidencias con cadena de custodia
firmada (SHA-256 + HMAC)**, verificables después.

## 5. Qué es capaz de hacer

- **Ciclo completo F0→F7** con ejecución fase a fase, cada una con su
  intención, y todo registrado.
- **OSINT pasivo real** (F1): certificados de transparencia (crt.sh), DNS,
  Wayback Machine, transferencias de zona (AXFR), postura SPF/DMARC/DKIM y
  robots.txt — con saneado anti-inyección de todo el contenido externo.
- **Grafo de relaciones del caso** (pestaña Objetivos → grafo): activos
  conectados solo por relaciones observadas (subdominios, mismo activo en dos
  capas, hallazgos asociados); lo no conectado se muestra como aislado y los
  hallazgos sin nodo se declaran — nada inventado.
- **Herramientas reales acotadas**: reconocimiento, enumeración y explotación
  controlada contra el alcance del ROE; el lab local permite probar todo sin
  tocar nada externo.
- **Integraciones con el arsenal del equipo** (nunca simuladas): Sliver /
  Mythic / Metasploit por sus APIs oficiales para C2 y explotación, LDAP real
  para enumeración de Active Directory (usuarios, grupos, SPNs), SMTP propio
  para envíos de phishing autorizados con doble firma humana. Sin
  credenciales, la fase documenta el requisito en lugar de fingir datos.
- **Gestión del programa, no solo del ataque**: matriz de cobertura MITRE
  ATT&CK entre campañas, técnicas recurrentes, y por caso una capa
  importable en ATT&CK Navigator.
- **Ciclo purple team**: marcas de detección (detectado / no detectado /
  prevenido) por hallazgo, métricas de cobertura de detección y paquete con
  esqueletos de reglas Sigma cuando la fuente de logs es de conocimiento
  público (nunca inventados).
- **Entregables con un clic**: informe Markdown/HTML, custodia JSON,
  respaldo ZIP del caso, capa ATT&CK Navigator, paquete purple team y matriz
  de cobertura entre campañas en CSV.
- **Notificaciones webhook firmadas** (HMAC-SHA256) para hallazgos,
  aprobaciones y parada de emergencia, con registro de entregas y reintentos.
- **Operación seria**: auditoría inmutable de sistema, respaldo completo en
  caliente de todas las bases (VACUUM INTO + manifiesto SHA-256), control de
  coste por tokens, roles admin/operador, contraseñas scrypt y JWT.

## 6. Cómo se usa (flujo real de un operador)

1. `./install.sh && ./start.sh` → abres `http://localhost:3000`.
2. La primera pantalla pide **el alta del primer operador** (queda como
   admin). Desde ahí, otros admins darán de alta al resto.
3. **Casos → Nuevo engagement**: nombre, cliente, dominios/CIDRs en alcance,
   exclusiones, técnicas prohibidas, techo de ruido y ventana horaria. Ese
   formulario firma el ROE que el guardián aplicará.
4. **Ejecutar fase** (o Ctrl+K): el agente ejecuta la fase actual; si
   necesita una técnica sensible, se detiene y aparece en **Aprobaciones**
   con su justificación; tú decides.
5. Los resultados van apareciendo: **Hallazgos** (con severidad y técnica
   ATT&CK), **Evidencias** firmadas, actividad en vivo. Puedes marcar qué
   detectó el blue team en cada hallazgo.
6. Al cerrar: **Exportar** → informe para el cliente, custodia verificada,
   capa ATT&CK Navigator, paquete purple team.
7. Entre campañas: **Cobertura ATT&CK** responde qué se ha ejercitado en
   todo el programa y dónde se repiten las debilidades.

## 7. Por qué está construido así

- **El ROE como código**, no como PDF: es lo único que hace defendible
  delegar acciones en un agente.
- **Operator-in-command**: la IA nunca tiene la última palabra; el diseño del
  grafo lo impide en lugar de pedirlo amablemente.
- **Nada de simulaciones**: cada hallazgo, evidencia o métrica procede de una
  acción real ejecutada y registrada; lo que no hay, no se pinta.
- **On-prem primero**: el despliegue no exige enviar nada fuera; el único
  servicio externo opcional es el modelo de IA, por un puente con token local
  y con coste visible.

## 8. Requisitos y límites

- Linux con Python 3.11+ y Node 20+; todo corre en tu máquina (127.0.0.1).
- El lab incluido (`:8080`) es intencionadamente vulnerable y SOLO local;
  sirve para aprender y para verificar la plataforma, no es un arma.
- Contra sistemas reales, el uso exige autorización firmada del propietario;
  la plataforma lo recuerda en cada pantalla y lo audita.

### Lo que NO es (por diseño)

- **No trae un C2 propio**: orquesta los frameworks del equipo (Sliver,
  Mythic, Metasploit) por sus APIs oficiales. Fabricar un implante propio
  está fuera del alcance de una consola de mando.
- **No fabrica métricas**: sin infraestructura SMTP conectada no hay cifras
  de phishing; sin proveedor de filtraciones licenciado no hay datos de
  brechas; sin controlador de dominio en el alcance, el módulo AD devuelve
  el requisito exacto. Lo que no hay, se documenta — no se pinta.

### El arsenal ofensivo (v20)

La v20 incorporó el **Arsenal**: evasión de detección, persistencia y
Active Directory ofensivo como capacidades de primera clase, ejecutables y
verificables en el lab con la misma disciplina del resto de la plataforma:

- **Evasión verificada (no prometida)**: genera artefactos con
  transformaciones criptográficas reales (AES-256-CBC con PBKDF2 de 100k
  iteraciones, XOR en cascada, troceado de blobs) y los mide contra un
  motor de firmas REAL (YARA, el mismo componente de matching estático que
  usan los EDR). Un artefacto solo se marca "evasión VERIFICADA" si cae a
  0 detecciones Y el round-trip reconstruye el payload byte a byte
  (el loader Python se ejecuta de verdad en un subprocess). Todo queda
  custodiado con SHA-256 y se puede re-escanear después.
- **Persistencia real del lab**: técnicas ATT&CK implantadas de verdad en
  el host del lab (hook de `.bashrc` T1546.004, hook de arranque Python
  T1546.016, unidad systemd T1543.002, clave SSH propia T1098.004) con
  prueba de activación real (shell interactivo, arranque de intérprete,
  análisis de unidad) y retirada con verificación de ausencia. Para
  Windows/cron genera artefactos con sintaxis y hash reales; para
  objetivos reales, las integraciones C2 conectadas. Implantar exige firma
  humana; retirar es higiene y se fomenta.
- **AD ofensivo con impacket**: kerberoasting (TGS reales por SPN, hashes
  John), AS-REP roast, DCSync (replicación DRSUAPI) y pass-the-hash (SMB
  con hash NT) contra el controlador del alcance del ROE; lecturas LDAP de
  LAPS, gMSA, trusts y rutas a DA derivadas solo de `memberOf` declarado.
  Sin DC configurado se muestra el requisito exacto — jamás datos
  inventados.
- **El boundary manda igual**: toda acción del arsenal pasa por el mismo
  boundary de guardrails que las herramientas del agente (scope del ROE,
  política, ventana horaria, techo de ruido, firma humana) y queda en la
  auditoría con la identidad del operador.

### Ronda v21: planificación threat-led, grafo AD profundo, intel y despliegue

- **Planificación threat-led (estilo Atomic Red Team)**: la vista *Cadenas*
  define cadenas de ataque completas (intrusión AD de extremo a extremo,
  acceso web + postex, phishing guiado, evasión y sigilo). Cada paso es una
  técnica ATT&CK con una herramienta REAL del boundary (o el aviso honesto
  de "guion manual"), su ruido estimado exacto —el mismo número que exigirá
  el guardrail— y la detección que debería ver el blue team. Al contrastar
  una cadena con tu caso, cada paso queda como *ejercitado* (solo si hay
  hallazgo/evidencia real con esa técnica), *disponible* o *manual*, y el
  plan se custodia como evidencia firmada.
- **RBAC multi-tenant**: cuatro roles con jerarquía (admin > gestor >
  operador > lector) y organizaciones (tenants) que aíslan los casos: el
  rol y la organización viajan FIRMADOS en el JWT y el aislamiento se
  aplica en la API (deny-by-default: un lector no puede ejecutar nada ni
  por accidente; una cuenta de la org A no ve los casos de la org B ni
  listando). Las altas de cuentas y organizaciones quedan en la auditoría
  de sistema.
- **SSO OIDC real**: login federado (Keycloak, Entra, Auth0...) con flujo
  authorization-code + PKCE, discovery, y verificación CRIPTOGRÁFICA del
  id_token (RS256 vía JWKS, iss/aud/exp/nonce). Alta JIT opcional como
  lector (mínimo privilegio) y vinculación con cuentas locales existentes.
  Sin IdP configurado, la consola muestra usuario/contraseña como siempre.
- **BloodHound CE**: la plataforma habla con tu instancia por su API REST
  oficial (login, dominios disponibles, búsqueda de objetos, shortest-path
  del grafo CE ≥ 6.0). Las rutas de ataque que ves son las del servidor —
  nunca recalculadas ni inventadas.
- **MISP (threat intel)**: contraste de los activos del caso contra el
  intel del equipo (attributes/restSearch), eventos recientes por tag y
  exportación de hallazgos como evento MISP. Las coincidencias entran
  custodiadas en el caso.
- **Despliegue productivo Docker/K8s**: imagen del orquestador multi-stage
  y no-root con HEALTHCHECK real, `integraciones/` incluido (bug del
  Dockerfile anterior corregido), cuentas y casos persistidos en el volumen
  de datos; compose endurecido (no-new-privileges, límites de recursos,
  healthchecks de consola) y manifiestos Kubernetes con sondas contra
  `/api/salud`, `readOnlyRootFilesystem`, PVC y Ingress TLS (ver
  `deploy/README.md`).
