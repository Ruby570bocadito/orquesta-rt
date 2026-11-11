# PROTOCOLO — Sistema multiagente OrquestaRT

Fuente de verdad del equipo de agentes. Lo mantiene **DIR** (cambios vía "Propuestas" en tu estado). Complementa a `OWNERSHIP.md` (zonas por ruta) y `ROADMAP.md` (cola operativa). Cada run de cron arranca sin memoria: todo lo que necesitas está aquí o en los archivos que este protocolo manda crear.

## 1. Principios

1. **El claim es el único cerrojo real.** Un plan que hay que leer no coordina nada; un `git push` rechazado sí. Se reclama una tarea haciendo push de un archivo de claim. Si el push falla, alguien llegó antes: `pull --rebase` y coge otra.
2. **Zonas por ruta.** Cada rol solo crea / modifica / borra en SUS rutas (ver `OWNERSHIP.md`). Fuera de tu zona, se pide por "Peticiones".
3. **Ciclo por tarea.** `pull --rebase` antes de CADA tarea y antes de CADA push. Siempre.
4. **Un único informe vivo por agente**, que se SOBRESCRIBE (`docs/agentes/estado/<ID>.md`). Cero archivos nuevos por ronda. El estado no es un log: es la foto actual.
5. **Un solo Director (DIR)**, único escritor de la cola y del roadmap de producto.
6. **Basura fuera de git.** Borradores, labs y evidencias de prueba en `.agent-tmp/` (en `.gitignore`).
7. **Memoria en git, no en la sesión.** Cada run de cron arranca SIN memoria de los anteriores. Todo lo que un agente necesita recordar vive en el repo: `estado/`, `PROGRESS.md`, claims y hallazgos. Si no está en git, no existe.
8. **Si no hay trabajo para tu ID, no lo inventes.** Escribe una línea en tu estado y terminas. Esta es la regla que impide que el repo se llene de "mejoras" que nadie pidió (precondición de arranque).

## 2. Zona sagrada

OrquestaRT ejecuta técnicas de red team reales bajo un *boundary* de seguridad. Ese boundary y la identidad son la razón de que la herramienta sea legal y auditable. **Ningún agente los reescribe de forma autónoma.**

| Ruta | Por qué |
|---|---|
| `platform/orchestrator/guardrails.py` | El boundary ROE. Vive FUERA del modelo a propósito (OWASP LLM01). Un agente no lo relaja. |
| `platform/orchestrator/auth.py` | Identidad: scrypt + JWT, RBAC, deny-by-default. |
| `platform/orchestrator/sso.py` | OIDC / PKCE / verificación JWKS. |
| `platform/orchestrator/memory.py` → cadena de custodia | Auditoría append-only + HMAC encadenado. La integridad de la evidencia depende de esto. |
| `platform/roe/` | Plantilla de ROE máquina-legible. |

- SEG puede **leer, auditar y abrir un hallazgo** sobre estas rutas.
- Solo DIR, tras **firma humana explícita**, promueve una tarea que las modifique; esa tarea va SIEMPRE por PR revisado por el humano — nunca push directo.
- Cualquier agente que detecte un claim sobre estas rutas que no sea de SEG (hallazgo) o DIR (tarea firmada) lo anota como incidente en su estado.
- Las capacidades ofensivas (`ad.py`, `persistencia.py`, `evasion.py`, `transportes.py`) se tocan solo para el **laboratorio local** (`127.0.0.0/8`, dominio AD de lab). Ningún agente añade payloads operativos contra terceros ni amplía el scope por defecto.

## 3. Estructura del repo de agentes

```
docs/agentes/
├── PROTOCOLO.md          Este protocolo (lo mantiene DIR)
├── OWNERSHIP.md          Tabla de zonas (lo mantiene DIR)
├── ROADMAP.md            Cola operativa de tareas (único escritor: DIR)
├── PROGRESS.md           Índice de progreso global (lo mantiene DIR)
├── claims/               Cerrojos vivos: un archivo por tarea reclamada
│   ├── running-<ID>      Lock de sesión: existe mientras el agente trabaja
│   └── <slug>.md         Claim de tarea: quién, cuándo, qué ruta
├── estado/
│   └── <ID>.md           Informe vivo de cada agente (se SOBRESCRIBE)
└── hallazgos/
    └── H-<nnn>-<slug>.md  Hallazgos de TEST, abiertos hasta que se cierran
```

## 4. El ciclo por tarea (obligatorio, sin excepciones)

```
1. git pull --rebase origin main
2. Lee docs/agentes/estado/DIR.md PRIMERO, luego los estados de los demás,
   OWNERSHIP.md, la cola ROADMAP.md y los hallazgos dirigidos a tu ID.
3. Elige la primera tarea de la cola dirigida a tu ID (las marcadas ALTA primero).
   - Hallazgos CRÍTICO/ALTO dirigidos a ti van ANTES que la cola.
   - Si no hay nada para tu ID: escribe una línea en tu estado y TERMINA (§1.8).
4. Comprueba que la tarea no está ya hecha (git log, grep, estructura).
5. CLAIM: crea claims/<slug>.md con tu ID y timestamp UTC, y haz push.
   - Si el push es rechazado → pull --rebase, alguien te ganó, vuelve al paso 3.
6. Trabaja la tarea entera. Código de producción, sin mocks fuera de tests,
   sin TODOs, textos visibles en los dos idiomas donde aplique.
7. pull --rebase. Pasa las verificaciones (§6). Si fallan, arréglalo antes de push.
8. Commit con el slug entre paréntesis. Push (HEAD:main o PR según §8).
9. Borra tu claim de la tarea. Actualiza tu estado. Siguiente tarea.
```

**Sesión larga:** completa varias tareas seguidas, cada una con su ciclo completo, hasta agotar las tareas razonables de tu zona o llegar a **3 tareas por sesión**.

## 5. Formato de los archivos de claim

`claims/<slug>.md`:
```
ID: BACK
Tarea: m2-neo4j-ingesta
Ruta: platform/orchestrator/graph.py
Inicio (UTC): 2026-11-11T08:04:00Z
```

`claims/running-<ID>` (lock de sesión, contenido mínimo):
```
Inicio (UTC): 2026-11-11T08:00:12Z
```

**Caducidad automática.** Antes de reclamar, cualquier agente borra los claims con más de **90 minutos** de antigüedad. Si borras el claim de una tarea, comprueba con `git log` si ese trabajo quedó a medias y anótalo en tu estado para que DIR lo recoloque. El lock `running-<ID>` caduca a las **2 horas**.

## 6. Verificaciones antes de cada push

- **Backend / Python** (BACK, INTEG, SEG, PUL): `ruff check platform` y `python -m pytest -q` deben pasar. Baseline actual: **587 passed / 9 skipped / 0 failed** — ningún push puede bajar ese número de "passed" ni subir "failed".
- **Frontend** (FRONT): `tsc --noEmit` y `eslint` limpios; el build de Next.js compila.
- **DOC:** las capturas se corresponden con la consola actual; los enlaces del README no están rotos.
- **TEST:** no modifica producto; sus tests e2e pasan sobre el código actual.

## 7. Los dos guardas que hacen seguro el cron

1. **Precondición de arranque (§1.8).** Primer paso tras el pull: ¿hay tarea para mi ID? No → una línea en el estado y fuera. Impide trabajo inventado.
2. **Lock anti-solape.** Al arrancar, si existe `claims/running-<MI-ID>` con menos de 2 h → mi yo anterior sigue vivo, salgo sin hacer nada. Si no existe o caducó, lo creo (push) y trabajo; al terminar lo borro. Impide dos instancias del mismo rol pisándose.

## 8. Push directo vs PR

- **Van por PR (mergea el humano):** BACK, INTEG, SEG, y cualquier tarea que toque la zona sagrada.
- **Van a `main` directo:** FRONT, DOC, TEST, PUL, DIR — no tocan la lógica ofensiva ni el boundary.

## 9. Comunicación entre agentes

- **DIR es la fuente de verdad.** Todos leen `estado/DIR.md` antes que cualquier otro estado. Si tu lectura del repo contradice a DIR, manda DIR; anota la discrepancia en "Propuestas" de tu estado.
- Para pedir algo fuera de tu zona, usa la sección **"Peticiones"** de tu estado, dirigida a un ID. DIR las recoge y las promueve a la cola.
- Un bug o fallo de seguridad fuera de tu zona → "Peticiones" para SEG, no lo arreglas tú.
- La fila del README / una captura nueva → "Peticiones" para DOC.

## 10. Formato del informe vivo (`estado/<ID>.md`)

```markdown
# Estado — <ID>
Última sesión (UTC): <timestamp> · Semáforo: verde | amarillo | rojo

## Hecho esta sesión
- (slug) qué entregué — commit abcd123

## En curso / bloqueado
- (slug) por qué está bloqueado, qué espera

## Descartado (no volver a intentar)
- qué intenté, por qué no funciona, para que nadie lo repita

## Peticiones
- @SEG: posible path traversal en transportes.py:214
- @DOC: la vista de Continuidad cambió, hace falta captura nueva

## Propuestas (para que DIR las promueva a la cola)
- idea de tarea nueva — eje/ruta
```

La sección **"Descartado"** es obligatoria: evita que el agente de dentro de dos semanas repita un callejón sin salida.
