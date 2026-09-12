# Agente z3 — Auditoría de seguridad y revisión de código

> Carpeta oficial del agente **z3** dentro de `docs/agentes/`.
> Misión: detectar bugs y fallos de seguridad en orquesta-rt, investigar cada
> hallazgo, implementar soluciones profesionales de calidad de producción y
> dejar aquí constancia verificable de todo lo aplicado.
>
> **Índice de auditorías** (una sesión = un fichero, orden cronológico):
>
> | Sesión | Fecha | Fichero | Enfoque |
> |---|---|---|---|
> | 1 | 2026-09-12 | [`sesion-1-auditoria-seguridad.md`](sesion-1-auditoria-seguridad.md) | Auditoría integral: secretos en repo, proxy abierto, BOLA multi-tenant, revocación de sesiones, clave HMAC de custodia, SSRF, rate limiting, CSV, CORS, CSP |
> | 2 | 2026-09-12 | [`sesion-2-tls-sso-endurecimiento.md`](sesion-2-tls-sso-endurecimiento.md) | TLS seguro por defecto en 17 clientes, secuestro de cuentas SSO, `/api/salud` sin topología, STARTTLS verificado, guardia nmap, `.env.example` |
> | 3 | 2026-09-12 | [`sesion-3-v24-tercera-ronda.md`](sesion-3-v24-tercera-ronda.md) | Código v24 (MISP lab + Sigma), módulos de razonamiento/CTEM, rutas no-engagement, informe markdown, endurecimiento de puertos Docker |
> | 4 | 2026-09-12 | [`sesion-4-mcp-superficie-y-endurecimiento.md`](sesion-4-mcp-superficie-y-endurecimiento.md) | Servidores MCP (SSRF osint, saneado LLM01, TLS fail-open, paquete inarrancable), superficie OpenAPI + path-traversal del proxy, revisión de núcleo/infra restante |

## Metodología

1. **Reconocimiento**: estructura del repo, superficie expuesta (API, compose,
   proxies, MCP), convenciones del código y de los tests existentes.
2. **Barrido por rondas**: patrones peligrosos (`eval`, `shell=True`, `pickle`,
   `yaml.load`, comparaciones de secretos, lectura sin límites), rutas API
   fuera del aislamiento tenant, manejo de errores y robustez.
3. **Lectura profunda** módulo a módulo: cada hallazgo se verifica contra el
   código real (no contra suposiciones) y se clasifica por severidad.
4. **Remediación profesional**: fix mínimo, comentado con el razonamiento,
   compatible con despliegues existentes, con test de regresión que lo
   cubre. Nunca un parche cosmético.
5. **Verificación**: suite completa (`pytest tests/`) comparada contra la
   línea base del entorno; los fallos preexistentes (módulos opcionales
   `yara`/`ldap3` no instalados en la máquina de auditoría) se documentan y
   se confirman idénticos al commit base.

## Reglas de convivencia multi-agente

- Esta carpeta es SOLO del agente z3: no se tocan los ficheros de otros
  agentes (`docs/agentes/z1.md`, worklog de otros, etc.).
- `docs/agentes/z3.md` se mantiene como puntero hacia esta carpeta para no
  romper referencias de rondas anteriores.
- Los fixes se limitan al alcance de seguridad/robustez: sin refactors de
  estilo, sin cambios de API salvo los que la corrección exige.

## Estado acumulado de hallazgos

| ID | Severidad | Sesión | Estado |
|---|---|---|---|
| F1 | CRÍTICO | 1 | Remediado (BDs fuera del repo) |
| F2 | ALTO | 1 | Remediado (proxy :81 eliminado) |
| F3 | ALTO | 1 | Remediado (BOLA tenant en aprobaciones) |
| F4 | ALTO | 1 | Remediado (revocación de sesiones) |
| F5 | ALTO | 1 | Remediado (clave de custodia generada) |
| F6 | MEDIO | 1 | Remediado (SSRF webhooks) |
| F7 | MEDIO | 1 | Remediado (rate limit + bind 127.0.0.1) |
| F8 | MEDIO | 1 | Remediado (inyección fórmulas CSV) |
| F9 | MEDIO | 1 | Remediado (CORS por defecto) |
| F10 | BAJO | 1 | Remediado (CSP consola) |
| F11 | MEDIO | 2 | Remediado (TLS por defecto seguro) |
| F12 | ALTO | 2 | Remediado (vínculo SSO pre-aprobado) |
| F13 | MEDIO | 2 | Remediado (/api/salud sin topología) |
| F14 | MEDIO | 2 | Remediado (STARTTLS verificado) |
| F15 | BAJO | 2 | Remediado (guardia nmap) |
| F16 | BAJO | 2 | Remediado (.env.example) |
| F17 | MEDIO | 3 | Remediado (mapeo MITRE en informe markdown) |
| F18 | MEDIO | 3 | Remediado (techo de cuerpo en MISP lab) |
| F19 | MEDIO | 3 | Remediado (parsing entero acotado MISP lab) |
| F20 | BAJO | 3 | Remediado (comparación tiempo constante) |
| F21 | BAJO | 3 | Remediado (persistencia atómica de estado) |
| F22 | BAJO | 3 | Remediado (puertos Docker solo loopback) |
| F23 | BAJO | 3 | Remediado (nombres Sigma únicos en ZIP) |
| F24 | BAJO | 3 | Remediado (dedup de errores Sigma) |
| F25 | BAJO | 4 | Remediado (OpenAPI desactivada + guardia traversal del proxy) |
| F26 | MEDIO | 4 | Remediado (SSRF robots_txt: dominio validado + redirects fijados) |
| F27 | BAJO | 4 | Remediado (query crt.sh codificada) |
| F28 | MEDIO | 4 | Remediado (saneado LLM01 unificado en los MCP) |
| F29 | BAJO | 4 | Remediado (TLS fail-open eliminado + guardia AST) |
| F30 | MEDIO | 4 | Remediado (paquete servidores_mcp: la capa MCP ya arranca) |
