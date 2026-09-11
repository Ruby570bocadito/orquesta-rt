# Núcleo Python — Orquestador, MCP y memoria

Código cerrado. Véase el README raíz para la vista general.

## Comandos

```bash
pip install -r requirements.txt

# Tests del boundary, la memoria y las integraciones (sin dependencias de LLM)
python -m pytest tests/ -v

# Caso de demostración (recorre las rutas reales del núcleo)
python -m orchestrator.cli demo
python -m orchestrator.cli estado caso_demo_acme
python -m orchestrator.cli informe caso_demo_acme

# API del orquestador (backend de la consola en modo live)
python -m orchestrator.cli servidor --puerto 8000

# Servidores MCP
python -m mcp.recon_server --dominios acme-demo.local,lab.acme-demo.local --cidrs 10.30.0.0/24
python -m mcp.evidence_server --caso casos/caso_demo_acme.db
python -m mcp.osint_server
python -m mcp.c2_adapter_server          # integraciones REALES (Sliver/Mythic/Metasploit)

# Lab local (objetivo de práctica autorizado del propio despliegue)
docker compose -f lab/docker-compose.lab.yml up -d
```

## Variables de entorno

Copiar `.env.example` a `.env`. Las críticas en producción:

- `CLAVE_CASO` — clave HMAC para firmar evidencias (gestor de secretos on-prem).
- `POLITICA_SALIDA` — `perimetro` (nada sale de la red) o `hibrido`.
- `API_LOCAL_BASE` / `MODELO_LOCAL` — vLLM u Ollama.
- `API_FRONTERA_BASE` / `API_FRONTERA_CLAVE` / `MODELO_FRONTERA` — modelo de frontera opcional.
- `HIBP_API_KEY` — clave gratuita de haveibeenpwned.com para la fase F1 (filtraciones).

### Integraciones reales (F3–F6)

La plataforma NO trae exploits ni payloads propios: orquesta las herramientas
estándar del sector mediante sus APIs oficiales, configuradas por el operador
contra sus propias instancias en entornos autorizados (ROE firmado).

| Integración | Variables | API usada | Fase |
|---|---|---|---|
| Metasploit | `MSF_HOST` `MSF_PORT` `MSF_SSL` `MSF_USER` `MSF_PASS` | MSG-RPC (`module.execute`, `session.*`) | F3 explotación, F5 postex |
| Sliver C2 | `SLIVER_CONFIG` (fichero del operador) o `SLIVER_HOST` `SLIVER_PORT` `SLIVER_TOKEN` | gRPC oficial vía `sliver-py` (instalar aparte: `pip install sliver-py`) | F5 C2 |
| Mythic C2 | `MYTHIC_URL` `MYTHIC_TOKEN` | GraphQL oficial (`callback`, `createTask`) | F5 C2 |
| Active Directory | `LDAP_HOST` `LDAP_PUERTO` `LDAP_SSL` `LDAP_BIND_DN` `LDAP_BIND_CLAVE` `LDAP_BASE_DN` | LDAP v3 (`ldap3`): usuarios, grupos, SPNs | F4 rutas DA |
| Phishing | `SMTP_HOST` `SMTP_PUERTO` `SMTP_USUARIO` `SMTP_CLAVE` `SMTP_REMITENTE` `SMTP_TLS` | SMTP (envío de campañas autorizadas) | F6 |

Reglas transversales:

- Sin configuración, cada integración devuelve el **requisito exacto** en el
  campo `error`: la consola lo documenta y las fases lo registran como
  evidencia. Nunca se simulan éxitos ni telemetría.
- Toda tarea/retirada/exploit pasa por el boundary de guardrails y exige
  **firma humana** en la cola de aprobaciones de la consola.
- Las credenciales viven solo en el entorno del backend; la consola ve
  boleanos y direcciones, jamás secretos.
- `RHOSTS` de cualquier módulo Metasploit se valida contra el alcance del ROE
  antes de ejecutar (defensa en profundidad: boundary + transporte).

## Nota sobre F3-F6

Los agentes de F3 (acceso inicial), F4 (escalada AD), F5 (C2) y F6 (phishing)
coordinan **integraciones reales** (tabla anterior) y no contienen payloads:
los módulos de explotación corren en el Metasploit del operador, los agentes
existen en su Sliver/Mythic y las campañas salen por su SMTP. Toda acción de
estos módulos pasa por el boundary y exige firma humana.
