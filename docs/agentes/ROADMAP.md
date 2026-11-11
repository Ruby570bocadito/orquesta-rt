# ROADMAP — cola operativa de OrquestaRT

**Único escritor: DIR.** Mantener 5-10 tareas abiertas, priorizadas, de la versión en curso, respetando dependencias. Los hallazgos CRÍTICO/ALTO dirigidos a un ID van ANTES que la cola. Las urgencias (build roto, regresión en la suite) suben arriba como ALTA dirigida a un ID concreto.

Formato: `- [ ] (ID) <slug> — descripción en una línea — rutas`

## Cola

- [ ] (TEST) test-instalacion-limpia — ALTA — instalar desde cero siguiendo SOLO el README (`./install.sh && ./start.sh`) y ejecutar la primera persona "operador nuevo" — platform/tests/, docs/agentes/hallazgos/
- [ ] (BACK) neo4j-ingesta-dominio-real — ALTA — ingesta del dominio real del operador (Azure/híbrido incluido) al motor de rutas Neo4j — platform/orchestrator/graph.py, platform/integraciones/bloodhound.py
- [ ] (INTEG) colector-lab-e2e — NORMAL — ejercitar end-to-end lab/coleccion_dominio.py → ingestión en Neo4j y resolución de rutas desde la consola — platform/integraciones/bloodhound.py, lab/
- [ ] (SEG) auditoria-inicial — NORMAL — auditoría de solo lectura (hallazgos, sin reescrituras): parsers ante entradas hostiles, integridad de la custodia, anti-SSRF en webhooks, deps con CVE (pip-audit / npm audit) — docs/agentes/hallazgos/
- [ ] (FRONT) v34-verificacion-vistas — NORMAL — verificar las 18 vistas contra el backend real tras v34 (higiene con sesiones activas, acceso federado administrable), tabla de cada gráfico y responsive — src/
- [ ] (DOC) readme-v35-capturas — NORMAL — comprobar que README y galería no mienten tras los últimos cambios y regenerar las capturas de las vistas que hayan cambiado — README.md, docs/DEMOSTRACION.md
- [ ] (PUL) ci-coherencia — NORMAL — .github/workflows/ci.yml coherente con ruff + pytest (baseline 587) y dependencias sincronizadas con el uso real — .github/workflows/, pyproject.toml, package.json

## Entregado (histórico)

- (DIR) bootstrap-agentes — estructura docs/agentes/ + protocolo + cola inicial — docs/agentes/
