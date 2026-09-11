# Imagen de producción del orquestador (multi-stage, usuario no-root)
# -----------------------------------------------------------------------------
# Correcciones v21 respecto al Dockerfile anterior:
#   - se copia integraciones/ (ldap, impacket, sliver/mythic/msf, misp,
#     bloodhound): sin él la imagen arrancaba y fallaba al importar
#   - stage de builder para no llevar compiladores a la imagen final
#   - usuario no-root + HEALTHCHECK real contra /api/salud
#   - USUARIOS_DB bajo /datos para persistir las cuentas en el volumen
FROM python:3.12-slim AS builder

WORKDIR /construir
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/instalar -r requirements.txt

FROM python:3.12-slim

# Etiquetas operativas (metadatos del despliegue)
LABEL org.opencontainers.image.title="OrquestaRT - orquestador"
LABEL org.opencontainers.image.description="Núcleo Red Team orquestado por IA (operator-in-command)"
LABEL org.opencontainers.image.licenses="MIT"

# Grupo y usuario dedicados (nunca root en runtime)
RUN groupadd -r orquesta && useradd -r -g orquesta -d /app -s /usr/sbin/nologin orquesta

WORKDIR /app
COPY --from=builder /instalar /usr/local
COPY orchestrator/ ./orchestrator/
COPY integraciones/ ./integraciones/
COPY mcp/ ./mcp/
COPY skills/ ./skills/
COPY roe/ ./roe/

# Datos persistentes: casos + cuentas de operadores + skills personalizables
RUN mkdir -p /datos/casos /app/skills \
    && chown -R orquesta:orquesta /datos /app
ENV RAIZ_CASOS=/datos/casos \
    RAIZ_SKILLS=/app/skills \
    USUARIOS_DB=/datos/usuarios.db \
    PYTHONUNBUFFERED=1
VOLUME ["/datos"]

USER orquesta
EXPOSE 8000

# HEALTHCHECK REAL: el mismo endpoint que usan la consola y Kubernetes
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/salud', timeout=4).status==200 else 1)"

CMD ["uvicorn", "orchestrator.api:app", "--host", "0.0.0.0", "--port", "8000", "--timeout-graceful-shutdown", "5"]
