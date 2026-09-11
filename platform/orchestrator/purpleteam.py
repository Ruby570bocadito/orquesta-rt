"""Paquete purple team del caso: resultados de detección + esqueletos Sigma.

Inspirado en el patrón VECTR (registro ofensa↔defensa por técnica) y en
el movimiento detection-as-code (Sigma): el paquete documenta, para cada
hallazgo REAL del caso, el resultado de detección registrado por el
equipo azul y, cuando la plataforma tiene conocimiento real y público de
la fuente de logs de esa técnica, un esqueleto de regla Sigma para que el
operador lo ajuste a su entorno.

Política anti-invención: la plataforma NO genera reglas Sigma para
técnicas cuya fuente de logs desconoce — el informe lo indica
explícitamente. Los esqueletos incluidos usan mapeos ampliamente
documentados (Windows Security EventLog: TGS 4769, AS-REQ 4768; Sysmon:
conexión de red 3) y quedan marcados `status: experimental` a la espera
del ajuste del operador.
"""
from __future__ import annotations

import io
import re
import unicodedata
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from .memory import MemoriaCaso

# Mapeo técnico→fuente de logs con conocimiento público y estable.
_FUENTES_CONOCIDAS: dict[str, dict] = {
    "T1558.003": {  # Kerberoasting
        "logsource": {
            "product": "windows",
            "service": "security",
            "definition": ("Requiere auditoría de solicitudes de tickets Kerberos "
                           "(EventID 4769) habilitada en los controladores de dominio."),
        },
        "selection_evento": {"EventID": 4769},
        "pistas": [
            "TicketEncryptionType '0x17' (RC4) en la solicitud del ticket",
            "TargetUserName|endswith: cuenta/SPN observado en el hallazgo",
            "Rafaga de 4769 desde un único origen en ventana corta",
        ],
        "campo_activo": "TargetUserName",  # el activo del hallazgo suele ser el SPN/cuenta
    },
    "T1558.004": {  # AS-REP Roasting
        "logsource": {
            "product": "windows",
            "service": "security",
            "definition": ("Requiere auditoría de eventos de autenticación Kerberos "
                           "(EventID 4768) en los controladores de dominio."),
        },
        "selection_evento": {"EventID": 4768},
        "pistas": [
            "PreAuthType '0' en el 4768 (solicitud sin preautenticación)",
            "TicketEncryptionType '0x17' (RC4)",
            "TargetUserName|endswith: cuenta observada en el hallazgo",
        ],
        "campo_activo": "TargetUserName",
    },
    "T1557.001": {  # LLMNR / NBT-NS poisoning
        "logsource": {
            "category": "network_connection",
            "product": "windows",
            "service": "sysmon",
            "definition": ("Conexiones salientes anómalas tras resolución LLMNR/NBT-NS "
                           "(Sysmon EventID 3); complementar con monitorización "
                           "específica de LLMNR/NBT-NS en la red."),
        },
        "selection_evento": {"EventID": 3},
        "pistas": [
            "DestinationHostname resuelto sin consulta DNS legítima previa",
            "Image|endswith: ejecutable no esperado iniciando conexiones SMB/HTTP",
        ],
        "campo_activo": "DestinationHostname",
    },
}

_RE_TECNICA = re.compile(r"^T\d{4}(?:\.\d{3})?$")
_TITULO_DETECCION = {
    "detectado": "Detectado",
    "no_detectado": "No detectado (punto ciego)",
    "prevenido": "Prevenido (bloqueado)",
    "pendiente": "Pendiente de verificación",
}
_ORDEN_SEV = {"critica": 0, "alta": 1, "media": 2, "baja": 3, "informativa": 4}


def _slug(texto: str, maximo: int = 42) -> str:
    normalizado = unicodedata.normalize("NFKD", texto)
    ascii_txt = normalizado.encode("ascii", "ignore").decode("ascii")
    slug = re.sub(r"[^A-Za-z0-9]+", "-", ascii_txt).strip("-").lower()
    return (slug[:maximo].rstrip("-")) or "hallazgo"


def _regla_sigma(hallazgo: dict, engagement_id: str) -> str | None:
    """Esqueleto Sigma del hallazgo, o None si la plataforma no conoce la
    fuente de logs de la técnica (política anti-invención)."""
    tecnica = str(hallazgo.get("tecnica_mitre") or "").strip().upper()
    if not _RE_TECNICA.match(tecnica) or tecnica not in _FUENTES_CONOCIDAS:
        return None
    fuente = _FUENTES_CONOCIDAS[tecnica]
    regla_id = uuid.uuid5(uuid.NAMESPACE_URL,
                          f"orquestart:{engagement_id}:{hallazgo['id']}")
    fecha = str(hallazgo.get("creado_en", ""))[:10] or datetime.now(timezone.utc).date().isoformat()
    descripcion = (hallazgo.get("descripcion") or hallazgo.get("titulo") or "").strip()

    logsource = fuente["logsource"]
    lineas: list[str] = [
        f"title: {hallazgo['titulo']}",
        f"id: {regla_id}",
        "status: experimental",
        "description: |",
    ]
    for parrafo in (descripcion or hallazgo["titulo"]).splitlines():
        lineas.append(f"    {parrafo.strip()}")
    lineas += [
        f"    Hallazgo {hallazgo['id']} del engagement {engagement_id} "
        "(OrquestaRT). Ajusta la selección a tu entorno antes de desplegar.",
        "author: Operador OrquestaRT",
        f"date: {fecha}",
        "tags:",
        f"    - attack.{tecnica.lower()}",
        "logsource:",
    ]
    for clave, valor in logsource.items():
        lineas.append(f"    {clave}: {valor}")
    lineas.append("detection:")
    lineas.append("    selection_evento:")
    for campo, valor in fuente["selection_evento"].items():
        lineas.append(f"        {campo}: {valor}")

    activo = str(hallazgo.get("activo") or "").strip().strip("'\"")
    condicion = "selection_evento"
    if activo:
        campo = fuente["campo_activo"]
        lineas.append("    selection_entorno:")
        lineas.append(f"        {campo}|endswith: '{activo}'")
        condicion = "selection_evento and selection_entorno"
    else:
        lineas.append("    # sin activo registrado: añade una selección con")
        lineas.append("    # la cuenta/host concreto observado en tu entorno")
    lineas.append(f"    condition: {condicion}")
    lineas.append("")
    lineas.append("# Pistas de ajuste documentadas para esta técnica:")
    for pista in fuente["pistas"]:
        lineas.append(f"#   - {pista}")
    return "\n".join(lineas) + "\n"


def construir_paquete_purple(engagement_id: str,
                             memoria: MemoriaCaso) -> tuple[bytes, dict]:
    """ZIP con informe purple team + esqueletos Sigma del caso real.

    Devuelve (zip_bytes, resumen) donde resumen contiene el número de
    hallazgos, de reglas generadas y de técnicas sin fuente conocida.
    """
    fila = memoria.obtener_engagement(engagement_id)
    if fila is None:
        raise KeyError(f"Engagement {engagement_id} no existe")
    hallazgos = [dict(h) for h in memoria.listar_hallazgos(engagement_id)]
    if not hallazgos:
        raise ValueError("sin hallazgos")

    hallazgos.sort(key=lambda h: _ORDEN_SEV.get(h.get("severidad", "informativa"), 4))
    evidencias = memoria.listar_evidencias(engagement_id)
    por_hallazgo: dict[str, list[dict]] = {}
    for e in evidencias:
        d = dict(e)
        if d.get("hallazgo_id"):
            por_hallazgo.setdefault(d["hallazgo_id"], []).append(d)

    reglas: dict[str, str] = {}
    sin_fuente: list[str] = []
    for h in hallazgos:
        yml = _regla_sigma(h, engagement_id)
        if yml is None:
            tecnica = str(h.get("tecnica_mitre") or "").strip().upper()
            if tecnica:
                sin_fuente.append(tecnica)
            continue
        reglas[h["id"]] = yml

    generados = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lineas = [
        f"# Informe purple team — {fila['nombre']}",
        "",
        f"**Cliente:** {fila['cliente']}  ",
        f"**Engagement:** `{engagement_id}`  ",
        f"**Generado:** {generados}  ",
        "",
        "Este paquete cruza los hallazgos reales del caso con el resultado de",
        "detección registrado por el equipo azul (patrón VECTR) y añade",
        "esqueletos de reglas Sigma cuando la plataforma tiene conocimiento",
        "real de la fuente de logs de la técnica. Nada de lo incluido se",
        "inventa: las reglas sin fuente conocida se documentan como pendientes",
        "para que las construya el operador con su propia telemetría.",
        "",
        "| Hallazgo | Severidad | Técnica | Detección (blue team) | Evidencias |",
        "|---|---|---|---|---|",
    ]
    for h in hallazgos:
        evs = por_hallazgo.get(h["id"], [])
        det = _TITULO_DETECCION.get(h.get("deteccion", "pendiente"), "—")
        tecnica = f"`{h['tecnica_mitre']}`" if h.get("tecnica_mitre") else "—"
        n_evs = str(len(evs)) if evs else "0"
        lineas.append(f"| {h['titulo']} | {h['severidad']} | {tecnica} | {det} | {n_evs} |")
    lineas += ["", "## Esqueletos Sigma", ""]
    if reglas:
        lineas.append(f"Reglas generadas: **{len(reglas)}** "
                      "(directorio `sigma/`, `status: experimental`). Ajusta la "
                      "selección a tu entorno y desplázalas vía tu pipeline de "
                      "detection-as-code.")
    else:
        lineas.append("Ninguna técnica del caso tiene fuente de logs conocida "
                      "por la plataforma: no se emiten reglas (política "
                      "anti-invención).")
    if sin_fuente:
        lineas.append("")
        lineas.append("Técnicas sin esqueleto Sigma (fuente de logs no mapeada): "
                      + ", ".join(f"`{t}`" for t in sorted(set(sin_fuente))) + ".")
    lineas += ["", "## Verificación recomendada por hallazgo", ""]
    for h in hallazgos:
        lineas.append(f"### {h['titulo']}")
        lineas.append("")
        if h.get("recomendacion"):
            lineas.append(f"{h['recomendacion']}")
        else:
            lineas.append("Sin recomendación registrada para este hallazgo.")
        evs = por_hallazgo.get(h["id"], [])
        if evs:
            lineas.append("")
            lineas.append("Evidencias firmadas asociadas: "
                          + ", ".join(f"`{e['id']}`" for e in evs) + ".")
        lineas.append("")

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("informe_purple.md", "\n".join(lineas))
        zf.writestr("sigma/README.md",
                    "# Esqueletos Sigma del caso\n\nReglas `experimental` "
                    "generadas desde hallazgos reales. Completa la selección "
                    "para tu entorno antes de desplegar.\n")
        for h_id, yml in reglas.items():
            h = next(x for x in hallazgos if x["id"] == h_id)
            nombre = f"{(h.get('tecnica_mitre') or 'tecnica').upper()}-{_slug(h['titulo'])}.yml"
            zf.writestr(f"sigma/{nombre}", yml)
    resumen = {"hallazgos": len(hallazgos), "reglas": len(reglas),
               "sin_fuente": len(set(sin_fuente))}
    return buffer.getvalue(), resumen
