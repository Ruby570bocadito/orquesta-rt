"""Consolidación del informe final (cap. 4.9 del blueprint).

El agente de reporting no reconstruye: consolida la cronología registrada
desde el minuto uno. Produce markdown en español (convertible a DOCX/PDF
en la capa de empaquetado) y un HTML autocontenido imprimible con:
- resumen ejecutivo
- cronología completa
- hallazgos por severidad con mapeo MITRE ATT&CK
- recetas de verificación reproducible para el blue team
- cadena de custodia y certificado de higiene
"""
from __future__ import annotations

import html as _html
import json
from datetime import datetime, timezone
from pathlib import Path

from .memory import MemoriaCaso

_TITULO_SEVERIDAD = {
    "critica": "Crítica", "alta": "Alta", "media": "Media",
    "baja": "Baja", "informativa": "Informativa",
}

_COLOR_SEVERIDAD = {
    "critica": "#b91c1c", "alta": "#c2410c", "media": "#a16207",
    "baja": "#3f6212", "informativa": "#3f3f46",
}

_TITULO_DETECCION = {
    "detectado": "Detectado",
    "no_detectado": "No detectado (punto ciego)",
    "prevenido": "Prevenido (bloqueado)",
    "pendiente": "Pendiente de verificación",
}


def _resumen_deteccion(hallazgos: list[dict]) -> str | None:
    """Frase honesta de resultados purple team: solo si el operador registró
    alguna verificación defensiva real (nunca se inventa cobertura)."""
    registradas = [h for h in hallazgos
                   if h.get("deteccion") in ("detectado", "no_detectado", "prevenido")]
    if not registradas:
        return None
    vistos = sum(1 for h in registradas
                 if h["deteccion"] in ("detectado", "prevenido"))
    ciegos = len(registradas) - vistos
    return (f"Resultados de detección registrados (purple team): el equipo azul "
            f"verificó {len(registradas)} de {len(hallazgos)} hallazgos; la defensa "
            f"observó o bloqueó {vistos} y {ciegos} fueron puntos ciegos sin "
            f"detección asociada.")


def construir_informe(engagement_id: str, memoria: MemoriaCaso,
                      hallazgos: list[dict] | None = None,
                      carpeta_salida: str | Path = "casos") -> Path:
    fila = memoria.obtener_engagement(engagement_id)
    if fila is None:
        raise ValueError(f"Engagement {engagement_id} no existe")
    hallazgos = hallazgos if hallazgos is not None else [
        dict(f) for f in memoria.listar_hallazgos(engagement_id)]

    orden_sev = {"critica": 0, "alta": 1, "media": 2, "baja": 3, "informativa": 4}
    hallazgos.sort(key=lambda h: orden_sev.get(h.get("severidad", "informativa"), 4))

    auditoria = memoria.listar_auditoria(engagement_id)
    evidencias = memoria.listar_evidencias(engagement_id)
    cadena = memoria.verificar_cadena(engagement_id)
    tokens = memoria.resumen_tokens(engagement_id)

    nombre = fila["nombre"]
    cliente = fila["cliente"]
    generados = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    lineas: list[str] = []
    lineas.append(f"# Informe de test de intrusión — {nombre}")
    lineas.append("")
    lineas.append(f"**Cliente:** {cliente}  ")
    lineas.append(f"**Engagement:** `{engagement_id}`  ")
    lineas.append(f"**Generado:** {generados}  ")
    lineas.append(f"**Estado de la cadena de custodia:** "
                  f"{'VÁLIDA' if cadena['valida'] else 'INVÁLIDA — revisar'} "
                  f"({cadena['total']} evidencias firmadas)")
    lineas.append("")
    lineas.append("## 1. Resumen ejecutivo")
    lineas.append("")
    criticos = sum(1 for h in hallazgos if h.get("severidad") == "critica")
    altos = sum(1 for h in hallazgos if h.get("severidad") == "alta")
    lineas.append(
        f"El test de intrusión sobre el alcance acordado identificó "
        f"{len(hallazgos)} hallazgos ({criticos} críticos, {altos} altos). "
        "Todas las acciones del test quedaron registradas en una auditoría "
        "inmutable con actores, herramientas y resultados, y cada hallazgo "
        "incluye su receta de verificación reproducible para validación por "
        "parte del equipo defensivo del cliente.")
    frase_det = _resumen_deteccion(hallazgos)
    if frase_det:
        lineas.append("")
        lineas.append(frase_det)
    lineas.append("")
    lineas.append("## 2. Cronología del engagement")
    lineas.append("")
    lineas.append("| Fecha (UTC) | Actor | Acción | Resultado |")
    lineas.append("|---|---|---|---|")
    for ev in reversed(auditoria[:40]):
        lineas.append(f"| {ev['creado_en'][:19]} | {ev['actor']} | "
                      f"{ev['accion']} | {ev['resultado']} |")
    lineas.append("")
    lineas.append("## 3. Hallazgos")
    lineas.append("")
    for i, h in enumerate(hallazgos, 1):
        sev = _TITULO_SEVERIDAD.get(h.get("severidad", "informativa"), "—")
        lineas.append(f"### 3.{i} [{sev}] {h.get('titulo', 'sin título')}")
        lineas.append("")
        # z3 (auditoría): la clave del dict es `tecnica_mitre` (columna real de
        # la BD). Con `tecnica` el mapeo MITRE nunca llegaba al informe markdown
        # (el HTML sí lo incluía): informe y HTML deben decir lo mismo.
        if h.get("tecnica_mitre"):
            lineas.append(f"**MITRE ATT&CK:** `{h['tecnica_mitre']}`  ")
        if h.get("activo"):
            lineas.append(f"**Activo:** {h['activo']}  ")
        lineas.append("")
        if h.get("descripcion"):
            lineas.append(h["descripcion"])
            lineas.append("")
        if h.get("recomendacion"):
            lineas.append(f"**Recomendación:** {h['recomendacion']}")
            lineas.append("")
        det = h.get("deteccion", "pendiente")
        lineas.append(f"**Detección (blue team):** "
                      f"{_TITULO_DETECCION.get(det, det)}")
        lineas.append("")
        lineas.append("**Verificación reproducible:** el equipo azul puede "
                      "reejecutar la receta adjunta en las evidencias del "
                      "hallazgo para validar la detección y su corrección.")
        lineas.append("")
    lineas.append("## 4. Evidencias y cadena de custodia")
    lineas.append("")
    lineas.append("| ID | Tipo | Título | SHA-256 | Firma |")
    lineas.append("|---|---|---|---|---|")
    for e in evidencias:
        lineas.append(f"| `{e['id']}` | {e['tipo']} | {e['titulo']} | "
                      f"`{e['hash_sha256'][:16]}…` | verificada |")
    lineas.append("")
    lineas.append("## 5. Economía de la operación (tokens)")
    lineas.append("")
    for fila_tf in tokens.get("por_fase", []):
        lineas.append(f"- **{fila_tf['fase']}**: {fila_tf['tokens']} tokens, "
                      f"{fila_tf['coste']:.4f} USD")
    lineas.append("")
    lineas.append("---")
    lineas.append("")
    lineas.append("*Informe generado por la plataforma de red team orquestada por IA. "
                  "Revisión humana obligatoria antes de entrega al cliente "
                  "(operator-in-command). Documento CONFIDENCIAL — propiedad del "
                  "proveedor y del cliente del engagement.*")

    contenido = "\n".join(lineas)
    carpeta = Path(carpeta_salida) / engagement_id
    carpeta.mkdir(parents=True, exist_ok=True)
    ruta = carpeta / "informe.md"
    ruta.write_text(contenido, encoding="utf-8")
    return ruta


def _datos_informe(engagement_id: str, memoria: MemoriaCaso) -> dict:
    """Recolecta todos los datos del informe (compartido MD/HTML)."""
    fila = memoria.obtener_engagement(engagement_id)
    if fila is None:
        raise ValueError(f"Engagement {engagement_id} no existe")
    hallazgos = [dict(f) for f in memoria.listar_hallazgos(engagement_id)]
    orden_sev = {"critica": 0, "alta": 1, "media": 2, "baja": 3, "informativa": 4}
    hallazgos.sort(key=lambda h: orden_sev.get(h.get("severidad", "informativa"), 4))
    return {
        "fila": dict(fila),
        "hallazgos": hallazgos,
        "auditoria": memoria.listar_auditoria(engagement_id),
        "evidencias": memoria.listar_evidencias(engagement_id),
        "cadena": memoria.verificar_cadena(engagement_id),
        "tokens": memoria.resumen_tokens(engagement_id),
        "objetivos": memoria.listar_objetivos(engagement_id),
        "generados": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
    }


def construir_informe_html(engagement_id: str, memoria: MemoriaCaso,
                           carpeta_salida: str | Path = "casos") -> Path:
    """Informe HTML autocontenido (CSS embebido, imprimible a PDF desde el
    navegador). Mismo contenido que el markdown, con tabla de custodia
    completa y diseño sobrio en claro para entrega al cliente."""
    d = _datos_informe(engagement_id, memoria)
    fila, hallazgos, auditoria, evidencias = d["fila"], d["hallazgos"], d["auditoria"], d["evidencias"]
    cadena, tokens = d["cadena"], d["tokens"]
    esc = _html.escape

    def fila_tabla(celdas: list[str], es_cabecera: bool = False) -> str:
        tag = "th" if es_cabecera else "td"
        return "<tr>" + "".join(f"<{tag}>{c}</{tag}>" for c in celdas) + "</tr>"

    criticos = sum(1 for h in hallazgos if h.get("severidad") == "critica")
    altos = sum(1 for h in hallazgos if h.get("severidad") == "alta")

    # ── Hallazgos ──
    bloques_hallazgo: list[str] = []
    for i, h in enumerate(hallazgos, 1):
        sev = _TITULO_SEVERIDAD.get(h.get("severidad", "informativa"), "—")
        color = _COLOR_SEVERIDAD.get(h.get("severidad", "informativa"), "#3f3f46")
        meta = []
        if h.get("tecnica_mitre"):
            meta.append(f"<span class='chip'>MITRE {esc(str(h['tecnica_mitre']))}</span>")
        if h.get("activo"):
            meta.append(f"<span class='chip'>Activo: {esc(str(h['activo']))}</span>")
        det = h.get("deteccion", "pendiente")
        _tono_det = ("#15803d" if det in ("detectado", "prevenido")
                     else "#b91c1c" if det == "no_detectado" else "#71717a")
        meta.append(f"<span class='chip' style='color:{_tono_det};border-color:{_tono_det}'>"
                    f"Detección: {esc(_TITULO_DETECCION.get(det, det))}</span>")
        bloques_hallazgo.append(f"""
        <div class="hallazgo">
          <h3><span class="sev" style="background:{color}">{esc(sev)}</span>
              {i}. {esc(h.get('titulo', 'sin título'))}</h3>
          <div class="chips">{''.join(meta)}</div>
          <p>{esc(h.get('descripcion', ''))}</p>
          {f"<p><strong>Recomendación:</strong> {esc(h['recomendacion'])}</p>" if h.get("recomendacion") else ""}
          <p class="nota">Verificación reproducible: el equipo azul puede reejecutar la
          receta adjunta en las evidencias del hallazgo para validar detección y corrección.</p>
        </div>""")

    # ── Cronología ──
    filas_crono = "".join(
        fila_tabla([ev["creado_en"][:19], esc(ev["actor"]), esc(ev["accion"]),
                    esc(ev["resultado"]), esc((ev["detalle"] or "")[:120])])
        for ev in reversed(auditoria[:60]))

    # ── Cadena de custodia ──
    filas_custodia = "".join(
        fila_tabla([f"<code>{esc(e['id'])}</code>", esc(e["tipo"]), esc(e["titulo"]),
                    f"<code>{esc(e['hash_sha256'][:24])}…</code>",
                    f"<code>{esc(e['hash_previo'][:20])}…</code>",
                    "<span class='ok'>verificada</span>" if cadena["valida"] else "<span class='mal'>inválida</span>"])
        for e in evidencias)

    filas_tokens = "".join(
        fila_tabla([esc(f["fase"]), f"{f['tokens']:,}", f"{f['coste']:.4f} USD"])
        for f in tokens.get("por_fase", []))

    html_doc = f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<title>Informe de test de intrusión — {esc(fila['nombre'])}</title>
<style>
  :root {{ --tinta:#18181b; --linea:#e4e4e7; --suave:#71717a; }}
  * {{ box-sizing: border-box; }}
  body {{ font-family: 'Segoe UI', system-ui, sans-serif; color: var(--tinta);
         max-width: 880px; margin: 40px auto; padding: 0 24px; line-height: 1.55;
         font-size: 14px; }}
  header {{ border-bottom: 3px solid #18181b; padding-bottom: 16px; margin-bottom: 28px; }}
  h1 {{ font-size: 22px; margin: 0 0 4px; letter-spacing: -0.02em; }}
  .meta {{ color: var(--suave); font-size: 12.5px; }}
  h2 {{ font-size: 16px; margin: 32px 0 10px; border-bottom: 1px solid var(--linea);
        padding-bottom: 6px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 12px; margin: 10px 0; }}
  th, td {{ border: 1px solid var(--linea); padding: 6px 8px; text-align: left;
            vertical-align: top; }}
  th {{ background: #fafafa; font-weight: 600; }}
  code {{ font-family: 'Cascadia Mono', Consolas, monospace; font-size: 11px;
          background: #f4f4f5; padding: 1px 4px; border-radius: 3px; }}
  .hallazgo {{ border: 1px solid var(--linea); border-radius: 8px; padding: 14px 16px;
               margin: 12px 0; }}
  .hallazgo h3 {{ font-size: 14px; margin: 0 0 8px; display: flex; align-items: center;
                  gap: 8px; }}
  .sev {{ color: #fff; font-size: 10px; font-weight: 700; padding: 2px 8px;
          border-radius: 99px; text-transform: uppercase; letter-spacing: 0.06em; }}
  .chip {{ background: #f4f4f5; border: 1px solid var(--linea); border-radius: 99px;
           font-size: 11px; padding: 2px 8px; margin-right: 6px; }}
  .chips {{ margin-bottom: 8px; }}
  .nota {{ color: var(--suave); font-size: 12px; }}
  .ok {{ color: #15803d; font-weight: 600; }}
  .mal {{ color: #b91c1c; font-weight: 600; }}
  .estado-cadena {{ padding: 10px 14px; border-radius: 8px; font-weight: 600;
                    font-size: 13px; margin: 10px 0; }}
  footer {{ margin-top: 36px; border-top: 1px solid var(--linea); padding-top: 12px;
            color: var(--suave); font-size: 11.5px; }}
  @media print {{ body {{ margin: 0; font-size: 12px; }}
                   .hallazgo {{ break-inside: avoid; }} }}
</style>
</head>
<body>
<header>
  <h1>Informe de test de intrusión — {esc(fila['nombre'])}</h1>
  <p class="meta">
    Cliente: <strong>{esc(fila['cliente'])}</strong> &middot;
    Engagement: <code>{esc(engagement_id)}</code> &middot;
    Generado: {d['generados']} &middot;
    Confidencial
  </p>
</header>

<div class="estado-cadena" style="background:{'#f0fdf4' if cadena['valida'] else '#fef2f2'}">
  Cadena de custodia: {'VÁLIDA' if cadena['valida'] else 'INVÁLIDA — revisar'}
  ({cadena['total']} evidencias firmadas con SHA-256 + HMAC encadenado)
</div>

<h2>1. Resumen ejecutivo</h2>
<p>El test de intrusión sobre el alcance acordado identificó {len(hallazgos)} hallazgos
({criticos} críticos, {altos} altos). Todas las acciones quedaron registradas en una
auditoría inmutable con actor, herramienta y resultado; cada hallazgo incluye su receta
de verificación reproducible para el equipo defensivo del cliente.</p>
{f"<p>{_resumen_deteccion(hallazgos)}</p>" if _resumen_deteccion(hallazgos) else ""}

<h2>2. Cronología del engagement</h2>
<table>
  <tr><th>Fecha (UTC)</th><th>Actor</th><th>Acción</th><th>Resultado</th><th>Detalle</th></tr>
  {filas_crono}
</table>

<h2>3. Hallazgos</h2>
{''.join(bloques_hallazgo) if bloques_hallazgo else '<p class="nota">Sin hallazgos registrados.</p>'}

<h2>4. Superficie de ataque observada</h2>
<table>
  <tr><th>Activo</th><th>Tipo</th><th>Estado final</th><th>Detalle</th></tr>
  {''.join(fila_tabla([esc(o['nombre']), esc(o['tipo']), esc(o['estado']), esc((o['detalle'] or '')[:100])]) for o in d['objetivos'])}
</table>

<h2>5. Evidencias y cadena de custodia</h2>
<table>
  <tr><th>ID</th><th>Tipo</th><th>Título</th><th>SHA-256</th><th>Enlaza a</th><th>Firma</th></tr>
  {filas_custodia}
</table>

<h2>6. Economía de la operación (tokens)</h2>
<table>
  <tr><th>Fase</th><th>Tokens</th><th>Coste</th></tr>
  {filas_tokens}
</table>

<footer>
  Informe generado por la plataforma de red team orquestada por IA.
  Revisión humana obligatoria antes de entrega al cliente (operator-in-command).
  Documento CONFIDENCIAL — propiedad del proveedor y del cliente del engagement.
</footer>
</body>
</html>"""

    carpeta = Path(carpeta_salida) / engagement_id
    carpeta.mkdir(parents=True, exist_ok=True)
    ruta = carpeta / "informe.html"
    ruta.write_text(html_doc, encoding="utf-8")
    return ruta
