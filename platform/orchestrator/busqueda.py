"""Búsqueda real en la memoria del caso: BM25 + embeddings opcionales.

Capítulo 2 del blueprint: la memoria del caso debe ser RECUPERABLE. Aquí
implementamos recuperación léxica BM25 (Okapi, k1=1.5, b=0.75) sobre todos
los artefactos del caso — evidencias, hallazgos, objetivos, auditoría,
aprobaciones y resúmenes de fase — 100% local y sin dependencias externas.

Si hay un backend de inferencia local configurado (API_LOCAL_BASE), el
mismo índice se refuerza con embeddings semánticos (endpoint OpenAI-compat
/v1/embeddings): consulta y documentos se proyectan y se combinan ambos
rangoles (RRF — Reciprocal Rank Fusion). Sin backend local, BM25 solo:
honesto y funcional.
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from typing import Any, Iterable

# Palabras vacías españolas (colección compacta de propósito operativo)
_STOPWORDS = frozenset("""
a al algo algunas algunos ante antes como con contra cual cuando de del desde
donde dos el ella ellas ellos en entre era erais eran eras eres es esa esas
ese eso esos esta estaba estamos estan estar este esto estos fue fueron ha
habia han hasta hay la las le les lo los mas me mi mis mucho muy nada ni no
nos nosotras nosotros nuestra nuestro o os otra otras otro otros para pero
poco por porque que quien se sea segun ser si sin sobre solo son su sus tambien
tan tanto te tu tus un una unas uno unos usted ustedes y ya yo
""".split())

_TOKEN = re.compile(r"[a-z0-9áéíóúüñ]+", re.IGNORECASE)


def tokenizar(texto: str) -> list[str]:
    """Tokenizador español: minúsculas, sin tildes (búsqueda tolerante),
    sin stopwords, tokens de longitud >= 2."""
    texto = (texto or "").lower()
    texto = (texto.replace("á", "a").replace("é", "e").replace("í", "i")
                  .replace("ó", "o").replace("ú", "u").replace("ü", "u"))
    return [t for t in _TOKEN.findall(texto) if len(t) >= 2 and t not in _STOPWORDS]


@dataclass
class Documento:
    """Artefacto indexable de la memoria del caso."""

    id: str
    tipo: str            # evidencia | hallazgo | objetivo | auditoria | aprobacion | resumen
    titulo: str
    contenido: str
    fase: str = ""
    creado_en: str = ""
    extra: dict[str, Any] = field(default_factory=dict)


class IndiceBM25:
    """Índice BM25 en memoria. Se reconstruye por consulta: para los
    volúmenes de un caso (miles de artefactos) el coste es marginal y evita
    sincronización incremental."""

    def __init__(self, documentos: list[Documento], k1: float = 1.5, b: float = 0.75):
        self.k1, self.b = k1, b
        self.documentos = documentos
        self.tokens_docs: list[list[str]] = [tokenizar(f"{d.titulo} {d.contenido}") for d in documentos]
        self.longitudes = [len(t) for t in self.tokens_docs]
        self.n = len(documentos)
        self.media = (sum(self.longitudes) / self.n) if self.n else 0.0
        # Frecuencias inversas
        self.idf: dict[str, float] = {}
        df: dict[str, int] = {}
        for tokens in self.tokens_docs:
            for t in set(tokens):
                df[t] = df.get(t, 0) + 1
        for t, f in df.items():
            self.idf[t] = math.log(1 + (self.n - f + 0.5) / (f + 0.5))

    def buscar(self, consulta: str, limite: int = 20) -> list[tuple[Documento, float]]:
        """Devuelve los documentos mejor puntuados para la consulta."""
        q = tokenizar(consulta)
        if not q or self.n == 0:
            return []
        puntuaciones = [0.0] * self.n
        for i, tokens in enumerate(self.tokens_docs):
            if not tokens:
                continue
            tf: dict[str, int] = {}
            for t in tokens:
                tf[t] = tf.get(t, 0) + 1
            longitud = self.longitudes[i]
            for t in q:
                f = tf.get(t)
                if not f:
                    continue
                idf = self.idf.get(t, 0.0)
                denom = f + self.k1 * (1 - self.b + self.b * longitud / self.media)
                puntuaciones[i] += idf * (f * (self.k1 + 1)) / denom
        orden = sorted(range(self.n), key=lambda i: puntuaciones[i], reverse=True)
        return [(self.documentos[i], puntuaciones[i])
                for i in orden[:limite] if puntuaciones[i] > 0]


def _normalizar_1a1(texto: str) -> str:
    """Normalización IDÉNTICA a la de tokenizar pero 1:1 por carácter.

    tokenizar quita tildes (búsqueda tolerante); el fragmento necesita
    LOCALIZAR esa misma coincidencia sobre el texto original. Como cada
    sustitución (á→a, ü→u, …) y el lower() en español conservan la longitud,
    las posiciones encontradas en el gemelo valen para recortar el original.
    (z2, ronda 7: antes el fragmento buscaba el término SIN normalizar sobre
    el contenido crudo y una consulta acentuada — o viceversa — no encontraba
    la posición y el recorte caía en la cabecera del documento, no en la
    coincidencia que BM25 sí había puntuado.)
    """
    texto = texto.lower()
    for origen, destino in (("á", "a"), ("é", "e"), ("í", "i"),
                            ("ó", "o"), ("ú", "u"), ("ü", "u")):
        texto = texto.replace(origen, destino)
    return texto


def _fragmento(contenido: str, consulta: str, radio: int = 90) -> str:
    """Recorte contextual del contenido alrededor de la primera coincidencia
    (con la MISMA tolerancia a tildes que el índice BM25).

    Compatibilidad: la vista de memoria del copiloto (RAG) consume solo el
    texto; la consola consume además las posiciones vía _fragmento_y_coincidencias.
    """
    return _fragmento_y_coincidencias(contenido, consulta, radio)[0]


def _fragmento_y_coincidencias(
        contenido: str, consulta: str, radio: int = 90) -> tuple[str, list[dict[str, int]]]:
    """Recorte contextual + posiciones EXACTAS de las coincidencias dentro
    del recorte devuelto.

    (z2, ronda 8): la vista Memoria pinta el término buscado con realce.
    Las posiciones se calculan aquí —fuente única de verdad de la
    normalización tolerante a tildes (z2, ronda 7)— y viajan en la
    respuesta; duplicar la lógica en TypeScript abriría una deriva
    backend↔frontend del mismo tipo que la que esta carpeta caza.

    Contrato del realce: `coincidencias` es una lista de pares
    {inicio, fin} SEMIABIERTOS [inicio, fin) sobre el fragmento DEVUELTO
    (con sus suspensivos incluidos, que nunca forman parte de una
    coincidencia), ordenados y sin solapes — listos para
    fragmento.slice(inicio, fin) en el frontend. Si el fragmento no
    contiene ninguna coincidencia (p. ej. el resultado entró solo por la
    vía semántica de embeddings, o el recorte es la cabecera por
    ausencia de match), la lista viene VACÍA: la vista no inventa
    realces que el índice no sostiene.
    """
    texto = (contenido or "").strip().replace("\n", " ")
    if len(texto) <= radio * 2:
        # El documento completo ya es visible: el realce cubre TODO lo
        # que contiene (sin ventana que recorte nada).
        return texto, _rangos_coincidencias(texto, consulta)

    terminos = tokenizar(consulta)
    bajo = _normalizar_1a1(texto)
    primer_pos = -1
    primer_len = 0
    for t in terminos:
        pos = bajo.find(t)
        if pos >= 0:
            primer_pos, primer_len = pos, len(t)
            break
    if primer_pos < 0:
        # Sin coincidencia léxica: cabecera honesta, sin realces.
        return texto[: radio * 2] + "…", []

    inicio = max(0, primer_pos - radio)
    # La primera coincidencia NUNCA queda cortada por la derecha (antes un
    # término más largo que el radio se partía a la mitad del recorte).
    fin = min(len(texto), max(primer_pos + radio, primer_pos + primer_len))
    ventana = texto[inicio:fin]
    prefijo = "…" if inicio > 0 else ""
    sufijo = "…" if fin < len(texto) else ""
    # El suspensivo inicial desplaza las posiciones de la ventana dentro del
    # fragmento final (el de la derecha va al final: no afecta a nada previo).
    desplazamiento = len(prefijo)
    rangos = [
        {"inicio": c["inicio"] + desplazamiento, "fin": c["fin"] + desplazamiento}
        for c in _rangos_coincidencias(ventana, consulta)
    ]
    return prefijo + ventana + sufijo, rangos


def _rangos_coincidencias(texto: str, consulta: str) -> list[dict[str, int]]:
    """Todas las coincidencias de los términos de la consulta sobre `texto`,
    con la MISMA tolerancia a tildes que el índice (gemelo normalizado 1:1).
    Devuelve pares {inicio, fin} semiabiertos, ordenados, sin solapes (los
    rangos que se solapan se FUNDEN — p. ej. «adm» dentro de una
    «administracion» puntuada — para que el frontend pinte una sola marca
    continua)."""
    if not texto:
        return []
    bajo = _normalizar_1a1(texto)
    bruto: list[list[int]] = []
    for t in dict.fromkeys(tokenizar(consulta)):  # dedup conservando orden
        pos = bajo.find(t)
        while pos >= 0:
            bruto.append([pos, pos + len(t)])
            pos = bajo.find(t, pos + 1)
    if not bruto:
        return []
    bruto.sort()
    fundidos: list[list[int]] = [bruto[0]]
    for ini, fin in bruto[1:]:
        if ini <= fundidos[-1][1]:  # solapa o toca el borde interior
            fundidos[-1][1] = max(fundidos[-1][1], fin)
        else:
            fundidos.append([ini, fin])
    return [{"inicio": ini, "fin": fin} for ini, fin in fundidos]


def _rrf(rangos: list[dict[str, float]], k: int = 60) -> dict[str, float]:
    """Reciprocal Rank Fusion: fusión robusta de listas de ranking."""
    fusion: dict[str, float] = {}
    for rango in rangos:
        for posicion, (clave, _) in enumerate(sorted(rango.items(), key=lambda x: -x[1])):
            fusion[clave] = fusion.get(clave, 0.0) + 1.0 / (k + posicion + 1)
    return fusion


def documentos_de_caso(memoria, engagement_id: str) -> list[Documento]:
    """Recolecta TODOS los artefactos indexables de la memoria del caso.

    `memoria` es una MemoriaCaso abierta y `engagement_id` el caso activo.
    Los contenidos se recortan a un máximo razonable por documento para el
    índice (la evidencia completa sigue disponible por su id).
    """
    docs: list[Documento] = []

    for f in memoria.listar_evidencias(engagement_id):
        docs.append(Documento(
            id=f"evidencia:{f['id']}", tipo="evidencia", titulo=f["titulo"],
            contenido=(f["contenido"] or "")[:4000], fase=f["fase"],
            creado_en=f["creado_en"], extra={"hash": f["hash_sha256"][:12]}))

    for f in memoria.listar_hallazgos(engagement_id):
        docs.append(Documento(
            id=f"hallazgo:{f['id']}", tipo="hallazgo", titulo=f["titulo"],
            contenido=f"{f['descripcion']} {f['recomendacion']} {f['activo']} "
                      f"severidad {f['severidad']}"[:4000],
            creado_en=f["creado_en"], extra={"severidad": f["severidad"],
                                             "mitre": f["tecnica_mitre"] or ""}))

    for f in memoria.listar_objetivos(engagement_id):
        docs.append(Documento(
            id=f"objetivo:{f['id']}", tipo="objetivo", titulo=f["nombre"],
            contenido=f"{f['tipo']} {f['estado']} {f['detalle']}"[:1500],
            fase=f["fase"], creado_en=f["descubierto_en"],
            extra={"estado": f["estado"]}))

    for f in memoria.listar_aprobaciones(engagement_id):
        docs.append(Documento(
            id=f"aprobacion:{f['id']}", tipo="aprobacion", titulo=f["titulo"],
            contenido=f"{f['motivo']} {f['descripcion']} herramienta {f['herramienta']} "
                      f"estado {f['estado']} decidida_por {f['decidida_por'] or '-'}"[:2500],
            fase=f["fase"], creado_en=f["creada_en"], extra={"estado": f["estado"]}))

    for f in memoria.listar_auditoria(engagement_id, limite=2000):
        docs.append(Documento(
            id=f"auditoria:{f['id']}", tipo="auditoria", titulo=f["accion"],
            contenido=f"{f['detalle']} resultado {f['resultado']}"[:1500],
            creado_en=f["creado_en"], extra={"actor": f["actor"],
                                             "resultado": f["resultado"]}))

    filas = memoria._conn.execute(
        "SELECT fase, texto, creado_en FROM resumenes_fase WHERE engagement_id=? "
        "ORDER BY id", (engagement_id,)).fetchall()
    for f in filas:
        docs.append(Documento(
            id=f"resumen:{f['creado_en']}", tipo="resumen", titulo=f"Resumen {f['fase']}",
            contenido=f["texto"][:4000], fase=f["fase"], creado_en=f["creado_en"]))

    return docs


def _embeddings_consulta(base: str, clave: str, textos: list[str]) -> dict[int, list[float]]:
    """Embeddings vía endpoint OpenAI-compat /v1/embeddings del backend LOCAL."""
    try:
        import httpx
        with httpx.Client(timeout=20) as c:
            r = c.post(f"{base.rstrip('/')}/embeddings",
                       json={"input": textos}, headers={"Authorization": f"Bearer {clave}"} if clave else {})
            r.raise_for_status()
            datos = r.json()
            return {i: d["embedding"] for i, d in enumerate(datos.get("data", []))}
    except Exception:
        return {}


def _similitud_coseno(a: list[float], b: list[float]) -> float:
    if not a or not b or len(a) != len(b):
        return 0.0
    producto = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    return producto / (na * nb) if na and nb else 0.0


def buscar_caso(
    memoria,
    engagement_id: str,
    consulta: str,
    limite: int = 20,
    tipos: Iterable[str] | None = None,
    local_base: str = "",
    local_clave: str = "",
) -> dict[str, Any]:
    """Búsqueda completa del caso: BM25 siempre + semántica si hay LLM local.

    Devuelve {consulta, total_indexado, resultados: [...], metodo}.
    Cada resultado: {id, tipo, titulo, fragmento, puntuacion, fase, creado_en, extra}.
    """
    documentos = documentos_de_caso(memoria, engagement_id)
    tipos_filtro = set(tipos) if tipos else None
    if tipos_filtro:
        documentos = [d for d in documentos if d.tipo in tipos_filtro]

    indice = IndiceBM25(documentos)
    pares = indice.buscar(consulta, limite=max(limite * 2, 40))

    metodo = "bm25"
    rangos: list[dict[str, float]] = [{p.id: s for p, s in pares}]

    # Refuerzo semántico opcional SOLO con el backend local del operador:
    # el contenido del caso nunca sale hacia la frontera (soberanía).
    if local_base and pares:
        candidatos = [p for p, _ in pares[:40]]
        vectores = _embeddings_consulta(
            local_base, local_clave, [consulta] + [f"{p.titulo} {p.contenido[:1200]}" for p in candidatos])
        if len(vectores) == len(candidatos) + 1:
            vec_q = vectores[0]
            semantico: dict[str, float] = {}
            for i, doc in enumerate(candidatos):
                semantico[doc.id] = _similitud_coseno(vec_q, vectores[i + 1])
            rangos.append(semantico)
            metodo = "bm25+embeddings_local"

    fusion = _rrf(rangos)
    por_id = {d.id: d for d in documentos}
    finales: list[dict[str, Any]] = []
    for clave, puntuacion in sorted(fusion.items(), key=lambda x: -x[1])[:limite]:
        doc = por_id.get(clave)
        if not doc:
            continue
        frag, coincidencias = _fragmento_y_coincidencias(doc.contenido, consulta)
        finales.append({
            "id": doc.id, "tipo": doc.tipo, "titulo": doc.titulo,
            "fragmento": frag,
            # Posiciones del realce sobre `fragmento` ([inicio, fin), sin
            # solapes); vacía cuando el fragmento no contiene el término —
            # contrato backend↔frontend fijado en test_v32_z2.py (ronda 8).
            "coincidencias": coincidencias,
            "puntuacion": round(puntuacion, 5), "fase": doc.fase,
            "creado_en": doc.creado_en, "extra": doc.extra,
        })
    return {
        "consulta": consulta,
        "total_indexado": len(documentos),
        "metodo": metodo,
        "resultados": finales,
    }
