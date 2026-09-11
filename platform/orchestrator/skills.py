"""Skills: conocimiento modular con progressive disclosure.

Una skill es una carpeta con SKILL.md (portada YAML + procedimiento) y
scripts de apoyo. El agente solo carga en contexto el NOMBRE y la
DESCRIPCIÓN de cada skill; el cuerpo completo se carga únicamente cuando
la tarea lo requiere (progressive disclosure, capítulo 2.4 del blueprint).

Una skill de red team es un playbook de TTP ejecutable: procedimiento,
herramientas, criterios de éxito, reglas OPSEC y evidencias a capturar.
La biblioteca se versiona en git y crece con cada engagement: es uno de
los fosos competitivos del producto.

SEGURIDAD DE LA CADENA DE SUMINISTRO (cap. 5.2, tabla 8):
- Solo se cargan skills firmadas o del propio caso (directorio `skills/`
  del despliegue, montado read-only).
- Los scripts de apoyo corren en sandbox de menor privilegio; el loader
  nunca ejecuta código de la skill: solo lo ENTREGA al boundary.
"""
from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None


@dataclass
class PortadaSkill:
    """Metadatos mínimos que entran en el índice (lo único que ve el modelo)."""

    nombre: str
    descripcion: str
    fase: str = ""
    tecnica_mitre: str = ""
    riesgo: str = "media"
    requiere_aprobacion: bool = True
    fuentes_permitidas: list[str] = field(default_factory=list)


@dataclass
class Skill:
    portada: PortadaSkill
    ruta: Path
    cuerpo: str = ""  # se carga bajo demanda (progressive disclosure)
    hash_contenido: str = ""

    def cargar_cuerpo(self) -> str:
        """Carga el cuerpo bajo demanda. Llamar solo cuando la tarea lo requiera."""
        if not self.cuerpo:
            self.cuerpo = self.ruta.read_text(encoding="utf-8")
        return self.cuerpo


class BibliotecaSkills:
    """Índice de skills del despliegue con verificación opcional de firma."""

    def __init__(self, raiz: str | Path = "skills", clave_firma: bytes | None = None):
        self.raiz = Path(raiz)
        self.clave = clave_firma or os.environ.get("CLAVE_SKILLS", "").encode() or None
        self._indice: dict[str, Skill] = {}
        self._cargar_indice()

    def _cargar_indice(self) -> None:
        if not self.raiz.exists():
            return
        for md in sorted(self.raiz.rglob("SKILL.md")):
            skill = self._parsear(md)
            if skill:
                self._indice[skill.portada.nombre] = skill

    def recargar(self) -> int:
        """Relee la biblioteca desde disco SIN reiniciar el orquestador.

        El índice se construye al instanciar la clase: si el operador añade
        una técnica nueva (o retira una), el orquestador vivo no se enteraría
        hasta el reinicio. `recargar()` reconstruye el índice y devuelve el
        total de técnicas vigentes — se expone en la consola como acción
        explícita y queda auditada.
        """
        self._indice = {}
        self._cargar_indice()
        return len(self._indice)

    def _parsear(self, ruta_md: Path) -> Optional[Skill]:
        # UNA sola lectura del fichero: los bytes alimentan el hash y el texto.
        try:
            contenido = ruta_md.read_bytes()
        except OSError:
            return None
        texto = contenido.decode("utf-8", errors="replace")
        portada = None
        cuerpo = texto
        if texto.startswith("---") and yaml is not None:
            partes = texto.split("---", 2)
            if len(partes) >= 3:
                try:
                    datos = yaml.safe_load(partes[1]) or {}
                    portada = PortadaSkill(
                        nombre=str(datos.get("nombre", ruta_md.parent.name)),
                        descripcion=str(datos.get("descripcion", "")),
                        fase=str(datos.get("fase", "")),
                        tecnica_mitre=str(datos.get("tecnica_mitre", "")),
                        riesgo=str(datos.get("riesgo", "media")),
                        requiere_aprobacion=bool(datos.get("requiere_aprobacion", True)),
                        fuentes_permitidas=list(datos.get("fuentes_permitidas", [])),
                    )
                    cuerpo = partes[2]
                except Exception:
                    return None
        if portada is None:
            primera = texto.strip().splitlines()
            titulo = next((l for l in primera if l.startswith("# ")), "")
            portada = PortadaSkill(
                nombre=ruta_md.parent.name,
                descripcion=titulo.lstrip("# ")[:200],
            )
            cuerpo = texto
        return Skill(
            portada=portada, ruta=ruta_md, cuerpo=cuerpo,
            hash_contenido=hashlib.sha256(contenido).hexdigest(),
        )

    # -- API -------------------------------------------------------------------

    def indice_para_prompt(self) -> str:
        """Índice compacto para el system prompt (solo nombre y descripción)."""
        lineas = []
        for s in self._indice.values():
            p = s.portada
            lineas.append(f"- {p.nombre}: {p.descripcion} "
                          f"[fase={p.fase or '-'} | ATT&CK={p.tecnica_mitre or '-'} | "
                          f"riesgo={p.riesgo}]")
        return "\n".join(lineas) if lineas else "(biblioteca de skills vacía)"

    def obtener(self, nombre: str) -> Optional[Skill]:
        """Devuelve la skill y carga su cuerpo (progressive disclosure)."""
        skill = self._indice.get(nombre)
        if skill:
            skill.cargar_cuerpo()
        return skill

    def listar(self) -> list[PortadaSkill]:
        return [s.portada for s in self._indice.values()]

    def verificar_firma(self, skill: Skill, firma: str) -> bool:
        """Verifica la firma HMAC del contenido de la skill (skills comunitarias)."""
        if not self.clave:
            return False
        esperada = hmac.new(self.clave, skill.hash_contenido.encode(),
                            hashlib.sha256).hexdigest()
        return hmac.compare_digest(esperada, firma)
