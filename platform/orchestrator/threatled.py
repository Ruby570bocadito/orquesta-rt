"""Planificación threat-led: cadenas de ataque estilo Atomic Red Team.

La diferencia entre una lista de técnicas y una PLANIFICACIÓN threat-led es
el ORDEN y el PROPÓSITO: una cadena emula el comportamiento secuencial de un
adversario real (recon → entrada → escalada → persistencia → sigilo), cada
paso habilita al siguiente y el plan se contrasta contra lo que el caso YA
ha ejercitado.

Disciplina anti-relleno (la misma de toda la plataforma):
- Cada paso referencia una herramienta REAL del boundary del despliegue
  (guardrails._RIESGO_HERRAMIENTAS) o se marca `manual`: el operador la
  ejecuta con su arsenal fuera de la plataforma. JAMÁS se presenta una
  capacidad como ejecutable si el boundary no la conoce.
- El ruido de cada paso proviene del MISMO catálogo que usa el guardrail
  en ejecución: lo que el plan promete es lo que el boundary exigirá.
- El plan por caso es DERIVADO (hallazgos + auditoría reales), nunca
  inventado: un paso "ejercitado" exige evidencia con esa técnica.

Referencias ATT&CK Enterprise v15+; las sub-técnicas se citan con el id
exacto para que la capa Navigator y la matriz de cobertura cruceen bien.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass(frozen=True)
class Paso:
    """Un eslabón de la cadena: técnica ATT&CK + herramienta del despliegue."""

    orden: int
    tecnica: str          # id ATT&CK exacto (Txxxx[.xxx])
    nombre: str           # nombre ATT&CK de la técnica
    fase: str             # fase del orquestador donde encaja (F0..F6)
    descripcion: str      # QUÉ hace el adversario en este paso
    herramienta: str      # herramienta del boundary o "manual"
    deteccion: str        # qué debería ver el blue team (hint purple)

    @property
    def es_manual(self) -> bool:
        return self.herramienta == "manual"


@dataclass(frozen=True)
class Cadena:
    """Cadena threat-led: perfil de adversario emulado, paso a paso."""

    id: str
    nombre: str
    perfil: str            # tipo de adversario emulado
    objetivo: str          # qué demuestra ejecutarla de punta a punta
    descripcion: str
    pasos: tuple[Paso, ...] = field(default_factory=tuple)

    def resumen(self) -> dict[str, Any]:
        tecnicas = [p.tecnica for p in self.pasos]
        return {
            "id": self.id, "nombre": self.nombre, "perfil": self.perfil,
            "objetivo": self.objetivo, "descripcion": self.descripcion,
            "pasos": len(self.pasos),
            "tecnicas": tecnicas,
            "manuales": sum(1 for p in self.pasos if p.es_manual),
            "ruido_total_estimado": sum(
                RUIDO.get(p.herramienta, 0) for p in self.pasos if not p.es_manual),
        }


# Ruido por herramienta: importado del MISMO catálogo que evalúa el boundary.
# Si el catálogo cambia, el plan y el guardrail siguen de acuerdo.
def _ruido_desde_guardrails() -> dict[str, int]:
    try:
        from .guardrails import _RIESGO_HERRAMIENTAS
        return {k: int(v.get("ruido", 0)) for k, v in _RIESGO_HERRAMIENTAS.items()}
    except Exception:  # pragma: no cover - el import no debe romper el catálogo
        return {}


RUIDO: dict[str, int] = _ruido_desde_guardrails()

# Fases válidas del orquestador (models.Fase) — validación de los pasos.
_FASES_VALIDAS = {
    "F0_scoping", "F1_osint", "F2_recon", "F3_acceso_inicial",
    "F4_dominio_ad", "F5_c2_postex", "F6_phishing", "F7_informe", "cierre",
}

_ID_TECNICA = re.compile(r"^T\d{4}(?:\.\d{3})?$")


def _validar_cadena(c: Cadena) -> None:
    if not c.id or not re.fullmatch(r"[a-z0-9_]{3,60}", c.id):
        raise ValueError(f"cadena id inválida: {c.id!r}")
    if not c.pasos:
        raise ValueError(f"cadena {c.id}: sin pasos")
    ordenes = [p.orden for p in c.pasos]
    if ordenes != list(range(1, len(ordenes) + 1)):
        raise ValueError(f"cadena {c.id}: los pasos deben ser 1..N consecutivos")
    for p in c.pasos:
        if not _ID_TECNICA.fullmatch(p.tecnica):
            raise ValueError(f"cadena {c.id}: técnica inválida {p.tecnica!r}")
        if p.fase not in _FASES_VALIDAS:
            raise ValueError(f"cadena {c.id}: fase inválida {p.fase!r}")
        if not p.descripcion or not p.deteccion:
            raise ValueError(f"cadena {c.id} paso {p.orden}: descripción y "
                             "detección son obligatorias (anti-relleno)")


_CADENAS: tuple[Cadena, ...] = (
    Cadena(
        id="intrusion_ad_completa",
        nombre="Intrusión AD de extremo a extremo",
        perfil="APT orientado a dominio (movimiento silencioso hasta DA)",
        objetivo="Demostrar el camino completo: visibilidad externa → enumeración "
                 "→ robo de credenciales → escalada a DA → persistencia → limpieza.",
        descripcion=(
            "La cadena de referencia para un lab con controlador de dominio. "
            "Cada paso produce hallazgo con técnica ATT&CK y evidencia "
            "custodiada; el orden replica cómo un adversario encadena "
            "enumeración y robo de credenciales antes de tocar DA."),
        pasos=(
            Paso(1, "T1595.002", "Active Scanning: Vulnerability Scanning", "F2_recon",
                 "Descubrir servicios expuestos del objetivo con escaneo controlado.",
                 "recon.nmap_servicios",
                 "Escaneo SYN/connect masivo desde una IP externa: IDS/NDR, "
                 "firewall logs, alertas de port scan."),
            Paso(2, "T1018", "Remote System Discovery", "F4_dominio_ad",
                 "Enumerar equipos del dominio vía LDAP (listado de hosts y SO).",
                 "ad.enumerar_ldap",
                 "Consultas LDAP genéricas al DC desde una cuenta estándar: "
                 "eventos 4662 de consulta masiva, SIEM con umbral de objetos leídos."),
            Paso(3, "T1087.002", "Account Discovery: Domain Account", "F4_dominio_ad",
                 "Enumerar cuentas de usuario y grupos del dominio.",
                 "ad.enumerar_ldap",
                 "Ráfaga de consultas de usuarios/grupos: evento 4662, "
                 "anomalía de volumen LDAP por cuenta no privilegiada."),
            Paso(4, "T1558.003", "Kerberoasting", "F4_dominio_ad",
                 "Solicitar TGS de cuentas con SPN y crackear offline.",
                 "ad.kerberoasting",
                 "Pico de peticiones TGS-REQ con cifrado RC4 (evento 4769 con "
                 "encryption 0x17) desde un solo origen."),
            Paso(5, "T1558.004", "AS-REP Roasting", "F4_dominio_ad",
                 "Solicitar AS-REP de cuentas sin preautenticación Kerberos.",
                 "ad.asrep_roasting",
                 "AS-REQ sin preauth (evento 4768 pre_auth_type 0) contra "
                 "cuentas con UAC 4194304."),
            Paso(6, "T1003.006", "OS Credential Dumping: DCSync", "F4_dominio_ad",
                 "Replicar hashes del DC con DRSUAPI (requiere privilegios ya "
                 "comprometidos: valida el camino de escalada del paso previo).",
                 "ad.dcsync",
                 "Evento 4662 con GUID de Replicación (1131f6aa/1131f6ad) por "
                 "cuenta sin permisos de replicación: alerta crítica."),
            Paso(7, "T1550.002", "Pass the Hash", "F4_dominio_ad",
                 "Autenticarse SMB con hash NT sin conocer la contraseña.",
                 "ad.pass_the_hash",
                 "4624 tipo 9 (NewCredentials), NTLM contra SMB desde origen "
                 "inusual; EDR detecta técnicas de pocas herramientas."),
            Paso(8, "T1053.005", "Scheduled Task/Job: Scheduled Task", "F5_c2_postex",
                 "Implantar persistencia en el lab vía tarea programada "
                 "(artefacto controlado, ventana horaria y firma del operador).",
                 "persistencia.implantar",
                 "Creación de tarea (4698) fuera de SCCM/GPO, comando con "
                 "línea base desconocida."),
            Paso(9, "T1070.001", "Indicator Removal: Clear Windows Event Logs", "cierre",
                 "Higiene del adversario: borrar rastros. El despliegue NO "
                 "ejecuta borrado de logs — el paso queda como guion manual "
                 "para ejercitar la DETECCIÓN del blue team bajo su control.",
                 "manual",
                 "Evento 1102/104 (log limpiado) ES la detección esperada: "
                 "el blue team debe alertar en minutos."),
        )),
    Cadena(
        id="entrada_web_postex",
        nombre="Acceso inicial web + postex silenciosa",
        perfil="Adversario externo con exploit conocido (sin zero-day)",
        objetivo="Demostrar explotación de app pública, acceso al host del lab "
                 "y persistencia de arranque sin activar el blue team.",
        descripcion=(
            "Cadena externa → interna: fingerprinting pasivo, explotación "
            "controlada vía MSF, y persistencia de intérprete en el host del "
            "lab verificada con activación real. Énfasis en bajo ruido."),
        pasos=(
            Paso(1, "T1592.002", "Gather Victim Host Information: Software", "F1_osint",
                 "Fingerprinting de stack tecnológico sin tocar el host "
                 "(cabeceras, metafiles, artefactos públicos).",
                 "recon.tech_fingerprint",
                 "Mínimo ruido: peticiones HTTP normales; el blue team debería "
                 "solo ver tasa anómala si correlaciona."),
            Paso(2, "T1590.005", "Gather Victim Network Information: IP Addresses", "F1_osint",
                 "Construir el mapa de superficie con registros públicos "
                 "(certificados, DNS, wayback).",
                 "osint.subdominios_crtsh",
                 "Consulta pasiva a terceros: invisible para el blue team "
                 "del objetivo (eso también se reporta)."),
            Paso(3, "T1190", "Exploit Public-Facing Application", "F3_acceso_inicial",
                 "Ejecutar el módulo de explotación elegido contra el servicio "
                 "en alcance vía Metasploit RPC (requiere firma humana).",
                 "explotar.ejecutar",
                 "Payload desconocido en endpoint público: WAF/EDR, "
                 "control de procesos anómalos, beacon saliente."),
            Paso(4, "T1059", "Command and Scripting Interpreter", "F3_acceso_inicial",
                 "Obtener ejecución de comandos en el host comprometido a "
                 "través de una tarea del C2 del operador (Sliver/Mythic/MSF).",
                 "c2.sliver_tarea",
                 "Shell con proceso padre inusual (ej. servidor web que lanza "
                 "cmd.exe): behavioral detection del EDR."),
            Paso(5, "T1546.016", "Event Triggered Execution: Installer Packages", "F5_c2_postex",
                 "Persistencia de arranque Python (.pth) en el host del lab: "
                 "implantación verificada con activación real del intérprete.",
                 "persistencia.implantar",
                 "Fichero .pth nuevo en site-packages: integridad de ficheros "
                 "(FIM) y revisión de contenido ejecutable."),
            Paso(6, "T1027", "Obfuscated Files or Information", "F5_c2_postex",
                 "Generar artefacto cifrado (AES-256 + XOR) y VERIFICAR contra "
                 "reglas YARA reales que no dispara detecciones.",
                 "evasion.generar",
                 "La medición es local (YARA): el blue team valora ficheros "
                 "de alta entropía con FIM/YARA propios."),
            Paso(7, "T1070.004", "Indicator Removal: File Deletion", "cierre",
                 "Retirada del implante de persistencia con verificación de "
                 "ausencia (higiene de cierre del engagement).",
                 "persistencia.retirar",
                 "Fichero de instalación borrado tras ejecución: FIM con "
                 "retención captura la eliminación."),
        )),
    Cadena(
        id="campana_phishing_guiada",
        nombre="Campaña de phishing con postex en lab",
        perfil="Crimen organizado: acceso inicial por ingeniería social",
        objetivo="Demostrar el ciclo completo de phishing autorizado: OSINT de "
                 "personas → plantilla → envío SMTP real → evaluación de detección.",
        descripcion=(
            "Cadena de acceso inicial por correo bajo doble aprobación "
            "(plantilla + destinatarios) y dominios de laboratorio. El envío "
            "es SMTP real; nada se simula, y los destinos fuera del ROE "
            "se bloquean."),
        pasos=(
            Paso(1, "T1589.001", "Gather Victim Identity Information: Credentials", "F1_osint",
                 "Buscar filtraciones públicas de credenciales del dominio "
                 "objetivo (HIBP u otra fuente autorizada).",
                 "osint.buscar_filtraciones",
                 "Consulta a servicio de terceros: no genera ruido en el "
                 "objetivo (pasivo por diseño)."),
            Paso(2, "T1589.002", "Gather Victim Identity Information: Email Addresses", "F1_osint",
                 "Derivar el patrón de correo corporativo y validar la "
                 "postura anti-spoofing (SPF/DKIM/DMARC) del dominio.",
                 "recon.correos_seguridad",
                 "Pasivo: DNS y registros públicos. Hallazgo directo si el "
                 "dominio carece de DMARC estricto."),
            Paso(3, "T1566.002", "Phishing: Spearphishing Link", "F6_phishing",
                 "Crear la plantilla del ejercicio (asunto, cuerpo, enlace "
                 "de lab) — exige aprobación explícita del operador.",
                 "phishing.crear_plantilla",
                 "Nada sale a la red aún: la plantilla se custodia con hash."),
            Paso(4, "T1566.002", "Phishing: Spearphishing Link (envío)", "F6_phishing",
                 "Enviar la campaña por SMTP REAL a los destinatarios del ROE "
                 "con doble firma; cada entrega queda registrada.",
                 "phishing.enviar_campana",
                 "Gateway de correo: cabeceras spoofed, dominio nuevo, "
                 "enlaces con reputación desconocida. Objetivo: medir si el "
                 "gateway reenvía o cuarentena."),
            Paso(5, "T1546.004", "Event Triggered Execution: .bashrc/.profile", "F5_c2_postex",
                 "Si un 'usuario' del lab ejecuta el adjunto de laboratorio: "
                 "persistencia .bashrc con marcador y prueba de activación "
                 "interactiva real.",
                 "persistencia.implantar",
                 "Shell de arranque que lanza proceso extra: auditoría de "
                 ".bashrc, EDR en el host del lab."),
            Paso(6, "T1114.003", "Email Collection: Email Forwarding Rule", "F5_c2_postex",
                 "Auditar reglas de reenvío sospechosas del lab (lectura "
                 "honesto: si el entorno no las soporta, el paso lo reporta).",
                 "manual",
                 "Reglas de buzón creadas vía protocolo: log de auditoría "
                 "M365/Exchange 'New-InboxRule'."),
        )),
    Cadena(
        id="evasion_y_sigilo",
        nombre="Evasión de detección y sigilo",
        perfil="Adversario averso al ruido (cuidadoso, objetivo de larga duración)",
        objetivo="Demostrar con MEDICIONES que los artefactos del ejercicio "
                 "eluden firmas YARA reales y que la persistencia y su "
                 "retirada dejan el host limpio.",
        descripcion=(
            "Cadena de defensa: cada paso termina en una MEDICIÓN "
            "(detecciones antes/después, round-trip criptográfico, "
            "verificación de ausencia). Es la cadena que más valora un "
            "blue team: convierte 'evasión' en números."),
        pasos=(
            Paso(1, "T1027", "Obfuscated Files or Information", "F5_c2_postex",
                 "Cifrar el payload de laboratorio (AES-256-CBC + PBKDF2) y "
                 "comprobar que YARA deja de detectarlo.",
                 "evasion.generar",
                 "El escaneo antes/después es la evidencia: detecciones 1→0 "
                 "con round-trip verificable."),
            Paso(2, "T1036.005", "Masquerading: Match Legitimate Name or Location", "F5_c2_postex",
                 "Nombres y rutas aleatorios para el artefacto (el generador "
                 "lo hace por defecto; el paso lo documenta y mide entropía).",
                 "evasion.generar",
                 "Comparativa de entropía de Shannon antes/después en la "
                 "evidencia; el FIM del blue team valora nombres raros."),
            Paso(3, "T1543.002", "Create or Modify System Process: Systemd Service", "F5_c2_postex",
                 "Persistencia vía unidad systemd de usuario VALIDADA con "
                 "systemd-analyze (sintaxis real, activación real).",
                 "persistencia.implantar",
                 "Unidad nueva en ~/.config/systemd/user: systemctl status, "
                 "journalctl, EDR con visibilidad de servicios de usuario."),
            Paso(4, "T1098.004", "Account Manipulation: SSH Authorized Keys", "F5_c2_postex",
                 "Clave ed25519 real en authorized_keys del lab; retirada "
                 "selectiva que preserva claves ajenas.",
                 "persistencia.implantar",
                 "Línea nueva en authorized_keys: auditoría de ficheros de "
                 "claves, alerta por clave sin origen conocido."),
            Paso(5, "T1053.003", "Scheduled Task/Job: Cron", "F5_c2_postex",
                 "Artefacto cron generado y custodiado (el runtime del lab "
                 "define si se activa; el paso lo declara honestamente).",
                 "persistencia.implantar",
                 "crontab modificado: auditoría del fichero, hash del artefacto."),
            Paso(6, "T1070.004", "Indicator Removal: File Deletion", "cierre",
                 "Retirar TODOS los implantes del ejercicio y verificar "
                 "ausencia uno a uno: el host queda limpio y demostrado.",
                 "persistencia.retirar",
                 "La retirada es visible para FIM (borrado); la evidencia "
                 "final es 'ausencia_verificada: true' por método."),
        )),
)

for _c in _CADENAS:
    _validar_cadena(_c)


# ---------------------------------------------------------------------------
# API del módulo
# ---------------------------------------------------------------------------


def catalogo() -> list[dict[str, Any]]:
    """Resumen de las cadenas disponibles (índice ligero para la consola)."""
    return [c.resumen() for c in _CADENAS]


def obtener(cadena_id: str) -> Optional[Cadena]:
    for c in _CADENAS:
        if c.id == cadena_id:
            return c
    return None


def detalle(cadena: Cadena) -> dict[str, Any]:
    """Detalle completo con el ruido REAL de cada herramienta."""
    pasos = []
    for p in cadena.pasos:
        pasos.append({
            "orden": p.orden, "tecnica": p.tecnica, "nombre": p.nombre,
            "fase": p.fase, "descripcion": p.descripcion,
            "herramienta": p.herramienta, "es_manual": p.es_manual,
            "deteccion": p.deteccion,
            "ruido_estimado": RUIDO.get(p.herramienta, 0) if not p.es_manual else 0,
        })
    return {
        "id": cadena.id, "nombre": cadena.nombre, "perfil": cadena.perfil,
        "objetivo": cadena.objetivo, "descripcion": cadena.descripcion,
        "pasos": pasos,
        "ruido_total_estimado": sum(p["ruido_estimado"] for p in pasos),
    }


def plan_para_caso(
    cadena: Cadena,
    tecnicas_ejercitadas: set[str],
) -> dict[str, Any]:
    """Contrasta la cadena contra lo que el caso YA ha ejercitado.

    `tecnicas_ejercitadas` proviene de datos REALES del caso (hallazgos con
    técnica + auditoría de herramientas ejecutadas). Estado por paso:
    - "ejercitado": hay evidencia del caso con esa técnica.
    - "disponible": la herramienta existe en el boundary del despliegue.
    - "manual": el despliegue no la ejecuta; guion para el operador.
    """
    pasos = []
    for p in cadena.pasos:
        if p.tecnica in tecnicas_ejercitadas:
            estado = "ejercitado"
            nota = "Hay hallazgo/evidencia de esta técnica en este caso"
        elif p.es_manual:
            estado = "manual"
            nota = "El despliegue no la ejecuta: guion manual bajo tu control"
        elif p.herramienta in RUIDO:
            estado = "disponible"
            nota = f"Herramienta del despliegue: {p.herramienta}"
        else:
            estado = "manual"
            nota = f"'{p.herramienta}' no está en el boundary vigente"
        pasos.append({
            "orden": p.orden, "tecnica": p.tecnica, "nombre": p.nombre,
            "fase": p.fase, "descripcion": p.descripcion,
            "herramienta": p.herramienta, "deteccion": p.deteccion,
            "estado": estado, "nota": nota,
            "ruido_estimado": RUIDO.get(p.herramienta, 0) if not p.es_manual else 0,
        })
    return {
        "cadena_id": cadena.id, "nombre": cadena.nombre,
        "perfil": cadena.perfil, "objetivo": cadena.objetivo,
        "pasos": pasos,
        "resumen": {
            "total": len(pasos),
            "ejercitados": sum(1 for p in pasos if p["estado"] == "ejercitado"),
            "disponibles": sum(1 for p in pasos if p["estado"] == "disponible"),
            "manuales": sum(1 for p in pasos if p["estado"] == "manual"),
            "ruido_total_estimado": sum(p["ruido_estimado"] for p in pasos),
        },
    }


def tecnicas_ejercitadas_de(hallazgos: list[dict[str, Any]],
                            acciones: list[dict[str, Any]]) -> set[str]:
    """Extrae técnicas con evidencia REAL del caso.

    Fuente honesta: hallazgos con tecnica_mitre + herramientas de auditoría
    cuya acción sea de ejecución (boundary:permitir / fase ejecutada). El id
    se normaliza a mayúsculas y se valida contra el patrón ATT&CK.
    """
    tecnicas: set[str] = set()
    for h in hallazgos:
        t = (h.get("tecnica_mitre") or "").strip().upper()
        if t and _ID_TECNICA.fullmatch(t):
            tecnicas.add(t)
    for a in acciones:
        t = (a.get("tecnica_mitre") or "").strip().upper()
        if t and _ID_TECNICA.fullmatch(t):
            tecnicas.add(t)
    return tecnicas
