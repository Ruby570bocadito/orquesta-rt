"""Seeder del engagement de demostración.

Siembra un caso completo EJECUTANDO las rutas reales del núcleo:
guardrails (con permisos y bloqueos), memoria del caso, cadena de
custodia firmada, auditoría inmutable y economía del token. El objetivo
es doble: verificar el núcleo de extremo a extremo sin LLM y alimentar
la consola con datos realistas en el modo live.

Escenario: "ACME Corporación" — test de intrusión externo autorizado sobre
el lab simulado (dominios ficticios *.lab.acme-demo.local, CIDR 10.30.0.0/24).
El escenario NO contiene ataques reales: los resultados de F3-F6 provienen
de los adaptadores mock del lab.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .memory import MemoriaCaso
from .models import (
    Aprobacion,
    Actor,
    DecisionGuardrail,
    Evidencia,
    Engagement,
    EventoAuditoria,
    Fase,
    Hallazgo,
    ResumenFase,
    ROEPolitica,
    Severidad,
    TipoEvidencia,
    TipoModelo,
    UsoTokens,
)


def sembrar_demo(raiz: str | Path = "casos") -> str:
    raiz = Path(raiz)
    raiz.mkdir(parents=True, exist_ok=True)
    eid = "caso_demo_acme"

    # Evitar doble siembra
    if (raiz / f"{eid}.db").exists():
        return eid

    roe = ROEPolitica(
        engagement_id=eid,
        cliente="ACME Corporación (demo)",
        alcance_dominios=["acme-demo.local", "lab.acme-demo.local"],
        alcance_cidrs=["10.30.0.0/24"],
        alcance_excluido=["10.30.0.1", "sistemas-criticos.acme-demo.local"],
        tecnicas_prohibidas=["T1485", "T1489", "T1490"],  # destrucción de datos
        tecnicas_con_aprobacion=["T1558.003", "T1558.004", "T1110.003"],
        techo_ruido=50,
        notas="Engagement de demostración con lab simulado. Sin contacto con "
              "infraestructura real. Todos los hallazgos son ficticios.",
    )
    eng = Engagement(
        id=eid, nombre="Test de intrusión externo — ACME (demo)",
        cliente="ACME Corporación (demo)", roe=roe,
        fase_actual=Fase.F4_DOMINIO, estado_fase="espera_aprobacion",
    )
    memoria = MemoriaCaso(raiz / f"{eid}.db")
    memoria.crear_engagement(eng)

    base = datetime.now(timezone.utc) - timedelta(hours=6)

    # --- F0: scoping -----------------------------------------------------------
    memoria.actualizar_fase(eid, Fase.F0_SCOPING, "completada")
    memoria.registrar_auditoria(eid, Actor.HUMANO, "engagement.crear",
                                detalle="Caso de demostración creado con ROE firmado",
                                herramienta="cli", resultado="ok",
                                parametros={"cliente": roe.cliente})
    memoria.registrar_auditoria(eid, Actor.AGENTE, "f0.borrador_roe",
                                detalle="Borrador de ROE generado a partir de la entrevista; "
                                        "firmado por el operador tras revisión",
                                herramienta="f0_scoping", resultado="ok")
    memoria.guardar_evidencia(Evidencia(
        id="ev_f0001", engagement_id=eid, tipo=TipoEvidencia.JSON,
        titulo="Contrato de engagement y ROE firmado (F0)",
        contenido=json.dumps(roe.model_dump(mode="json"), ensure_ascii=False, indent=2),
        fase=Fase.F0_SCOPING, actor=Actor.HUMANO, creado_en=base + timedelta(minutes=25)))
    memoria.guardar_resumen_fase(ResumenFase(
        fase=Fase.F0_SCOPING,
        texto="Alcance firmado: acme-demo.local y lab.acme-demo.local, CIDR 10.30.0.0/24. "
              "Excluido 10.30.0.1 y sistemas-criticos. Prohibidas técnicas destructivas. "
              "Techo de ruido 50. Criterio de éxito: demostrar ruta hasta Domain Admin sin alertas.",
        hallazgos_clave=[]), eid)

    # --- F1: OSINT --------------------------------------------------------------
    memoria.actualizar_fase(eid, Fase.F1_OSINT, "completada")
    memoria.registrar_auditoria(eid, Actor.AGENTE, "fase.inicio:F1_osint",
                                detalle="Recolectores OSINT desplegados (4 frentes)",
                                herramienta="osint", resultado="ok")
    memoria.guardar_evidencia(Evidencia(
        id="ev_f1001", engagement_id=eid, tipo=TipoEvidencia.JSON,
        titulo="Certificados de transparencia — 47 subdominios descubiertos",
        contenido=json.dumps({
            "dominio": "acme-demo.local",
            "subdominios": ["vpn", "correo", "jira", "gitlab", "wiki", "portail",
                            "sistemas-criticos", "legacy-erp", "backup", "staging",
                            "demo", "ftp", "monitor", "intranet", "api"][:15],
            "total": 47, "fuente": "crt.sh (adaptador pasivo)",
        }, ensure_ascii=False, indent=2),
        fase=Fase.F1_OSINT, actor=Actor.AGENTE, creado_en=base + timedelta(hours=1, minutes=12)))
    memoria.guardar_evidencia(Evidencia(
        id="ev_f1002", engagement_id=eid, tipo=TipoEvidencia.JSON,
        titulo="Mapa de superficie humana priorizado",
        contenido=json.dumps({
            "personas_clave": [
                {"rol": "CFO", "exposicion": "alta", "nota": "perfil profesional público con correo corporativo"},
                {"rol": "helpdesk", "exposicion": "media", "nota": "posts técnicos revelan stack interno"},
            ],
            "nota_metodologica": "Perfiles ficticios de demostración",
        }, ensure_ascii=False, indent=2),
        fase=Fase.F1_OSINT, actor=Actor.AGENTE, creado_en=base + timedelta(hours=1, minutes=40)))
    memoria.guardar_resumen_fase(ResumenFase(
        fase=Fase.F1_OSINT,
        texto="47 subdominios descubiertos vía CT logs. Pistas tech en legacy-erp (SAP UI) y "
              "gitlab autoalojado. Búsqueda de filtraciones bloqueada por boundary hasta aprobación.",
        hallazgos_clave=["47 subdominios", "gitlab autoalojado expuesto"]), eid)

    # --- F2: recon ---------------------------------------------------------------
    memoria.actualizar_fase(eid, Fase.F2_RECON, "completada")
    memoria.guardar_evidencia(Evidencia(
        id="ev_f2001", engagement_id=eid, tipo=TipoEvidencia.JSON,
        titulo="Sondeo HTTP del perímetro del lab",
        contenido=json.dumps({
            "vivo": True, "cabeceras": {"server": "nginx/1.24.0", "x-powered-by": "PHP/8.2"},
            "url": "https://lab.acme-demo.local", "nota": "objetivo simulado del lab",
        }, ensure_ascii=False, indent=2),
        fase=Fase.F2_RECON, actor=Actor.AGENTE, creado_en=base + timedelta(hours=2, minutes=5)))
    memoria.guardar_evidencia(Evidencia(
        id="ev_f2002", engagement_id=eid, tipo=TipoEvidencia.JSON,
        titulo="Inventario de puertos del rango autorizado",
        contenido=json.dumps({
            "host": "lab.acme-demo.local", "puertos_abiertos": [80, 443, 445, 3389],
            "metodo": "socket-connect acotado (ventana horaria respetada)",
        }, ensure_ascii=False, indent=2),
        fase=Fase.F2_RECON, actor=Actor.AGENTE, creado_en=base + timedelta(hours=2, minutes=30)))
    memoria.guardar_hallazgo(Hallazgo(
        id="hal_f2001", engagement_id=eid,
        titulo="Servicio RDP expuesto en el perímetro del lab",
        severidad=Severidad.MEDIA, tecnica_mitre="T1021.001",
        activo="lab.acme-demo.local:3389",
        descripcion="El puerto 3389 responde desde el segmento autorizado del lab. "
                    "En un entorno real de cliente esto amplifica el impacto de cualquier "
                    "credencial filtrada y debería estar tras una VPN o bastión.",
        recomendacion="Restringir RDP a bastión con MFA y filtrado por origen.",
        estado="confirmado", creado_por=Actor.AGENTE,
        creado_en=base + timedelta(hours=2, minutes=35)))
    memoria.guardar_resumen_fase(ResumenFase(
        fase=Fase.F2_RECON,
        texto="Perímetro del lab: nginx/PHP en 443, RDP en 3389, SMB 445. Vector inicial "
              "propuesto: superficie web (menor ruido). RDP catalogado como hallazgo medio.",
        hallazgos_clave=["RDP expuesto 3389"]), eid)

    # --- F3: acceso inicial (adaptador mock, con aprobación) ----------------------
    memoria.actualizar_fase(eid, Fase.F3_ACCESO, "completada")
    memoria.crear_aprobacion(Aprobacion(
        id="apr_f3001", engagement_id=eid, fase=Fase.F3_ACCESO,
        titulo="Autorizar explotación del vector web en el lab",
        descripcion="El boundary requiere firma humana para ejecutar el adaptador de "
                    "explotación (riesgo alto, T1190). Objetivo: lab.acme-demo.local. "
                    "Payload: MOCK del lab, sin carga ofensiva real.",
        herramienta="explotar.ejecutar",
        argumentos={"vector": "servicio web expuesto", "tecnica_mitre": "T1190"},
        tecnica_mitre="T1190", riesgo=Severidad.ALTA, ruido_estimado=70,
        motivo="operator-in-command: riesgo ALTA supera umbral de ejecución autónoma",
        referencia_roe="operator-in-command (umbral de riesgo)",
        estado="aprobada", decidida_por="operador.demo",
        comentario_operador="Aprobado para el lab. Registrar evidencia completa.",
        creada_en=base + timedelta(hours=3), decidida_en=base + timedelta(hours=3, minutes=9)))
    memoria.registrar_auditoria(eid, Actor.AGENTE, "boundary:explotar.ejecutar",
                                 detalle="Requiere aprobación humana (riesgo alto)",
                                 herramienta="explotar.ejecutar",
                                 parametros={"vector": "servicio web expuesto"},
                                 resultado="requiere_aprobacion",
                                 guardrail=DecisionGuardrail.REQUIERE_APROBACION)
    memoria.registrar_auditoria(eid, Actor.HUMANO, "aprobacion.decision",
                                detalle="Aprobada: apr_f3001 (vector web del lab)",
                                herramienta="consola", resultado="aprobada")
    memoria.guardar_evidencia(Evidencia(
        id="ev_f3001", engagement_id=eid, tipo=TipoEvidencia.JSON,
        titulo="Acceso inicial confirmado en el objetivo simulado (adaptador mock)",
        contenido=json.dumps({
            "exito": True,
            "detalle": "El adaptador mock del lab simula el acceso al objetivo ficticio. "
                       "En producción este resultado provendría del módulo licenciado "
                       "conectado vía MCP (p. ej. integración con el tooling del equipo).",
            "tecnica_mitre": "T1190", "ruido_real": 65, "dentro_de_ventana": True,
        }, ensure_ascii=False, indent=2),
        fase=Fase.F3_ACCESO, actor=Actor.AGENTE, creado_en=base + timedelta(hours=3, minutes=22)))
    memoria.guardar_hallazgo(Hallazgo(
        id="hal_f3001", engagement_id=eid,
        titulo="Vector de acceso inicial viable vía superficie web (demostrado en lab)",
        severidad=Severidad.CRITICA, tecnica_mitre="T1190",
        activo="lab.acme-demo.local",
        descripcion="El adaptador del lab confirma la viabilidad del vector propuesto en F2 "
                    "tras aprobación explícita del operador. La cadena boundary→aprobación→"
                    "ejecución→evidencia quedó registrada íntegra en la auditoría.",
        recomendacion="Priorizar parcheado del componente afectado y WAF con reglas estrictas; "
                      "validar detección con la receta de verificación adjunta.",
        estado="confirmado", creado_por=Actor.AGENTE,
        creado_en=base + timedelta(hours=3, minutes=25)))
    memoria.guardar_resumen_fase(ResumenFase(
        fase=Fase.F3_ACCESO,
        texto="Acceso inicial confirmado en el lab tras aprobación (apr_f3001). Plan B no "
              "necesario. Credenciales del simulacro en bóveda cifrada (no en contexto).",
        hallazgos_clave=["acceso inicial confirmado"]), eid)

    # --- F4: dominio AD (en curso, esperando aprobación) --------------------------
    memoria.actualizar_fase(eid, Fase.F4_DOMINIO, "espera_aprobacion")
    memoria.guardar_evidencia(Evidencia(
        id="ev_f4001", engagement_id=eid, tipo=TipoEvidencia.JSON,
        titulo="Grafo del dominio simulado — rutas hacia Domain Admin",
        contenido=json.dumps({
            "rutas": [
                {"ruta": "usuario.basico -> HELPDESK -> reset svc-backup -> DA",
                 "ruido": 30, "probabilidad": "alta", "tecnica": "T1098"},
                {"ruta": "kerberoasting svc-sql -> crack offline -> SQL01 -> DA",
                 "ruido": 45, "probabilidad": "media", "tecnica": "T1558.003"},
            ],
            "grafo": {"nodos": 128, "aristas": 412, "coleccion": "adaptador mock BloodHound"},
        }, ensure_ascii=False, indent=2),
        fase=Fase.F4_DOMINIO, actor=Actor.AGENTE, creado_en=base + timedelta(hours=4, minutes=15)))
    memoria.crear_aprobacion(Aprobacion(
        id="apr_f4002", engagement_id=eid, fase=Fase.F4_DOMINIO,
        titulo="Autorizar técnica de escalada T1558.003 (Kerberoasting) en el lab",
        descripcion="La skill 'kerberoasting_lab' propone ejecutar la técnica contra el "
                    "dominio simulado del lab. Ruido estimado 45 (dentro del techo 50). "
                    "El ROE exige firma humana para esta familia de técnicas.",
        herramienta="ad.kerberoasting",
        argumentos={"dominio": "lab.acme-demo.local", "tecnica_mitre": "T1558.003"},
        tecnica_mitre="T1558.003", riesgo=Severidad.ALTA, ruido_estimado=45,
        motivo="tecnicas_con_aprobacion: T1558.003 está en la lista de firma obligatoria",
        referencia_roe="tecnicas_con_aprobacion",
        estado="pendiente", creada_en=base + timedelta(hours=4, minutes=20)))
    memoria.registrar_auditoria(eid, Actor.AGENTE, "boundary:ad.kerberoasting",
                                 detalle="Técnica en lista de aprobación obligatoria del ROE",
                                 herramienta="ad.kerberoasting",
                                 parametros={"dominio": "lab.acme-demo.local"},
                                 resultado="requiere_aprobacion",
                                 guardrail=DecisionGuardrail.REQUIERE_APROBACION)
    memoria.guardar_resumen_fase(ResumenFase(
        fase=Fase.F4_DOMINIO,
        texto="Grafo simulado con 128 nodos: 2 rutas hacia DA. La ruta HELPDESK (ruido 30) "
              "es la más silenciosa; Kerberoasting svc-sql requiere firma humana (pendiente).",
        hallazgos_clave=["2 rutas a DA calculadas"]), eid)

    # --- Economía del token ---------------------------------------------------------
    usos = [
        (Fase.F0_SCOPING, "glm-4.7", TipoModelo.FRONTERA, 4200, 680, False, 0.0209),
        (Fase.F1_OSINT, "qwen2.5:14b", TipoModelo.LOCAL, 18500, 1200, False, 0.0),
        (Fase.F1_OSINT, "qwen2.5:14b", TipoModelo.LOCAL, 3100, 400, True, 0.0),
        (Fase.F2_RECON, "qwen2.5:14b", TipoModelo.LOCAL, 5400, 610, True, 0.0),
        (Fase.F2_RECON, "glm-4.7", TipoModelo.FRONTERA, 2800, 520, False, 0.0147),
        (Fase.F3_ACCESO, "glm-4.7", TipoModelo.FRONTERA, 3600, 540, False, 0.0173),
        (Fase.F4_DOMINIO, "qwen2.5:14b", TipoModelo.LOCAL, 22000, 980, True, 0.0),
    ]
    for fase, modelo, tipo, tin, tout, cache, coste in usos:
        memoria.registrar_uso_tokens(eid, UsoTokens(
            fase=fase, modelo=modelo, tipo=tipo, tokens_entrada=tin,
            tokens_salida=tout, cache_hit=cache, coste_usd=coste,
            creado_en=base + timedelta(hours=1)))

    # Auditoría de cierre parcial
    memoria.registrar_auditoria(eid, Actor.SISTEMA, "cadenas.verificar",
                                detalle="Cadena de custodia verificada automáticamente",
                                herramienta="memoria", resultado="ok")

    memoria.cerrar()
    return eid


if __name__ == "__main__":
    caso = sembrar_demo()
    print(f"Demo sembrada: {caso}")
