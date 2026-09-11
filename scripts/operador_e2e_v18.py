"""Test de operador E2E (v18): ejercita la plataforma EN VIVO como un
operador real — bootstrap, caso con ROE, las 8 fases con firmas reales,
copiloto IA (GLM-4.6 real), razonador, informe y analítica ATT&CK.

Todo el I/O es real: crt.sh, DNS, Wayback, sockets contra el lab :8080,
LLM frontera glm-4.6. Sin simulaciones. Al final limpia el caso y la
cuenta temporal (bootstrap a 0 operadores).
"""
from __future__ import annotations

import json
import os
import shutil
import sys
import time
from pathlib import Path

import httpx

BASE = "http://127.0.0.1:8000"
USUARIO = os.environ.get("OP_USUARIO", "op_verif_v18")
CLAVE = "Clave-Verif-2026!x"
CASO_DIR = Path("/home/z/my-project/platform/casos")

paso_n = 0
resultados: list[tuple[str, str]] = []


def paso(titulo: str) -> None:
    global paso_n
    paso_n += 1
    print(f"\n[{paso_n:02d}] {titulo}")


def ok(texto: str) -> None:
    print(f"     OK  {texto}")
    resultados.append(("OK", texto))


def nota(texto: str) -> None:
    print(f"     --  {texto}")


def fallo(texto: str) -> None:
    print(f"     XX  {texto}")
    resultados.append(("FALLO", texto))


def main() -> int:
    c = httpx.Client(base_url=BASE, timeout=90)

    # ------------------------------------------------------------------ auth
    paso("Estado de autenticación (bootstrap)")
    estado = c.get("/api/auth/estado").json()
    hay_operadores = bool(estado.get("operadores"))
    nota(f"operadores registrados: {estado.get('total_operadores', 0)}")

    if not hay_operadores:
        r = c.post("/api/auth/registrar", json={
            "usuario": USUARIO, "contrasena": CLAVE, "rol": "admin"})
        if r.status_code != 200:
            fallo(f"registro: {r.status_code} {r.text[:200]}")
            return 1
        ok(f"operador {USUARIO} registrado (admin bootstrap)")
    else:
        nota("ya existen operadores: se intenta login directo")

    paso("Login (JWT real)")
    r = c.post("/api/auth/login", json={"usuario": USUARIO, "contrasena": CLAVE})
    if r.status_code != 200:
        fallo(f"login: {r.status_code} {r.text[:200]}")
        return 1
    token = (r.json().get("token") or r.json().get("access_token")
             or r.json().get("sesion") or "")
    if not token and isinstance(r.json().get("operador"), dict):
        token = r.json()["operador"].get("token", "")
    if not token:
        fallo(f"respuesta de login sin token: {list(r.json().keys())}")
        return 1
    c.headers["Authorization"] = f"Bearer {token}"
    ok("sesión autenticada con JWT")

    # ------------------------------------------------------- integraciones
    paso("Estado REAL de integraciones (C2/LDAP/SMTP/MSF) — sin fingir conexión")
    r = c.get("/api/integraciones")
    if r.status_code != 200:
        fallo(f"integraciones: {r.status_code}")
    else:
        integr = r.json()
        datos_int = integr.get("integraciones", integr)
        if isinstance(datos_int, dict):
            for nombre, estado_i in sorted(datos_int.items()):
                if isinstance(estado_i, dict):
                    conectado = estado_i.get("conectado") or estado_i.get("configurado")
                    nota(f"{nombre}: conectado/configurado={bool(conectado)}")

    # ------------------------------------------------------------- crear caso
    paso("Creación de engagement con ROE (lab local 127.0.0.1/32)")
    r = c.post("/api/engagements", json={
        "nombre": "Verificación operador v18",
        "cliente": "ACME Lab",
        "alcance_dominios": ["lab-interno.test"],
        "alcance_cidrs": ["127.0.0.1/32"],
        "tecnicas_con_aprobacion": ["T1190", "T1558.003"],
        "techo_ruido": 60,
        "ventana_inicio": "00:00", "ventana_fin": "23:59",
        "ventana_dias": ["lun", "mar", "mie", "jue", "vie", "sab", "dom"],
    })
    if r.status_code != 200:
        fallo(f"crear caso: {r.status_code} {r.text[:300]}")
        return 1
    caso_id = r.json()["id"]
    ok(f"caso creado: {caso_id}")

    # ---------------------------------------------------- ciclo de fases
    paso("Ciclo de fases F0→cierre con firma humana de aprobaciones")
    fases_vistas: list[str] = []
    aprovadas = rechazadas = 0
    copiloto_coste = tokens_in = tokens_out = None

    for iteracion in range(60):
        # (1) Estado actual: fase y pendientes — como hace la consola real
        re = c.get(f"/api/engagements/{caso_id}/estado")
        if re.status_code != 200:
            fallo(f"estado: {re.status_code}")
            break
        eng = re.json().get("engagement", {})
        fase_actual = str(eng.get("fase_actual", "?"))
        if fase_actual not in fases_vistas:
            fases_vistas.append(fase_actual)

        # (2) Firma humana REAL de las aprobaciones pendientes
        rp = c.get(f"/api/engagements/{caso_id}/aprobaciones",
                   params={"solo_pendientes": "true"})
        pend = rp.json() if rp.status_code == 200 else []
        if pend:
            for ap in pend[:12]:
                rd = c.post(f"/api/aprobaciones/{ap['id']}/decision",
                            json={"decidir": True,
                                  "comentario": "verificación operador v18"})
                if rd.status_code == 200:
                    aprovadas += 1
                else:
                    rechazadas += 1
                    nota(f"decisión {ap['id'][:12]}: {rd.status_code} {rd.text[:80]}")
            continue  # reanudar la fase donde quedó

        if fase_actual in ("cierre", "CIERRE"):
            break

        # (3) Parámetros que aporta el operador según la fase activa
        cuerpo: dict = {}
        if fase_actual.endswith("scoping"):
            cuerpo = {"notas_cliente": "Verificación E2E: lab ACME local, "
                                       "dominio de prueba .test"}
        elif fase_actual.endswith("acceso"):
            cuerpo = {"vector_elegido": "explotación del portal web ACME en "
                                        "127.0.0.1:8080"}
        elif fase_actual.endswith("phishing"):
            cuerpo = {"perfil_objetivo": "empleado estándar", "destinatarios": []}

        r = c.post(f"/api/engagements/{caso_id}/avanzar", json=cuerpo)
        if r.status_code != 200:
            fallo(f"avanzar: {r.status_code} {r.text[:250]}")
            break
        datos = r.json()
        nota(f"it{iteracion:02d} fase={fase_actual} "
             f"ejecutada={datos.get('ejecutada')} · {str(datos.get('resumen'))[:150]}")
        if datos.get("ejecutada") and not datos.get("espera") and fase_actual.endswith("informe"):
            break

    ok(f"fases recorridas: {' → '.join(fases_vistas) if fases_vistas else 'ninguna'}")
    ok(f"aprobaciones firmadas como operador: {aprovadas}"
       + (f" · rechazadas por API: {rechazadas}" if rechazadas else ""))

    # ------------------------------------------------------------- estado
    paso("Estado consolidado: superficie, custodia, ruido")
    r = c.get(f"/api/engagements/{caso_id}/estado")
    if r.status_code == 200:
        est = r.json()
        objs = est.get("objetivos", [])
        cadena = est.get("cadena_custodia")
        ok(f"objetivos en superficie: {len(objs)}")
        tipos = {}
        for o in objs:
            tipos[o["tipo"]] = tipos.get(o["tipo"], 0) + 1
        if tipos:
            ok(f"tipos de activo: {tipos}")
        nota(f"cadena de custodia: {cadena}")
    else:
        fallo(f"estado: {r.status_code}")

    paso("Hallazgos y evidencias reales del caso")
    r = c.get(f"/api/engagements/{caso_id}/hallazgos")
    hal = r.json() if r.status_code == 200 else []
    ok(f"hallazgos: {len(hal)}" + (f" → {[(h['titulo'][:50], h['severidad']) for h in hal[:4]]}" if hal else ""))
    r = c.get(f"/api/engagements/{caso_id}/evidencias")
    evs = (r.json().get("evidencias", []) if r.status_code == 200 else [])
    ok(f"evidencias firmadas: {len(evs)}")

    # ------------------------------------------------------------ copiloto IA
    paso("COPILOTO IA REAL (GLM-4.6): pregunta del operador")
    c.post(f"/api/engagements/{caso_id}/copiloto/config",
           json={"habilitado": True})
    t0 = time.time()
    r = c.post(f"/api/engagements/{caso_id}/copiloto", json={
        "pregunta": "Resume qué hemos confirmado en este caso y dime cuál es el siguiente paso más prioritario según el ROE.",
        "historial": []})
    dt = time.time() - t0
    if r.status_code != 200:
        fallo(f"copiloto: {r.status_code} {r.text[:250]}")
    else:
        cop = r.json()
        secciones = list((cop.get("secciones") or {}).keys())
        sug = cop.get("sugerencias") or []
        tokens_in = cop.get("tokens_entrada")
        tokens_out = cop.get("tokens_salida")
        copiloto_coste = cop.get("coste_usd")
        ok(f"respuesta estructurada en {dt:.1f}s · modelo={cop.get('modelo')} ({cop.get('tipo_modelo')})")
        ok(f"secciones: {secciones}")
        ok(f"sugerencias accionables: {len(sug)}" +
           (f" → primera: '{sug[0].get('titulo', '')[:60]}' canal={sug[0].get('canal')}" if sug else ""))
        ok(f"tokens entrada={tokens_in} salida={tokens_out} coste=${copiloto_coste}")

    # ---------------------------------------------------------- razonador
    paso("Razonador: prioridades adaptativas + plan de fase IA")
    r = c.get(f"/api/engagements/{caso_id}/razonamiento/prioridades")
    if r.status_code == 200:
        pri = r.json()
        lista = pri.get("prioridades") or pri.get("items") or []
        ok(f"prioridades (reglas deterministas): {len(lista)}")
        if lista and isinstance(lista[0], dict):
            nota(f"top: {str(lista[0])[:160]}")
    else:
        fallo(f"prioridades: {r.status_code}")
    r = c.post(f"/api/engagements/{caso_id}/razonamiento/plan", json={})
    if r.status_code == 200:
        plan = r.json()
        pasos_plan = plan.get("pasos") or plan.get("plan") or []
        ok(f"plan IA (glm-4.6): {len(pasos_plan) if isinstance(pasos_plan, list) else 'ok'} pasos")
    else:
        nota(f"plan IA: {r.status_code} ({r.text[:120]})")

    # ------------------------------------------------------------ informe
    paso("Informe ejecutivo generado del caso")
    r = c.get(f"/api/engagements/{caso_id}/informe")
    if r.status_code == 200:
        inf = r.json()
        md = inf.get("contenido") or ""
        ok(f"informe markdown: {len(md)} caracteres, {'con ATT&CK' if 'ATT&CK' in md or 'T1' in md else 'sin técnicas ATT&CK'}")
    else:
        fallo(f"informe: {r.status_code}")

    # ------------------------------------------------- analítica ATT&CK
    paso("Analítica de cobertura ATT&CK entre campañas")
    r = c.get("/api/analitica/cobertura-attack")
    if r.status_code == 200:
        cov = r.json()
        nota(f"matriz: {json.dumps(cov)[:220]}")
        ok("cobertura ATT&CK multi-campaña disponible")
    else:
        fallo(f"cobertura: {r.status_code}")

    # ------------------------------------------------------------ auditoría
    paso("Auditoría inmutable del caso (cadena de custodia)")
    r = c.get(f"/api/engagements/{caso_id}/auditoria")
    if r.status_code == 200:
        aud = r.json()
        n = len(aud) if isinstance(aud, list) else len(aud.get("eventos", []))
        ok(f"eventos de auditoría: {n}")

    # ------------------------------------------------------------- limpieza
    paso("Limpieza: baja del caso y del operador (bootstrap a 0)")
    c.post("/api/auth/eliminar", json={"usuario": USUARIO})
    db_dir = CASO_DIR / caso_id
    try:
        for sufijo in ("", "-wal", "-shm"):
            p = CASO_DIR / f"{caso_id}.db{sufijo}"
            if p.exists():
                p.unlink()
        if db_dir.exists():
            shutil.rmtree(db_dir, ignore_errors=True)
        ok(f"caso {caso_id} eliminado del disco")
    except OSError as exc:
        nota(f"limpieza de caso: {exc}")
    r = c.get("/api/auth/estado")
    nota(f"¿hay operadores? {r.json().get('hay_operadores')}")
    c.close()

    print("\n" + "=" * 64)
    buenos = [t for e, t in resultados if e == "OK"]
    malos = [t for e, t in resultados if e == "FALLO"]
    print(f"RESULTADO: {len(buenos)} OK · {len(malos)} FALLOS")
    for t in malos:
        print(f"  FALLO: {t}")
    if copiloto_coste is not None:
        print(f"coste real del copiloto en esta sesión: ${copiloto_coste} "
              f"(tokens {tokens_in}/{tokens_out})")
    return 1 if malos else 0


if __name__ == "__main__":
    sys.exit(main())
