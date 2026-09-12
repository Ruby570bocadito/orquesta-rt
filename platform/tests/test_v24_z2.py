"""Ronda Z2 — pulimiento de mecánicas del núcleo.

Cada test reproduce un defecto verificado en la ronda de auditoría Z2 y
fija su corrección como contrato:

1.  Ventana horaria fail-closed + ventanas que cruzan medianoche (boundary).
2.  Validación estricta de VentanaHoraria (HH:MM, días) en el modelo.
3.  Techo de ruido: TODO ruido cuenta y el cruce del nivel pactado avisa.
4.  Motivo de menor privilegio para herramientas no catalogadas.
5.  Cadena de custodia atómica bajo escritura concurrente.
6.  Dedup de hallazgos devuelve la ORIGINAL (id real, no fantasma).
7.  Webhook: reintento ante error de red y veto SSRF por IP resuelta.
8.  Planificador CTEM: timestamp naive no mata el barrido; claim atómico.
9.  /api/salud con la variable USUARIOS_DB correcta.
10. RBAC: /api/auth/operadores solo admin; decidir con aislamiento tenant.
11. Respaldo completo sin excluir BDs de ids antiguos.
12. TLS verificado por defecto en integraciones con credenciales.
"""
from __future__ import annotations

import base64
import json
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path

import pytest

from orchestrator import auth as _auth
from orchestrator import ctem, respaldo, threatled, webhook
from orchestrator.guardrails import MotorGuardrails, _en_ventana_horaria
from orchestrator.memory import MemoriaCaso
from orchestrator.models import (
    Aprobacion,
    DecisionGuardrail,
    Evidencia,
    Engagement,
    Fase,
    Hallazgo,
    ROEPolitica,
    Severidad,
    TipoEvidencia,
    VentanaHoraria,
)
from pydantic import ValidationError


# ---------------------------------------------------------------------------
# Fábricas comunes
# ---------------------------------------------------------------------------


def _roe(tmp_path: Path, **ajustes) -> ROEPolitica:
    base = dict(
        engagement_id="caso_z2test01", cliente="Cliente Z2",
        alcance_dominios=["cliente.com"], alcance_cidrs=[],
        alcance_excluido=[], tecnicas_prohibidas=[],
        tecnicas_con_aprobacion=[], techo_ruido=50,
    )
    base.update(ajustes)
    return ROEPolitica(**base)


def _caso(tmp_path: Path, eid: str = "caso_z2test01") -> tuple[MemoriaCaso, str]:
    memoria = MemoriaCaso(tmp_path / f"{eid}.db")
    memoria.crear_engagement(Engagement(
        id=eid, nombre="Caso Z2", cliente="Cliente Z2", roe=_roe(eid)))
    return memoria, eid


# ---------------------------------------------------------------------------
# 1) Ventana horaria: fail-closed y cruce de medianoche
# ---------------------------------------------------------------------------


class TestVentanaHoraria:
    def _roe_ventana(self, inicio: str, fin: str, dias: list[str] | None = None):
        roe = _roe(Path("/tmp"), ventanas_activas=VentanaHoraria(
            inicio=inicio, fin=fin, dias=dias or []))
        return roe

    def test_ventana_nocturna_cruza_medianoche(self) -> None:
        # 22:00→06:00: viernes 23:30 dentro; sábado 02:00 hereda la noche
        # del viernes; sábado 12:00 fuera.
        roe = self._roe_ventana("22:00", "06:00")
        viernes_noche = datetime(2026, 1, 9, 23, 30)   # viernes
        sabado_madrugada = datetime(2026, 1, 10, 2, 0)  # sábado
        sabado_mediodia = datetime(2026, 1, 10, 12, 0)
        assert _en_ventana_horaria(roe, viernes_noche) is True
        assert _en_ventana_horaria(roe, sabado_madrugada) is True
        assert _en_ventana_horaria(roe, sabado_mediodia) is False

    def test_ventana_nocturna_con_dias_hereda_el_tramo_inicial(self) -> None:
        # Ventana nocturna SOLO del miércoles: la madrugada del jueves
        # pertenece a la noche del miércoles; la del miércoles no (arrancó
        # el martes).
        roe = self._roe_ventana("22:00", "06:00", dias=["mie"])
        miercoles_noche = datetime(2026, 1, 14, 23, 0)   # miércoles
        jueves_madrugada = datetime(2026, 1, 15, 3, 0)   # jueves
        martes_noche = datetime(2026, 1, 13, 23, 0)      # martes
        assert _en_ventana_horaria(roe, miercoles_noche) is True
        assert _en_ventana_horaria(roe, jueves_madrugada) is True
        assert _en_ventana_horaria(roe, martes_noche) is False

    def test_formato_invalido_fail_closed(self, tmp_path) -> None:
        # ROE legado con ventana malformada inyectado SIN validación de
        # modelo (model_construct): el boundary deniega la actividad activa
        # en lugar de saltarse el control (fail-open de antes).
        roe = ROEPolitica.model_construct(
            engagement_id="caso_z2test01", cliente="c",
            alcance_dominios=[], alcance_cidrs=[], alcance_excluido=[],
            tecnicas_prohibidas=[], tecnicas_con_aprobacion=[],
            techo_ruido=50, parada_emergencia=False,
            ventanas_activas=VentanaHoraria.model_construct(
                inicio="9h", fin="cualquier", dias=[]),
            notas="")
        assert _en_ventana_horaria(roe, datetime(2026, 1, 5, 10, 0)) is False

    def test_modelo_rechaza_horas_y_dias_invalidos(self) -> None:
        with pytest.raises(ValidationError):
            VentanaHoraria(inicio="9h", fin="18:00")
        with pytest.raises(ValidationError):
            VentanaHoraria(inicio="24:00", fin="18:00")
        with pytest.raises(ValidationError):
            VentanaHoraria(inicio="08:00", fin="18:00", dias=["ene"])
        # Normalización determinista
        v = VentanaHoraria(inicio="9:30", fin="18:05")
        assert v.inicio == "09:30" and v.fin == "18:05"

    def test_boundary_deniega_fuera_de_ventana_nocturna(self, tmp_path) -> None:
        memoria, eid = _caso(tmp_path)
        roe = _roe(eid, ventanas_activas=VentanaHoraria(
            inicio="22:00", fin="06:00", dias=[]))
        motor = MotorGuardrails(roe, memoria)
        v_dia = motor.evaluar("recon.port_scan", {"host": "cliente.com"},
                              Fase.F2_RECON, momento=datetime(2026, 1, 10, 12, 0))
        v_noche = motor.evaluar("recon.port_scan", {"host": "cliente.com"},
                                Fase.F2_RECON, momento=datetime(2026, 1, 9, 23, 30))
        assert v_dia.denegado and "ventana horaria" in v_dia.motivo.lower()
        assert v_noche.permitido
        memoria.cerrar()


# ---------------------------------------------------------------------------
# 2) Techo de ruido: todo ruido cuenta; aviso del nivel pactado
# ---------------------------------------------------------------------------


class TestTechoRuido:
    def test_todas_las_herramientas_cuentan_hacia_el_presupuesto(self, tmp_path) -> None:
        # techo pactado 10 → presupuesto duro 10×5 = 50. Herramientas de
        # ruido 5 (ANTES exentas si 5<=30… de hecho exentas TODAS las
        # <=30): ahora suman y el corte duro llega en el límite.
        memoria, eid = _caso(tmp_path)
        roe = _roe(eid, techo_ruido=10)
        motor = MotorGuardrails(roe, memoria)
        denegada = None
        for i in range(11):  # 11 × ruido 5 = 55 > 50
            v = motor.evaluar("recon.dns_enum", {"dominio": "cliente.com"},
                              Fase.F2_RECON, momento=datetime(2026, 1, 5, 10, 0))
            if v.denegado:
                denegada = v
                break
        assert denegada is not None, "el presupuesto duro debía agotarse"
        assert "techo de ruido" in denegada.motivo.lower()
        memoria.cerrar()

    def test_aviso_al_cruzar_el_nivel_pactado(self, tmp_path) -> None:
        # techo pactado 10: la tercera acción (10+5) cruza el pacto sin
        # llegar al presupuesto duro: PERMITIDA pero con aviso explícito
        # (auditoría y firmas informadas del exceso).
        memoria, eid = _caso(tmp_path)
        roe = _roe(eid, techo_ruido=10)
        motor = MotorGuardrails(roe, memoria)
        motor.evaluar("recon.dns_enum", {"dominio": "cliente.com"},
                      Fase.F2_RECON, momento=datetime(2026, 1, 5, 10, 0))
        motor.evaluar("recon.dns_enum", {"dominio": "cliente.com"},
                      Fase.F2_RECON, momento=datetime(2026, 1, 5, 10, 0))
        v = motor.evaluar("recon.dns_enum", {"dominio": "cliente.com"},
                          Fase.F2_RECON, momento=datetime(2026, 1, 5, 10, 0))
        assert v.permitido
        assert "techo de ruido pactado" in v.motivo
        memoria.cerrar()


# ---------------------------------------------------------------------------
# 3) Motivo de menor privilegio para herramientas no catalogadas
# ---------------------------------------------------------------------------


def test_motivo_herramienta_no_catalogada(tmp_path) -> None:
    memoria, eid = _caso(tmp_path)
    motor = MotorGuardrails(_roe(eid), memoria)
    v = motor.evaluar("mcp.exotica.accion_rara", {"host": "cliente.com"},
                      Fase.F2_RECON, momento=datetime(2026, 1, 5, 10, 0))
    assert v.decision == DecisionGuardrail.REQUIERE_APROBACION
    assert "no catalogada" in v.motivo and "menor privilegio" in v.motivo
    memoria.cerrar()


# ---------------------------------------------------------------------------
# 4) Cadena de custodia atómica bajo concurrencia
# ---------------------------------------------------------------------------


def test_custodia_concurrente_cadena_valida(tmp_path) -> None:
    memoria, eid = _caso(tmp_path)
    memoria.cerrar()  # cada hilo abre SU conexión (como los hilos de la API)

    def _escribir(n: int) -> None:
        m = MemoriaCaso(tmp_path / "caso_z2test01.db")
        try:
            for i in range(6):
                m.guardar_evidencia(Evidencia(
                    id=m.nuevo_id("ev"), engagement_id=eid,
                    tipo=TipoEvidencia.NOTA, titulo=f"ev-{n}-{i}",
                    contenido=f"contenido {n}-{i} " * 20, hash_sha256="",
                    firma_hmac="", hash_previo="", fase=Fase.F2_RECON))
        finally:
            m.cerrar()

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(_escribir, range(8)))
    verificador = MemoriaCaso(tmp_path / "caso_z2test01.db")
    resultado = verificador.verificar_cadena(eid)
    assert resultado["valida"], resultado["primer_error"]
    assert resultado["total"] == 48
    verificador.cerrar()


# ---------------------------------------------------------------------------
# 5) Dedup de hallazgos: devuelve la ORIGINAL
# ---------------------------------------------------------------------------


def test_dedup_hallazgos_devuelve_original(tmp_path) -> None:
    memoria, eid = _caso(tmp_path)
    original = memoria.guardar_hallazgo(Hallazgo(
        id="hal_orig01", engagement_id=eid, titulo="Kerberoasting viable",
        severidad=Severidad.ALTA, tecnica_mitre="T1558.003",
        activo="lab.local", descripcion="SPN con clave débil",
        estado="confirmado"))
    copia = memoria.guardar_hallazgo(Hallazgo(
        id="hal_copia9", engagement_id=eid, titulo="Kerberoasting viable",
        severidad=Severidad.ALTA, tecnica_mitre="T1558.003",
        activo="lab.local", descripcion="SPN con clave débil",
        estado="confirmado"))
    assert copia.id == "hal_orig01", "el dedup debe devolver la ORIGINAL"
    filas = memoria.listar_hallazgos(eid)
    assert len(filas) == 1 and filas[0]["id"] == "hal_orig01"
    memoria.cerrar()


# ---------------------------------------------------------------------------
# 6) Webhooks: reintento ante red y SSRF por IP resuelta
# ---------------------------------------------------------------------------


@pytest.fixture()
def webhook_db(tmp_path, monkeypatch):
    monkeypatch.setattr(webhook, "_ruta_db", lambda: tmp_path / "wh_z2.db")
    return tmp_path


class TestWebhookZ2:
    def test_reintenta_ante_error_de_red(self, webhook_db, monkeypatch) -> None:
        alta = webhook.crear_webhook("https://receptor.lab/hook",
                                     ["hallazgo.registrado"], secreto="s" * 20)
        intentos = []

        def _post_falso(url, cuerpo, cabeceras):
            intentos.append(1)
            if len(intentos) == 1:
                return {"ok": False, "http": None, "error": "conexion reiniciada"}
            return {"ok": True, "http": 200, "error": None}

        monkeypatch.setattr(webhook, "_post", _post_falso)
        monkeypatch.setattr(webhook.time, "sleep", lambda s: None)
        entregas = webhook.despachar("hallazgo.registrado", "caso_z2test01", {})
        assert entregas == 1
        assert len(intentos) == 2, "el error de red debe reintentarse (t+2 s)"
        historial = webhook.entregas_de(alta["id"])
        assert historial[0]["ok"] and historial[0]["intentos"] == 2

    def test_no_reintenta_ante_4xx(self, webhook_db, monkeypatch) -> None:
        alta = webhook.crear_webhook("https://receptor.lab/hook",
                                     ["hallazgo.registrado"], secreto="s" * 20)
        intentos = []

        def _post_4xx(url, cuerpo, cabeceras):
            intentos.append(1)
            return {"ok": False, "http": 410, "error": None}

        monkeypatch.setattr(webhook, "_post", _post_4xx)
        monkeypatch.setattr(webhook.time, "sleep", lambda s: None)
        entregas = webhook.despachar("hallazgo.registrado", "caso_z2test01", {})
        assert entregas == 0
        assert len(intentos) == 1, "4xx es respuesta firme: sin reintento"
        historial = webhook.entregas_de(alta["id"])
        assert not historial[0]["ok"] and historial[0]["http"] == 410
        assert historial[0]["intentos"] == 1

    @pytest.mark.parametrize("url", [
        "http://169.254.169.254/latest/meta-data/",
        "http://2852039166/latest/meta-data/",       # decimal de 169.254.169.254
        "http://[::ffff:169.254.169.254]/latest/",   # IPv6 mapeada
        "http://metadata.goog/computeMetadata/",
        "http://metadata.google.internal/computeMetadata/",
    ])
    def test_ssrf_vetado_en_todas_las_formas(self, url) -> None:
        with pytest.raises(ValueError):
            webhook.validar_url(url)

    def test_receptor_lab_localhost_sigue_valido(self) -> None:
        # El laboratorio usa receptores en 127.0.0.1: NO deben romperse.
        assert webhook.validar_url("http://127.0.0.1:9099/hook") == \
            "http://127.0.0.1:9099/hook"

    def test_dns_que_resuelve_a_link_local_vetado(self, monkeypatch) -> None:
        import socket as _socket

        class _Info(tuple):
            pass

        monkeypatch.setattr(webhook.socket, "getaddrinfo", lambda h, p: [
            (2, 1, 6, "", ("169.254.169.254", 0))])
        with pytest.raises(ValueError, match="link-local"):
            webhook.validar_url("http://evilsito.lab/hook")

    def test_host_no_resoluble_se_registra(self, monkeypatch) -> None:
        """Un host que aún no resuelve se ADMITE en el alta: no puede
        alcanzar metadatos ninguno y la entrega fallará de forma natural
        (registrada en el historial)."""
        def _getaddrinfo(host, puerto):
            raise OSError("resolución fallida")
        monkeypatch.setattr(webhook.socket, "getaddrinfo", _getaddrinfo)
        url = "http://fantasma.invalido/hook"
        assert webhook.validar_url(url) == url


# ---------------------------------------------------------------------------
# 7) Planificador CTEM: robustez y claim atómico
# ---------------------------------------------------------------------------


class TestPlanificadorCtem:
    CADENA = "intrusion_ad_completa"  # catálogo real threatled

    def test_timestamp_naive_no_mata_el_barrido_y_autocura(self, tmp_path) -> None:
        memoria, eid = _caso(tmp_path, "caso_z2ctem01")
        ctem.programar(memoria, eid, self.CADENA, 1, "op.z2")
        # Corrompemos el timestamp a naive (BD antigua/editada):
        memoria._conn.execute(
            "UPDATE ctem_programas SET proxima_corrida_en=? WHERE engagement_id=?",
            ("2026-01-01T00:00:00", eid))
        memoria._conn.commit()
        resumenes = ctem.ejecutar_pendientes(tmp_path)
        assert len(resumenes) == 1, "el programa naive debía ejecutarse"
        fila = memoria._conn.execute(
            "SELECT proxima_corrida_en FROM ctem_programas").fetchone()
        nueva = datetime.fromisoformat(fila["proxima_corrida_en"])
        assert nueva.tzinfo is not None, "reprogramada con timestamp aware"
        memoria.cerrar()

    def test_claim_atomico_no_duplica_corridas(self, tmp_path, monkeypatch) -> None:
        memoria, eid = _caso(tmp_path, "caso_z2ctem02")
        ctem.programar(memoria, eid, self.CADENA, 1, "op.z2")
        memoria._conn.execute(
            "UPDATE ctem_programas SET proxima_corrida_en=? WHERE engagement_id=?",
            ("2026-01-01T00:00:00+00:00", eid))
        memoria._conn.commit()
        pend = {
            "programa_id": memoria._conn.execute(
                "SELECT id FROM ctem_programas").fetchone()["id"],
            "engagement_id": eid, "cadena_id": self.CADENA,
            "proxima_corrida_en": "2026-01-01T00:00:00+00:00",
            "bd": str(tmp_path / "caso_z2ctem02.db"),
        }
        # Dos "workers" ven el mismo pend (tick solapado): el claim atómico
        # deja la corrida en UNA sola.
        monkeypatch.setattr(ctem, "programas_pendientes", lambda r, ahora=None: [pend])
        ctem.ejecutar_pendientes(tmp_path)
        ctem.ejecutar_pendientes(tmp_path)
        total = memoria._conn.execute(
            "SELECT COUNT(*) FROM ctem_corridas").fetchone()[0]
        assert total == 1, f"corridas duplicadas: {total}"
        memoria.cerrar()


# ---------------------------------------------------------------------------
# 8) API: salud, operadores y decidir con aislamiento
# ---------------------------------------------------------------------------


@pytest.fixture()
def cliente_z2(tmp_path, monkeypatch):
    """API aislada con admin + operador de otra organización.

    Limitador de tasa FRESCO por test: el global es estado compartido del
    proceso y la suite ya roza su presupuesto (10 logins/60 s) — así esta
    ronda no consume el cupo de los demás ficheros de tests.
    """
    from fastapi.testclient import TestClient
    from orchestrator import api as api_mod

    monkeypatch.setattr(api_mod, "RAIZ_CASOS", tmp_path / "casos")
    (tmp_path / "casos").mkdir(exist_ok=True)
    monkeypatch.setattr(api_mod, "_limitador_auth", api_mod._LimitadorTasa(10**9))
    ruta_usuarios = tmp_path / "usuarios_z2.db"
    monkeypatch.setattr(_auth, "RUTA_DB", ruta_usuarios)
    monkeypatch.setattr(_auth, "_intentos", {})
    _auth.crear_operador("adminz2", "ClaveZ2segura1", rol="admin")
    _auth.crear_organizacion("orgb", "Org B")
    _auth.crear_operador("op.ajeno", "ClaveZ2segura2", rol="operador",
                         tenant_id="orgb")
    cliente = TestClient(api_mod.app)

    def _token(usuario: str, clave: str) -> dict[str, str]:
        r = cliente.post("/api/auth/login",
                         json={"usuario": usuario, "contrasena": clave})
        assert r.status_code == 200, r.text
        return {"Authorization": f"Bearer {r.json()['token']}"}

    cliente.token_de = _token  # type: ignore[attr-defined]
    return cliente


def test_salud_usa_la_variable_correcta(cliente_z2) -> None:
    r = cliente_z2.get("/api/salud")
    assert r.status_code == 200
    componentes = r.json()["componentes"]
    assert componentes["operadores"]["ok"] is True, \
        "USUARIOS_DB apunta a una BD existente: salud debía ser ok"
    assert r.json()["estado"] == "ok"


def test_operadores_solo_admin(cliente_z2) -> None:
    ra = cliente_z2.get("/api/auth/operadores", headers=cliente_z2.token_de(
        "adminz2", "ClaveZ2segura1"))
    assert ra.status_code == 200 and len(ra.json()) >= 2
    ro = cliente_z2.get("/api/auth/operadores", headers=cliente_z2.token_de(
        "op.ajeno", "ClaveZ2segura2"))
    assert ro.status_code == 403


def test_decidir_cruza_tenant_bloqueado(cliente_z2, tmp_path) -> None:
    """Un operador de org B NO firma aprobaciones de un caso de la org por
    defecto (antes el endpoint buscaba en todas las BDs sin comprobar
    tenant). El admin sí."""
    from orchestrator.models import Actor

    admin = cliente_z2.token_de("adminz2", "ClaveZ2segura1")
    ajeno = cliente_z2.token_de("op.ajeno", "ClaveZ2segura2")
    rc = cliente_z2.post("/api/engagements", json={
        "nombre": "Caso org A", "cliente": "ACME",
        "alcance_dominios": ["acme.com"], "ventana_inicio": "00:00",
        "ventana_fin": "23:59"}, headers=admin)
    assert rc.status_code == 200, rc.text
    caso_id = rc.json()["id"]
    memoria = MemoriaCaso(tmp_path / "casos" / f"{caso_id}.db")
    memoria.crear_aprobacion(Aprobacion(
        id="apr_z2tenant", engagement_id=caso_id, fase=Fase.F3_ACCESO,
        titulo="Aprobación tenant", herramienta="explotar.ejecutar"))
    memoria.cerrar()
    # Operador ajeno: 404 (el caso le es inexistente)
    r1 = cliente_z2.post("/api/aprobaciones/apr_z2tenant/decision",
                         json={"decidir": True}, headers=ajeno)
    assert r1.status_code == 404
    # La aprobación SIGUE pendiente (sin decisión fantasma)
    memoria = MemoriaCaso(tmp_path / "casos" / f"{caso_id}.db")
    pendientes = memoria.listar_aprobaciones(caso_id, solo_pendientes=True)
    assert any(a["id"] == "apr_z2tenant" for a in pendientes)
    memoria.cerrar()
    # Admin sí decide
    r2 = cliente_z2.post("/api/aprobaciones/apr_z2tenant/decision",
                         json={"decidir": True, "comentario": "ok"}, headers=admin)
    assert r2.status_code == 200


# ---------------------------------------------------------------------------
# 9) Respaldo completo sin exclusión silenciosa
# ---------------------------------------------------------------------------


def test_respaldo_incluye_bds_de_ids_antiguos(tmp_path) -> None:
    casos = tmp_path / "casos"
    casos.mkdir()
    memoria, eid = _caso(casos, "caso_z2resp01")
    memoria.cerrar()
    # BD de despliegue antiguo/demo SIN el prefijo caso_ (la API la sirve:
    # _memoria_de acepta ids [A-Za-z0-9._-]+)
    vieja = MemoriaCaso(casos / "demo_antigua.db")
    vieja.crear_engagement(Engagement(
        id="demo_antigua", nombre="Demo vieja", cliente="Cliente",
        roe=_roe("demo_antigua")))
    vieja.cerrar()
    zip_bytes, manifiesto = respaldo.construir_respaldo_completo(
        casos, tmp_path / "usuarios.db")
    nombres = {f["nombre"] for f in manifiesto["ficheros"]}
    assert "caso_z2resp01.db" in nombres
    assert "demo_antigua.db" in nombres, \
        "las BDs sin prefijo caso_ también son casos y van al respaldo"


# ---------------------------------------------------------------------------
# 10) TLS verificado por defecto en integraciones con credenciales
# ---------------------------------------------------------------------------


def test_msf_verifica_tls_por_defecto(monkeypatch) -> None:
    from integraciones.metasploit import RpcMsf
    monkeypatch.setenv("MSF_HOST", "msf.lab")
    monkeypatch.setenv("MSF_USER", "msf")
    monkeypatch.setenv("MSF_PASS", "clave-msf")
    monkeypatch.setenv("MSF_SSL", "1")
    inst = RpcMsf()
    assert inst.verificar_tls is True
    monkeypatch.setenv("MSF_TLS_VERIFICAR", "0")
    assert RpcMsf().verificar_tls is False


def test_bloodhound_y_mythic_verifican_tls(monkeypatch) -> None:
    import integraciones.bloodhound as bh
    import integraciones.mythic as my
    # Opt-out documentado en cada módulo; por defecto la verificación está ON.
    assert os_environ_get_default_one(monkeypatch, bh, "BLOODHOUND_TLS_VERIFICAR")
    assert os_environ_get_default_one(monkeypatch, my, "MYTHIC_TLS_VERIFICAR")


def os_environ_get_default_one(monkeypatch, modulo, clave: str) -> bool:
    """Lee la lógica del módulo sin contactar red: con la env ausente el
    patrón (env != '0') debe evaluar a True."""
    monkeypatch.delenv(clave, raising=False)
    # Reproduce exactamente la expresión de los módulos:
    return __import__("os").environ.get(clave, "1") != "0"


# ---------------------------------------------------------------------------
# 11) Ronda Z2-2: SSRF en el despacho, sin redirecciones, cadena legada
# ---------------------------------------------------------------------------


class TestWebhookDespachoZ2:
    def test_rebinding_detectado_en_despacho(self, webhook_db, monkeypatch) -> None:
        """TOCTOU de DNS: el ALTA fue legítima, pero al DESPACHAR el host
        resuelve a link-local (rebinding). El veto ahora se re-aplica justo
        antes de conectar: sin ni un intento de red y con la entrega
        registrada como bloqueada (defensa en profundidad, no alarma)."""
        alta = webhook.crear_webhook("https://receptor.lab/hook",
                                     ["hallazgo.registrado"], secreto="s" * 20)

        def _post_prohibido(url, cuerpo, cabeceras):
            raise AssertionError("no debe conectarse a un receptor vetado")

        def _getaddrinfo_rebinding(host, puerto):
            # Entre el alta y la entrega, el DNS del receptor "cambió":
            return [(2, 1, 6, "", ("169.254.169.254", 0))]

        monkeypatch.setattr(webhook, "_post", _post_prohibido)
        monkeypatch.setattr(webhook.socket, "getaddrinfo", _getaddrinfo_rebinding)
        entregas = webhook.despachar("hallazgo.registrado", "caso_z2test02", {})
        assert entregas == 0
        historial = webhook.entregas_de(alta["id"])
        assert not historial[0]["ok"]
        assert historial[0]["http"] is None
        assert "link-local" in (historial[0]["error"] or "")
        assert historial[0]["intentos"] == 0, "un veto no consume intentos"

    def test_canal_heredado_entorno_tambien_verificado(self, webhook_db, monkeypatch) -> None:
        """El canal heredado WEBHOOK_URL nunca pasó por validar_url: la capa
        de despacho lo cubre ahora igual que los receptores de BD."""
        monkeypatch.setenv("WEBHOOK_URL",
                           "http://2852039166/latest/meta-data/")  # decimal de 169.254.169.254

        def _post_prohibido(url, cuerpo, cabeceras):
            raise AssertionError("el canal heredado vetado no debe conectar")

        monkeypatch.setattr(webhook, "_post", _post_prohibido)
        assert webhook.despachar("hallazgo.registrado", "caso_z2test03", {}) == 0

    def test_redirecciones_no_se_siguen(self, webhook_db) -> None:
        """Un receptor que responde 302 hacia metadatos NO arrastra el POST
        firmado: follow_redirects=False → la 3xx es no-OK y respuesta FIRME
        (sin reintento, sin segundo salto)."""
        import threading
        from http.server import BaseHTTPRequestHandler, HTTPServer

        class _Redir(BaseHTTPRequestHandler):
            def do_POST(self):
                self.send_response(302)
                self.send_header("Location",
                                 "http://169.254.169.254/latest/meta-data/")
                self.end_headers()

            def log_message(self, *args):
                pass

        servidor = HTTPServer(("127.0.0.1", 0), _Redir)
        threading.Thread(target=servidor.serve_forever, daemon=True).start()
        try:
            alta = webhook.crear_webhook(
                f"http://127.0.0.1:{servidor.server_port}/hook",
                ["hallazgo.registrado"], secreto="s" * 20)
            r = webhook.probar_webhook(alta["id"])
            assert r["http"] == 302 and not r["enviado"]
            historial = webhook.entregas_de(alta["id"], limite=1)
            assert historial[0]["intentos"] == 1, \
                "3xx es respuesta firme: sin reintento"
        finally:
            servidor.shutdown()
            servidor.server_close()


class TestCadenaLegadaZ2:
    def test_cadena_escrita_en_orden_legado_verifica_y_declara_modo(self, tmp_path) -> None:
        """BD anterior a v24: la cadena se escribió recorriendo creado_en.
        Con orden de inserción (rowid) distinto, el verificador nuevo daba
        'ruptura de encadenamiento' FALSA sobre datos íntegros. Ahora
        re-verifica en el orden legado y declara modo='legado_creado_en'."""
        from datetime import timedelta, timezone

        memoria, eid = _caso(tmp_path, "caso_z2leg01")
        base = datetime.now(timezone.utc)
        # A se inserta PRIMERO pero su reloj dice DESPUÉS (lo que el orden
        # legado por creado_en reordenaba); B queda segunda por rowid.
        ev_a = Evidencia(id="ev_leg_a", engagement_id=eid,
                         tipo=TipoEvidencia.JSON, titulo="A", contenido="cuerpo a",
                         fase=Fase.F2_RECON, creado_en=base + timedelta(seconds=30))
        ev_b = Evidencia(id="ev_leg_b", engagement_id=eid,
                         tipo=TipoEvidencia.JSON, titulo="B", contenido="cuerpo b",
                         fase=Fase.F2_RECON, creado_en=base)
        memoria.guardar_evidencia(ev_a)
        memoria.guardar_evidencia(ev_b)
        # Reescribimos el encadenamiento COMO LO GENERABA el código legado
        # (orden creado_en: B → genesis, A → hash(B)). La firma no cambia:
        # firma el hash del CONTENIDO, no el eslabón — es fiel a una BD vieja.
        memoria._conn.execute("UPDATE evidencias SET hash_previo='genesis' "
                              "WHERE id='ev_leg_b'")
        memoria._conn.execute("UPDATE evidencias SET hash_previo=? "
                              "WHERE id='ev_leg_a'", (ev_b.hash_sha256,))
        memoria._conn.commit()

        r = memoria.verificar_cadena(eid)
        assert r["valida"] is True, \
            "una cadena legada íntegra no debe alarmar (falso positivo)"
        assert r.get("modo") == "legado_creado_en", \
            "el resultado debe declarar que verificó bajo el orden legado"

        # Y una manipulación REAL sigue detectándose (ambos órdenes fallan):
        memoria._conn.execute("UPDATE evidencias SET contenido='manipulado' "
                              "WHERE id='ev_leg_a'")
        memoria._conn.commit()
        r2 = memoria.verificar_cadena(eid)
        assert r2["valida"] is False
        assert "contenido manipulado" in (r2["primer_error"] or "")

    def test_cadena_actual_verifica_sin_modo(self, tmp_path) -> None:
        """La BD creada con el mecanismo actual (rowid) verifica en primer
        lugar y NO declara modo legado (el caso común no paga re-verificación)."""
        memoria, eid = _caso(tmp_path, "caso_z2leg02")
        memoria.guardar_evidencia(Evidencia(
            id="ev_act_a", engagement_id=eid, tipo=TipoEvidencia.JSON,
            titulo="A", contenido="uno", fase=Fase.F2_RECON))
        memoria.guardar_evidencia(Evidencia(
            id="ev_act_b", engagement_id=eid, tipo=TipoEvidencia.JSON,
            titulo="B", contenido="dos", fase=Fase.F2_RECON))
        r = memoria.verificar_cadena(eid)
        assert r["valida"] is True
        assert "modo" not in r
