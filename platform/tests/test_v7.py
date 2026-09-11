"""Tests de la ronda v7: producción, optimización y nuevas habilidades.

Cubre: gestión admin de operadores (alta/rol/restablecer + protección de
último admin), exportación de custodia del caso, diferencial de superficie,
config del copiloto (habilitación honesta), webhook real de aprobaciones
con receptor HTTP local y firma HMAC, y los tres transportes nuevos
(scope enforcement sin red).
"""
from __future__ import annotations

import json
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from orchestrator import auth  # noqa: E402
from orchestrator.memory import MemoriaCaso  # noqa: E402
from orchestrator.models import (  # noqa: E402
    Actor, Engagement, Fase, ROEPolitica, TipoEvidencia,
)
from orchestrator.transportes import transportes_de, TRANSPORTE_NOMBRES  # noqa: E402
from orchestrator import webhook  # noqa: E402


# ---------------------------------------------------------------------------
# Fábrica de caso aislado
# ---------------------------------------------------------------------------


def _caso_tmp(tmp_path: Path) -> tuple[MemoriaCaso, str]:
    memoria = MemoriaCaso(tmp_path / "caso_test.db")
    eid = "caso_test_v7"
    roe = ROEPolitica(
        engagement_id=eid, cliente="ACME",
        alcance_dominios=["acme.test"], alcance_cidrs=["127.0.0.0/8"],
    )
    memoria.crear_engagement(Engagement(
        id=eid, nombre="Caso v7", cliente="ACME", roe=roe,
        fase_actual=Fase.F0_SCOPING, estado_fase="pendiente",
        presupuesto_tokens={}))
    return memoria, eid


# ---------------------------------------------------------------------------
# 1) Gestión admin de operadores
# ---------------------------------------------------------------------------


@pytest.fixture()
def almacen_tmp(tmp_path, monkeypatch):
    ruta = tmp_path / "usuarios_v7.db"
    monkeypatch.setattr(auth, "RUTA_DB", ruta)
    monkeypatch.setattr(auth, "_intentos", {})
    return ruta


def test_restablecer_contrasena_admin(almacen_tmp) -> None:
    auth.crear_operador("op1", "ClaveVieja2026")
    auth.restablecer_contrasena("op1", "ClaveNueva2026")
    assert auth.verificar_credenciales("op1", "ClaveVieja2026") is None
    assert auth.verificar_credenciales("op1", "ClaveNueva2026") is not None


def test_restablecer_desbloquea_cuenta(almacen_tmp) -> None:
    auth.crear_operador("op2", "ClaveLarga2026")
    # Agotar intentos: cuenta bloqueada
    for _ in range(auth.MAX_FALLOS):
        auth.verificar_credenciales("op2", "malamala1")
    with pytest.raises(ValueError, match="bloqueada"):
        auth.verificar_credenciales("op2", "ClaveLarga2026")
    # El restablecimiento administrativo desbloquea
    auth.restablecer_contrasena("op2", "ClaveLarga2026")
    assert auth.verificar_credenciales("op2", "ClaveLarga2026") is not None


def test_cambiar_rol_protecciones(almacen_tmp) -> None:
    auth.crear_operador("root", "ClaveRoot2026", rol="admin")
    auth.crear_operador("ayudante", "ClaveAyud2026", rol="operador")
    # Auto-cambio de rol: DENEGADO (protección de bloqueo)
    with pytest.raises(ValueError, match="propio rol"):
        auth.cambiar_rol("root", "operador", "root")
    # Con un segundo admin ya sí se puede degradar otro admin
    auth.crear_operador("root2", "ClaveRoot2026", rol="admin")
    auth.cambiar_rol("root", "operador", "root2")
    assert any(o["usuario"] == "root" and o["rol"] == "operador"
               for o in auth.listar_operadores())
    # Rol inválido: DENEGADO
    with pytest.raises(ValueError, match="Rol inválido"):
        auth.cambiar_rol("root", "superadmin", "root2")


def test_eliminar_ultimo_admin_denegado(almacen_tmp) -> None:
    auth.crear_operador("unico", "ClaveUnica2026", rol="admin")
    with pytest.raises(ValueError, match="último admin"):
        auth.eliminar_operador("unico", "otro")


# ---------------------------------------------------------------------------
# 2) Exportación de custodia y dif de superficie (capa de memoria/API)
# ---------------------------------------------------------------------------


def test_export_contiene_cadena_valida(tmp_path) -> None:
    from orchestrator.models import Evidencia
    memoria, eid = _caso_tmp(tmp_path)
    memoria.guardar_evidencia(Evidencia(
        id="ev_1", engagement_id=eid, tipo=TipoEvidencia.NOTA,
        titulo="Evidencia base", contenido="contenido de prueba",
        fase=Fase.F0_SCOPING))
    evidencias = memoria.listar_evidencias(eid)
    assert len(evidencias) == 1
    cadena = memoria.verificar_cadena(eid)
    assert cadena["valida"] is True
    memoria.cerrar()


def test_config_caso_kv_persistente(tmp_path) -> None:
    memoria, eid = _caso_tmp(tmp_path)
    assert memoria.config_caso(eid, "copiloto_habilitado") is None
    memoria.fijar_config_caso(eid, "copiloto_habilitado", "1")
    assert memoria.config_caso(eid, "copiloto_habilitado") == "1"
    memoria.fijar_config_caso(eid, "copiloto_habilitado", "0")
    assert memoria.config_caso(eid, "copiloto_habilitado") == "0"
    memoria.cerrar()


def test_dif_superficie_por_fecha(tmp_path) -> None:
    from datetime import datetime, timedelta, timezone
    from orchestrator.models import Objetivo, TipoObjetivo
    memoria, eid = _caso_tmp(tmp_path)
    ayer = (datetime.now(timezone.utc) - timedelta(days=1))
    ahora = datetime.now(timezone.utc)
    memoria.guardar_objetivo(Objetivo(
        id="obj_1", engagement_id=eid, nombre="acme.test",
        tipo=TipoObjetivo.DOMINIO, fase=Fase.F1_OSINT,
        descubierto_en=ayer))
    memoria.guardar_objetivo(Objetivo(
        id="obj_2", engagement_id=eid, nombre="acme.test:443",
        tipo=TipoObjetivo.SERVICIO, fase=Fase.F2_RECON,
        descubierto_en=ahora))
    filas = memoria.listar_objetivos(eid)
    corte = datetime.now(timezone.utc) - timedelta(hours=12)
    nuevos = [f for f in filas
              if datetime.fromisoformat(f["descubierto_en"]) >= corte]
    assert [f["nombre"] for f in nuevos] == ["acme.test:443"]
    memoria.cerrar()


# ---------------------------------------------------------------------------
# 3) Webhook real: receptor HTTP local + firma HMAC
# ---------------------------------------------------------------------------


class _Receptor(BaseHTTPRequestHandler):
    recibidos: list[dict] = []
    respuesta = 200

    def do_POST(self):  # noqa: N802
        longitud = int(self.headers.get("Content-Length", 0))
        cuerpo = self.rfile.read(longitud)
        _Receptor.recibidos.append({
            "cuerpo": json.loads(cuerpo),
            "firma": self.headers.get("X-Orquesta-Firma", ""),
        })
        self.send_response(_Receptor.respuesta)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args):  # silencio
        pass


def test_webhook_post_real_firmado(tmp_path, monkeypatch) -> None:
    """v16: receptor de BD con entrega real firmada (HMAC-SHA256 sobre el
    cuerpo crudo); la firma se verifica contra el cuerpo CAPTURADO."""
    servidor = HTTPServer(("127.0.0.1", 0), _Receptor)
    puerto = servidor.server_address[1]
    hilo = threading.Thread(target=servidor.serve_forever, daemon=True)
    hilo.start()
    try:
        monkeypatch.delenv("WEBHOOK_URL", raising=False)
        monkeypatch.setattr(webhook, "_ruta_db", lambda: tmp_path / "usuarios_v7.db")
        _Receptor.recibidos = []
        secreto = "secreto-compartido-v7-32-chars!"
        creado = webhook.crear_webhook(
            f"http://127.0.0.1:{puerto}/gancho", ["aprobacion.solicitada"],
            secreto, "canal equipo")
        entregas = webhook.despachar(
            "aprobacion.solicitada", "caso_x",
            {"titulo": "prueba", "riesgo": "alta"})
        assert entregas == 1
        assert len(_Receptor.recibidos) == 1
        r = _Receptor.recibidos[0]
        assert r["cuerpo"]["evento"] == "aprobacion.solicitada"
        assert r["firma"].startswith("sha256=")
        # La firma verifica con el secreto compartido sobre el cuerpo REAL
        import hashlib, hmac
        cuerpo_bytes = json.dumps(r["cuerpo"], ensure_ascii=False,
                                  default=str).encode()
        esperada = "sha256=" + hmac.new(
            secreto.encode(), cuerpo_bytes, hashlib.sha256).hexdigest()
        assert hmac.compare_digest(r["firma"], esperada)
        entregas_log = webhook.entregas_de(creado["id"])
        assert entregas_log[0]["ok"] is True
    finally:
        servidor.shutdown()


def test_webhook_sin_configuracion_honesto(tmp_path, monkeypatch) -> None:
    """v16: sin receptores en BD y sin WEBHOOK_URL no hay entrega (0)."""
    monkeypatch.delenv("WEBHOOK_URL", raising=False)
    monkeypatch.setattr(webhook, "_ruta_db", lambda: tmp_path / "usuarios_v7b.db")
    assert webhook.despachar("aprobacion.solicitada", "caso_x", {}) == 0


# ---------------------------------------------------------------------------
# 4) Transportes nuevos: scope enforcement real (sin red)
# ---------------------------------------------------------------------------


def test_transportes_v7_registrados() -> None:
    for clave in ("osint.sitemap", "recon.correos_seguridad", "recon.rutas_sensibles"):
        assert clave in TRANSPORTE_NOMBRES


def _roe_scope() -> ROEPolitica:
    return ROEPolitica(
        engagement_id="caso_x", cliente="ACME",
        alcance_dominios=["acme.test"], alcance_cidrs=["127.0.0.0/8"])


def test_correos_seguridad_fuera_scope() -> None:
    t = transportes_de(_roe_scope())
    r = t["recon.correos_seguridad"]("evil.com")
    assert r["error"] and "fuera del alcance" in r["error"]


def test_correos_seguridad_en_scope_dns_real() -> None:
    # acme.test no resuelve DNS: la guardia anti-falso-positivo (v18) lo
    # reporta como sin_resolucion y NO fabrica "debilidades" de un dominio
    # que ni siquiera existe (un dominio sin DNS no es un dominio sin SPF).
    t = transportes_de(_roe_scope())
    r = t["recon.correos_seguridad"]("acme.test")
    assert r.get("sin_resolucion") is True
    assert r.get("debilidades") == []
    assert "nota" in r


def test_rutas_sensibles_fuera_scope() -> None:
    t = transportes_de(_roe_scope())
    r = t["recon.rutas_sensibles"]("http://evil.com")
    assert "fuera de alcance" in r["error"]


def test_sitemap_fuera_scope() -> None:
    t = transportes_de(_roe_scope())
    r = t["osint.sitemap"]("evil.com")
    assert "fuera de alcance" in r["error"]


# ---------------------------------------------------------------------------
# 5) Catálogo de guardrails clasifica los transportes nuevos
# ---------------------------------------------------------------------------


def test_guardrails_clasifica_transportes_v7() -> None:
    from orchestrator.guardrails import MotorGuardrails
    roe = _roe_scope()
    motor = MotorGuardrails(roe, memoria=None)
    # correos_seguridad es pasivo: sin firma, ruido 0
    veredicto = motor.evaluar(
        herramienta="recon.correos_seguridad",
        argumentos={"dominio": "acme.test"}, fase=Fase.F1_OSINT,
        momento=datetime_fija())
    assert veredicto.permitido
    # rutas_sensibles es media + ventana: fuera de ventana, denegado
    veredicto2 = motor.evaluar(
        herramienta="recon.rutas_sensibles",
        argumentos={"url": "https://acme.test"}, fase=Fase.F2_RECON,
        momento=datetime_fuera_ventana())
    assert veredicto2.denegado
    # En ventana: riesgo media con ventana y ruido acotado → permitido
    # (mismo tratamiento que banner_grab); fuera de ventana: denegado.
    veredicto3 = motor.evaluar(
        herramienta="recon.rutas_sensibles",
        argumentos={"url": "https://acme.test"}, fase=Fase.F2_RECON,
        momento=datetime_fija())
    assert veredicto3.permitido


def datetime_fija():
    from datetime import datetime
    # lunes 10:30 (dentro de la ventana estándar)
    return datetime(2026, 3, 2, 10, 30)


def datetime_fuera_ventana():
    from datetime import datetime
    # domingo 03:00 (fuera de ventana)
    return datetime(2026, 3, 1, 3, 0)


# ---------------------------------------------------------------------------
# 6) Regresión: alta de operador post-bootstrap con JWT de admin
#    (la ruta es pública en el middleware; el endpoint debe verificar el
#     JWT explícito — antes devolvía 403 SIEMPRE tras el bootstrap)
# ---------------------------------------------------------------------------


def test_alta_post_bootstrap_con_jwt_admin(tmp_path, monkeypatch, almacen_tmp) -> None:
    from fastapi.testclient import TestClient
    from orchestrator import api as api_mod
    monkeypatch.setattr(api_mod, "RAIZ_CASOS", tmp_path / "casos")
    (tmp_path / "casos").mkdir(exist_ok=True)
    auth.crear_operador("root", "ClaveRoot2026", rol="admin")
    cliente = TestClient(api_mod.app)
    token = auth.emitir_token("root", "admin")["token"]
    r = cliente.post(
        "/api/auth/registrar",
        json={"usuario": "nuevo.op", "contrasena": "ClaveNueva2026", "rol": "operador"},
        headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200, r.text
    assert any(o["usuario"] == "nuevo.op" for o in auth.listar_operadores())
    # Sin JWT: 403 (un anónimo no da de alta cuentas tras el bootstrap)
    r2 = cliente.post(
        "/api/auth/registrar",
        json={"usuario": "intruso", "contrasena": "ClaveIntrusa2026", "rol": "admin"})
    assert r2.status_code == 403
    assert not any(o["usuario"] == "intruso" for o in auth.listar_operadores())
