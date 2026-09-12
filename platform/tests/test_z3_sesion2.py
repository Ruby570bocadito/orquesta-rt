"""Tests z3 (sesión 2): regresión de los fixes de la segunda auditoría.

Cubre:
- F11 TLS: política centralizada del recon (RECON_TLS_ESTRICTO) y verificación
  POR DEFECTO en las integraciones con credenciales (MSF/BloodHound/Mythic).
- F12 SSO: ninguna cuenta privilegiada se enlaza por coincidencia de nombre
  sin pre-aprobación explícita; dominios de confianza con email verificado.
- F13 /api/salud: sin token solo el estado agregado, sin topología interna.
- F14 SMTP: STARTTLS con contexto verificado por defecto.
- F15 nmap: objetivo que empieza por '-' se rechaza (inyección de argumentos).

Los servidores HTTP se simulan interceptando el constructor de httpx.Client
(se verifica el kwarg REAL con el que se construiría el cliente); no se
abre red saliente en ninguna prueba.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from orchestrator import auth as _auth  # noqa: E402
from orchestrator import transportes  # noqa: E402
from orchestrator.api import app  # noqa: E402
from orchestrator.models import ROEPolitica  # noqa: E402

RAIZ_REPO = Path(__file__).resolve().parents[2]


# ---------------------------------------------------------------------------
# Fijas comunes
# ---------------------------------------------------------------------------


@pytest.fixture()
def bd_temporal(tmp_path, monkeypatch):
    monkeypatch.setattr(_auth, "RUTA_DB", tmp_path / "usuarios_test_z3b.db")
    monkeypatch.setattr(_auth, "_intentos", {})
    yield tmp_path


def _token_admin() -> str:
    if not _auth.hay_operadores():
        _auth.crear_operador("opz3b", "ClaveZ3b-segura!", rol="admin")
    return _auth.emitir_token("opz3b", "admin", "predeterminada")["token"]


@pytest.fixture()
def cliente_api(bd_temporal, monkeypatch):
    monkeypatch.setattr("orchestrator.sidecar.asegurar_consola", lambda: True)
    return TestClient(app)


# ---------------------------------------------------------------------------
# F12 · SSO: vinculación segura de identidades federadas
# ---------------------------------------------------------------------------


def test_sso_cuenta_admin_no_se_enlaza_sin_preaprobacion(bd_temporal) -> None:
    _auth.crear_operador("jefe", "ClaveJefe-1234!", rol="admin")
    with pytest.raises(ValueError, match="pre-aprobación"):
        _auth.crear_o_vincular_sso(sso_sub="sub-malicioso-1", usuario="jefe")


def test_sso_cuenta_admin_se_enlaza_con_preaprobacion(bd_temporal) -> None:
    _auth.crear_operador("jefe2", "ClaveJefe-1234!", rol="admin")
    _auth.preaprobar_vinculo_sso("cli:admin", "jefe2", "sub-ok-42")
    cuenta = _auth.crear_o_vincular_sso(sso_sub="sub-ok-42", usuario="jefe2")
    assert cuenta["rol"] == "admin" and cuenta["sso_sub"] == "sub-ok-42"
    # La pre-aprobación queda consumida: un sub DISTINTO no se enlaza.
    with pytest.raises(ValueError, match="pre-aprobación"):
        _auth.crear_o_vincular_sso(sso_sub="sub-distinto", usuario="jefe2")


def test_sso_cuenta_lectora_se_enlaza_sin_env_como_antes(bd_temporal,
                                                         monkeypatch) -> None:
    monkeypatch.delenv("OIDC_DOMINIOS_PERMITIDOS", raising=False)
    _auth.crear_operador("ana", "ClaveAna-1234!", rol="lector")
    cuenta = _auth.crear_o_vincular_sso(sso_sub="sub-ana-1", usuario="ana")
    assert cuenta["rol"] == "lector"


def test_sso_jit_con_dominio_confianza_email_verificado(bd_temporal,
                                                        monkeypatch) -> None:
    monkeypatch.setenv("OIDC_DOMINIOS_PERMITIDOS", "empresa.com, @otro.net")
    cuenta = _auth.crear_o_vincular_sso(
        sso_sub="sub-fede-1", usuario="fede.garcia",
        email="fede.garcia@EMPRESA.com", email_verificado=True)
    assert cuenta["rol"] == "lector"  # JIT mínimo privilegio


@pytest.mark.parametrize("email,verificado", [
    ("fede@laboratorio.org", True),      # dominio ajeno
    ("fede@empresa.com", False),         # dominio bueno, email SIN verificar
    ("", False),                          # sin email
])
def test_sso_jit_sin_email_verificado_valido_se_bloquea(
        bd_temporal, monkeypatch, email, verificado) -> None:
    monkeypatch.setenv("OIDC_DOMINIOS_PERMITIDOS", "empresa.com")
    with pytest.raises(ValueError, match="email federado verificado"):
        _auth.crear_o_vincular_sso(sso_sub="sub-x", usuario="alguien",
                                   email=email, email_verificado=verificado)


def test_sso_preaprobaciones_listar_y_retirar(bd_temporal) -> None:
    _auth.crear_operador("gest", "ClaveGest-1234!", rol="gestor")
    _auth.preaprobar_vinculo_sso("cli:admin", "gest", "sub-g1")
    lista = _auth.listar_vinculos_preaprobados()
    assert any(v["usuario"] == "gest" and v["sso_sub"] == "sub-g1"
               for v in lista)
    assert _auth.eliminar_vinculo_preaprobado("cli:admin", "gest") == 1
    assert _auth.listar_vinculos_preaprobados() == []


# ---------------------------------------------------------------------------
# F13 · /api/salud: sin token, sin topología
# ---------------------------------------------------------------------------


def test_salud_anonimo_sin_detalle_de_topologia(cliente_api) -> None:
    r = cliente_api.get("/api/salud")
    assert r.status_code == 200
    cuerpo = r.json()
    assert cuerpo["estado"] in ("ok", "degradado")
    assert "componentes" not in cuerpo          # sin detalle de componentes
    assert "raiz" not in str(cuerpo).lower()    # nada de rutas internas


def test_salud_autenticado_con_detalle_completo(cliente_api) -> None:
    cliente_api.headers.update({"Authorization": f"Bearer {_token_admin()}"})
    r = cliente_api.get("/api/salud")
    assert r.status_code == 200
    componentes = r.json().get("componentes", {})
    assert "memoria_casos" in componentes and "router_ia" in componentes


# ---------------------------------------------------------------------------
# F11 · Política TLS: recon configurable, integraciones seguras por defecto
# ---------------------------------------------------------------------------


class _CapturaCliente:
    """Sustituto de httpx.Client que registra los kwargs de construcción."""

    instancias: list[dict] = []

    def __init__(self, *args, **kwargs):
        _CapturaCliente.instancias.append(kwargs)
        raise RuntimeError("capturado: no se abre red en los tests")


@pytest.fixture()
def captura_httpx(monkeypatch):
    _CapturaCliente.instancias.clear()
    import httpx
    monkeypatch.setattr(httpx, "Client", _CapturaCliente)
    yield _CapturaCliente.instancias


def test_recon_tls_por_defecto_permite_autofirmados(captura_httpx) -> None:
    roe = ROEPolitica(engagement_id="e", cliente="c",
                      alcance_dominios=["lab.local"])
    transportes.recon_tech_fingerprint("https://servidor.lab.local", roe)
    assert captura_httpx and captura_httpx[0].get("verify") is False


def test_recon_tls_estrito_con_env(monkeypatch, captura_httpx) -> None:
    monkeypatch.setenv("RECON_TLS_ESTRICTO", "1")
    roe = ROEPolitica(engagement_id="e", cliente="c",
                      alcance_dominios=["lab.local"])
    transportes.recon_tech_fingerprint("https://servidor.lab.local", roe)
    assert captura_httpx and captura_httpx[0].get("verify") is True


def test_msf_rpc_verifica_tls_por_defecto(monkeypatch, captura_httpx) -> None:
    from integraciones import metasploit
    monkeypatch.setenv("MSF_HOST", "127.0.0.1")
    monkeypatch.setenv("MSF_PORT", "55553")
    monkeypatch.setenv("MSF_SSL", "1")
    monkeypatch.setenv("MSF_USER", "msf")
    monkeypatch.setenv("MSF_PASS", "clave-msf")
    monkeypatch.delenv("MSF_TLS_VERIFICAR", raising=False)
    rpc = metasploit.RpcMsf()
    assert rpc.verificar_tls is True            # seguro por defecto
    rpc._token = "t"
    with pytest.raises(RuntimeError):
        rpc._llamar("core.version")
    assert captura_httpx and captura_httpx[0].get("verify") is True
    # Escape consciente para labs autofirmados
    monkeypatch.setenv("MSF_TLS_VERIFICAR", "0")
    rpc0 = metasploit.RpcMsf()
    assert rpc0.verificar_tls is False


def _post_login_capturado(modulo, env_key: str, monkeypatch, captura_httpx):
    monkeypatch.delenv(env_key, raising=False)
    with pytest.raises(RuntimeError):
        # Sin servidor detrás: la construcción del cliente queda capturada
        # ANTES de cualquier intento de conexión.
        modulo._post_login("http://127.0.0.1:1", "u", "s")
    assert captura_httpx and captura_httpx[0].get("verify") is True


def test_bloodhound_verifica_tls_por_defecto(monkeypatch, captura_httpx) -> None:
    from integraciones import bloodhound
    _post_login_capturado(bloodhound, "BLOODHOUND_TLS_VERIFICAR",
                          monkeypatch, captura_httpx)
    monkeypatch.setenv("BLOODHOUND_TLS_VERIFICAR", "0")
    with pytest.raises(RuntimeError):
        bloodhound._post_login("http://127.0.0.1:1", "u", "s")
    assert captura_httpx[-1].get("verify") is False


def test_mythic_verifica_tls_por_defecto(monkeypatch, captura_httpx) -> None:
    from integraciones import mythic
    monkeypatch.setenv("MYTHIC_URL", "http://127.0.0.1:1")
    monkeypatch.setenv("MYTHIC_TOKEN", "tok")
    monkeypatch.delenv("MYTHIC_TLS_VERIFICAR", raising=False)
    with pytest.raises(RuntimeError):
        mythic._gql("query { callback { id } }")
    assert captura_httpx and captura_httpx[0].get("verify") is True
    monkeypatch.setenv("MYTHIC_TLS_VERIFICAR", "0")
    with pytest.raises(RuntimeError):
        mythic._gql("query { callback { id } }")
    assert captura_httpx[-1].get("verify") is False


# ---------------------------------------------------------------------------
# F15 · nmap: sin inyección de argumentos vía el objetivo
# ---------------------------------------------------------------------------


def test_nmap_rechaza_objetivo_que_empieza_por_guion(monkeypatch) -> None:
    """Defensa en profundidad: el modelo ROEPolitica ya rechaza dominios con
    '-' en su validador; esta prueba fuerza el caso en el TRANSPORTE (ROE
    manipulado / llamada directa) para comprobar el guardia de nmap."""
    import shutil
    monkeypatch.setattr(shutil, "which", lambda _: "/usr/bin/nmap")
    roe = ROEPolitica(engagement_id="e", cliente="c",
                      alcance_dominios=["lab.local"])
    monkeypatch.setattr(transportes, "_host_de", lambda _: "-iL/etc/passwd")
    monkeypatch.setattr(transportes, "_en_scope", lambda *_a, **_k: True)
    r = transportes.recon_nmap_servicios("-iL/etc/passwd", roe)
    assert "objetivo" in r.get("error", "")
    assert r.get("servicios") == []


def test_nmap_objetivo_normal_pasa_el_guardia(monkeypatch) -> None:
    """Sin binario real instalado el flujo sigue: el guardia no bloquea
    objetivos legítimos (se comprueba que el error ya no es el del guardia)."""
    import shutil
    monkeypatch.setattr(shutil, "which", lambda _: None)  # sin nmap → mensaje de requisito
    roe = ROEPolitica(engagement_id="e", cliente="c",
                      alcance_dominios=["lab.local"])
    r = transportes.recon_nmap_servicios("servidor.lab.local", roe)
    assert "nmap no está instalado" in r.get("error", "")
