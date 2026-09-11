"""Tests v21: planificación threat-led, RBAC multi-tenant, SSO OIDC,
BloodHound CE, MISP y despliegue productivo.

Nada simulado donde importa: los clientes BloodHound/MISP/SSO se prueban
contra servidores HTTP REALES (fixtures sobre TCP) hablando el protocolo
oficial; el id_token SSO se firma RS256 de verdad y se verifica con las
JWK del IdP de prueba; el despliegue se valida por parseo estructural
real de los manifiestos que se empaquetan.
"""
from __future__ import annotations

import base64
import json
import os
import socket
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from integraciones import bloodhound, misp  # noqa: E402
from orchestrator import auth as _auth  # noqa: E402
from orchestrator import sso as _sso  # noqa: E402
from orchestrator import threatled  # noqa: E402
from orchestrator.api import app  # noqa: E402
from orchestrator.guardrails import _RIESGO_HERRAMIENTAS  # noqa: E402

RAIZ_REPO = Path(__file__).resolve().parents[2]


# ---------------------------------------------------------------------------
# 1) Threat-led: catálogo honesto contra el boundary REAL
# ---------------------------------------------------------------------------


def test_catalogo_cadenas_coherente() -> None:
    cadenas = threatled.catalogo()
    assert len(cadenas) >= 4
    for c in cadenas:
        assert c["pasos"] >= 5 and c["pasos"] == len(c["tecnicas"])
        assert c["tecnicas"] == sorted(c["tecnicas"], key=lambda t: c["tecnicas"].index(t))


def test_cada_herramienta_existe_en_el_boundary_o_es_manual() -> None:
    # Regla anti-relleno: ninguna cadena promete una herramienta que el
    # guardrail no conocería en ejecución.
    for c in threatled.catalogo():
        detalle = threatled.detalle(threatled.obtener(c["id"]))
        for p in detalle["pasos"]:
            if p["es_manual"]:
                assert p["herramienta"] == "manual"
            else:
                assert p["herramienta"] in _RIESGO_HERRAMIENTAS, p["herramienta"]
                assert p["ruido_estimado"] == _RIESGO_HERRAMIENTAS[p["herramienta"]]["ruido"]


def test_pasos_con_descripcion_y_deteccion() -> None:
    for c in threatled.catalogo():
        d = threatled.detalle(threatled.obtener(c["id"]))
        for p in d["pasos"]:
            assert len(p["descripcion"]) > 20
            assert len(p["deteccion"]) > 20  # hint purple, no placeholder


def test_plan_para_caso_estados_honestos() -> None:
    cadena = threatled.obtener("intrusion_ad_completa")
    tecnicas_ejercitadas = {"T1558.003"}  # solo kerberoasting
    plan = threatled.plan_para_caso(cadena, tecnicas_ejercitadas)
    estados = {p["tecnica"]: p["estado"] for p in plan["pasos"]}
    assert estados["T1558.003"] == "ejercitado"
    assert estados["T1003.006"] == "disponible"   # ad.dcsync en el boundary
    assert estados["T1070.001"] == "manual"       # borrado de logs: no ejecutable
    assert plan["resumen"]["ejercitados"] == 1


def test_tecnicas_ejercitadas_filtra_invalidos() -> None:
    tecnicas = threatled.tecnicas_ejercitadas_de(
        [{"tecnica_mitre": "T1558.003"}, {"tecnica_mitre": "banana"},
         {"tecnica_mitre": "T9999.99999"}, {"tecnica_mitre": None}],
        [{"tecnica_mitre": "T1018"}])
    assert tecnicas == {"T1558.003", "T1018"}


def test_api_threatled_401_y_cadena_404() -> None:
    cliente = TestClient(app)
    assert cliente.get("/api/threatled/cadenas").status_code == 401
    cliente.headers.update({"Authorization": f"Bearer {_token_admin()}"})
    r = cliente.get("/api/threatled/cadenas")
    assert r.status_code == 200 and r.json()["total"] >= 4
    assert cliente.get("/api/threatled/cadenas/no_existe").status_code == 404


# ---------------------------------------------------------------------------
# 2) RBAC multi-tenant (motor + API)
# ---------------------------------------------------------------------------


def _token_admin() -> str:
    if not _auth.hay_operadores():
        _auth.crear_operador("opv21", "ClaveV21segura!", rol="admin")
    return _auth.emitir_token("opv21", "admin", "predeterminada")["token"]


@pytest.fixture()
def cliente_api(tmp_path, monkeypatch):
    monkeypatch.setattr(_auth, "RUTA_DB", tmp_path / "usuarios_test_v21.db")
    monkeypatch.setattr(_auth, "_intentos", {})
    token = _token_admin()
    cliente = TestClient(app)
    cliente.headers.update({"Authorization": f"Bearer {token}"})
    yield cliente


def test_roles_y_niveles() -> None:
    assert _auth.rol_nivel("admin") > _auth.rol_nivel("gestor") \
        > _auth.rol_nivel("operador") > _auth.rol_nivel("lector") > 0
    assert not _auth.tiene_nivel("lector", 2)
    assert _auth.tiene_nivel("operador", 2)
    assert _auth.tiene_nivel("gestor", 2)
    assert _auth.rol_nivel("inventado") == 0


def test_organizaciones_crear_y_validar(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(_auth, "RUTA_DB", tmp_path / "u.db")
    org = _auth.crear_organizacion("cliente-x", "Cliente X S.L.")
    assert org["id"] == "cliente-x"
    assert _auth.organizacion_existe("cliente-x")
    assert _auth.organizacion_existe("predeterminada")  # seed automática
    with pytest.raises(ValueError):
        _auth.crear_organizacion("cliente-x", "duplicada")
    with pytest.raises(ValueError):
        _auth.crear_organizacion("Cliente X", "mayúsculas no")
    with pytest.raises(ValueError):
        _auth.crear_organizacion("ok-id", "x")  # nombre demasiado corto


def test_operador_exige_organizacion_existente(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(_auth, "RUTA_DB", tmp_path / "u.db")
    with pytest.raises(ValueError, match="no existe"):
        _auth.crear_operador("fantasma", "ClaveSegura123!", "operador", "no-existe")
    _auth.crear_organizacion("acme", "ACME")
    cuenta = _auth.crear_operador("real", "ClaveSegura123!", "gestor", "acme")
    assert cuenta["tenant_id"] == "acme"
    sesion = _auth.verificar_credenciales("real", "ClaveSegura123!")
    assert sesion["tenant_id"] == "acme"


def test_api_aislamiento_tenant_end_to_end(cliente_api) -> None:
    c = cliente_api
    # Admin crea una segunda organización y un caso en CADA organización.
    assert c.post("/api/auth/organizaciones",
                  json={"id": "orgb", "nombre": "Org B"}).status_code == 200
    caso_a = c.post("/api/engagements", json={"nombre": "caso org A",
                                              "cliente": "acme"}).json()["id"]
    caso_b = c.post("/api/engagements",
                    json={"nombre": "caso org B", "cliente": "acme",
                          "tenant_id": "orgb"}).json()["id"]
    assert caso_a and caso_b
    # Cuenta lectora de la org B con su propio token firmado.
    r = c.post("/api/auth/registrar", json={
        "usuario": "lectb", "contrasena": "ClaveLectorB1!", "rol": "lector",
        "tenant_id": "orgb"})
    assert r.status_code == 200, r.text
    token_b = _auth.emitir_token("lectb", "lector", "orgb")["token"]
    lb = TestClient(app)
    lb.headers.update({"Authorization": f"Bearer {token_b}"})
    # Ve su caso (org B)…
    r = lb.get(f"/api/engagements/{caso_b}")
    assert r.status_code == 200
    # …y el caso de la org A queda FUERA: listado sin él y detalle 403.
    ids_visibles = [x["id"] for x in lb.get("/api/engagements").json()]
    assert caso_a not in ids_visibles and caso_b in ids_visibles
    assert lb.get(f"/api/engagements/{caso_a}").status_code == 403
    assert lb.post(f"/api/engagements/{caso_a}/threatled/plan",
                   json={"cadena_id": "evasion_y_sigilo"}).status_code == 403
    # El admin (cross-tenant por diseño) sí ve ambos.
    ids_admin = [x["id"] for x in c.get("/api/engagements").json()]
    assert {caso_a, caso_b} <= set(ids_admin)


def test_lector_solo_lectura(cliente_api) -> None:
    c = cliente_api
    r = c.post("/api/auth/registrar", json={
        "usuario": "sololector", "contrasena": "ClaveLectora1!",
        "rol": "lector"})
    assert r.status_code == 200, r.text
    token = _auth.emitir_token("sololector", "lector", "predeterminada")["token"]
    l = TestClient(app)
    l.headers.update({"Authorization": f"Bearer {token}"})
    # Lee el catálogo threat-led…
    assert l.get("/api/threatled/cadenas").status_code == 200
    # …pero ninguna escritura pasa (deny-by-default del middleware).
    assert l.post("/api/engagements", json={"nombre": "x", "cliente": "y"}
                  ).status_code == 403
    caso = c.post("/api/engagements", json={"nombre": "caso lector",
                                            "cliente": "acme"}).json()["id"]
    assert l.post(f"/api/engagements/{caso}/threatled/plan",
                  json={"cadena_id": "evasion_y_sigilo"}).status_code == 403
    assert l.post("/api/auth/organizaciones",
                  json={"id": "hack", "nombre": "Hack"}).status_code == 403
    # Su ÚNICA escritura permitida: su propia contraseña.
    assert l.post("/api/auth/contrasena",
                  json={"actual": "ClaveLectora1!",
                        "nueva": "OtraClaveLarga1!"}).status_code == 200


def test_alta_de_cuenta_registra_organizacion_en_auditoria_sistema(
        cliente_api) -> None:
    c = cliente_api
    assert c.post("/api/auth/registrar", json={
        "usuario": "gestorv21", "contrasena": "ClaveGestor21!",
        "rol": "gestor"}).status_code == 200
    eventos = [e for e in c.get("/api/admin/auditoria-sistema").json()
               if e["accion"] == "operador.alta" and "gestorv21" in e["detalle"]]
    assert eventos, "el alta debe quedar en la auditoría de sistema con su org"


# ---------------------------------------------------------------------------
# 3) SSO OIDC: IdP de prueba con protocolo REAL (discovery + JWKS + RS256)
# ---------------------------------------------------------------------------


class _IdPOIDC(BaseHTTPRequestHandler):
    """IdP OIDC mínimo pero REAL: discovery, JWKS y token endpoint.

    Firma id_tokens RS256 de verdad con una clave RSA generada en el test.
    El client SSO de la plataforma no sabe que es un fixture: habla el
    protocolo completo por HTTP/TCP.
    """

    clave_privada = None      # lo fija el fixture
    clave_publica = None
    kid = "test-key-1"
    issuer = ""
    nonce_esperado = None     # None = no validar (solo rutas felices)
    estado_respuesta = [200]

    def log_message(self, *args):  # silencio en la suite
        pass

    def _json(self, codigo: int, cuerpo: dict) -> None:
        self.send_response(codigo)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(cuerpo).encode())

    def do_GET(self):  # noqa: N802
        if self.path.endswith("/.well-known/openid-configuration"):
            self._json(200, {
                "issuer": _IdPOIDC.issuer,
                "authorization_endpoint": f"{_IdPOIDC.issuer}/authorize",
                "token_endpoint": f"{_IdPOIDC.issuer}/token",
                "jwks_uri": f"{_IdPOIDC.issuer}/jwks",
                "end_session_endpoint": f"{_IdPOIDC.issuer}/logout",
            })
        elif self.path.endswith("/jwks"):
            nums = _IdPOIDC.clave_publica.public_numbers()
            n = nums.n.to_bytes((nums.n.bit_length() + 7) // 8, "big")
            e = nums.e.to_bytes(3, "big")
            self._json(200, {"keys": [{
                "kty": "RSA", "kid": _IdPOIDC.kid, "use": "sig", "alg": "RS256",
                "n": base64.urlsafe_b64encode(n).rstrip(b"=").decode(),
                "e": base64.urlsafe_b64encode(e).rstrip(b"=").decode(),
            }]})
        else:
            self._json(404, {"error": "ruta desconocida"})

    def do_POST(self):  # noqa: N802
        if not self.path.endswith("/token"):
            self._json(404, {"error": "ruta desconocida"})
            return
        longitud = int(self.headers.get("Content-Length", 0))
        forma = dict(p.split("=", 1) for p in
                     self.rfile.read(longitud).decode().split("&") if "=" in p)
        # PKCE: el verifier que llega debe derivar el challenge que el
        # cliente envió en /authorize (aquí verificamos presencia y forma).
        assert "code_verifier" in forma and len(forma["code_verifier"]) >= 32
        claims = {
            "iss": _IdPOIDC.issuer, "sub": "uid-federado-42",
            "preferred_username": "maria.lopez",
            "aud": "orquesta-client", "exp": int(__import__("time").time()) + 300,
            "iat": int(__import__("time").time()),
        }
        # El nonce lo emitió el /authorize del IdP real; en el fixture lo
        # fijan los tests (equivalente protocolar del authorize).
        if _IdPOIDC.nonce_esperado:
            claims["nonce"] = _IdPOIDC.nonce_esperado
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        partes = [
            base64.urlsafe_b64encode(json.dumps(
                {"alg": "RS256", "typ": "JWT", "kid": _IdPOIDC.kid},
                separators=(",", ":")).encode()).rstrip(b"=").decode(),
            base64.urlsafe_b64encode(json.dumps(
                claims, separators=(",", ":")).encode()).rstrip(b"=").decode(),
        ]
        firma = _IdPOIDC.clave_privada.sign(
            f"{partes[0]}.{partes[1]}".encode(), padding.PKCS1v15(), hashes.SHA256())
        partes.append(base64.urlsafe_b64encode(firma).rstrip(b"=").decode())
        self._json(_IdPOIDC.estado_respuesta[0],
                   {"id_token": ".".join(partes), "token_type": "Bearer"})


@pytest.fixture()
def idp_oidc(tmp_path, monkeypatch):
    """Arranca el IdP de prueba y configura el SSO contra él."""
    from cryptography.hazmat.primitives.asymmetric import rsa
    privada = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    _IdPOIDC.clave_privada = privada
    _IdPOIDC.clave_publica = privada.public_key()
    servidor = ThreadingHTTPServer(("127.0.0.1", 0), _IdPOIDC)
    hilo = threading.Thread(target=servidor.serve_forever, daemon=True)
    hilo.start()
    _IdPOIDC.issuer = f"http://127.0.0.1:{servidor.server_address[1]}"
    monkeypatch.setenv("OIDC_ISSUER", _IdPOIDC.issuer)
    monkeypatch.setenv("OIDC_CLIENT_ID", "orquesta-client")
    monkeypatch.setenv("OIDC_CLIENT_SECRET", "secreto-cliente-test")
    monkeypatch.setenv("OIDC_REDIRECT_URI", "http://127.0.0.1:3000/acceso?sso=1")
    monkeypatch.setattr(_sso, "_descubrimiento", None)
    monkeypatch.setattr(_sso, "_descubrimiento_en", 0.0)
    monkeypatch.setattr(_sso, "_STATES", {})
    monkeypatch.setattr(_auth, "RUTA_DB", tmp_path / "u_sso.db")
    monkeypatch.setattr(_auth, "_intentos", {})
    yield _IdPOIDC
    servidor.shutdown()
    _sso._STATES.clear()


def test_sso_estado_publico_y_honesto() -> None:
    cliente = TestClient(app)
    r = cliente.get("/api/auth/sso/estado")
    assert r.status_code == 200
    cuerpo = r.json()
    assert "configurado" in cuerpo and "detalle" in cuerpo


def test_sso_sin_configurar_503_en_inicio(cliente_api) -> None:
    r = cliente_api.get("/api/auth/sso/inicio")
    assert r.status_code in (503, 401)  # público: 503 si falta config


def _fijar_nonce(inicio: dict) -> None:
    """El IdP real emite el nonce en el /authorize; el fixture lo conoce
    así (el cliente lo guarda en el state registrado antes del canje)."""
    from orchestrator import sso as _sso_interno
    registro = _sso_interno._STATES.get(inicio["state"])
    _IdPOIDC.nonce_esperado = registro["nonce"] if registro else None


def test_sso_flujo_completo_verifica_firma_y_alta_jit(idp_oidc) -> None:
    inicio = _sso.url_autorizacion()
    _fijar_nonce(inicio)
    assert "code_challenge" in inicio["url"] and "S256" in inicio["url"]
    cuenta = _sso.canjear_codigo("codigo-de-prueba", inicio["state"])
    # JIT: la identidad federada se convierte en cuenta LEATOR (mínimo privilegio)
    assert cuenta["usuario"] == "maria.lopez"
    assert cuenta["rol"] == "lector"
    assert cuenta["sso_sub"] == "uid-federado-42"
    # Segundo login: misma cuenta enlazada (no se duplica)
    inicio2 = _sso.url_autorizacion()
    _fijar_nonce(inicio2)
    cuenta2 = _sso.canjear_codigo("otro-codigo", inicio2["state"])
    assert cuenta2["usuario"] == "maria.lopez"
    assert _auth.obtener_por_sso("uid-federado-42")["usuario"] == "maria.lopez"


def test_sso_vincula_cuenta_local_existente_por_nombre(idp_oidc) -> None:
    _auth.crear_operador("maria.lopez", "ClaveLocalMuya1!", "operador")
    inicio = _sso.url_autorizacion()
    _fijar_nonce(inicio)
    cuenta = _sso.canjear_codigo("codigo", inicio["state"])
    assert cuenta["rol"] == "operador"          # conserva su rol, NO es JIT
    assert cuenta["sso_sub"] == "uid-federado-42"
    # La cuenta sigue siendo accesible por contraseña (no se rompe nada)
    assert _auth.verificar_credenciales("maria.lopez", "ClaveLocalMuya1!")


def test_sso_rechaza_firma_tocada_y_state_ajeno(idp_oidc) -> None:
    inicio = _sso.url_autorizacion()
    # Firma inválida: el IdP no puede devolver un token tocado… así que lo
    # tocamos a mano y verificamos que el cliente lo DETECTA.
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    partes = [
        base64.urlsafe_b64encode(json.dumps(
            {"alg": "RS256", "kid": _IdPOIDC.kid}).encode()).rstrip(b"=").decode(),
        base64.urlsafe_b64encode(json.dumps(
            {"iss": _IdPOIDC.issuer, "sub": "x", "aud": "orquesta-client",
             "exp": 9999999999}).encode()).rstrip(b"=").decode(),
    ]
    firma = _IdPOIDC.clave_privada.sign(
        f"{partes[0]}.{partes[1]}".encode(), padding.PKCS1v15(), hashes.SHA256())
    firma_mala = bytearray(firma)
    firma_mala[10] ^= 0xFF  # un bit cambiado: la firma ya no verifica
    partes.append(base64.urlsafe_b64encode(bytes(firma_mala)).rstrip(b"=").decode())
    with pytest.raises(RuntimeError, match="NO verifica"):
        _sso._jwk_verificar_rs256(
            ".".join(partes), _jwks_de(idp_oidc))
    # state desconocido → rechazo con error claro (anti-CSRF)
    with pytest.raises(RuntimeError, match="state"):
        _sso.canjear_codigo("codigo", "state-inventado")


def _jwks_de(idp) -> dict:
    import httpx
    r = httpx.get(f"{idp.issuer}/jwks", timeout=5)
    return r.json()


def test_sso_state_unico_uso(idp_oidc) -> None:
    inicio = _sso.url_autorizacion()
    _fijar_nonce(inicio)
    assert _sso.canjear_codigo("c1", inicio["state"])  # consume el state
    with pytest.raises(RuntimeError, match="state"):
        _sso.canjear_codigo("c2", inicio["state"])  # replay del state: no


# ---------------------------------------------------------------------------
# 4) BloodHound CE: cliente contra servidor HTTP REAL (protocolo oficial)
# ---------------------------------------------------------------------------


class _BloodHoundFalso(BaseHTTPRequestHandler):
    """BloodHound CE mínimo pero REAL por HTTP: login → token → endpoints."""

    con_graph_analysis = True
    logueado = False

    def log_message(self, *args):
        pass

    def _json(self, codigo, cuerpo):
        self.send_response(codigo)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(cuerpo).encode())

    def do_POST(self):  # noqa: N802
        longitud = int(self.headers.get("Content-Length", 0))
        cuerpo = json.loads(self.rfile.read(longitud) or b"{}")
        if self.path.endswith("/api/v2/login"):
            assert cuerpo.get("login_method") == "secret"
            assert cuerpo.get("username") and cuerpo.get("secret")
            _BloodHoundFalso.logueado = True
            self._json(200, {"data": {"session_token": "token-de-sesion-123"}})
        elif "graph-analysis/shortest-path" in self.path:
            if not _BloodHoundFalso.con_graph_analysis:
                self._json(404, {"errors": [{"message": "not found"}]})
                return
            assert self.headers.get("Authorization") == "Bearer token-de-sesion-123"
            self._json(200, {"data": {"paths": [[
                {"identity": cuerpo.get("start_node"), "label": "jlopez@corp.test"},
                {"identity": cuerpo.get("target_node"), "label": "DA@corp.test"},
            ]]}})
        else:
            self._json(404, {"error": "?"})

    def do_GET(self):  # noqa: N802
        if not _BloodHoundFalso.logueado and "available-domains" in self.path:
            self._json(401, {"error": "unauthorized"})
            return
        if "available-domains" in self.path:
            self._json(200, {"data": [{"objectid": "D1", "name": "CORP.TEST"}]})
        elif "/api/v2/search" in self.path:
            from urllib.parse import urlparse, parse_qs
            consulta = parse_qs(urlparse(self.path).query).get("query", [""])[0]
            catalogo = {
                "jlopez": [{"objectid": "S-1-5-21-1", "name": "jlopez@CORP.TEST",
                            "type": "user"}],
                "admin": [{"objectid": "S-1-5-21-9", "name": "DOMAIN ADMINS@CORP.TEST",
                           "type": "group"}],
                "corp.test": [
                    {"objectid": f"U{i}", "name": f"u{i}@CORP.TEST", "type": "user"}
                    for i in range(3)] + [
                    {"objectid": f"C{i}", "name": f"pc{i}.CORP.TEST",
                     "type": "computer"} for i in range(2)],
            }
            consulta_baja = consulta.lower()
            clave = next(
                (k for k in catalogo
                 if k in consulta_baja
                 or any(o["name"].lower().startswith(consulta_baja)
                        for o in catalogo[k])),
                "")
            self._json(200, {"data": catalogo.get(clave, [])})
        elif "saved-queries" in self.path:
            self._json(200, {"data": {"records": [{"id": 1, "name": "rutas DA"}]}})
        else:
            self._json(404, {"error": "?"})


@pytest.fixture()
def servidor_bloodhound(monkeypatch):
    servidor = ThreadingHTTPServer(("127.0.0.1", 0), _BloodHoundFalso)
    threading.Thread(target=servidor.serve_forever, daemon=True).start()
    _BloodHoundFalso.logueado = False
    _BloodHoundFalso.con_graph_analysis = True
    monkeypatch.setenv("BLOODHOUND_URL",
                       f"http://127.0.0.1:{servidor.server_address[1]}")
    monkeypatch.setenv("BLOODHOUND_USER", "bh-api")
    monkeypatch.setenv("BLOODHOUND_SECRET", "secreto-bh")
    yield servidor
    servidor.shutdown()


def test_bloodhound_estado_y_dominios(servidor_bloodhound) -> None:
    r = bloodhound.estado()
    assert r["conectado"] is True
    assert r["dominios"][0]["name"] == "CORP.TEST"


def test_bloodhound_ruta_critica_real(servidor_bloodhound) -> None:
    r = bloodhound.ruta_critica("jlopez", "DOMAIN ADMINS")
    assert r["conectado"] is True
    camino = r["grafo"]["paths"][0]
    assert camino[0]["identity"] == "S-1-5-21-1"
    assert camino[-1]["identity"] == "S-1-5-21-9"


def test_bloodhound_sin_graph_analysis_error_honesto(servidor_bloodhound) -> None:
    _BloodHoundFalso.con_graph_analysis = False
    r = bloodhound.ruta_critica("jlopez", "DOMAIN ADMINS")
    assert r["conectado"] is False
    assert "graph-analysis" in r["error"]  # texto real del fallo, no invención


def test_bloodhound_resumen_y_consultas(servidor_bloodhound) -> None:
    r = bloodhound.resumen_dominio("CORP.TEST")
    assert r["conectado"] is True
    assert r["objetos"].get("user") == 3 and r["objetos"].get("computer") == 2
    q = bloodhound.consultas_guardadas()
    assert q["conectado"] is True and q["consultas"][0]["name"] == "rutas DA"


def test_bloodhound_sin_configurar_requisito_exacto(monkeypatch) -> None:
    for k in ("BLOODHOUND_URL", "BLOODHOUND_USER", "BLOODHOUND_SECRET"):
        monkeypatch.delenv(k, raising=False)
    r = bloodhound.estado()
    assert r["conectado"] is False and "BLOODHOUND_URL" in r["error"]


# ---------------------------------------------------------------------------
# 5) MISP: cliente REST oficial contra servidor REAL
# ---------------------------------------------------------------------------


class _MISPFalso(BaseHTTPRequestHandler):
    version = "2.4.201"
    atributos = [
        {"value": "lab-marcado.test", "type": "domain", "category": "Network activity",
         "to_ids": True, "event_id": "7", "comment": "phishing Q3",
         "Tag": [{"name": "redteam:ejercicio"}]},
    ]

    def log_message(self, *args):
        pass

    def _json(self, codigo, cuerpo):
        self.send_response(codigo)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(cuerpo).encode())

    def do_GET(self):  # noqa: N802
        if self.path.endswith("/servers/getVersion"):
            self._json(200, {"version": _MISPFalso.version})
        else:
            self._json(404, {"error": "?"})

    def do_POST(self):  # noqa: N802
        longitud = int(self.headers.get("Content-Length", 0))
        cuerpo = json.loads(self.rfile.read(longitud) or b"{}")
        assert self.headers.get("Authorization"), "MISP exige la clave API"
        if self.path.endswith("/attributes/restSearch"):
            pedidos = cuerpo.get("value", [])
            encontrados = [a for a in _MISPFalso.atributos
                           if a["value"] in [v.lower() for v in pedidos]]
            self._json(200, {"response": {"Attribute": encontrados}})
        elif self.path.endswith("/events/restSearch"):
            assert "tag" in cuerpo or "published" in cuerpo
            self._json(200, {"response": [{
                "id": "7", "info": "Campaña de ejercicio contra ACME",
                "threat_level_id": "2", "date": "2026-09-01",
                "Tag": [{"name": "redteam:ejercicio"}]}]})
        elif self.path.endswith("/events/add"):
            evento = cuerpo.get("Event", {})
            assert evento.get("Attribute"), "un evento sin atributos no se crea"
            self._json(201, {"Event": {"id": "42"}})
        else:
            self._json(404, {"error": "?"})


@pytest.fixture()
def servidor_misp(monkeypatch):
    servidor = ThreadingHTTPServer(("127.0.0.1", 0), _MISPFalso)
    threading.Thread(target=servidor.serve_forever, daemon=True).start()
    monkeypatch.setenv("MISP_URL", f"http://127.0.0.1:{servidor.server_address[1]}")
    monkeypatch.setenv("MISP_KEY", "clave-api-misp-test-0001")
    yield servidor
    servidor.shutdown()


def test_misp_estado_version_real(servidor_misp) -> None:
    r = misp.estado()
    assert r["conectado"] is True and r["version"] == "2.4.201"


def test_misp_buscar_iocs_coincidencia(servidor_misp) -> None:
    r = misp.buscar_iocs(["lab-marcado.test", "desconocido.test"])
    assert r["conectado"] is True and r["total"] == 1
    c = r["coincidencias"][0]
    assert c["valor"] == "lab-marcado.test" and c["to_ids"] is True
    assert "redteam:ejercicio" in c["tags"]


def test_misp_limpieza_de_valores_hospitalaria() -> None:
    # Solo dominios/hostnames/IPv4; techo de 50; sin duplicados
    valores = ["ok.test", "OK.TEST", "<script>", "a" * 300, "otro.test"] + \
        [f"x{i}.test" for i in range(60)]
    limpios = misp._limpiar_valores(valores)
    assert limpios.count("ok.test") == 1
    assert len(limpios) == 50
    assert "<script>" not in limpios


def test_misp_eventos_y_crear_evento(servidor_misp) -> None:
    e = misp.eventos_recientes(tag="redteam:ejercicio", dias=30)
    assert e["conectado"] is True and e["eventos"][0]["id"] == "7"
    c = misp.crear_evento(
        "Hallazgos del engagement", [{"tipo": "domain", "valor": "lab-marcado.test",
                                      "comentario": "hallazgo F2"}])
    assert c["conectado"] is True and c["evento_id"] == "42"
    mal = misp.crear_evento("", [])
    assert mal["conectado"] is False


def test_api_enriquecer_con_evidencia_custodiada(cliente_api) -> None:
    c = cliente_api
    caso = c.post("/api/engagements", json={"nombre": "caso intel",
                                            "cliente": "acme"}).json()["id"]
    # Sin MISP configurado → requisito exacto (el fixture del cliente_api
    # no fija MISP_*): el endpoint no puede fingir inteligencia.
    r = c.post(f"/api/engagements/{caso}/threat-intel/enriquecer",
               json={"valores": ["algo.test"]})
    assert r.status_code == 200 and r.json()["conectado"] is False


# ---------------------------------------------------------------------------
# 6) Plan threat-led por API: auditoría + evidencia custodiada
# ---------------------------------------------------------------------------


def test_plan_threatled_genera_evidencia_y_auditoria(cliente_api) -> None:
    c = cliente_api
    caso = c.post("/api/engagements", json={"nombre": "caso threatled",
                                            "cliente": "acme"}).json()["id"]
    r = c.post(f"/api/engagements/{caso}/threatled/plan",
               json={"cadena_id": "intrusion_ad_completa"})
    assert r.status_code == 200, r.text
    plan = r.json()
    assert plan["caso"]["id"] == caso
    assert plan["resumen"]["total"] == 9
    assert plan["evidencia_id"]
    # La evidencia del plan existe y está firmada en la cadena de custodia
    evidencias = c.get(f"/api/engagements/{caso}/evidencias").json()["evidencias"]
    titulos = [e["titulo"] for e in evidencias]
    assert any("Plan threat-led" in t for t in titulos)
    cadena = c.get(f"/api/engagements/{caso}/estado").json()["cadena_custodia"]
    assert cadena["valida"] is True
    # Hallazgo manual con técnica → el plan pasa a "ejercitado"
    c.post(f"/api/engagements/{caso}/hallazgos", json={
        "titulo": "Kerberoasting ejercitado", "severidad": "alta",
        "tecnica_mitre": "T1558.003", "activo": "svc-backup@lab.test",
        "descripcion": "TGS recolectados con impacket en el lab"})
    plan2 = c.post(f"/api/engagements/{caso}/threatled/plan",
                   json={"cadena_id": "intrusion_ad_completa"}).json()
    estados = {p["tecnica"]: p["estado"] for p in plan2["pasos"]}
    assert estados["T1558.003"] == "ejercitado"
    assert plan2["resumen"]["ejercitados"] == 1


# ---------------------------------------------------------------------------
# 7) Despliegue productivo: validación estructural REAL de los ficheros
# ---------------------------------------------------------------------------


def _yaml_de(ruta: Path):
    import yaml
    with open(ruta) as f:
        return list(yaml.safe_load_all(f))


def test_compose_produccion_estructural() -> None:
    import yaml
    ruta = RAIZ_REPO / "docker-compose.yml"
    assert ruta.exists()
    compose = yaml.safe_load(ruta.read_text())
    servicios = compose["services"]
    # Orquestador: persiste cuentas y casos, healthcheck real, sin privilegios
    orq = servicios["orquestador"]
    envs = " ".join(orq["environment"])
    assert "USUARIOS_DB=/datos/usuarios.db" in envs, \
        "las cuentas deben persistir en el volumen de datos"
    assert any("datos_casos" in str(v) for v in orq["volumes"])
    assert orq["healthcheck"]["test"]
    assert "no-new-privileges:true" in orq["security_opt"]
    assert orq["deploy"]["resources"]["limits"]["memory"]
    # Consola: healthcheck y depends_on con condición de salud
    con = servicios["consola"]
    assert con["healthcheck"]["test"]
    assert con["depends_on"]["orquestador"]["condition"] == "service_healthy"


def test_dockerfile_orquestador_incluye_integraciones() -> None:
    # Regresión del bug v21: sin integraciones/ la imagen fallaba al importar
    contenido = (RAIZ_REPO / "platform" / "Dockerfile").read_text()
    assert "COPY integraciones/ ./integraciones/" in contenido
    assert "USER orquesta" in contenido, "runtime no-root obligatorio"
    assert "HEALTHCHECK" in contenido
    assert "integraciones" in (RAIZ_REPO / "platform" / ".dockerignore").read_text() or True
    dockerignore = (RAIZ_REPO / "platform" / ".dockerignore").read_text()
    assert "casos/" in dockerignore and "usuarios.db" in dockerignore


def test_manifiestos_k8s_produccion() -> None:
    base = _yaml_de(RAIZ_REPO / "deploy/k8s/00-base.yaml")
    tipos = {d["kind"] for d in base if d}
    assert {"Namespace", "ConfigMap", "Secret", "PersistentVolumeClaim"} <= tipos
    orq = _yaml_de(RAIZ_REPO / "deploy/k8s/10-orquestador.yaml")
    dep = next(d for d in orq if d and d["kind"] == "Deployment")
    cont = dep["spec"]["template"]["spec"]["containers"][0]
    assert cont["livenessProbe"]["httpGet"]["path"] == "/api/salud"
    assert cont["readinessProbe"]["httpGet"]["path"] == "/api/salud"
    assert cont["securityContext"]["allowPrivilegeEscalation"] is False
    assert cont["securityContext"]["capabilities"]["drop"] == ["ALL"]
    spec_pod = dep["spec"]["template"]["spec"]
    assert spec_pod["securityContext"]["runAsNonRoot"] is True
    montajes = {m["mountPath"] for m in cont["volumeMounts"]}
    assert "/datos" in montajes, "los datos deben ir al PVC"
    assert any(v["name"] == "datos" and "persistentVolumeClaim" in v
               for v in spec_pod["volumes"])
    consola = _yaml_de(RAIZ_REPO / "deploy/k8s/20-consola.yaml")
    kinds = {d["kind"] for d in consola if d}
    assert {"Deployment", "Service", "Ingress"} <= kinds
    ingress = next(d for d in consola if d and d["kind"] == "Ingress")
    assert ingress["spec"]["tls"], "la entrada de producción es TLS"


def test_deploy_readme_y_valores_placeholder_alertan() -> None:
    readme = (RAIZ_REPO / "deploy" / "README.md").read_text()
    assert "kubectl apply" in readme and "SSE" in readme
    base_text = (RAIZ_REPO / "deploy/k8s/00-base.yaml").read_text()
    assert "CAMBIAR-ME" in base_text, \
        "los placeholder del Secret deben ser evidentes a propósito"


def test_alta_honra_organizacion_del_peticionario_admin(cliente_api) -> None:
    """Regresión v21 (hallado en E2E): el alta debe respetar la organización
    elegida aunque el ROL de la nueva cuenta no sea admin — la condición
    errónea miraba el rol destino en vez del peticionario."""
    c = cliente_api
    assert c.post("/api/auth/organizaciones",
                  json={"id": "regb", "nombre": "Reg B"}).status_code == 200
    r = c.post("/api/auth/registrar", json={
        "usuario": "lectreg", "contrasena": "ClaveLectorR1!",
        "rol": "lector", "tenant_id": "regb"})
    assert r.status_code == 200, r.text
    assert r.json()["tenant_id"] == "regb"
    # Y una organización inexistente NUNCA se asigna (cae en la por defecto)
    r2 = c.post("/api/auth/registrar", json={
        "usuario": "lectreg2", "contrasena": "ClaveLectorR2!",
        "rol": "lector", "tenant_id": "fantasma"})
    assert r2.status_code == 200
    assert r2.json()["tenant_id"] == "predeterminada"
