"""Fixtures globales de la suite (Z2-ronda-2).

El limitador de tasa de login y el registro de intentos fallidos son
estado EN PROCESO compartido por TODA la suite: sin reseteo por test, los
ficheros que hacen muchos logins consumen el presupuesto (10 peticiones
por 60 s) de los siguientes y la suite se vuelve orden-dependiente
(fragilidad detectada en la Ronda Z2-1: "la suite ya rozaba su
presupuesto").

Este fixture autouse da a CADA test un limitador y un registro frescos.
El contrato del limitador (429 + Retry-After, ventana deslizante, poda de
memoria y tope duro de claves) queda fijado por test_v9.py a nivel de
clase; aquí solo se aísla el estado compartido del proceso entre tests —
ningún test depende ya del número de logins que hicieron los anteriores.
"""
from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _estado_auth_fresco(monkeypatch):
    from orchestrator import api as api_mod
    from orchestrator import auth as auth_mod

    # Presupuesto holgado: el contrato 429 se prueba a nivel de clase en
    # test_v9.py; en integración lo que se aísla es el ESTADO, no el límite.
    monkeypatch.setattr(api_mod, "_limitador_auth",
                        api_mod._LimitadorTasa(10 ** 9))
    monkeypatch.setattr(auth_mod, "_intentos", {})


@pytest.fixture(autouse=True)
def _hogares_lab_para_tests(monkeypatch, tmp_path_factory):
    """z3 (sesión 7, F37): el arsenal de persistencia está CONFINADO a los
    hogares del lab (ORQUESTA_LAB_HOGARES). La suite implanta en tmp_path
    de pytest: ese árbol se declara lab autorizado para cada test, igual
    que un despliegue real declara sus hogares de laboratorio. La raíz
    BASETEMP cubre todos los tmp_path y subdirectorios creados por los
    tests (incluidos los que contienen espacios)."""
    base = str(tmp_path_factory.getbasetemp())
    monkeypatch.setenv("ORQUESTA_LAB_HOGARES", base)
