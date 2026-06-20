"""Fixtures compartidas para los tests del motor de alcance."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from senuelo.scope import Authorization, Party, sign

TEST_KEY = "clave-de-prueba-no-usar-en-produccion"


def make_authorization(**overrides) -> Authorization:
    """Construye una autorización válida; los kwargs sobreescriben campos."""
    now = datetime.now(timezone.utc)
    defaults = dict(
        organization="Empresa Demo SpA",
        authorized_by=Party(
            name="Ana Soto",
            role="CISO",
            email="ana.soto@empresa.cl",
        ),
        requested_by=Party(
            name="Equipo Red Team",
            role="Operador del ejercicio",
            email="redteam@consultora.cl",
        ),
        scope_domains=["empresa.cl"],
        excluded_addresses=["gerencia.general@empresa.cl"],
        window_start=now - timedelta(days=1),
        window_end=now + timedelta(days=7),
        data_retention_days=90,
        consent_reference="Anexo RoE 2026-04 firmado por gerencia",
    )
    defaults.update(overrides)
    return Authorization(**defaults)


@pytest.fixture
def key() -> str:
    return TEST_KEY


@pytest.fixture
def signed_auth() -> Authorization:
    return sign(make_authorization(), TEST_KEY)
