"""Tests de los modelos de autorización."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from senuelo.scope import Authorization, AuthorizationStatus
from tests.conftest import make_authorization


def test_scope_domains_normalized_and_deduped():
    auth = make_authorization(
        scope_domains=["  Empresa.CL ", "@empresa.cl", "Sucursal.empresa.cl"]
    )
    # minúsculas, sin '@' inicial, sin duplicados, preservando orden de aparición
    assert auth.scope_domains == ["empresa.cl", "sucursal.empresa.cl"]


def test_invalid_domain_rejected():
    with pytest.raises(ValidationError):
        make_authorization(scope_domains=["no-es-un-dominio"])


def test_window_end_must_be_after_start():
    now = datetime.now(timezone.utc)
    with pytest.raises(ValidationError):
        make_authorization(
            window_start=now, window_end=now - timedelta(hours=1)
        )


def test_naive_datetime_rejected():
    with pytest.raises(ValidationError):
        make_authorization(window_start=datetime(2026, 1, 1))  # sin tzinfo


def test_excluded_addresses_normalized():
    auth = make_authorization(
        excluded_addresses=["  Jefe@Empresa.CL ", "jefe@empresa.cl"]
    )
    assert auth.excluded_addresses == ["jefe@empresa.cl"]


def test_status_unsigned_then_active():
    auth = make_authorization()
    assert auth.status() is AuthorizationStatus.UNSIGNED


def test_status_not_yet_active_and_expired():
    now = datetime.now(timezone.utc)
    future = make_authorization(
        window_start=now + timedelta(days=1),
        window_end=now + timedelta(days=2),
        signature="x",  # basta con que esté "firmada" para mirar la ventana
    )
    assert future.status() is AuthorizationStatus.NOT_YET_ACTIVE

    past = make_authorization(
        window_start=now - timedelta(days=2),
        window_end=now - timedelta(days=1),
        signature="x",
    )
    assert past.status() is AuthorizationStatus.EXPIRED


def test_status_revoked_takes_precedence():
    now = datetime.now(timezone.utc)
    auth = make_authorization(signature="x", revoked_at=now)
    assert auth.status() is AuthorizationStatus.REVOKED


def test_data_retention_bounds():
    with pytest.raises(ValidationError):
        make_authorization(data_retention_days=0)
