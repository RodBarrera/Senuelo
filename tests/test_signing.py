"""Tests del firmado antimanipulación."""

from __future__ import annotations

import pytest

from senuelo.scope import InvalidSignatureError, sign, verify
from tests.conftest import TEST_KEY, make_authorization


def test_sign_then_verify_ok(signed_auth):
    # No lanza: la firma recién puesta valida.
    verify(signed_auth, TEST_KEY)
    assert signed_auth.signature is not None
    assert signed_auth.signed_at is not None


def test_tampering_scope_breaks_signature(signed_auth):
    # Editar el alcance después de firmar invalida la firma.
    signed_auth.scope_domains.append("otra-empresa.cl")
    with pytest.raises(InvalidSignatureError):
        verify(signed_auth, TEST_KEY)


def test_tampering_window_breaks_signature(signed_auth):
    from datetime import timedelta

    signed_auth.window_end = signed_auth.window_end + timedelta(days=365)
    with pytest.raises(InvalidSignatureError):
        verify(signed_auth, TEST_KEY)


def test_wrong_key_fails(signed_auth):
    with pytest.raises(InvalidSignatureError):
        verify(signed_auth, "otra-clave")


def test_unsigned_fails_closed():
    auth = make_authorization()
    with pytest.raises(InvalidSignatureError):
        verify(auth, TEST_KEY)


def test_missing_key_raises():
    auth = make_authorization()
    with pytest.raises(ValueError):
        sign(auth, key=None)  # sin clave ni variable de entorno
