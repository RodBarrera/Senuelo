"""Tests del motor de admisión (ScopeEngine)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from senuelo.scope import (
    AuthorizationNotActiveError,
    AuthorizationRevokedError,
    ExcludedRecipientError,
    InvalidSignatureError,
    MalformedRecipientError,
    OutOfScopeError,
    ScopeEngine,
    sign,
)
from tests.conftest import TEST_KEY, make_authorization


def engine_for(auth) -> ScopeEngine:
    return ScopeEngine(auth, TEST_KEY)


def test_admit_in_scope(signed_auth):
    eng = engine_for(signed_auth)
    assert eng.admit("Juan.Perez@Empresa.cl") == "juan.perez@empresa.cl"


def test_out_of_scope_rejected(signed_auth):
    eng = engine_for(signed_auth)
    with pytest.raises(OutOfScopeError):
        eng.admit("alguien@gmail.com")


def test_excluded_rejected(signed_auth):
    eng = engine_for(signed_auth)
    with pytest.raises(ExcludedRecipientError):
        eng.admit("gerencia.general@empresa.cl")


def test_malformed_rejected(signed_auth):
    eng = engine_for(signed_auth)
    for bad in ["sin-arroba", "doble@@empresa.cl", "@empresa.cl", "x@"]:
        with pytest.raises(MalformedRecipientError):
            eng.admit(bad)


def test_subdomains_excluded_by_default(signed_auth):
    eng = engine_for(signed_auth)
    with pytest.raises(OutOfScopeError):
        eng.admit("user@correo.empresa.cl")


def test_subdomains_allowed_when_enabled():
    auth = sign(make_authorization(include_subdomains=True), TEST_KEY)
    eng = engine_for(auth)
    assert eng.admit("user@correo.empresa.cl") == "user@correo.empresa.cl"
    # pero el dominio base sigue admitido
    assert eng.admit("user@empresa.cl") == "user@empresa.cl"
    # y un sufijo engañoso no entra
    with pytest.raises(OutOfScopeError):
        eng.admit("user@noempresa.cl")


def test_not_yet_active_blocks_admission():
    now = datetime.now(timezone.utc)
    auth = sign(
        make_authorization(
            window_start=now + timedelta(days=1),
            window_end=now + timedelta(days=2),
        ),
        TEST_KEY,
    )
    with pytest.raises(AuthorizationNotActiveError):
        engine_for(auth).admit("user@empresa.cl")


def test_expired_blocks_admission():
    now = datetime.now(timezone.utc)
    auth = sign(
        make_authorization(
            window_start=now - timedelta(days=5),
            window_end=now - timedelta(days=1),
        ),
        TEST_KEY,
    )
    with pytest.raises(AuthorizationNotActiveError):
        engine_for(auth).admit("user@empresa.cl")


def test_revoked_blocks_admission(signed_auth):
    signed_auth.revoked_at = datetime.now(timezone.utc)
    # revocar cambia el payload -> además rompería la firma; re-firmamos para
    # aislar que lo que bloquea aquí es la revocación, no la firma.
    sign(signed_auth, TEST_KEY)
    with pytest.raises(AuthorizationRevokedError):
        engine_for(signed_auth).admit("user@empresa.cl")


def test_tampered_authorization_blocks_everyone(signed_auth):
    signed_auth.scope_domains.append("inyectado.cl")  # manipulación
    eng = engine_for(signed_auth)
    with pytest.raises(InvalidSignatureError):
        eng.filter_recipients(["user@empresa.cl", "user@inyectado.cl"])


def test_filter_recipients_report(signed_auth):
    eng = engine_for(signed_auth)
    report = eng.filter_recipients(
        [
            "ok1@empresa.cl",
            "ok2@empresa.cl",
            "fuera@gmail.com",
            "gerencia.general@empresa.cl",  # excluido
            "malformado",
        ]
    )
    assert report.admitted == ["ok1@empresa.cl", "ok2@empresa.cl"]
    assert report.admitted_count == 2
    assert report.rejected_count == 3
    codes = {r.code for r in report.rejected}
    assert codes == {"out_of_scope", "excluded_recipient", "malformed_recipient"}
    assert report.total == 5
