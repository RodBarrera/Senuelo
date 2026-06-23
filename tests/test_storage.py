"""Tests de la capa de persistencia (SQLite) y el audit log."""

from __future__ import annotations

import dataclasses
import sqlite3

import pytest

from senuelo.scope import sign
from senuelo.storage import (
    AuditTamperError,
    InMemoryAuditLog,
    SqliteAuditLog,
    SqliteAuthorizationRepository,
    get_connection,
    reset_connections,
)
from tests.conftest import TEST_KEY, make_authorization


@pytest.fixture(autouse=True)
def _cleanup():
    yield
    reset_connections()


def test_sqlite_repo_roundtrip_and_persistence(tmp_path):
    path = str(tmp_path / "t.db")
    repo = SqliteAuthorizationRepository(get_connection(path))
    auth = sign(make_authorization(), TEST_KEY)
    repo.add(auth)

    got = repo.get(auth.authorization_id)
    assert got is not None and got.signature == auth.signature
    assert len(repo.list()) == 1

    # simular reinicio: nueva conexión a la misma ruta ve el dato
    reset_connections()
    repo2 = SqliteAuthorizationRepository(get_connection(path))
    assert repo2.get(auth.authorization_id) is not None


def test_sqlite_repo_get_missing(tmp_path):
    repo = SqliteAuthorizationRepository(get_connection(str(tmp_path / "t.db")))
    assert repo.get("no-existe") is None


def test_audit_chain_memory():
    log = InMemoryAuditLog()
    log.append("a")
    e2 = log.append("b", "id1", {"x": 1})
    entries = log.entries()
    assert len(entries) == 2
    assert e2.prev_hash == entries[0].entry_hash  # encadenado
    assert log.verify() is True


def test_audit_chain_sqlite(tmp_path):
    log = SqliteAuditLog(get_connection(str(tmp_path / "a.db")))
    log.append("a")
    e2 = log.append("b", "id1", {"x": 1})
    assert e2.seq == 2
    assert log.entries()[1].detail == {"x": 1}
    assert log.verify() is True


def test_audit_triggers_block_update_and_delete(tmp_path):
    conn = get_connection(str(tmp_path / "a.db"))
    SqliteAuditLog(conn).append("a")
    with pytest.raises(sqlite3.DatabaseError):
        conn.execute("UPDATE audit_log SET action='x' WHERE seq=1")
        conn.commit()
    with pytest.raises(sqlite3.DatabaseError):
        conn.execute("DELETE FROM audit_log WHERE seq=1")
        conn.commit()


def test_audit_detects_tampering_memory():
    log = InMemoryAuditLog()
    log.append("a")
    log.append("b")
    # manipular la primera entrada rompe la cadena
    log._entries[0] = dataclasses.replace(log._entries[0], action="HACKED")
    with pytest.raises(AuditTamperError):
        log.verify()


def test_audit_detects_tampering_sqlite(tmp_path):
    conn = get_connection(str(tmp_path / "a.db"))
    log = SqliteAuditLog(conn)
    log.append("a")
    log.append("b")
    # quitar los triggers para poder simular una manipulación directa
    conn.executescript(
        "DROP TRIGGER audit_no_update; DROP TRIGGER audit_no_delete;"
    )
    conn.execute("UPDATE audit_log SET action='HACKED' WHERE seq=1")
    conn.commit()
    with pytest.raises(AuditTamperError):
        log.verify()
