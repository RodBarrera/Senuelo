"""Conexión y esquema SQLite de Señuelo.

Define el esquema de ``authorizations`` y ``audit_log``, más dos triggers que
hacen el audit log *solo-append*: cualquier ``UPDATE`` o ``DELETE`` sobre él
aborta a nivel de motor. Sumado a la cadena de hashes de ``audit.py``, la
inmutabilidad queda defendida en dos capas: la base la impide, y si alguien
edita el archivo por fuera, la cadena lo delata.

Las conexiones se cachean por ruta (una por archivo), con
``check_same_thread=False`` para el servidor con hilos. ``reset_connections``
las cierra y limpia (útil en tests).
"""

from __future__ import annotations

import sqlite3
import threading

_SCHEMA = """
CREATE TABLE IF NOT EXISTS authorizations (
    authorization_id TEXT PRIMARY KEY,
    payload          TEXT NOT NULL,
    updated_at       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
    seq              INTEGER PRIMARY KEY AUTOINCREMENT,
    ts               TEXT NOT NULL,
    action           TEXT NOT NULL,
    authorization_id TEXT,
    detail           TEXT,
    prev_hash        TEXT NOT NULL,
    entry_hash       TEXT NOT NULL
);

CREATE TRIGGER IF NOT EXISTS audit_no_update
BEFORE UPDATE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log es inmutable: UPDATE no permitido');
END;

CREATE TRIGGER IF NOT EXISTS audit_no_delete
BEFORE DELETE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log es inmutable: DELETE no permitido');
END;
"""

_connections: dict[str, sqlite3.Connection] = {}
_lock = threading.Lock()


def init_schema(conn: sqlite3.Connection) -> None:
    """Crea tablas y triggers si no existen."""
    conn.executescript(_SCHEMA)
    conn.commit()


def get_connection(path: str) -> sqlite3.Connection:
    """Devuelve (cacheada por ruta) una conexión lista, con esquema aplicado."""
    with _lock:
        conn = _connections.get(path)
        if conn is None:
            conn = sqlite3.connect(path, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            init_schema(conn)
            _connections[path] = conn
        return conn


def reset_connections() -> None:
    """Cierra y olvida todas las conexiones cacheadas."""
    with _lock:
        for conn in _connections.values():
            conn.close()
        _connections.clear()
