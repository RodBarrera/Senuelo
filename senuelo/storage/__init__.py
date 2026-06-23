"""Persistencia de Señuelo (SQLite): repositorio de autorizaciones y audit log."""

from .audit import (
    AuditEntry,
    AuditTamperError,
    InMemoryAuditLog,
    SqliteAuditLog,
)
from .db import get_connection, init_schema, reset_connections
from .repository import SqliteAuthorizationRepository

__all__ = [
    "get_connection",
    "init_schema",
    "reset_connections",
    "SqliteAuthorizationRepository",
    "AuditEntry",
    "AuditTamperError",
    "InMemoryAuditLog",
    "SqliteAuditLog",
]
