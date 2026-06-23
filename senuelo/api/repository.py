"""Persistencia de autorizaciones.

Se define una interfaz (``AuthorizationRepository``) y una implementación en
memoria. Cuando llegue la base de datos (SQLite/Postgres), solo se agrega otra
implementación de la misma interfaz; el resto de la API no cambia.
"""

from __future__ import annotations

from typing import Protocol

from ..scope import Authorization


class AuthorizationRepository(Protocol):
    """Contrato de almacenamiento de autorizaciones."""

    def add(self, authorization: Authorization) -> None: ...
    def get(self, authorization_id: str) -> Authorization | None: ...
    def list(self) -> list[Authorization]: ...


class InMemoryAuthorizationRepository:
    """Implementación en memoria. Útil para desarrollo, demo y tests."""

    def __init__(self) -> None:
        self._store: dict[str, Authorization] = {}

    def add(self, authorization: Authorization) -> None:
        self._store[authorization.authorization_id] = authorization

    def get(self, authorization_id: str) -> Authorization | None:
        return self._store.get(authorization_id)

    def list(self) -> list[Authorization]:
        return list(self._store.values())


# Singletons en memoria (modo dev / tests).
_memory_repository: AuthorizationRepository = InMemoryAuthorizationRepository()
_memory_audit = None  # type: ignore[var-annotated]


def get_repository() -> AuthorizationRepository:
    """Repositorio activo: SQLite si hay SENUELO_DB_PATH, si no en memoria."""
    from .config import get_settings

    settings = get_settings()
    if settings.persistence_enabled:
        from ..storage import SqliteAuthorizationRepository, get_connection

        return SqliteAuthorizationRepository(get_connection(settings.db_path))  # type: ignore[arg-type]
    return _memory_repository


def get_audit_log():
    """Audit log activo: SQLite si hay SENUELO_DB_PATH, si no en memoria."""
    global _memory_audit
    from .config import get_settings

    settings = get_settings()
    if settings.persistence_enabled:
        from ..storage import SqliteAuditLog, get_connection

        return SqliteAuditLog(get_connection(settings.db_path))  # type: ignore[arg-type]
    if _memory_audit is None:
        from ..storage import InMemoryAuditLog

        _memory_audit = InMemoryAuditLog()
    return _memory_audit
