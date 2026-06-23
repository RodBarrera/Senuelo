"""Repositorio de autorizaciones sobre SQLite.

Implementa la misma interfaz estructural que el repositorio en memoria
(``add`` / ``get`` / ``list``), de modo que la API no distingue cuál usa.
Cada autorización se guarda como su JSON (que ya incluye la firma).
"""

from __future__ import annotations

import sqlite3

from ..scope import Authorization
from .db import get_connection


class SqliteAuthorizationRepository:
    """Persistencia de autorizaciones en SQLite."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    @classmethod
    def from_path(cls, path: str) -> "SqliteAuthorizationRepository":
        return cls(get_connection(path))

    def add(self, authorization: Authorization) -> None:
        from datetime import datetime, timezone

        self._conn.execute(
            "INSERT INTO authorizations (authorization_id, payload, updated_at) "
            "VALUES (?, ?, ?) "
            "ON CONFLICT(authorization_id) DO UPDATE SET "
            "payload = excluded.payload, updated_at = excluded.updated_at",
            (
                authorization.authorization_id,
                authorization.model_dump_json(),
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        self._conn.commit()

    def get(self, authorization_id: str) -> Authorization | None:
        row = self._conn.execute(
            "SELECT payload FROM authorizations WHERE authorization_id = ?",
            (authorization_id,),
        ).fetchone()
        if row is None:
            return None
        return Authorization.model_validate_json(row["payload"])

    def list(self) -> list[Authorization]:
        rows = self._conn.execute(
            "SELECT payload FROM authorizations ORDER BY updated_at DESC"
        ).fetchall()
        return [Authorization.model_validate_json(r["payload"]) for r in rows]
