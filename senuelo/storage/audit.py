"""Bitácora de auditoría inmutable y encadenada por hash.

Cada entrada incluye el hash de la anterior, formando una cadena: alterar una
entrada pasada rompe todos los hashes siguientes y la verificación lo detecta.
Es el mismo principio antimanipulación que la firma del motor de scope, aplicado
a la traza completa de acciones.

Dos backends comparten la lógica de encadenado: uno en memoria (modo dev/tests)
y uno sobre SQLite (durable). En SQLite, además, dos triggers impiden ``UPDATE``
y ``DELETE`` (ver ``db.py``).
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone

GENESIS_HASH = "0" * 64


class AuditTamperError(Exception):
    """La cadena de auditoría no valida: hubo manipulación."""


@dataclass(frozen=True)
class AuditEntry:
    seq: int
    ts: str
    action: str
    authorization_id: str | None
    detail: dict | None
    prev_hash: str
    entry_hash: str


def compute_entry_hash(
    prev_hash: str,
    ts: str,
    action: str,
    authorization_id: str | None,
    detail: dict | None,
) -> str:
    """Hash determinista de una entrada, encadenado al ``prev_hash``."""
    payload = json.dumps(
        {
            "prev": prev_hash,
            "ts": ts,
            "action": action,
            "authorization_id": authorization_id,
            "detail": detail,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class InMemoryAuditLog:
    """Bitácora encadenada en memoria (modo dev / tests)."""

    def __init__(self) -> None:
        self._entries: list[AuditEntry] = []

    def append(
        self,
        action: str,
        authorization_id: str | None = None,
        detail: dict | None = None,
    ) -> AuditEntry:
        prev = self._entries[-1].entry_hash if self._entries else GENESIS_HASH
        ts = _now()
        h = compute_entry_hash(prev, ts, action, authorization_id, detail)
        entry = AuditEntry(
            seq=len(self._entries) + 1, ts=ts, action=action,
            authorization_id=authorization_id, detail=detail,
            prev_hash=prev, entry_hash=h,
        )
        self._entries.append(entry)
        return entry

    def entries(self) -> list[AuditEntry]:
        return list(self._entries)

    def verify(self) -> bool:
        prev = GENESIS_HASH
        for e in self._entries:
            if e.prev_hash != prev:
                raise AuditTamperError(
                    f"entrada {e.seq}: el enlace al hash anterior no coincide"
                )
            expected = compute_entry_hash(
                prev, e.ts, e.action, e.authorization_id, e.detail
            )
            if expected != e.entry_hash:
                raise AuditTamperError(
                    f"entrada {e.seq}: el hash no coincide (fue alterada)"
                )
            prev = e.entry_hash
        return True


class SqliteAuditLog:
    """Bitácora encadenada persistida en SQLite."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    def append(
        self,
        action: str,
        authorization_id: str | None = None,
        detail: dict | None = None,
    ) -> AuditEntry:
        row = self._conn.execute(
            "SELECT entry_hash FROM audit_log ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        prev = row["entry_hash"] if row else GENESIS_HASH
        ts = _now()
        h = compute_entry_hash(prev, ts, action, authorization_id, detail)
        detail_json = json.dumps(detail) if detail is not None else None
        cur = self._conn.execute(
            "INSERT INTO audit_log "
            "(ts, action, authorization_id, detail, prev_hash, entry_hash) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (ts, action, authorization_id, detail_json, prev, h),
        )
        self._conn.commit()
        return AuditEntry(
            seq=cur.lastrowid, ts=ts, action=action,
            authorization_id=authorization_id, detail=detail,
            prev_hash=prev, entry_hash=h,
        )

    def entries(self) -> list[AuditEntry]:
        rows = self._conn.execute(
            "SELECT * FROM audit_log ORDER BY seq ASC"
        ).fetchall()
        return [
            AuditEntry(
                seq=r["seq"], ts=r["ts"], action=r["action"],
                authorization_id=r["authorization_id"],
                detail=json.loads(r["detail"]) if r["detail"] else None,
                prev_hash=r["prev_hash"], entry_hash=r["entry_hash"],
            )
            for r in rows
        ]

    def verify(self) -> bool:
        prev = GENESIS_HASH
        for e in self.entries():
            if e.prev_hash != prev:
                raise AuditTamperError(
                    f"entrada {e.seq}: el enlace al hash anterior no coincide"
                )
            expected = compute_entry_hash(
                prev, e.ts, e.action, e.authorization_id, e.detail
            )
            if expected != e.entry_hash:
                raise AuditTamperError(
                    f"entrada {e.seq}: el hash no coincide (fue alterada)"
                )
            prev = e.entry_hash
        return True
