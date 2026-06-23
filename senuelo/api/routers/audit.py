"""Endpoints de auditoría: exponen la bitácora inmutable."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from ...storage import AuditTamperError
from ..deps import require_api_key
from ..repository import get_audit_log
from ..schemas import AuditEntryResponse, AuditVerifyResponse

router = APIRouter(
    prefix="/audit",
    tags=["auditoría"],
    dependencies=[Depends(require_api_key)],
)


@router.get("", response_model=list[AuditEntryResponse])
def list_audit(audit=Depends(get_audit_log)) -> list[AuditEntryResponse]:
    """Lista las entradas de la bitácora, en orden cronológico."""
    return [
        AuditEntryResponse(
            seq=e.seq, ts=e.ts, action=e.action,
            authorization_id=e.authorization_id, detail=e.detail,
            prev_hash=e.prev_hash, entry_hash=e.entry_hash,
        )
        for e in audit.entries()
    ]


@router.get("/verify", response_model=AuditVerifyResponse)
def verify_audit(audit=Depends(get_audit_log)) -> AuditVerifyResponse:
    """Verifica la integridad de la cadena de hashes de la bitácora."""
    count = len(audit.entries())
    try:
        audit.verify()
    except AuditTamperError as exc:
        return AuditVerifyResponse(valid=False, entries=count, message=str(exc))
    return AuditVerifyResponse(
        valid=True, entries=count,
        message="la cadena de auditoría es íntegra",
    )
