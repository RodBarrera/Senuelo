"""Endpoints de autorizaciones: envuelven el motor de scope."""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status

from ...scope import (
    Authorization,
    ScopeEngine,
    ScopeError,
    sign,
)
from ..config import get_settings
from ..deps import require_api_key
from ..repository import AuthorizationRepository, get_audit_log, get_repository
from ..schemas import (
    AuthorizationCreate,
    AuthorizationResponse,
    RecipientCheckRequest,
    RecipientCheckResponse,
    RejectionItem,
)

router = APIRouter(
    prefix="/authorizations",
    tags=["autorizaciones"],
    dependencies=[Depends(require_api_key)],
)


def _to_response(auth: Authorization) -> AuthorizationResponse:
    return AuthorizationResponse(
        authorization_id=auth.authorization_id,
        organization=auth.organization,
        scope_domains=auth.scope_domains,
        include_subdomains=auth.include_subdomains,
        excluded_addresses=auth.excluded_addresses,
        window_start=auth.window_start,
        window_end=auth.window_end,
        data_retention_days=auth.data_retention_days,
        consent_reference=auth.consent_reference,
        signed_at=auth.signed_at,
        revoked_at=auth.revoked_at,
        signature=auth.signature,
        status=auth.status().value,
    )


def _signing_key() -> str:
    settings = get_settings()
    if not settings.signing_enabled:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="el servidor no tiene SENUELO_SIGNING_KEY configurada",
        )
    return settings.signing_key  # type: ignore[return-value]


def _get_or_404(
    authorization_id: str, repo: AuthorizationRepository
) -> Authorization:
    auth = repo.get(authorization_id)
    if auth is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="autorización no encontrada",
        )
    return auth


@router.post("", response_model=AuthorizationResponse,
             status_code=status.HTTP_201_CREATED)
def create_authorization(
    body: AuthorizationCreate,
    repo: AuthorizationRepository = Depends(get_repository),
    audit=Depends(get_audit_log),
) -> AuthorizationResponse:
    """Crea una autorización y la firma con la clave del servidor."""
    key = _signing_key()
    try:
        auth = Authorization(**body.model_dump())
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc
    sign(auth, key)
    repo.add(auth)
    audit.append(
        "authorization.created",
        authorization_id=auth.authorization_id,
        detail={
            "organization": auth.organization,
            "scope_domains": auth.scope_domains,
            "requested_by": auth.requested_by.email,
        },
    )
    return _to_response(auth)


@router.get("/{authorization_id}", response_model=AuthorizationResponse)
def get_authorization(
    authorization_id: str,
    repo: AuthorizationRepository = Depends(get_repository),
) -> AuthorizationResponse:
    return _to_response(_get_or_404(authorization_id, repo))


@router.post("/{authorization_id}/revoke", response_model=AuthorizationResponse)
def revoke_authorization(
    authorization_id: str,
    repo: AuthorizationRepository = Depends(get_repository),
    audit=Depends(get_audit_log),
) -> AuthorizationResponse:
    """Revoca una autorización; vuelve a firmar para sellar el cambio."""
    key = _signing_key()
    auth = _get_or_404(authorization_id, repo)
    auth.revoked_at = datetime.now(timezone.utc)
    sign(auth, key)
    repo.add(auth)
    audit.append("authorization.revoked", authorization_id=auth.authorization_id)
    return _to_response(auth)


@router.post("/{authorization_id}/recipient-check",
             response_model=RecipientCheckResponse)
def check_recipients(
    authorization_id: str,
    body: RecipientCheckRequest,
    repo: AuthorizationRepository = Depends(get_repository),
    audit=Depends(get_audit_log),
) -> RecipientCheckResponse:
    """Valida una lista de destinatarios contra el alcance de la autorización."""
    key = _signing_key()
    auth = _get_or_404(authorization_id, repo)
    engine = ScopeEngine(auth, key)
    try:
        report = engine.filter_recipients(body.recipients)
    except ScopeError as exc:
        # La autorización no es válida (firma/vigencia/revocación): falla la
        # campaña entera, no un destinatario.
        audit.append(
            "recipients.check_denied",
            authorization_id=authorization_id,
            detail={"code": exc.code, "reason": exc.reason},
        )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": exc.code, "reason": exc.reason},
        ) from exc
    audit.append(
        "recipients.checked",
        authorization_id=authorization_id,
        detail={
            "total": report.total,
            "admitted": report.admitted_count,
            "rejected": report.rejected_count,
        },
    )
    return RecipientCheckResponse(
        admitted=report.admitted,
        rejected=[
            RejectionItem(email=r.email, code=r.code, reason=r.reason)
            for r in report.rejected
        ],
        admitted_count=report.admitted_count,
        rejected_count=report.rejected_count,
        total=report.total,
    )
