"""Endpoints de campañas: el flujo que une scope, scoring, simulación y audit."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from ...campaigns import (
    Campaign,
    CampaignMetrics,
    InvalidTransitionError,
    RejectionRecord,
    TrackingEvent,
    simulate,
)
from ...scope import ScopeEngine, ScopeError
from ...scoring import PhishScaleAssessment
from ..campaign_repository import CampaignRepository, get_campaign_repository
from ..config import get_settings
from ..deps import require_api_key
from ..repository import AuthorizationRepository, get_audit_log, get_repository

router = APIRouter(
    prefix="/campaigns",
    tags=["campañas"],
    dependencies=[Depends(require_api_key)],
)


class CampaignCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    authorization_id: str
    assessment: PhishScaleAssessment
    recipients: list[str] = Field(min_length=1)


class CampaignLaunchRequest(BaseModel):
    seed: int | None = None  # fija la simulación para demos reproducibles


def _signing_key() -> str:
    settings = get_settings()
    if not settings.signing_enabled:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="el servidor no tiene SENUELO_SIGNING_KEY configurada",
        )
    return settings.signing_key  # type: ignore[return-value]


def _get_or_404(campaign_id: str, repo: CampaignRepository) -> Campaign:
    campaign = repo.get(campaign_id)
    if campaign is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="campaña no encontrada"
        )
    return campaign


def _transition(campaign, action, repo, audit, event_name):
    """Aplica una transición pura, persiste y audita; 409 si es inválida."""
    try:
        action()
    except InvalidTransitionError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail=str(exc)
        ) from exc
    repo.add(campaign)
    audit.append(event_name, detail={"campaign_id": campaign.campaign_id})
    return campaign


@router.post("", response_model=Campaign, status_code=status.HTTP_201_CREATED)
def create_campaign(
    body: CampaignCreate,
    repo: CampaignRepository = Depends(get_campaign_repository),
    auth_repo: AuthorizationRepository = Depends(get_repository),
    audit=Depends(get_audit_log),
) -> Campaign:
    """Crea una campaña en estado borrador. La autorización referida debe existir."""
    if auth_repo.get(body.authorization_id) is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="la autorización referida no existe",
        )
    campaign = Campaign(
        name=body.name,
        authorization_id=body.authorization_id,
        assessment=body.assessment,
        recipients=body.recipients,
    )
    repo.add(campaign)
    audit.append("campaign.created",
                 authorization_id=body.authorization_id,
                 detail={"campaign_id": campaign.campaign_id, "name": body.name})
    return campaign


@router.get("", response_model=list[Campaign])
def list_campaigns(
    repo: CampaignRepository = Depends(get_campaign_repository),
) -> list[Campaign]:
    return repo.list()


@router.get("/{campaign_id}", response_model=Campaign)
def get_campaign(
    campaign_id: str,
    repo: CampaignRepository = Depends(get_campaign_repository),
) -> Campaign:
    return _get_or_404(campaign_id, repo)


@router.post("/{campaign_id}/schedule", response_model=Campaign)
def schedule_campaign(
    campaign_id: str,
    repo: CampaignRepository = Depends(get_campaign_repository),
    audit=Depends(get_audit_log),
) -> Campaign:
    c = _get_or_404(campaign_id, repo)
    return _transition(c, c.schedule, repo, audit, "campaign.scheduled")


@router.post("/{campaign_id}/launch", response_model=Campaign)
def launch_campaign(
    campaign_id: str,
    body: CampaignLaunchRequest | None = None,
    repo: CampaignRepository = Depends(get_campaign_repository),
    auth_repo: AuthorizationRepository = Depends(get_repository),
    audit=Depends(get_audit_log),
) -> Campaign:
    """Lanza la campaña en modo simulación: valida alcance y genera tracking."""
    campaign = _get_or_404(campaign_id, repo)
    key = _signing_key()

    auth = auth_repo.get(campaign.authorization_id)
    if auth is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="la autorización de la campaña ya no existe",
        )

    engine = ScopeEngine(auth, key)
    try:
        report = engine.filter_recipients(campaign.recipients)
    except ScopeError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": exc.code, "reason": exc.reason},
        ) from exc

    result = campaign.assessment.result()
    seed = body.seed if body else None
    events = simulate(report.admitted, result, seed=seed)
    rejected = [
        RejectionRecord(email=r.email, code=r.code, reason=r.reason)
        for r in report.rejected
    ]

    try:
        campaign.mark_running(report.admitted, rejected, events)
    except InvalidTransitionError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail=str(exc)
        ) from exc

    repo.add(campaign)
    audit.append(
        "campaign.launched",
        authorization_id=campaign.authorization_id,
        detail={
            "campaign_id": campaign.campaign_id,
            "admitted": len(report.admitted),
            "rejected": len(report.rejected),
            "difficulty": result.detection_difficulty.value,
        },
    )
    return campaign


@router.post("/{campaign_id}/complete", response_model=Campaign)
def complete_campaign(
    campaign_id: str,
    repo: CampaignRepository = Depends(get_campaign_repository),
    audit=Depends(get_audit_log),
) -> Campaign:
    c = _get_or_404(campaign_id, repo)
    return _transition(c, c.complete, repo, audit, "campaign.completed")


@router.post("/{campaign_id}/cancel", response_model=Campaign)
def cancel_campaign(
    campaign_id: str,
    repo: CampaignRepository = Depends(get_campaign_repository),
    audit=Depends(get_audit_log),
) -> Campaign:
    c = _get_or_404(campaign_id, repo)
    return _transition(c, c.cancel, repo, audit, "campaign.cancelled")


@router.get("/{campaign_id}/events", response_model=list[TrackingEvent])
def campaign_events(
    campaign_id: str,
    repo: CampaignRepository = Depends(get_campaign_repository),
) -> list[TrackingEvent]:
    return _get_or_404(campaign_id, repo).events


@router.get("/{campaign_id}/metrics", response_model=CampaignMetrics)
def campaign_metrics(
    campaign_id: str,
    repo: CampaignRepository = Depends(get_campaign_repository),
) -> CampaignMetrics:
    """Embudo de la campaña, con la tasa de reporte como KPI primario."""
    return _get_or_404(campaign_id, repo).metrics()
