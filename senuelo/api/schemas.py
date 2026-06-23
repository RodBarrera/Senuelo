"""Esquemas (DTOs) de la API.

Separan el contrato HTTP de los modelos de dominio. En particular, al crear una
autorización el cliente NO envía ni la firma ni el id: el servidor los genera y
firma con su propia clave.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from ..scope import Party
from ..scoring import PremiseAlignment, PremiseElement


# --- Autorizaciones -----------------------------------------------------

class AuthorizationCreate(BaseModel):
    """Cuerpo para crear una autorización. El servidor la firma."""

    organization: str
    authorized_by: Party
    requested_by: Party
    scope_domains: list[str] = Field(min_length=1)
    include_subdomains: bool = False
    excluded_addresses: list[str] = Field(default_factory=list)
    window_start: datetime
    window_end: datetime
    data_retention_days: int = Field(ge=1, le=3650)
    consent_reference: str


class AuthorizationResponse(BaseModel):
    """Vista pública de una autorización (incluye firma y estado calculado)."""

    authorization_id: str
    organization: str
    scope_domains: list[str]
    include_subdomains: bool
    excluded_addresses: list[str]
    window_start: datetime
    window_end: datetime
    data_retention_days: int
    consent_reference: str
    signed_at: datetime | None
    revoked_at: datetime | None
    signature: str | None
    status: str


class RecipientCheckRequest(BaseModel):
    recipients: list[str] = Field(min_length=1)


class RejectionItem(BaseModel):
    email: str
    code: str
    reason: str


class RecipientCheckResponse(BaseModel):
    admitted: list[str]
    rejected: list[RejectionItem]
    admitted_count: int
    rejected_count: int
    total: int


# --- Scoring ------------------------------------------------------------

class CueInfo(BaseModel):
    id: str
    category: str
    name: str
    criterion: str


class ScoringResultResponse(BaseModel):
    cue_total: int
    cue_count: str
    premise_score: int | None
    premise_alignment: str
    detection_difficulty: str
    detection_difficulty_label: str
    expected_click_rate: tuple[float, float]
    normalized_difficulty: float


class ContextualizeRequest(BaseModel):
    """Evaluación de plantilla más el click rate observado a interpretar."""

    target_audience: str
    cues: dict[str, int] = Field(default_factory=dict)
    premise_alignment: PremiseAlignment | None = None
    premise_elements: dict[PremiseElement, int] | None = None
    observed_click_rate: float = Field(ge=0.0, le=100.0)


class ContextualizeResponse(BaseModel):
    result: ScoringResultResponse
    observed: float
    expected: tuple[float, float]
    verdict: str
    message: str


# --- Auditoría ----------------------------------------------------------

class AuditEntryResponse(BaseModel):
    seq: int
    ts: str
    action: str
    authorization_id: str | None
    detail: dict | None
    prev_hash: str
    entry_hash: str


class AuditVerifyResponse(BaseModel):
    valid: bool
    entries: int
    message: str
