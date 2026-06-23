"""Modelo de campaña de Señuelo.

Una campaña une los cuatro módulos previos: referencia una **autorización**
(scope), embebe una **evaluación de plantilla** (scoring), lleva una **lista de
destinatarios** que se valida contra el alcance al lanzar, y produce **eventos
de tracking** en modo simulación.

Ciclo de vida (máquina de estados estricta):

    draft ──schedule──▶ scheduled ──launch──▶ running ──complete──▶ completed
      │                     │
      └─────────cancel──────┴──▶ cancelled

Decisión ética que se hereda del resto del proyecto: el evento ``SUBMITTED``
registra que la persona *envió datos*, nunca qué datos. No se captura ninguna
credencial.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, Field

from ..scoring import PhishScaleAssessment


class CampaignStatus(str, Enum):
    DRAFT = "draft"
    SCHEDULED = "scheduled"
    RUNNING = "running"
    COMPLETED = "completed"
    CANCELLED = "cancelled"


class EventType(str, Enum):
    """Embudo de tracking. ``SUBMITTED`` = envió datos; nunca el contenido."""

    SENT = "sent"
    OPENED = "opened"
    CLICKED = "clicked"
    SUBMITTED = "submitted"
    REPORTED = "reported"  # el resultado resiliente: detectó y avisó


class InvalidTransitionError(Exception):
    """Transición de estado no permitida por la máquina de estados."""


# Transiciones permitidas: estado actual -> estados destino válidos.
_ALLOWED: dict[CampaignStatus, set[CampaignStatus]] = {
    CampaignStatus.DRAFT: {CampaignStatus.SCHEDULED, CampaignStatus.CANCELLED},
    CampaignStatus.SCHEDULED: {CampaignStatus.RUNNING, CampaignStatus.CANCELLED},
    CampaignStatus.RUNNING: {CampaignStatus.COMPLETED},
    CampaignStatus.COMPLETED: set(),
    CampaignStatus.CANCELLED: set(),
}


class TrackingEvent(BaseModel):
    recipient: str
    event_type: EventType
    at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class RejectionRecord(BaseModel):
    email: str
    code: str
    reason: str


class CampaignMetrics(BaseModel):
    """Embudo de la campaña. Las tasas son porcentaje sobre los envíos."""

    sent: int
    opened: int
    clicked: int
    submitted: int
    reported: int
    open_rate: float
    click_rate: float
    submit_rate: float
    report_rate: float  # KPI primario: resiliencia, no susceptibilidad


def _rate(part: int, whole: int) -> float:
    return round(100.0 * part / whole, 1) if whole else 0.0


class Campaign(BaseModel):
    campaign_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = Field(min_length=1, max_length=200)
    authorization_id: str
    assessment: PhishScaleAssessment
    recipients: list[str] = Field(min_length=1)

    status: CampaignStatus = CampaignStatus.DRAFT
    admitted: list[str] = Field(default_factory=list)
    rejected: list[RejectionRecord] = Field(default_factory=list)
    events: list[TrackingEvent] = Field(default_factory=list)

    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    scheduled_at: datetime | None = None
    launched_at: datetime | None = None
    completed_at: datetime | None = None
    cancelled_at: datetime | None = None

    # --- máquina de estados ---------------------------------------------

    def _transition(self, target: CampaignStatus) -> None:
        if target not in _ALLOWED[self.status]:
            raise InvalidTransitionError(
                f"no se puede pasar de '{self.status.value}' a '{target.value}'"
            )
        self.status = target

    def schedule(self) -> None:
        self._transition(CampaignStatus.SCHEDULED)
        self.scheduled_at = datetime.now(timezone.utc)

    def mark_running(
        self,
        admitted: list[str],
        rejected: list[RejectionRecord],
        events: list[TrackingEvent],
    ) -> None:
        """Lanza la campaña con los destinatarios ya validados y sus eventos."""
        self._transition(CampaignStatus.RUNNING)
        self.admitted = admitted
        self.rejected = rejected
        self.events = events
        self.launched_at = datetime.now(timezone.utc)

    def complete(self) -> None:
        self._transition(CampaignStatus.COMPLETED)
        self.completed_at = datetime.now(timezone.utc)

    def cancel(self) -> None:
        self._transition(CampaignStatus.CANCELLED)
        self.cancelled_at = datetime.now(timezone.utc)

    # --- métricas --------------------------------------------------------

    def metrics(self) -> CampaignMetrics:
        counts = {t: 0 for t in EventType}
        for ev in self.events:
            counts[ev.event_type] += 1
        sent = counts[EventType.SENT]
        return CampaignMetrics(
            sent=sent,
            opened=counts[EventType.OPENED],
            clicked=counts[EventType.CLICKED],
            submitted=counts[EventType.SUBMITTED],
            reported=counts[EventType.REPORTED],
            open_rate=_rate(counts[EventType.OPENED], sent),
            click_rate=_rate(counts[EventType.CLICKED], sent),
            submit_rate=_rate(counts[EventType.SUBMITTED], sent),
            report_rate=_rate(counts[EventType.REPORTED], sent),
        )
