"""Módulo de campañas de Señuelo.

Une autorización (scope), plantilla evaluada (scoring), destinatarios validados
y eventos de tracking simulados en un solo objeto de negocio con ciclo de vida.
"""

from .models import (
    Campaign,
    CampaignMetrics,
    CampaignStatus,
    EventType,
    InvalidTransitionError,
    RejectionRecord,
    TrackingEvent,
)
from .simulation import DEFAULT_PARAMS, SimulationParams, simulate

__all__ = [
    "Campaign",
    "CampaignStatus",
    "CampaignMetrics",
    "EventType",
    "TrackingEvent",
    "RejectionRecord",
    "InvalidTransitionError",
    "simulate",
    "SimulationParams",
    "DEFAULT_PARAMS",
]
