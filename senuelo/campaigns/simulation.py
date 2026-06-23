"""Simulación de envío en modo dry-run.

No se manda ningún correo: se *modela* el comportamiento de los destinatarios a
partir de la dificultad de la plantilla (NIST Phish Scale) y se generan los
eventos de tracking del embudo. Es reproducible vía ``seed``.

Las probabilidades base están ancladas en las bandas de click rate del paper de
NIST, pero son **supuestos de modelado**, no verdades de campo; por eso viven en
``SimulationParams`` y se pueden ajustar. El embudo por destinatario:

    SENT ─▶ (abre?) OPENED ─┬─▶ (clic?) CLICKED ─▶ (envía datos?) SUBMITTED
                            └─▶ (resiste y avisa?) REPORTED
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from ..scoring import DetectionDifficulty, PhishScaleResult
from .models import EventType, TrackingEvent


def _default_base_rates() -> dict[DetectionDifficulty, float]:
    # Click rate representativo por dificultad, dentro/junto a las bandas NIST.
    return {
        DetectionDifficulty.LEAST: 0.05,
        DetectionDifficulty.MODERATELY_TO_LEAST: 0.12,
        DetectionDifficulty.MODERATELY: 0.15,
        DetectionDifficulty.VERY: 0.25,
    }


@dataclass(frozen=True)
class SimulationParams:
    base_click_rate: dict[DetectionDifficulty, float] = field(
        default_factory=_default_base_rates
    )
    open_to_click_ratio: float = 2.5      # se abre ~2.5x más de lo que se clickea
    submit_given_click: float = 0.5       # de quienes clickean, mitad envía datos
    report_given_open_no_click: float = 0.25  # de quienes resisten, una parte avisa


DEFAULT_PARAMS = SimulationParams()


def simulate(
    admitted: list[str],
    result: PhishScaleResult,
    params: SimulationParams = DEFAULT_PARAMS,
    seed: int | None = None,
) -> list[TrackingEvent]:
    """Genera los eventos de tracking simulados para los destinatarios admitidos."""
    rng = random.Random(seed)
    base = params.base_click_rate[result.detection_difficulty]
    p_open = min(1.0, base * params.open_to_click_ratio)
    p_click_given_open = min(1.0, base / p_open) if p_open > 0 else 0.0

    now = datetime.now(timezone.utc)
    events: list[TrackingEvent] = []

    def add(recipient: str, etype: EventType, step: int) -> None:
        events.append(TrackingEvent(
            recipient=recipient,
            event_type=etype,
            at=now + timedelta(seconds=step),
        ))

    for recipient in admitted:
        add(recipient, EventType.SENT, 0)
        if rng.random() < p_open:
            add(recipient, EventType.OPENED, 1)
            if rng.random() < p_click_given_open:
                add(recipient, EventType.CLICKED, 2)
                if rng.random() < params.submit_given_click:
                    add(recipient, EventType.SUBMITTED, 3)
            elif rng.random() < params.report_given_open_no_click:
                add(recipient, EventType.REPORTED, 2)
    return events
