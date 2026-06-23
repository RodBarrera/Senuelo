"""Tests del dominio de campañas."""

from __future__ import annotations

import pytest

from senuelo.campaigns import (
    Campaign,
    CampaignStatus,
    EventType,
    InvalidTransitionError,
    simulate,
)
from senuelo.scoring import PhishScaleAssessment, PremiseAlignment


def make_assessment(premise=PremiseAlignment.HIGH):
    return PhishScaleAssessment.from_cue_list(
        ["mimics_business_process", "url_hyperlinking"],
        target_audience="Finanzas",
        premise_alignment=premise,
    )


def make_campaign(recipients=None):
    return Campaign(
        name="Campaña demo",
        authorization_id="auth-1",
        assessment=make_assessment(),
        recipients=recipients or ["a@empresa.cl", "b@empresa.cl"],
    )


def test_starts_in_draft():
    assert make_campaign().status is CampaignStatus.DRAFT


def test_happy_path_transitions():
    c = make_campaign()
    c.schedule()
    assert c.status is CampaignStatus.SCHEDULED
    c.mark_running(["a@empresa.cl"], [], [])
    assert c.status is CampaignStatus.RUNNING
    assert c.admitted == ["a@empresa.cl"]
    c.complete()
    assert c.status is CampaignStatus.COMPLETED


def test_cannot_complete_from_draft():
    with pytest.raises(InvalidTransitionError):
        make_campaign().complete()


def test_cannot_launch_without_scheduling():
    with pytest.raises(InvalidTransitionError):
        make_campaign().mark_running([], [], [])


def test_cancel_from_draft_and_scheduled():
    c = make_campaign()
    c.cancel()
    assert c.status is CampaignStatus.CANCELLED

    c2 = make_campaign()
    c2.schedule()
    c2.cancel()
    assert c2.status is CampaignStatus.CANCELLED


def test_cannot_cancel_running():
    c = make_campaign()
    c.schedule()
    c.mark_running([], [], [])
    with pytest.raises(InvalidTransitionError):
        c.cancel()


def test_simulation_is_deterministic():
    adm = [f"u{i}@empresa.cl" for i in range(50)]
    result = make_assessment().result()
    a = simulate(adm, result, seed=7)
    b = simulate(adm, result, seed=7)
    assert [(e.recipient, e.event_type) for e in a] == \
           [(e.recipient, e.event_type) for e in b]


def test_funnel_structure():
    adm = [f"u{i}@empresa.cl" for i in range(200)]
    result = make_assessment().result()
    events = simulate(adm, result, seed=1)

    by_recipient: dict[str, set] = {}
    for e in events:
        by_recipient.setdefault(e.recipient, set()).add(e.event_type)

    # cada destinatario tiene exactamente un SENT
    assert all(EventType.SENT in s for s in by_recipient.values())
    for s in by_recipient.values():
        if EventType.CLICKED in s:
            assert EventType.OPENED in s          # clic implica apertura
        if EventType.SUBMITTED in s:
            assert EventType.CLICKED in s          # envío implica clic
        if EventType.REPORTED in s:
            assert EventType.OPENED in s           # reporte implica apertura
            assert EventType.CLICKED not in s      # reportar y clickear son excluyentes


def test_metrics_from_events():
    adm = [f"u{i}@empresa.cl" for i in range(100)]
    result = make_assessment().result()
    events = simulate(adm, result, seed=3)
    c = make_campaign()
    c.schedule()
    c.mark_running(adm, [], events)
    m = c.metrics()
    assert m.sent == 100
    assert 0.0 <= m.report_rate <= 100.0
    assert m.clicked >= m.submitted  # el embudo no se ensancha hacia abajo
