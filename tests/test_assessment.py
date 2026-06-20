"""Tests de la evaluación de plantillas y la contextualización de métricas."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from senuelo.scoring import (
    ClickRateVerdict,
    DetectionDifficulty,
    PhishScaleAssessment,
    PremiseAlignment,
    PremiseElement,
    contextualize_click_rate,
)


def test_method1_few_cues_high_premise_is_very_difficult():
    # Caso E4 del paper ("archivo escaneado"): pocas señales + premisa alta.
    a = PhishScaleAssessment.from_cue_list(
        ["mimics_business_process", "url_hyperlinking"],  # 2 señales -> Few
        target_audience="Personal administrativo",
        premise_alignment=PremiseAlignment.HIGH,
    )
    r = a.result()
    assert r.cue_total == 2
    assert r.detection_difficulty is DetectionDifficulty.VERY
    assert r.premise_score is None  # Método 1


def test_method2_scoring_path():
    a = PhishScaleAssessment(
        target_audience="Finanzas",
        cues={"sense_of_urgency": 1, "generic_greeting": 1},  # Few
        premise_elements={
            PremiseElement.MIMICS_WORKPLACE_PROCESS: 8,
            PremiseElement.WORKPLACE_RELEVANCE: 8,
            PremiseElement.ALIGNS_WITH_EVENTS: 4,
            PremiseElement.CONCERN_IF_NOT_CLICKING: 4,
        },
    )
    r = a.result()
    assert r.premise_score == 24
    assert r.premise_alignment is PremiseAlignment.HIGH
    assert r.detection_difficulty is DetectionDifficulty.VERY


def test_many_cues_low_premise_is_least_difficult():
    a = PhishScaleAssessment(
        target_audience="General",
        cues={cid: 1 for cid in [
            "spelling_grammar", "inconsistency", "attachment_type",
            "sender_display_mismatch", "url_hyperlinking", "domain_spoofing",
            "no_minimal_branding", "logo_imitation_outdated",
            "unprofessional_design", "security_indicators_icons",
            "legal_language", "distracting_detail", "requests_sensitive_info",
            "sense_of_urgency", "threatening_language",  # 15 -> Many
        ]},
        premise_alignment=PremiseAlignment.LOW,
    )
    r = a.result()
    assert r.cue_total == 15
    assert r.detection_difficulty is DetectionDifficulty.LEAST
    assert r.normalized_difficulty == 0.25


def test_requires_at_least_one_cue():
    with pytest.raises(ValidationError):
        PhishScaleAssessment(
            target_audience="x", cues={},
            premise_alignment=PremiseAlignment.LOW,
        )


def test_unknown_cue_rejected():
    with pytest.raises(ValidationError):
        PhishScaleAssessment(
            target_audience="x", cues={"no_existe": 1},
            premise_alignment=PremiseAlignment.LOW,
        )


def test_premise_method_must_be_exactly_one():
    # ninguno
    with pytest.raises(ValidationError):
        PhishScaleAssessment(target_audience="x", cues={"inconsistency": 1})
    # ambos
    with pytest.raises(ValidationError):
        PhishScaleAssessment(
            target_audience="x", cues={"inconsistency": 1},
            premise_alignment=PremiseAlignment.LOW,
            premise_elements={PremiseElement.WORKPLACE_RELEVANCE: 4},
        )


def _very_difficult_result():
    return PhishScaleAssessment.from_cue_list(
        ["mimics_business_process"],
        target_audience="x",
        premise_alignment=PremiseAlignment.HIGH,
    ).result()


def test_click_rate_within_for_hard_phish():
    r = _very_difficult_result()  # esperado >= 19%
    ctx = contextualize_click_rate(r, 22.0)
    assert ctx.verdict is ClickRateVerdict.WITHIN


def test_click_rate_above_is_flagged_on_easy_phish():
    # phish poco difícil (Many + Low) con click rate alto -> alerta real
    easy = PhishScaleAssessment(
        target_audience="x",
        cues={cid: 1 for cid in [
            "spelling_grammar", "inconsistency", "attachment_type",
            "sender_display_mismatch", "url_hyperlinking", "domain_spoofing",
            "no_minimal_branding", "logo_imitation_outdated",
            "unprofessional_design", "security_indicators_icons",
            "legal_language", "distracting_detail", "requests_sensitive_info",
            "sense_of_urgency", "threatening_language",
        ]},
        premise_alignment=PremiseAlignment.LOW,
    ).result()
    ctx = contextualize_click_rate(easy, 25.0)  # esperado < 10%
    assert ctx.verdict is ClickRateVerdict.ABOVE


def test_click_rate_out_of_bounds():
    with pytest.raises(ValueError):
        contextualize_click_rate(_very_difficult_result(), 120.0)
