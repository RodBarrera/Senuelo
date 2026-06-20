"""Tests del núcleo del NIST Phish Scale."""

from __future__ import annotations

import pytest

from senuelo.scoring import (
    CueCount,
    DetectionDifficulty,
    PremiseAlignment,
    PremiseElement,
    cue_count_category,
    detection_difficulty,
    premise_category_from_score,
    premise_score,
)
from senuelo.scoring.phish_scale import DIFFICULTY_MATRIX


@pytest.mark.parametrize(
    "total,expected",
    [
        (1, CueCount.FEW), (8, CueCount.FEW),
        (9, CueCount.SOME), (14, CueCount.SOME),
        (15, CueCount.MANY), (40, CueCount.MANY),
    ],
)
def test_cue_count_boundaries(total, expected):
    assert cue_count_category(total) is expected


def test_cue_count_zero_invalid():
    with pytest.raises(ValueError):
        cue_count_category(0)


def test_premise_score_subtracts_training():
    ratings = {
        PremiseElement.MIMICS_WORKPLACE_PROCESS: 8,
        PremiseElement.WORKPLACE_RELEVANCE: 8,
        PremiseElement.ALIGNS_WITH_EVENTS: 8,
        PremiseElement.CONCERN_IF_NOT_CLICKING: 8,
        PremiseElement.PRIOR_TRAINING_OR_WARNING: 8,  # se resta
    }
    assert premise_score(ratings) == 32 - 8  # 24


def test_premise_score_invalid_anchor():
    with pytest.raises(ValueError):
        premise_score({PremiseElement.WORKPLACE_RELEVANCE: 5})


@pytest.mark.parametrize(
    "score,expected",
    [
        (-8, PremiseAlignment.LOW), (10, PremiseAlignment.LOW),
        (11, PremiseAlignment.MEDIUM), (17, PremiseAlignment.MEDIUM),
        (18, PremiseAlignment.HIGH), (32, PremiseAlignment.HIGH),
    ],
)
def test_premise_category_boundaries(score, expected):
    assert premise_category_from_score(score) is expected


def test_matrix_is_complete_and_matches_table1():
    # Las 9 celdas existen.
    assert len(DIFFICULTY_MATRIX) == 9
    # Esquinas y casos clave de la Tabla 1.
    assert detection_difficulty(CueCount.FEW, PremiseAlignment.HIGH) is DetectionDifficulty.VERY
    assert detection_difficulty(CueCount.FEW, PremiseAlignment.LOW) is DetectionDifficulty.MODERATELY
    assert detection_difficulty(CueCount.SOME, PremiseAlignment.LOW) is DetectionDifficulty.MODERATELY_TO_LEAST
    assert detection_difficulty(CueCount.MANY, PremiseAlignment.HIGH) is DetectionDifficulty.MODERATELY
    assert detection_difficulty(CueCount.MANY, PremiseAlignment.LOW) is DetectionDifficulty.LEAST


def test_difficulty_ordinal_and_click_bands():
    assert DetectionDifficulty.LEAST.ordinal == 1
    assert DetectionDifficulty.VERY.ordinal == 4
    assert DetectionDifficulty.LEAST.expected_click_rate == (0.0, 10.0)
    assert DetectionDifficulty.VERY.expected_click_rate == (19.0, 100.0)
