"""Scoring de dificultad con el NIST Phish Scale.

Segundo diferenciador de Señuelo: puntúa la dificultad de detección de cada
plantilla (señales + alineación de premisa) y permite normalizar y contextualizar
los click rates en vez de leerlos a ciegas.
"""

from .assessment import (
    ClickRateContext,
    ClickRateVerdict,
    PhishScaleAssessment,
    PhishScaleResult,
    contextualize_click_rate,
)
from .cues import CUE_CATALOG, CUES_BY_ID, Cue, CueCategory, get_cue
from .phish_scale import (
    CueCount,
    DetectionDifficulty,
    PremiseAlignment,
    PremiseElement,
    cue_count_category,
    detection_difficulty,
    premise_category_from_score,
    premise_score,
)

__all__ = [
    "Cue",
    "CueCategory",
    "CUE_CATALOG",
    "CUES_BY_ID",
    "get_cue",
    "CueCount",
    "PremiseAlignment",
    "PremiseElement",
    "DetectionDifficulty",
    "cue_count_category",
    "premise_score",
    "premise_category_from_score",
    "detection_difficulty",
    "PhishScaleAssessment",
    "PhishScaleResult",
    "ClickRateContext",
    "ClickRateVerdict",
    "contextualize_click_rate",
]
