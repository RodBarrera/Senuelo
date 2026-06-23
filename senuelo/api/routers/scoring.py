"""Endpoints de scoring: envuelven el motor del NIST Phish Scale."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import ValidationError

from ...scoring import (
    CUE_CATALOG,
    PhishScaleAssessment,
    PhishScaleResult,
    contextualize_click_rate,
)
from ..deps import require_api_key
from ..schemas import (
    ContextualizeRequest,
    ContextualizeResponse,
    CueInfo,
    ScoringResultResponse,
)

router = APIRouter(
    prefix="/scoring",
    tags=["scoring"],
    dependencies=[Depends(require_api_key)],
)


def _result_response(result: PhishScaleResult) -> ScoringResultResponse:
    return ScoringResultResponse(
        cue_total=result.cue_total,
        cue_count=result.cue_count.value,
        premise_score=result.premise_score,
        premise_alignment=result.premise_alignment.value,
        detection_difficulty=result.detection_difficulty.value,
        detection_difficulty_label=result.detection_difficulty.label_es,
        expected_click_rate=result.expected_click_rate,
        normalized_difficulty=result.normalized_difficulty,
    )


@router.get("/cues", response_model=list[CueInfo])
def list_cues() -> list[CueInfo]:
    """Catálogo de las 23 señales del Phish Scale (útil para poblar una UI)."""
    return [
        CueInfo(id=c.id, category=c.category.value, name=c.name,
                criterion=c.criterion)
        for c in CUE_CATALOG
    ]


@router.post("/assess", response_model=ScoringResultResponse)
def assess_template(assessment: PhishScaleAssessment) -> ScoringResultResponse:
    """Evalúa la dificultad de detección de una plantilla."""
    return _result_response(assessment.result())


@router.post("/contextualize", response_model=ContextualizeResponse)
def contextualize(body: ContextualizeRequest) -> ContextualizeResponse:
    """Interpreta un click rate observado a la luz de la dificultad de la plantilla."""
    try:
        assessment = PhishScaleAssessment(
            target_audience=body.target_audience,
            cues=body.cues,
            premise_alignment=body.premise_alignment,
            premise_elements=body.premise_elements,
        )
    except ValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=exc.errors()
        ) from exc

    result = assessment.result()
    ctx = contextualize_click_rate(result, body.observed_click_rate)
    return ContextualizeResponse(
        result=_result_response(result),
        observed=ctx.observed,
        expected=ctx.expected,
        verdict=ctx.verdict.value,
        message=ctx.message,
    )
