"""Evaluación de una plantilla con el Phish Scale y contextualización de métricas.

Une las dos dimensiones (señales + premisa) en un resultado de dificultad, y
ofrece lo que de verdad le interesa a Señuelo: comparar el click rate *observado*
contra el rango *esperado* para esa dificultad. Así un click rate alto en un
phish muy difícil deja de leerse como "fracaso del entrenamiento" y un click
rate alto en un phish fácil enciende la alarma correcta.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from pydantic import BaseModel, Field, model_validator

from .cues import CUES_BY_ID
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


@dataclass(frozen=True)
class PhishScaleResult:
    """Resultado completo de aplicar el Phish Scale a una plantilla."""

    cue_total: int
    cue_count: CueCount
    premise_alignment: PremiseAlignment
    detection_difficulty: DetectionDifficulty
    premise_score: int | None = None  # None si se usó el Método 1 (directo)

    @property
    def expected_click_rate(self) -> tuple[float, float]:
        return self.detection_difficulty.expected_click_rate

    @property
    def normalized_difficulty(self) -> float:
        """Dificultad ordinal normalizada a [0.25, 1.0], para pesar/ordenar campañas."""
        return self.detection_difficulty.ordinal / 4.0


class PhishScaleAssessment(BaseModel):
    """Evaluación de una plantilla. La premisa se da por Método 1 *o* Método 2."""

    template_id: str | None = None
    target_audience: str = Field(min_length=1, max_length=500)

    #: señal -> número de instancias observadas (>= 1).
    cues: dict[str, int] = Field(default_factory=dict)

    #: Método 1: alineación directa.
    premise_alignment: PremiseAlignment | None = None
    #: Método 2: ratings por elemento (anclas 0/2/4/6/8).
    premise_elements: dict[PremiseElement, int] | None = None

    @model_validator(mode="after")
    def _validate(self) -> "PhishScaleAssessment":
        # Señales: ids conocidos e instancias válidas.
        if not self.cues:
            raise ValueError("debe declararse al menos una señal presente")
        for cue_id, instances in self.cues.items():
            if cue_id not in CUES_BY_ID:
                raise ValueError(f"señal desconocida: {cue_id!r}")
            if instances < 1:
                raise ValueError(f"instancias de {cue_id!r} deben ser >= 1")
        # Premisa: exactamente uno de los dos métodos.
        has_m1 = self.premise_alignment is not None
        has_m2 = self.premise_elements is not None
        if has_m1 == has_m2:
            raise ValueError(
                "indica la premisa por exactamente un método: "
                "'premise_alignment' (Método 1) o 'premise_elements' (Método 2)"
            )
        return self

    @classmethod
    def from_cue_list(cls, cue_ids: list[str], **kwargs) -> "PhishScaleAssessment":
        """Atajo: lista de señales presentes, cada una contada una vez."""
        cues: dict[str, int] = {}
        for cid in cue_ids:
            cues[cid] = cues.get(cid, 0) + 1
        return cls(cues=cues, **kwargs)

    def result(self) -> PhishScaleResult:
        total = sum(self.cues.values())
        cue_cat = cue_count_category(total)

        score: int | None = None
        if self.premise_alignment is not None:
            premise = self.premise_alignment
        else:
            assert self.premise_elements is not None
            score = premise_score(self.premise_elements)
            premise = premise_category_from_score(score)

        difficulty = detection_difficulty(cue_cat, premise)
        return PhishScaleResult(
            cue_total=total,
            cue_count=cue_cat,
            premise_alignment=premise,
            detection_difficulty=difficulty,
            premise_score=score,
        )


class ClickRateVerdict(str, Enum):
    """Cómo se compara un click rate observado contra el rango esperado."""

    BELOW = "below_expected"
    WITHIN = "within_expected"
    ABOVE = "above_expected"


@dataclass(frozen=True)
class ClickRateContext:
    """Lectura contextualizada de un click rate observado."""

    observed: float
    expected: tuple[float, float]
    verdict: ClickRateVerdict
    message: str


def contextualize_click_rate(
    result: PhishScaleResult, observed_pct: float
) -> ClickRateContext:
    """Interpreta un click rate observado a la luz de la dificultad de la plantilla.

    Es el corazón del argumento del Phish Scale: el click rate solo significa algo
    *relativo a la dificultad*. Un 22% en un phish "Muy difícil" es esperable;
    el mismo 22% en uno "Poco difícil" es la señal de alerta real.
    """
    if not 0.0 <= observed_pct <= 100.0:
        raise ValueError("el click rate observado debe estar entre 0 y 100")

    low, high = result.expected_click_rate
    diff = result.detection_difficulty

    if observed_pct < low:
        verdict = ClickRateVerdict.BELOW
        message = (
            f"{observed_pct:.1f}% está por debajo del rango esperado "
            f"({low:.0f}–{high:.0f}%) para un phish '{diff.label_es}'."
        )
    elif observed_pct > high:
        verdict = ClickRateVerdict.ABOVE
        message = (
            f"{observed_pct:.1f}% supera el rango esperado "
            f"({low:.0f}–{high:.0f}%) para un phish '{diff.label_es}': "
            f"vale la pena investigar."
        )
    else:
        verdict = ClickRateVerdict.WITHIN
        message = (
            f"{observed_pct:.1f}% está dentro de lo esperado "
            f"({low:.0f}–{high:.0f}%) para un phish '{diff.label_es}'."
        )
    return ClickRateContext(
        observed=observed_pct,
        expected=(low, high),
        verdict=verdict,
        message=message,
    )
