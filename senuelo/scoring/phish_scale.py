"""Núcleo del NIST Phish Scale.

Implementa fielmente Steves, Greene & Theofanos (2020), "Categorizing human
phishing difficulty: a Phish Scale" (Journal of Cybersecurity, 6(1)):

- Conteo de señales ⇒ categoría Few / Some / Many.
- Alineación de premisa ⇒ Low / Medium / High (Método 1 directo, o Método 2
  formulaico de cinco elementos).
- Tabla 1: combina ambas en una dificultad de detección.
- Cada dificultad se asocia a un rango esperado de click rate, lo que permite
  *contextualizar* las métricas en vez de leerlas a ciegas.

Las constantes de corte llevan el valor exacto del paper.
"""

from __future__ import annotations

from enum import Enum

from .cues import CueCategory  # noqa: F401  (re-export conveniente)

# --- Cortes de conteo de señales (Tabla 2 del paper) --------------------
CUE_FEW_MAX = 8       # Few: 1–8
CUE_SOME_MAX = 14     # Some: 9–14  |  Many: 15+

# --- Cortes de premisa, Método 2 (paper + NIST User Guide) --------------
# Low: <= 10  |  Medium: 11–17  |  High: >= 18
PREMISE_MEDIUM_MIN = 11
PREMISE_HIGH_MIN = 18

# Anclas válidas de la escala de 5 puntos por elemento (números pares 0–8).
PREMISE_ANCHORS = (0, 2, 4, 6, 8)


class CueCount(str, Enum):
    """Categoría de conteo de señales. Menos señales ⇒ más difícil."""

    FEW = "few"
    SOME = "some"
    MANY = "many"


class PremiseAlignment(str, Enum):
    """Alineación de la premisa con el contexto de la audiencia objetivo."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class PremiseElement(str, Enum):
    """Los cinco elementos del Método 2 (formulaico).

    Los elementos 1–4 suman; el 5 (entrenamiento/advertencia previa) se resta,
    porque ayuda a la detección y por lo tanto reduce la alineación efectiva.
    """

    MIMICS_WORKPLACE_PROCESS = "mimics_workplace_process"
    WORKPLACE_RELEVANCE = "workplace_relevance"
    ALIGNS_WITH_EVENTS = "aligns_with_events"
    CONCERN_IF_NOT_CLICKING = "concern_if_not_clicking"
    PRIOR_TRAINING_OR_WARNING = "prior_training_or_warning"  # se resta


#: Elementos que suman (1–4).
_ADDITIVE_ELEMENTS = (
    PremiseElement.MIMICS_WORKPLACE_PROCESS,
    PremiseElement.WORKPLACE_RELEVANCE,
    PremiseElement.ALIGNS_WITH_EVENTS,
    PremiseElement.CONCERN_IF_NOT_CLICKING,
)


class DetectionDifficulty(str, Enum):
    """Dificultad de detección humana resultante (Tabla 1).

    El paper no etiqueta ninguna categoría como "fácil": la premisa de casi todo
    phish alinea para al menos algunas personas, y para ellas detectar no es fácil.
    """

    LEAST = "least"
    MODERATELY_TO_LEAST = "moderately_to_least"  # celda de rango (Some + Low)
    MODERATELY = "moderately"
    VERY = "very"

    @property
    def ordinal(self) -> int:
        """1 (menos difícil) a 4 (más difícil)."""
        return {
            "least": 1,
            "moderately_to_least": 2,
            "moderately": 3,
            "very": 4,
        }[self.value]

    @property
    def label_es(self) -> str:
        return {
            "least": "Poco difícil",
            "moderately_to_least": "De moderada a poco difícil",
            "moderately": "Moderadamente difícil",
            "very": "Muy difícil",
        }[self.value]

    @property
    def expected_click_rate(self) -> tuple[float, float]:
        """Rango esperado de click rate (%) asociado por el paper a la dificultad.

        Least < 10% · Moderately 11.6–18% · Very >= 19%. La celda de rango
        (Some + Low) se reporta como "menos que moderada" (< 18%).
        """
        return {
            "least": (0.0, 10.0),
            "moderately_to_least": (0.0, 18.0),
            "moderately": (11.6, 18.0),
            "very": (19.0, 100.0),
        }[self.value]


# --- Tabla 1: la matriz del Phish Scale ---------------------------------
# (conteo de señales, alineación de premisa) -> dificultad de detección.
DIFFICULTY_MATRIX: dict[tuple[CueCount, PremiseAlignment], DetectionDifficulty] = {
    (CueCount.FEW,  PremiseAlignment.HIGH):   DetectionDifficulty.VERY,
    (CueCount.FEW,  PremiseAlignment.MEDIUM): DetectionDifficulty.VERY,
    (CueCount.FEW,  PremiseAlignment.LOW):    DetectionDifficulty.MODERATELY,
    (CueCount.SOME, PremiseAlignment.HIGH):   DetectionDifficulty.VERY,
    (CueCount.SOME, PremiseAlignment.MEDIUM): DetectionDifficulty.MODERATELY,
    (CueCount.SOME, PremiseAlignment.LOW):    DetectionDifficulty.MODERATELY_TO_LEAST,
    (CueCount.MANY, PremiseAlignment.HIGH):   DetectionDifficulty.MODERATELY,
    (CueCount.MANY, PremiseAlignment.MEDIUM): DetectionDifficulty.MODERATELY,
    (CueCount.MANY, PremiseAlignment.LOW):    DetectionDifficulty.LEAST,
}


def cue_count_category(total: int) -> CueCount:
    """Convierte el total de señales contadas en su categoría Few/Some/Many."""
    if total < 1:
        raise ValueError("el total de señales debe ser al menos 1")
    if total <= CUE_FEW_MAX:
        return CueCount.FEW
    if total <= CUE_SOME_MAX:
        return CueCount.SOME
    return CueCount.MANY


def premise_score(ratings: dict[PremiseElement, int]) -> int:
    """Calcula el puntaje del Método 2: suma de elementos 1–4 menos el 5.

    Cada rating debe ser una de las anclas válidas (0, 2, 4, 6, 8). Faltantes
    se asumen como 0 (no aplica).
    """
    for element, value in ratings.items():
        if not isinstance(element, PremiseElement):
            raise TypeError(f"clave no es un PremiseElement: {element!r}")
        if value not in PREMISE_ANCHORS:
            raise ValueError(
                f"rating inválido para {element.value}: {value} "
                f"(debe ser uno de {PREMISE_ANCHORS})"
            )
    additive = sum(ratings.get(e, 0) for e in _ADDITIVE_ELEMENTS)
    penalty = ratings.get(PremiseElement.PRIOR_TRAINING_OR_WARNING, 0)
    return additive - penalty


def premise_category_from_score(score: int) -> PremiseAlignment:
    """Convierte el puntaje del Método 2 en Low/Medium/High."""
    if score >= PREMISE_HIGH_MIN:
        return PremiseAlignment.HIGH
    if score >= PREMISE_MEDIUM_MIN:
        return PremiseAlignment.MEDIUM
    return PremiseAlignment.LOW


def detection_difficulty(
    cues: CueCount, premise: PremiseAlignment
) -> DetectionDifficulty:
    """Aplica la Tabla 1: dificultad de detección a partir de ambas dimensiones."""
    return DIFFICULTY_MATRIX[(cues, premise)]
