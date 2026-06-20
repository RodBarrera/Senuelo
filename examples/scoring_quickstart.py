"""Quickstart del scoring NIST Phish Scale.

Ejecutar:  PYTHONPATH=. python examples/scoring_quickstart.py
"""

from __future__ import annotations

from senuelo.scoring import (
    PhishScaleAssessment,
    PremiseElement,
    PremiseAlignment,
    contextualize_click_rate,
)


def show(title: str, assessment: PhishScaleAssessment, observed: float) -> None:
    r = assessment.result()
    low, high = r.expected_click_rate
    print(f"== {title} ==")
    print(f"  Señales: {r.cue_total} ({r.cue_count.value})", end="")
    if r.premise_score is not None:
        print(f" | premisa: {r.premise_score} ({r.premise_alignment.value})")
    else:
        print(f" | premisa: {r.premise_alignment.value} (Método 1)")
    print(f"  Dificultad: {r.detection_difficulty.label_es} "
          f"(esperado {low:.0f}–{high:.0f}% de click)")
    ctx = contextualize_click_rate(r, observed)
    print(f"  Observado: {ctx.message}\n")


def main() -> None:
    # Phish dirigido: imita un proceso interno, pocas señales, premisa muy alta.
    spear = PhishScaleAssessment.from_cue_list(
        ["mimics_business_process", "url_hyperlinking"],
        target_audience="Finanzas (paga facturas)",
        premise_elements=None,
        premise_alignment=PremiseAlignment.HIGH,
    )
    show("Factura impaga a Finanzas (dirigido)", spear, observed=22.0)

    # Phish genérico y burdo: muchas señales, premisa baja para la audiencia.
    crude = PhishScaleAssessment(
        target_audience="Toda la empresa",
        cues={cid: 1 for cid in [
            "spelling_grammar", "inconsistency", "attachment_type",
            "sender_display_mismatch", "url_hyperlinking", "domain_spoofing",
            "no_minimal_branding", "unprofessional_design",
            "requests_sensitive_info", "sense_of_urgency",
            "threatening_language", "too_good_to_be_true",
            "limited_time_offer", "generic_greeting", "lack_signer_details",
        ]},
        premise_elements={
            PremiseElement.MIMICS_WORKPLACE_PROCESS: 0,
            PremiseElement.WORKPLACE_RELEVANCE: 2,
            PremiseElement.ALIGNS_WITH_EVENTS: 0,
            PremiseElement.CONCERN_IF_NOT_CLICKING: 2,
        },
    )
    show("Lotería sospechosa (genérico)", crude, observed=24.0)


if __name__ == "__main__":
    main()
