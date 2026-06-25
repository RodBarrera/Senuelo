"""Datos agregados para el panel de concientización."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from ...campaigns import EventType
from ...scoring import contextualize_click_rate
from ..campaign_repository import CampaignRepository, get_campaign_repository
from ..deps import require_api_key

router = APIRouter(
    prefix="/dashboard",
    tags=["panel"],
    dependencies=[Depends(require_api_key)],
)


def _rate(part: int, whole: int) -> float:
    return round(100.0 * part / whole, 1) if whole else 0.0


@router.get("/data")
def dashboard_data(
    repo: CampaignRepository = Depends(get_campaign_repository),
) -> dict:
    campaigns = repo.list()

    agg = {t.value: 0 for t in EventType}
    per_campaign = []

    for c in campaigns:
        m = c.metrics()
        agg["sent"] += m.sent
        agg["opened"] += m.opened
        agg["clicked"] += m.clicked
        agg["submitted"] += m.submitted
        agg["reported"] += m.reported

        result = c.assessment.result()
        low, high = result.expected_click_rate
        verdict = None
        if m.sent:
            verdict = contextualize_click_rate(result, m.click_rate).verdict.value

        per_campaign.append({
            "name": c.name,
            "status": c.status.value,
            "difficulty": result.detection_difficulty.value,
            "difficulty_label": result.detection_difficulty.label_es,
            "sent": m.sent,
            "open_rate": m.open_rate,
            "click_rate": m.click_rate,
            "submit_rate": m.submit_rate,
            "report_rate": m.report_rate,
            "expected_low": low,
            "expected_high": high,
            "verdict": verdict,
        })

    sent = agg["sent"]
    return {
        "summary": {
            "campaigns": len(campaigns),
            "recipients_reached": sent,
            "report_rate": _rate(agg["reported"], sent),
            "click_rate": _rate(agg["clicked"], sent),
            "open_rate": _rate(agg["opened"], sent),
        },
        "funnel": {
            "sent": agg["sent"],
            "opened": agg["opened"],
            "clicked": agg["clicked"],
            "submitted": agg["submitted"],
            "reported": agg["reported"],
        },
        "campaigns": per_campaign,
    }
