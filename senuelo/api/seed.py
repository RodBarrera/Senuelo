"""Datos de demostración para poblar el panel.

Crea una autorización firmada y varias campañas de distinta dificultad, las
lanza en modo simulación y deja una intencionalmente anómala: un phish fácil
de detectar que, aun así, obtuvo un click rate alto — el caso que el panel debe
encender en rojo. Se activa con SENUELO_SEED=1.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from ..campaigns import Campaign, RejectionRecord, SimulationParams, simulate
from ..scope import Authorization, Party, ScopeEngine, sign
from ..scoring import CUE_CATALOG, DetectionDifficulty, PhishScaleAssessment
from ..scoring import PremiseAlignment as PA

_CUE_IDS = [c.id for c in CUE_CATALOG]


def _assessment(n_cues: int, premise: PA, audience: str) -> PhishScaleAssessment:
    return PhishScaleAssessment.from_cue_list(
        _CUE_IDS[:n_cues], target_audience=audience, premise_alignment=premise,
    )


_SPECS = [
    ("Aviso de seguridad TI", 2, PA.HIGH, "Toda la empresa", 120, 11, None, True),
    ("Restablecer tu contraseña", 2, PA.HIGH, "Toda la empresa", 90, 12, None, False),
    ("Encuesta de clima laboral", 10, PA.MEDIUM, "RR.HH.", 80, 13, None, True),
    ("Actualización de beneficios", 10, PA.LOW, "Toda la empresa", 70, 14, None, False),
    ("Has ganado un premio", 16, PA.LOW, "Toda la empresa", 100, 15, None, True),
    ("Paquete retenido (urgente)", 16, PA.LOW, "Logística", 60, 16, 0.22, False),
]


def _params_with(difficulty: DetectionDifficulty, rate: float) -> SimulationParams:
    base = dict(SimulationParams().base_click_rate)
    base[difficulty] = rate
    return SimulationParams(base_click_rate=base)


def seed_demo(auth_repo, campaign_repo, audit, signing_key: str) -> None:
    """Puebla los repositorios con datos de demostración (idempotente por proceso)."""
    if campaign_repo.list():
        return

    now = datetime.now(timezone.utc)
    auth = sign(Authorization(
        organization="Empresa Demo SpA",
        authorized_by=Party(name="Ana Soto", role="CISO", email="ana@empresa.cl"),
        requested_by=Party(name="Red Team", role="Operador", email="rt@consultora.cl"),
        scope_domains=["empresa.cl"],
        excluded_addresses=["jefe@empresa.cl"],
        window_start=now - timedelta(days=2),
        window_end=now + timedelta(days=28),
        data_retention_days=90,
        consent_reference="Anexo RoE 2026-04",
    ), signing_key)
    auth_repo.add(auth)
    audit.append("authorization.created", authorization_id=auth.authorization_id,
                 detail={"organization": auth.organization})

    engine = ScopeEngine(auth, signing_key)

    for name, n_cues, premise, audience, n, seed, override, complete in _SPECS:
        assessment = _assessment(n_cues, premise, audience)
        recipients = [f"persona{i}@empresa.cl" for i in range(n)] + \
                     ["externo@gmail.com", "jefe@empresa.cl"]
        campaign = Campaign(
            name=name, authorization_id=auth.authorization_id,
            assessment=assessment, recipients=recipients,
        )
        campaign.schedule()

        report = engine.filter_recipients(campaign.recipients)
        result = assessment.result()
        params = (_params_with(result.detection_difficulty, override)
                  if override is not None else SimulationParams())
        events = simulate(report.admitted, result, params=params, seed=seed)
        rejected = [RejectionRecord(email=r.email, code=r.code, reason=r.reason)
                    for r in report.rejected]
        campaign.mark_running(report.admitted, rejected, events)
        if complete:
            campaign.complete()

        campaign_repo.add(campaign)
        audit.append("campaign.launched",
                     authorization_id=auth.authorization_id,
                     detail={"campaign_id": campaign.campaign_id, "name": name})
