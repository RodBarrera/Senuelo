"""Quickstart de campaña: los cuatro módulos componiéndose.

Ejecutar:  PYTHONPATH=. python examples/campaign_quickstart.py
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from senuelo.campaigns import Campaign, RejectionRecord, simulate
from senuelo.scope import Authorization, Party, ScopeEngine, sign
from senuelo.scoring import PhishScaleAssessment, PremiseAlignment

KEY = "demo-key-no-usar-en-produccion"


def main() -> None:
    now = datetime.now(timezone.utc)

    # 1) Autorización firmada (scope)
    auth = sign(Authorization(
        organization="Empresa Demo SpA",
        authorized_by=Party(name="Ana Soto", role="CISO", email="ana@empresa.cl"),
        requested_by=Party(name="Red Team", role="Operador", email="rt@consultora.cl"),
        scope_domains=["empresa.cl"],
        excluded_addresses=["jefe@empresa.cl"],
        window_start=now - timedelta(days=1),
        window_end=now + timedelta(days=14),
        data_retention_days=90,
        consent_reference="Anexo RoE 2026-04",
    ), KEY)

    # 2) Plantilla evaluada (scoring): pocas señales + premisa alta -> Muy difícil
    assessment = PhishScaleAssessment.from_cue_list(
        ["mimics_business_process", "url_hyperlinking"],
        target_audience="Finanzas",
        premise_alignment=PremiseAlignment.HIGH,
    )

    # 3) Campaña (draft) con 30 destinatarios en alcance + 2 que no
    recipients = [f"u{i}@empresa.cl" for i in range(30)] + \
                 ["fuera@gmail.com", "jefe@empresa.cl"]
    campaign = Campaign(
        name="Factura impaga a Finanzas",
        authorization_id=auth.authorization_id,
        assessment=assessment,
        recipients=recipients,
    )
    campaign.schedule()

    # 4) Lanzamiento dry-run: validar alcance + simular tracking
    report = ScopeEngine(auth, KEY).filter_recipients(campaign.recipients)
    result = assessment.result()
    events = simulate(report.admitted, result, seed=42)
    rejected = [RejectionRecord(email=r.email, code=r.code, reason=r.reason)
                for r in report.rejected]
    campaign.mark_running(report.admitted, rejected, events)

    m = campaign.metrics()
    print(f"Campaña: {campaign.name}  [{campaign.status.value}]")
    print(f"Dificultad de la plantilla: {result.detection_difficulty.label_es}\n")
    print(f"Destinatarios: {len(campaign.admitted)} admitidos, "
          f"{len(campaign.rejected)} rechazados")
    for r in campaign.rejected:
        print(f"  ✗ {r.email} [{r.code}]")
    print("\nEmbudo (dry-run):")
    print(f"  Enviados:  {m.sent}")
    print(f"  Abiertos:  {m.opened}  ({m.open_rate}%)")
    print(f"  Clicks:    {m.clicked}  ({m.click_rate}%)")
    print(f"  Enviaron datos: {m.submitted}  ({m.submit_rate}%)")
    print(f"  REPORTARON: {m.reported}  ({m.report_rate}%)   <- KPI de resiliencia")


if __name__ == "__main__":
    main()
