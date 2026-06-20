"""Quickstart de Señuelo: del consentimiento al control de alcance.

Ejecutar:  python examples/quickstart.py
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from senuelo.scope import Authorization, Party, ScopeEngine, sign

KEY = "demo-key-no-usar-en-produccion"


def main() -> None:
    now = datetime.now(timezone.utc)

    auth = Authorization(
        organization="Empresa Demo SpA",
        authorized_by=Party(name="Ana Soto", role="CISO",
                             email="ana.soto@empresa.cl"),
        requested_by=Party(name="Equipo Red Team", role="Operador",
                            email="redteam@consultora.cl"),
        scope_domains=["empresa.cl"],
        include_subdomains=False,
        excluded_addresses=["gerencia.general@empresa.cl"],
        window_start=now - timedelta(days=1),
        window_end=now + timedelta(days=14),
        data_retention_days=90,
        consent_reference="Anexo RoE 2026-04 firmado por gerencia",
    )
    sign(auth, KEY)

    print(f"Autorización {auth.authorization_id[:8]} — estado: "
          f"{auth.status().value}")
    print(f"Alcance: {', '.join(auth.scope_domains)} | "
          f"retención: {auth.data_retention_days} días\n")

    destinatarios = [
        "juan.perez@empresa.cl",
        "MARIA.LOPEZ@Empresa.CL",
        "gerencia.general@empresa.cl",   # excluido (opt-out)
        "contratista@gmail.com",          # fuera de alcance
        "user@correo.empresa.cl",         # subdominio (no incluido)
        "direccion-mala",                 # malformado
    ]

    report = ScopeEngine(auth, KEY).filter_recipients(destinatarios)

    print(f"Admitidos ({report.admitted_count}):")
    for r in report.admitted:
        print(f"  ✓ {r}")
    print(f"\nRechazados ({report.rejected_count}):")
    for rej in report.rejected:
        print(f"  ✗ {rej.email:<32} [{rej.code}] {rej.reason}")


if __name__ == "__main__":
    main()
