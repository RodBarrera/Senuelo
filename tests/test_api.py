"""Tests de la capa FastAPI."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from senuelo.api import config
from senuelo.api.app import create_app
from senuelo.api.campaign_repository import (
    InMemoryCampaignRepository,
    get_campaign_repository,
)
from senuelo.api.repository import (
    InMemoryAuthorizationRepository,
    get_audit_log,
    get_repository,
)
from senuelo.storage import InMemoryAuditLog


def make_client(monkeypatch, *, signing_key="clave-test", api_key=None):
    if signing_key is None:
        monkeypatch.delenv("SENUELO_SIGNING_KEY", raising=False)
    else:
        monkeypatch.setenv("SENUELO_SIGNING_KEY", signing_key)
    if api_key is None:
        monkeypatch.delenv("SENUELO_API_KEY", raising=False)
    else:
        monkeypatch.setenv("SENUELO_API_KEY", api_key)
    config.get_settings.cache_clear()
    app = create_app()
    repo = InMemoryAuthorizationRepository()
    campaign_repo = InMemoryCampaignRepository()
    audit = InMemoryAuditLog()
    app.dependency_overrides[get_repository] = lambda: repo
    app.dependency_overrides[get_campaign_repository] = lambda: campaign_repo
    app.dependency_overrides[get_audit_log] = lambda: audit
    return TestClient(app)


def auth_payload(**over):
    now = datetime.now(timezone.utc)
    payload = {
        "organization": "Empresa Demo SpA",
        "authorized_by": {"name": "Ana Soto", "role": "CISO",
                          "email": "ana@empresa.cl"},
        "requested_by": {"name": "Red Team", "role": "Operador",
                         "email": "rt@consultora.cl"},
        "scope_domains": ["empresa.cl"],
        "excluded_addresses": ["jefe@empresa.cl"],
        "window_start": (now - timedelta(days=1)).isoformat(),
        "window_end": (now + timedelta(days=7)).isoformat(),
        "data_retention_days": 90,
        "consent_reference": "Anexo RoE 2026-04",
    }
    payload.update(over)
    return payload


def test_health(monkeypatch):
    c = make_client(monkeypatch)
    r = c.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["signing_enabled"] is True
    assert body["auth_enabled"] is False  # modo dev


def test_create_and_get_authorization(monkeypatch):
    c = make_client(monkeypatch)
    r = c.post("/authorizations", json=auth_payload())
    assert r.status_code == 201
    data = r.json()
    assert data["status"] == "active"
    assert data["signature"]  # viene firmada
    aid = data["authorization_id"]

    r2 = c.get(f"/authorizations/{aid}")
    assert r2.status_code == 200
    assert r2.json()["organization"] == "Empresa Demo SpA"


def test_get_missing_is_404(monkeypatch):
    c = make_client(monkeypatch)
    assert c.get("/authorizations/no-existe").status_code == 404


def test_recipient_check(monkeypatch):
    c = make_client(monkeypatch)
    aid = c.post("/authorizations", json=auth_payload()).json()["authorization_id"]
    r = c.post(f"/authorizations/{aid}/recipient-check", json={
        "recipients": [
            "ok@empresa.cl",
            "fuera@gmail.com",
            "jefe@empresa.cl",  # excluido
        ]
    })
    assert r.status_code == 200
    body = r.json()
    assert body["admitted"] == ["ok@empresa.cl"]
    assert body["admitted_count"] == 1
    assert body["rejected_count"] == 2
    codes = {item["code"] for item in body["rejected"]}
    assert codes == {"out_of_scope", "excluded_recipient"}


def test_revoke_then_check_conflict(monkeypatch):
    c = make_client(monkeypatch)
    aid = c.post("/authorizations", json=auth_payload()).json()["authorization_id"]
    r = c.post(f"/authorizations/{aid}/revoke")
    assert r.status_code == 200
    assert r.json()["status"] == "revoked"
    # tras revocar, validar destinatarios falla a nivel de campaña
    r2 = c.post(f"/authorizations/{aid}/recipient-check",
                json={"recipients": ["ok@empresa.cl"]})
    assert r2.status_code == 409
    assert r2.json()["detail"]["code"] == "authorization_revoked"


def test_signing_key_missing_is_503(monkeypatch):
    c = make_client(monkeypatch, signing_key=None)
    r = c.post("/authorizations", json=auth_payload())
    assert r.status_code == 503


def test_scoring_cues_catalog(monkeypatch):
    c = make_client(monkeypatch)
    r = c.get("/scoring/cues")
    assert r.status_code == 200
    assert len(r.json()) == 23


def test_scoring_assess(monkeypatch):
    c = make_client(monkeypatch)
    r = c.post("/scoring/assess", json={
        "target_audience": "Finanzas",
        "cues": {"mimics_business_process": 1, "url_hyperlinking": 1},
        "premise_alignment": "high",
    })
    assert r.status_code == 200
    assert r.json()["detection_difficulty"] == "very"


def test_scoring_contextualize(monkeypatch):
    c = make_client(monkeypatch)
    r = c.post("/scoring/contextualize", json={
        "target_audience": "Finanzas",
        "cues": {"mimics_business_process": 1},
        "premise_alignment": "high",
        "observed_click_rate": 22.0,
    })
    assert r.status_code == 200
    assert r.json()["verdict"] == "within_expected"


def test_api_key_enforced_when_configured(monkeypatch):
    c = make_client(monkeypatch, api_key="secreta")
    # sin header -> 401
    assert c.get("/scoring/cues").status_code == 401
    # con header correcto -> 200
    r = c.get("/scoring/cues", headers={"X-API-Key": "secreta"})
    assert r.status_code == 200
    # health queda fuera del router protegido
    assert c.get("/health").status_code == 200


# --- Campañas -----------------------------------------------------------

def _assessment_body():
    return {
        "target_audience": "Finanzas",
        "cues": {"mimics_business_process": 1, "url_hyperlinking": 1},
        "premise_alignment": "high",
    }


def _create_auth(c):
    return c.post("/authorizations", json=auth_payload()).json()["authorization_id"]


def test_create_campaign_requires_existing_auth(monkeypatch):
    c = make_client(monkeypatch)
    r = c.post("/campaigns", json={
        "name": "X", "authorization_id": "no-existe",
        "assessment": _assessment_body(),
        "recipients": ["a@empresa.cl"],
    })
    assert r.status_code == 404


def test_campaign_full_flow(monkeypatch):
    c = make_client(monkeypatch)
    aid = _create_auth(c)

    # crear -> draft
    r = c.post("/campaigns", json={
        "name": "Campaña Q3",
        "authorization_id": aid,
        "assessment": _assessment_body(),
        "recipients": ["a@empresa.cl", "b@empresa.cl", "fuera@gmail.com"],
    })
    assert r.status_code == 201
    cid = r.json()["campaign_id"]
    assert r.json()["status"] == "draft"

    # schedule -> scheduled
    assert c.post(f"/campaigns/{cid}/schedule").json()["status"] == "scheduled"

    # launch -> running, valida alcance y genera tracking
    r = c.post(f"/campaigns/{cid}/launch", json={"seed": 42})
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "running"
    assert set(data["admitted"]) == {"a@empresa.cl", "b@empresa.cl"}
    assert [x["email"] for x in data["rejected"]] == ["fuera@gmail.com"]
    assert len(data["events"]) >= 2  # al menos un SENT por admitido

    # metrics
    m = c.get(f"/campaigns/{cid}/metrics").json()
    assert m["sent"] == 2
    assert "report_rate" in m

    # events
    assert c.get(f"/campaigns/{cid}/events").status_code == 200


def test_campaign_invalid_transition_is_409(monkeypatch):
    c = make_client(monkeypatch)
    aid = _create_auth(c)
    cid = c.post("/campaigns", json={
        "name": "X", "authorization_id": aid,
        "assessment": _assessment_body(), "recipients": ["a@empresa.cl"],
    }).json()["campaign_id"]
    # completar desde draft no es válido
    assert c.post(f"/campaigns/{cid}/complete").status_code == 409
