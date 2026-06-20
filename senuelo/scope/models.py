"""Modelos de datos del alcance de Señuelo.

Una :class:`Authorization` es el artefacto central de la plataforma: traduce
las *rules of engagement* de un ejercicio de phishing controlado a datos
verificables. Sin una autorización firmada y vigente, Señuelo no envía nada.

Cada campo existe por una razón de gobernanza:

- ``authorized_by`` / ``requested_by``: separan a *quien tiene la autoridad*
  para consentir el ejercicio de *quien lo ejecuta*. No es lo mismo.
- ``scope_domains`` (+ ``include_subdomains``): el alcance duro. Un destinatario
  fuera de estos dominios se rechaza, no se "asume autorizado".
- ``excluded_addresses``: lista de exclusión / opt-out, respetada incluso dentro
  del alcance. La gente puede no querer ser objetivo, y eso se honra.
- ``window_start`` / ``window_end``: un ejercicio sin ventana temporal no es un
  ejercicio profesional. Toda autorización caduca.
- ``data_retention_days``: minimización de datos desde el diseño (Ley 19.628).
- ``consent_reference``: puntero al aviso/consentimiento entregado a las personas.
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from enum import Enum

from pydantic import (
    BaseModel,
    EmailStr,
    Field,
    field_validator,
    model_validator,
)

# Validación pragmática de dominio: etiquetas alfanuméricas separadas por puntos,
# con al menos un punto. No pretende ser un parser RFC completo, sino un filtro
# robusto para el alcance.
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)


def _utc(value: datetime) -> datetime:
    """Normaliza un datetime a UTC. Exige que sea *aware* (con zona horaria)."""
    if value.tzinfo is None:
        raise ValueError("los datetimes deben incluir zona horaria (aware)")
    return value.astimezone(timezone.utc)


class AuthorizationStatus(str, Enum):
    """Estado derivado de una autorización en un instante dado."""

    UNSIGNED = "unsigned"
    NOT_YET_ACTIVE = "not_yet_active"
    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"


class Party(BaseModel):
    """Una parte de la autorización: quien autoriza o quien ejecuta."""

    name: str = Field(min_length=1, max_length=200)
    role: str = Field(min_length=1, max_length=200)
    email: EmailStr

    @field_validator("name", "role")
    @classmethod
    def _strip(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("no puede quedar vacío tras recortar espacios")
        return v


class Authorization(BaseModel):
    """Autorización firmada para un ejercicio de phishing controlado."""

    authorization_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    organization: str = Field(min_length=1, max_length=300)

    authorized_by: Party
    requested_by: Party

    scope_domains: list[str] = Field(min_length=1)
    include_subdomains: bool = False
    excluded_addresses: list[str] = Field(default_factory=list)

    window_start: datetime
    window_end: datetime

    data_retention_days: int = Field(ge=1, le=3650)
    consent_reference: str = Field(min_length=1, max_length=500)

    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    signed_at: datetime | None = None
    revoked_at: datetime | None = None
    signature: str | None = None

    # --- normalización / validación -------------------------------------

    @field_validator("organization", "consent_reference")
    @classmethod
    def _strip_text(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("no puede quedar vacío tras recortar espacios")
        return v

    @field_validator("scope_domains")
    @classmethod
    def _normalize_domains(cls, domains: list[str]) -> list[str]:
        normalized: list[str] = []
        seen: set[str] = set()
        for raw in domains:
            d = raw.strip().lower().lstrip("@")
            if not _DOMAIN_RE.match(d):
                raise ValueError(f"dominio inválido en el alcance: {raw!r}")
            if d not in seen:
                seen.add(d)
                normalized.append(d)
        if not normalized:
            raise ValueError("el alcance debe incluir al menos un dominio")
        return normalized

    @field_validator("excluded_addresses")
    @classmethod
    def _normalize_excluded(cls, addrs: list[str]) -> list[str]:
        out: list[str] = []
        seen: set[str] = set()
        for raw in addrs:
            a = raw.strip().lower()
            if a and a not in seen:
                seen.add(a)
                out.append(a)
        return out

    @field_validator("window_start", "window_end", "created_at",
                     "signed_at", "revoked_at")
    @classmethod
    def _to_utc(cls, v: datetime | None) -> datetime | None:
        return None if v is None else _utc(v)

    @model_validator(mode="after")
    def _check_window(self) -> "Authorization":
        if self.window_end <= self.window_start:
            raise ValueError("window_end debe ser posterior a window_start")
        return self

    # --- API de conveniencia --------------------------------------------

    def canonical_payload(self) -> dict:
        """Devuelve los campos firmables (todo excepto ``signature``).

        Es lo que el firmante canonicaliza y sella. Si alguien altera el
        alcance, la ventana o las exclusiones después de firmar, este payload
        cambia y la verificación falla. Esa es la propiedad antimanipulación.
        """
        data = self.model_dump(mode="json", exclude={"signature"})
        return data

    def status(self, at: datetime | None = None) -> AuthorizationStatus:
        """Estado de la autorización en el instante ``at`` (por defecto, ahora)."""
        now = _utc(at) if at is not None else datetime.now(timezone.utc)
        if self.revoked_at is not None:
            return AuthorizationStatus.REVOKED
        if self.signature is None:
            return AuthorizationStatus.UNSIGNED
        if now < self.window_start:
            return AuthorizationStatus.NOT_YET_ACTIVE
        if now > self.window_end:
            return AuthorizationStatus.EXPIRED
        return AuthorizationStatus.ACTIVE

    def is_excluded(self, email: str) -> bool:
        """Indica si una dirección está en la lista de exclusión."""
        return email.strip().lower() in set(self.excluded_addresses)
